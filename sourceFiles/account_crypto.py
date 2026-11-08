"""
The cryptography of PassMan 3.0 accounts (design: E:\\CLAUDE\\PassMan\\DESIGN-3.0.md).

Nothing in the 2.x app calls this yet: phase 1 builds the local account on it.
Every function is pure -- bytes and dicts in, bytes and dicts out, no files --
so the format can be pinned by tests before any screen depends on it.

The pieces, from what the user types to what opens a vault::

    master password --Argon2id(salt)--+
                                      +--HKDF--> AUK (Account Unlock Key)
    Secret Key (128 bits) ------------+   \\----> Login Key (for the server)

    AUK            --AES-GCM--> keyset {X25519 private key, personal vault key}
    X25519 key     --unwraps--> a shared vault's key
    vault key      --AES-GCM--> PMV3: the vault's entries

Recovery (personal accounts): a 12-word BIP39 phrase carries 128 random bits;
they make a Recovery Key that seals a second copy of the keyset.

Libraries: ``cryptography`` for AES-GCM, HKDF and X25519 (all present in the
old 3.4 that Ubuntu 22.04 ships); Argon2id from ``cryptography`` >= 44 where it
exists (Windows), else from argon2-cffi (Ubuntu's python3-argon2). Both give
the same bytes for the same inputs -- the tests hold them to it.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import unicodedata

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from bip39_words import WORDS

KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
SECRET_KEY_LEN = 16
VAULT_ID_LEN = 16

#: Argon2id cost for a new account: 64 MiB, 3 passes, 1 lane -- 0.12 s on the
#: development PC (2026), a few times that on an old laptop. Memory is what
#: makes guessing on graphics cards expensive. Stored in each keyset header, so it
#: can be raised later without breaking older files.
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_PASSES = 3
ARGON2_LANES = 1
#: Refuse headers outside these: a damaged or hostile file must not make the
#: app allocate gigabytes or spin for minutes before saying "wrong password".
ARGON2_MAX_MEMORY_KIB = 1024 * 1024
ARGON2_MAX_PASSES = 20
ARGON2_MAX_LANES = 16


class CryptoError(ValueError):
    """A sentence the user can be shown: wrong password, damaged file, typo."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text, what: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        raise CryptoError(f"The {what} is damaged (not valid base64).") from None


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info).derive(ikm)


# ===========================================================================
# Argon2id
# ===========================================================================
def _argon2_cryptography(secret, salt, passes, memory_kib, lanes, length):
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    return Argon2id(salt=salt, length=length, iterations=passes, lanes=lanes,
                    memory_cost=memory_kib).derive(secret)


def _argon2_cffi(secret, salt, passes, memory_kib, lanes, length):
    from argon2.low_level import Type, hash_secret_raw
    return hash_secret_raw(secret=secret, salt=salt, time_cost=passes,
                           memory_cost=memory_kib, parallelism=lanes,
                           hash_len=length, type=Type.ID)


def argon2_backends() -> dict:
    """The Argon2id implementations importable here, by name."""
    found = {}
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id  # noqa: F401
        found["cryptography"] = _argon2_cryptography
    except ImportError:
        pass
    try:
        from argon2.low_level import hash_secret_raw  # noqa: F401
        found["argon2-cffi"] = _argon2_cffi
    except ImportError:
        pass
    return found


def argon2id(secret: bytes, salt: bytes, passes: int = ARGON2_PASSES,
             memory_kib: int = ARGON2_MEMORY_KIB, lanes: int = ARGON2_LANES,
             length: int = KEY_LEN) -> bytes:
    backends = argon2_backends()
    if not backends:
        raise CryptoError("Argon2id is not available: install cryptography 44 "
                          "or newer, or argon2-cffi (python3-argon2).")
    return next(iter(backends.values()))(secret, salt, passes, memory_kib,
                                         lanes, length)


def _check_cost(passes, memory_kib, lanes):
    if not (1 <= passes <= ARGON2_MAX_PASSES
            and 8 * lanes <= memory_kib <= ARGON2_MAX_MEMORY_KIB
            and 1 <= lanes <= ARGON2_MAX_LANES):
        raise CryptoError("The account file asks for an unreasonable key "
                          "derivation cost; it is damaged or not PassMan's.")


# ===========================================================================
# Secret Key
# ===========================================================================
SECRET_KEY_PREFIX = "A3"
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _secret_check_char(raw: bytes) -> str:
    return _B32[hashlib.sha256(b"PassMan3 secret key" + raw).digest()[0] % 32]


def new_secret_key() -> bytes:
    return os.urandom(SECRET_KEY_LEN)


def format_secret_key(raw: bytes) -> str:
    """
    ``A3-XXXXX-XXXXX-XXXXX-XXXXXX-XXXXXX``: 26 base32 characters for the 128
    bits plus one check character, so a mistyped character is caught as a
    typo instead of reported as a wrong password.
    """
    if len(raw) != SECRET_KEY_LEN:
        raise ValueError("a Secret Key is 16 bytes")
    body = base64.b32encode(raw).decode("ascii").rstrip("=") + _secret_check_char(raw)
    groups = [body[0:5], body[5:10], body[10:15], body[15:21], body[21:27]]
    return SECRET_KEY_PREFIX + "-" + "-".join(groups)


def parse_secret_key(text: str) -> bytes:
    """The 16 bytes of a typed Secret Key, or CryptoError saying what is wrong."""
    cleaned = "".join((text or "").split()).replace("-", "").upper()
    if not cleaned:
        raise CryptoError("Enter your Secret Key (it starts with A3-).")
    if not cleaned.startswith(SECRET_KEY_PREFIX):
        raise CryptoError("A Secret Key starts with A3-; check your Emergency Kit.")
    body = cleaned[len(SECRET_KEY_PREFIX):]
    if len(body) != 27:
        raise CryptoError(f"A Secret Key has 27 characters after A3-; this one "
                          f"has {len(body)}.")
    bad = sorted({c for c in body if c not in _B32})
    if bad:
        hint = " (0 and 1 are never used: did you mean O or I?)" \
            if set(bad) & set("01") else ""
        raise CryptoError("A Secret Key uses only A-Z and 2-7; this one also "
                          "has " + " ".join(bad) + hint + ".")
    try:
        raw = base64.b32decode(body[:26] + "=" * 6)
    except Exception:
        raise CryptoError("That Secret Key is not valid; check it against your "
                          "Emergency Kit.") from None
    # The 26th character carries only 3 of the 128 bits; decoding ignores the
    # rest, so compare against the canonical spelling to catch a typo there.
    canonical = base64.b32encode(raw).decode("ascii")[:26]
    if canonical != body[:26] or _secret_check_char(raw) != body[26]:
        raise CryptoError("That Secret Key has a typo; check it against your "
                          "Emergency Kit.")
    return raw


# ===========================================================================
# Master password + Secret Key -> AUK and Login Key
# ===========================================================================
def _normalise(password: str) -> bytes:
    # The same password typed on Windows and on Linux (or pasted) can arrive
    # in different Unicode forms; NFKC makes them one.
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def derive_account_keys(master_password: str, secret_key: bytes, username: str,
                        salt: bytes, passes: int = ARGON2_PASSES,
                        memory_kib: int = ARGON2_MEMORY_KIB,
                        lanes: int = ARGON2_LANES):
    """
    (AUK, Login Key). Both need the password AND the Secret Key; the HKDF
    labels keep them independent, so a server that sees the Login Key learns
    nothing about the AUK. The username is mixed in so two accounts with the
    same password and (impossibly) the same salt still differ.
    """
    if not master_password:
        raise CryptoError("Enter the master password.")
    if len(secret_key) != SECRET_KEY_LEN or len(salt) != SALT_LEN:
        raise ValueError("bad Secret Key or salt length")
    _check_cost(passes, memory_kib, lanes)
    stretched = argon2id(_normalise(master_password), salt, passes, memory_kib,
                         lanes)
    who = unicodedata.normalize("NFKC", username).encode("utf-8")
    auk = _hkdf(stretched, secret_key, b"PassMan3 account unlock key|" + who)
    login = _hkdf(stretched, secret_key, b"PassMan3 login key|" + who)
    return auk, login


# ===========================================================================
# Sealed containers (keyset, recovery copy)
# ===========================================================================
KEYSET_MAGIC = b"PMK3"
KEYSET_VERSION = 1
KDF_ARGON2ID = 1        # sealed under the AUK (master password + Secret Key)
KDF_NONE = 0            # sealed under a full-strength key (the Recovery Key)
_KEYSET_HEADER = struct.Struct(">4sBBIBB16s")   # magic ver kdf mem passes lanes salt


def seal_keyset(key: bytes, keyset: dict, salt: bytes, kdf: int = KDF_ARGON2ID,
                passes: int = ARGON2_PASSES, memory_kib: int = ARGON2_MEMORY_KIB,
                lanes: int = ARGON2_LANES) -> str:
    """
    The keyset as base64 text: a header (how to get the key back from the
    password: KDF, cost, salt) authenticated as AES-GCM associated data, so
    lowering the cost or swapping the salt in a file breaks decryption.
    """
    header = _KEYSET_HEADER.pack(KEYSET_MAGIC, KEYSET_VERSION, kdf, memory_kib,
                                 passes, lanes, salt)
    nonce = os.urandom(NONCE_LEN)
    body = json.dumps(keyset, separators=(",", ":"), sort_keys=True).encode()
    return _b64(header + nonce + AESGCM(key).encrypt(nonce, body, header))


def keyset_header(blob: str) -> dict:
    """What a sealed keyset says about its own key derivation -- read before
    the password is stretched, so the stored cost is the one used."""
    raw = _unb64(blob, "account file")
    if len(raw) < _KEYSET_HEADER.size + NONCE_LEN + 16:
        raise CryptoError("The account file is too short to be PassMan's.")
    magic, version, kdf, memory_kib, passes, lanes, salt = \
        _KEYSET_HEADER.unpack(raw[:_KEYSET_HEADER.size])
    if magic != KEYSET_MAGIC:
        raise CryptoError("That is not a PassMan 3 account file.")
    if version != KEYSET_VERSION:
        raise CryptoError("The account file was written by a newer PassMan; "
                          "update this one.")
    if kdf not in (KDF_ARGON2ID, KDF_NONE):
        raise CryptoError("The account file uses an unknown key derivation.")
    if kdf == KDF_ARGON2ID:
        _check_cost(passes, memory_kib, lanes)
    return {"kdf": kdf, "memory_kib": memory_kib, "passes": passes,
            "lanes": lanes, "salt": salt}


def open_keyset(key: bytes, blob: str) -> dict:
    keyset_header(blob)                      # format errors before key errors
    raw = _unb64(blob, "account file")
    header = raw[:_KEYSET_HEADER.size]
    nonce = raw[_KEYSET_HEADER.size:_KEYSET_HEADER.size + NONCE_LEN]
    try:
        body = AESGCM(key).decrypt(nonce, raw[_KEYSET_HEADER.size + NONCE_LEN:],
                                   header)
    except Exception:
        raise CryptoError("Wrong master password or Secret Key.") from None
    return json.loads(body)


def new_keyset() -> dict:
    """A fresh account: an X25519 key pair and the personal vault's key."""
    private = X25519PrivateKey.generate()
    return {"x25519_private": _b64(private.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption())),
            "personal_vault_key": _b64(os.urandom(KEY_LEN))}


def public_key_of(keyset: dict) -> bytes:
    private = X25519PrivateKey.from_private_bytes(
        _unb64(keyset["x25519_private"], "account key"))
    return private.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)


# ===========================================================================
# Wrapping a vault key to a member (sealed box)
# ===========================================================================
WRAP_VERSION = 1


def _wrap_context(vault_id: bytes, member: str) -> bytes:
    return (b"PassMan3 wrap|" + vault_id + b"|" +
            unicodedata.normalize("NFKC", member).encode("utf-8"))


def wrap_key(recipient_public: bytes, vault_key: bytes, vault_id: bytes,
             member: str) -> str:
    """
    ``vault_key`` sealed so only ``recipient_public``'s owner can open it:
    a one-off X25519 key, HKDF over the shared secret, AES-GCM. The vault id
    and member name are associated data, so a wrapped key cannot be passed
    off as another vault's or another person's.
    """
    ephemeral = X25519PrivateKey.generate()
    eph_pub = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))
    key = _hkdf(shared, eph_pub + recipient_public, b"PassMan3 wrap key")
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, vault_key, _wrap_context(vault_id, member))
    return _b64(bytes([WRAP_VERSION]) + eph_pub + nonce + ct)


def unwrap_key(keyset: dict, wrapped: str, vault_id: bytes, member: str) -> bytes:
    raw = _unb64(wrapped, "shared vault key")
    if len(raw) != 1 + 32 + NONCE_LEN + KEY_LEN + 16 or raw[0] != WRAP_VERSION:
        raise CryptoError("A shared vault key is damaged or from a newer PassMan.")
    eph_pub, nonce, ct = raw[1:33], raw[33:33 + NONCE_LEN], raw[33 + NONCE_LEN:]
    private = X25519PrivateKey.from_private_bytes(
        _unb64(keyset["x25519_private"], "account key"))
    shared = private.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = _hkdf(shared, eph_pub + public_key_of(keyset), b"PassMan3 wrap key")
    try:
        return AESGCM(key).decrypt(nonce, ct, _wrap_context(vault_id, member))
    except Exception:
        raise CryptoError("This shared vault key was not made for this account "
                          "and vault.") from None


def fingerprint(public_key: bytes) -> str:
    """Six groups of four digits, read aloud before the first share."""
    digest = hashlib.sha256(b"PassMan3 fingerprint" + public_key).digest()
    digits = str(int.from_bytes(digest[:12], "big") % 10 ** 24).zfill(24)
    return " ".join(digits[i:i + 4] for i in range(0, 24, 4))


# ===========================================================================
# PMV3: a vault's entries under its own key
# ===========================================================================
VAULT_MAGIC = b"PMV3"
VAULT_VERSION = 1
_VAULT_HEADER = struct.Struct(">4sB16sI")        # magic ver vault-id key-generation


def new_vault_id() -> bytes:
    return os.urandom(VAULT_ID_LEN)


def encrypt_vault(vault_key: bytes, vault_id: bytes, key_generation: int,
                  data: dict) -> str:
    header = _VAULT_HEADER.pack(VAULT_MAGIC, VAULT_VERSION, vault_id,
                                key_generation)
    nonce = os.urandom(NONCE_LEN)
    body = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return _b64(header + nonce + AESGCM(vault_key).encrypt(nonce, body, header))


def vault_header(blob: str) -> dict:
    raw = _unb64(blob, "vault")
    if len(raw) < _VAULT_HEADER.size + NONCE_LEN + 16:
        raise CryptoError("The vault file is too short to be a PassMan 3 vault.")
    magic, version, vault_id, generation = _VAULT_HEADER.unpack(
        raw[:_VAULT_HEADER.size])
    if magic != VAULT_MAGIC:
        raise CryptoError("That is not a PassMan 3 vault.")
    if version != VAULT_VERSION:
        raise CryptoError("The vault was written by a newer PassMan; update "
                          "this one.")
    return {"vault_id": vault_id, "key_generation": generation}


def decrypt_vault(vault_key: bytes, blob: str, expect_vault_id: bytes = None) -> dict:
    """
    The vault's data. ``expect_vault_id`` refuses a file that decrypts but
    belongs to another vault -- the header is authenticated, so it cannot be
    edited to pass.
    """
    head = vault_header(blob)
    if expect_vault_id is not None and not hmac.compare_digest(
            head["vault_id"], expect_vault_id):
        raise CryptoError("That file belongs to a different vault.")
    raw = _unb64(blob, "vault")
    header = raw[:_VAULT_HEADER.size]
    nonce = raw[_VAULT_HEADER.size:_VAULT_HEADER.size + NONCE_LEN]
    try:
        body = AESGCM(vault_key).decrypt(
            nonce, raw[_VAULT_HEADER.size + NONCE_LEN:], header)
    except Exception:
        raise CryptoError("The vault could not be decrypted: wrong key, or the "
                          "file is damaged.") from None
    return json.loads(body)


# ===========================================================================
# The 12-word recovery phrase (BIP39, English)
# ===========================================================================
PHRASE_WORDS = 12
_INDEX = {w: i for i, w in enumerate(WORDS)}


def entropy_to_phrase(entropy: bytes) -> str:
    """BIP39: 128 bits + the first 4 bits of their SHA-256 -> 12 words."""
    if len(entropy) != 16:
        raise ValueError("a 12-word phrase holds 16 bytes")
    bits = int.from_bytes(entropy, "big") << 4 | hashlib.sha256(entropy).digest()[0] >> 4
    return " ".join(WORDS[(bits >> (11 * (PHRASE_WORDS - 1 - i))) & 0x7FF]
                    for i in range(PHRASE_WORDS))


def new_recovery_phrase() -> str:
    return entropy_to_phrase(os.urandom(16))


def phrase_to_entropy(phrase: str) -> bytes:
    """The 16 bytes behind a typed phrase, or CryptoError naming the problem."""
    words = (phrase or "").lower().split()
    if len(words) != PHRASE_WORDS:
        raise CryptoError(f"The recovery phrase has {PHRASE_WORDS} words; "
                          f"{len(words)} were entered.")
    unknown = [f"{n}. \u201c{w}\u201d" for n, w in enumerate(words, 1)
               if w not in _INDEX]
    if unknown:
        raise CryptoError("Not in the word list: " + ", ".join(unknown) +
                          ". Check the spelling against your paper.")
    bits = 0
    for w in words:
        bits = bits << 11 | _INDEX[w]
    entropy = (bits >> 4).to_bytes(16, "big")
    if hashlib.sha256(entropy).digest()[0] >> 4 != bits & 0xF:
        raise CryptoError("Those words are all in the list, but not in this "
                          "order: two may be swapped or one replaced.")
    return entropy


def recovery_key(phrase: str, username: str) -> bytes:
    """
    The key that seals the recovery copy of the keyset. No slow KDF: the
    phrase is 128 random bits, already beyond guessing.
    """
    who = unicodedata.normalize("NFKC", username).encode("utf-8")
    return _hkdf(phrase_to_entropy(phrase), b"PassMan3 recovery",
                 b"PassMan3 recovery key|" + who)


# ===========================================================================
# One account, end to end
# ===========================================================================
def create_account(username: str, master_password: str,
                   passes: int = ARGON2_PASSES,
                   memory_kib: int = ARGON2_MEMORY_KIB,
                   lanes: int = ARGON2_LANES) -> dict:
    """
    Everything a new account needs, made on this device. The caller shows
    ``secret_key_text`` (Emergency Kit) and ``recovery_phrase`` once, stores
    the sealed blobs, and keeps ``login_key`` only to register with a server.
    """
    secret = new_secret_key()
    salt = os.urandom(SALT_LEN)
    auk, login = derive_account_keys(master_password, secret, username, salt,
                                     passes, memory_kib, lanes)
    keyset = new_keyset()
    phrase = new_recovery_phrase()
    return {
        "keyset": keyset,
        "public_key": public_key_of(keyset),
        "secret_key": secret,
        "secret_key_text": format_secret_key(secret),
        "recovery_phrase": phrase,
        "login_key": login,
        "sealed_keyset": seal_keyset(auk, keyset, salt, KDF_ARGON2ID, passes,
                                     memory_kib, lanes),
        "sealed_recovery": seal_keyset(recovery_key(phrase, username), keyset,
                                       bytes(SALT_LEN), KDF_NONE, 0, 0, 0),
    }


def unlock_account(username: str, master_password: str, secret_key: bytes,
                   sealed_keyset: str):
    """(keyset, login key) from the master password and the Secret Key."""
    head = keyset_header(sealed_keyset)
    if head["kdf"] != KDF_ARGON2ID:
        raise CryptoError("That is a recovery copy, not the account file.")
    auk, login = derive_account_keys(master_password, secret_key, username,
                                     head["salt"], head["passes"],
                                     head["memory_kib"], head["lanes"])
    return open_keyset(auk, sealed_keyset), login


def recover_account(username: str, phrase: str, sealed_recovery: str) -> dict:
    """The keyset from the recovery phrase alone (personal accounts)."""
    if keyset_header(sealed_recovery)["kdf"] != KDF_NONE:
        raise CryptoError("That is the account file, not its recovery copy.")
    try:
        return open_keyset(recovery_key(phrase, username), sealed_recovery)
    except CryptoError as e:
        if "Wrong master password" in str(e):
            raise CryptoError("That recovery phrase is not the one for this "
                              "account.") from None
        raise


def reseal_with_new_password(username: str, keyset: dict, new_password: str,
                             secret_key: bytes, passes: int = ARGON2_PASSES,
                             memory_kib: int = ARGON2_MEMORY_KIB,
                             lanes: int = ARGON2_LANES):
    """
    After a recovery or a password change: the same keyset (so every wrapped
    vault key still opens) under a new password, with a fresh salt.
    Returns (sealed keyset, new login key).
    """
    salt = os.urandom(SALT_LEN)
    auk, login = derive_account_keys(new_password, secret_key, username, salt,
                                     passes, memory_kib, lanes)
    return seal_keyset(auk, keyset, salt, KDF_ARGON2ID, passes, memory_kib,
                       lanes), login
