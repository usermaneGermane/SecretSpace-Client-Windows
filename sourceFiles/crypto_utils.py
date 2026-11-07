"""
Vault encryption for PassMan.

Container format (all vaults written by this version)::

    b"PMV2" || kdf_id(1) || iterations(4, big endian) || salt(16) || nonce(12) || ciphertext

the whole thing base64-encoded. The 9-byte header is passed to AES-GCM as
additional authenticated data, so the KDF parameters are covered by the
authentication tag: an attacker cannot rewrite the stored iteration count
down to 1 and hand the file back to us.

Vaults written before the header existed are still readable -- see
``_decrypt_legacy``. They are laid out as ``salt(16) || nonce(12) || ct``
with a fixed 200_000 PBKDF2 iterations and no AAD.
"""

import os
import base64
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==============================
# Container constants
# ==============================
MAGIC = b"PMV2"
KDF_PBKDF2_SHA256 = 1

SALT_LEN = 16
NONCE_LEN = 12
HEADER_LEN = len(MAGIC) + 1 + 4          # magic || kdf id || iterations

#: Iterations for newly written vaults. OWASP's current floor for
#: PBKDF2-HMAC-SHA256. Raising this is safe: the value used is stored in
#: every vault's header, so old vaults keep opening with their own count.
DEFAULT_ITERATIONS = 600_000

#: What headerless (pre-PMV2) vaults were written with.
LEGACY_ITERATIONS = 200_000

#: Refuse absurd iteration counts from a hostile or corrupt file, which would
#: otherwise hang the app for hours inside the KDF.
MAX_ITERATIONS = 10_000_000


# ==============================
# Key Derivation
# ==============================
def derive_key(master_password: str, salt: bytes,
               iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Derive a 256-bit AES key from the master password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,                # 256-bit key
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())


# ==============================
# Encryption
# ==============================
def encrypt(master_password: str, data: dict,
            iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Encrypt a dictionary into a base64 PMV2 blob."""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = MAGIC + bytes([KDF_PBKDF2_SHA256]) + iterations.to_bytes(4, "big")

    key = derive_key(master_password, salt, iterations)
    aesgcm = AESGCM(key)
    # header as AAD -> the KDF parameters are authenticated, not just carried.
    ciphertext = aesgcm.encrypt(nonce, json.dumps(data).encode(), header)

    return base64.b64encode(header + salt + nonce + ciphertext)


# ==============================
# Decryption
# ==============================
def _decrypt_legacy(master_password: str, raw: bytes) -> dict:
    """Read a pre-PMV2 vault: salt(16) || nonce(12) || ct, 200k iters, no AAD."""
    salt = raw[:SALT_LEN]
    nonce = raw[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = raw[SALT_LEN + NONCE_LEN:]
    key = derive_key(master_password, salt, LEGACY_ITERATIONS)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode())


def _decrypt_v2(master_password: str, raw: bytes) -> dict:
    header = raw[:HEADER_LEN]
    kdf_id = header[len(MAGIC)]
    if kdf_id != KDF_PBKDF2_SHA256:
        raise ValueError(f"Unsupported key-derivation function id {kdf_id}. "
                         "This vault needs a newer version of PassMan.")

    iterations = int.from_bytes(header[len(MAGIC) + 1:], "big")
    if not 1 <= iterations <= MAX_ITERATIONS:
        raise ValueError("Vault header declares an implausible iteration "
                         "count; refusing to open it.")

    body = raw[HEADER_LEN:]
    salt = body[:SALT_LEN]
    nonce = body[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = body[SALT_LEN + NONCE_LEN:]

    key = derive_key(master_password, salt, iterations)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    return json.loads(plaintext.decode())


def decrypt(master_password: str, encrypted_data: bytes) -> dict:
    """Decrypt a vault blob (either container version) into a dictionary."""
    try:
        raw = base64.b64decode(encrypted_data)
    except Exception as e:
        raise ValueError("Decryption failed. Wrong password or corrupted data.") from e

    if raw.startswith(MAGIC):
        decoder, minimum = _decrypt_v2, HEADER_LEN + SALT_LEN + NONCE_LEN
    else:
        decoder, minimum = _decrypt_legacy, SALT_LEN + NONCE_LEN

    if len(raw) <= minimum:
        raise ValueError("Decryption failed. Wrong password or corrupted data.")

    try:
        return decoder(master_password, raw)
    except ValueError:
        raise                      # our own explicit, more specific messages
    except Exception as e:
        raise ValueError("Decryption failed. Wrong password or corrupted data.") from e


def password_matches(typed: str, actual: str) -> bool:
    """
    Compare a typed master password with the one in memory, in constant
    time, so how long a wrong guess takes says nothing about how much of it
    was right.
    """
    import hmac
    return hmac.compare_digest((typed or "").encode("utf-8"),
                               (actual or "").encode("utf-8"))


def blob_iterations(encrypted_data: bytes):
    """
    Iteration count a stored blob was written with, or ``None`` if it cannot
    be determined. Used to decide whether a vault should be re-encrypted at
    the current cost on unlock.
    """
    try:
        raw = base64.b64decode(encrypted_data)
    except Exception:
        return None
    if not raw.startswith(MAGIC):
        return LEGACY_ITERATIONS if len(raw) > SALT_LEN + NONCE_LEN else None
    if len(raw) < HEADER_LEN:
        return None
    return int.from_bytes(raw[len(MAGIC) + 1:HEADER_LEN], "big")
