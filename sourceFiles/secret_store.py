"""
How a 3.0 account keeps its Secret Key on this device.

The Secret Key is typed once per device, from the Emergency Kit, and kept
here afterwards, so unlocking needs only the master password (as in
1Password). It is never stored in the clear:

* **Windows -- DPAPI** (``CryptProtectData``), tied to the Windows user. A
  copy of the account folder taken to another PC, or opened by another
  Windows user, cannot read it back; that device asks for the Emergency Kit
  once and stores the key its own way.
* **Elsewhere -- under the master password**: Argon2id with its own salt,
  then AES-GCM. A stolen account folder is then as strong as the master
  password (and Argon2id), never weaker -- the Secret Key's extra 128 bits
  protect what is on the *server*. The Linux keyring would do better, but it
  needs a library and a running keyring daemon; it can be added later as a
  third scheme without changing the others.

A record is a small dict stored in ``account.json``; ``scheme`` says which
of the two it is, so a file written on one OS is recognised (and refused
cleanly) on the other.
"""

import os
import sys
import unicodedata

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import account_crypto
from account_crypto import CryptoError, _b64, _unb64

SCHEME_DPAPI = "dpapi"
SCHEME_PASSWORD = "password"


class Unavailable(Exception):
    """This device cannot read the stored Secret Key: ask for the Emergency Kit."""


def default_scheme() -> str:
    return SCHEME_DPAPI if sys.platform == "win32" else SCHEME_PASSWORD


def _context(username: str) -> bytes:
    # Binds a record to its account, so one copied into another account's
    # file does not open there.
    return b"PassMan 3 Secret Key\x00" + username.encode("utf-8")


# ---------------------------------------------------------------------------
# DPAPI (Windows)
# ---------------------------------------------------------------------------
def _dpapi(data: bytes, entropy: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(raw):
        buf = ctypes.create_string_buffer(raw, len(raw))
        return Blob(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    data_in, keep1 = blob(data)
    extra, keep2 = blob(entropy)
    out = Blob()
    ui_forbidden = 0x1
    if protect:
        ok = crypt32.CryptProtectData(ctypes.byref(data_in), "PassMan Secret Key",
                                      ctypes.byref(extra), None, None,
                                      ui_forbidden, ctypes.byref(out))
    else:
        ok = crypt32.CryptUnprotectData(ctypes.byref(data_in), None,
                                        ctypes.byref(extra), None, None,
                                        ui_forbidden, ctypes.byref(out))
    if not ok:
        raise Unavailable("Windows could not read the stored Secret Key "
                          "(another PC or another Windows user).")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


# ---------------------------------------------------------------------------
# Under the master password (everywhere else)
# ---------------------------------------------------------------------------
def _password_key(password: str, salt: bytes, passes: int, memory_kib: int,
                  lanes: int) -> bytes:
    account_crypto._check_cost(passes, memory_kib, lanes)
    pw = unicodedata.normalize("NFKC", password).encode("utf-8")
    return account_crypto.argon2id(pw, salt, passes, memory_kib, lanes)


# ---------------------------------------------------------------------------
def protect(secret: bytes, username: str, password: str,
            scheme: str = None) -> dict:
    """A record that gives ``secret`` back to this device (see the module doc)."""
    scheme = scheme or default_scheme()
    if scheme == SCHEME_DPAPI:
        return {"scheme": SCHEME_DPAPI,
                "blob": _b64(_dpapi(secret, _context(username), True))}
    if scheme == SCHEME_PASSWORD:
        salt = os.urandom(account_crypto.SALT_LEN)
        nonce = os.urandom(account_crypto.NONCE_LEN)
        cost = (account_crypto.ARGON2_PASSES, account_crypto.ARGON2_MEMORY_KIB,
                account_crypto.ARGON2_LANES)
        key = _password_key(password, salt, *cost)
        return {"scheme": SCHEME_PASSWORD, "salt": _b64(salt),
                "nonce": _b64(nonce), "passes": cost[0],
                "memory_kib": cost[1], "lanes": cost[2],
                "sealed": _b64(AESGCM(key).encrypt(nonce, secret,
                                                   _context(username)))}
    raise ValueError(f"Unknown Secret Key scheme {scheme!r}")


def unprotect(record, username: str, password: str) -> bytes:
    """
    The Secret Key, or :class:`Unavailable` when this device cannot read the
    record (none stored, another PC's DPAPI, a scheme this OS lacks). A wrong
    master password under the password scheme is a :class:`CryptoError`,
    worded like the keyset's own, so the two failures read the same.
    """
    if not isinstance(record, dict):
        raise Unavailable("This PC does not hold the Secret Key yet.")
    scheme = record.get("scheme")
    if scheme == SCHEME_DPAPI:
        if sys.platform != "win32":
            raise Unavailable("The Secret Key was stored by Windows.")
        try:
            blob = _unb64(record.get("blob"), "Secret Key")
        except CryptoError:
            raise Unavailable("The stored Secret Key is damaged.") from None
        raw = _dpapi(blob, _context(username), False)
    elif scheme == SCHEME_PASSWORD:
        try:
            salt = _unb64(record["salt"], "Secret Key")
            nonce = _unb64(record["nonce"], "Secret Key")
            sealed = _unb64(record["sealed"], "Secret Key")
            cost = (int(record["passes"]), int(record["memory_kib"]),
                    int(record["lanes"]))
        except (KeyError, TypeError, ValueError):   # CryptoError is a ValueError
            raise Unavailable("The stored Secret Key is damaged.") from None
        key = _password_key(password, salt, *cost)
        try:
            raw = AESGCM(key).decrypt(nonce, sealed, _context(username))
        except Exception:
            raise CryptoError("Wrong master password or Secret Key.") from None
    else:
        raise Unavailable("The stored Secret Key is in a form this PassMan "
                          "does not know.")
    if len(raw) != account_crypto.SECRET_KEY_LEN:
        raise Unavailable("The stored Secret Key is damaged.")
    return raw
