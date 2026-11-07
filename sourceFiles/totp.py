"""
2FA codes (TOTP, RFC 6238) from the secret stored with an entry.

Made here on this PC with the standard library -- no network, no new
dependency. The stored secret is accepted in the two forms people paste:

- the plain secret a site shows under its QR code ("JBSW Y3DP EHPK 3PXP"):
  base32, spaces, dashes and lower case allowed; 6 digits every 30 seconds
  with SHA-1, which is what nearly every site uses;
- an ``otpauth://totp/...`` link, as exported by authenticator apps and
  password managers, which may also set ``digits``, ``period`` and
  ``algorithm``.

Nothing here touches the vault. ``parse`` raises ValueError with a sentence
the user can act on; the dialogs show it as is.
"""

import base64
import hashlib
import hmac
import struct
import time
from collections import namedtuple
from urllib.parse import parse_qs, unquote, urlparse

#: What a stored secret says about making codes.
Params = namedtuple("Params", "key digits period algorithm")

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256,
              "SHA512": hashlib.sha512}
DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30


def _decode_secret(text: str) -> bytes:
    cleaned = "".join(text.split()).replace("-", "").upper().rstrip("=")
    if not cleaned:
        raise ValueError("The 2FA secret is empty.")
    bad = sorted({c for c in cleaned if c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"})
    if bad:
        raise ValueError("A 2FA secret uses only the letters A-Z and the "
                         "digits 2-7; this one also has "
                         + " ".join(repr(c) for c in bad) + ".")
    try:
        key = base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except Exception:
        raise ValueError("That 2FA secret is not complete: some characters "
                         "seem to be missing.") from None
    if len(key) < 10:
        raise ValueError("That 2FA secret is too short to be a real one "
                         "(fewer than 16 characters).")
    return key


def parse(stored: str) -> Params:
    """The code settings in a stored secret, or ValueError saying why not."""
    stored = (stored or "").strip()
    if not stored.lower().startswith("otpauth://"):
        return Params(_decode_secret(stored), DEFAULT_DIGITS, DEFAULT_PERIOD,
                      "SHA1")

    url = urlparse(stored)
    if url.netloc.lower() != "totp":
        raise ValueError("Only time-based codes (otpauth://totp/...) are "
                         "supported, not otpauth://" + url.netloc + ".")
    query = {k.lower(): v[-1] for k, v in parse_qs(url.query).items()}
    if "secret" not in query:
        raise ValueError("That otpauth:// link has no secret in it.")
    key = _decode_secret(unquote(query["secret"]))

    algorithm = query.get("algorithm", "SHA1").upper().replace("-", "")
    if algorithm not in ALGORITHMS:
        raise ValueError(f"The algorithm {algorithm} is not supported "
                         "(SHA1, SHA256 or SHA512).")
    try:
        digits = int(query.get("digits", DEFAULT_DIGITS))
        period = int(query.get("period", DEFAULT_PERIOD))
    except ValueError:
        raise ValueError("The digits or period in that otpauth:// link is "
                         "not a number.") from None
    if not 6 <= digits <= 8:
        raise ValueError("Codes must have 6 to 8 digits.")
    if not 1 <= period <= 300:
        raise ValueError("The code period must be 1 to 300 seconds.")
    return Params(key, digits, period, algorithm)


def check(stored: str) -> str:
    """'' if codes can be made from ``stored`` (or it is empty), else why not."""
    if not (stored or "").strip():
        return ""
    try:
        parse(stored)
        return ""
    except ValueError as e:
        return str(e)


def code(params: Params, at: float = None) -> str:
    """The code for the moment ``at`` (Unix time; now by default)."""
    at = time.time() if at is None else at
    counter = int(at // params.period)
    mac = hmac.new(params.key, struct.pack(">Q", counter),
                   ALGORITHMS[params.algorithm]).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** params.digits).zfill(params.digits)


def seconds_left(params: Params, at: float = None) -> int:
    """Whole seconds until the code changes (1 to period)."""
    at = time.time() if at is None else at
    return params.period - int(at % params.period)


def spaced(digits: str) -> str:
    """'123456' -> '123 456', '12345678' -> '1234 5678', for reading aloud."""
    half = (len(digits) + 1) // 2 if len(digits) != 6 else 3
    return digits[:half] + " " + digits[half:]
