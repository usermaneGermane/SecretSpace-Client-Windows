import re
import secrets
import string
import math

# ==============================
# Character classes
# ==============================
_UPPER = string.ascii_uppercase
_LOWER = string.ascii_lowercase
_DIGITS = string.digits
_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/|~"


def generate_password(length: int = 16, *, use_upper: bool = True,
                      use_lower: bool = True, use_digits: bool = True,
                      use_symbols: bool = True) -> str:
    """
    Generate a cryptographically secure random password.

    Backwards compatible: ``generate_password(16)`` still works and includes
    uppercase, lowercase, digits and symbols. The keyword flags let callers
    pick which character classes to include. At least one character from every
    selected class is guaranteed to appear (when the length allows).
    """
    if length < 6:
        raise ValueError("Password length should be at least 6 characters.")

    pools = []
    if use_upper:
        pools.append(_UPPER)
    if use_lower:
        pools.append(_LOWER)
    if use_digits:
        pools.append(_DIGITS)
    if use_symbols:
        pools.append(_SYMBOLS)

    # If the caller disabled everything, fall back to the full alphabet.
    if not pools:
        pools = [_UPPER, _LOWER, _DIGITS, _SYMBOLS]

    alphabet = "".join(pools)

    # Guarantee at least one character from each selected pool, then fill the
    # rest from the combined alphabet and shuffle so positions aren't fixed.
    required = [secrets.choice(pool) for pool in pools][:length]
    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    chars = required + remaining
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# A short list of the passwords that actually show up in breach dumps. Not a
# substitute for zxcvbn, but enough to stop the meter praising "Password1!".
_COMMON = {
    "password", "passwd", "pass", "secret", "letmein", "welcome", "admin",
    "administrator", "login", "master", "qwerty", "qwertyuiop", "azerty",
    "abc", "abcd", "abcdef", "abcdefg", "monkey", "dragon", "sunshine",
    "princess", "football", "baseball", "iloveyou", "trustno", "starwars",
    "superman", "batman", "shadow", "michael", "jennifer", "jordan",
    "hunter", "freedom", "whatever", "zaq", "asdf", "asdfgh", "qazwsx",
    "changeme", "default", "test", "guest", "root", "user", "temp",
}

_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm",
                  "azertyuiop", "qwertzuiop", "1234567890")


def _core(password: str) -> str:
    """Strip leading/trailing digits and symbols and common letter/digit
    substitutions, so 'P@ssw0rd123!' reduces to 'password'."""
    core = password.lower().strip()
    core = re.sub(r"^[^a-z]+|[^a-z0-9]+$", "", core)
    core = re.sub(r"[0-9]+$", "", core)
    for a, b in (("@", "a"), ("4", "a"), ("3", "e"), ("1", "l"), ("0", "o"),
                 ("$", "s"), ("5", "s"), ("7", "t"), ("!", "i")):
        core = core.replace(a, b)
    return core


def _shortest_repeated_unit(password: str) -> str:
    """'abcabcabc' -> 'abc'. Returns the password itself when it does not
    consist of a single repeated block."""
    n = len(password)
    for size in range(1, n // 2 + 1):
        if n % size == 0 and password[:size] * (n // size) == password:
            return password[:size]
    return password


def _is_common(password: str) -> bool:
    # Test the repeated unit too, so "qwertyuiopqwertyuiop" is caught by the
    # same rule as "qwertyuiop".
    for candidate in {_core(password), _core(_shortest_repeated_unit(password))}:
        if candidate in _COMMON:
            return True
        for row in _KEYBOARD_ROWS:
            if len(candidate) >= 4 and (candidate in row or candidate in row[::-1]):
                return True
    return False


def _effective_length(password: str) -> float:
    """
    Length discounted for structure. A character that merely repeats or
    continues the previous one carries far less information than a fresh one,
    so 'aaaaaaaa' should not score like eight random letters.
    """
    unit = _shortest_repeated_unit(password)
    if unit != password:
        # Repeating a block adds only the information needed to say "and again
        # N times", which grows logarithmically -- not once per copy.
        return _effective_length(unit) + math.log2(len(password) // len(unit))

    total = 1.0
    for prev, cur in zip(password, password[1:]):
        if cur == prev:
            total += 0.15                                   # runs: aaaa
        elif abs(ord(cur) - ord(prev)) == 1 and prev.isalnum() and cur.isalnum():
            total += 0.25                                   # sequences: abcd, 1234
        else:
            total += 1.0
    return total


def estimate_strength(password: str):
    """
    Roughly estimate password strength.

    Returns a tuple ``(label, fraction, color)`` where ``fraction`` is a
    0.0-1.0 value suitable for a progress bar and ``color`` is a hex string.

    The estimate is entropy over the character classes used, but computed on a
    structure-adjusted length: repeats, runs and keyboard walks are discounted
    and known breach-list passwords are capped at Weak. A plain
    ``len(password) * log2(pool)`` rated twenty 'a's as strong.
    """
    if not password:
        return ("", 0.0, "#9B9BA3")

    pool = 0
    if any(c in _LOWER for c in password):
        pool += 26
    if any(c in _UPPER for c in password):
        pool += 26
    if any(c in _DIGITS for c in password):
        pool += 10
    if any(c in _SYMBOLS for c in password):
        pool += len(_SYMBOLS)
    if any(c not in (_LOWER + _UPPER + _DIGITS + _SYMBOLS) for c in password):
        pool += 32  # anything else (spaces, unicode, etc.)

    entropy = _effective_length(password) * math.log2(max(pool, 1))
    if _is_common(password):
        entropy = min(entropy, 20.0)

    fraction = min(entropy / 120.0, 1.0)
    if entropy < 40:
        return ("Weak", fraction, "#E5534B")
    elif entropy < 70:
        return ("Fair", fraction, "#E0A030")
    elif entropy < 100:
        return ("Good", fraction, "#67C090")
    return ("Strong", fraction, "#3FB27F")


def copy_to_clipboard(text: str):
    """Copy the given text to the system clipboard."""
    import pyperclip          # imported lazily: generation needs no clipboard
    pyperclip.copy(text)
