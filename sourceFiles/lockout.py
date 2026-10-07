"""
Rate limiting for master-password attempts at the unlock screen.

What this does: makes repeated guessing through the UI slow, and survives the
app being closed and reopened (the counters live in config.json).

What this does NOT do, and cannot: protect the vault file itself. Anyone who
can copy ``<user>.vault.enc`` can attack it offline with no rate limit at all
— that is what the KDF cost in crypto_utils is for. Deleting config.json or
moving the system clock backwards also clears a penalty. Treat this as a
speed bump against someone sitting at the keyboard, not as a security
boundary.
"""

import time

import appconfig

_KEY = "unlock_failures"

#: Wrong attempts allowed before any delay kicks in.
FREE_ATTEMPTS = 3

#: Seconds to wait after the 4th, 5th, 6th ... consecutive failure.
PENALTIES = (5, 15, 60, 300)


def _load() -> dict:
    data = appconfig.load_config().get(_KEY)
    return data if isinstance(data, dict) else {}


def _store(state: dict) -> None:
    appconfig.save_config(**{_KEY: state})


def _entry(state, username):
    entry = state.get(username)
    return entry if isinstance(entry, dict) else {}


def penalty_for(failures: int) -> int:
    """Seconds of lockout earned by ``failures`` consecutive wrong attempts."""
    if failures <= FREE_ATTEMPTS:
        return 0
    return PENALTIES[min(failures - FREE_ATTEMPTS, len(PENALTIES)) - 1]


def remaining(username: str, now: float = None) -> int:
    """Seconds the user must still wait, or 0 when an attempt is allowed."""
    now = time.time() if now is None else now
    until = _entry(_load(), username).get("until", 0)
    try:
        return max(0, int(round(float(until) - now)))
    except (TypeError, ValueError):
        return 0


def record_failure(username: str, now: float = None) -> int:
    """Count a wrong password. Returns the seconds of lockout now in force."""
    now = time.time() if now is None else now
    state = _load()
    entry = _entry(state, username)
    try:
        failures = int(entry.get("failures", 0)) + 1
    except (TypeError, ValueError):
        failures = 1

    wait = penalty_for(failures)
    state[username] = {"failures": failures, "until": now + wait}
    _store(state)
    return wait


def reset(username: str) -> None:
    """Clear the counter after a successful unlock."""
    state = _load()
    if username in state:
        del state[username]
        _store(state)


def failures(username: str) -> int:
    """Consecutive failures recorded for a user."""
    try:
        return int(_entry(_load(), username).get("failures", 0))
    except (TypeError, ValueError):
        return 0
