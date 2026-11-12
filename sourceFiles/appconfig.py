"""
Non-secret user preferences (last username, auto-lock delay).

Never put anything sensitive in here: this file is plain JSON sitting next to
the vault. Writes are best effort -- a read-only install directory must not
stop the app from running.
"""

import os
import json

from vault import get_home_dir, SORT_ORDERS

#: Minutes of inactivity before the vault locks itself. 0 disables auto-lock.
DEFAULT_AUTOLOCK_MINUTES = 10
AUTOLOCK_CHOICES = (0, 1, 5, 10, 30)


def config_file() -> str:
    return os.path.join(get_home_dir(), "config.json")


def load_config() -> dict:
    try:
        with open(config_file(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_config(**updates) -> bool:
    """Merge ``updates`` into the stored config. Returns whether it stuck."""
    cfg = load_config()
    cfg.update(updates)
    try:
        os.makedirs(os.path.dirname(config_file()), exist_ok=True)
        with open(config_file(), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception:
        return False       # preferences are best-effort, never block the app


def autolock_minutes() -> int:
    """Configured auto-lock delay in minutes, clamped to something sane."""
    try:
        value = int(load_config().get("autolock_minutes",
                                      DEFAULT_AUTOLOCK_MINUTES))
    except (TypeError, ValueError):
        return DEFAULT_AUTOLOCK_MINUTES
    return value if 0 <= value <= 24 * 60 else DEFAULT_AUTOLOCK_MINUTES


def appearance() -> str:
    """Light, dark or what the system uses; see theme.APPEARANCES."""
    value = load_config().get("appearance")
    return value if value in ("system", "light", "dark") else "system"


def sort_order() -> str:
    """How the account list is ordered; see vault.SORT_ORDERS."""
    value = load_config().get("sort_order")
    return value if value in SORT_ORDERS else SORT_ORDERS[0]
