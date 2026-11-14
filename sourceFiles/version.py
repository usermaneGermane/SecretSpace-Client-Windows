"""
Single source of truth for the application version.

Read by gui.py for the labels shown in the UI. Bump this on release; keep it
in step with the vault container versions when the on-disk format changes.

A test version carries a pre-release tag, ``3.0.0-alpha.1``. Windows wants
four plain numbers for the exe and the installer, so :func:`file_version`
turns that into 3.0.0.1 (the fourth number is the pre-release's; a release
has 0).
"""

import re

__version__ = "4.0.0"

#: The container an account's vaults are written in (account_crypto).
VAULT_FORMAT = "SSV4"
#: What SecretSpace 3 wrote, which is read to convert an account, and the
#: 2.x container, which is read to import a vault (legacy_names).
OLDER_VAULT_FORMATS = ("PMV3", "PMV2")

_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-(?:alpha|beta|rc)\.(\d+))?")


def file_version(text: str = __version__) -> tuple:
    """(3, 0, 0, 1) for '3.0.0-alpha.1', (3, 0, 0, 0) for '3.0.0'."""
    m = _VERSION.fullmatch(text)
    if not m:
        raise ValueError(f"Not a SecretSpace version: {text!r}")
    return tuple(int(g or 0) for g in m.groups())


def version_string() -> str:
    """e.g. 'v3.0.0' — what the UI shows."""
    return f"v{__version__}"


def long_version_string() -> str:
    """e.g. 'SecretSpace v4.0.0 · vault format SSV4' — for the Settings footer."""
    return f"SecretSpace {version_string()} · vault format {VAULT_FORMAT}"
