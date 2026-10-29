"""
Single source of truth for the application version.

Read by gui.py for the labels shown in the UI. Bump this on release; keep it
in step with the vault container version in crypto_utils.py when the on-disk
format changes.
"""

__version__ = "2.7.0"

#: Container version PassMan writes today (see crypto_utils.MAGIC).
VAULT_FORMAT = "PMV2"


def version_string() -> str:
    """e.g. 'v2.0.0' — what the UI shows."""
    return f"v{__version__}"


def long_version_string() -> str:
    """e.g. 'PassMan v2.0.0 · vault format PMV2' — for the Settings footer."""
    return f"PassMan {version_string()} · vault format {VAULT_FORMAT}"
