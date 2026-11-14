"""
The names from before the rename.

SecretSpace was called PassMan until November 2026, and SecretSpace 3 still
carried that name where nobody saw it: in the labels its keys are made
with, in the markers at the start of its files, in the name of its data
folder. SecretSpace 4 uses its own name everywhere.

This module is the one place the old names live. They are here to *read*
what an older version wrote, so that it can be converted, or -- for another
member's signature, which only its author could make again -- still be
checked. Nothing new is ever made with them, with one exception that the
format itself requires: a vault shared with someone whose app is still
SecretSpace 3 stays in the old format, so that they can keep opening it,
until every member has updated (see ``FORMAT`` in account_crypto).

Strings only, and no imports: anything may import this.
"""

#: What every label of a format-1 key or signature starts with.
LABEL_PREFIX = "PassMan3"

#: The first bytes of a format-1 keyset / recovery copy and vault, and of
#: the 2.x vault file that the importer reads.
KEYSET_MAGIC = b"PMK3"
VAULT_MAGIC = b"PMV3"
VAULT_2X_MAGIC = b"PMV2"

#: A Secret Key printed by SecretSpace 3 starts with this.
SECRET_KEY_PREFIX = "A3"

#: How a format-1 account's files are called inside its folder.
KEYSET_FILE = "keyset.pmk"
RECOVERY_FILE = "recovery.pmk"
VAULT_SUFFIX = ".pmv3"

#: What bound the stored Secret Key to its account on this device.
DEVICE_CONTEXT = b"PassMan 3 Secret Key\x00"

#: The data folder: in %APPDATA% on Windows, in ~/.local/share on Linux.
DATA_FOLDER_WINDOWS = "PassMan"
DATA_FOLDER_LINUX = "passman"

#: The variable that pointed tests and tools at another data folder.
DATA_DIR_VARIABLE = "PASSMAN_DATA_DIR"
