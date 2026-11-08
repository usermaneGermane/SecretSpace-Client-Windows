"""
PassMan 3.0 accounts on this device -- phase 1: local only, no server.

An account replaces the 2.x "one vault file per user". It is a folder::

    <home>/accounts/<username>/
        account.json        nothing secret: mode, public key, the personal
                            vault's id, the Secret Key as this device keeps
                            it (secret_store), fingerprints seen
        keyset.pmk          the keyset, under master password + Secret Key
        recovery.pmk        the same keyset, under the 12-word phrase
        vaults/<id>.pmv3    the personal vault (+ .bak, the previous save)

``<home>`` is the folder that holds the 2.x ``vault`` folder (beside the app
for a lab copy, %APPDATA%\\PassMan when installed). 2.x vault files are only
ever *read*, by the importer; nothing here writes to them.

The cryptography is account_crypto; this module is files and lifecycle.
"""

import json
import os
import shutil

import account_crypto
import secret_store
import vault
from account_crypto import CryptoError

ACCOUNTS_DIR_NAME = "accounts"
ACCOUNT_FILE = "account.json"
KEYSET_FILE = "keyset.pmk"
RECOVERY_FILE = "recovery.pmk"
VAULTS_DIR = "vaults"
VAULT_SUFFIX = ".pmv3"
ACCOUNT_FORMAT = 1
MODE_PERSONAL = "personal"


class SecretKeyNeeded(Exception):
    """
    This device does not hold the account's Secret Key -- a copied folder on
    a new PC, another Windows user. Ask for the Emergency Kit and call
    :func:`unlock` again with ``secret_key_text``.
    """


# ---------------------------------------------------------------------------
# Where things are
# ---------------------------------------------------------------------------
def accounts_dir() -> str:
    """Beside the 2.x vault folder, so PASSMAN_DATA_DIR moves both."""
    return os.path.join(os.path.dirname(os.path.abspath(vault.get_data_dir())),
                        ACCOUNTS_DIR_NAME)


def account_dir(username: str) -> str:
    return os.path.join(accounts_dir(), vault.validate_username(username))


def _path(username: str, name: str) -> str:
    return os.path.join(account_dir(username), name)


def list_accounts() -> list:
    """Accounts on this PC, by name. A folder without account.json is not one."""
    root = accounts_dir()
    try:
        names = os.listdir(root)
    except OSError:
        return []
    found = []
    for name in names:
        try:
            vault.validate_username(name)
        except ValueError:
            continue
        if os.path.isfile(os.path.join(root, name, ACCOUNT_FILE)):
            found.append(name)
    return sorted(found, key=str.lower)


def account_exists(username: str) -> bool:
    return os.path.isfile(_path(username, ACCOUNT_FILE))


def _write_text(path: str, text: str) -> None:
    vault._write_file_atomic(path, text.encode("utf-8"))


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _read_info(username: str) -> dict:
    try:
        with open(_path(username, ACCOUNT_FILE), "r", encoding="utf-8") as f:
            info = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"There is no account “{username}” on this "
                                "PC.") from None
    except (OSError, ValueError):
        raise ValueError(f"The account file of “{username}” is damaged.") from None
    if not isinstance(info, dict) or info.get("format") != ACCOUNT_FORMAT:
        raise ValueError(f"The account “{username}” was made by another "
                         "PassMan version.")
    return info


def _write_info(username: str, info: dict) -> None:
    _write_text(_path(username, ACCOUNT_FILE),
                json.dumps(info, indent=2, sort_keys=True))


# ---------------------------------------------------------------------------
# An open account
# ---------------------------------------------------------------------------
class Account:
    """An unlocked account: its keys in memory, its files on disk."""

    def __init__(self, username: str, info: dict, keyset: dict, secret: bytes):
        self.username = username
        self.info = info
        self.keyset = keyset
        self._secret = secret
        self.vault_id = bytes.fromhex(info["personal_vault"])
        self._vault_key = account_crypto._unb64(keyset["personal_vault_key"],
                                                "vault key")

    @property
    def mode(self) -> str:
        return self.info.get("mode", MODE_PERSONAL)

    @property
    def fingerprint(self) -> str:
        return account_crypto.fingerprint(account_crypto.public_key_of(self.keyset))

    @property
    def secret_key_text(self) -> str:
        """For the Emergency Kit again (Settings)."""
        return account_crypto.format_secret_key(self._secret)

    @property
    def vault_path(self) -> str:
        return os.path.join(account_dir(self.username), VAULTS_DIR,
                            self.info["personal_vault"] + VAULT_SUFFIX)

    def load_vault(self) -> dict:
        """The personal vault. Falls back to .bak like a 2.x vault does."""
        first_error = None
        for path in (self.vault_path, self.vault_path + vault.BACKUP_SUFFIX):
            if not os.path.exists(path):
                continue
            try:
                data = account_crypto.decrypt_vault(
                    self._vault_key, _read_text(path), self.vault_id)
                return vault.validate_vault(data)
            except (ValueError, OSError) as e:      # CryptoError is a ValueError
                if first_error is None:
                    first_error = e
        raise first_error or FileNotFoundError("The personal vault is missing.")

    def save_vault(self, data: dict) -> None:
        blob = account_crypto.encrypt_vault(self._vault_key, self.vault_id, 0,
                                            vault.validate_vault(data))
        vault._rotate_backup(self.vault_path)
        _write_text(self.vault_path, blob)

    def check_password(self, password: str) -> bool:
        """Is this the master password? (Re-derives: 2FA reveal, delete.)"""
        try:
            account_crypto.unlock_account(self.username, password, self._secret,
                                          _read_text(_path(self.username,
                                                           KEYSET_FILE)))
            return True
        except (CryptoError, OSError):
            return False

    def change_password(self, new_password: str) -> None:
        """
        The same keyset under a new password, so the vault file is not
        touched. The old keyset.pmk is replaced, not kept: a .bak of it would
        still open with the old password.
        """
        sealed, _login = account_crypto.reseal_with_new_password(
            self.username, self.keyset, new_password, self._secret,
            account_crypto.ARGON2_PASSES, account_crypto.ARGON2_MEMORY_KIB,
            account_crypto.ARGON2_LANES)
        info = dict(self.info)
        # Under the password scheme the stored Secret Key is sealed with the
        # password too; DPAPI does not care, but re-protecting is harmless.
        info["secret_key"] = secret_store.protect(self._secret, self.username,
                                                  new_password)
        _write_text(_path(self.username, KEYSET_FILE), sealed)
        _write_info(self.username, info)
        self.info = info


# ---------------------------------------------------------------------------
# Making one
# ---------------------------------------------------------------------------
class NewAccount:
    """
    An account made in memory and not yet written. The create flow shows
    the Emergency Kit and the phrase first and writes only at the end, so
    closing the window half-way leaves nothing behind.
    """

    def __init__(self, username: str, password: str, made: dict):
        self.username = username
        self._password = password
        self._made = made
        self.secret_key_text = made["secret_key_text"]
        self.recovery_phrase = made["recovery_phrase"]
        self.fingerprint = account_crypto.fingerprint(made["public_key"])

    def save(self) -> Account:
        username = self.username
        if account_exists(username):
            raise FileExistsError(f"There is already an account “{username}”.")
        folder = account_dir(username)
        if os.path.exists(folder):
            raise FileExistsError(
                f"A folder for “{username}” is already there ({folder}) but "
                "holds no account. Move it away to use this name.")
        made = self._made
        vault_id = account_crypto.new_vault_id()
        info = {
            "format": ACCOUNT_FORMAT,
            "username": username,
            "mode": MODE_PERSONAL,
            "created_at": vault.utc_now(),
            "public_key": account_crypto._b64(made["public_key"]),
            "personal_vault": vault_id.hex(),
            "secret_key": secret_store.protect(made["secret_key"], username,
                                               self._password),
            "server": None,
            "fingerprints_seen": {},
        }
        os.makedirs(folder)
        try:
            _write_text(os.path.join(folder, KEYSET_FILE), made["sealed_keyset"])
            _write_text(os.path.join(folder, RECOVERY_FILE),
                        made["sealed_recovery"])
            account = Account(username, info, made["keyset"], made["secret_key"])
            account.save_vault({"accounts": []})
            _write_info(username, info)            # last: it makes it an account
        except BaseException:
            shutil.rmtree(folder, ignore_errors=True)
            raise
        self._password = None
        return account


def prepare_account(username: str, password: str) -> NewAccount:
    username = vault.validate_username(username)
    if not password:
        raise ValueError("Master password is required.")
    if account_exists(username):
        raise FileExistsError(f"There is already an account “{username}”.")
    made = account_crypto.create_account(
        username, password, account_crypto.ARGON2_PASSES,
        account_crypto.ARGON2_MEMORY_KIB, account_crypto.ARGON2_LANES)
    return NewAccount(username, password, made)


# ---------------------------------------------------------------------------
# Opening one
# ---------------------------------------------------------------------------
def unlock(username: str, password: str, secret_key_text: str = None) -> Account:
    """
    Open an account. Raises :class:`SecretKeyNeeded` when this device does
    not hold the Secret Key and none was given, and CryptoError("Wrong
    master password or Secret Key.") for a wrong one. A Secret Key typed in
    is stored (secret_store) once it has opened the account, so it is asked
    for once per device.
    """
    info = _read_info(username)
    sealed = _read_text(_path(username, KEYSET_FILE))
    typed = None
    if secret_key_text:
        typed = account_crypto.parse_secret_key(secret_key_text)
        secret = typed
    else:
        try:
            secret = secret_store.unprotect(info.get("secret_key"), username,
                                            password)
        except secret_store.Unavailable:
            raise SecretKeyNeeded(username) from None
    keyset, _login = account_crypto.unlock_account(username, password, secret,
                                                   sealed)
    if typed is not None:
        info = dict(info)
        info["secret_key"] = secret_store.protect(typed, username, password)
        _write_info(username, info)
    return Account(username, info, keyset, secret)


def check_recovery_phrase(username: str, phrase: str) -> bool:
    """Does this phrase open the account's recovery copy? (Phase 5 recovers.)"""
    try:
        account_crypto.recover_account(username, phrase,
                                       _read_text(_path(username, RECOVERY_FILE)))
        return True
    except (CryptoError, OSError):
        return False


def delete_account(username: str) -> None:
    """Remove the account folder. The caller has checked the password."""
    folder = account_dir(username)
    if not os.path.isfile(os.path.join(folder, ACCOUNT_FILE)):
        raise FileNotFoundError(f"There is no account “{username}” on this PC.")
    shutil.rmtree(folder)


# ---------------------------------------------------------------------------
# Emergency Kit
# ---------------------------------------------------------------------------
def emergency_kit_text(username: str, secret_key_text: str, created: str = "") -> str:
    """The Emergency Kit as a text file (Save Emergency Kit…)."""
    return "\n".join([
        "PassMan Emergency Kit",
        "=====================",
        "",
        f"Account:      {username}",
        f"Secret Key:   {secret_key_text}",
        "Server:       (none - this account is on this PC only)",
        "Master password: ______________________________",
        "",
        f"Made: {created or vault.utc_now()}",
        "",
        "You need the Secret Key and your master password to open this",
        "account on another PC, or on this one after Windows is reinstalled.",
        "Print this page or keep the file somewhere safe and offline. Do not",
        "keep it in the same place as your master password.",
        "",
        "Your 12-word recovery phrase is NOT on this page, on purpose: it",
        "opens the account on its own. Keep it apart from this kit.",
        "",
    ])
