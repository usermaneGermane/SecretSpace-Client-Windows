"""
SecretSpace 3.0 accounts on this device. Since phase 2 an account may also
live on a sync server (account_sync.py); this module stays files only.

An account replaces the 2.x "one vault file per user". It is a folder::

    <home>/accounts/<username>/
        account.json        nothing secret: mode, public key, the personal
                            vault's id, the Secret Key as this device keeps
                            it (secret_store), fingerprints seen
        keyset.pmk          the keyset, under master password + Secret Key
        recovery.pmk        the same keyset, under the 12-word phrase
        vaults/<id>.pmv3    a vault (+ .bak, the previous save, + .base,
                            the state last agreed with the server): the
                            personal one, and since phase 3 any further
                            vaults the account has (account.json "vaults")

``<home>`` is the folder that holds the 2.x ``vault`` folder (beside the app
for a lab copy, %APPDATA%\\SecretSpace when installed). 2.x vault files are only
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

#: What the personal vault is called wherever vaults are listed. It has no
#: stored name, and no other vault may take this one.
PERSONAL_NAME = "Personal"

#: What a member of a vault may do (the server enforces it; the app follows).
ROLE_OWNER, ROLE_EDITOR, ROLE_READER = "owner", "editor", "reader"
ROLES = (ROLE_OWNER, ROLE_EDITOR, ROLE_READER)


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
                         "SecretSpace version.")
    return info


def _write_info(username: str, info: dict) -> None:
    _write_text(_path(username, ACCOUNT_FILE),
                json.dumps(info, indent=2, sort_keys=True))


# ---------------------------------------------------------------------------
# One vault of an open account
# ---------------------------------------------------------------------------
def clean_vault_name(name: str) -> str:
    """A vault name as it is stored, or ValueError saying what is wrong."""
    name = " ".join((name or "").split())
    if not name:
        raise ValueError("Give the vault a name.")
    if len(name) > account_crypto.VAULT_NAME_CHARS or \
            len(name.encode("utf-8")) > account_crypto.VAULT_NAME_BYTES:
        raise ValueError(f"A vault name can be up to "
                         f"{account_crypto.VAULT_NAME_CHARS} characters.")
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError("A vault name cannot contain control characters.")
    return name


class VaultFile:
    """
    One vault of an unlocked account: its id, name and key in memory, its
    files on disk. Everything that reads, writes or syncs a vault goes
    through one of these, the personal vault and any other alike.
    """

    def __init__(self, username: str, vault_id: bytes, key: bytes, name: str,
                 personal: bool, generation: int = 0, role: str = ROLE_OWNER):
        self.id = vault_id
        self.hex = vault_id.hex()
        self.name = name
        self.personal = personal
        # How many times the vault's key was changed (a member removed);
        # written into each file's header so the server can refuse an upload
        # made under a key that is no longer the vault's.
        self.generation = generation
        self.role = role
        self._key = key
        self.path = os.path.join(account_dir(username), VAULTS_DIR,
                                 self.hex + VAULT_SUFFIX)

    @property
    def base_path(self) -> str:
        return self.path + vault.BASE_SUFFIX

    @property
    def has_file(self) -> bool:
        return os.path.exists(self.path)

    @property
    def can_write(self) -> bool:
        """May this account change the vault (owner or editor)?"""
        return self.role != ROLE_READER

    def encrypt(self, data: dict) -> str:
        """``data`` as a PMV3 blob under this vault's key."""
        return account_crypto.encrypt_vault(self._key, self.id, self.generation,
                                            vault.validate_vault(data))

    def decrypt(self, blob: str) -> dict:
        """A PMV3 blob of this vault (it must name this vault)."""
        return vault.validate_vault(account_crypto.decrypt_vault(
            self._key, blob, self.id))

    def load(self) -> dict:
        """The vault's data. Falls back to .bak like a 2.x vault does."""
        first_error = None
        for path in (self.path, self.path + vault.BACKUP_SUFFIX):
            if not os.path.exists(path):
                continue
            try:
                return self.decrypt(_read_text(path))
            except (ValueError, OSError) as e:      # CryptoError is a ValueError
                if first_error is None:
                    first_error = e
        raise first_error or FileNotFoundError(
            f"The vault “{self.name}” is missing on this PC.")

    def save(self, data: dict) -> None:
        vault._rotate_backup(self.path)
        _write_text(self.path, self.encrypt(data))

    def load_base(self):
        """
        The vault as last agreed with the server, or None -- as 2.x's
        vault.load_base: a missing or unreadable base only makes the next
        merge noisier, never destructive.
        """
        try:
            return self.decrypt(_read_text(self.base_path))
        except (OSError, ValueError):
            return None

    def save_base(self, data: dict, origin: dict) -> None:
        """Written at the very end of a successful sync, with the server and
        revision it was agreed at (sync_client.base_matches)."""
        data = dict(data)
        data[vault.BASE_ORIGIN_KEY] = origin
        _write_text(self.base_path, self.encrypt(data))

    def sealed_name(self) -> str:
        """The name as the server keeps it (it cannot read it)."""
        return account_crypto.seal_vault_name(self._key, self.id, self.name)

    def open_name(self, sealed: str) -> str:
        return account_crypto.open_vault_name(self._key, self.id, sealed)

    def remove_files(self) -> None:
        for path in (self.path, self.path + vault.BACKUP_SUFFIX, self.base_path):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass


# ---------------------------------------------------------------------------
# An open account
# ---------------------------------------------------------------------------
class Account:
    """An unlocked account: its keys in memory, its files on disk."""

    def __init__(self, username: str, info: dict, keyset: dict, secret: bytes,
                 login_key: bytes = None):
        self.username = username
        self.info = info
        self.keyset = keyset
        self._secret = secret
        # What logs this account in to its server (account_sync). Derived at
        # unlock from the password and the Secret Key, so it is kept only in
        # memory, like the keys it travels with.
        self.login_key = login_key
        self.vault_id = bytes.fromhex(info["personal_vault"])
        self._vault_key = account_crypto._unb64(keyset["personal_vault_key"],
                                                "vault key")
        # Keys of the further vaults, unwrapped once per unlock.
        self._vault_keys = {}

    @property
    def mode(self) -> str:
        return self.info.get("mode", MODE_PERSONAL)

    @property
    def fingerprint(self) -> str:
        """What this account's owner reads out to someone who is about to
        share a vault with them."""
        return account_crypto.account_fingerprint(
            account_crypto.public_key_of(self.keyset),
            account_crypto.signing_key_of(self.keyset))

    @property
    def signing_key(self) -> str:
        """The public signing key, as the server and other members get it."""
        return account_crypto._b64(account_crypto.signing_key_of(self.keyset))

    # -- other people ------------------------------------------------------------
    def contact(self, username: str):
        """
        The keys this device has seen for another account, or None:
        {"public_key", "signing_key" (bytes), "verified" (the fingerprint was
        compared by the user)}.
        """
        seen = self.info.get("fingerprints_seen")
        found = seen.get(username) if isinstance(seen, dict) else None
        if not isinstance(found, dict):
            return None
        try:
            return {"public_key": account_crypto._unb64(found["public_key"], "key"),
                    "signing_key": account_crypto._unb64(found["signing_key"], "key"),
                    "verified": bool(found.get("verified"))}
        except (KeyError, CryptoError):
            return None

    def remember_contact(self, username: str, public_key: bytes,
                         signing_key: bytes, verified: bool) -> None:
        """Keep an account's keys, so a later change of them is noticed."""
        info = dict(self.info)
        seen = dict(info.get("fingerprints_seen") or {})
        seen[username] = {"public_key": account_crypto._b64(public_key),
                          "signing_key": account_crypto._b64(signing_key),
                          "verified": bool(verified), "seen_at": vault.utc_now()}
        info["fingerprints_seen"] = seen
        _write_info(self.username, info)
        self.info = info

    def signing_key_for(self, username: str):
        """The key to check ``username``'s signatures with, or None."""
        if username == self.username:
            return account_crypto.signing_key_of(self.keyset)
        found = self.contact(username)
        return found["signing_key"] if found else None

    @property
    def secret_key_text(self) -> str:
        """For the Emergency Kit again (Settings)."""
        return account_crypto.format_secret_key(self._secret)

    # -- its vaults -----------------------------------------------------------
    @property
    def personal_id(self) -> str:
        return self.info["personal_vault"]

    def _extra(self) -> dict:
        """account.json's record of the vaults besides the personal one."""
        found = self.info.get("vaults")
        return found if isinstance(found, dict) else {}

    def vault_ids(self) -> list:
        """Every vault of the account, by id: the personal one first, then
        the others by name."""
        extra = self._extra()
        return [self.personal_id] + sorted(
            extra, key=lambda v: (str(extra[v].get("name", "")).lower(), v))

    def vault_record(self, vault_id: str) -> dict:
        """What account.json holds about a further vault ({} for the personal
        one): name, wrapped_key, on_server, gone_from_server, rename_pending,
        and since phase 4 role, key_generation and members (how many)."""
        return dict(self._extra().get(vault_id, {}))

    def vault_role(self, vault_id: str) -> str:
        if vault_id is None or vault_id == self.personal_id:
            return ROLE_OWNER
        role = self._extra().get(vault_id, {}).get("role")
        return role if role in ROLES else ROLE_OWNER

    def can_write(self, vault_id: str) -> bool:
        return self.vault_role(vault_id) != ROLE_READER

    def is_shared(self, vault_id: str) -> bool:
        """Is anyone else in this vault (as far as the last sync knew)?"""
        record = self._extra().get(vault_id, {})
        return int(record.get("members", 1) or 1) > 1 or \
            self.vault_role(vault_id) != ROLE_OWNER

    def vault_file(self, vault_id: str = None) -> VaultFile:
        """The vault with this id (the personal one when None)."""
        if vault_id is None or vault_id == self.personal_id:
            return VaultFile(self.username, self.vault_id, self._vault_key,
                             PERSONAL_NAME, True)
        record = self._extra().get(vault_id)
        if record is None:
            raise KeyError(f"This account has no vault {vault_id}.")
        key = self._vault_keys.get(vault_id)
        if key is None:
            key = account_crypto.unwrap_key(
                self.keyset, record["wrapped_key"], bytes.fromhex(vault_id),
                self.username)
            self._vault_keys[vault_id] = key
        return VaultFile(self.username, bytes.fromhex(vault_id), key,
                         record.get("name", ""), False,
                         int(record.get("key_generation", 0) or 0),
                         self.vault_role(vault_id))

    def _name_taken(self, name: str, except_id: str = None) -> bool:
        wanted = name.lower()
        if wanted == PERSONAL_NAME.lower():
            return True
        return any(str(r.get("name", "")).lower() == wanted
                   for v, r in self._extra().items() if v != except_id)

    def _write_vaults(self, extra: dict) -> None:
        info = dict(self.info)
        info["vaults"] = extra
        _write_info(self.username, info)
        self.info = info

    def create_vault(self, name: str) -> VaultFile:
        """
        A further vault, empty, on this device. Its key is random and kept
        wrapped to the account's own public key -- exactly how it will be
        handed to another member once vaults are shared.
        """
        name = clean_vault_name(name)
        if self._name_taken(name):
            raise ValueError(f"There is already a vault called “{name}”.")
        vault_id = account_crypto.new_vault_id()
        key = account_crypto.new_vault_key()
        wrapped = account_crypto.wrap_key(
            account_crypto.public_key_of(self.keyset), key, vault_id,
            self.username)
        made = VaultFile(self.username, vault_id, key, name, False)
        made.save({"accounts": []})
        extra = dict(self._extra())
        extra[made.hex] = {"name": name, "wrapped_key": wrapped,
                           "created_at": vault.utc_now(), "on_server": False}
        self._write_vaults(extra)                  # last: it makes it a vault
        self._vault_keys[made.hex] = key
        return made

    def adopt_vault(self, vault_id: str, wrapped_key: str, sealed_name: str,
                    role: str = ROLE_OWNER, key_generation: int = 0,
                    members: int = 1) -> VaultFile:
        """
        A vault the server holds for this account and this device does not
        have yet. The key must open with this account's key, and the name
        with the vault's -- otherwise it is not ours and nothing is written.
        """
        raw_id = bytes.fromhex(vault_id)
        key = account_crypto.unwrap_key(self.keyset, wrapped_key, raw_id,
                                        self.username)
        name = clean_vault_name(account_crypto.open_vault_name(key, raw_id,
                                                               sealed_name))
        # Two devices may each have made a vault of the same name while
        # offline: both are kept, and told apart.
        base, n = name, 2
        while self._name_taken(name, except_id=vault_id):
            name = f"{base} ({n})"
            n += 1
        extra = dict(self._extra())
        extra[vault_id] = {"name": name, "wrapped_key": wrapped_key,
                           "created_at": vault.utc_now(), "on_server": True,
                           "role": role if role in ROLES else ROLE_OWNER,
                           "key_generation": int(key_generation or 0),
                           "members": int(members or 1)}
        self._write_vaults(extra)
        self._vault_keys[vault_id] = key
        return self.vault_file(vault_id)

    def rekey_vault(self, vault_id: str, wrapped_key: str, generation: int) -> None:
        """
        The vault has a new key (a member was removed, here or by another
        owner): take it, and put this device's copy of the vault under it.
        ``wrapped_key`` must open with this account's key, or nothing changes.
        """
        if vault_id == self.personal_id or vault_id not in self._extra():
            raise ValueError("That vault has no key to change.")
        raw_id = bytes.fromhex(vault_id)
        new_key = account_crypto.unwrap_key(self.keyset, wrapped_key, raw_id,
                                            self.username)
        old = self.vault_file(vault_id)
        data = base = None
        if old.has_file:
            try:
                data = old.load()
            except (ValueError, OSError):
                data = None             # unreadable already: a sync refetches it
        base = old.load_base()
        extra = dict(self._extra())
        record = dict(extra[vault_id])
        record["wrapped_key"] = wrapped_key
        record["key_generation"] = int(generation)
        extra[vault_id] = record
        self._write_vaults(extra)
        self._vault_keys[vault_id] = new_key
        new = self.vault_file(vault_id)
        if data is not None:
            new.save(data)              # the old file becomes its .bak ...
        else:
            old.remove_files()
        # ... which, like the old base, is under the old key and unreadable
        # from now on.
        for stale in (new.path + vault.BACKUP_SUFFIX, new.base_path):
            try:
                os.remove(stale)
            except OSError:
                pass
        origin = (base or {}).pop(vault.BASE_ORIGIN_KEY, None)
        if base is not None and origin:
            new.save_base(base, origin)

    def rename_vault(self, vault_id: str, name: str, pending: bool = True) -> None:
        """``pending`` marks a name the server has not been told yet."""
        name = clean_vault_name(name)
        if vault_id == self.personal_id or vault_id not in self._extra():
            raise ValueError("That vault cannot be renamed.")
        if self._name_taken(name, except_id=vault_id):
            raise ValueError(f"There is already a vault called “{name}”.")
        extra = dict(self._extra())
        record = dict(extra[vault_id])
        record["name"] = name
        record["rename_pending"] = bool(pending and record.get("on_server"))
        extra[vault_id] = record
        self._write_vaults(extra)

    def mark_vault(self, vault_id: str, **flags) -> None:
        """Set on_server / gone_from_server / rename_pending for a vault."""
        extra = dict(self._extra())
        if vault_id not in extra:
            return
        record = dict(extra[vault_id])
        record.update(flags)
        extra[vault_id] = record
        self._write_vaults(extra)

    def delete_vault(self, vault_id: str) -> None:
        """Forget a further vault on this device: its record and its files.
        The caller has checked the password (and told the server first)."""
        if vault_id == self.personal_id or vault_id not in self._extra():
            raise ValueError("That vault cannot be deleted.")
        target = self.vault_file(vault_id)
        extra = dict(self._extra())
        del extra[vault_id]
        self._write_vaults(extra)              # first: no record, no vault
        self._vault_keys.pop(vault_id, None)
        target.remove_files()

    # -- the personal vault, as before phase 3 -----------------------------------
    @property
    def vault_path(self) -> str:
        return self.vault_file().path

    def load_vault(self) -> dict:
        return self.vault_file().load()

    def save_vault(self, data: dict) -> None:
        self.vault_file().save(data)

    def encrypt(self, data: dict) -> str:
        return self.vault_file().encrypt(data)

    def decrypt(self, blob: str) -> dict:
        return self.vault_file().decrypt(blob)

    @property
    def has_vault_file(self) -> bool:
        return self.vault_file().has_file

    # -- the server -----------------------------------------------------------
    @property
    def server(self) -> dict:
        """{"url", "ca_file"} of the server this account syncs with, or None."""
        found = self.info.get("server")
        return found if isinstance(found, dict) and found.get("url") else None

    def set_server(self, url, ca_file: str = "") -> None:
        """Remember the server (None forgets it). account.json only."""
        info = dict(self.info)
        before = (info.get("server") or {}).get("url")
        info["server"] = ({"url": url.rstrip("/"), "ca_file": ca_file or ""}
                          if url else None)
        if (info["server"] or {}).get("url") != before:
            # Another server (or none) knows nothing of these vaults: they
            # are this device's again, to be put on whichever comes next.
            # (Roles and key generations were that server's too: on the next
            # one each vault starts as this account's own, at generation 0.)
            info["vaults"] = {
                v: {k: x for k, x in r.items()
                    if k not in ("on_server", "gone_from_server",
                                 "rename_pending", "role", "key_generation",
                                 "members")}
                for v, r in self._extra().items()}
        _write_info(self.username, info)
        self.info = info

    @property
    def base_path(self) -> str:
        return self.vault_file().base_path

    def load_base(self):
        return self.vault_file().load_base()

    def save_base(self, data: dict, origin: dict) -> None:
        self.vault_file().save_base(data, origin)

    def check_password(self, password: str) -> bool:
        """Is this the master password? (Re-derives: 2FA reveal, delete.)"""
        try:
            account_crypto.unlock_account(self.username, password, self._secret,
                                          _read_text(_path(self.username,
                                                           KEYSET_FILE)))
            return True
        except (CryptoError, OSError):
            return False

    def change_password(self, new_password: str, before_write=None) -> None:
        """
        The same keyset under a new password, so the vault file is not
        touched. The old keyset.pmk is replaced, not kept: a .bak of it would
        still open with the old password.

        ``before_write(sealed_keyset, login_key)`` runs before anything here
        is written; account_sync passes one that tells the server. If it
        raises, nothing changes on this device either, so the two can never
        disagree about the password.
        """
        sealed, login = account_crypto.reseal_with_new_password(
            self.username, self.keyset, new_password, self._secret,
            account_crypto.ARGON2_PASSES, account_crypto.ARGON2_MEMORY_KIB,
            account_crypto.ARGON2_LANES)
        if before_write is not None:
            before_write(sealed, login)
        info = dict(self.info)
        # Under the password scheme the stored Secret Key is sealed with the
        # password too; DPAPI does not care, but re-protecting is harmless.
        info["secret_key"] = secret_store.protect(self._secret, self.username,
                                                  new_password)
        _write_text(_path(self.username, KEYSET_FILE), sealed)
        _write_info(self.username, info)
        self.info = info
        self.login_key = login

    def sealed_files(self) -> dict:
        """The sealed keyset and recovery copy, as stored -- what a server
        keeps so another device can sign in."""
        return {"keyset": _read_text(_path(self.username, KEYSET_FILE)),
                "recovery": _read_text(_path(self.username, RECOVERY_FILE))}


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
        self.fingerprint = account_crypto.account_fingerprint(
            made["public_key"], account_crypto.signing_key_of(made["keyset"]))

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
        # This user's only, as the 2.x vault folder is on Linux: the other
        # users of the machine cannot even list whose accounts are here.
        os.makedirs(accounts_dir(), mode=0o700, exist_ok=True)
        os.mkdir(folder, 0o700)
        try:
            _write_text(os.path.join(folder, KEYSET_FILE), made["sealed_keyset"])
            _write_text(os.path.join(folder, RECOVERY_FILE),
                        made["sealed_recovery"])
            account = Account(username, info, made["keyset"], made["secret_key"],
                              made["login_key"])
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
    keyset, login = account_crypto.unlock_account(username, password, secret,
                                                  sealed)
    if typed is not None:
        info = dict(info)
        info["secret_key"] = secret_store.protect(typed, username, password)
        _write_info(username, info)
    return Account(username, info, keyset, secret, login)


# ---------------------------------------------------------------------------
# An account that came from a server
# ---------------------------------------------------------------------------
def stored_secret(username: str, password: str) -> bytes:
    """
    The Secret Key this device keeps for an account, or SecretKeyNeeded --
    also when it is sealed under a password that is no longer the account's
    (changed on another device), since then only the Emergency Kit helps.
    """
    info = _read_info(username)
    try:
        return secret_store.unprotect(info.get("secret_key"), username, password)
    except (secret_store.Unavailable, CryptoError):
        raise SecretKeyNeeded(username) from None


def adopt_from_server(username: str, me: dict, keyset: dict, secret: bytes,
                      login_key: bytes, password: str, server: dict) -> Account:
    """
    Write what a server holds for an account onto this device: a new device
    signing in, or this device catching up with a password changed on
    another. ``keyset`` is ``me["keyset"]`` already opened by the caller, so
    a wrong password or Secret Key never gets this far.

    An account already here keeps its vault files (the next sync merges
    them); only its keys and the Secret Key's protection are replaced. One
    with the same name but another personal vault is someone else's, and is
    left alone.
    """
    vault_id = me["personal_vault"]
    folder = account_dir(username)
    if account_exists(username):
        info = _read_info(username)
        if info.get("personal_vault") != vault_id:
            raise FileExistsError(
                f"This PC already has a different account called "
                f"\u201c{username}\u201d. Delete or rename it first.")
        info = dict(info)
    elif os.path.exists(folder):
        raise FileExistsError(
            f"A folder for \u201c{username}\u201d is already there ({folder}) "
            "but holds no account. Move it away to use this name.")
    else:
        os.makedirs(accounts_dir(), mode=0o700, exist_ok=True)
        os.mkdir(folder, 0o700)
        info = {"format": ACCOUNT_FORMAT, "username": username,
                "mode": MODE_PERSONAL, "created_at": vault.utc_now(),
                "personal_vault": vault_id, "fingerprints_seen": {},
                "vaults": {}}
    info.update({"public_key": me["public_key"], "server": server,
                 "secret_key": secret_store.protect(secret, username, password)})
    _write_text(os.path.join(folder, KEYSET_FILE), me["keyset"])
    _write_text(os.path.join(folder, RECOVERY_FILE), me["recovery"])
    _write_info(username, info)                 # last: it makes it an account
    return Account(username, info, keyset, secret, login_key)


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
def write_emergency_kit(path: str, username: str, secret_key_text: str) -> None:
    """Save the kit readable by this user only: it holds the Secret Key."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.chmod(path, 0o600)             # an existing file keeps its mode
    except OSError:
        pass
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(emergency_kit_text(username, secret_key_text))


def emergency_kit_text(username: str, secret_key_text: str, created: str = "") -> str:
    """The Emergency Kit as a text file (Save Emergency Kit…)."""
    return "\n".join([
        "SecretSpace Emergency Kit",
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
