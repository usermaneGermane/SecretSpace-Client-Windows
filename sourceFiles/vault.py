import os
import re
import sys
import csv
import json
import uuid
import hashlib
import tempfile
from datetime import datetime, timedelta, timezone

from crypto_utils import encrypt, decrypt, blob_iterations, DEFAULT_ITERATIONS

#: Suffix of the previous-generation copy kept beside every vault.
BACKUP_SUFFIX = ".bak"

#: Suffix of the "last known server state" copy kept beside every vault once
#: sync has run. merge_vaults needs it as the common ancestor -- without it a
#: deletion on one PC is indistinguishable from an addition on the other.
BASE_SUFFIX = ".base"
#: Key inside a sync base recording which server it was agreed with.
BASE_ORIGIN_KEY = "base_origin"

#: Fields an account may carry beyond site/username/password. Kept optional so
#: older vaults stay valid and entries without them stay small.
#:
#: ``updated_at`` and ``archived_at`` are UTC ISO-8601 strings. They exist for
#: display and for choosing a sensible default in the sync conflict dialog --
#: never for deciding a merge, because the two PCs' clocks disagree. That
#: decision belongs to the three-way merge in sync.py.
OPTIONAL_FIELDS = ("notes", "totp", "updated_at", "archived_at",
                   "history_cleared_at")

#: What a revision records, and what counts as an edit worth recording.
#: Everything the user can type into an entry -- not just the password, since
#: a changed username or site is just as worth being able to undo.
REVISION_FIELDS = ("site", "username", "password", "notes", "totp")

#: Earlier versions kept per entry. Old passwords are useful (a site that
#: still has the old one, an edit made by mistake) but they are also old
#: secrets sitting in the vault, so the list is kept short.
HISTORY_LIMIT = 10

#: Namespace for deriving a stable id for an entry that predates the id field.
#: This MUST stay fixed: two PCs holding the same pre-sync vault have to derive
#: the SAME id for the same entry, or the first sync sees two unrelated
#: entries and duplicates the whole vault. Random ids are only ever handed to
#: genuinely new entries.
_ID_NAMESPACE = uuid.UUID("1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed")


def utc_now() -> str:
    """Timestamp for updated_at / archived_at. UTC, so it reads the same on
    both machines."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id() -> str:
    """A fresh random id for a genuinely new entry."""
    return uuid.uuid4().hex


def legacy_id(site: str, username: str) -> str:
    """
    The id an entry written before this field existed gets on first load.

    Derived from its content rather than drawn at random, so that a vault
    already copied to two PCs backfills identically on both.
    """
    return uuid.uuid5(_ID_NAMESPACE, f"{site}\x00{username}").hex


# ==============================
# Vault File Management
# ==============================
#: Where vaults live, relative to the project root / the folder holding the exe.
VAULT_DIR_NAME = "vault"

#: What that folder was called in earlier versions. Still honoured so an
#: existing installation is not orphaned by the rename.
LEGACY_DIR_NAME = "data"


def get_app_dir() -> str:
    """
    The project root: the folder holding PassMan.exe when frozen, else the
    parent of ``sourceFiles`` where this module lives.

    Anchored to the executable, NOT the working directory, so shortcuts with
    odd "Start in" folders can't lose the vault. Both cases resolve to the
    same place, so a vault created by the exe is the one you see when running
    from source.
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    # .../PassMan/sourceFiles/vault.py -> .../PassMan
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


#: The installer puts a file of this name next to PassMan.exe. Its presence
#: means "installed copy": the program folder is replaced on upgrade and
#: removed on uninstall, so the user's data must live somewhere else.
INSTALLED_MARKER = "installed"


def is_installed() -> bool:
    return os.path.isfile(os.path.join(get_app_dir(), INSTALLED_MARKER))


def get_home_dir() -> str:
    """
    Where config.json and the vault folder live.

    Portable (no installer marker): the app folder, so the app and its data
    travel together on a USB stick. Installed: %APPDATA%\\PassMan, which
    survives upgrades and uninstalling and does not need the program folder
    to be writable.
    """
    if is_installed():
        base = os.environ.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming")
        return os.path.join(base, "PassMan")
    return get_app_dir()


def get_data_dir() -> str:
    """
    The vault directory: ``vault`` inside get_home_dir(). This is
    deliberately the ONLY place vaults are read from or written to — the
    user requires a single copy they control (no AppData mirrors, no
    automatic migration copies). Do not re-add code that copies vault files
    elsewhere. An installed copy keeps its one copy in %APPDATA%\\PassMan
    instead of next to the exe; that is a different home, not a mirror.

    If a folder from before the rename (``data``) is present and ``vault`` is
    not, the old one is used as-is. Nothing is moved or copied: an existing
    installation keeps working, and the user can rename the folder themselves
    whenever they like.

    PASSMAN_DATA_DIR overrides the location (used by tests).
    """
    override = os.environ.get("PASSMAN_DATA_DIR")
    if override:
        return override

    app_dir = get_home_dir()
    current = os.path.join(app_dir, VAULT_DIR_NAME)
    legacy = os.path.join(app_dir, LEGACY_DIR_NAME)
    if not os.path.isdir(current) and os.path.isdir(legacy):
        return legacy
    return current


# Usernames become filenames, so they must not be able to escape the data
# directory or collide with names Windows reserves for devices.
_VALID_USERNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._ -]{0,62})$")
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def validate_username(username: str) -> str:
    """
    Return the username if it is safe to use as a filename, else raise
    ValueError. Rejects path separators, traversal, control characters and
    Windows device names.
    """
    name = (username or "").strip()
    if not name:
        raise ValueError("Username is required.")
    if not _VALID_USERNAME.match(name):
        raise ValueError(
            "Usernames may only contain letters, digits, spaces, dots, "
            "hyphens and underscores, must start with a letter or digit, "
            "and can be at most 63 characters.")
    if name.rstrip(". ").lower() in _WINDOWS_RESERVED:
        raise ValueError(f"'{name}' is a reserved device name on Windows.")
    return name


def get_vault_path(username: str) -> str:
    """Return the file path for a user's vault."""
    return os.path.join(get_data_dir(), f"{validate_username(username)}.vault.enc")


def get_backup_path(username: str) -> str:
    """Path of the previous-generation copy kept beside a user's vault."""
    return get_vault_path(username) + BACKUP_SUFFIX


def list_users() -> list:
    """Usernames that have a vault in the data directory."""
    try:
        names = os.listdir(get_data_dir())
    except OSError:
        return []
    return sorted(n[: -len(".vault.enc")] for n in names
                  if n.endswith(".vault.enc"))


# ==============================
# Durable writes
# ==============================
def _write_file_atomic(path: str, payload: bytes) -> None:
    """
    Write ``payload`` to ``path`` so that a crash, power loss or full disk can
    never leave a half-written file behind.

    The old implementation opened the real vault with "wb", which truncates
    it before the new bytes land — an interruption there destroyed every
    stored password. Here the data goes to a temp file in the same directory,
    is flushed all the way to the platter, and only then replaced into place;
    os.replace is atomic on both POSIX and Windows.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)

    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        # Leave the existing file untouched; drop the partial temp file.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    # Persist the rename itself, so the file survives a power cut too.
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except (OSError, AttributeError):
        pass       # not supported on Windows; the replace is still atomic


def _rotate_backup(vault_file: str) -> None:
    """Keep the current vault as the .bak generation before overwriting it."""
    if not os.path.exists(vault_file):
        return
    try:
        with open(vault_file, "rb") as f:
            current = f.read()
    except OSError:
        return
    if not current:
        return
    try:
        _write_file_atomic(vault_file + BACKUP_SUFFIX, current)
    except OSError:
        pass       # a failed backup must never block the real save


# ==============================
# Vault schema
# ==============================
def validate_vault(data) -> dict:
    """
    Check that a decrypted blob really is a vault and normalise it.

    Decryption succeeding only proves the password was right; it says nothing
    about the shape of the JSON inside. Without this the GUI blew up with a
    bare KeyError after an apparently successful unlock.
    """
    if not isinstance(data, dict):
        raise ValueError("This file is not a PassMan vault.")
    accounts = data.get("accounts")
    if accounts is None:
        raise ValueError("This vault has no 'accounts' section; it may have "
                         "been written by another program.")
    if not isinstance(accounts, list):
        raise ValueError("This vault's 'accounts' section is malformed.")

    clean = []
    seen_ids = set()
    for entry in accounts:
        if not isinstance(entry, dict):
            continue           # skip junk rows rather than lose the whole vault
        row = {
            "site": str(entry.get("site", "")),
            "username": str(entry.get("username", "")),
            "password": str(entry.get("password", "")),
        }
        # Optional fields are only stored when present, so vaults that have
        # never held one stay byte-identical in shape to before.
        for key in OPTIONAL_FIELDS:
            value = str(entry.get(key, "") or "")
            if value:
                row[key] = value

        # Every entry carries an id: it is what the merge matches on, so it
        # has to survive a rename of the site or the username. An entry from
        # before the field existed is backfilled from its content, and only
        # falls back to a random id when that collides -- which happens when
        # the vault holds true duplicates of the same site+username.
        entry_id = str(entry.get("id", "") or "")
        if not entry_id or entry_id in seen_ids:
            entry_id = legacy_id(row["site"], row["username"])
        if entry_id in seen_ids:
            entry_id = new_id()
        seen_ids.add(entry_id)
        row["id"] = entry_id

        # Earlier versions. Absent rather than empty, like the optional
        # fields, so entries that were never edited stay small.
        raw_history = entry.get("history")
        if isinstance(raw_history, list):
            row["history"] = raw_history
        normalize_history(row)

        clean.append(row)
    data["accounts"] = clean
    return data


# ==============================
# Load / save
# ==============================
def create_new_user(username: str, master_password: str) -> None:
    """
    Creates a new vault file for a user.
    Raises an exception if the user already exists.
    """
    vault_file = get_vault_path(username)
    if os.path.exists(vault_file):
        raise FileExistsError(f"User '{username}' already exists!")
    if not master_password:
        raise ValueError("Master password is required.")

    _write_file_atomic(vault_file, encrypt(master_password, {"accounts": []}))


def load_vault(master_password: str, username: str) -> dict:
    """
    Loads and decrypts the vault for a given user.

    If the primary file is unreadable or corrupt, the .bak generation is
    tried before giving up, so a vault damaged by an interrupted write in an
    older version can still be recovered.
    """
    vault_file = get_vault_path(username)
    backup_file = vault_file + BACKUP_SUFFIX

    if not os.path.exists(vault_file) and not os.path.exists(backup_file):
        raise FileNotFoundError(f"User '{username}' does not exist!")

    first_error = None
    for path in (vault_file, backup_file):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "rb") as f:
                return validate_vault(decrypt(master_password, f.read()))
        except (ValueError, OSError) as e:
            if first_error is None:
                first_error = e
    raise first_error


def save_vault(master_password: str, vault_data: dict, username: str,
               rekey: bool = False) -> None:
    """
    Encrypts and saves the vault for a given user, atomically.

    Pass ``rekey=True`` when ``master_password`` has just changed. Normally the
    outgoing file is rotated into .bak, but after a password change that copy
    is still readable with the OLD password — and load_vault falls back to it,
    so the old password would keep working. On a rekey the backup is replaced
    with the new ciphertext instead of the old one.

    The sync base has the same problem and no such fix: it holds the server's
    state, which cannot be re-encrypted without the old password. It is
    dropped instead, so the next sync re-merges from scratch. That asks more
    questions than it needs to, but it never loses anything -- and leaving a
    base behind that the new password cannot open would silently degrade
    every later merge.
    """
    vault_file = get_vault_path(username)
    payload = encrypt(master_password, validate_vault(vault_data))
    if rekey:
        _write_file_atomic(vault_file + BACKUP_SUFFIX, payload)
        clear_base(username)
    else:
        _rotate_backup(vault_file)
    _write_file_atomic(vault_file, payload)


# ==============================
# Sync base ("last known server state")
# ==============================
def get_base_path(username: str) -> str:
    """Path of the sync base kept beside a user's vault."""
    return get_vault_path(username) + BASE_SUFFIX


def load_base(master_password: str, username: str):
    """
    The vault as it stood at the end of the last successful sync, or None if
    this PC has never synced.

    A missing or unreadable base is not an error: the merge falls back to
    treating every entry as new, which is noisier but never destructive.
    """
    path = get_base_path(username)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            return validate_vault(decrypt(master_password, f.read()))
    except (ValueError, OSError):
        return None


def save_base(master_password: str, vault_data: dict, username: str,
              origin=None) -> None:
    """
    Record the state both sides agreed on, at the END of a successful sync.

    Encrypted with the same master password as the vault itself -- it holds
    the same passwords, so it gets the same protection. It is rewritten on a
    master-password change for the same reason save_vault rewrites .bak.

    ``origin`` says which server and revision this state was agreed with
    (see sync_client.base_matches). It is stored in the base only, never in
    the vault: the vault is the same whichever server it syncs with.
    """
    data = dict(vault_data)
    if origin is not None:
        data[BASE_ORIGIN_KEY] = dict(origin)
    _write_file_atomic(get_base_path(username),
                       encrypt(master_password, validate_vault(data)))


def base_origin(base) -> dict:
    """The server and revision a base was agreed with; {} for a base from
    before origins were recorded."""
    origin = (base or {}).get(BASE_ORIGIN_KEY)
    return dict(origin) if isinstance(origin, dict) else {}


def clear_base(username: str) -> None:
    """Forget the sync base. The next sync then re-merges from scratch."""
    try:
        os.remove(get_base_path(username))
    except OSError:
        pass


def change_master_password(vault_data: dict, username: str,
                           old_password: str, new_password: str) -> None:
    """
    Re-encrypt everything this PC keeps for ``username`` under a new password.

    save_vault(rekey=True) has to drop the sync base, because it does not
    know the old password. Here both are known, so the base is carried
    across instead. That matters: without a base the next sync cannot tell
    which side changed what, and every entry that differs becomes a question
    for the user -- a password change would turn into a wall of conflicts.
    """
    base = load_base(old_password, username)
    save_vault(new_password, vault_data, username, rekey=True)
    if base is not None:
        save_base(new_password, base, username)


def needs_rekey(username: str) -> bool:
    """
    True when the stored vault was written with fewer KDF iterations than we
    now use, i.e. it should be transparently re-encrypted on next unlock.
    """
    try:
        with open(get_vault_path(username), "rb") as f:
            stored = blob_iterations(f.read())
    except (OSError, ValueError):
        return False
    return stored is not None and stored < DEFAULT_ITERATIONS


def delete_user(username: str, master_password: str) -> None:
    """
    Deletes the vault file of a user if the master password is correct.
    Raises an exception if the password is incorrect or file does not exist.
    """
    vault_file = get_vault_path(username)
    if not os.path.exists(vault_file):
        raise FileNotFoundError(f"User '{username}' does not exist!")

    # Verify master password before deleting
    try:
        _ = load_vault(master_password, username)
    except FileNotFoundError:
        raise
    except Exception:
        raise ValueError("Master password incorrect. Cannot delete user.")

    os.remove(vault_file)
    for leftover in (vault_file + BACKUP_SUFFIX, vault_file + BASE_SUFFIX):
        try:
            os.remove(leftover)
        except OSError:
            pass


# ==============================
# Backup / export
# ==============================
def export_encrypted(username: str, destination: str) -> str:
    """
    Copy the encrypted vault to ``destination`` verbatim. The copy stays
    protected by the same master password, so it is safe to keep anywhere.
    """
    with open(get_vault_path(username), "rb") as f:
        blob = f.read()
    _write_file_atomic(destination, blob)
    return destination


def export_csv(vault_data: dict, destination: str) -> int:
    """
    Write the vault to a plaintext CSV readable by browsers and other password
    managers. The caller MUST warn the user first: this file has no protection
    whatsoever. Returns the number of rows written.

    Archived entries are left out. This file is for feeding another password
    manager, and logins the user has retired should not come back to life in
    their browser.
    """
    accounts = active_accounts(validate_vault(vault_data))
    directory = os.path.dirname(os.path.abspath(destination))
    os.makedirs(directory, exist_ok=True)
    with open(destination, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "url", "username", "password", "notes", "totp"])
        for acc in accounts:
            writer.writerow([acc["site"], "", acc["username"], acc["password"],
                             acc.get("notes", ""), acc.get("totp", "")])
    return len(accounts)


def export_json(vault_data: dict, destination: str) -> int:
    """
    Plaintext JSON export. Same warning as :func:`export_csv` applies.

    Unlike the CSV, this one DOES carry archived entries, with their
    ``archived_at`` intact. It is the "take everything with me" export, and
    silently dropping the archive would make it a lossy one.
    """
    accounts = validate_vault(vault_data)["accounts"]
    _write_file_atomic(destination,
                       json.dumps({"accounts": accounts}, indent=2).encode("utf-8"))
    return len(accounts)


# ==============================
# Revision history
# ==============================
# Each entry may carry ``history``: earlier versions of its fields, newest
# first, at most HISTORY_LIMIT of them. A revision is
#
#     {"site", "username", "password", ["notes"], ["totp"],
#      "replaced_at": when it stopped being current (UTC ISO-8601),
#      "changed":     which fields the edit that replaced it changed,
#      "rid":         a stable id, derived from the two above}
#
# History is designed so it can never conflict in a sync: the merge takes the
# union of both sides' histories, and normalize_history turns any union into
# the same list on every PC. The one thing a union cannot express is removal,
# so "clear history" records a cut-off date instead of emptying the list --
# otherwise the other PC would hand the cleared revisions straight back.

_last_history_stamp = None


def history_now() -> str:
    """
    Timestamp for revisions and history clears, to the microsecond, and
    always later than the previous one this process handed out.

    Whole seconds are not enough here: the clear is a cut-off compared with
    <=, so a clear followed by an edit within the same second would drop the
    revision that edit just made. Microseconds are not enough on their own
    either: on Windows, Python 3.12's clock only moves every ~15 ms, so two
    quick edits could share a stamp and list in the wrong order. Hence the
    nudge forward by a microsecond when the clock has not moved. Every
    history timestamp uses this one format, so they still compare correctly
    as plain strings.
    """
    global _last_history_stamp
    now = datetime.now(timezone.utc)
    if _last_history_stamp is not None and now <= _last_history_stamp:
        now = _last_history_stamp + timedelta(microseconds=1)
    _last_history_stamp = now
    return now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def snapshot(entry: dict) -> dict:
    """The user-visible fields of an entry, as a revision records them."""
    snap = {}
    for field in REVISION_FIELDS:
        value = str(entry.get(field, "") or "")
        if value or field in ("site", "username", "password"):
            snap[field] = value
    return snap


def _content_key(fields: dict) -> tuple:
    return tuple(str(fields.get(f, "") or "") for f in REVISION_FIELDS)


def changed_fields(old: dict, new: dict) -> list:
    """Which of REVISION_FIELDS differ between two versions, in field order."""
    return [f for f in REVISION_FIELDS
            if str(old.get(f, "") or "") != str(new.get(f, "") or "")]


def _revision_id(rev: dict) -> str:
    # Derived, not random: a revision that reaches two PCs by different routes
    # must still be recognised as the same one.
    material = json.dumps([rev.get("replaced_at", ""), list(_content_key(rev))])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _clean_revision(raw):
    if not isinstance(raw, dict):
        return None
    rev = snapshot(raw)
    rev["replaced_at"] = str(raw.get("replaced_at", "") or "")
    changed = raw.get("changed")
    rev["changed"] = ([f for f in REVISION_FIELDS if f in changed]
                      if isinstance(changed, list) else [])
    rev["rid"] = _revision_id(rev)
    return rev


def normalize_history(entry: dict) -> dict:
    """
    Put an entry's history into its one canonical form, in place.

    Deterministic by design: two PCs holding the same set of revisions in any
    order, with any duplicates, end up with byte-identical lists -- so a merge
    never creates a difference that the next merge has to chase.

    - junk is dropped and every field is a string
    - revisions from before ``history_cleared_at`` are dropped
    - a revision identical to the current values is dropped (after a revert,
      the version you went back to is current, not history)
    - identical versions collapse to the most recent one
    - newest first, at most HISTORY_LIMIT
    """
    cutoff = str(entry.get("history_cleared_at", "") or "")
    current = _content_key(snapshot(entry))
    best = {}
    for raw in entry.get("history") or []:
        rev = _clean_revision(raw)
        if rev is None:
            continue
        if cutoff and rev["replaced_at"] <= cutoff:
            continue
        key = _content_key(rev)
        if key == current:
            continue
        kept = best.get(key)
        if kept is None or (rev["replaced_at"], rev["rid"]) > \
                (kept["replaced_at"], kept["rid"]):
            best[key] = rev
    history = sorted(best.values(), key=lambda r: (r["replaced_at"], r["rid"]),
                     reverse=True)[:HISTORY_LIMIT]
    if history:
        entry["history"] = history
    else:
        entry.pop("history", None)
    return entry


def history_signature(entry: dict) -> str:
    """Everything about an entry's history, for comparing two copies."""
    return json.dumps([entry.get("history") or [],
                       entry.get("history_cleared_at", "")], sort_keys=True)


def add_revision(entry: dict, old: dict, changed, at: str = None) -> dict:
    """Record ``old`` (a snapshot) as an earlier version of ``entry``."""
    rev = dict(snapshot(old))
    rev["replaced_at"] = at or history_now()
    rev["changed"] = list(changed)
    entry["history"] = list(entry.get("history") or []) + [rev]
    return normalize_history(entry)


def merge_history(target: dict, *others) -> dict:
    """
    Give ``target`` the union of its own history and the others', in place.
    The latest clear wins, so a clear on one PC reaches the rest.
    """
    pool = list(target.get("history") or [])
    cutoff = str(target.get("history_cleared_at", "") or "")
    for other in others:
        if not other:
            continue
        pool += list(other.get("history") or [])
        cutoff = max(cutoff, str(other.get("history_cleared_at", "") or ""))
    target["history"] = pool
    if cutoff:
        target["history_cleared_at"] = cutoff
    return normalize_history(target)


def update_entry(entry: dict, **fields) -> bool:
    """
    Change an entry's fields, keeping what they were as a revision.

    The single path for user edits, so history cannot be skipped by accident.
    Returns False, recording nothing, when nothing actually changed.
    """
    unknown = set(fields) - set(REVISION_FIELDS)
    if unknown:
        raise ValueError(f"Not editable fields: {sorted(unknown)}")
    old = snapshot(entry)
    for field, value in fields.items():
        value = str(value or "")
        if value or field in ("site", "username", "password"):
            entry[field] = value
        else:
            entry.pop(field, None)       # optional fields: absent, not empty
    changed = changed_fields(old, entry)
    if not changed:
        return False
    add_revision(entry, old, changed)
    touch(entry)
    return True


def find_revision(entry: dict, rid: str):
    for rev in entry.get("history") or []:
        if rev.get("rid") == rid:
            return rev
    return None


def revert_entry(entry: dict, rid: str) -> bool:
    """
    Make an earlier version current again.

    An edit like any other: the version being left goes into history, so a
    revert is itself undoable, and it syncs to other PCs as a normal change.
    """
    rev = find_revision(entry, rid)
    if rev is None:
        return False
    return update_entry(entry, **{f: rev.get(f, "") for f in REVISION_FIELDS})


def clear_history(entry: dict) -> None:
    """
    Forget an entry's earlier versions, here and -- via sync -- everywhere.

    Records a cut-off instead of just emptying the list: the merge takes the
    union of histories, so an empty list on this PC would be refilled from
    the other one on the next sync.
    """
    entry["history_cleared_at"] = history_now()
    normalize_history(entry)


# ==============================
# CRUD Operations
# ==============================
def touch(entry: dict) -> dict:
    """
    Stamp an entry as edited now.

    Call this from every code path that changes an entry's contents. It is
    deliberately NOT done inside validate_vault: that runs on every load and
    save, so stamping there would mark the whole vault as freshly edited and
    make every entry look like a conflict on the next sync.
    """
    entry["updated_at"] = utc_now()
    return entry


def add_account(vault: dict, site: str, username: str, password: str,
                notes: str = "", totp: str = "") -> dict:
    entry = {
        "id": new_id(),
        "site": site,
        "username": username,
        "password": password,
        "updated_at": utc_now(),
    }
    if notes:
        entry["notes"] = notes
    if totp:
        entry["totp"] = totp
    vault["accounts"].append(entry)
    return entry


def is_archived(entry: dict) -> bool:
    return bool(entry.get("archived_at"))


def active_accounts(vault: dict) -> list:
    """The entries the main list shows: everything not in the archive."""
    return [a for a in vault["accounts"] if not is_archived(a)]


#: Orders the main list can be shown in, as stored in config.json. The first
#: is the default.
SORT_ORDERS = ("modified_desc", "modified_asc", "name_asc", "name_desc")


def _name_key(entry: dict) -> tuple:
    return (entry.get("site", "").casefold(),
            entry.get("username", "").casefold())


def sort_accounts(accounts: list, order: str) -> list:
    """
    The entries in ``order`` (one of SORT_ORDERS), as a new list.

    By date, entries with no ``updated_at`` -- written before 2.0 and never
    edited since -- go last either way: an unknown date is neither newest
    nor oldest. Ties, and an unknown ``order``, fall back to A-Z.
    """
    by_name = sorted(accounts, key=_name_key, reverse=(order == "name_desc"))
    if order not in ("modified_desc", "modified_asc"):
        return by_name
    dated = [a for a in by_name if a.get("updated_at")]
    undated = [a for a in by_name if not a.get("updated_at")]
    # sorted() is stable, so entries stamped the same second stay A-Z.
    dated.sort(key=lambda a: str(a["updated_at"]),
               reverse=(order == "modified_desc"))
    return dated + undated


def archived_accounts(vault: dict) -> list:
    """Archived entries, most recently archived first."""
    return sorted((a for a in vault["accounts"] if is_archived(a)),
                  key=lambda a: a.get("archived_at", ""), reverse=True)


def find_entry(vault: dict, entry_id: str):
    """The entry with this id, or None. Identity for every operation below."""
    for acc in vault["accounts"]:
        if acc.get("id") == entry_id:
            return acc
    return None


def find_duplicate(vault: dict, site: str, username: str, exclude_id=None):
    """
    A live entry with this site and username (ignoring case and surrounding
    spaces), other than ``exclude_id``, or None. Used to warn before the
    same login is stored twice; archived entries do not count.
    """
    key = (site.strip().casefold(), username.strip().casefold())
    for acc in active_accounts(vault):
        if acc.get("id") != exclude_id and key == (
                acc["site"].strip().casefold(),
                acc["username"].strip().casefold()):
            return acc
    return None


def find_accounts(vault: dict, site: str, include_archived: bool = False) -> list:
    pool = vault["accounts"] if include_archived else active_accounts(vault)
    return [acc for acc in pool if acc["site"] == site]


def archive_account(vault: dict, entry_id: str) -> bool:
    """
    Retire an entry without destroying it -- what used to be a delete.

    The entry stays in the vault carrying ``archived_at``, which does double
    duty: the user can restore it, and the merge in sync.py reads it as a
    tombstone, so a removal propagates to the other PC instead of being
    resurrected by the next sync.
    """
    entry = find_entry(vault, entry_id)
    if entry is None or is_archived(entry):
        return False
    entry["archived_at"] = utc_now()
    return touch(entry) is not None


def restore_account(vault: dict, entry_id: str) -> bool:
    """Bring an archived entry back into the main list."""
    entry = find_entry(vault, entry_id)
    if entry is None or not is_archived(entry):
        return False
    del entry["archived_at"]
    return touch(entry) is not None


def purge_account(vault: dict, entry_id: str) -> bool:
    """
    Destroy an entry for good. The only operation in this module that loses
    data, so the UI must confirm it explicitly.

    Note for sync: a purge is a local act. If the other PC still holds the
    entry, the next merge treats it as an addition there and brings it back --
    purge on both, or archive instead, if you want it gone everywhere.
    """
    for i, acc in enumerate(vault["accounts"]):
        if acc.get("id") == entry_id:
            vault["accounts"].pop(i)
            return True
    return False


#: An archived_at this function trusts. Anything else -- hand-edited, from
#: another program -- is never auto-purged: comparing it as a string could
#: make it look ancient.
_ARCHIVED_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def archived_before(vault: dict, cutoff: str) -> list:
    """Archived entries whose archived_at is earlier than ``cutoff``."""
    return [a for a in vault["accounts"]
            if is_archived(a) and _ARCHIVED_AT.fullmatch(a["archived_at"])
            and a["archived_at"] < cutoff]


def purge_archived_before(vault: dict, cutoff: str) -> int:
    """
    Purge every entry archived before ``cutoff`` (a UTC ISO-8601 string).
    Returns how many went. Used by the optional auto-purge setting.
    """
    doomed = [a["id"] for a in archived_before(vault, cutoff)]
    for entry_id in doomed:
        purge_account(vault, entry_id)
    return len(doomed)


# ==============================
# Auto-purge of the archive
# ==============================
#: How many days an archived entry is kept before it is deleted for good.
#: Stored in the vault, not in config.json, so turning it on for one vault
#: never deletes anything from another vault on the same PC. Absent or 0:
#: archived entries stay until deleted by hand (the default).
ARCHIVE_PURGE_KEY = "archive_purge_days"
ARCHIVE_PURGE_CHOICES = (0, 30, 90, 180, 365)


def archive_purge_days(vault: dict) -> int:
    """The vault's keep-for limit in days; 0 means never purge."""
    try:
        days = int(vault.get(ARCHIVE_PURGE_KEY, 0) or 0)
    except (TypeError, ValueError):
        return 0
    return days if 0 < days <= 3650 else 0


def set_archive_purge_days(vault: dict, days: int) -> None:
    days = int(days)
    if days > 0:
        vault[ARCHIVE_PURGE_KEY] = days
    else:
        vault.pop(ARCHIVE_PURGE_KEY, None)


def purge_cutoff(days: int, now=None) -> str:
    """The archived_at before which an entry is older than ``days``."""
    now = now or datetime.now(timezone.utc)
    return (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def auto_purge_archive(vault: dict, now=None) -> int:
    """
    Apply the vault's keep-for limit; returns how many entries went. Run at
    unlock and when the setting changes. Like any purge it is a local act
    that sync passes on: the other PC drops the entries at its next sync,
    unless it edited them meanwhile, which shows as a conflict.
    """
    days = archive_purge_days(vault)
    if not days:
        return 0
    return purge_archived_before(vault, purge_cutoff(days, now))
