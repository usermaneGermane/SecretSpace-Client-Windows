"""
Talking to the sync server.

Deliberately built on urllib from the standard library rather than requests:
the app ships as a PyInstaller bundle, and every dependency added here is
another package the build has to find and another way for the exe to fail on
a machine that cannot be debugged remotely. There is nothing here requests
would do better.

What crosses the network is the vault blob exactly as it sits on disk --
AES-256-GCM ciphertext. The master password is never sent, and the key is
never derived anywhere but locally, so a compromised server yields ciphertext
and an offline attack on the master password, nothing more.
"""

import json
import ssl
import hashlib
import urllib.error
import urllib.request

import vault
from crypto_utils import encrypt, decrypt
from sync import merge_vaults, resolve, merged_vault

#: Sync settings live inside the vault, under this key. The vault is
#: encrypted and the token is a credential, so config.json -- which is plain
#: JSON next to the vault -- is the wrong home for it. Syncing only happens
#: while the vault is unlocked anyway, so the lifetimes match.
SETTINGS_KEY = "sync"

DEFAULT_TIMEOUT = 20


class SyncError(Exception):
    """Anything that stopped a sync, phrased for the status bar."""


class Conflict409(SyncError):
    """The server moved on mid-sync. The caller should merge again."""


class ServerUnreachable(SyncError):
    """Nothing answered at the configured address -- the network, not the
    server, is the problem."""


class PasswordMismatch(SyncError):
    """
    The server's copy is encrypted under a different master password.

    That is not corruption: a password change on one PC leaves every other
    copy under the old one until they catch up. Which way to catch up is the
    whole question, and ``adopt`` answers it:

    ``adopt=True``   the server is NEWER -- the password was changed on
                     another PC. This PC should switch to that password.
    ``adopt=False``  the server is OLDER -- the password was changed here and
                     the server has not seen it yet. This PC keeps its
                     password and re-uploads under it.

    Either way the user has to supply the server's password once. ``wrong``
    is set when they already tried one and it did not open the copy.
    """

    def __init__(self, adopt: bool, wrong: bool = False):
        self.adopt = adopt
        self.wrong = wrong
        if adopt:
            message = ("The master password was changed on another PC. "
                       "Enter that new password to keep syncing.")
        else:
            message = ("The server still has this vault under your previous "
                       "master password. Enter it once to update the server.")
        super().__init__(message)


# ==============================
# Settings (stored inside the vault)
# ==============================
def get_settings(vault_data) -> dict:
    raw = (vault_data or {}).get(SETTINGS_KEY)
    return dict(raw) if isinstance(raw, dict) else {}


def set_settings(vault_data: dict, url: str, token: str, ca_file: str = "") -> dict:
    """
    Store the connection settings, keeping anything else sync has recorded.

    Replacing the whole dict would reset key_generation to 0 every time the
    address was edited, and the next password change would then look older
    than the server's copy -- this PC would be told to adopt a password that
    is really its own previous one.
    """
    settings = get_settings(vault_data)
    settings.update({"url": url.rstrip("/"), "token": token,
                     "ca_file": ca_file})
    vault_data[SETTINGS_KEY] = settings
    return settings


def key_generation(vault_data) -> int:
    """How many times this vault's master password has been changed, as far
    as sync knows. Travels inside the encrypted vault."""
    try:
        return max(0, int(get_settings(vault_data).get("key_generation", 0)))
    except (TypeError, ValueError):
        return 0


def set_key_generation(vault_data: dict, generation: int) -> None:
    settings = get_settings(vault_data)
    settings["key_generation"] = max(0, int(generation))
    vault_data[SETTINGS_KEY] = settings


def note_password_change(vault_data: dict) -> int:
    """
    Record a master-password change for sync. Call it before saving the
    re-encrypted vault, so the new number is inside what gets written.

    The counter is how the other PC tells "the server is ahead of me" from
    "I am ahead of the server" when neither password opens the other's copy.
    Nothing secret is in it; the server stores it in the clear.
    """
    generation = key_generation(vault_data) + 1
    set_key_generation(vault_data, generation)
    return generation


def _same_server(a: str, b: str) -> bool:
    return (a or "").rstrip("/").lower() == (b or "").rstrip("/").lower()


def base_origin_for(url: str, revision: int) -> dict:
    """What save_base records: the server and revision a base was agreed at."""
    return {"url": (url or "").rstrip("/"), "revision": int(revision)}


def base_matches(base, url: str, revision: int) -> bool:
    """
    Whether ``base`` describes the copy now on the server at ``url``.

    The merge reads every difference from the base as a change made on one
    side. Against another server -- or this one restored from an older
    backup -- those differences are only two copies that drifted apart, and
    trusting the base would quietly delete entries the other server never
    had and revert edits it never saw. So the base is trusted only when it
    was agreed with this same address and the server has not gone back to an
    earlier revision than the one recorded.

    A base from before origins were recorded has none and is trusted, as it
    always was -- refusing it would turn the first sync after the update into a
    review of every entry.
    """
    origin = vault.base_origin(base)
    if not origin:
        return True
    if origin.get("url") and not _same_server(origin["url"], url):
        return False
    try:
        return int(revision) >= int(origin.get("revision", 0))
    except (TypeError, ValueError):
        return True


def is_configured(vault_data) -> bool:
    settings = get_settings(vault_data)
    return bool(settings.get("url") and settings.get("token"))


# ==============================
# Transport
# ==============================
class SyncClient:
    def __init__(self, url: str, token: str, ca_file: str = "",
                 timeout: int = DEFAULT_TIMEOUT):
        if not url:
            raise SyncError("No server address configured.")
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.context = None

        if self.url.startswith("https://"):
            if ca_file:
                # A private server usually has a self-signed certificate.
                # Pinning it beats turning verification off: the VPN
                # authenticates the network path, not the service on it.
                self.context = ssl.create_default_context(cafile=ca_file)
            else:
                self.context = ssl.create_default_context()

    def _request(self, method: str, path: str, body=None, headers=None) -> dict:
        request = urllib.request.Request(
            f"{self.url}{path}", method=method,
            data=json.dumps(body).encode("utf-8") if body is not None else None)
        request.add_header("Authorization", f"Bearer {self.token}")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            request.add_header(key, value)

        try:
            with urllib.request.urlopen(request, timeout=self.timeout,
                                        context=self.context) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise self._http_error(e) from e
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, ssl.SSLError):
                raise SyncError(
                    f"The server's certificate was rejected ({reason}). If it "
                    f"is self-signed, point the CA file setting at it.") from e
            raise ServerUnreachable(
                f"Could not reach {self.url} ({reason}). Check the address, "
                f"and that this PC is on the server's network or VPN.") from e
        except (ValueError, OSError) as e:
            raise SyncError(f"Unexpected reply from the server: {e}") from e

    @staticmethod
    def _http_error(e) -> SyncError:
        try:
            message = json.loads(e.read().decode("utf-8")).get("error", "")
        except Exception:
            message = ""
        if e.code == 401:
            return SyncError("The server rejected the sync token.")
        if e.code == 409:
            return Conflict409(message or "The vault changed on the server.")
        if e.code == 428:
            return Conflict409("The server needs a fresh merge.")
        return SyncError(message or f"Server error {e.code}.")

    # -- endpoints --------------------------------------------------------
    def health(self) -> dict:
        return self._request("GET", "/health")

    def meta(self, username: str) -> dict:
        return self._request("GET", f"/vault/{username}/meta")

    def fetch(self, username: str) -> dict:
        """
        The stored copy with its metadata: ``blob`` (bytes, or None when
        nothing is stored yet), ``revision`` and ``key_generation``. A server
        from before password-change support reports no generation; that reads
        as 0, which is right for a vault whose password never changed.
        """
        payload = self._request("GET", f"/vault/{username}")
        blob = payload.get("blob")
        try:
            generation = max(0, int(payload.get("key_generation", 0)))
        except (TypeError, ValueError):
            generation = 0
        return {"blob": blob.encode("ascii") if blob else None,
                "revision": int(payload.get("revision", 0)),
                "key_generation": generation}

    def pull(self, username: str):
        """Return (blob or None, revision). None means nothing stored yet."""
        stored = self.fetch(username)
        return stored["blob"], stored["revision"]

    def push(self, username: str, blob: bytes, revision: int,
             key_generation=None, drop_history: bool = False) -> dict:
        """Store a new revision, refusing if the server has moved past
        ``revision``. ``drop_history`` asks the server to discard earlier
        revisions -- used after a password change."""
        headers = {"If-Match": str(revision)}
        if key_generation is not None:
            headers["X-PassMan-Key-Generation"] = str(int(key_generation))
        if drop_history:
            headers["X-PassMan-Drop-History"] = "1"
        return self._request(
            "PUT", f"/vault/{username}", body={"blob": blob.decode("ascii")},
            headers=headers)


def client_for(vault_data, timeout: int = DEFAULT_TIMEOUT) -> SyncClient:
    settings = get_settings(vault_data)
    if not settings.get("url"):
        raise SyncError("Sync is not set up yet. Add the server address in "
                        "Settings.")
    return SyncClient(settings["url"], settings.get("token", ""),
                      settings.get("ca_file", ""), timeout)


# ==============================
# One sync, in two halves
# ==============================
class SyncSession:
    """
    A sync split either side of the user.

    :meth:`prepare` pulls and merges, then stops. If it found conflicts the
    GUI puts them to the user; :meth:`commit` folds the answers in, saves and
    pushes. They are separate because a modal dialog can sit open for minutes,
    and holding a half-applied merge across that would be the one thing worse
    than a conflict.
    """

    def __init__(self, client: SyncClient, username: str, master_password: str):
        self.client = client
        self.username = username
        self.master_password = master_password
        self.revision = 0
        self.result = None
        self._fingerprint = None
        # Set by prepare() when the base was agreed with another server (or
        # an earlier state of this one) and so was left out of the merge.
        self.base_ignored = False
        # Set by prepare() when the server's copy is under another password.
        self.adopt_password = None       # server is newer: switch to this
        self.upgrade = False             # server is older: re-upload ours
        self.target_generation = 0
        # Set by commit() once this PC's vault really has switched password.
        # The caller must then use self.master_password from here on.
        self.password_changed = False

    @staticmethod
    def fingerprint(vault_data) -> str:
        """A cheap content hash of a vault's accounts, to detect local edits."""
        accounts = (vault_data or {}).get("accounts", [])
        return hashlib.sha256(
            json.dumps(accounts, sort_keys=True).encode("utf-8")).hexdigest()

    def has_work(self) -> bool:
        """
        Whether commit() needs to run after prepare().

        Not the same as ``result.changed``. After a password change the
        entries often match exactly, yet this PC still has to switch password
        or the server's copy still has to be re-encrypted -- skipping the
        commit there would leave sync failing on every attempt.

        The same goes for a base left out because it came from another
        server: even with nothing to merge, the commit has to record this
        server as the new base, or every later sync would merge without one.
        """
        return (self.result is not None and self.result.changed) \
            or self.upgrade or self.adopt_password is not None \
            or self.base_ignored

    @staticmethod
    def _open(blob: bytes, password: str):
        """The decrypted copy, or None if ``password`` does not open it."""
        try:
            return decrypt(password, blob)
        except ValueError:
            return None

    def prepare(self, local_vault: dict, server_password=None):
        """
        Pull the server's copy and merge it against ours. No writes yet.

        If the copy will not open with this PC's password, the master password
        was changed on one side and not yet the other. Without
        ``server_password`` that raises PasswordMismatch, saying which side is
        ahead; the caller asks the user for the server's password and calls
        again with it.
        """
        stored = self.client.fetch(self.username)
        self.revision = stored["revision"]
        self._fingerprint = self.fingerprint(local_vault)
        self.adopt_password = None
        self.upgrade = False

        local_generation = key_generation(local_vault)
        server_generation = stored["key_generation"]
        self.target_generation = max(local_generation, server_generation)

        blob = stored["blob"]
        if blob is None:
            remote = {"accounts": []}       # first push for this user
        else:
            remote = self._open(blob, self.master_password)
            if remote is None:
                # Ties go to the server: if both PCs changed the password
                # before either synced, the one that reached the server first
                # already won, and this PC follows it rather than
                # overwriting a vault the other PC is now locked to.
                adopt = server_generation >= local_generation
                if server_password is None:
                    raise PasswordMismatch(adopt)
                remote = self._open(blob, server_password)
                if remote is None:
                    raise PasswordMismatch(adopt, wrong=True)
                if adopt:
                    self.adopt_password = server_password
                    self.target_generation = server_generation
                else:
                    self.upgrade = True
                    self.target_generation = local_generation
            try:
                remote = vault.validate_vault(remote)
            except ValueError as e:
                raise SyncError(f"The vault on the server is damaged: {e}") from e

        # The base is under this PC's current password: carried across by
        # vault.change_master_password when the change happened here, and
        # untouched on a PC that is only now catching up.
        #
        # No vault on the server at all means a fresh start -- a new server,
        # a lost disk, a vault removed by hand -- not "every entry was deleted
        # elsewhere". With the base, each entry would look untouched here and
        # gone there, and the merge would delete them all from this PC. A
        # real deletion on another PC always arrives inside an uploaded vault,
        # never as an empty server, so ignoring the base here loses nothing:
        # this PC's vault is simply uploaded again.
        #
        # A base agreed with another server is ignored for the same reason:
        # see base_matches. Without it nothing is deleted or reverted -- the
        # differences come up as additions and conflicts instead.
        self.base_ignored = False
        if blob is None:
            base = None
        else:
            base = vault.load_base(self.master_password, self.username)
            if base is not None and not base_matches(
                    base, self.client.url, self.revision):
                base = None
                self.base_ignored = True
        self.result = merge_vaults(base, local_vault, remote)
        return self.result

    def _push(self, password: str, merged: dict, drop_history: bool) -> None:
        blob = encrypt(password, merged)
        meta = self.client.push(self.username, blob, self.revision,
                                key_generation=self.target_generation,
                                drop_history=drop_history)
        self.revision = int(meta.get("revision", self.revision + 1))

    def commit(self, local_vault: dict, choices=None,
               drop_history: bool = False) -> dict:
        """
        Apply the merge, save it locally, push it, and record the new base.

        Local save happens before the push on purpose. If the network dies
        between the two, this PC still holds the merged vault and the next
        sync pushes it; the reverse order could leave the merge only on the
        server while this PC still believed it had never happened.

        The one exception is adopting another PC's new password, where the
        push goes first: until the server has the merge, this PC must stay
        exactly as it was, under the password the app still believes it has.
        A failed push then leaves nothing half-changed, and the next sync
        simply asks again.

        ``drop_history`` asks the server to discard earlier revisions. It is
        meant for the upload after a password change here, when those
        revisions are still readable with the old password.
        """
        if self.result is None:
            raise SyncError("Nothing prepared to commit.")

        # The merged list was computed from the vault as prepare() saw it, so
        # committing a vault that has changed since would quietly drop those
        # edits. The GUI holds a modal dialog across the gap and cannot hit
        # this, which is exactly why it has to fail loudly rather than be
        # left to trust.
        if self.fingerprint(local_vault) != self._fingerprint:
            raise SyncError("The vault changed while the sync was open. "
                            "Press Sync again to merge the newer version.")

        merged = merged_vault(local_vault, resolve(self.result, choices))
        set_key_generation(merged, self.target_generation)
        vault.validate_vault(merged)

        # When the merge only brought changes down, the server already holds
        # what we just saved, and pushing an identical blob would burn a
        # revision and could lose a race with the other PC for no gain. The
        # exception is a copy still under this PC's previous password: its
        # content may match, but it has to be replaced.
        must_push = self.result.needs_push or self.upgrade

        if self.adopt_password:
            password = self.adopt_password
            if must_push:
                self._push(password, merged, drop_history)
            # rekey=True: .bak is rewritten under the adopted password too,
            # so the old one stops opening anything on this PC.
            vault.save_vault(password, merged, self.username, rekey=True)
            self.master_password = password
            self.password_changed = True
        else:
            password = self.master_password
            vault.save_vault(password, merged, self.username)
            if must_push:
                self._push(password, merged, drop_history)

        # Only now do both sides agree, so only now is this the base. Written
        # last: a base recorded before a failed push would claim agreement
        # that never happened, and the next merge would trust it.
        vault.save_base(password, merged, self.username,
                        origin=base_origin_for(self.client.url, self.revision))
        return merged


def download_vault(client: SyncClient, username: str, master_password: str):
    """
    Pull a vault from the server without merging -- the first-run path on a
    new PC, where there is nothing local to merge against.

    Returns (decrypted vault, revision), or (None, 0) if the server holds
    nothing for this user. The caller writes it out and records it as the
    base, with base_origin_for(client.url, revision).
    """
    blob, revision = client.pull(username)
    if blob is None:
        return None, 0
    try:
        return vault.validate_vault(decrypt(master_password, blob)), revision
    except ValueError as e:
        raise SyncError("That master password does not open the vault stored "
                        "on the server.") from e


def fetch_vault(client: SyncClient, username: str, master_password: str):
    """download_vault without the revision."""
    return download_vault(client, username, master_password)[0]
