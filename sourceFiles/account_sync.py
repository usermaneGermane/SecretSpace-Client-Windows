"""
SecretSpace 3 accounts on a sync server (API v2) -- phase 2.

What 2.x does with one shared token and a vault per username, an account
does with its own login: the server keeps the account (its sealed keyset,
recovery copy and public key) and its personal vault, and lets in only that
account. Nothing secret leaves this device: the server gets the Login Key
(derived from master password + Secret Key, and useless for opening
anything) and blobs it cannot decrypt.

Three things live here:

- :class:`AccountServer`, the HTTP calls, on sync_client's transport;
- :class:`AccountSync`, one sync of one vault in two halves, with the same
  three-way merge, conflict choices and base rules as 2.x
  (sync.merge_vaults, sync_client.base_matches);
- :func:`reconcile_vaults` (phase 3), which makes the account's list of
  vaults the same here and on the server before they are synced;
- the account lifecycle around them: :func:`connect` (an account made here
  goes onto a server), :func:`sign_in` (a new device, or one catching up
  with a password changed elsewhere) and :func:`change_password`.

Like sync_client, nothing here touches a widget; account_sync_ui.py runs
these on a worker thread.
"""

import base64
import os
import urllib.parse

import account_crypto
import accounts
import sync_client
import vault
from account_crypto import CryptoError
from sync import merge_vaults, resolve, merged_vault
from sync_client import SyncClient, SyncError, Conflict409

#: The server API this module speaks. A server lists the ones it has in
#: /health; a 1.x server answers without "api" and has only the 2.x one.
API_VERSION = 2

#: /health "features" entry of a server that keeps several vaults per
#: account (SecretSpace Server 2.0.0-alpha.2).
FEATURE_VAULTS = "vaults"


class LoginFailed(SyncError):
    """The server did not take this username + password + Secret Key."""


class AccountServer(SyncClient):
    """
    The /v2/ calls. ``token`` (the inherited Authorization header) is the
    session once :meth:`login` has run, and the server's token only for the
    one call that needs it, :meth:`sign_up`.
    """

    def __init__(self, url: str, ca_file: str = "",
                 timeout: int = sync_client.DEFAULT_TIMEOUT):
        super().__init__(url, "", ca_file, timeout)
        self._features = None

    @staticmethod
    def _http_error(e) -> SyncError:
        try:
            import json
            message = json.loads(e.read().decode("utf-8")).get("error", "")
        except Exception:
            message = ""
        if e.code == 401:
            return LoginFailed(message or "The server did not accept the login.")
        if e.code in (409, 428):
            return Conflict409(message or "The vault changed on the server.")
        return SyncError(message or f"Server error {e.code}.")

    # -- calls -------------------------------------------------------------
    def check_api(self) -> None:
        health = self.health()
        if API_VERSION not in (health.get("api") or [1]):
            raise SyncError("This server cannot hold SecretSpace 3 accounts yet: "
                            "it needs SecretSpace Server 2.0 or newer. (2.x "
                            "vaults sync with it as before.)")

    def has_vaults(self) -> bool:
        """Can this server keep more than the personal vault? Asked once
        per connection."""
        if self._features is None:
            self._features = list(self.health().get("features") or [])
        return FEATURE_VAULTS in self._features

    def create_vault(self, vault_id: str, sealed_name: str, wrapped_key: str) -> dict:
        return self._request("POST", "/v2/vaults", body={
            "id": vault_id, "name": sealed_name, "wrapped_key": wrapped_key})

    def rename_vault(self, vault_id: str, sealed_name: str) -> dict:
        return self._request("PUT", f"/v2/vaults/{vault_id}/name",
                             body={"name": sealed_name})

    def delete_vault(self, vault_id: str) -> None:
        self._request("DELETE", f"/v2/vaults/{vault_id}")

    def prelogin(self, username: str) -> dict:
        return self._request("GET", "/v2/prelogin/" + urllib.parse.quote(
            username, safe=""))

    def sign_up(self, server_token: str, body: dict) -> dict:
        session, self.token = self.token, server_token
        try:
            return self._request("POST", "/v2/accounts", body=body)
        finally:
            self.token = session

    def login(self, username: str, login_key: bytes) -> None:
        reply = self._request("POST", "/v2/login", body={
            "username": username,
            "login_key": base64.b64encode(login_key).decode("ascii")})
        self.token = reply["session"]

    def logout(self) -> None:
        if self.token:
            try:
                self._request("POST", "/v2/logout", body={})
            except SyncError:
                pass
            self.token = ""

    def me(self) -> dict:
        return self._request("GET", "/v2/me")

    def put_keyset(self, login_key: bytes, sealed_keyset: str) -> None:
        self._request("PUT", "/v2/me/keyset", body={
            "login_key": base64.b64encode(login_key).decode("ascii"),
            "keyset": sealed_keyset})

    def get_vault(self, vault_id: str) -> dict:
        """``blob`` (text, or None when nothing is stored yet) and
        ``revision``."""
        reply = self._request("GET", f"/v2/vaults/{vault_id}")
        return {"blob": reply.get("blob"), "revision": int(reply.get("revision", 0))}

    def put_vault(self, vault_id: str, blob: str, revision: int) -> int:
        """Store a new revision unless the server has moved past
        ``revision`` (Conflict409); returns the new revision."""
        reply = self._request("PUT", f"/v2/vaults/{vault_id}", body={"blob": blob},
                              headers={"If-Match": str(revision)})
        return int(reply.get("revision", revision + 1))


def server_for(account: accounts.Account) -> AccountServer:
    found = account.server
    if not found:
        raise SyncError("This account is not on a sync server yet. Set it up in "
                        "Settings → Sync.")
    return AccountServer(found["url"], found.get("ca_file", ""))


def logged_in(account: accounts.Account, server: AccountServer = None) -> AccountServer:
    """A server session for an open account."""
    server = server or server_for(account)
    if account.login_key is None:
        raise SyncError("Lock and unlock the account once, then sync.")
    try:
        server.login(account.username, account.login_key)
    except LoginFailed:
        raise LoginFailed(
            "The server did not accept this account's login. If the master "
            "password was changed on another device, use “Sign in from a "
            "server” on the login screen with the new password.") from None
    return server


# ---------------------------------------------------------------------------
# An account made here goes onto a server
# ---------------------------------------------------------------------------
def connect(account: accounts.Account, url: str, ca_file: str,
            server_token: str) -> str:
    """
    Put ``account`` on the server at ``url`` and remember it.

    If the server already has this account (set up from another device)
    the login simply works. Otherwise the account is created there with the
    server's token as the sign-up code. Returns "created" or "joined".
    Nothing is remembered unless it worked.
    """
    server = AccountServer(url, ca_file)
    server.check_api()
    outcome = "joined"
    try:
        server.login(account.username, account.login_key)
    except LoginFailed:
        if not server_token:
            raise LoginFailed("The server has no such account yet. Enter the "
                              "server's token to create it there.") from None
        files = account.sealed_files()
        try:
            server.sign_up(server_token, {
                "username": account.username,
                "login_key": base64.b64encode(account.login_key).decode("ascii"),
                "keyset": files["keyset"], "recovery": files["recovery"],
                "public_key": account.info["public_key"],
                "personal_vault": account.vault_id.hex()})
        except Conflict409:
            raise SyncError(
                f"The server already has an account called “{account.username}” "
                "with another master password or Secret Key — or it is "
                "someone else's. Nothing was changed.") from None
        except LoginFailed:
            raise LoginFailed("The server did not accept that token.") from None
        server.login(account.username, account.login_key)
        outcome = "created"
    if server.me()["personal_vault"] != account.vault_id.hex():
        raise SyncError(f"The server's account “{account.username}” has a "
                        "different personal vault: it is another account with "
                        "the same name. Nothing was changed.")
    server.logout()
    account.set_server(url, ca_file)
    return outcome


# ---------------------------------------------------------------------------
# One sync of the personal vault
# ---------------------------------------------------------------------------
class AccountSync:
    """
    sync_client.SyncSession for an account: :meth:`prepare` pulls and merges,
    :meth:`commit` saves, pushes and records the base. There is no password
    dance here -- the vault key does not change with the master password.
    """

    def __init__(self, account: accounts.Account, server: AccountServer = None,
                 vault_id: str = None):
        self.account = account
        self.server = server
        # The vault this sync is for: the personal one unless told otherwise.
        self.file = account.vault_file(vault_id)
        self.revision = 0
        self.result = None
        self.first_push = False
        self.base_ignored = False
        self._fingerprint = None

    def prepare(self, local_vault: dict):
        self.server = logged_in(self.account, self.server)
        stored = self.server.get_vault(self.file.hex)
        self.revision = stored["revision"]
        self._fingerprint = sync_client.SyncSession.fingerprint(local_vault)
        blob = stored["blob"]
        self.first_push = blob is None
        if blob is None:
            remote = {"accounts": []}
        else:
            try:
                remote = self.file.decrypt(blob)
            except (CryptoError, ValueError) as e:
                raise SyncError(f"The vault on the server cannot be read: {e}") from e
        # The 2.x rules for the base (sync_client.SyncSession.prepare): none
        # when the server is empty, and none if it was agreed elsewhere.
        self.base_ignored = False
        base = None
        if blob is not None:
            base = self.file.load_base()
            if base is not None and not sync_client.base_matches(
                    base, self.server.url, self.revision):
                base, self.base_ignored = None, True
        self.result = merge_vaults(base, local_vault, remote)
        return self.result

    def has_work(self) -> bool:
        return (self.result is not None and self.result.changed) \
            or self.base_ignored or self.first_push

    def commit(self, local_vault: dict, choices=None) -> dict:
        if self.result is None:
            raise SyncError("Nothing prepared to commit.")
        if sync_client.SyncSession.fingerprint(local_vault) != self._fingerprint:
            raise SyncError("The vault changed while the sync was open. "
                            "Press Sync again to merge the newer version.")
        merged = vault.validate_vault(
            merged_vault(local_vault, resolve(self.result, choices)))
        # Saved here first, then pushed: if the network fails in between,
        # this device holds the merge and the next sync pushes it.
        self.file.save(merged)
        if self.result.needs_push or self.first_push:
            self.revision = self.server.put_vault(
                self.file.hex, self.file.encrypt(merged), self.revision)
        self.file.save_base(merged, sync_client.base_origin_for(
            self.server.url, self.revision))
        return merged

    def close(self) -> None:
        if self.server is not None:
            self.server.logout()


# ---------------------------------------------------------------------------
# The account's list of vaults, here and on the server
# ---------------------------------------------------------------------------
class VaultChanges:
    """What :func:`reconcile_vaults` did, for the user to be told."""

    def __init__(self):
        self.added = []          # names: came from the server to this device
        self.uploaded = []       # names: made here, now on the server too
        self.gone = []           # names: deleted on the server, kept here
        self.renamed = []        # (old, new): renamed on another device
        self.server_too_old = False

    def __bool__(self):
        return bool(self.added or self.uploaded or self.gone or self.renamed
                    or self.server_too_old)


def reconcile_vaults(account: accounts.Account, server: AccountServer) -> VaultChanges:
    """
    Make the list of vaults the same on this device and on the server.
    ``server`` is logged in. Vault *contents* are not touched here; the
    caller syncs each vault afterwards.

    - A vault the server has and this device does not is added here (its
      entries arrive with its first sync).
    - A vault made here goes onto the server.
    - A vault that was on the server and is no longer there was deleted from
      another device. It is **kept** on this one, marked, and left out of the
      sync: deleting someone's entries is their decision, not a sync's.
    - A name changed here is told to the server; one changed elsewhere is
      taken over.

    A server older than 2.0.0-alpha.2 keeps only the personal vault; the
    others then simply stay on this device.
    """
    changes = VaultChanges()
    extra_here = [v for v in account.vault_ids() if v != account.personal_id]
    listed = {v["id"]: v for v in server.me().get("vaults", [])
              if v.get("kind") != "personal" and v.get("id") != account.personal_id}
    if not server.has_vaults():
        changes.server_too_old = bool(extra_here)
        return changes

    for vault_id in extra_here:
        record = account.vault_record(vault_id)
        file = account.vault_file(vault_id)
        there = listed.get(vault_id)
        if there is None:
            if record.get("on_server"):
                if not record.get("gone_from_server"):
                    account.mark_vault(vault_id, gone_from_server=True)
                    changes.gone.append(file.name)
                continue
            try:
                server.create_vault(vault_id, file.sealed_name(),
                                    record["wrapped_key"])
            except Conflict409:
                raise SyncError(f"The server already has another vault with the "
                                f"id of “{file.name}”. Nothing was changed.") from None
            account.mark_vault(vault_id, on_server=True, gone_from_server=False)
            changes.uploaded.append(file.name)
            continue
        if not record.get("on_server") or record.get("gone_from_server"):
            account.mark_vault(vault_id, on_server=True, gone_from_server=False)
        if record.get("rename_pending"):
            server.rename_vault(vault_id, file.sealed_name())
            account.mark_vault(vault_id, rename_pending=False)
            continue
        try:
            name = accounts.clean_vault_name(file.open_name(there.get("name", "")))
        except (CryptoError, ValueError):
            continue                    # an unreadable name changes nothing
        if name != file.name:
            try:
                account.rename_vault(vault_id, name, pending=False)
                changes.renamed.append((file.name, name))
            except ValueError:
                pass                    # taken here: keep this device's name

    for vault_id, there in listed.items():
        if vault_id in extra_here:
            continue
        try:
            file = account.adopt_vault(vault_id, there.get("wrapped_key", ""),
                                       there.get("name", ""))
        except (CryptoError, ValueError) as e:
            raise SyncError(f"The server lists a vault this account cannot "
                            f"open ({e}). Nothing was changed.") from e
        changes.added.append(file.name)
    return changes


def syncable_vaults(account: accounts.Account, server: AccountServer) -> list:
    """Ids of the vaults a sync covers: the personal one, and every other
    that is on the server."""
    if not server.has_vaults():
        return [account.personal_id]
    return [v for v in account.vault_ids()
            if v == account.personal_id or (
                account.vault_record(v).get("on_server")
                and not account.vault_record(v).get("gone_from_server"))]


def delete_vault(account: accounts.Account, vault_id: str) -> None:
    """
    Delete a vault for good. On a server it is deleted there first: if the
    server cannot be reached nothing is deleted anywhere, so a vault never
    comes back from the server after being deleted here.
    """
    record = account.vault_record(vault_id)
    if account.server and record.get("on_server") \
            and not record.get("gone_from_server"):
        server = logged_in(account)
        try:
            server.delete_vault(vault_id)
        finally:
            server.logout()
    account.delete_vault(vault_id)


def put_vault_back(account: accounts.Account, vault_id: str) -> None:
    """A vault deleted on the server and kept here goes onto the server
    again with the next sync (the user's choice, in the Vaults window)."""
    account.mark_vault(vault_id, on_server=False, gone_from_server=False)
    try:
        os.remove(account.vault_file(vault_id).base_path)   # agreed with a vault that is gone
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Signing in from a server
# ---------------------------------------------------------------------------
def sign_in(url: str, ca_file: str, username: str, password: str,
            secret_key_text: str = None):
    """
    Bring an account from the server onto this device -- a new device, or
    this one after the master password was changed on another.

    ``secret_key_text`` comes from the Emergency Kit; it may be left out when
    this device already has the account and keeps its Secret Key. Returns
    (account, vault data or None when the server has no vault yet). A
    device that already had the account keeps its own vault files; the
    caller syncs to merge them.
    """
    server = AccountServer(url, ca_file)
    server.check_api()
    pre = server.prelogin(username)
    username = pre.get("username") or username         # the server's spelling

    if secret_key_text:
        secret = account_crypto.parse_secret_key(secret_key_text)
    elif accounts.account_exists(username):
        secret = accounts.stored_secret(username, password)   # or SecretKeyNeeded
    else:
        raise accounts.SecretKeyNeeded(username)

    kdf = pre["kdf"]
    try:
        salt = base64.b64decode(kdf["salt"])
        auk, login = account_crypto.derive_account_keys(
            password, secret, username, salt, int(kdf["passes"]),
            int(kdf["memory_kib"]), int(kdf["lanes"]))
    except (KeyError, TypeError, ValueError) as e:
        if isinstance(e, CryptoError):
            raise
        raise SyncError("The server sent sign-in details this version cannot "
                        "use.") from e
    try:
        server.login(username, login)
    except LoginFailed:
        raise LoginFailed("Wrong username, master password or Secret Key.") from None
    me = server.me()
    try:
        keyset = account_crypto.open_keyset(auk, me["keyset"])
    except CryptoError:
        raise SyncError("The server's copy of the account does not open with "
                        "these details. Nothing was changed.") from None

    had_it = accounts.account_exists(username)
    account = accounts.adopt_from_server(
        username, me, keyset, secret, login, password,
        {"url": url.rstrip("/"), "ca_file": ca_file or ""})
    data = None
    if not had_it or not account.has_vault_file:
        stored = server.get_vault(me["personal_vault"])
        data = account.decrypt(stored["blob"]) if stored["blob"] else {"accounts": []}
        account.save_vault(data)
        if stored["blob"]:
            account.save_base(data, sync_client.base_origin_for(
                server.url, stored["revision"]))
    # The account's other vaults come with it, so a new device opens with
    # everything; a later sync merges whatever this device already had.
    reconcile_vaults(account, server)
    for vault_id in syncable_vaults(account, server):
        file = account.vault_file(vault_id)
        if file.personal or file.has_file:
            continue
        stored = server.get_vault(vault_id)
        fetched = file.decrypt(stored["blob"]) if stored["blob"] else {"accounts": []}
        file.save(fetched)
        if stored["blob"]:
            file.save_base(fetched, sync_client.base_origin_for(
                server.url, stored["revision"]))
    server.logout()
    return account, data


# ---------------------------------------------------------------------------
# A new master password, on the server and here together
# ---------------------------------------------------------------------------
def change_password(account: accounts.Account, new_password: str) -> None:
    """
    For an account on a server, the server learns the new password first:
    if it cannot be reached nothing changes anywhere, so this device and the
    server never disagree about which password opens the account.
    """
    if not account.server:
        return account.change_password(new_password)
    server = logged_in(account)
    try:
        account.change_password(
            new_password, before_write=lambda sealed, login:
            server.put_keyset(login, sealed))
    finally:
        server.logout()
