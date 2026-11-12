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
import hashlib
import json
import os
import urllib.parse

import account_crypto
import accounts
import changelog
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

#: ... and of one that shares vaults between accounts and keeps a log
#: (2.0.0-alpha.3).
FEATURE_SHARING = "sharing"

#: ... and of one that recovers an account with its phrase (2.0.0-alpha.4).
FEATURE_RECOVERY = "recovery"

#: ... and of one that keeps a signature with every wrapped vault key
#: (2.0.0-alpha.5). Without it this client syncs only the personal vault:
#: a key that comes with no signature is never taken (see check_key).
FEATURE_SIGNED_KEYS = "signed-keys"


class LoginFailed(SyncError):
    """The server did not take this username + password + Secret Key."""


class KeyNotTrusted(SyncError):
    """The server offers a vault key this device has no reason to trust: it
    is not signed by this account or by someone known here. Nothing is
    taken, nothing is uploaded under it."""


class KeyChanged(SyncError):
    """The server gives other keys for an account than this device has seen
    for it: a new account under an old name, or a server that lies."""


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

    def has_sharing(self) -> bool:
        self.has_vaults()
        return FEATURE_SHARING in self._features

    def has_recovery(self) -> bool:
        self.has_vaults()
        return FEATURE_RECOVERY in self._features

    def has_signed_keys(self) -> bool:
        self.has_vaults()
        return FEATURE_SIGNED_KEYS in self._features

    def put_key_sig(self, vault_id: str, key_sig: str) -> None:
        self._request("PUT", f"/v2/vaults/{vault_id}/key-sig",
                      body={"key_sig": key_sig})

    # -- recovery (phase 5) ----------------------------------------------------
    def recovery_copy(self, username: str) -> dict:
        return self._request("GET", "/v2/recovery/" + urllib.parse.quote(
            username, safe=""))

    def recover(self, body: dict) -> dict:
        return self._request("POST", "/v2/recovery", body=body)

    def put_recovery_proof(self, proof: bytes) -> None:
        self._request("PUT", "/v2/me/recovery-proof", body={
            "recovery_proof": base64.b64encode(proof).decode("ascii")})

    def put_recovery(self, sealed_recovery: str) -> None:
        self._request("PUT", "/v2/me/recovery",
                      body={"recovery": sealed_recovery})

    # -- sharing (phase 4) ---------------------------------------------------
    def put_signing_key(self, signing_key: str) -> None:
        self._request("PUT", "/v2/me/signing-key",
                      body={"signing_key": signing_key})

    def public_keys(self, username: str) -> dict:
        return self._request("GET", "/v2/accounts/" + urllib.parse.quote(
            username, safe="") + "/public-key")

    def members(self, vault_id: str) -> dict:
        return self._request("GET", f"/v2/vaults/{vault_id}/members")

    def put_member(self, vault_id: str, username: str, role: str,
                   wrapped_key: str = None, key_sig: str = None) -> dict:
        body = {"role": role}
        if wrapped_key:
            body["wrapped_key"] = wrapped_key
        if key_sig:
            body["key_sig"] = key_sig
        return self._request("PUT", f"/v2/vaults/{vault_id}/members/" +
                             urllib.parse.quote(username, safe=""), body=body)

    def leave_vault(self, vault_id: str, username: str) -> None:
        self._request("DELETE", f"/v2/vaults/{vault_id}/members/" +
                      urllib.parse.quote(username, safe=""))

    def rotate(self, vault_id: str, body: dict) -> dict:
        return self._request("POST", f"/v2/vaults/{vault_id}/rotate", body=body)

    def vault_log(self, vault_id: str) -> list:
        return list(self._request("GET", f"/v2/vaults/{vault_id}/log")
                    .get("lines") or [])

    def create_vault(self, vault_id: str, sealed_name: str, wrapped_key: str,
                     key_sig: str = "") -> dict:
        return self._request("POST", "/v2/vaults", body={
            "id": vault_id, "name": sealed_name, "wrapped_key": wrapped_key,
            "key_sig": key_sig})

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


def is_plain_remote(url: str) -> bool:
    """Is this an unencrypted (http://) address of another machine? On such
    a connection someone on the network can take the login and act as the
    account on the server (they still cannot read a vault)."""
    parts = urllib.parse.urlsplit((url or "").strip())
    if parts.scheme.lower() != "http":
        return False
    host = (parts.hostname or "").lower()
    return host not in ("localhost", "::1") and not host.startswith("127.")


# ---------------------------------------------------------------------------
# Whose key is this? (security review, 2026-11-12)
# ---------------------------------------------------------------------------
# The server stores each member's copy of a vault key but must never be able
# to choose one: if it could hand a device a key of its own making, the
# device would encrypt the vault under it at the next sync and the server
# could read everything. So every wrapped key carries a signature by the
# account that wrapped it, and a device takes a key only when it is signed
# by itself or by someone it has reason to trust.
def key_message(vault_hex: str, generation: int, member: str, wrapped_key: str,
                signer: str) -> bytes:
    """What the signature on a wrapped key covers: which vault, which key
    generation, for whom, the wrapped key itself, and who vouches."""
    return json.dumps(["PassMan3 vault key", vault_hex, int(generation), member,
                       hashlib.sha256(wrapped_key.encode("ascii")).hexdigest(),
                       signer], separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def sign_key(account: accounts.Account, vault_hex: str, generation: int,
             member: str, wrapped_key: str) -> str:
    return account_crypto.sign(account.keyset, key_message(
        vault_hex, generation, member, wrapped_key, account.username))


def check_key(account: accounts.Account, server: "AccountServer", there: dict,
              name: str, held_from: str = None) -> str:
    """
    Decide whether to take the vault key the server lists (``there``, one
    vault of /v2/me) or raise :class:`KeyNotTrusted`. Returns who signed it.

    A key signed by this account is always its own. Otherwise:

    - for a vault this device does not have yet (``held_from`` None), the
      signer may be anyone; their keys are remembered on first sight, and
      the vault shows as shared by someone "not checked" until the user
      compares fingerprints;
    - for a vault this device already has (a new key generation), the
      signer must be whoever signed the key held now (``held_from``) or
      someone whose fingerprint the user has compared. A name the server
      could have introduced on its own is not enough to replace a key.
    """
    signer = str(there.get("key_signer") or "")
    sig = str(there.get("key_sig") or "")
    wrapped = str(there.get("wrapped_key") or "")
    if not sig or not signer:
        raise KeyNotTrusted(
            f"The server's key for the vault “{name}” has no signature (it "
            "was put there by an older SecretSpace). Sync once from a device "
            "that already has this vault, or ask its owner to change the "
            "vault's key (Members → Change key). Nothing was changed.")
    if signer == account.username:
        key = account_crypto.signing_key_of(account.keyset)
    else:
        seen = account.contact(signer)
        new_vault = held_from is None
        if seen is not None and (new_vault or seen["verified"]
                                 or signer == held_from):
            key = seen["signing_key"]
        elif seen is None and new_vault:
            keys = lookup_contact(account, server, signer)
            trust_contact(account, keys, False)
            key = keys["signing_key"]
        else:
            raise KeyNotTrusted(
                f"The server offers a new key for the vault “{name}”, signed "
                f"by “{signer}”, whose fingerprint was never checked on this "
                f"PC. Nothing was changed. If {signer} is an owner of this "
                "vault, compare fingerprints with them (Vaults → Members → "
                "Check), then sync again.")
    message = key_message(there.get("id", ""),
                          int(there.get("key_generation", 0) or 0),
                          account.username, wrapped, signer)
    if not account_crypto.verify(key, message, sig):
        raise KeyNotTrusted(
            f"The key the server offers for the vault “{name}” is not signed "
            f"by “{signer}” as it claims. Nothing was changed, and nothing "
            "of this vault was sent. If this keeps happening, do not trust "
            "this server with that vault.")
    return signer


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
                "signing_key": account.signing_key,
                "recovery_proof": base64.b64encode(account_crypto.recovery_proof(
                    account.keyset)).decode("ascii"),
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
        self._remote_log = []
        self._log_in = self._log_out = False

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
        # The change log is merged on its own: each side's lines, once.
        self._remote_log = changelog.lines_of(remote)
        here = {l["id"] for l in changelog.lines_of(local_vault)}
        there = {l["id"] for l in self._remote_log}
        merged = {l["id"] for l in changelog.merge(
            changelog.lines_of(local_vault), self._remote_log)}
        self._log_in = merged != here            # lines to take from the server
        self._log_out = merged != there and blob is not None   # ... to give it
        return self.result

    def has_work(self) -> bool:
        return (self.result is not None and self.result.changed) \
            or self.base_ignored or self.first_push \
            or self._log_in or (self._log_out and self.file.can_write)

    def commit(self, local_vault: dict, choices=None) -> dict:
        if self.result is None:
            raise SyncError("Nothing prepared to commit.")
        if sync_client.SyncSession.fingerprint(local_vault) != self._fingerprint:
            raise SyncError("The vault changed while the sync was open. "
                            "Press Sync again to merge the newer version.")
        merged = vault.validate_vault(
            merged_vault(local_vault, resolve(self.result, choices)))
        log = changelog.merge(changelog.lines_of(local_vault), self._remote_log)
        if log or changelog.CHANGES_KEY in merged:
            merged[changelog.CHANGES_KEY] = log
        # Saved here first, then pushed: if the network fails in between,
        # this device holds the merge and the next sync pushes it.
        self.file.save(merged)
        # A reader only ever takes: the server would refuse its upload, and
        # it has nothing of its own to give.
        if (self.result.needs_push or self.first_push or self._log_out) \
                and self.file.can_write:
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
        self.gone = []           # names: no longer on the server, kept here
        self.renamed = []        # (old, new): renamed on another device
        self.rekeyed = []        # names: the vault got a new key
        self.roles = []          # (name, role): what this account may do changed
        self.server_too_old = False

    def __bool__(self):
        return bool(self.added or self.uploaded or self.gone or self.renamed
                    or self.rekeyed or self.roles or self.server_too_old)


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
    me = server.me()
    listed = {v["id"]: v for v in me.get("vaults", [])
              if v.get("kind") != "personal" and v.get("id") != account.personal_id}
    if not server.has_vaults() or not server.has_signed_keys():
        changes.server_too_old = bool(extra_here)
        return changes
    if server.has_sharing() and not me.get("signing_key"):
        # An account made before changes were signed: the server learns its
        # signing key now, once, so other members can check its lines.
        server.put_signing_key(account.signing_key)
    if server.has_recovery() and not me.get("can_recover"):
        # Likewise what lets the server recover the account with its phrase.
        server.put_recovery_proof(account_crypto.recovery_proof(account.keyset))
    sealed = me.get("recovery")
    if sealed and sealed != account.sealed_files()["recovery"]:
        # A new phrase was made on another device: this one takes the copy
        # that goes with it, so the old phrase opens nothing here either.
        account.set_recovery(sealed)

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
                server.create_vault(
                    vault_id, file.sealed_name(), record["wrapped_key"],
                    sign_key(account, vault_id, file.generation,
                             account.username, record["wrapped_key"]))
            except Conflict409:
                raise SyncError(f"The server already has another vault with the "
                                f"id of “{file.name}”. Nothing was changed.") from None
            account.mark_vault(vault_id, on_server=True, gone_from_server=False,
                               key_signer=account.username)
            changes.uploaded.append(file.name)
            continue
        if not record.get("on_server") or record.get("gone_from_server"):
            account.mark_vault(vault_id, on_server=True, gone_from_server=False)
        generation = int(there.get("key_generation", 0) or 0)
        held = int(record.get("key_generation", 0) or 0)
        if generation < held:
            # An older key can only come back from a server that lies (or a
            # restored backup): the people removed since could read again.
            raise KeyNotTrusted(
                f"The server offers an older key for the vault “{file.name}” "
                "than this PC holds. Nothing was changed, and nothing of "
                "this vault was sent.")
        if generation > held:
            # The key was changed (someone was removed). Before anything
            # else: is it a key an owner made? Then the name and the entries
            # are under it now.
            signer = check_key(account, server, there, file.name,
                               held_from=record.get("key_signer") or "")
            try:
                account.rekey_vault(vault_id, there.get("wrapped_key", ""),
                                    generation)
            except (CryptoError, ValueError) as e:
                raise SyncError(f"The new key of “{file.name}” cannot be "
                                f"opened by this account ({e}). Nothing was "
                                "changed.") from e
            account.mark_vault(vault_id, key_signer=signer)
            changes.rekeyed.append(file.name)
            file = account.vault_file(vault_id)
        elif there.get("wrapped_key", "") != record.get("wrapped_key", ""):
            # The same generation with another key: nothing honest does that.
            raise KeyNotTrusted(
                f"The server's key for the vault “{file.name}” is not the "
                "one this PC holds, though the vault's key was not changed. "
                "Nothing was changed, and nothing of this vault was sent.")
        elif not there.get("key_sig"):
            # A vault from before keys were signed: this device vouches for
            # the key it already holds, so the account's other devices take it.
            try:
                server.put_key_sig(vault_id, sign_key(
                    account, vault_id, held, account.username,
                    record["wrapped_key"]))
            except SyncError:
                pass                    # signed meanwhile: nothing to add
            if not record.get("key_signer"):
                account.mark_vault(vault_id, key_signer=account.username)
        role = there.get("role") if there.get("role") in accounts.ROLES \
            else accounts.ROLE_OWNER
        if role != account.vault_role(vault_id):
            account.mark_vault(vault_id, role=role)
            changes.roles.append((file.name, role))
        count = int(there.get("members", 1) or 1)
        if count != int(record.get("members", 1) or 1):
            account.mark_vault(vault_id, members=count)
        if record.get("rename_pending") and role != accounts.ROLE_OWNER:
            account.mark_vault(vault_id, rename_pending=False)   # not theirs to name
            record = account.vault_record(vault_id)
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
        signer = check_key(account, server, there, "(new on the server)")
        try:
            file = account.adopt_vault(vault_id, there.get("wrapped_key", ""),
                                       there.get("name", ""),
                                       there.get("role", accounts.ROLE_OWNER),
                                       there.get("key_generation", 0),
                                       there.get("members", 1))
        except (CryptoError, ValueError) as e:
            raise SyncError(f"The server lists a vault this account cannot "
                            f"open ({e}). Nothing was changed.") from e
        account.mark_vault(vault_id, key_signer=signer)
        changes.added.append(file.name)
    return changes


def syncable_vaults(account: accounts.Account, server: AccountServer) -> list:
    """Ids of the vaults a sync covers: the personal one, and every other
    that is on the server."""
    if not server.has_vaults() or not server.has_signed_keys():
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
            if account.vault_role(vault_id) == accounts.ROLE_OWNER:
                server.delete_vault(vault_id)
            else:
                # Someone else's vault: this account leaves it. The vault
                # stays for the others.
                server.leave_vault(vault_id, account.username)
        finally:
            server.logout()
    account.delete_vault(vault_id)


def put_vault_back(account: accounts.Account, vault_id: str) -> None:
    """A vault deleted on the server and kept here goes onto the server
    again with the next sync (the user's choice, in the Vaults window)."""
    # It goes back as this account's own vault, with a first key generation.
    account.mark_vault(vault_id, on_server=False, gone_from_server=False,
                       role=accounts.ROLE_OWNER, key_generation=0, members=1,
                       key_signer=account.username)
    try:
        os.remove(account.vault_file(vault_id).base_path)   # agreed with a vault that is gone
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Sharing a vault (phase 4)
# ---------------------------------------------------------------------------
def lookup_contact(account: accounts.Account, server: AccountServer,
                   username: str) -> dict:
    """
    Another account's keys from the server, set against what this device
    has seen for it before. Returns {"username" (as the server spells it),
    "public_key", "signing_key" (bytes), "fingerprint", "status": "new" |
    "known" | "changed", "verified": the user compared this fingerprint}.
    Nothing is remembered here; :func:`trust_contact` does that.
    """
    reply = server.public_keys(username)
    name = reply.get("username") or username
    try:
        public = base64.b64decode(reply["public_key"], validate=True)
        signing = base64.b64decode(reply.get("signing_key") or "", validate=True)
    except (KeyError, ValueError, TypeError):
        raise SyncError("The server sent keys this version cannot use.") from None
    if len(public) != 32:
        raise SyncError("The server sent keys this version cannot use.")
    if len(signing) != 32:
        raise SyncError(f"“{name}” has not used a SecretSpace version that can "
                        "share vaults yet. Ask them to update and sync once.")
    if name == account.username:
        raise SyncError("That is your own account.")
    seen = account.contact(name)
    status, verified = "new", False
    if seen is not None:
        same = seen["public_key"] == public and seen["signing_key"] == signing
        status = "known" if same else "changed"
        verified = same and seen["verified"]
    return {"username": name, "public_key": public, "signing_key": signing,
            "fingerprint": account_crypto.account_fingerprint(public, signing),
            "status": status, "verified": verified}


def trust_contact(account: accounts.Account, keys: dict, verified: bool) -> None:
    """Remember ``keys`` (from :func:`lookup_contact`) for that account;
    ``verified`` when the user compared the fingerprint with its owner."""
    account.remember_contact(keys["username"], keys["public_key"],
                             keys["signing_key"], verified)


def share_vault(account: accounts.Account, server: AccountServer, vault_id: str,
                keys: dict, role: str) -> dict:
    """
    Give the account behind ``keys`` (looked up, and its fingerprint
    confirmed by the user) the vault's key, wrapped so that only it can open
    it. The server stores the wrapped copy; it never holds the key itself.
    """
    if account.vault_role(vault_id) != accounts.ROLE_OWNER:
        raise SyncError("Only an owner of this vault can share it.")
    file = account.vault_file(vault_id)
    if file.personal:
        raise SyncError("The personal vault cannot be shared; make another "
                        "vault for that.")
    wrapped = account_crypto.wrap_key(keys["public_key"], file._key, file.id,
                                      keys["username"])
    done = server.put_member(vault_id, keys["username"], role, wrapped,
                             sign_key(account, vault_id, file.generation,
                                      keys["username"], wrapped))
    trust_contact(account, keys, True)
    account.mark_vault(vault_id, members=len(server.members(vault_id)
                                             .get("members") or [1]))
    return done


def list_members(account: accounts.Account, server: AccountServer,
                 vault_id: str) -> list:
    """The vault's members as the server lists them, each with "me" and
    "verified" (this device has compared their fingerprint)."""
    found = []
    for member in server.members(vault_id).get("members") or []:
        name = member.get("username", "")
        seen = account.contact(name)
        found.append({"username": name, "role": member.get("role", ""),
                      "added_by": member.get("added_by", ""),
                      "added_at": member.get("added_at", ""),
                      "me": name == account.username,
                      "verified": bool(seen and seen["verified"])})
    account.mark_vault(vault_id, members=max(1, len(found)))
    return found


def change_key(account: accounts.Account, server: AccountServer, vault_id: str,
               local_vault: dict, remove=()) -> dict:
    """
    Give a vault a new key, removing ``remove`` (usernames) in the same
    step -- what "Remove" does, so that a removed member can open nothing
    written afterwards. (What they already saw they may have copied; no
    password manager can undo that.)

    The vault is synced first, so the copy that goes under the new key is
    the one everybody agrees on; a sync that needs the user's decision stops
    this with nothing changed. Returns the vault's data as it now is here.
    """
    if account.vault_role(vault_id) != accounts.ROLE_OWNER:
        raise SyncError("Only an owner of this vault can do that.")
    sync = AccountSync(account, server, vault_id)
    result = sync.prepare(local_vault)
    if result.conflicts:
        raise SyncError("This vault has changes here and on the server that "
                        "need your decision. Press Sync first, then try again.")
    merged = sync.commit(local_vault)
    file = sync.file
    listing = server.members(vault_id)
    if int(listing.get("key_generation", 0) or 0) != file.generation:
        raise SyncError("This vault's key was changed on another device. "
                        "Press Sync first, then try again.")
    names = [m.get("username", "") for m in listing.get("members") or []]
    missing = [name for name in remove if name not in names]
    if missing:
        raise SyncError("Not a member any more: " + ", ".join(missing) + ".")
    staying = [name for name in names if name not in remove]
    new_key = account_crypto.new_vault_key()
    generation = file.generation + 1
    wrapped = {}
    for name in staying:
        if name == account.username:
            public = account_crypto.public_key_of(account.keyset)
        else:
            keys = lookup_contact(account, server, name)
            if keys["status"] == "changed":
                raise KeyChanged(
                    f"The server now gives different keys for “{name}” than "
                    "this PC has seen before. Nothing was changed. Check "
                    f"with {name} (Members → Check), or remove them too.")
            if keys["status"] == "new":
                trust_contact(account, keys, False)
            public = keys["public_key"]
        wrapped[name] = account_crypto.wrap_key(public, new_key, file.id, name)
    view = server.rotate(vault_id, {
        "generation": generation, "remove": list(remove),
        "wrapped_keys": wrapped,
        "key_sigs": {name: sign_key(account, vault_id, generation, name, key)
                     for name, key in wrapped.items()},
        "name": account_crypto.seal_vault_name(new_key, file.id, file.name),
        "blob": account_crypto.encrypt_vault(new_key, file.id, generation,
                                             vault.validate_vault(dict(merged))),
        "revision": sync.revision})
    # The server has it; now this device. (If this is interrupted, the next
    # sync finds the new generation and takes the key from the server.)
    account.rekey_vault(vault_id, wrapped[account.username], generation)
    account.mark_vault(vault_id, key_signer=account.username)
    account.vault_file(vault_id).save_base(merged, sync_client.base_origin_for(
        server.url, int(view.get("revision", sync.revision + 1))))
    account.mark_vault(vault_id, members=len(staying))
    return merged


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
