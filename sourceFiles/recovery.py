"""
Recovering an account with its 12-word phrase (phase 5), and making a new
phrase.

The phrase opens a second copy of the account's keyset (recovery.ssk on the
device, "recovery" on the server). With the keyset open, nothing is lost:
the same keys are sealed under a new master password, and a new phrase
replaces the old one -- which opens nothing from then on.

Where the copy comes from:
- this PC has the account: its own recovery.ssk;
- it does not (a new or reinstalled PC): the account's server hands it out
  (GET /v2/recovery/<name>; it opens only with the phrase).

The Secret Key: this PC keeps the one it has when it can read it (Windows
DPAPI does not need the master password). Otherwise -- a new PC, or Linux,
where the stored key is sealed under the forgotten password -- a new Secret
Key is made and a new Emergency Kit shown. Either way the phrase alone is
enough, as it must be for someone who lost both password and kit.

An account on a server is changed there first (POST /v2/recovery, proving
with a key derived from the keyset that the phrase really opened it): if
the server cannot be reached, nothing changes anywhere, so this PC and the
server never disagree about the password. Other devices then sign in again
with the new password (and the new kit, if one was made).

Nothing here touches a widget; recovery_ui.py runs it on a worker thread.
"""

import base64

import account_crypto
import account_sync
import accounts
import secret_store
from account_crypto import CryptoError
from sync_client import SyncError


class Opened:
    """The keyset, opened with the phrase: what step 2 (the new password)
    works with."""

    def __init__(self, username, keyset, server, local):
        self.username = username
        self.keyset = keyset
        self.server = server            # {"url", "ca_file"} or None
        self.local = local              # this PC has the account


class Pending:
    """
    Everything a recovery will write, made in memory: shown to the user
    (the new phrase, the new kit) before :meth:`save` writes anything.
    """

    def __init__(self, opened, password, secret, new_secret, phrase,
                 sealed_keyset, login_key, sealed_recovery):
        self.username = opened.username
        self.opened = opened
        self.password = password
        self._secret = secret
        self.new_secret = new_secret
        self.secret_key_text = account_crypto.format_secret_key(secret)
        self.recovery_phrase = phrase
        self.sealed_keyset = sealed_keyset
        self.login_key = login_key
        self.sealed_recovery = sealed_recovery

    def save(self):
        """Write it all: the server first, then this PC. Returns (account,
        the personal vault's data)."""
        server = self.opened.server
        if server:
            remote = account_sync.AccountServer(server["url"],
                                                server.get("ca_file", ""))
            remote.check_api()
            if not remote.has_recovery():
                raise SyncError("This server cannot recover accounts yet: it "
                                "needs SecretSpace Server 2.0.0 or "
                                "newer. Nothing was changed.")
            remote.recover({
                "username": self.username,
                "recovery_proof": _b64(account_crypto.recovery_proof(
                    self.opened.keyset)),
                "login_key": _b64(self.login_key),
                "keyset": self.sealed_keyset,
                "recovery": self.sealed_recovery})
            # The server holds the new keys now; this PC takes them from
            # there exactly as a sign-in does (and a new PC gets its vaults).
            try:
                account, data = account_sync.sign_in(
                    server["url"], server.get("ca_file", ""), self.username,
                    self.password, self.secret_key_text)
            except Exception as e:
                raise SyncError(
                    "The account was recovered on the server, but this PC "
                    f"could not sign in afterwards ({e}). Use “Sign in from "
                    "a server” with the new master password" +
                    (" and the new Emergency Kit." if self.new_secret else
                     ".")) from e
            loaded = data if data is not None else account.load_vault()
            return account, loaded
        accounts.replace_keys(self.username, self.sealed_keyset,
                              self.sealed_recovery, self._secret, self.password,
                              self.opened.keyset)
        account = accounts.unlock(self.username, self.password)
        return account, account.load_vault()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def open_with_phrase(username: str, phrase: str, url: str = "",
                     ca_file: str = "") -> Opened:
    """
    Step 1: open the account's keyset with the phrase. Raises CryptoError
    for a phrase that is mistyped or not this account's (said the same way
    for a name that has no account), SyncError for the server.
    """
    username = (username or "").strip()
    if not username:
        raise ValueError("Enter the account name.")
    account_crypto.phrase_to_entropy(phrase)          # typos first, offline
    if accounts.account_exists(username):
        info = accounts._read_any_info(username)
        sealed = accounts.read_recovery_copy(username)
        server = info.get("server")
        server = server if isinstance(server, dict) and server.get("url") else None
        local = True
    else:
        url = (url or "").strip().rstrip("/")
        if not url:
            raise ValueError(f"This PC has no account “{username}”. Enter the "
                             "address of the server it is on.")
        if not url.startswith(("http://", "https://")):
            raise ValueError("The server address starts with http:// or "
                             "https://.")
        remote = account_sync.AccountServer(url, ca_file)
        remote.check_api()
        if not remote.has_recovery():
            raise SyncError("This server cannot recover accounts yet: it needs "
                            "SecretSpace Server 2.0.0 or newer.")
        reply = remote.recovery_copy(username)
        username = reply.get("username") or username
        sealed = reply.get("recovery", "")
        server = {"url": url, "ca_file": ca_file or ""}
        local = False
    try:
        keyset = account_crypto.recover_account(username, phrase, sealed)
    except CryptoError:
        if not (local and server):
            raise
        # The phrase may have been changed on another device: the server
        # has the copy that goes with the newest one.
        remote = account_sync.AccountServer(server["url"], server.get("ca_file", ""))
        if not remote.has_recovery():
            raise
        keyset = account_crypto.recover_account(
            username, phrase, remote.recovery_copy(username).get("recovery", ""))
    return Opened(username, keyset, server, local)


def prepare(opened: Opened, new_password: str) -> Pending:
    """Step 2: the same keys under a new password, a new phrase, and the
    Secret Key this PC keeps (or a new one) -- nothing written yet."""
    if not new_password:
        raise ValueError("Enter a new master password.")
    secret = None
    if opened.local:
        try:
            # DPAPI (Windows) reads it without the master password; the
            # password scheme (Linux) cannot, as that password is forgotten.
            secret = secret_store.unprotect(
                accounts._read_any_info(opened.username).get("secret_key"),
                opened.username, "")
        except (secret_store.Unavailable, CryptoError, ValueError, OSError):
            secret = None
    new_secret = secret is None
    if new_secret:
        secret = account_crypto.new_secret_key()
    sealed_keyset, login = account_crypto.reseal_with_new_password(
        opened.username, opened.keyset, new_password, secret,
        account_crypto.ARGON2_PASSES, account_crypto.ARGON2_MEMORY_KIB,
        account_crypto.ARGON2_LANES)
    phrase = account_crypto.new_recovery_phrase()
    return Pending(opened, new_password, secret, new_secret, phrase,
                   sealed_keyset, login,
                   account_crypto.seal_recovery(phrase, opened.username,
                                                opened.keyset))


# ---------------------------------------------------------------------------
# The recovery copy of an account converted from SecretSpace 3
# ---------------------------------------------------------------------------
def convert_copy(account: accounts.Account, phrase: str) -> None:
    """
    Seal the recovery copy again in the current format, under the SAME 12
    words. A conversion cannot do this by itself: the copy opens only with
    the words. As with a new phrase, the server (if any) gets it first, so
    this PC and the server never hold different copies. CryptoError when the
    words are mistyped or not this account's.
    """
    account_crypto.recover_account(
        account.username, phrase, accounts.read_recovery_copy(account.username))
    sealed = account_crypto.seal_recovery(phrase, account.username,
                                          account.keyset)
    if account.server:
        remote = account_sync.logged_in(account)
        try:
            remote.put_recovery(sealed)
        finally:
            remote.logout()
    account.set_recovery(sealed)


# ---------------------------------------------------------------------------
# A new phrase, for an open account (Settings)
# ---------------------------------------------------------------------------
class NewPhrase:
    """A new phrase for an open account: shown first, then :meth:`save`
    makes it the one (the old phrase opens nothing afterwards)."""

    def __init__(self, account: accounts.Account):
        self.account = account
        self.username = account.username
        self.recovery_phrase = account_crypto.new_recovery_phrase()

    def save(self) -> None:
        sealed = account_crypto.seal_recovery(self.recovery_phrase,
                                              self.username,
                                              self.account.keyset)
        if self.account.server:
            remote = account_sync.logged_in(self.account)
            try:
                if not remote.has_recovery():
                    raise SyncError("The server cannot take a new recovery "
                                    "phrase yet: it needs SecretSpace Server "
                                    "2.0.0 or newer. Nothing was "
                                    "changed.")
                remote.put_recovery(sealed)
            finally:
                remote.logout()
        self.account.set_recovery(sealed)
