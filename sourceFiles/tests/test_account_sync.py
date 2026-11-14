"""
Phase 2 end to end: SecretSpace 3 accounts on a real copy of the sync server.

Two "devices" are two data folders on one machine, switched with
SECRETSPACE_DATA_DIR. The server is the copy in sync_server/, run on a free port,
exactly as test_sync_server.py runs it for 2.x.
"""

import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "sync_server"))

import account_crypto                                           # noqa: E402
import account_sync                                             # noqa: E402
import accounts                                                 # noqa: E402
import secret_store                                             # noqa: E402
import sync                                                     # noqa: E402
import sync_client                                              # noqa: E402
import secretspace_server                                           # noqa: E402
from account_sync import LoginFailed                            # noqa: E402
from sync_client import SyncError                               # noqa: E402

TOKEN = "test-token-that-is-long-enough"
PW = "correct horse battery staple"


@pytest.fixture(autouse=True)
def cheap_argon2(monkeypatch):
    monkeypatch.setattr(account_crypto, "ARGON2_MEMORY_KIB", 64)
    monkeypatch.setattr(account_crypto, "ARGON2_PASSES", 1)


@pytest.fixture
def server(tmp_path):
    httpd = secretspace_server.ThreadingHTTPServer(("127.0.0.1", 0),
                                               secretspace_server.Handler)
    httpd.store = secretspace_server.Store(str(tmp_path / "store"))
    httpd.token = TOKEN
    os.makedirs(httpd.store.root, exist_ok=True)
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        httpd.url = f"http://127.0.0.1:{httpd.server_address[1]}"
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture
def device(tmp_path, monkeypatch):
    """device("a") makes that PC's data folder the current one."""
    def use(name):
        monkeypatch.setenv("SECRETSPACE_DATA_DIR", str(tmp_path / name / "data"))
    use("a")
    return use


def entry(site, password="p"):
    return {"site": site, "username": "me", "password": password}


def sync_once(account, local, choices=None):
    """One whole sync, as the UI runs it; returns the merged vault."""
    session = account_sync.AccountSync(account)
    try:
        result = session.prepare(local)
        if not session.has_work():
            return local
        if result.conflicts and choices is None:
            raise AssertionError(f"unexpected conflicts: {result.conflicts}")
        return session.commit(local, choices)
    finally:
        session.close()


def new_account(name="alice", pw=PW):
    return accounts.prepare_account(name, pw)


@pytest.fixture
def alice(server, device):
    """Device a: alice, made here and put on the server."""
    new = new_account()
    account = new.save()
    assert account_sync.connect(account, server.url, "", TOKEN) == "created"
    account.kit = new.secret_key_text
    return account


# ---------------------------------------------------------------------------
# Putting an account on a server
# ---------------------------------------------------------------------------
def test_connect_creates_the_account_and_remembers_the_server(server, alice):
    assert alice.server == {"url": server.url, "ca_file": ""}
    again = accounts.unlock("alice", PW)
    assert again.server == alice.server          # in account.json
    # connecting again finds it there
    assert account_sync.connect(again, server.url, "", "") == "joined"


@pytest.mark.parametrize("token", ["", "wrong-token-of-a-decent-length"])
def test_connect_needs_the_servers_token_to_create(server, device, token):
    account = new_account().save()
    with pytest.raises(LoginFailed):
        account_sync.connect(account, server.url, "", token)
    assert account.server is None
    assert accounts.unlock("alice", PW).server is None


def test_a_name_taken_on_the_server_is_not_overwritten(server, device, alice):
    device("b")
    other = new_account("alice", "another password").save()
    with pytest.raises(SyncError, match="already has an account"):
        account_sync.connect(other, server.url, "", TOKEN)
    assert other.server is None


def test_an_account_with_another_personal_vault_is_not_joined(server, device,
                                                              alice, monkeypatch):
    """Only a confused or hostile server could answer like this -- the login
    already proves the keys -- but then this device must not adopt it."""
    real_me = account_sync.AccountServer.me
    monkeypatch.setattr(account_sync.AccountServer, "me", lambda self: {
        **real_me(self), "personal_vault": os.urandom(16).hex()})
    account = accounts.unlock("alice", PW)
    account.set_server(None)
    with pytest.raises(SyncError, match="different personal vault"):
        account_sync.connect(account, server.url, "", "")
    assert account.server is None


def test_a_server_without_accounts_says_so(server, device, monkeypatch):
    monkeypatch.setattr(account_sync.AccountServer, "health",
                        lambda self: {"ok": True, "service": "secretspace-sync"})
    account = new_account().save()
    with pytest.raises(SyncError, match="2.1.0 or newer"):
        account_sync.connect(account, server.url, "", TOKEN)


def test_an_account_not_on_a_server_cannot_sync(device):
    account = new_account().save()
    with pytest.raises(SyncError, match="not on a sync server"):
        account_sync.AccountSync(account).prepare(account.load_vault())


# ---------------------------------------------------------------------------
# Syncing the personal vault
# ---------------------------------------------------------------------------
def test_the_first_sync_uploads_and_records_the_base(server, alice):
    local = {"accounts": [entry("github")]}
    alice.save_vault(local)
    merged = sync_once(alice, local)
    assert [e["site"] for e in merged["accounts"]] == ["github"]
    stored = server.accounts.vaults.read(alice.vault_id.hex()).decode()
    assert alice.decrypt(stored)["accounts"][0]["site"] == "github"
    origin = alice.load_base()[sync_client.vault.BASE_ORIGIN_KEY]
    assert origin == {"url": server.url, "revision": 1}


def test_a_second_device_signs_in_and_gets_the_vault(server, device, alice):
    alice.save_vault({"accounts": [entry("github")]})
    sync_once(alice, alice.load_vault())

    device("b")
    account, data = account_sync.sign_in(server.url, "", "alice", PW, alice.kit)
    assert [e["site"] for e in data["accounts"]] == ["github"]
    assert account.load_vault() == data
    assert account.server["url"] == server.url
    assert account.fingerprint == alice.fingerprint
    # The Secret Key is kept: next time the password alone opens it.
    assert accounts.unlock("alice", PW).load_vault() == data


def test_two_devices_merge_through_the_server(server, device, alice):
    device("b")
    bob_side, _ = account_sync.sign_in(server.url, "", "alice", PW, alice.kit)

    device("a")
    a_local = {"accounts": [entry("github")]}
    alice.save_vault(a_local)
    a_local = sync_once(alice, a_local)

    device("b")
    b_local = bob_side.load_vault()
    b_local["accounts"].append(entry("gitlab"))
    bob_side.save_vault(b_local)
    b_local = sync_once(bob_side, b_local)
    assert sorted(e["site"] for e in b_local["accounts"]) == ["github", "gitlab"]

    device("a")
    a_local = sync_once(alice, alice.load_vault())
    assert sorted(e["site"] for e in a_local["accounts"]) == ["github", "gitlab"]


def test_an_edit_on_both_devices_is_a_conflict_to_choose(server, device, alice):
    alice.save_vault({"accounts": [entry("github", "v1")]})
    sync_once(alice, alice.load_vault())
    device("b")
    other, _ = account_sync.sign_in(server.url, "", "alice", PW, alice.kit)

    local_b = other.load_vault()
    local_b["accounts"][0]["password"] = "from-b"
    other.save_vault(local_b)
    sync_once(other, local_b)

    device("a")
    local_a = alice.load_vault()
    local_a["accounts"][0]["password"] = "from-a"
    alice.save_vault(local_a)
    session = account_sync.AccountSync(alice)
    result = session.prepare(local_a)
    assert len(result.conflicts) == 1
    merged = session.commit(local_a, {result.conflicts[0].id: sync.KEEP_REMOTE})
    session.close()
    assert merged["accounts"][0]["password"] == "from-b"


def test_a_vault_changed_during_the_sync_is_not_overwritten(server, alice):
    local = {"accounts": [entry("github")]}
    session = account_sync.AccountSync(alice)
    session.prepare(local)
    with pytest.raises(SyncError, match="changed while the sync was open"):
        session.commit({"accounts": [entry("github"), entry("new")]})
    session.close()


def test_the_server_never_holds_anything_readable(server, alice):
    alice.save_vault({"accounts": [entry("bank", "s3cret-entry-password")]})
    sync_once(alice, alice.load_vault())
    everything = b""
    for folder, _, files in os.walk(server.store.root):
        for name in files:
            with open(os.path.join(folder, name), "rb") as f:
                everything += f.read()
    for secret in (b"s3cret-entry-password", b"bank", PW.encode(),
                   alice.kit.encode(), alice.kit.replace("-", "").encode()):
        assert secret not in everything


# ---------------------------------------------------------------------------
# Signing in
# ---------------------------------------------------------------------------
def test_sign_in_with_a_wrong_password_or_key_says_neither(server, device, alice):
    device("b")
    wrong_key = account_crypto.format_secret_key(account_crypto.new_secret_key())
    for password, kit in ((PW + "x", alice.kit), (PW, wrong_key)):
        with pytest.raises(LoginFailed,
                           match="Wrong username, master password or Secret Key"):
            account_sync.sign_in(server.url, "", "alice", password, kit)
    assert accounts.list_accounts() == []          # nothing written


def test_a_new_device_needs_the_emergency_kit(server, device, alice):
    device("b")
    with pytest.raises(accounts.SecretKeyNeeded):
        account_sync.sign_in(server.url, "", "alice", PW)


def test_sign_in_takes_the_servers_spelling_of_the_name(server, device, alice):
    device("b")
    account, _ = account_sync.sign_in(server.url, "", "ALICE", PW, alice.kit)
    assert account.username == "alice"


def test_sign_in_does_not_replace_someone_elses_account_here(server, device, alice):
    device("b")
    new_account("alice", "local only").save()          # unrelated, same name
    with pytest.raises(FileExistsError, match="different account"):
        account_sync.sign_in(server.url, "", "alice", PW, alice.kit)
    accounts.unlock("alice", "local only")             # untouched


# ---------------------------------------------------------------------------
# Changing the master password
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("scheme", ["native", "password"])
def test_a_password_changed_on_one_device_reaches_the_other(server, device, alice,
                                                            monkeypatch, scheme):
    if scheme == "password":
        monkeypatch.setattr(secret_store, "default_scheme",
                            lambda: secret_store.SCHEME_PASSWORD)
    alice.save_vault({"accounts": [entry("github")]})
    sync_once(alice, alice.load_vault())
    device("b")
    other, _ = account_sync.sign_in(server.url, "", "alice", PW, alice.kit)
    other_local = other.load_vault()
    other_local["accounts"].append(entry("only-on-b"))
    other.save_vault(other_local)

    device("a")
    account_sync.change_password(alice, "a brand new password")
    accounts.unlock("alice", "a brand new password")      # here: new one

    device("b")
    stale = accounts.unlock("alice", PW)                   # b still has the old
    with pytest.raises(LoginFailed, match="Sign in from a server"):
        account_sync.AccountSync(stale).prepare(stale.load_vault())
    # b signs in again with the new password. Where the Secret Key is kept
    # under the password (the scheme forced here, and Linux's own), it was
    # sealed with the old one, so the kit is needed; DPAPI does not care.
    kit = (alice.kit if secret_store.default_scheme() == secret_store.SCHEME_PASSWORD
           else None)
    if kit is None:
        caught, _ = account_sync.sign_in(server.url, "", "alice",
                                         "a brand new password")
    else:
        with pytest.raises(accounts.SecretKeyNeeded):
            account_sync.sign_in(server.url, "", "alice", "a brand new password")
        caught, _ = account_sync.sign_in(server.url, "", "alice",
                                         "a brand new password", kit)
    # b kept its own unsynced entry, and the next sync merges it in
    merged = sync_once(caught, caught.load_vault())
    assert sorted(e["site"] for e in merged["accounts"]) == ["github", "only-on-b"]
    accounts.unlock("alice", "a brand new password")
    with pytest.raises(account_crypto.CryptoError):
        accounts.unlock("alice", PW)


def test_no_server_no_password_change(server, alice):
    server.shutdown()
    server.server_close()
    with pytest.raises(SyncError):
        account_sync.change_password(alice, "never set")
    accounts.unlock("alice", PW)                            # unchanged here
