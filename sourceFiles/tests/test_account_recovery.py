"""
Phase 5: recovering an account with its 12-word phrase, and a new phrase --
on a PC alone, and through the real (test copy of the) sync server.
"""

import json
import os

import pytest

import account_crypto
import account_sync
import accounts
import recovery
import secret_store
import vault
from account_crypto import CryptoError
from sync_client import SyncError

from test_account_sync import (PW, TOKEN, alice, cheap_argon2, device,  # noqa: F401
                               new_account, secretspace_server, server)
from test_account_vaults import sync_all, sites

NEW_PW = "a brand new master password"


def make_local(name="alice", pw=PW):
    """An account on this PC only; returns (account, its phrase, its kit)."""
    new = accounts.prepare_account(name, pw)
    account = new.save()
    return account, new.recovery_phrase, new.secret_key_text


def add_entry(account, site, vault_id=None):
    file = account.vault_file(vault_id)
    data = file.load()
    vault.add_account(data, site, "me", "pw-" + site)
    file.save(data)


def recover(name, phrase, password=NEW_PW, url=""):
    pending = recovery.prepare(recovery.open_with_phrase(name, phrase, url),
                               password)
    account, loaded = pending.save()
    return pending, account, loaded


def folder_bytes(name):
    found = {}
    root = accounts.account_dir(name)
    for folder, _, files in os.walk(root):
        for n in files:
            with open(os.path.join(folder, n), "rb") as f:
                found[os.path.relpath(os.path.join(folder, n), root)] = f.read()
    return found


def server_record(server, name):
    path = os.path.join(server.store.root, "_v2", "accounts", name.lower() + ".json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# A. The pieces
# ---------------------------------------------------------------------------
def test_the_recovery_proof_comes_from_the_keyset_and_is_not_a_key_of_it():
    keyset = account_crypto.new_keyset()
    proof = account_crypto.recovery_proof(keyset)
    assert proof == account_crypto.recovery_proof(json.loads(json.dumps(keyset)))
    assert len(proof) == 32
    assert proof not in (account_crypto.public_key_of(keyset),
                         account_crypto.signing_key_of(keyset),
                         account_crypto._unb64(keyset["x25519_private"], "k"))
    assert proof != account_crypto.recovery_proof(account_crypto.new_keyset())


def test_seal_recovery_opens_only_with_its_phrase_and_name():
    keyset = account_crypto.new_keyset()
    phrase = account_crypto.new_recovery_phrase()
    sealed = account_crypto.seal_recovery(phrase, "alice", keyset)
    assert account_crypto.recover_account("alice", phrase, sealed) == keyset
    with pytest.raises(CryptoError):
        account_crypto.recover_account("bob", phrase, sealed)
    with pytest.raises(CryptoError):
        account_crypto.recover_account(
            "alice", account_crypto.new_recovery_phrase(), sealed)


# ---------------------------------------------------------------------------
# B. On a PC with no server
# ---------------------------------------------------------------------------
def test_a_local_account_is_recovered_with_its_phrase():
    account, phrase, kit = make_local()
    add_entry(account, "Mail")
    pending, again, loaded = recover("alice", phrase)
    assert [e["site"] for e in loaded["accounts"]] == ["Mail"]
    # the new password opens it, the old one no longer does
    assert accounts.unlock("alice", NEW_PW).username == "alice"
    with pytest.raises(CryptoError):
        accounts.unlock("alice", PW)
    # same keys: the vault and its key never changed
    assert again.keyset == account.keyset


def test_the_old_phrase_stops_working_and_the_new_one_works():
    account, phrase, kit = make_local()
    pending, again, _ = recover("alice", phrase)
    with pytest.raises(CryptoError):
        recovery.open_with_phrase("alice", phrase)
    assert accounts.check_recovery_phrase("alice", pending.recovery_phrase)
    assert pending.recovery_phrase != phrase


@pytest.mark.skipif(secret_store.default_scheme() != secret_store.SCHEME_DPAPI,
                    reason="Windows keeps the Secret Key with DPAPI")
def test_windows_keeps_the_secret_key_so_the_old_kit_still_works():
    account, phrase, kit = make_local()
    pending, again, _ = recover("alice", phrase)
    assert pending.new_secret is False
    assert pending.secret_key_text == kit
    assert again.secret_key_text == kit


def test_without_a_readable_secret_key_a_new_one_is_made(monkeypatch):
    monkeypatch.setattr(secret_store, "default_scheme",
                        lambda: secret_store.SCHEME_PASSWORD)
    account, phrase, kit = make_local()
    pending, again, _ = recover("alice", phrase)
    assert pending.new_secret is True and pending.secret_key_text != kit
    # the new key is the one stored, under the new password
    assert accounts.unlock("alice", NEW_PW).secret_key_text == pending.secret_key_text


@pytest.mark.parametrize("bad", [
    "not twelve words",
    " ".join(["abandon"] * 12),                       # wrong checksum
    "zzzz " + " ".join(["abandon"] * 11),             # not in the list
])
def test_a_mistyped_phrase_changes_nothing(bad):
    make_local()
    before = folder_bytes("alice")
    with pytest.raises(CryptoError):
        recovery.open_with_phrase("alice", bad)
    assert folder_bytes("alice") == before


def test_another_accounts_phrase_changes_nothing():
    make_local("alice")
    _, other_phrase, _ = make_local("bob")
    before = folder_bytes("alice")
    with pytest.raises(CryptoError):
        recovery.open_with_phrase("alice", other_phrase)
    assert folder_bytes("alice") == before


def test_nothing_is_written_before_save():
    account, phrase, kit = make_local()
    before = folder_bytes("alice")
    recovery.prepare(recovery.open_with_phrase("alice", phrase), NEW_PW)
    assert folder_bytes("alice") == before


def test_a_short_or_empty_password_or_name_is_refused():
    account, phrase, kit = make_local()
    with pytest.raises(ValueError):
        recovery.prepare(recovery.open_with_phrase("alice", phrase), "")
    with pytest.raises(ValueError):
        recovery.open_with_phrase("", phrase)


def test_a_name_this_pc_does_not_have_needs_a_server_address():
    with pytest.raises(ValueError, match="server"):
        recovery.open_with_phrase("nobody",
                                  account_crypto.new_recovery_phrase())


def test_a_new_phrase_replaces_the_old_one_locally():
    account, phrase, kit = make_local()
    made = recovery.NewPhrase(account)
    made.save()
    assert not accounts.check_recovery_phrase("alice", phrase)
    assert accounts.check_recovery_phrase("alice", made.recovery_phrase)
    assert not os.path.exists(os.path.join(accounts.account_dir("alice"),
                                           accounts.RECOVERY_FILE + ".bak"))


# ---------------------------------------------------------------------------
# C. With a server
# ---------------------------------------------------------------------------
@pytest.fixture
def on_server(server, device):                       # noqa: F811
    """alice on device a, made here (keeping her phrase) and on the server."""
    new = new_account()
    account = new.save()
    assert account_sync.connect(account, server.url, "", TOKEN) == "created"
    add_entry(account, "Mail")
    sync_all(account)
    account.phrase, account.kit = new.recovery_phrase, new.secret_key_text
    return account


def test_sign_up_gives_the_server_what_recovery_needs(server, on_server):
    assert server_record(server, "alice")["recovery_check"]
    me = account_sync.logged_in(on_server).me()
    assert me["can_recover"] is True


def test_recovery_on_the_same_pc_changes_the_password_on_the_server_too(
        server, on_server, device):
    pending, again, loaded = recover("alice", on_server.phrase)
    assert [e["site"] for e in loaded["accounts"]] == ["Mail"]
    # the server takes the new password, and no longer the old one
    account_sync.logged_in(again).logout()
    with pytest.raises(account_sync.LoginFailed):
        account_sync.sign_in(server.url, "", "alice", PW, on_server.kit)
    # another device signs in with the new password (and the kit in use)
    device("b")
    other, data = account_sync.sign_in(server.url, "", "alice", NEW_PW,
                                       pending.secret_key_text)
    assert [e["site"] for e in data["accounts"]] == ["Mail"]


def test_recovery_on_a_new_pc_brings_the_account_and_its_vaults(server, on_server,
                                                                device):
    team = on_server.create_vault("Team").hex
    add_entry(on_server, "Router", team)
    sync_all(on_server)
    device("b")
    assert not accounts.account_exists("alice")
    pending, again, loaded = recover("alice", on_server.phrase, url=server.url)
    assert pending.new_secret is True               # nothing to keep on a new PC
    assert sites(again) == ["Mail"]
    assert sites(again, team) == ["Router"]
    assert again.server["url"] == server.url
    assert accounts.unlock("alice", NEW_PW).username == "alice"


def test_a_wrong_phrase_or_an_unknown_name_read_the_same_on_the_server(
        server, on_server, device):
    device("b")
    wrong = account_crypto.new_recovery_phrase()
    with pytest.raises(CryptoError) as one:
        recovery.open_with_phrase("alice", wrong, server.url)
    with pytest.raises(CryptoError) as two:
        recovery.open_with_phrase("nobody", wrong, server.url)
    assert str(one.value) == str(two.value)
    assert not accounts.account_exists("alice")


def test_the_server_refuses_a_proof_that_is_not_the_accounts(server, on_server):
    remote = account_sync.AccountServer(server.url)
    other = account_crypto.new_keyset()
    sealed, login = account_crypto.reseal_with_new_password(
        "alice", other, NEW_PW, account_crypto.new_secret_key(), 1, 64, 1)
    with pytest.raises(SyncError):
        remote.recover({"username": "alice",
                        "recovery_proof": account_crypto._b64(
                            account_crypto.recovery_proof(other)),
                        "login_key": account_crypto._b64(login),
                        "keyset": sealed,
                        "recovery": account_crypto.seal_recovery(
                            account_crypto.new_recovery_phrase(), "alice", other)})
    # alice is untouched: her password still works
    account_sync.logged_in(on_server).logout()


def test_an_unreachable_server_changes_nothing_here(server, on_server):
    opened = recovery.open_with_phrase("alice", on_server.phrase)
    pending = recovery.prepare(opened, NEW_PW)
    before = folder_bytes("alice")
    opened.server = {"url": "http://127.0.0.1:1", "ca_file": ""}
    with pytest.raises(SyncError):
        pending.save()
    assert folder_bytes("alice") == before
    assert accounts.unlock("alice", PW).username == "alice"


def test_an_account_from_before_recovery_sends_its_proof_at_the_next_sync(
        server, on_server):
    path = os.path.join(server.store.root, "_v2", "accounts", "alice.json")
    record = server_record(server, "alice")
    del record["recovery_check"]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f)
    with pytest.raises(SyncError, match="sync it once"):
        recover("alice", on_server.phrase)
    sync_all(on_server)
    assert server_record(server, "alice")["recovery_check"]
    recover("alice", on_server.phrase)
    assert accounts.unlock("alice", NEW_PW)


def test_a_new_phrase_reaches_the_server_and_the_other_devices(server, on_server,
                                                               device):
    device("b")
    other, _ = account_sync.sign_in(server.url, "", "alice", PW, on_server.kit)
    device("a")
    made = recovery.NewPhrase(on_server)
    made.save()
    assert server_record(server, "alice")["recovery"] == \
        on_server.sealed_files()["recovery"]
    # device b takes the new copy at its next sync: the old phrase opens
    # nothing there either
    device("b")
    assert accounts.check_recovery_phrase("alice", on_server.phrase)
    sync_all(other)
    assert not accounts.check_recovery_phrase("alice", on_server.phrase)
    assert accounts.check_recovery_phrase("alice", made.recovery_phrase)
    # and a new PC cannot use the old phrase through the server
    device("c")
    with pytest.raises(CryptoError):
        recovery.open_with_phrase("alice", on_server.phrase, server.url)


def test_the_new_phrase_works_on_a_device_that_still_has_the_old_copy(
        server, on_server, device):
    device("b")
    other, _ = account_sync.sign_in(server.url, "", "alice", PW, on_server.kit)
    device("a")
    made = recovery.NewPhrase(on_server)
    made.save()
    device("b")                                     # not synced since
    pending, again, _ = recover("alice", made.recovery_phrase)
    assert accounts.unlock("alice", NEW_PW).username == "alice"


def test_shared_vaults_still_open_after_a_recovery(server, on_server, device):
    device("b")
    bob = new_account("bob").save()
    account_sync.connect(bob, server.url, "", TOKEN)
    sync_all(bob)
    device("a")
    team = on_server.create_vault("Team").hex
    add_entry(on_server, "Router", team)
    sync_all(on_server)
    session = account_sync.logged_in(on_server)
    keys = account_sync.lookup_contact(on_server, session, "bob")
    account_sync.share_vault(on_server, session, team, keys, "editor")
    session.logout()
    # the owner recovers: same keys, so her vaults and the share all still open
    pending, again, _ = recover("alice", on_server.phrase)
    assert sites(again, team) == ["Router"]
    sync_all(again)
    assert sites(again, team) == ["Router"]
    device("b")
    sync_all(bob)
    assert sites(bob, team) == ["Router"]


def test_recovery_ends_the_other_sessions_on_the_server(server, on_server):
    session = account_sync.logged_in(on_server)
    recover("alice", on_server.phrase)
    with pytest.raises(account_sync.LoginFailed):
        session.me()


def test_connect_alone_gives_the_server_the_proof(server, device):  # noqa: F811
    account = new_account("carol").save()
    assert account_sync.connect(account, server.url, "", TOKEN) == "created"
    assert server_record(server, "carol")["recovery_check"]       # no sync yet


def test_a_typo_is_reported_before_any_server_is_asked():
    # an address nothing listens on: a typo must be named, not a network error
    with pytest.raises(CryptoError, match="12 words|word list|order"):
        recovery.open_with_phrase("nobody", "only eleven " + "abandon " * 9,
                                  "http://127.0.0.1:1")
