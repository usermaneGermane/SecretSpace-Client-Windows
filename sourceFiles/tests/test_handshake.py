"""The version handshake (9c): what this app tells the server and hears from
it, and vaults changed by a newer SecretSpace, which are read and never
written."""

import copy

import pytest

import account_sync
import accounts
import sync
import sync_client
import vault
import version
from sync_client import SyncError
from test_account_sync import (PW, alice, cheap_argon2, device,  # noqa: F401
                               entry, secretspace_server, server, sync_once)

NEWER = vault.DATA_LEVEL + 1


def marked(*entries, level=NEWER, **more):
    data = {"accounts": [dict(e) for e in entries], **more}
    vault.require_level(data, level, windows="5.0", linux="3.0")
    return data


def other_device(server, device, account):
    device("b")
    return account_sync.sign_in(server.url, "", "alice", PW, account.kit)[0]


def stored(server, account):
    return account.decrypt(server.accounts.vaults.read(
        account.vault_id.hex()).decode())


# --- the marker --------------------------------------------------------------
@pytest.mark.parametrize("needs, level", [
    (None, 0), ({}, 0), ("9", 0), ({"level": "9"}, 0), ({"level": True}, 0),
    ({"level": -1}, 0), ({"level": 1.5}, 0), ({"level": 1}, 1), ({"level": 7}, 7)])
def test_reading_the_marker(needs, level):
    data = {"accounts": [], vault.NEEDS_KEY: needs}
    assert vault.needed_level(data) == level
    assert vault.too_new(data) is (level > vault.DATA_LEVEL)
    assert vault.needed_level({"accounts": []}) == 0


@pytest.mark.parametrize("said, shown", [
    ("5.0", "5.0"), ("5", "5"), ("5.0.1", "5.0.1"), ("", ""), (None, ""),
    ("5.0 <click>", ""), ("now!", "")])
def test_the_version_it_names_is_shown_only_when_it_is_one(said, shown):
    data = {"accounts": [], vault.NEEDS_KEY: {"level": NEWER, "linux": said}}
    assert vault.needed_version(data, "linux") == shown
    assert vault.needed_version(data, "windows") == ""


def test_the_level_is_never_lowered():
    data = marked(level=5)
    vault.require_level(data, 3, windows="4.9")
    assert vault.needed_level(data) == 5


@pytest.mark.parametrize("a, b", [(2, 3), (3, 2), (0, 2), (2, 0), (3, 3)])
def test_a_merge_keeps_the_higher_level(a, b):
    def side(level):
        return marked(level=level) if level else {"accounts": []}
    for base in (None, side(a), side(b)):
        result = sync.merge_vaults(base, side(a), side(b))
        out = sync.merged_vault(side(a), sync.resolve(result), result.extra)
        assert vault.needed_level(out) == max(a, b)
        assert bool(result.stats["extra_in"]) is (a < b)
        assert bool(result.stats["extra_out"]) is (b < a)


# --- read-only on this device ------------------------------------------------
def test_a_marked_vault_can_be_read_but_not_written(alice):
    assert alice.can_write(alice.personal_id) and alice.vault_file().can_write
    alice.save_vault(marked(entry("Mail")))
    for who in (alice, accounts.unlock("alice", PW)):
        assert who.load_vault()["accounts"][0]["site"] == "Mail"
        assert not who.can_write(who.personal_id) and not who.can_write(None)
        assert not who.vault_file().can_write
        assert who.needs_newer_app(who.personal_id)
        assert who.newer_app_text(None) == "SecretSpace %s or newer" % (
            {"windows": "5.0", "linux": "3.0"}[version.PLATFORM])


def test_only_that_vault_is(alice):
    work = alice.create_vault("Work")
    alice.save_vault(marked(entry("Mail")))
    assert alice.can_write(work.hex) and alice.vault_file(work.hex).can_write
    alice.vault_file(work.hex).save(marked(entry("x")))
    assert not alice.can_write(work.hex)
    assert alice.vault_role(work.hex) == accounts.ROLE_OWNER


def test_a_level_this_version_knows_changes_nothing(alice):
    alice.save_vault(marked(entry("Mail"), level=vault.DATA_LEVEL))
    assert alice.can_write(alice.personal_id)


# --- syncing one -------------------------------------------------------------
def newer_app_changes(server, account, monkeypatch, *entries):
    """The other device runs a newer SecretSpace, which knows the level."""
    with monkeypatch.context() as m:
        m.setattr(vault, "DATA_LEVEL", NEWER)
        data = account.load_vault()
        data["accounts"] += [dict(e) for e in entries]
        vault.require_level(data, NEWER, windows="5.0", linux="3.0")
        account.save_vault(data)
        sync_once(account, account.load_vault())


@pytest.fixture
def two(server, device, alice, monkeypatch):                        # noqa: F811
    """Both devices in step; then b, newer, marks the vault and adds one."""
    alice.save_vault({"accounts": [entry("Mail")]})
    sync_once(alice, alice.load_vault())
    other = other_device(server, device, alice)
    newer_app_changes(server, other, monkeypatch, entry("New", "n"))
    device("a")
    return alice, other


def test_it_is_taken_and_is_read_only_from_then_on(server, two):
    alice, _ = two
    before = server.accounts.vaults.read(alice.vault_id.hex())
    merged = sync_once(alice, alice.load_vault())
    assert [e["site"] for e in merged["accounts"]] == ["Mail", "New"]
    assert not alice.can_write(alice.personal_id)
    assert server.accounts.vaults.read(alice.vault_id.hex()) == before
    session = account_sync.AccountSync(alice)
    session.prepare(alice.load_vault())
    assert not session.has_work()
    session.close()


def test_changes_of_this_device_are_left_alone_here_and_there(server, two):
    alice, _ = two
    mine = alice.load_vault()
    mine["accounts"].append(entry("Mine"))
    alice.save_vault(mine)
    before = server.accounts.vaults.read(alice.vault_id.hex())
    with pytest.raises(account_sync.NeedsNewerApp, match="stay on this PC"):
        sync_once(alice, alice.load_vault())
    assert [e["site"] for e in alice.load_vault()["accounts"]] == ["Mail", "Mine"]
    assert server.accounts.vaults.read(alice.vault_id.hex()) == before


def test_after_the_update_they_merge_and_nothing_was_lost(server, two, monkeypatch):
    alice, _ = two
    mine = alice.load_vault()
    mine["accounts"].append(entry("Mine"))
    alice.save_vault(mine)
    with pytest.raises(account_sync.NeedsNewerApp):
        sync_once(alice, alice.load_vault())
    monkeypatch.setattr(vault, "DATA_LEVEL", NEWER)
    merged = sync_once(alice, alice.load_vault())
    assert sorted(e["site"] for e in merged["accounts"]) == ["Mail", "Mine", "New"]
    assert sorted(e["site"] for e in stored(server, alice)["accounts"]) == \
        ["Mail", "Mine", "New"]
    assert vault.needed_level(stored(server, alice)) == NEWER


def test_it_is_not_put_on_an_empty_server(server, device, alice):   # noqa: F811
    alice.save_vault(marked(entry("Mail")))
    with pytest.raises(account_sync.NeedsNewerApp):
        sync_once(alice, alice.load_vault())


def test_its_key_is_not_changed_by_this_version(server, device, alice):  # noqa: F811
    work = alice.create_vault("Work")
    work.save({"accounts": [entry("Mail")]})
    session = account_sync.logged_in(alice)
    account_sync.reconcile_vaults(alice, session)
    sync_once_in(alice, work.hex)
    data = copy.deepcopy(work.load())
    vault.require_level(data, NEWER, windows="5.0")
    with pytest.MonkeyPatch.context() as m:
        m.setattr(vault, "DATA_LEVEL", NEWER)
        work.save(data)
        sync_once_in(alice, work.hex)
    generation = alice.vault_file(work.hex).generation
    with pytest.raises(SyncError, match="newer SecretSpace"):
        account_sync.change_key(alice, session, work.hex, work.load())
    assert alice.vault_file(work.hex).generation == generation


def sync_once_in(account, vault_id):
    s = account_sync.AccountSync(account, None, vault_id)
    s.prepare(account.vault_file(vault_id).load())
    if s.has_work():
        s.commit(account.vault_file(vault_id).load())
    s.close()


# --- with the server ---------------------------------------------------------
def test_every_request_says_which_app_this_is(server, alice, monkeypatch):
    seen = []
    real = secretspace_server.Handler._refused

    def note(self):
        seen.append(self.headers.get(secretspace_server.HEADER_CLIENT))
        return real(self)
    monkeypatch.setattr(secretspace_server.Handler, "_refused", note)
    sync_once(alice, alice.load_vault())
    assert seen and set(seen) == {f"{version.PLATFORM}/{version.__version__}"}


def test_the_servers_version_is_known_after_a_login(server, alice, monkeypatch):
    monkeypatch.setattr(secretspace_server, "SERVER_VERSION", "9.8.7")
    account_sync.logged_in(alice).logout()
    assert alice.server_version == "9.8.7"


def test_a_server_that_needs_a_newer_app_says_so_first(server, alice, monkeypatch):
    monkeypatch.setitem(secretspace_server.MIN_CLIENT, version.PLATFORM, "99.0.0")
    with pytest.raises(SyncError, match="needs SecretSpace 99.0.0 or newer"):
        account_sync.logged_in(alice)


def test_and_its_refusal_is_shown_even_if_health_was_not_asked(server, alice,
                                                               monkeypatch):
    session = account_sync.logged_in(alice)
    monkeypatch.setitem(secretspace_server.MIN_CLIENT, version.PLATFORM, "99.0.0")
    with pytest.raises(SyncError, match="needs SecretSpace 99.0.0 or newer"):
        session.me()


@pytest.mark.parametrize("health", [
    {}, {"min_client": None}, {"min_client": []}, {"min_client": {}},
    {"min_client": {version.PLATFORM: 5}}, {"min_client": {version.PLATFORM: "x"}},
    {"version": None}, {"version": 7}])
def test_an_older_or_odd_server_locks_nobody_out(alice, monkeypatch, health):
    s = account_sync.server_for(alice)
    monkeypatch.setattr(s, "health", lambda: dict(
        health, api=[1, 2], features=["format-2"]))
    s.check_api()


@pytest.mark.parametrize("have, needed, want", [
    ("4.7.0", "4.7.0", False), ("4.7.0", "4.7.1", True), ("4.10.0", "4.9.0", False),
    ("4.7.0-rc.1", "4.8.0", True), ("4.7.0", "", False), ("4.7.0", None, False),
    ("4.7.0", "4.8", False)])
def test_older(have, needed, want):
    assert sync_client.older(have, needed) is want


def test_this_app_meets_the_servers_minimum():
    assert not sync_client.older(version.__version__, secretspace_server
                                 .MIN_CLIENT[version.PLATFORM])


def test_once_updated_the_vault_can_be_changed_again(alice, monkeypatch):
    alice.save_vault(marked(entry("Mail")))
    assert not alice.can_write(alice.personal_id)
    monkeypatch.setattr(vault, "DATA_LEVEL", NEWER)
    alice.load_vault()
    assert alice.can_write(alice.personal_id)


def test_the_servers_minimum_is_read_before_anything_is_sent(alice, monkeypatch):
    s = account_sync.server_for(alice)
    monkeypatch.setattr(s, "health", lambda: {
        "min_client": {version.PLATFORM: "99.0.0"}, "api": [1, 2],
        "features": ["format-2"]})
    with pytest.raises(SyncError, match="99.0.0 or newer"):
        s.check_api()


@pytest.mark.parametrize("odd", [["99.0.0"], "99.0.0", 99])
def test_a_minimum_in_another_shape_is_ignored(alice, monkeypatch, odd):
    s = account_sync.server_for(alice)
    monkeypatch.setattr(s, "health", lambda: {
        "min_client": odd, "api": [1, 2], "features": ["format-2"]})
    s.check_api()
