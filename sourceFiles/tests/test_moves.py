"""Moving an entry between vaults: the copy, the original that waits in the
Archive, when it goes, and what other devices make of it."""

import copy

import pytest

import account_sync
import accounts
import changelog
import moves
import sync
import vault
from test_account_sync import (PW, alice, cheap_argon2, device,  # noqa: F401
                               secretspace_server, server)


def entry(i="a", **more):
    return dict({"id": i, "site": "Mail", "username": "u", "password": "p"},
                **more)


def data(*entries, **top):
    return vault.validate_vault(dict({"accounts": [dict(e) for e in entries]},
                                     **top))


def pair(**more):
    source, target = data(entry(**more)), data()
    return source, target, moves.move(source, target, "a", "T")


def yes(vault_id, entry_id):
    return True


# --- the move itself ---------------------------------------------------------
def test_the_copy_has_everything_and_an_id_of_its_own():
    e = entry(totp="JBSWY3DPEHPK3PXP", url="https://x", notes="n",
              passkey={"deep": [1]}, updated_at="2026-01-01T00:00:00Z")
    vault.update_entry(e, password="p2")
    source, target = data(e), data()
    before = copy.deepcopy(source["accounts"][0])
    moved = moves.move(source, target, "a", "T")
    assert target["accounts"] == [moved]
    assert moved["id"] != "a"
    assert {**moved, "id": "a"} == before
    source["accounts"][0]["passkey"]["deep"].append(2)
    assert moved["passkey"] == {"deep": [1]}


def test_the_original_waits_in_the_archive_marked_as_moved():
    source, _, moved = pair()
    original = source["accounts"][0]
    assert vault.is_archived(original) and original["password"] == "p"
    mark = moves.marker(original)
    assert mark["vault"] == "T" and mark["id"] == moved["id"]
    again = vault.validate_vault(copy.deepcopy(source))["accounts"][0]
    assert moves.marker(again) == mark


def test_what_cannot_be_moved():
    source, target = data(entry(archived_at="2026-01-01T00:00:00Z")), data()
    assert moves.move(source, target, "a", "T") is None
    assert moves.move(source, target, "nope", "T") is None
    live = data(entry())
    assert moves.move(live, live, "a", "T") is None
    assert target["accounts"] == [] and not vault.is_archived(live["accounts"][0])


def test_two_devices_that_move_it_to_one_vault_make_one_copy():
    assert pair()[2]["id"] == pair()[2]["id"]
    other = data(entry())
    assert moves.move(other, data(), "a", "T2")["id"] != pair()[2]["id"]


def test_a_second_copy_in_the_same_vault_gets_another_id():
    source, target, first = pair()
    vault.restore_account(source, "a")
    second = moves.move(source, target, "a", "T")
    assert second["id"] != first["id"] and len(target["accounts"]) == 2


def test_it_can_be_moved_on_and_back():
    source, target, moved = pair()
    back = moves.move(target, source, moved["id"], "S")
    assert back["id"] not in ("a", moved["id"])
    assert moves.MOVED_KEY not in back


# --- the original goes -------------------------------------------------------
def test_it_goes_once_the_copy_has_arrived_and_not_before():
    source, _, moved = pair()
    asked = []
    assert moves.settle(source, lambda v, i: asked.append((v, i))) == 0
    assert asked == [("T", moved["id"])] and len(source["accounts"]) == 1
    assert moves.settle(source, yes) == 1 and source["accounts"] == []


def test_saving_does_not_keep_it_there():
    """record() fills in who made a revision, after the copy was made."""
    e = entry()
    vault.update_entry(e, password="p2")
    source, target = data(e), data()
    moves.move(source, target, "a", "T")
    for rev in source["accounts"][0]["history"]:
        rev["by"] = "alice"
    source["accounts"][0]["updated_by"] = "alice"
    assert moves.settle(vault.validate_vault(source), yes) == 1


@pytest.mark.parametrize("change", [
    lambda e: e.update(password="changed elsewhere"),
    lambda e: e.update(passkey="from a newer version"),
    lambda e: vault.add_revision(e, entry(password="older"), ["password"]),
    lambda e: e.update(archived_at="2030-01-01T00:00:00Z"),
    lambda e: e.update(moved="junk"),
    lambda e: e.pop("archived_at")])
def test_one_that_changed_since_stays(change):
    source, _, _ = pair()
    change(source["accounts"][0])
    assert moves.settle(source, yes) == 0 and len(source["accounts"]) == 1


def test_restoring_it_makes_it_ordinary_again():
    source, _, _ = pair()
    vault.restore_account(source, "a")
    vault.archive_account(source, "a")
    assert moves.MOVED_KEY not in source["accounts"][0]
    assert moves.settle(source, yes) == 0


def test_a_live_entry_never_keeps_a_mark():
    source, target = data(entry()), data()
    source["accounts"][0]["moved"] = {"vault": "left by an older app"}
    assert moves.MOVED_KEY not in moves.move(source, target, "a", "T")
    out = data(entry(moved={"vault": "T"}))
    assert moves.MOVED_KEY not in out["accounts"][0]


def test_a_conflicts_losing_copy_is_not_taken_for_the_original():
    source, _, _ = pair()
    for made in (sync._archived_copy, sync._active_copy):
        assert moves.marker(made(source["accounts"][0])) is None


# --- the change log ----------------------------------------------------------
def test_the_log_says_moved_once_and_holds_no_value():
    before = data(entry())
    source, target = copy.deepcopy(before), data()
    moves.move(source, target, "a", "T")
    found = changelog.diff(before, source)
    assert [(f["action"], f["entry"]) for f in found] == [(changelog.MOVED, "a")]
    assert changelog.describe(found[0]) == "moved “Mail” to another vault"
    assert [f["action"] for f in changelog.diff(data(), target)] == [changelog.ADDED]
    settled = copy.deepcopy(source)
    moves.settle(settled, yes)
    assert changelog.diff(source, settled) == []
    # ... but an ordinary archived one that is deleted is still logged.
    gone = data(entry(archived_at="2026-01-01T00:00:00Z"))
    assert [f["action"] for f in changelog.diff(gone, data())] == [changelog.DELETED]


# --- the other devices -------------------------------------------------------
def line(action, at, i="a"):
    return {"id": f"{action}{at}{i}", "at": at, "by": "x", "action": action,
            "entry": i, "title": "t", "fields": [], "count": 0, "sig": "s", "v": 2}


def lone(local_log, remote_log, local=None):
    """The entry is live here and gone from the server."""
    base = data(entry())
    return sync.merge_vaults(base, data(local or entry(), changes=local_log),
                             data(changes=remote_log))


def test_a_moved_entry_goes_without_a_question():
    result = lone([], [line("moved", "2")])
    assert result.clean and result.accounts == [] and result.stats["removed"] == 1


@pytest.mark.parametrize("local, remote", [
    ([], []),                                          # an older server copy
    ([line("moved", "2")], []),                        # only this PC knows
    ([], [line("moved", "2", "other")]),               # another entry
    ([], [line("deleted", "2")]),
    ([], [line("moved", "2"), line("restored", "3")]),
    ([line("restored", "3")], [line("moved", "2")])])
def test_every_other_missing_entry_still_asks(local, remote):
    result = lone(local, remote)
    assert [c.kind for c in result.conflicts] == ["missing"]


def test_a_moved_entry_that_was_changed_here_asks():
    result = lone([], [line("moved", "2")], entry(password="mine"))
    assert [c.kind for c in result.conflicts] == ["purge"]


# --- through the server ------------------------------------------------------
def sync_all(account, choices=None):
    s = account_sync.logged_in(account)
    try:
        account_sync.reconcile_vaults(account, s)
        for v in account_sync.syncable_vaults(account, s):
            f = account.vault_file(v)
            one = account_sync.AccountSync(account, s, v)
            local = f.load() if f.has_file else {"accounts": []}
            result = one.prepare(local)
            assert not result.conflicts
            if one.has_work():
                one.commit(local)
    finally:
        s.logout()


def save(account, vault_id, new):
    f = account.vault_file(vault_id)
    before = f.load() if f.has_file else {"accounts": []}
    changelog.record(new, before, account.username, account.keyset, f.hex, f.fmt)
    f.save(new)


def sites(account, vault_id):
    return [(a["site"], vault.is_archived(a))
            for a in account.vault_file(vault_id).load()["accounts"]]


def test_a_device_that_saw_none_of_it_ends_up_the_same(server, device, alice):  # noqa: F811
    home = alice.personal_id
    start = alice.load_vault()
    vault.add_account(start, "Mail", "me", "p")
    save(alice, home, start)
    work = alice.create_vault("Work").hex
    sync_all(alice)
    device("b")
    other = account_sync.sign_in(server.url, "", "alice", PW, alice.kit)[0]
    sync_all(other)
    assert sites(other, home) == [("Mail", False)]

    device("a")
    source, target = alice.load_vault(), alice.vault_file(work).load()
    moves.move(source, target, source["accounts"][0]["id"], work)
    save(alice, work, target)
    save(alice, home, source)

    def arrived(v, i):
        base = alice.vault_file(v).load_base() or {"accounts": []}
        return any(a["id"] == i for a in base["accounts"])
    assert moves.settle(alice.load_vault(), arrived) == 0      # not yet
    sync_all(alice)
    source = alice.load_vault()
    assert moves.settle(source, arrived) == 1
    save(alice, home, source)
    sync_all(alice)

    device("b")
    other = accounts.unlock("alice", PW)
    sync_all(other)                          # asks nothing (asserted there)
    assert sites(other, home) == [] and sites(other, work) == [("Mail", False)]
    sync_all(other)
    device("a")
    sync_all(alice)
    assert sites(alice, home) == [] and sites(alice, work) == [("Mail", False)]
    log = changelog.lines_of(alice.load_vault())
    assert [l["action"] for l in log] == ["added", "moved"]
