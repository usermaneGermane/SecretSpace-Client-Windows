"""
Deleting archived entries after N days (Settings > Archive).

The only automatic path to destroying a password, so the cases here are the
ones where it could take too much: entries that are not old enough, live
entries, timestamps it cannot read, other vaults, and the setting being off.
"""

from datetime import datetime, timezone

import sync
import vault

NOW = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)


def entry(entry_id, archived_at=None):
    e = {"id": entry_id, "site": entry_id, "username": "u", "password": "p",
         "updated_at": "2026-01-01T00:00:00Z"}
    if archived_at:
        e["archived_at"] = archived_at
    return e


def ids(data):
    return {a["id"] for a in data["accounts"]}


def test_off_by_default():
    data = {"accounts": [entry("ancient", "2001-01-01T00:00:00Z")]}
    assert vault.archive_purge_days(data) == 0
    assert vault.auto_purge_archive(data, NOW) == 0
    assert ids(data) == {"ancient"}


def test_set_and_clear():
    data = {"accounts": []}
    vault.set_archive_purge_days(data, 90)
    assert data[vault.ARCHIVE_PURGE_KEY] == 90
    assert vault.archive_purge_days(data) == 90
    vault.set_archive_purge_days(data, 0)
    assert vault.ARCHIVE_PURGE_KEY not in data       # off leaves no trace


def test_unreadable_setting_means_off():
    for bad in ("soon", -5, 0, None, 10 ** 6, [30]):
        assert vault.archive_purge_days({"accounts": [], "archive_purge_days": bad}) == 0


def test_cutoff_is_n_days_back_in_utc():
    assert vault.purge_cutoff(30, NOW) == "2026-09-08T12:00:00Z"


def test_purges_only_entries_archived_longer_ago_than_the_limit():
    data = {"accounts": [
        entry("old", "2026-07-01T00:00:00Z"),          # 99 days
        entry("edge", "2026-07-10T12:00:00Z"),         # exactly 90 days: kept
        entry("recent", "2026-10-01T00:00:00Z"),
        entry("live"),
    ]}
    vault.set_archive_purge_days(data, 90)
    assert vault.auto_purge_archive(data, NOW) == 1
    assert ids(data) == {"edge", "recent", "live"}


def test_never_purges_a_timestamp_it_cannot_read():
    """'1/1/2020' sorts before '2026-...' as a string; it must not count as old."""
    data = {"accounts": [entry("odd", "1/1/2020"), entry("lower", "2020-01-01t00:00:00z")]}
    vault.set_archive_purge_days(data, 30)
    assert vault.auto_purge_archive(data, NOW) == 0
    assert ids(data) == {"odd", "lower"}


def test_archived_before_lists_what_would_go():
    data = {"accounts": [entry("old", "2026-01-01T00:00:00Z"),
                         entry("new", "2026-10-07T00:00:00Z"), entry("live")]}
    due = vault.archived_before(data, vault.purge_cutoff(30, NOW))
    assert [a["id"] for a in due] == ["old"]
    assert ids(data) == {"old", "new", "live"}       # listing changes nothing


def test_setting_is_per_vault_and_survives_save(data_dir):
    vault.create_new_user("alice", "pw-alice-123")
    vault.create_new_user("bob", "pw-bob-123")
    alice = vault.load_vault("pw-alice-123", "alice")
    vault.set_archive_purge_days(alice, 30)
    vault.save_vault("pw-alice-123", alice, "alice")

    assert vault.archive_purge_days(vault.load_vault("pw-alice-123", "alice")) == 30
    assert vault.archive_purge_days(vault.load_vault("pw-bob-123", "bob")) == 0


def test_purge_reaches_the_other_pc_through_sync():
    """Purged here, untouched there: the merge drops it, no conflict."""
    gone = entry("gone", "2026-01-01T00:00:00Z")
    base = {"accounts": [gone, entry("keep")]}
    here = {"accounts": [dict(gone), entry("keep")]}
    vault.set_archive_purge_days(here, 30)
    vault.auto_purge_archive(here, NOW)

    # This PC pushes: the server's copy loses the entry.
    pushed = sync.merge_vaults(base, here, base)
    assert pushed.clean and {a["id"] for a in pushed.accounts} == {"keep"}

    # The other PC, still holding it unchanged, drops it at its next sync.
    there = {"accounts": [dict(gone), entry("keep")]}
    pulled = sync.merge_vaults(base, there, {"accounts": pushed.accounts})
    assert pulled.clean and {a["id"] for a in pulled.accounts} == {"keep"}


def test_merge_keeps_this_pcs_setting():
    """Each PC keeps its own limit; a sync never changes it."""
    here = {"accounts": [], "archive_purge_days": 30}
    remote = {"accounts": [], "archive_purge_days": 365}
    result = sync.merge_vaults({"accounts": []}, here, remote)
    assert vault.archive_purge_days(sync.merged_vault(here, result.accounts)) == 30
