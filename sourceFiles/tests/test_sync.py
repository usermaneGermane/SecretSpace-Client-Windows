"""
The three-way merge.

These are the tests that matter most in the sync feature: every case here is
one where getting it wrong silently loses a password or resurrects one the
user deleted. No network or crypto is involved -- merge_vaults is a pure
function over dicts, which is the whole reason it lives apart from the
transport.
"""

import pytest

import sync
import vault


def entry(entry_id, site="site", username="u", password="p", **extra):
    e = {"id": entry_id, "site": site, "username": username,
         "password": password, "updated_at": "2026-01-01T00:00:00Z"}
    e.update(extra)
    return e


def vlt(*entries):
    return {"accounts": list(entries)}


def ids(accounts):
    return {a["id"] for a in accounts}


def by_id(accounts, entry_id):
    return next(a for a in accounts if a["id"] == entry_id)


# --- the case that makes the base file necessary --------------------------
def test_archiving_here_propagates_instead_of_being_resurrected():
    """
    The central bug a two-way merge cannot avoid: this PC archives an entry,
    the other PC has not touched it. Without the base, "archived here, active
    there" is indistinguishable from "active there, not yet archived here",
    and a union merge brings the entry back every single sync.
    """
    base = vlt(entry("a"))
    local = vlt(entry("a", archived_at="2026-02-01T00:00:00Z"))
    remote = vlt(entry("a"))

    result = sync.merge_vaults(base, local, remote)

    assert result.clean, "one side changed; this is not a conflict"
    assert vault.is_archived(by_id(result.accounts, "a"))


def test_an_archive_on_the_server_lands_here():
    base = vlt(entry("a"))
    local = vlt(entry("a"))
    remote = vlt(entry("a", archived_at="2026-02-01T00:00:00Z"))

    result = sync.merge_vaults(base, local, remote)

    assert result.clean
    assert vault.is_archived(by_id(result.accounts, "a"))
    assert result.stats["archived"] == 1


def test_without_a_base_an_archive_is_a_conflict_not_a_guess():
    """
    First sync on a PC that has never synced. There is no ancestor, so the
    merge refuses to decide which side is the change and asks instead. Noisy,
    but it never silently picks wrong.
    """
    local = vlt(entry("a", archived_at="2026-02-01T00:00:00Z"))
    remote = vlt(entry("a"))

    result = sync.merge_vaults(None, local, remote)

    assert len(result.conflicts) == 1


# --- ordinary additions and edits ----------------------------------------
def test_additions_from_both_sides_are_kept():
    base = vlt()
    local = vlt(entry("a", site="here"))
    remote = vlt(entry("b", site="there"))

    result = sync.merge_vaults(base, local, remote)

    assert result.clean
    assert ids(result.accounts) == {"a", "b"}
    assert result.stats["new"] == 1


def test_a_one_sided_edit_needs_no_question():
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="old"))
    remote = vlt(entry("a", password="new"))

    result = sync.merge_vaults(base, local, remote)

    assert result.clean
    assert by_id(result.accounts, "a")["password"] == "new"


def test_the_same_edit_on_both_sides_is_not_a_conflict():
    """Identical content with different updated_at must not ask a question."""
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="new", updated_at="2026-03-01T00:00:00Z"))
    remote = vlt(entry("a", password="new", updated_at="2026-04-01T00:00:00Z"))

    result = sync.merge_vaults(base, local, remote)

    assert result.clean
    assert by_id(result.accounts, "a")["password"] == "new"


def test_identical_content_converges_on_one_answer():
    """
    Both PCs run the same merge and must reach the same vault, or they trade
    cosmetically different copies forever.
    """
    base = vlt(entry("a", password="old"))
    l = vlt(entry("a", password="new", updated_at="2026-03-01T00:00:00Z"))
    r = vlt(entry("a", password="new", updated_at="2026-04-01T00:00:00Z"))

    one = sync.merge_vaults(base, l, r).accounts
    other = sync.merge_vaults(base, r, l).accounts

    assert one == other


def test_both_sides_edited_is_a_conflict():
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="mine"))
    remote = vlt(entry("a", password="theirs"))

    result = sync.merge_vaults(base, local, remote)

    assert not result.clean
    assert result.conflicts[0].kind == "edit"
    assert "a" not in ids(result.accounts), "conflicts are held back"


def test_edited_here_archived_there_is_flagged_as_an_archive_conflict():
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="mine"))
    remote = vlt(entry("a", password="old", archived_at="2026-02-01T00:00:00Z"))

    result = sync.merge_vaults(base, local, remote)

    assert result.conflicts[0].kind == "archive"


# --- clocks must not decide anything -------------------------------------
def test_an_out_of_order_clock_does_not_change_the_outcome():
    """
    The remote edit carries a timestamp a year in the past -- a PC with a wrong
    clock. The merge follows the base, not the clock, so the edit still wins.
    """
    base = vlt(entry("a", password="old", updated_at="2026-05-01T00:00:00Z"))
    local = vlt(entry("a", password="old", updated_at="2026-05-01T00:00:00Z"))
    remote = vlt(entry("a", password="new", updated_at="2025-01-01T00:00:00Z"))

    result = sync.merge_vaults(base, local, remote)

    assert result.clean
    assert by_id(result.accounts, "a")["password"] == "new"


# --- purge (the one destructive operation) -------------------------------
def test_a_purge_on_the_server_removes_an_untouched_archived_entry():
    """Purging is offered from the Archive only, so that is what it hits."""
    gone = entry("a", archived_at="2026-01-02T00:00:00Z")
    base = vlt(gone)
    local = vlt(dict(gone))
    remote = vlt()

    result = sync.merge_vaults(base, local, remote)

    assert result.clean
    assert ids(result.accounts) == set()
    assert result.stats["removed"] == 1


def test_a_live_entry_missing_from_the_server_asks_rather_than_dropping():
    """
    Regression (Windows 2.4.0, Linux 0.3.0): a vault synced with one server, then with another
    holding an older copy. The entry the older copy lacked looked "purged on
    the server, untouched here" and vanished without a word.
    """
    base = vlt(entry("a"), entry("b"))
    local = vlt(entry("a"), entry("b"))
    remote = vlt(entry("a"))

    result = sync.merge_vaults(base, local, remote)

    assert [c.kind for c in result.conflicts] == ["missing"]
    assert result.conflicts[0].id == "b"
    assert result.stats["removed"] == 0
    assert result.needs_push


def test_by_default_a_missing_entry_is_kept_and_uploaded_again():
    base = vlt(entry("a"), entry("b"))
    result = sync.merge_vaults(base, vlt(entry("a"), entry("b")),
                               vlt(entry("a")))

    final = sync.resolve(result)

    assert ids(final) == {"a", "b"}
    assert not vault.is_archived(by_id(final, "b"))


def test_agreeing_a_missing_entry_is_gone_archives_it_rather_than_destroying():
    base = vlt(entry("a"), entry("b", site="kept"))
    result = sync.merge_vaults(base, vlt(entry("a"), entry("b", site="kept")),
                               vlt(entry("a")))

    final = sync.resolve(result, {"b": sync.KEEP_REMOTE})

    archived = [a for a in final if vault.is_archived(a)]
    assert [a["site"] for a in archived] == ["kept"]


def test_purged_there_but_edited_here_asks_rather_than_dropping():
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="mine"))
    remote = vlt()

    result = sync.merge_vaults(base, local, remote)

    assert result.conflicts[0].kind == "purge"


def test_an_entry_added_here_and_not_yet_pushed_survives():
    base = vlt()
    local = vlt(entry("a"))
    remote = vlt()

    result = sync.merge_vaults(base, local, remote)

    assert result.clean
    assert ids(result.accounts) == {"a"}


# --- work in the push direction counts as work ---------------------------
def test_a_never_pushed_vault_is_not_reported_as_up_to_date():
    """
    Regression: `changed` once counted only what a merge altered LOCALLY, so
    the very first sync -- nothing to pull, the whole vault to upload --
    reported "already up to date" and never sent anything.
    """
    result = sync.merge_vaults(None, vlt(entry("a"), entry("b")), vlt())

    assert result.changed
    assert result.needs_push
    assert result.pulled == 0
    assert "uploaded" in result.summary()


def test_a_local_edit_that_beats_the_server_needs_pushing():
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="mine"))
    remote = vlt(entry("a", password="old"))

    result = sync.merge_vaults(base, local, remote)

    assert result.clean and result.needs_push


def test_a_purge_here_still_has_to_reach_the_server():
    base = vlt(entry("a"))
    local = vlt()
    remote = vlt(entry("a"))

    result = sync.merge_vaults(base, local, remote)

    assert result.needs_push


def test_a_pull_only_merge_does_not_need_pushing():
    """Nothing to send back, so the push is skipped and no revision burnt."""
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="old"))
    remote = vlt(entry("a", password="new"))

    result = sync.merge_vaults(base, local, remote)

    assert result.changed and result.pulled == 1
    assert not result.needs_push


def test_conflicts_always_need_pushing():
    base = vlt(entry("a", password="old"))
    result = sync.merge_vaults(base, vlt(entry("a", password="mine")),
                               vlt(entry("a", password="theirs")))

    assert result.needs_push


# --- resolution: no branch may lose data ---------------------------------
@pytest.mark.parametrize("choice", [sync.KEEP_LOCAL, sync.KEEP_REMOTE,
                                    sync.KEEP_BOTH])
def test_no_resolution_ever_discards_either_version(choice):
    """
    Whichever side loses a conflict is still in the vault afterwards -- as a
    live entry, or as a revision in the kept entry's history -- so a misclick
    is a revert away.
    """
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="mine"))
    remote = vlt(entry("a", password="theirs"))

    result = sync.merge_vaults(base, local, remote)
    accounts = sync.resolve(result, {"a": choice})

    passwords = {a["password"] for a in accounts}
    passwords |= {r["password"] for a in accounts for r in a.get("history", [])}
    assert {"mine", "theirs"} <= passwords


def test_keeping_one_side_puts_the_other_in_its_history():
    """
    The version not kept becomes the entry's latest revision: one entry,
    revertable in one click, and nothing added to the archive.
    """
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="mine"))
    remote = vlt(entry("a", password="theirs"))

    result = sync.merge_vaults(base, local, remote)
    [kept] = sync.resolve(result, {"a": sync.KEEP_REMOTE})

    assert kept["id"] == "a" and kept["password"] == "theirs"
    assert not vault.is_archived(kept)
    latest = kept["history"][0]
    assert latest["password"] == "mine"
    assert latest["changed"] == ["password"]


def test_keeping_both_leaves_two_live_entries_with_distinct_ids():
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="mine"))
    remote = vlt(entry("a", password="theirs"))

    result = sync.merge_vaults(base, local, remote)
    accounts = sync.resolve(result, {"a": sync.KEEP_BOTH})

    assert len(accounts) == 2
    assert len(ids(accounts)) == 2, "duplicate ids would break the next merge"
    assert all(not vault.is_archived(a) for a in accounts)


def test_an_unresolved_conflict_defaults_to_keeping_everything():
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="mine"))
    remote = vlt(entry("a", password="theirs"))

    result = sync.merge_vaults(base, local, remote)
    accounts = sync.resolve(result)          # no choices supplied at all

    assert {a["password"] for a in accounts} == {"mine", "theirs"}


def test_honouring_a_purge_still_keeps_the_edit_in_the_archive():
    """
    The user sides with the PC that purged the entry. The other PC's edited
    version is archived rather than thrown away.
    """
    base = vlt(entry("a", password="old"))
    local = vlt(entry("a", password="mine"))
    remote = vlt()

    result = sync.merge_vaults(base, local, remote)
    accounts = sync.resolve(result, {"a": sync.KEEP_REMOTE})

    assert len(accounts) == 1
    assert accounts[0]["password"] == "mine"
    assert vault.is_archived(accounts[0])


# --- results a caller relies on ------------------------------------------
def test_an_identical_pair_reports_no_change():
    base = local = remote = vlt(entry("a"))
    result = sync.merge_vaults(base, local, remote)

    assert result.clean
    assert not result.changed
    assert result.summary() == "already up to date"


def test_local_ordering_is_preserved_so_the_list_does_not_reshuffle():
    base = vlt()
    local = vlt(entry("a"), entry("b"), entry("c"))
    remote = vlt(entry("z"))

    result = sync.merge_vaults(base, local, remote)

    assert [a["id"] for a in result.accounts] == ["a", "b", "c", "z"]


def test_merged_vault_keeps_other_top_level_keys():
    local = {"accounts": [], "sync": {"url": "https://vault.example"}}
    out = sync.merged_vault(local, [entry("a")])

    assert out["sync"] == {"url": "https://vault.example"}
    assert len(out["accounts"]) == 1


def test_a_merge_result_survives_validate_vault():
    """The merged list has to be storable without anything being stripped."""
    base = vlt(entry("a", password="old"))
    result = sync.merge_vaults(base, vlt(entry("a", password="mine")),
                               vlt(entry("a", password="theirs")))
    merged = sync.merged_vault({"accounts": []}, sync.resolve(result))

    out = vault.validate_vault(merged)

    assert len(out["accounts"]) == 2
    assert len({a["id"] for a in out["accounts"]}) == 2


# --- revision history ----------------------------------------------------
def rev(password, at, changed=("password",)):
    return {"site": "site", "username": "u", "password": password,
            "replaced_at": at, "changed": list(changed)}


def with_history(e, *revs):
    e = dict(e)
    e["history"] = list(revs)
    vault.normalize_history(e)
    return e


def test_both_pcs_archiving_the_same_entry_is_not_a_conflict():
    """
    Regression: archived_at timestamps were compared, so two PCs that both
    archived an entry got an "edited on both sides" dialog.
    """
    base = vlt(entry("a"))
    local = vlt(entry("a", archived_at="2026-02-01T00:00:00Z"))
    remote = vlt(entry("a", archived_at="2026-02-03T09:30:00Z"))

    result = sync.merge_vaults(base, local, remote)

    assert result.clean
    assert vault.is_archived(by_id(result.accounts, "a"))


def test_histories_from_both_sides_are_combined():
    base = vlt(entry("a"))
    local = vlt(with_history(entry("a"), rev("p-local", "2026-01-01T00:00:00.000001Z")))
    remote = vlt(with_history(entry("a"), rev("p-remote", "2026-01-02T00:00:00.000001Z")))

    result = sync.merge_vaults(base, local, remote)

    [merged] = result.accounts
    assert [r["password"] for r in merged["history"]] == ["p-remote", "p-local"]
    assert result.clean, "history never asks a question"


def test_a_history_only_difference_still_syncs_both_ways():
    base = vlt(entry("a"))
    local = vlt(with_history(entry("a"), rev("only-here", "2026-01-01T00:00:00.000001Z")))
    remote = vlt(with_history(entry("a"), rev("only-there", "2026-01-02T00:00:00.000001Z")))

    result = sync.merge_vaults(base, local, remote)

    assert result.changed, "the local vault gains a revision"
    assert result.needs_push, "and so does the server"
    assert result.pulled == 0 and result.stats["push"] == 0, \
        "but no entry's fields changed"
    assert result.summary() == "revision history updated"


def test_the_combined_history_is_still_capped_at_ten():
    base = vlt(entry("a"))
    mine = [rev(f"l{i}", f"2026-01-{i + 1:02d}T00:00:00.000000Z") for i in range(8)]
    theirs = [rev(f"r{i}", f"2026-02-{i + 1:02d}T00:00:00.000000Z") for i in range(8)]
    local = vlt(with_history(entry("a"), *mine))
    remote = vlt(with_history(entry("a"), *theirs))

    [merged] = sync.merge_vaults(base, local, remote).accounts

    assert len(merged["history"]) == vault.HISTORY_LIMIT
    assert merged["history"][0]["password"] == "r7", "newest kept"


def test_both_pcs_compute_the_same_history():
    base = vlt(entry("a"))
    l = vlt(with_history(entry("a"), rev("x", "2026-01-01T00:00:00.000001Z")))
    r = vlt(with_history(entry("a"), rev("y", "2026-01-02T00:00:00.000001Z")))

    one = sync.merge_vaults(base, l, r).accounts
    other = sync.merge_vaults(base, r, l).accounts

    assert one[0]["history"] == other[0]["history"]


def test_merging_never_modifies_the_vault_it_was_given():
    """
    The session fingerprints the local vault at prepare() and refuses to
    commit if it changed. Merging history into it in place would make every
    sync fail with "the vault changed while the sync was open".
    """
    import copy
    base = vlt(entry("a"))
    local = vlt(with_history(entry("a"), rev("here", "2026-01-01T00:00:00.000001Z")))
    remote = vlt(with_history(entry("a"), rev("there", "2026-01-02T00:00:00.000001Z")))
    before = copy.deepcopy(local)

    sync.resolve(sync.merge_vaults(base, local, remote))

    assert local == before


def test_a_cleared_history_wins_over_an_uncleared_copy():
    base = vlt(entry("a"))
    stale = with_history(entry("a"), rev("old", "2026-01-01T00:00:00.000001Z"))
    cleared = dict(stale)
    vault.clear_history(cleared)

    [merged] = sync.merge_vaults(base, vlt(cleared), vlt(stale)).accounts

    assert "history" not in merged


def test_history_arriving_from_the_server_alone_is_still_work():
    """
    Mutation-test gap: the server already has the cleared history, so nothing
    needs pushing -- only pulling. If that did not count as a change, the GUI
    would report "already up to date" and never apply it here.
    """
    base = vlt(entry("a"))
    stale = with_history(entry("a"), rev("old", "2026-01-01T00:00:00.000001Z"))
    cleared = dict(stale)
    vault.clear_history(cleared)

    result = sync.merge_vaults(base, vlt(stale), vlt(cleared))

    assert not result.needs_push, "the server is already right"
    assert result.changed, "but this PC still has to catch up"
