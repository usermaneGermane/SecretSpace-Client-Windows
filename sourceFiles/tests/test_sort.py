"""Ordering of the main account list."""

import appconfig
import vault


def _entry(site, username="user", updated_at=None):
    e = {"site": site, "username": username, "password": "pw"}
    if updated_at:
        e["updated_at"] = updated_at
    return e


def _sites(accounts):
    return [a["site"] for a in accounts]


ACCOUNTS = [
    _entry("github", updated_at="2026-10-01T09:00:00Z"),
    _entry("Amazon", updated_at="2026-10-03T09:00:00Z"),
    _entry("legacy-b"),                       # pre-2.0, never edited
    _entry("bank", updated_at="2026-09-20T09:00:00Z"),
    _entry("legacy-a"),
]


def test_recently_modified_first():
    assert _sites(vault.sort_accounts(ACCOUNTS, "modified_desc")) == [
        "Amazon", "github", "bank", "legacy-a", "legacy-b"]


def test_oldest_modified_first():
    assert _sites(vault.sort_accounts(ACCOUNTS, "modified_asc")) == [
        "bank", "github", "Amazon", "legacy-a", "legacy-b"]


def test_undated_entries_go_last_both_ways():
    for order in ("modified_desc", "modified_asc"):
        assert _sites(vault.sort_accounts(ACCOUNTS, order))[-2:] == [
            "legacy-a", "legacy-b"]


def test_name_order_ignores_case():
    assert _sites(vault.sort_accounts(ACCOUNTS, "name_asc")) == [
        "Amazon", "bank", "github", "legacy-a", "legacy-b"]
    assert _sites(vault.sort_accounts(ACCOUNTS, "name_desc")) == [
        "legacy-b", "legacy-a", "github", "bank", "Amazon"]


def test_same_site_sorted_by_username():
    accounts = [_entry("mail", "zoe"), _entry("mail", "Adam")]
    assert [a["username"] for a in vault.sort_accounts(accounts, "name_asc")] \
        == ["Adam", "zoe"]


def test_same_timestamp_falls_back_to_name():
    stamp = "2026-10-05T12:00:00Z"
    accounts = [_entry("zeta", updated_at=stamp), _entry("alpha", updated_at=stamp)]
    assert _sites(vault.sort_accounts(accounts, "modified_desc")) == [
        "alpha", "zeta"]


def test_unknown_order_falls_back_to_name():
    assert _sites(vault.sort_accounts(ACCOUNTS, "bogus")) == _sites(
        vault.sort_accounts(ACCOUNTS, "name_asc"))


def test_does_not_reorder_the_vault():
    accounts = list(ACCOUNTS)
    vault.sort_accounts(accounts, "name_asc")
    assert accounts == ACCOUNTS


def test_edit_moves_entry_to_the_top():
    data = {"accounts": []}
    first = vault.add_account(data, "first", "u", "pw")
    second = vault.add_account(data, "second", "u", "pw")
    first["updated_at"] = "2026-01-01T00:00:00Z"
    second["updated_at"] = "2026-02-01T00:00:00Z"
    assert vault.update_entry(first, password="new-pw")
    assert _sites(vault.sort_accounts(data["accounts"], "modified_desc"))[0] \
        == "first"


def test_stored_sort_order(monkeypatch):
    monkeypatch.setattr(appconfig, "load_config", lambda: {})
    assert appconfig.sort_order() == "modified_desc"
    monkeypatch.setattr(appconfig, "load_config",
                        lambda: {"sort_order": "name_asc"})
    assert appconfig.sort_order() == "name_asc"
    monkeypatch.setattr(appconfig, "load_config",
                        lambda: {"sort_order": "nonsense"})
    assert appconfig.sort_order() == "modified_desc"
