"""An entry's name and its web address: two fields, and the address a link."""

import csv

import pytest

import changelog
import history_ui
import importers
import sync
import vault
import weblink


# --- what the form accepts ---------------------------------------------------
@pytest.mark.parametrize("typed,stored", [
    ("https://github.com/login", "https://github.com/login"),
    ("http://router.local", "http://router.local"),
    ("github.com/login", "https://github.com/login"),
    ("  github.com  ", "https://github.com"),
    ("localhost:8080", "https://localhost:8080"),
    ("10.10.10.1:4444/webconsole", "https://10.10.10.1:4444/webconsole"),
    ("HTTPS://Example.com", "HTTPS://Example.com"),
])
def test_good_addresses_are_kept_with_a_scheme(typed, stored):
    assert weblink.clean(typed) == (stored, "")


def test_an_empty_address_is_fine_because_it_is_optional():
    assert weblink.clean("") == ("", "")
    assert weblink.clean("   ") == ("", "")


@pytest.mark.parametrize("typed", [
    "javascript:alert(1)",
    "file:///C:/Windows/System32/calc.exe",
    "file://server/share",
    "mailto:a@b.c",
    "ms-settings:privacy",
    "ftp://example.com",
    "data:text/html,hi",
    "https://",
    "https:///nohost",
    "two words.com",
    "https://example.com/" + "a" * 3000,
])
def test_anything_that_is_not_a_web_link_is_refused(typed):
    value, problem = weblink.clean(typed)
    assert problem
    assert weblink.openable(typed) is None


# --- opening -------------------------------------------------------------
def test_a_click_opens_the_address_in_the_browser():
    opened = []
    assert weblink.open_in_browser("github.com/login",
                                   opener=lambda u: opened.append(u) or True)
    assert opened == ["https://github.com/login"]


def test_a_bad_address_already_in_a_vault_is_never_opened():
    # Written by another member of a shared vault, or another program:
    # the form's check never saw it, so the click checks again.
    opened = []
    for bad in ("file:///C:/Windows/System32/calc.exe", "javascript:x",
                "ms-settings:privacy"):
        assert not weblink.open_in_browser(bad, opener=opened.append)
    assert opened == []


def test_a_browser_that_fails_to_start_is_reported_not_raised():
    def broken(_):
        raise OSError("no browser")
    assert weblink.open_in_browser("https://a.example", opener=broken) is False


def test_the_card_shows_the_address_without_https():
    assert weblink.display("https://github.com/") == "github.com"
    assert weblink.display("https://github.com/login") == "github.com/login"
    assert weblink.display("http://router.local") == "router.local"


# --- stored like the other optional fields --------------------------------
def test_the_address_survives_validation_and_stays_absent_when_empty():
    data = vault.validate_vault({"accounts": [
        {"site": "GitHub", "username": "u", "password": "p",
         "url": "https://github.com/login"},
        {"site": "Bank", "username": "u", "password": "p", "url": ""},
    ]})
    first, second = data["accounts"]
    assert first["url"] == "https://github.com/login"
    assert "url" not in second


def test_add_account_stores_the_address():
    v = {"accounts": []}
    e = vault.add_account(v, "GitHub", "u", "p", url="https://github.com")
    assert e["url"] == "https://github.com"
    assert "url" not in vault.add_account(v, "Bank", "u", "p")


def test_changing_the_address_is_an_edit_with_history_and_can_be_undone():
    v = {"accounts": []}
    e = vault.add_account(v, "GitHub", "u", "p", url="https://old.example")
    assert vault.update_entry(e, site="GitHub", username="u", password="p",
                              notes="", totp="", url="https://new.example")
    rev = e["history"][0]
    assert rev["changed"] == ["url"]
    assert rev["url"] == "https://old.example"
    assert vault.revert_entry(e, rev["rid"])
    assert e["url"] == "https://old.example"


def test_clearing_the_address_removes_the_key():
    v = {"accounts": []}
    e = vault.add_account(v, "GitHub", "u", "p", url="https://github.com")
    vault.update_entry(e, site="GitHub", username="u", password="p", url="")
    assert "url" not in e


def test_revisions_without_an_address_keep_their_old_ids():
    # The id is a hash over the fields. Adding url to the list must not
    # rename every earlier version already in people's vaults.
    import hashlib
    import json
    rev = {"site": "a", "username": "u", "password": "p",
           "replaced_at": "2026-01-01T00:00:00.000000Z"}
    before = hashlib.sha256(json.dumps(
        [rev["replaced_at"], ["a", "u", "p", "", ""]]).encode()).hexdigest()[:16]
    assert vault._revision_id(rev) == before


def test_csv_export_fills_the_url_column(tmp_path):
    out = tmp_path / "e.csv"
    vault.export_csv({"accounts": [
        {"site": "GitHub", "username": "u", "password": "p",
         "url": "https://github.com/login"}]}, str(out))
    rows = list(csv.reader(out.open(encoding="utf-8")))
    assert rows[0][:2] == ["name", "url"]
    assert rows[1][:2] == ["GitHub", "https://github.com/login"]


# --- sync -------------------------------------------------------------------
def _e(**extra):
    e = {"id": "a", "site": "GitHub", "username": "u", "password": "p",
         "updated_at": "2026-01-01T00:00:00Z"}
    e.update(extra)
    return e


def test_an_address_added_on_the_other_pc_arrives_here():
    result = sync.merge_vaults({"accounts": [_e()]}, {"accounts": [_e()]},
                               {"accounts": [_e(url="https://github.com")]})
    assert result.clean
    assert result.accounts[0]["url"] == "https://github.com"


def test_different_addresses_on_both_sides_are_a_conflict():
    result = sync.merge_vaults({"accounts": [_e()]},
                               {"accounts": [_e(url="https://a.example")]},
                               {"accounts": [_e(url="https://b.example")]})
    assert not result.clean


# --- import ---------------------------------------------------------------
def test_chrome_export_keeps_name_and_address_apart(tmp_path):
    p = tmp_path / "c.csv"
    p.write_text("name,url,username,password,note\n"
                 "GitHub,https://github.com/login,me,pw,\n", encoding="utf-8")
    row = importers.parse_csv(str(p)).rows[0]
    assert (row.site, row.url) == ("GitHub", "https://github.com/login")


def test_bitwarden_login_uri_is_the_address(tmp_path):
    p = tmp_path / "b.csv"
    p.write_text("folder,favorite,type,name,notes,fields,reprompt,login_uri,"
                 "login_username,login_password,login_totp\n"
                 "Work,0,login,GitHub,,,0,https://github.com,me,pw,\n",
                 encoding="utf-8")
    row = importers.parse_csv(str(p)).rows[0]
    assert (row.site, row.url, row.username) == ("GitHub", "https://github.com",
                                                 "me")


def test_an_export_without_addresses_has_none(tmp_path):
    p = tmp_path / "n.csv"
    p.write_text("name,username,password\nSite,u,p\n", encoding="utf-8")
    assert importers.parse_csv(str(p)).rows[0].url == ""


# --- words on screen ------------------------------------------------------
def test_history_and_change_log_name_the_new_field():
    assert history_ui.FIELD_LABELS["url"] == "web address"
    assert history_ui.FIELD_LABELS["site"] == "name"
    line = {"action": changelog.EDITED, "title": "GitHub", "fields": ["url"]}
    assert "web address" in changelog.describe(line)
