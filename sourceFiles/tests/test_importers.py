"""Column mapping for exports from other password managers."""

import json

import pytest

import importers


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


CHROME = "name,url,username,password,note\nGitHub,https://github.com/login,me@example.com,hunter2,\n"
KEEPASS = '"Account","Login Name","Password","Web Site","Comments"\n"Bank","alice","s3cret","https://bank.example.com",""\n'
LASTPASS = "url,username,password,totp,extra,name,grouping,fav\nhttps://mail.example.com,bob,pw123,,,Mail,Personal,0\n"
BITWARDEN = ("folder,favorite,type,name,notes,fields,reprompt,login_uri,"
             "login_username,login_password,login_totp\n"
             "Work,0,login,GitHub,recovery codes,,0,https://github.com,"
             "me@x.com,hunter2,JBSWY3DPEHPK3PXP\n")


@pytest.mark.parametrize("text,expected", [
    (CHROME, ("GitHub", "me@example.com", "hunter2")),
    (KEEPASS, ("Bank", "alice", "s3cret")),
    (LASTPASS, ("Mail", "bob", "pw123")),
    (BITWARDEN, ("GitHub", "me@x.com", "hunter2")),
])
def test_real_world_exports_map_correctly(tmp_path, text, expected):
    row = importers.parse_csv(write(tmp_path, "e.csv", text)).rows[0]
    assert (row.site, row.username, row.password) == expected


def test_semicolon_delimited_csv(tmp_path):
    text = "name;username;password\nSite;user;pass\n"
    assert importers.parse_csv(write(tmp_path, "e.csv", text)).rows == [
        importers.Account("Site", "user", "pass", "", "")]


def test_headerless_csv_assumes_site_user_password(tmp_path):
    text = "example.com,alice,pw1\nother.com,bob,pw2\n"
    rows = importers.parse_csv(write(tmp_path, "e.csv", text)).rows
    assert [(r.site, r.username, r.password) for r in rows] == [
        ("example.com", "alice", "pw1"), ("other.com", "bob", "pw2")]


def test_urls_are_tidied_into_site_names(tmp_path):
    text = "url,username,password\nhttps://www.example.com/login?x=1,u,p\n"
    assert importers.parse_csv(write(tmp_path, "e.csv", text)).rows == [
        importers.Account("example.com", "u", "p", "", "")]


def test_blank_lines_are_ignored(tmp_path):
    text = "name,username,password\nA,u,p\n\n\nB,u2,p2\n"
    assert len(importers.parse_csv(write(tmp_path, "e.csv", text)).rows) == 2


def test_utf8_bom_is_handled(tmp_path):
    p = tmp_path / "bom.csv"
    p.write_bytes(b"\xef\xbb\xbfname,username,password\nSite,u,p\n")
    assert importers.parse_csv(str(p)).rows == [
        importers.Account("Site", "u", "p", "", "")]


# --- the user must be told what cannot be stored --------------------------
def test_totp_and_notes_are_imported(tmp_path):
    row = importers.parse_csv(write(tmp_path, "bw.csv", BITWARDEN)).rows[0]
    assert row.totp == "JBSWY3DPEHPK3PXP"
    assert row.notes == "recovery codes"


def test_imported_fields_reports_what_was_carried(tmp_path):
    rows = importers.parse_csv(write(tmp_path, "bw.csv", BITWARDEN)).rows
    assert importers.imported_fields(rows) == ["TOTP / 2FA secrets", "notes"]


def test_nothing_extra_is_reported_for_a_plain_export(tmp_path):
    result = importers.parse_csv(write(tmp_path, "c.csv", CHROME))
    assert result.dropped == []
    assert importers.imported_fields(result.rows) == []


def test_unsupported_columns_are_still_reported(tmp_path):
    text = ("name,username,password,card_number\n"
            "Shop,u,p,4111111111111111\n")
    assert "card details" in importers.parse_csv(
        write(tmp_path, "c.csv", text)).dropped


# --- JSON -----------------------------------------------------------------
def test_json_list_of_objects(tmp_path):
    text = json.dumps([{"site": "A", "username": "u", "password": "p"}])
    assert importers.parse_json(write(tmp_path, "e.json", text)).rows == [
        importers.Account("A", "u", "p", "", "")]


def test_json_vault_shape(tmp_path):
    text = json.dumps({"accounts": [{"site": "A", "username": "u", "password": "p"}]})
    assert importers.parse_json(write(tmp_path, "e.json", text)).rows == [
        importers.Account("A", "u", "p", "", "")]


def test_parse_import_file_dispatches_on_extension(tmp_path):
    j = write(tmp_path, "e.json", json.dumps([{"site": "A", "username": "u", "password": "p"}]))
    c = write(tmp_path, "e.csv", CHROME)
    assert importers.parse_import_file(j).rows == [
        importers.Account("A", "u", "p", "", "")]
    assert importers.parse_import_file(c).rows[0][0] == "GitHub"


def test_accounts_from_vault():
    data = {"accounts": [{"site": "A", "username": "u", "password": "p"}]}
    assert importers.accounts_from_vault(data).rows == [
        importers.Account("A", "u", "p", "", "")]


@pytest.mark.parametrize("payload", ["[]", "{}", '"nope"', "null"])
def test_degenerate_json_returns_no_rows(tmp_path, payload):
    assert importers.parse_json(write(tmp_path, "e.json", payload)).rows == []


def test_json_notes_and_totp_are_carried(tmp_path):
    text = json.dumps([{"site": "A", "username": "u", "password": "p",
                        "notes": "hello", "totp": "SEED"}])
    row = importers.parse_json(write(tmp_path, "e.json", text)).rows[0]
    assert (row.notes, row.totp) == ("hello", "SEED")


def test_vault_round_trip_preserves_notes_and_totp():
    data = {"accounts": [{"site": "A", "username": "u", "password": "p",
                          "notes": "n", "totp": "T"}]}
    row = importers.accounts_from_vault(data).rows[0]
    assert (row.notes, row.totp) == ("n", "T")


def test_named_header_is_used_even_if_the_sniffer_says_no(tmp_path, monkeypatch):
    """Python 3.12's csv.Sniffer reports no header once blank lines are in
    the sample, which imported the header row as an account."""
    import csv
    monkeypatch.setattr(csv.Sniffer, "has_header", lambda self, sample: False)
    text = "name,username,password\nA,u,p\n\n\nB,u2,p2\n"
    rows = importers.parse_csv(write(tmp_path, "e.csv", text)).rows
    assert [(r.site, r.username) for r in rows] == [("A", "u"), ("B", "u2")]


def test_headerless_row_with_header_like_words_is_still_data(tmp_path):
    text = "github,username1,pass123\ngitlab,bob,pw\n"
    assert len(importers.parse_csv(write(tmp_path, "e.csv", text)).rows) == 2
