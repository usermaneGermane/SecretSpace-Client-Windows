"""Durability of vault writes, schema validation and username safety."""

import os
import csv
import json

import pytest

import vault
import crypto_utils


def _content(entry):
    """An entry minus the bookkeeping fields, for comparing against a literal.

    id is assigned by validate_vault and updated_at/archived_at move with the
    clock, so asserting on the whole dict would test the wrong thing.
    """
    return {k: v for k, v in entry.items()
            if k not in ("id", "updated_at", "archived_at")}


@pytest.fixture
def alice():
    vault.create_new_user("alice", "master-pw")
    data = vault.load_vault("master-pw", "alice")
    for i in range(5):
        vault.add_account(data, f"site{i}", "user", f"pw{i}")
    vault.save_vault("master-pw", data, "alice")
    return data


# --- the bug that could lose every stored password ------------------------
@pytest.mark.parametrize("syscall", ["fsync", "replace"])
def test_interrupted_save_leaves_the_vault_intact(alice, monkeypatch, syscall):
    """
    A save that dies part-way (full disk, power cut, antivirus) must not
    damage the existing vault. The previous implementation opened the real
    file with "wb", truncating it before the new bytes landed.
    """
    path = vault.get_vault_path("alice")
    before = open(path, "rb").read()

    def boom(*args, **kwargs):
        raise OSError("No space left on device")

    real = getattr(os, syscall)
    monkeypatch.setattr(os, syscall, boom)
    with pytest.raises(OSError):
        vault.save_vault("master-pw", {"accounts": []}, "alice")
    monkeypatch.setattr(os, syscall, real)      # not undo(): that would also
                                                # revert the data-dir fixture
    assert open(path, "rb").read() == before
    assert len(vault.load_vault("master-pw", "alice")["accounts"]) == 5


def test_interrupted_save_leaves_no_temp_files(alice, monkeypatch):
    real = os.replace
    monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    with pytest.raises(OSError):
        vault.save_vault("master-pw", {"accounts": []}, "alice")
    monkeypatch.setattr(os, "replace", real)
    leftovers = [f for f in os.listdir(vault.get_data_dir()) if ".tmp-" in f]
    assert leftovers == []


def test_corrupt_primary_vault_is_recovered_from_backup(alice):
    vault.save_vault("master-pw", alice, "alice")        # creates the .bak
    with open(vault.get_vault_path("alice"), "wb") as f:
        f.write(b"corrupted junk")
    assert len(vault.load_vault("master-pw", "alice")["accounts"]) == 5


def test_backup_fallback_does_not_mask_a_wrong_password(alice):
    vault.save_vault("master-pw", alice, "alice")
    with pytest.raises(ValueError):
        vault.load_vault("wrong-pw", "alice")


def test_save_creates_a_backup_generation(alice):
    vault.save_vault("master-pw", alice, "alice")
    assert os.path.exists(vault.get_backup_path("alice"))


# --- usernames become filenames -------------------------------------------
@pytest.mark.parametrize("bad", [
    "../../etc/passwd", "/etc/evil", "a/b", "a\\b", "a:b", "", "   ",
    "con", "PRN", "nul", "com1", "x" * 64, ".hidden",
])
def test_dangerous_usernames_are_rejected(bad):
    with pytest.raises(ValueError):
        vault.get_vault_path(bad)


@pytest.mark.parametrize("good", ["alice", "Bob Smith", "dev.test_1", "user-2"])
def test_ordinary_usernames_are_accepted(good):
    assert vault.get_vault_path(good).endswith(f"{good}.vault.enc")


def test_vault_path_stays_inside_the_data_directory():
    path = os.path.abspath(vault.get_vault_path("alice"))
    assert path.startswith(os.path.abspath(vault.get_data_dir()) + os.sep)


# --- schema validation ----------------------------------------------------
@pytest.mark.parametrize("payload", [
    {"entries": []}, [1, 2], "a string", {"accounts": "not a list"}, 42,
])
def test_malformed_vaults_raise_a_clean_error(payload):
    os.makedirs(vault.get_data_dir(), exist_ok=True)
    with open(vault.get_vault_path("bob"), "wb") as f:
        f.write(crypto_utils.encrypt("pw", payload))
    with pytest.raises(ValueError):
        vault.load_vault("pw", "bob")


def test_junk_rows_are_skipped_rather_than_losing_the_vault():
    os.makedirs(vault.get_data_dir(), exist_ok=True)
    payload = {"accounts": [{"site": "a", "username": "b", "password": "c"},
                            "junk", 5, None]}
    with open(vault.get_vault_path("bob"), "wb") as f:
        f.write(crypto_utils.encrypt("pw", payload))
    accounts = vault.load_vault("pw", "bob")["accounts"]
    assert len(accounts) == 1
    assert _content(accounts[0]) == {"site": "a", "username": "b",
                                     "password": "c"}


def test_missing_fields_are_filled_in():
    out = vault.validate_vault({"accounts": [{"site": "x"}]})["accounts"]
    assert _content(out[0]) == {"site": "x", "username": "", "password": ""}


# --- lifecycle ------------------------------------------------------------
def test_unknown_user_raises_filenotfound():
    with pytest.raises(FileNotFoundError):
        vault.load_vault("pw", "nobody")


def test_duplicate_user_is_refused(alice):
    with pytest.raises(FileExistsError):
        vault.create_new_user("alice", "other")


def test_delete_requires_the_right_password(alice):
    with pytest.raises(ValueError):
        vault.delete_user("alice", "wrong")
    assert os.path.exists(vault.get_vault_path("alice"))


def test_delete_removes_vault_and_backup(alice):
    vault.save_vault("master-pw", alice, "alice")
    vault.delete_user("alice", "master-pw")
    assert not os.path.exists(vault.get_vault_path("alice"))
    assert not os.path.exists(vault.get_backup_path("alice"))


def test_list_users(alice):
    vault.create_new_user("bob", "pw")
    assert vault.list_users() == ["alice", "bob"]


# --- rekey / migration ----------------------------------------------------
def test_legacy_iteration_vault_is_flagged_for_rekey(alice):
    with open(vault.get_vault_path("alice"), "wb") as f:
        f.write(crypto_utils.encrypt("master-pw", alice, iterations=200_000))
    assert vault.needs_rekey("alice") is True
    vault.save_vault("master-pw", vault.load_vault("master-pw", "alice"), "alice")
    assert vault.needs_rekey("alice") is False


# --- export ---------------------------------------------------------------
def test_encrypted_export_is_still_encrypted(alice, tmp_path):
    # The marker is long on purpose. Searching a base64 blob for a short
    # string like "pw0" is a coincidence lottery -- 3 characters turn up in
    # ~900 characters of random base64 often enough to fail a build now and
    # then, and the odds rise with every field an entry gains. At 40
    # characters a chance match is not going to happen.
    marker = "plaintext-marker-3f9a2b7c4e1d8065afbe2971"
    vault.add_account(alice, "marker-site", "u", marker)
    vault.save_vault("master-pw", alice, "alice")

    dest = tmp_path / "backup.enc"
    vault.export_encrypted("alice", str(dest))
    blob = dest.read_bytes()

    assert marker.encode() not in blob
    assert crypto_utils.decrypt("master-pw", blob)["accounts"][0]["site"] == "site0"


def test_csv_export_survives_awkward_characters(tmp_path):
    data = {"accounts": [{"site": "s", "username": "u",
                          "password": 'we,ird"pass\nword'}]}
    dest = tmp_path / "out.csv"
    assert vault.export_csv(data, str(dest)) == 1
    row = next(iter(csv.DictReader(dest.open())))
    assert row["password"] == 'we,ird"pass\nword'


def test_json_export_round_trips(alice, tmp_path):
    dest = tmp_path / "out.json"
    assert vault.export_json(alice, str(dest)) == 5
    import json
    assert json.loads(dest.read_text())["accounts"][0]["site"] == "site0"


# --- optional fields (notes / TOTP) ---------------------------------------
def test_notes_and_totp_survive_a_save_and_load():
    vault.create_new_user("dana", "pw")
    data = vault.load_vault("pw", "dana")
    vault.add_account(data, "github", "u", "p", notes="recovery codes",
                      totp="JBSWY3DPEHPK3PXP")
    vault.save_vault("pw", data, "dana")
    acc = vault.load_vault("pw", "dana")["accounts"][0]
    assert acc["notes"] == "recovery codes"
    assert acc["totp"] == "JBSWY3DPEHPK3PXP"


def test_entries_without_optional_fields_stay_minimal():
    """Only id is added; no empty notes/totp/archived_at are invented."""
    out = vault.validate_vault(
        {"accounts": [{"site": "a", "username": "b", "password": "c"}]})
    assert set(out["accounts"][0]) == {"site", "username", "password", "id"}


def test_blank_optional_fields_are_not_stored():
    out = vault.validate_vault({"accounts": [
        {"site": "a", "username": "b", "password": "c", "notes": "", "totp": ""}]})
    assert set(out["accounts"][0]) == {"site", "username", "password", "id"}


def test_validate_vault_no_longer_strips_optional_fields():
    """The earlier implementation rebuilt entries with three keys only."""
    out = vault.validate_vault({"accounts": [
        {"site": "a", "username": "b", "password": "c", "totp": "SEED"}]})
    assert out["accounts"][0]["totp"] == "SEED"


def test_csv_export_includes_notes_and_totp(tmp_path):
    data = {"accounts": [{"site": "s", "username": "u", "password": "p",
                          "notes": "n", "totp": "T"}]}
    dest = tmp_path / "out.csv"
    vault.export_csv(data, str(dest))
    row = next(iter(csv.DictReader(dest.open())))
    assert (row["notes"], row["totp"]) == ("n", "T")


# --- changing the master password must actually revoke the old one --------
def test_old_master_password_stops_working_after_a_change(alice):
    """
    Regression: save_vault rotated the outgoing file into .bak, so after a
    password change the .bak was still encrypted with the OLD password and
    load_vault's backup fallback happily accepted it.
    """
    vault.save_vault("master-pw", alice, "alice")        # ensure a .bak exists
    vault.save_vault("new-pw", alice, "alice", rekey=True)

    assert len(vault.load_vault("new-pw", "alice")["accounts"]) == 5
    with pytest.raises(ValueError):
        vault.load_vault("master-pw", "alice")


def test_rekey_still_leaves_a_usable_backup(alice):
    vault.save_vault("new-pw", alice, "alice", rekey=True)
    assert os.path.exists(vault.get_backup_path("alice"))
    with open(vault.get_backup_path("alice"), "rb") as f:
        assert len(crypto_utils.decrypt("new-pw", f.read())["accounts"]) == 5


def test_ordinary_save_keeps_the_previous_generation(alice):
    """A normal save must still roll the old content into .bak."""
    alice["accounts"] = alice["accounts"][:2]
    vault.save_vault("master-pw", alice, "alice")
    with open(vault.get_backup_path("alice"), "rb") as f:
        assert len(crypto_utils.decrypt("master-pw", f.read())["accounts"]) == 5


# --- project layout: vault/ beside the app, legacy data/ still honoured ----
def test_app_dir_is_the_project_root_not_the_source_folder(monkeypatch):
    """Sources live in sourceFiles/, but the vault belongs one level up."""
    monkeypatch.delenv("SECRETSPACE_DATA_DIR", raising=False)
    app_dir = vault.get_app_dir()
    assert os.path.basename(app_dir) != "sourceFiles"
    assert os.path.isfile(os.path.join(app_dir, "sourceFiles", "vault.py"))


def test_default_vault_folder_is_named_vault(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRETSPACE_DATA_DIR", raising=False)
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(tmp_path))
    assert vault.get_data_dir() == str(tmp_path / "vault")


def test_existing_legacy_data_folder_is_still_used(tmp_path, monkeypatch):
    """Renaming the folder must not orphan an existing installation."""
    monkeypatch.delenv("SECRETSPACE_DATA_DIR", raising=False)
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(tmp_path))
    (tmp_path / "data").mkdir()
    assert vault.get_data_dir() == str(tmp_path / "data")


def test_vault_folder_wins_when_both_exist(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRETSPACE_DATA_DIR", raising=False)
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(tmp_path))
    (tmp_path / "data").mkdir()
    (tmp_path / "vault").mkdir()
    assert vault.get_data_dir() == str(tmp_path / "vault")


def test_a_legacy_vault_file_is_readable_after_the_rename(tmp_path, monkeypatch):
    """End to end: a vault created under data/ still opens after upgrading."""
    monkeypatch.delenv("SECRETSPACE_DATA_DIR", raising=False)
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(tmp_path))
    (tmp_path / "data").mkdir()
    vault.create_new_user("alice", "pw")
    data = vault.load_vault("pw", "alice")
    vault.add_account(data, "github", "u", "p")
    vault.save_vault("pw", data, "alice")

    assert (tmp_path / "data" / "alice.vault.enc").exists()
    assert not (tmp_path / "vault").exists()
    assert len(vault.load_vault("pw", "alice")["accounts"]) == 1


def test_env_override_still_beats_both(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(tmp_path))
    (tmp_path / "data").mkdir()
    monkeypatch.setenv("SECRETSPACE_DATA_DIR", str(tmp_path / "elsewhere"))
    assert vault.get_data_dir() == str(tmp_path / "elsewhere")


# ==========================================================================
# Archive instead of delete
# ==========================================================================
def test_archiving_keeps_the_entry_and_its_password():
    data = {"accounts": []}
    acc = vault.add_account(data, "github", "u", "secret")

    assert vault.archive_account(data, acc["id"])

    assert len(data["accounts"]) == 1, "archiving must not remove the entry"
    assert data["accounts"][0]["password"] == "secret"
    assert vault.is_archived(data["accounts"][0])


def test_archived_entries_leave_the_main_list_but_not_the_vault():
    data = {"accounts": []}
    keep = vault.add_account(data, "keep", "u", "p")
    gone = vault.add_account(data, "gone", "u", "p")
    vault.archive_account(data, gone["id"])

    assert [a["id"] for a in vault.active_accounts(data)] == [keep["id"]]
    assert [a["id"] for a in vault.archived_accounts(data)] == [gone["id"]]


def test_restoring_brings_an_entry_back():
    data = {"accounts": []}
    acc = vault.add_account(data, "github", "u", "p")
    vault.archive_account(data, acc["id"])

    assert vault.restore_account(data, acc["id"])

    assert vault.active_accounts(data) == [acc]
    assert "archived_at" not in acc


def test_archive_and_restore_are_idempotent():
    data = {"accounts": []}
    acc = vault.add_account(data, "github", "u", "p")

    assert vault.archive_account(data, acc["id"])
    assert not vault.archive_account(data, acc["id"]), "already archived"
    assert vault.restore_account(data, acc["id"])
    assert not vault.restore_account(data, acc["id"]), "already active"


def test_purge_is_the_only_thing_that_really_removes_an_entry():
    data = {"accounts": []}
    acc = vault.add_account(data, "github", "u", "p")
    vault.archive_account(data, acc["id"])

    assert vault.purge_account(data, acc["id"])
    assert data["accounts"] == []


def test_archived_state_survives_a_save_and_load():
    vault.create_new_user("erin", "pw")
    data = vault.load_vault("pw", "erin")
    acc = vault.add_account(data, "github", "u", "p")
    vault.archive_account(data, acc["id"])
    vault.save_vault("pw", data, "erin")

    reloaded = vault.load_vault("pw", "erin")
    assert len(reloaded["accounts"]) == 1
    assert vault.is_archived(reloaded["accounts"][0])
    assert vault.active_accounts(reloaded) == []


def test_auto_purge_only_takes_entries_older_than_the_cutoff():
    data = {"accounts": [
        {"id": "old", "site": "a", "username": "u", "password": "p",
         "archived_at": "2026-01-01T00:00:00Z"},
        {"id": "new", "site": "b", "username": "u", "password": "p",
         "archived_at": "2026-09-01T00:00:00Z"},
        {"id": "live", "site": "c", "username": "u", "password": "p"},
    ]}

    assert vault.purge_archived_before(data, "2026-06-01T00:00:00Z") == 1
    assert {a["id"] for a in data["accounts"]} == {"new", "live"}


# --- exports -------------------------------------------------------------
def test_csv_export_leaves_archived_entries_out(tmp_path):
    """A retired login must not come back to life in the user's browser."""
    data = {"accounts": []}
    vault.add_account(data, "live", "u", "p")
    gone = vault.add_account(data, "retired", "u", "p")
    vault.archive_account(data, gone["id"])

    dest = tmp_path / "out.csv"
    assert vault.export_csv(data, str(dest)) == 1
    rows = list(csv.DictReader(dest.open()))
    assert [r["name"] for r in rows] == ["live"]


def test_json_export_carries_the_archive(tmp_path):
    """The 'take everything with me' export must not be lossy."""
    data = {"accounts": []}
    vault.add_account(data, "live", "u", "p")
    gone = vault.add_account(data, "retired", "u", "p")
    vault.archive_account(data, gone["id"])

    dest = tmp_path / "out.json"
    assert vault.export_json(data, str(dest)) == 2
    written = json.loads(dest.read_text())
    archived = [a for a in written["accounts"] if a.get("archived_at")]
    assert [a["site"] for a in archived] == ["retired"]


# ==========================================================================
# Entry ids
# ==========================================================================
def test_a_pre_sync_vault_backfills_the_same_ids_on_both_pcs():
    """
    The same vault copied to two PCs before sync existed must backfill
    identically, or the very first sync sees two unrelated sets of entries and
    duplicates everything.
    """
    payload = {"accounts": [{"site": "github", "username": "u", "password": "p"},
                            {"site": "gmail", "username": "v", "password": "q"}]}

    one = vault.validate_vault(json.loads(json.dumps(payload)))
    two = vault.validate_vault(json.loads(json.dumps(payload)))

    assert [a["id"] for a in one["accounts"]] == [a["id"] for a in two["accounts"]]


def test_duplicate_entries_still_get_distinct_ids():
    """Same site+username twice would otherwise derive one id for both."""
    out = vault.validate_vault({"accounts": [
        {"site": "github", "username": "u", "password": "p"},
        {"site": "github", "username": "u", "password": "p"}]})

    assert len({a["id"] for a in out["accounts"]}) == 2


def test_an_existing_id_is_never_reassigned():
    out = vault.validate_vault({"accounts": [
        {"id": "keepme", "site": "a", "username": "b", "password": "c"}]})

    assert out["accounts"][0]["id"] == "keepme"


def test_ids_survive_a_save_and_load():
    vault.create_new_user("frank", "pw")
    data = vault.load_vault("pw", "frank")
    acc = vault.add_account(data, "github", "u", "p")
    vault.save_vault("pw", data, "frank")

    assert vault.load_vault("pw", "frank")["accounts"][0]["id"] == acc["id"]


def test_validate_vault_does_not_stamp_updated_at():
    """
    Stamping on load or save would mark every entry as freshly edited, and the
    next sync would see a vault full of conflicts.
    """
    out = vault.validate_vault({"accounts": [
        {"site": "a", "username": "b", "password": "c"}]})

    assert "updated_at" not in out["accounts"][0]


# ==========================================================================
# The sync base
# ==========================================================================
def test_the_base_round_trips():
    vault.create_new_user("gina", "pw")
    data = vault.load_vault("pw", "gina")
    vault.add_account(data, "github", "u", "p")
    vault.save_base("pw", data, "gina")

    base = vault.load_base("pw", "gina")
    assert [a["site"] for a in base["accounts"]] == ["github"]


def test_the_base_records_its_server_but_the_vault_does_not():
    vault.create_new_user("gwen", "pw")
    data = vault.load_vault("pw", "gwen")
    origin = {"url": "http://10.0.0.1:8787", "revision": 4}

    vault.save_base("pw", data, "gwen", origin=origin)

    assert vault.base_origin(vault.load_base("pw", "gwen")) == origin
    assert vault.BASE_ORIGIN_KEY not in data
    assert vault.BASE_ORIGIN_KEY not in vault.load_vault("pw", "gwen")


def test_a_base_from_before_origins_reports_none():
    vault.create_new_user("gail", "pw")
    vault.save_base("pw", vault.load_vault("pw", "gail"), "gail")

    assert vault.base_origin(vault.load_base("pw", "gail")) == {}


def test_a_password_change_keeps_the_bases_origin():
    vault.create_new_user("gemma", "old-pw")
    data = vault.load_vault("old-pw", "gemma")
    vault.save_base("old-pw", data, "gemma",
                    origin={"url": "http://s:1", "revision": 2})

    vault.change_master_password(data, "gemma", "old-pw", "new-pw")

    assert vault.base_origin(vault.load_base("new-pw", "gemma")) == {
        "url": "http://s:1", "revision": 2}


def test_a_missing_base_is_not_an_error():
    vault.create_new_user("hana", "pw")
    assert vault.load_base("pw", "hana") is None


def test_a_base_that_will_not_open_is_not_an_error():
    """A corrupt base must degrade to "never synced", never crash the app."""
    vault.create_new_user("iris", "pw")
    with open(vault.get_base_path("iris"), "wb") as f:
        f.write(b"not a vault at all")

    assert vault.load_base("pw", "iris") is None


def test_changing_the_master_password_drops_the_base():
    """
    The base is encrypted with the old password and cannot be re-encrypted
    without it. Leaving it behind would silently degrade every later merge.
    """
    vault.create_new_user("jade", "old-pw")
    data = vault.load_vault("old-pw", "jade")
    vault.save_base("old-pw", data, "jade")
    assert os.path.exists(vault.get_base_path("jade"))

    vault.save_vault("new-pw", data, "jade", rekey=True)

    assert not os.path.exists(vault.get_base_path("jade"))


def test_deleting_a_user_takes_the_base_with_it():
    vault.create_new_user("kim", "pw")
    data = vault.load_vault("pw", "kim")
    vault.save_base("pw", data, "kim")

    vault.delete_user("kim", "pw")

    assert not os.path.exists(vault.get_base_path("kim"))


def test_a_master_password_change_carries_the_base_across():
    """
    Unlike save_vault(rekey=True), which cannot read the old base and drops
    it, change_master_password knows both passwords and re-encrypts it. A
    dropped base would turn the next sync into a wall of needless conflicts.
    """
    vault.create_new_user("lena", "old-pw")
    data = vault.load_vault("old-pw", "lena")
    vault.add_account(data, "github", "u", "p")
    vault.save_vault("old-pw", data, "lena")
    vault.save_base("old-pw", data, "lena")

    vault.change_master_password(data, "lena", "old-pw", "new-pw")

    base = vault.load_base("new-pw", "lena")
    assert base is not None and base["accounts"][0]["site"] == "github"
    assert vault.load_base("old-pw", "lena") is None
    with pytest.raises(ValueError):
        vault.load_vault("old-pw", "lena")        # main file and .bak both


def test_a_master_password_change_without_a_base_creates_none():
    vault.create_new_user("mona", "old-pw")
    data = vault.load_vault("old-pw", "mona")

    vault.change_master_password(data, "mona", "old-pw", "new-pw")

    assert not os.path.exists(vault.get_base_path("mona"))
    assert vault.load_vault("new-pw", "mona") is not None


# ==========================================================================
# Revision history
# ==========================================================================
def _entry(**fields):
    data = {"accounts": []}
    acc = vault.add_account(data, fields.pop("site", "github"),
                            fields.pop("username", "me"),
                            fields.pop("password", "v1"), **fields)
    return data, acc


def test_an_edit_keeps_the_previous_version():
    _, acc = _entry()
    assert vault.update_entry(acc, password="v2")

    [rev] = acc["history"]
    assert rev["password"] == "v1"
    assert rev["changed"] == ["password"]
    assert acc["password"] == "v2"


def test_every_field_is_tracked_not_just_the_password():
    _, acc = _entry(notes="old note")
    vault.update_entry(acc, site="gitlab", username="you", notes="new note")

    [rev] = acc["history"]
    assert rev["changed"] == ["site", "username", "notes"]
    assert (rev["site"], rev["username"], rev["notes"]) == ("github", "me",
                                                            "old note")


def test_saving_without_changes_records_nothing():
    _, acc = _entry()
    assert not vault.update_entry(acc, password="v1", site="github")
    assert "history" not in acc


def test_only_the_newest_ten_versions_are_kept():
    _, acc = _entry(password="p0")
    for i in range(1, 13):
        vault.update_entry(acc, password=f"p{i}")

    passwords = [r["password"] for r in acc["history"]]
    assert len(passwords) == vault.HISTORY_LIMIT == 10
    assert passwords == [f"p{i}" for i in range(11, 1, -1)], "newest first"


def test_revert_brings_a_version_back_and_keeps_the_one_left():
    _, acc = _entry(password="v1")
    vault.update_entry(acc, password="v2")
    vault.update_entry(acc, password="v3")
    v1 = next(r for r in acc["history"] if r["password"] == "v1")

    assert vault.revert_entry(acc, v1["rid"])

    assert acc["password"] == "v1"
    in_history = [r["password"] for r in acc["history"]]
    assert "v3" in in_history, "the version left must be recoverable"
    assert "v1" not in in_history, "the current version is not history"


def test_a_revert_can_itself_be_undone():
    _, acc = _entry(password="v1")
    vault.update_entry(acc, password="v2")
    vault.revert_entry(acc, acc["history"][0]["rid"])        # back to v1
    v2 = next(r for r in acc["history"] if r["password"] == "v2")

    vault.revert_entry(acc, v2["rid"])

    assert acc["password"] == "v2"


def test_clear_history_empties_it():
    _, acc = _entry()
    vault.update_entry(acc, password="v2")
    vault.clear_history(acc)

    assert "history" not in acc
    assert acc["history_cleared_at"]


def test_a_cleared_history_is_not_refilled_by_an_older_copy():
    """The merge unions histories; the clear must survive that."""
    _, acc = _entry()
    vault.update_entry(acc, password="v2")
    stale_copy = json.loads(json.dumps(acc))        # the other PC, before
    vault.clear_history(acc)

    vault.merge_history(acc, stale_copy)

    assert "history" not in acc


def test_an_edit_straight_after_a_clear_is_kept():
    """Regression guard: second-resolution timestamps dropped this one."""
    _, acc = _entry()
    vault.update_entry(acc, password="v2")
    vault.clear_history(acc)
    vault.update_entry(acc, password="v3")

    assert [r["password"] for r in acc["history"]] == ["v2"]


def test_history_normalises_the_same_on_every_pc():
    """Order and duplicates must not matter, or two PCs never converge."""
    _, acc = _entry()
    for p in ("v2", "v3", "v4"):
        vault.update_entry(acc, password=p)
    shuffled = json.loads(json.dumps(acc))
    shuffled["history"] = list(reversed(shuffled["history"])) * 2

    vault.normalize_history(shuffled)

    assert shuffled["history"] == acc["history"]


def test_history_survives_a_save_and_load():
    vault.create_new_user("nina", "pw")
    data = vault.load_vault("pw", "nina")
    acc = vault.add_account(data, "github", "u", "v1")
    vault.update_entry(acc, password="v2")
    vault.save_vault("pw", data, "nina")

    [rev] = vault.load_vault("pw", "nina")["accounts"][0]["history"]
    assert rev["password"] == "v1"


def test_junk_in_a_history_is_dropped_not_fatal():
    out = vault.validate_vault({"accounts": [
        {"site": "a", "username": "b", "password": "now",
         "history": ["junk", 5, None,
                     {"password": "then", "replaced_at": "2026-01-01T00:00:00.000000Z"}]}]})

    [rev] = out["accounts"][0]["history"]
    assert rev["password"] == "then"


def test_csv_export_leaves_history_out_json_keeps_it(tmp_path):
    data, acc = _entry(password="v1")
    vault.update_entry(acc, password="v2")

    vault.export_csv(data, str(tmp_path / "out.csv"))
    vault.export_json(data, str(tmp_path / "out.json"))

    assert "v1" not in (tmp_path / "out.csv").read_text()
    exported = json.loads((tmp_path / "out.json").read_text())
    assert exported["accounts"][0]["history"][0]["password"] == "v1"


# --- installed copy: data in %APPDATA%\SecretSpace, not the program folder -----
def test_portable_copy_keeps_data_next_to_the_app(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRETSPACE_DATA_DIR", raising=False)
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(tmp_path / "app"))
    assert not vault.is_installed()
    assert vault.get_home_dir() == str(tmp_path / "app")
    assert vault.get_data_dir() == str(tmp_path / "app" / "vault")


def test_installed_copy_keeps_data_in_appdata(tmp_path, monkeypatch):
    import appconfig
    monkeypatch.delenv("SECRETSPACE_DATA_DIR", raising=False)
    app = tmp_path / "Programs" / "SecretSpace"
    app.mkdir(parents=True)
    (app / vault.INSTALLED_MARKER).write_text("installed by setup")
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(app))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    home = tmp_path / "Roaming" / "SecretSpace"
    assert vault.is_installed()
    assert vault.get_data_dir() == str(home / "vault")
    assert appconfig.config_file() == str(home / "config.json")

    vault.create_new_user("alice", "pw")
    assert (home / "vault" / "alice.vault.enc").exists()
    assert sorted(p.name for p in app.iterdir()) == [vault.INSTALLED_MARKER]


def _installed(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRETSPACE_DATA_DIR", raising=False)
    app = tmp_path / "Programs" / "SecretSpace"
    app.mkdir(parents=True)
    (app / vault.INSTALLED_MARKER).write_text("installed by setup")
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(app))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    return tmp_path / "Roaming"


def _old_home(roaming):
    """A data folder as an install from before the rename left it."""
    old = roaming / "PassMan"
    (old / "vault").mkdir(parents=True)
    (old / "accounts" / "bob").mkdir(parents=True)
    (old / "vault" / "bob.vault.enc").write_bytes(b"x")
    (old / "accounts" / "bob" / "account.json").write_bytes(b"{}")
    (old / "config.json").write_bytes(b"{}")
    return old


def _files(folder):
    return sorted(str(p.relative_to(folder)).replace("\\", "/")
                  for p in folder.rglob("*") if p.is_file())


def test_the_data_folder_of_the_old_name_is_renamed_at_start(tmp_path, monkeypatch):
    """Installed before the rename: at the next start the folder gets its
    current name -- renamed, not copied, with everything in it."""
    roaming = _installed(tmp_path, monkeypatch)
    old = _old_home(roaming)
    before = _files(old)
    status, was, now = vault.settle_home()
    assert status == vault.HOME_MOVED
    assert (was, now) == (str(old), str(roaming / "SecretSpace"))
    assert not old.exists()
    assert _files(roaming / "SecretSpace") == before
    assert vault.get_data_dir() == str(roaming / "SecretSpace" / "vault")
    assert "bob" in vault.list_users()


def test_a_second_start_has_nothing_left_to_move(tmp_path, monkeypatch):
    roaming = _installed(tmp_path, monkeypatch)
    _old_home(roaming)
    vault.settle_home()
    assert vault.settle_home()[0] is None


def test_a_folder_that_cannot_be_renamed_is_used_where_it_is(tmp_path, monkeypatch):
    """Something has it open: the vaults must still be reachable, and the
    next start tries again."""
    roaming = _installed(tmp_path, monkeypatch)
    old = _old_home(roaming)
    real = os.rename

    def busy(source, target):
        raise PermissionError("in use")

    monkeypatch.setattr(vault.os, "rename", busy)
    assert vault.settle_home()[0] == vault.HOME_BUSY
    assert vault.get_data_dir() == str(old / "vault")
    assert "bob" in vault.list_users()
    assert not (roaming / "SecretSpace").exists()
    monkeypatch.setattr(vault.os, "rename", real)
    assert vault.settle_home()[0] == vault.HOME_MOVED
    assert vault.get_data_dir() == str(roaming / "SecretSpace" / "vault")


def test_with_both_folders_the_current_one_is_used_and_the_old_left_alone(
        tmp_path, monkeypatch):
    roaming = _installed(tmp_path, monkeypatch)
    old = _old_home(roaming)
    before = _files(old)
    (roaming / "SecretSpace" / "vault").mkdir(parents=True)
    assert vault.settle_home()[0] == vault.HOME_BOTH
    assert _files(old) == before
    assert vault.get_data_dir() == str(roaming / "SecretSpace" / "vault")


def test_a_lab_copy_has_no_folder_to_rename(tmp_path, monkeypatch):
    """Not installed: the data is beside the program, under no name."""
    app = tmp_path / "lab"
    app.mkdir()
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(app))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    monkeypatch.delenv("SECRETSPACE_DATA_DIR", raising=False)
    _old_home(tmp_path / "Roaming")
    assert vault.settle_home() == (None, None, None)
    assert (tmp_path / "Roaming" / "PassMan").is_dir()


def test_a_test_run_never_moves_the_real_folder(tmp_path, monkeypatch):
    """With the data folder overridden (tests, tools) nothing is renamed."""
    roaming = _installed(tmp_path, monkeypatch)
    _old_home(roaming)
    monkeypatch.setenv("SECRETSPACE_DATA_DIR", str(tmp_path / "elsewhere"))
    assert vault.settle_home() == (None, None, None)
    assert (roaming / "PassMan").is_dir()


def test_the_new_folder_wins_once_it_exists(tmp_path, monkeypatch):
    roaming = _installed(tmp_path, monkeypatch)
    (roaming / "PassMan").mkdir(parents=True)
    (roaming / "SecretSpace").mkdir(parents=True)
    assert vault.get_data_dir() == str(roaming / "SecretSpace" / "vault")


def test_a_new_install_uses_the_new_name(tmp_path, monkeypatch):
    roaming = _installed(tmp_path, monkeypatch)
    assert vault.get_data_dir() == str(roaming / "SecretSpace" / "vault")


def test_env_override_beats_an_installed_copy(tmp_path, monkeypatch):
    (tmp_path / vault.INSTALLED_MARKER).write_text("")
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(tmp_path))
    monkeypatch.setenv("SECRETSPACE_DATA_DIR", str(tmp_path / "elsewhere"))
    assert vault.get_data_dir() == str(tmp_path / "elsewhere")


# --- duplicate warning ------------------------------------------------------
def _dup_vault():
    data = {"accounts": []}
    vault.add_account(data, "GitHub.com", "Alice", "pw")
    return data


def test_duplicate_found_ignoring_case_and_spaces():
    data = _dup_vault()
    assert vault.find_duplicate(data, " github.com ", "alice") is data["accounts"][0]


def test_different_username_is_not_a_duplicate():
    assert vault.find_duplicate(_dup_vault(), "github.com", "bob") is None


def test_entry_is_not_its_own_duplicate():
    data = _dup_vault()
    own = data["accounts"][0]["id"]
    assert vault.find_duplicate(data, "github.com", "alice", exclude_id=own) is None


def test_archived_entry_is_not_a_duplicate():
    data = _dup_vault()
    vault.archive_account(data, data["accounts"][0]["id"])
    assert vault.find_duplicate(data, "github.com", "alice") is None


# --- coarse clocks (Python 3.12 on Windows ticks every ~15 ms) ---------------
class _FrozenClock:
    """A datetime whose now() never moves: the worst case of a coarse clock."""
    from datetime import datetime as _real

    @classmethod
    def now(cls, tz=None):
        return cls._real(2026, 10, 5, 12, 0, 0, tzinfo=tz)


def test_history_stamps_increase_even_when_the_clock_does_not(monkeypatch):
    monkeypatch.setattr(vault, "datetime", _FrozenClock)
    stamps = [vault.history_now() for _ in range(5)]
    assert stamps == sorted(stamps) and len(set(stamps)) == 5


def test_history_order_survives_a_coarse_clock(monkeypatch):
    monkeypatch.setattr(vault, "datetime", _FrozenClock)
    _, acc = _entry(password="p0")
    for i in range(1, 13):
        vault.update_entry(acc, password=f"p{i}")
    assert [r["password"] for r in acc["history"]] == \
        [f"p{i}" for i in range(11, 1, -1)]


def test_edit_after_clear_survives_a_coarse_clock(monkeypatch):
    monkeypatch.setattr(vault, "datetime", _FrozenClock)
    _, acc = _entry()
    vault.update_entry(acc, password="v2")
    vault.clear_history(acc)
    vault.update_entry(acc, password="v3")
    assert [r["password"] for r in acc["history"]] == ["v2"]


def test_installed_copy_has_the_plain_title(tmp_path, monkeypatch):
    """The installed copy is production: no LAB in its title."""
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(tmp_path))
    (tmp_path / vault.INSTALLED_MARKER).write_text("")
    assert vault.window_title() == vault.APP_TITLE


def test_copy_without_the_marker_says_lab_and_where(tmp_path, monkeypatch):
    """A lab copy or a source run names itself LAB, with its vault folder."""
    monkeypatch.delenv("SECRETSPACE_DATA_DIR", raising=False)
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(tmp_path))
    title = vault.window_title()
    assert title.startswith(vault.APP_TITLE)
    assert "LAB" in title
    assert str(tmp_path / "vault") in title


def test_lab_title_follows_the_data_dir_override(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "get_app_dir", lambda: str(tmp_path))
    monkeypatch.setenv("SECRETSPACE_DATA_DIR", str(tmp_path / "elsewhere"))
    assert str(tmp_path / "elsewhere") in vault.window_title()
