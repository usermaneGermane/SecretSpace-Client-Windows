"""What a newer SecretSpace wrote survives this one: load, save, edit, merge,
history and the signed change log keep fields they do not know."""

import copy
import json

import pytest

import changelog
import sync
import vault

PASSKEY = {"rp": "example.com", "ids": [1, 2, {"deep": None}], "on": False}


def entry(i="a", **more):
    return dict({"id": i, "site": "Site", "username": "u", "password": "p"},
                **more)


def data(*entries, **top):
    return dict({"accounts": list(entries)}, **top)


def merge(base, local, remote, choices=None):
    """What a device does: validate all three, merge, rebuild."""
    b, l, r = (vault.validate_vault(copy.deepcopy(x)) if x is not None else None
               for x in (base, local, remote))
    result = sync.merge_vaults(b, l, r)
    return result, vault.validate_vault(sync.merged_vault(
        l, sync.resolve(result, choices), result.extra))


# --- load and save -----------------------------------------------------------
def test_unknown_entry_fields_keep_their_value_and_type():
    out = vault.validate_vault(data(entry(passkey=PASSKEY, zero=0, empty="")))
    row = out["accounts"][0]
    assert row["passkey"] == PASSKEY and row["zero"] == 0 and row["empty"] == ""


def test_unknown_top_level_keys_are_kept():
    assert vault.validate_vault(data(tags={"x": 1}))["tags"] == {"x": 1}


def test_a_saved_vault_file_still_has_them(tmp_path, monkeypatch):
    monkeypatch.setenv(vault.DATA_DIR_VARIABLE, str(tmp_path))
    vault.create_new_user("me", "Correct-horse-1")
    vault.save_vault("Correct-horse-1", data(entry(passkey=PASSKEY), tags=[1]),
                     "me")
    back = vault.load_vault("Correct-horse-1", "me")
    assert back["accounts"][0]["passkey"] == PASSKEY and back["tags"] == [1]


def test_a_vault_without_them_keeps_its_shape():
    assert vault.validate_vault(data(entry()))["accounts"] == [entry()]


# --- editing here ------------------------------------------------------------
def test_editing_an_entry_leaves_them_alone_and_remembers_them():
    e = entry(passkey=PASSKEY)
    assert vault.update_entry(e, password="new")
    assert e["passkey"] == PASSKEY
    assert e["history"][0]["passkey"] == PASSKEY
    assert e["history"][0]["changed"] == ["password"]


def test_a_revert_brings_them_back_and_can_be_undone():
    e = entry(passkey="one")
    vault.update_entry(e, password="p2")
    e["passkey"] = "two"                    # a newer version changed it
    old = next(r for r in e["history"] if r["password"] == "p")
    assert vault.revert_entry(e, old["rid"])
    assert (e["password"], e["passkey"]) == ("p", "one")
    left = e["history"][0]
    assert (left["password"], left["passkey"]) == ("p2", "two")
    assert vault.revert_entry(e, left["rid"])
    assert (e["password"], e["passkey"]) == ("p2", "two")


def test_a_revert_never_removes_one_the_old_version_did_not_have():
    e = entry()
    vault.update_entry(e, password="p2")
    e["passkey"] = PASSKEY
    vault.revert_entry(e, e["history"][0]["rid"])
    assert e["password"] == "p" and e["passkey"] == PASSKEY


def test_a_revert_that_changes_only_an_unknown_field_is_recorded():
    e = entry(passkey="now")
    vault.add_revision(e, entry(passkey="before"), [])
    assert vault.revert_entry(e, e["history"][0]["rid"])
    assert e["passkey"] == "before" and e["history"][0]["passkey"] == "now"


def test_versions_that_differ_only_there_are_two_versions():
    e = entry(passkey="now")
    vault.add_revision(e, entry(passkey="one"), [])
    vault.add_revision(e, entry(passkey="two"), [])
    assert [r["passkey"] for r in e["history"]] == ["two", "one"]


def test_revisions_without_them_keep_the_id_they_had():
    """Ids of every revision written so far must not change."""
    for fields, key in (({}, ("Site", "u", "p", "", "")),
                        ({"url": "https://x"}, ("Site", "u", "p", "", "",
                                                "https://x"))):
        assert vault._content_key(entry(**fields)) == key


def test_an_unknown_field_is_not_mistaken_for_a_web_address():
    text = vault.extra_key(entry(f="x"))
    assert vault._content_key(entry(f="x")) != vault._content_key(entry(url=text))


def test_a_newer_field_name_in_a_revisions_changed_list_is_kept():
    e = entry(history=[dict(entry(password="o"), replaced_at="2026-01-01",
                            changed=["passkey", "url", "site", 5, ""])])
    vault.normalize_history(e)
    assert e["history"][0]["changed"] == ["site", "url", "passkey"]


def test_a_snapshot_is_a_copy():
    e = entry(passkey={"n": 1})
    snap = vault.snapshot(e)
    e["passkey"]["n"] = 2
    assert snap["passkey"] == {"n": 1}


# --- merging -----------------------------------------------------------------
def test_one_changed_elsewhere_is_taken():
    was, now = data(entry(passkey=1)), data(entry(passkey=2))
    result, out = merge(was, was, now)
    assert result.clean and out["accounts"][0]["passkey"] == 2


def test_one_changed_here_is_uploaded():
    was, now = data(entry(passkey=1)), data(entry(passkey=2))
    result, out = merge(was, now, was)
    assert result.needs_push and out["accounts"][0]["passkey"] == 2


def test_changed_on_both_sides_asks_and_the_lost_one_is_in_the_history():
    result, out = merge(data(entry(passkey=1)), data(entry(passkey=2)),
                        data(entry(passkey=3)), {"a": sync.KEEP_LOCAL})
    assert [c.id for c in result.conflicts] == ["a"]
    e = out["accounts"][0]
    assert e["passkey"] == 2 and e["history"][0]["passkey"] == 3


def test_the_same_value_written_in_another_key_order_is_no_change():
    result, _ = merge(None, data(entry(k={"a": 1, "b": 2})),
                      data(entry(k={"b": 2, "a": 1})))
    assert not result.changed


def test_merging_is_stable_afterwards():
    """Both devices end with the same vault, and the next sync does nothing."""
    base = data(entry(passkey=1), tags="t1")
    _, here = merge(base, data(entry(passkey=2), tags="t1"),
                    data(entry(passkey=1), tags="t2"))
    again, there = merge(base, data(entry(passkey=1), tags="t2"), here)
    assert there["accounts"][0]["passkey"] == 2 and there["tags"] == "t2"
    assert json.dumps(here, sort_keys=True) == json.dumps(there, sort_keys=True)
    done, _ = merge(here, here, there)
    assert not done.changed


# --- top-level keys in a merge -----------------------------------------------
@pytest.mark.parametrize("base, local, remote, want, pull, push", [
    ({}, {}, {"t": 1}, {"t": 1}, True, False),             # new elsewhere
    ({}, {"t": 1}, {}, {"t": 1}, False, True),             # new here
    ({"t": 1}, {"t": 1}, {"t": 2}, {"t": 2}, True, False),  # changed there
    ({"t": 1}, {"t": 2}, {"t": 1}, {"t": 2}, False, True),  # changed here
    ({"t": 1}, {"t": 2}, {"t": 3}, {"t": 2}, False, True),  # both: ours
    ({"t": 1}, {"t": 1}, {}, {"t": 1}, False, True),       # dropped by an old app
    ({"t": 1}, {}, {"t": 1}, {"t": 1}, True, False),
    (None, {"t": 1}, {"t": 2}, {"t": 1}, False, True),     # never synced
])
def test_top_level_keys(base, local, remote, want, pull, push):
    result, out = merge(None if base is None else data(**base),
                        data(**local), data(**remote))
    assert {k: v for k, v in out.items() if k != "accounts"} == want
    assert bool(result.stats["extra_in"]) is pull
    assert result.needs_push is push and result.changed


@pytest.mark.parametrize("key", sorted(sync.KNOWN_VAULT_KEYS
                                        - {"accounts", vault.NEEDS_KEY}))
def test_this_devices_own_settings_are_never_taken_from_the_server(key):
    result, out = merge(None, data(**{key: "mine"}), data(**{key: "theirs"}))
    assert out[key] == "mine" and not result.changed
    result, out = merge(None, data(), data(**{key: "theirs"}))
    assert key not in out and not result.changed


def test_the_known_keys_are_the_ones_the_code_uses():
    import sync_client
    assert sync.KNOWN_VAULT_KEYS == {
        "accounts", sync_client.SETTINGS_KEY, changelog.CHANGES_KEY,
        vault.BASE_ORIGIN_KEY, vault.ARCHIVE_PURGE_KEY, vault.NEEDS_KEY}


# --- the signed change log ---------------------------------------------------
def line(**more):
    return dict({"id": "1", "at": "2026-01-01", "by": "me", "action": "edited",
                 "entry": "a", "title": "Site", "fields": ["password"],
                 "count": 0, "sig": "s", "v": 2}, **more)


def test_a_newer_field_or_action_in_the_log_is_kept_as_signed():
    newer = line(action="moved", fields=["passkey", "url"])
    assert changelog.lines_of({"changes": [newer]}) == [newer]
    assert changelog.describe(newer) == "changed something"
    assert changelog.message("ab", changelog.lines_of(
        {"changes": [newer]})[0]) == changelog.message("ab", newer)


@pytest.mark.parametrize("action", [None, 5, "", "Two words", "x" * 33])
def test_junk_actions_are_still_dropped(action):
    assert changelog.lines_of({"changes": [line(action=action)]}) == []


def test_junk_field_names_are_still_dropped():
    got = changelog.lines_of({"changes": [line(
        fields=["url", 5, None, "<b>", "x" * 33])]})
    assert got[0]["fields"] == ["url"]


def test_a_change_to_an_unknown_field_alone_is_logged():
    found = changelog.diff(data(entry(passkey=1)), data(entry(passkey=2)))
    assert [(f["action"], f["fields"]) for f in found] == [("edited", [])]
    assert changelog.describe(found[0]) == "changed the details of “Site”"
