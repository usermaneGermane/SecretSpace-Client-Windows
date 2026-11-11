"""
Phase 4: a vault shared between accounts, and the record of who changed
what -- end to end through the real (test copy of the) sync server.

alice and bob are two accounts on two "devices" (two data folders). alice
owns a vault called Team and shares it with bob.
"""

import base64
import copy
import json
import os

import pytest

import account_crypto
import account_sync
import accounts
import changelog
import vault
from account_crypto import CryptoError
from sync_client import SyncError

from test_account_sync import (PW, TOKEN, alice, cheap_argon2, device,  # noqa: F401
                               new_account, passman_server, server)
from test_account_vaults import reconcile, sync_all, sync_vault, sites


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def logged_in(account):
    return account_sync.logged_in(account)


def with_server(account, work):
    session = logged_in(account)
    try:
        return work(session)
    finally:
        session.logout()


def add_entry(account, vault_id, site, password="pw"):
    """What the app does on Save: change the data, note who did, write."""
    file = account.vault_file(vault_id)
    before = file.load()
    data = copy.deepcopy(before)
    made = vault.add_account(data, site, "me", password)
    changelog.record(data, before, account.username, account.keyset, file.hex)
    file.save(data)
    return made["id"]


def edit_entry(account, vault_id, site, **fields):
    file = account.vault_file(vault_id)
    before = file.load()
    data = copy.deepcopy(before)
    target = next(e for e in data["accounts"] if e["site"] == site)
    vault.update_entry(target, **{**vault.snapshot(target), **fields})
    changelog.record(data, before, account.username, account.keyset, file.hex)
    file.save(data)


def share(owner, vault_id, name, role=accounts.ROLE_EDITOR):
    def work(session):
        keys = account_sync.lookup_contact(owner, session, name)
        return account_sync.share_vault(owner, session, vault_id, keys, role)
    return with_server(owner, work)


def rotate(owner, vault_id, remove=()):
    data = owner.vault_file(vault_id).load()
    return with_server(owner, lambda session: account_sync.change_key(
        owner, session, vault_id, data, remove=list(remove)))


def log_of(account, vault_id):
    return changelog.lines_of(account.vault_file(vault_id).load())


def server_blob(server, vault_id):
    path = os.path.join(server.store.root, "_v2", "vaults", vault_id, "vault.enc")
    with open(path, "rb") as f:
        return f.read().decode("ascii")


@pytest.fixture
def bob(server, device, alice):                      # noqa: F811
    """Device b: bob, his own account on the same server."""
    device("b")
    new = new_account("bob")
    account = new.save()
    assert account_sync.connect(account, server.url, "", TOKEN) == "created"
    sync_all(account)                    # the server learns his signing key
    device("a")
    return account


@pytest.fixture
def team(server, device, alice, bob):                # noqa: F811
    """alice's vault Team with one entry, on the server, shared with bob as
    an editor and fetched by him. Returns (alice, bob, vault id)."""
    device("a")
    vault_id = alice.create_vault("Team").hex
    add_entry(alice, vault_id, "Router")
    sync_all(alice)
    share(alice, vault_id, "bob")
    device("b")
    sync_all(bob)
    device("a")
    return alice, bob, vault_id


# ---------------------------------------------------------------------------
# A. The signing key
# ---------------------------------------------------------------------------
def test_a_signature_checks_out_only_for_its_message_and_its_signer():
    one, two = account_crypto.new_keyset(), account_crypto.new_keyset()
    signature = account_crypto.sign(one, b"hello")
    assert account_crypto.verify(account_crypto.signing_key_of(one), b"hello",
                                 signature)
    assert not account_crypto.verify(account_crypto.signing_key_of(one),
                                     b"hellp", signature)
    assert not account_crypto.verify(account_crypto.signing_key_of(two),
                                     b"hello", signature)


@pytest.mark.parametrize("junk", ["", "not base64 !!", "AAAA", None])
def test_verify_says_no_to_junk_instead_of_raising(junk):
    key = account_crypto.signing_key_of(account_crypto.new_keyset())
    assert account_crypto.verify(key, b"m", junk) is False
    assert account_crypto.verify(b"short", b"m", "AAAA") is False


def test_the_signing_key_comes_from_the_keyset_and_is_not_the_wrapping_key():
    keyset = account_crypto.new_keyset()
    again = json.loads(json.dumps(keyset))
    assert account_crypto.signing_key_of(keyset) == \
        account_crypto.signing_key_of(again)
    assert account_crypto.signing_key_of(keyset) != \
        account_crypto.public_key_of(keyset)
    assert len(account_crypto.signing_key_of(keyset)) == 32


def test_the_account_fingerprint_covers_both_keys():
    a, b = os.urandom(32), os.urandom(32)
    base = account_crypto.account_fingerprint(a, b)
    assert base != account_crypto.account_fingerprint(a, os.urandom(32))
    assert base != account_crypto.account_fingerprint(os.urandom(32), b)
    assert len(base.split()) == 6 and all(len(g) == 4 and g.isdigit()
                                          for g in base.split())


# ---------------------------------------------------------------------------
# B. The change log on its own
# ---------------------------------------------------------------------------
def entry(site, entry_id=None, **more):
    made = {"id": entry_id or vault.new_id(), "site": site, "username": "u",
            "password": "p"}
    made.update(more)
    return made


def test_diff_names_what_happened_to_each_entry():
    kept, edited, gone, back, filed = (entry(s) for s in
                                       ("Kept", "Edited", "Gone", "Back", "Filed"))
    back["archived_at"] = "2026-01-01T00:00:00Z"
    before = {"accounts": [kept, edited, gone, back, filed]}
    after = copy.deepcopy({"accounts": [kept, edited, back, filed]})
    after["accounts"][1]["password"] = "new"
    after["accounts"][1]["notes"] = "n"
    del after["accounts"][2]["archived_at"]
    after["accounts"][3]["archived_at"] = "2026-02-02T00:00:00Z"
    after["accounts"].append(entry("New"))
    found = {(d["action"], d["title"]): d for d in changelog.diff(before, after)}
    assert set(found) == {("added", "New"), ("edited", "Edited"),
                          ("restored", "Back"), ("archived", "Filed"),
                          ("deleted", "Gone")}
    assert found[("edited", "Edited")]["fields"] == ["password", "notes"]


def test_diff_of_an_unchanged_vault_is_empty():
    data = {"accounts": [entry("A"), entry("B")]}
    assert changelog.diff(data, copy.deepcopy(data)) == []


def test_going_back_to_an_earlier_version_is_called_a_revert():
    before = {"accounts": [entry("A")]}
    vault.update_entry(before["accounts"][0], site="A", username="u",
                       password="second")
    after = copy.deepcopy(before)
    rid = after["accounts"][0]["history"][0]["rid"]
    vault.revert_entry(after["accounts"][0], rid)
    assert [d["action"] for d in changelog.diff(before, after)] == ["reverted"]


def test_many_entries_added_at_once_are_one_line():
    after = {"accounts": [entry(f"S{i}") for i in range(changelog.BULK + 1)]}
    found = changelog.diff({"accounts": []}, after)
    assert [(d["action"], d["count"]) for d in found] == \
        [("imported", changelog.BULK + 1)]
    exactly = {"accounts": after["accounts"][:changelog.BULK]}
    assert len(changelog.diff({"accounts": []}, exactly)) == changelog.BULK


def test_a_line_never_holds_a_value():
    keyset = account_crypto.new_keyset()
    before = {"accounts": [entry("Mail", username="who@x", password="old-secret")]}
    after = copy.deepcopy(before)
    vault.update_entry(after["accounts"][0], site="Mail", username="new@x",
                       password="new-secret", notes="a private note")
    changelog.record(after, before, "alice", keyset, "ab" * 16)
    text = json.dumps(after[changelog.CHANGES_KEY])
    for value in ("old-secret", "new-secret", "who@x", "new@x", "a private note"):
        assert value not in text


def test_record_signs_its_lines_and_names_the_author_on_the_entry():
    keyset = account_crypto.new_keyset()
    before = {"accounts": [entry("Mail")]}
    after = copy.deepcopy(before)
    vault.update_entry(after["accounts"][0], site="Mail", username="u",
                       password="changed")
    assert changelog.record(after, before, "alice", keyset, "ab" * 16) == 1
    line = changelog.lines_of(after)[0]
    assert (line["by"], line["action"], line["fields"]) == \
        ("alice", "edited", ["password"])
    key = account_crypto.signing_key_of(keyset)
    assert changelog.check(line, "ab" * 16, key) == changelog.OK
    assert after["accounts"][0]["updated_by"] == "alice"
    assert after["accounts"][0]["history"][0]["by"] == "alice"
    # ... and it survives the vault's own validation
    clean = vault.validate_vault(copy.deepcopy(after))
    assert clean["accounts"][0]["updated_by"] == "alice"
    assert clean["accounts"][0]["history"][0]["by"] == "alice"


@pytest.mark.parametrize("field,value", [
    ("by", "bob"), ("at", "2020-01-01T00:00:00.000000Z"), ("action", "deleted"),
    ("entry", "another-entry"), ("title", "Other"), ("fields", ["notes"]),
    ("count", 7)])
def test_a_line_changed_after_signing_is_flagged(field, value):
    keyset = account_crypto.new_keyset()
    before = {"accounts": [entry("Mail")]}
    after = copy.deepcopy(before)
    vault.update_entry(after["accounts"][0], site="Mail", username="u",
                       password="changed")
    changelog.record(after, before, "alice", keyset, "ab" * 16)
    line = dict(changelog.lines_of(after)[0])
    line[field] = value
    assert changelog.check(line, "ab" * 16,
                           account_crypto.signing_key_of(keyset)) == changelog.BAD


def test_a_line_is_bound_to_its_vault_and_to_its_signer():
    keyset, other = account_crypto.new_keyset(), account_crypto.new_keyset()
    after = {"accounts": [entry("Mail")]}
    changelog.record(after, {"accounts": []}, "alice", keyset, "ab" * 16)
    line = changelog.lines_of(after)[0]
    key = account_crypto.signing_key_of(keyset)
    assert changelog.check(line, "cd" * 16, key) == changelog.BAD
    assert changelog.check(line, "ab" * 16,
                           account_crypto.signing_key_of(other)) == changelog.BAD
    assert changelog.check(line, "ab" * 16, None) == changelog.UNKNOWN
    unsigned = dict(line, sig="")
    assert changelog.check(unsigned, "ab" * 16, key) == changelog.BAD


def test_merge_keeps_each_line_once_oldest_first_and_caps_the_log(monkeypatch):
    def line(n):
        return {"id": f"{n:016x}", "at": f"2026-01-01T00:00:{n:02d}.000000Z",
                "by": "a", "action": "added", "entry": "e", "title": "t",
                "fields": [], "count": 0, "sig": "x"}
    one, two = [line(3), line(1)], [line(2), line(1), "junk", {"id": "x"}]
    merged = changelog.merge(one, two)
    assert [l["id"] for l in merged] == [f"{n:016x}" for n in (1, 2, 3)]
    assert changelog.merge(two, one) == merged
    monkeypatch.setattr(changelog, "CHANGES_LIMIT", 2)
    assert [l["id"] for l in changelog.merge(one, two)] == \
        [f"{n:016x}" for n in (2, 3)]


def test_describe_reads_as_a_sentence():
    assert changelog.describe({"action": "edited", "title": "Mail",
                               "fields": ["username", "password"]}) == \
        "changed the username and password of “Mail”"
    assert changelog.describe({"action": "added", "title": "Mail"}) == \
        "added “Mail”"
    assert "12 entries" in changelog.describe({"action": "imported", "count": 12})


# ---------------------------------------------------------------------------
# C. Sharing through the server
# ---------------------------------------------------------------------------
def test_a_shared_vault_arrives_at_the_other_account_with_its_entries(team, device):
    alice, bob, vault_id = team
    device("b")
    assert vault_id in bob.vault_ids()
    assert bob.vault_file(vault_id).name == "Team"
    assert bob.vault_role(vault_id) == accounts.ROLE_EDITOR
    assert bob.is_shared(vault_id)
    assert sites(bob, vault_id) == ["Router"]


def test_the_server_never_holds_the_shared_vaults_key(team, server, device):
    alice, bob, vault_id = team
    key = alice.vault_file(vault_id)._key
    found = b""
    for folder, _, files in os.walk(server.store.root):
        for name in files:
            with open(os.path.join(folder, name), "rb") as f:
                found += f.read()
    assert key not in found and base64.b64encode(key) not in found
    assert b"Router" not in found and b"Team" not in found


def test_each_members_wrapped_key_opens_only_for_them(team, device):
    alice, bob, vault_id = team
    device("b")
    wrapped = bob.vault_record(vault_id)["wrapped_key"]
    assert wrapped != alice.vault_record(vault_id)["wrapped_key"]
    with pytest.raises(CryptoError):
        account_crypto.unwrap_key(alice.keyset, wrapped, bytes.fromhex(vault_id),
                                  "alice")
    with pytest.raises(CryptoError):
        account_crypto.unwrap_key(alice.keyset, wrapped, bytes.fromhex(vault_id),
                                  "bob")


def test_a_change_by_one_member_reaches_the_other_with_their_name(team, device):
    alice, bob, vault_id = team
    device("b")
    add_entry(bob, vault_id, "Printer")
    edit_entry(bob, vault_id, "Router", password="changed-by-bob")
    sync_all(bob)
    device("a")
    sync_all(alice)
    data = alice.vault_file(vault_id).load()
    router = next(e for e in data["accounts"] if e["site"] == "Router")
    assert router["password"] == "changed-by-bob"
    assert router["updated_by"] == "bob"
    assert router["history"][0]["by"] == "bob"
    lines = [(l["by"], l["action"], l["title"]) for l in log_of(alice, vault_id)]
    assert lines == [("alice", "added", "Router"), ("bob", "added", "Printer"),
                     ("bob", "edited", "Router")]
    # alice compared bob's fingerprint when she shared: his lines check out
    for line in log_of(alice, vault_id):
        assert changelog.check(line, vault_id,
                               alice.signing_key_for(line["by"])) == changelog.OK


def test_a_line_forged_under_another_members_name_is_flagged(team, device):
    alice, bob, vault_id = team
    device("b")
    file = bob.vault_file(vault_id)
    before = file.load()
    data = copy.deepcopy(before)
    vault.add_account(data, "Backdoor", "me", "pw")
    # bob writes the line under alice's name (he holds the vault key, so he
    # can write anything) -- but he can only sign it with his own key
    changelog.record(data, before, "alice", bob.keyset, file.hex)
    file.save(data)
    sync_all(bob)
    device("a")
    sync_all(alice)
    forged = [l for l in log_of(alice, vault_id) if l["title"] == "Backdoor"][0]
    assert forged["by"] == "alice"
    assert changelog.check(forged, vault_id,
                           alice.signing_key_for("alice")) == changelog.BAD


def test_both_members_lines_survive_changes_made_at_the_same_time(team, device):
    alice, bob, vault_id = team
    add_entry(alice, vault_id, "FromAlice")
    device("b")
    add_entry(bob, vault_id, "FromBob")
    sync_all(bob)
    device("a")
    sync_all(alice)
    device("b")
    sync_all(bob)
    for who in (alice, bob):
        device("a" if who is alice else "b")
        assert sites(who, vault_id) == ["FromAlice", "FromBob", "Router"]
        assert sorted((l["by"], l["title"]) for l in log_of(who, vault_id)) == \
            [("alice", "FromAlice"), ("alice", "Router"), ("bob", "FromBob")]


def test_a_sync_with_only_new_log_lines_still_has_work(team, device):
    """A line with no entry change left to carry it (the entry was changed
    back) must not be stranded on one device."""
    alice, bob, vault_id = team
    file = alice.vault_file(vault_id)
    data = file.load()
    extra = {"id": "f" * 16, "at": vault.history_now(), "by": "alice",
             "action": "added", "entry": "x", "title": "Ghost", "fields": [],
             "count": 0, "sig": ""}
    data[changelog.CHANGES_KEY] = changelog.merge(changelog.lines_of(data), [extra])
    file.save(data)
    sync_all(alice)
    device("b")
    sync_all(bob)
    assert "Ghost" in [l["title"] for l in log_of(bob, vault_id)]


# ---------------------------------------------------------------------------
# D. Roles
# ---------------------------------------------------------------------------
def test_a_reader_gets_the_entries_and_uploads_nothing(server, device, alice, bob):  # noqa: F811
    vault_id = alice.create_vault("Team").hex
    add_entry(alice, vault_id, "Router")
    sync_all(alice)
    share(alice, vault_id, "bob", accounts.ROLE_READER)
    device("b")
    sync_all(bob)
    assert bob.vault_role(vault_id) == accounts.ROLE_READER
    assert not bob.can_write(vault_id)
    assert not bob.vault_file(vault_id).can_write
    assert sites(bob, vault_id) == ["Router"]
    # a change that somehow got into his copy stays there and goes nowhere
    add_entry(bob, vault_id, "Sneaked")
    stored = server_blob(server, vault_id)
    sync_all(bob)
    assert server_blob(server, vault_id) == stored
    device("a")
    sync_all(alice)
    assert sites(alice, vault_id) == ["Router"]


def test_the_server_refuses_a_readers_upload(server, device, alice, bob):  # noqa: F811
    vault_id = alice.create_vault("Team").hex
    sync_all(alice)
    share(alice, vault_id, "bob", accounts.ROLE_READER)
    device("b")
    sync_all(bob)
    file = bob.vault_file(vault_id)
    with pytest.raises(SyncError, match="not\\s+change"):
        with_server(bob, lambda s: s.put_vault(
            vault_id, file.encrypt({"accounts": []}),
            s.get_vault(vault_id)["revision"]))


def test_a_role_change_reaches_the_member_with_the_next_sync(team, device):
    alice, bob, vault_id = team
    with_server(alice, lambda s: s.put_member(vault_id, "bob",
                                              accounts.ROLE_READER))
    device("b")
    changes = sync_all(bob)
    assert changes.roles == [("Team", accounts.ROLE_READER)]
    assert bob.vault_role(vault_id) == accounts.ROLE_READER


def test_only_an_owner_can_share_or_change_the_key(team, device):
    alice, bob, vault_id = team
    device("b")
    carol = new_account("carol").save()
    assert account_sync.connect(carol, alice.server["url"], "", TOKEN) == "created"
    sync_all(carol)
    with pytest.raises(SyncError, match="owner"):
        share(bob, vault_id, "carol")
    with pytest.raises(SyncError, match="owner"):
        rotate(bob, vault_id)


def test_the_personal_vault_cannot_be_shared(server, device, alice, bob):  # noqa: F811
    with pytest.raises(SyncError, match="[Pp]ersonal"):
        share(alice, alice.personal_id, "bob")


def test_sharing_with_a_name_the_server_does_not_know_is_refused(team):
    alice, bob, vault_id = team
    with pytest.raises(SyncError, match="no account"):
        share(alice, vault_id, "nobody")


def test_sharing_with_yourself_is_refused(team):
    alice, bob, vault_id = team
    with pytest.raises(SyncError, match="own account"):
        share(alice, vault_id, "alice")


def test_the_member_list_says_who_is_checked(team, device):
    alice, bob, vault_id = team
    listed = with_server(alice, lambda s: account_sync.list_members(
        alice, s, vault_id))
    assert [(m["username"], m["role"], m["me"], m["verified"]) for m in listed] == \
        [("alice", "owner", True, False), ("bob", "editor", False, True)]
    device("b")
    listed = with_server(bob, lambda s: account_sync.list_members(bob, s, vault_id))
    # bob never compared alice's fingerprint
    assert [(m["username"], m["verified"]) for m in listed] == \
        [("alice", False), ("bob", False)]


# ---------------------------------------------------------------------------
# E. Keys of other people
# ---------------------------------------------------------------------------
def test_lookup_says_new_then_known_and_shows_the_other_sides_fingerprint(
        server, device, alice, bob):                 # noqa: F811
    keys = with_server(alice, lambda s: account_sync.lookup_contact(alice, s, "BOB"))
    assert keys["username"] == "bob" and keys["status"] == "new"
    assert keys["fingerprint"] == bob.fingerprint
    account_sync.trust_contact(alice, keys, True)
    again = with_server(alice, lambda s: account_sync.lookup_contact(alice, s, "bob"))
    assert (again["status"], again["verified"]) == ("known", True)
    # remembered across a lock
    assert accounts.unlock("alice", PW).contact("bob")["verified"] is True


def test_lookup_notices_keys_that_changed(server, device, alice, bob):  # noqa: F811
    keys = with_server(alice, lambda s: account_sync.lookup_contact(alice, s, "bob"))
    account_sync.trust_contact(alice, keys, True)
    alice.remember_contact("bob", os.urandom(32), keys["signing_key"], True)
    again = with_server(alice, lambda s: account_sync.lookup_contact(alice, s, "bob"))
    assert (again["status"], again["verified"]) == ("changed", False)


def test_a_key_change_stops_when_a_members_keys_are_not_the_ones_seen(team, server):
    alice, bob, vault_id = team
    seen = alice.contact("bob")
    alice.remember_contact("bob", os.urandom(32), seen["signing_key"], True)
    stored = server_blob(server, vault_id)
    with pytest.raises(account_sync.KeyChanged):
        rotate(alice, vault_id)
    assert server_blob(server, vault_id) == stored
    assert alice.vault_file(vault_id).generation == 0


def test_an_account_from_before_signing_sends_its_key_at_the_next_sync(
        server, device, alice):                      # noqa: F811
    path = os.path.join(server.store.root, "_v2", "accounts", "alice.json")
    with open(path, encoding="utf-8") as f:
        record = json.load(f)
    record["signing_key"] = ""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f)
    sync_all(alice)
    with open(path, encoding="utf-8") as f:
        assert json.load(f)["signing_key"] == alice.signing_key


# ---------------------------------------------------------------------------
# F. Removing a member: a new key
# ---------------------------------------------------------------------------
def test_a_removed_member_cannot_open_what_is_written_afterwards(team, server, device):
    alice, bob, vault_id = team
    device("b")
    old_key = bob.vault_file(vault_id)._key
    device("a")
    rotate(alice, vault_id, remove=["bob"])
    add_entry(alice, vault_id, "AfterBob")
    sync_all(alice)
    assert alice.vault_file(vault_id).generation == 1
    assert sites(alice, vault_id) == ["AfterBob", "Router"]
    with pytest.raises(CryptoError):
        account_crypto.decrypt_vault(old_key, server_blob(server, vault_id))
    # the server lets him in no more, and his copy is kept but marked
    device("b")
    with pytest.raises(SyncError):
        with_server(bob, lambda s: s.get_vault(vault_id))
    changes = sync_all(bob)
    assert changes.gone == ["Team"]
    assert bob.vault_record(vault_id)["gone_from_server"] is True
    assert sites(bob, vault_id) == ["Router"]


def test_the_earlier_revisions_under_the_old_key_are_dropped(team, server):
    alice, bob, vault_id = team
    add_entry(alice, vault_id, "Second")
    sync_all(alice)
    history = os.path.join(server.store.root, "_v2", "vaults", vault_id, "history")
    assert os.listdir(history)
    rotate(alice, vault_id, remove=["bob"])
    assert os.listdir(history) == []


def test_nothing_under_the_old_key_stays_on_the_owners_device(team):
    alice, bob, vault_id = team
    old = alice.vault_file(vault_id)
    old_key = old._key
    rotate(alice, vault_id, remove=["bob"])
    new = alice.vault_file(vault_id)
    assert new._key != old_key
    for path in (new.path, new.base_path):
        with open(path, encoding="utf-8") as f:
            blob = f.read().strip()
        assert account_crypto.vault_header(blob)["key_generation"] == 1
        with pytest.raises(CryptoError):
            account_crypto.decrypt_vault(old_key, blob)
    assert not os.path.exists(new.path + vault.BACKUP_SUFFIX)
    assert sites(alice, vault_id) == ["Router"]
    # and it survives a lock
    assert sorted(e["site"] for e in accounts.unlock("alice", PW)
                  .vault_file(vault_id).load()["accounts"]) == ["Router"]


def test_a_member_who_stays_gets_the_new_key_and_keeps_unsynced_changes(team, device):
    alice, bob, vault_id = team
    device("b")
    add_entry(bob, vault_id, "BobOffline")          # not synced yet
    device("a")
    rotate(alice, vault_id)                         # nobody removed
    add_entry(alice, vault_id, "AfterRotation")
    sync_all(alice)
    device("b")
    changes = sync_all(bob)
    assert changes.rekeyed == ["Team"]
    assert bob.vault_file(vault_id).generation == 1
    assert sites(bob, vault_id) == ["AfterRotation", "BobOffline", "Router"]
    device("a")
    sync_all(alice)
    assert sites(alice, vault_id) == ["AfterRotation", "BobOffline", "Router"]


def test_an_upload_under_the_old_key_is_refused_after_a_key_change(team, device):
    alice, bob, vault_id = team
    device("b")
    stale = bob.vault_file(vault_id)                # generation 0
    device("a")
    rotate(alice, vault_id)
    device("b")
    with pytest.raises(SyncError, match="key was changed"):
        with_server(bob, lambda s: s.put_vault(
            vault_id, stale.encrypt({"accounts": []}),
            s.get_vault(vault_id)["revision"]))


def test_the_owners_other_device_takes_the_new_key(team, server, device):
    alice, bob, vault_id = team
    device("c")
    other, _ = account_sync.sign_in(server.url, "", "alice", PW, alice.kit)
    assert sites(other, vault_id) == ["Router"]
    device("a")
    rotate(alice, vault_id, remove=["bob"])
    add_entry(alice, vault_id, "New")
    sync_all(alice)
    device("c")
    changes = sync_all(other)
    assert changes.rekeyed == ["Team"]
    assert sites(other, vault_id) == ["New", "Router"]


def test_the_vaults_name_is_readable_under_the_new_key(team, device):
    alice, bob, vault_id = team
    rotate(alice, vault_id)
    device("b")
    sync_all(bob)
    listed = with_server(bob, lambda s: s.me())["vaults"]
    sealed = next(v["name"] for v in listed if v["id"] == vault_id)
    assert bob.vault_file(vault_id).open_name(sealed) == "Team"


def test_a_key_change_needs_the_vault_synced_without_open_questions(team, device):
    alice, bob, vault_id = team
    edit_entry(alice, vault_id, "Router", password="alice-version")
    device("b")
    edit_entry(bob, vault_id, "Router", password="bob-version")
    sync_all(bob)
    device("a")
    with pytest.raises(SyncError, match="Sync first"):
        rotate(alice, vault_id, remove=["bob"])
    assert alice.vault_file(vault_id).generation == 0


def test_removing_someone_who_is_not_a_member_changes_nothing(team):
    alice, bob, vault_id = team
    with pytest.raises(SyncError, match="Not a member"):
        rotate(alice, vault_id, remove=["carol"])
    assert alice.vault_file(vault_id).generation == 0


# ---------------------------------------------------------------------------
# G. Leaving, and vaults on another server
# ---------------------------------------------------------------------------
def test_a_member_leaves_and_the_vault_stays_for_the_owner(team, device):
    alice, bob, vault_id = team
    device("b")
    account_sync.delete_vault(bob, vault_id)
    assert vault_id not in bob.vault_ids()
    assert sync_all(bob).added == []                # it does not come back
    device("a")
    sync_all(alice)
    assert sites(alice, vault_id) == ["Router"]
    listed = with_server(alice, lambda s: account_sync.list_members(
        alice, s, vault_id))
    assert [m["username"] for m in listed] == ["alice"]


def test_an_owner_deleting_the_vault_takes_it_from_every_member(team, device):
    alice, bob, vault_id = team
    account_sync.delete_vault(alice, vault_id)
    device("b")
    assert sync_all(bob).gone == ["Team"]
    assert sites(bob, vault_id) == ["Router"]       # kept on his device


def test_a_vault_put_back_starts_as_ones_own_again(team, device):
    alice, bob, vault_id = team
    rotate(alice, vault_id, remove=["bob"])
    device("b")
    sync_all(bob)
    account_sync.put_vault_back(bob, vault_id)
    record = bob.vault_record(vault_id)
    assert (record["role"], record["key_generation"], record["members"]) == \
        (accounts.ROLE_OWNER, 0, 1)


def test_moving_to_another_server_forgets_roles_and_generations(team):
    alice, bob, vault_id = team
    rotate(alice, vault_id)
    assert alice.vault_record(vault_id)["key_generation"] == 1
    alice.set_server("http://127.0.0.1:1")
    record = alice.vault_record(vault_id)
    assert "key_generation" not in record and "role" not in record
    assert alice.vault_file(vault_id).generation == 0
    assert sites(alice, vault_id) == ["Router"]     # still opens


# ---------------------------------------------------------------------------
# H. The server's own log, as an owner reads it
# ---------------------------------------------------------------------------
def test_the_owner_reads_what_the_server_noted(team, device):
    alice, bob, vault_id = team
    device("b")
    add_entry(bob, vault_id, "Printer")
    sync_all(bob)
    device("a")
    lines = with_server(alice, lambda s: s.vault_log(vault_id))
    events = [(l["event"], l["by"]) for l in lines]
    assert events[0] == ("vault_created", "alice")
    assert ("member_added", "alice") in events
    assert events[-1] == ("upload", "bob")
    assert all(l.get("address") == "127.0.0.1" for l in lines)
    device("b")
    with pytest.raises(SyncError, match="owner"):
        with_server(bob, lambda s: s.vault_log(vault_id))


def test_a_new_account_gives_the_server_its_signing_key_at_sign_up(server, alice):  # noqa: F811
    path = os.path.join(server.store.root, "_v2", "accounts", "alice.json")
    with open(path, encoding="utf-8") as f:
        assert json.load(f)["signing_key"] == alice.signing_key
