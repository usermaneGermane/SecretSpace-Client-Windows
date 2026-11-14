"""
Security review (2026-11-12): a server must never be able to choose a
vault's key.

The server stores each member's wrapped copy of a vault key. If a device
took whatever key the server listed, a dishonest server could wrap a key of
its own to the member's public key (which it knows), announce it as a new
key generation, and read the vault the device then uploads under it. So
every wrapped key carries a signature by the account that wrapped it, and a
device takes a key only when it is signed by itself or by someone it has
reason to trust.

Here the server's files are edited directly, as a dishonest server (or
whoever broke into it) would.
"""

import base64
import json
import os
import shutil

import pytest

import account_crypto
import account_sync
import accounts
import vault
from account_sync import KeyNotTrusted
from sync_client import SyncError

from test_account_sync import (PW, TOKEN, alice, cheap_argon2, device,  # noqa: F401
                               new_account, secretspace_server, server)
from test_account_vaults import sync_all, sites
from test_account_sharing import add_entry, share, rotate, with_server


# ---------------------------------------------------------------------------
# The dishonest server's tools
# ---------------------------------------------------------------------------
def vault_folder(server, vault_id):
    return os.path.join(server.store.root, "_v2", "vaults", vault_id)


def read_members(server, vault_id):
    with open(os.path.join(vault_folder(server, vault_id), "members.json"),
              encoding="utf-8") as f:
        return json.load(f)


def write_members(server, vault_id, members):
    with open(os.path.join(vault_folder(server, vault_id), "members.json"), "w",
              encoding="utf-8") as f:
        json.dump(members, f)


def public_key_on_server(server, name):
    path = os.path.join(server.store.root, "_v2", "accounts", name + ".json")
    with open(path, encoding="utf-8") as f:
        return base64.b64decode(json.load(f)["public_key"])


def swap_key(server, vault_id, victim, generation, signer=None, signer_keyset=None,
             drop_blob=True):
    """Give ``victim`` a key the server made itself, as key generation
    ``generation``; optionally with a signature by ``signer_keyset`` under
    the name ``signer``. Returns the server's key."""
    raw_id = bytes.fromhex(vault_id)
    evil = os.urandom(32)
    members = read_members(server, vault_id)
    wrapped = account_crypto.wrap_key(public_key_on_server(server, victim), evil,
                                      raw_id, victim)
    entry = members["members"][victim]
    entry["wrapped_key"] = wrapped
    entry["key_sig"], entry["key_signer"] = "", ""
    if signer:
        entry["key_signer"] = signer
        entry["key_sig"] = account_crypto.sign(
            signer_keyset, account_sync.key_message(vault_id, generation, victim,
                                                    wrapped, signer))
    members["key_generation"] = generation
    members["name"] = account_crypto.seal_vault_name(evil, raw_id, "Team")
    write_members(server, vault_id, members)
    if drop_blob:                       # "nothing uploaded yet": push it all
        for name in ("vault.enc", "meta.json"):
            try:
                os.remove(os.path.join(vault_folder(server, vault_id), name))
            except FileNotFoundError:
                pass
    return evil


def server_can_read(server, vault_id, evil_key):
    path = os.path.join(vault_folder(server, vault_id), "vault.enc")
    if not os.path.exists(path):
        return False
    with open(path, "rb") as f:
        blob = f.read().decode("ascii")
    try:
        account_crypto.decrypt_vault(evil_key, blob)
        return True
    except account_crypto.CryptoError:
        return False


def make_account(server, device, name, where):       # noqa: F811
    device(where)
    account = new_account(name).save()
    assert account_sync.connect(account, server.url, "", TOKEN) == "created"
    sync_all(account)
    return account


@pytest.fixture
def team(server, device, alice):                     # noqa: F811
    """alice's own vault Team with a secret in it, on the server."""
    vault_id = alice.create_vault("Team").hex
    add_entry(alice, vault_id, "Bank", "TOP-SECRET")
    sync_all(alice)
    return alice, vault_id


def untouched(account, vault_id, key_before):
    file = account.vault_file(vault_id)
    assert file._key == key_before
    assert file.generation == 0
    assert sites(account, vault_id) == ["Bank"]


# ---------------------------------------------------------------------------
# A. The signature itself
# ---------------------------------------------------------------------------
def test_a_key_signature_covers_vault_generation_member_key_and_signer(alice):
    wrapped = alice.vault_record(alice.create_vault("V").hex)["wrapped_key"]
    vault_id = "ab" * 16
    sig = account_sync.sign_key(alice, vault_id, 3, "bob", wrapped)
    key = account_crypto.signing_key_of(alice.keyset)

    def ok(*args):
        return account_crypto.verify(key, account_sync.key_message(*args), sig)

    assert ok(vault_id, 3, "bob", wrapped, "alice")
    assert not ok("cd" * 16, 3, "bob", wrapped, "alice")
    assert not ok(vault_id, 4, "bob", wrapped, "alice")
    assert not ok(vault_id, 3, "carol", wrapped, "alice")
    assert not ok(vault_id, 3, "bob", wrapped[:-4] + "AAAA", "alice")
    assert not ok(vault_id, 3, "bob", wrapped, "mallory")


def test_a_vault_goes_to_the_server_with_its_owners_signature(server, team):
    alice, vault_id = team
    entry = read_members(server, vault_id)["members"]["alice"]
    assert entry["key_signer"] == "alice"
    assert account_crypto.verify(
        account_crypto.signing_key_of(alice.keyset),
        account_sync.key_message(vault_id, 0, "alice", entry["wrapped_key"],
                                 "alice"), entry["key_sig"])
    assert alice.vault_record(vault_id)["key_signer"] == "alice"


# ---------------------------------------------------------------------------
# B. A server that makes up a key for a vault this device already has
# ---------------------------------------------------------------------------
def test_a_key_with_no_signature_is_refused_and_nothing_is_uploaded(server, team):
    alice, vault_id = team
    key = alice.vault_file(vault_id)._key
    evil = swap_key(server, vault_id, "alice", 1)
    with pytest.raises(KeyNotTrusted, match="no signature"):
        sync_all(alice)
    assert not server_can_read(server, vault_id, evil)
    untouched(alice, vault_id, key)


def test_a_key_signed_by_the_wrong_key_under_the_owners_name_is_refused(server, team):
    alice, vault_id = team
    key = alice.vault_file(vault_id)._key
    evil = swap_key(server, vault_id, "alice", 1, "alice",
                    account_crypto.new_keyset())
    with pytest.raises(KeyNotTrusted, match="not signed by"):
        sync_all(alice)
    assert not server_can_read(server, vault_id, evil)
    untouched(alice, vault_id, key)


def test_a_key_signed_by_an_account_never_seen_here_is_refused(server, team, device):
    alice, vault_id = team
    key = alice.vault_file(vault_id)._key
    mallory = make_account(server, device, "mallory", "m")
    device("a")
    evil = swap_key(server, vault_id, "alice", 1, "mallory", mallory.keyset)
    with pytest.raises(KeyNotTrusted, match="never checked"):
        sync_all(alice)
    assert not server_can_read(server, vault_id, evil)
    untouched(alice, vault_id, key)
    assert alice.contact("mallory") is None          # and not remembered for it


def test_being_seen_once_is_not_enough_to_replace_a_key(server, team, device):
    """Two steps: first a harmless vault "shared by mallory" (her key is
    remembered, unchecked), then a made-up key for Team signed by her."""
    alice, vault_id = team
    key = alice.vault_file(vault_id)._key
    mallory = make_account(server, device, "mallory", "m")
    bait = mallory.create_vault("Bait").hex
    sync_all(mallory)
    session = account_sync.logged_in(mallory)
    keys = account_sync.lookup_contact(mallory, session, "alice")
    account_sync.share_vault(mallory, session, bait, keys, "editor")
    session.logout()
    device("a")
    assert sync_all(alice).added == ["Bait"]
    assert alice.contact("mallory")["verified"] is False
    evil = swap_key(server, vault_id, "alice", 1, "mallory", mallory.keyset)
    with pytest.raises(KeyNotTrusted, match="never checked"):
        sync_all(alice)
    assert not server_can_read(server, vault_id, evil)
    untouched(alice, vault_id, key)


def test_an_older_key_generation_is_refused(server, team, device):
    alice, vault_id = team
    bob = make_account(server, device, "bob", "b")
    device("a")
    share(alice, vault_id, "bob")
    before = os.path.join(server.store.root, "_before")
    shutil.copytree(vault_folder(server, vault_id), before)
    rotate(alice, vault_id, remove=["bob"])
    add_entry(alice, vault_id, "AfterBob")
    sync_all(alice)
    # the server (with bob) puts the vault back as it was before the removal
    shutil.rmtree(vault_folder(server, vault_id))
    shutil.copytree(before, vault_folder(server, vault_id))
    with pytest.raises(KeyNotTrusted, match="older key"):
        sync_all(alice)
    assert alice.vault_file(vault_id).generation == 1
    assert sites(alice, vault_id) == ["AfterBob", "Bank"]


def test_another_key_at_the_same_generation_is_refused(server, team):
    alice, vault_id = team
    key = alice.vault_file(vault_id)._key
    evil = swap_key(server, vault_id, "alice", 0, "alice", alice.keyset)
    # (even "signed by alice": the server cannot do that, this is the worst case)
    with pytest.raises(KeyNotTrusted, match="not the\\s+one this PC holds"):
        sync_all(alice)
    assert not server_can_read(server, vault_id, evil)
    untouched(alice, vault_id, key)


# ---------------------------------------------------------------------------
# C. A server that invents a vault
# ---------------------------------------------------------------------------
def invent_vault(server, victim, signer="", signer_keyset=None):
    vault_id = os.urandom(16).hex()
    raw_id = bytes.fromhex(vault_id)
    evil = os.urandom(32)
    wrapped = account_crypto.wrap_key(public_key_on_server(server, victim), evil,
                                      raw_id, victim)
    entry = {"role": "owner", "wrapped_key": wrapped, "key_sig": "",
             "key_signer": signer}
    if signer_keyset is not None:
        entry["key_sig"] = account_crypto.sign(signer_keyset, account_sync.key_message(
            vault_id, 0, victim, wrapped, signer))
    os.makedirs(vault_folder(server, vault_id))
    write_members(server, vault_id, {
        "kind": "shared", "created_by": victim, "key_generation": 0,
        "name": account_crypto.seal_vault_name(evil, raw_id, "Work"),
        "members": {victim: entry}})
    path = os.path.join(server.store.root, "_v2", "accounts", victim + ".json")
    with open(path, encoding="utf-8") as f:
        record = json.load(f)
    record["vaults"] = record.get("vaults", []) + [vault_id]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f)
    return vault_id


@pytest.mark.parametrize("forged_as_own", [False, True])
def test_an_invented_vault_is_not_taken_as_ones_own(server, alice, forged_as_own):
    made_up = invent_vault(server, "alice",
                           "alice" if forged_as_own else "",
                           account_crypto.new_keyset() if forged_as_own else None)
    with pytest.raises(KeyNotTrusted):
        sync_all(alice)
    assert made_up not in alice.vault_ids()


# ---------------------------------------------------------------------------
# D. What must keep working
# ---------------------------------------------------------------------------
def test_a_key_change_by_the_owner_who_shared_the_vault_is_taken(server, team, device):
    alice, vault_id = team
    bob = make_account(server, device, "bob", "b")
    device("a")
    share(alice, vault_id, "bob")
    device("b")
    assert sync_all(bob).added == ["Team"]
    assert bob.vault_record(vault_id)["key_signer"] == "alice"
    device("a")
    rotate(alice, vault_id)
    add_entry(alice, vault_id, "New")
    sync_all(alice)
    device("b")
    assert sync_all(bob).rekeyed == ["Team"]
    assert sites(bob, vault_id) == ["Bank", "New"]


def test_a_key_change_by_another_owner_needs_their_fingerprint_checked(
        server, team, device):
    alice, vault_id = team
    bob = make_account(server, device, "bob", "b")
    carol = make_account(server, device, "carol", "c")
    device("a")
    share(alice, vault_id, "bob", accounts.ROLE_OWNER)
    share(alice, vault_id, "carol")
    device("b")
    sync_all(bob)
    device("c")
    sync_all(carol)                      # carol got the vault from alice
    device("b")
    rotate(bob, vault_id)                # bob, an owner too, changes the key
    # alice compared bob's fingerprint when she shared: she takes his key
    device("a")
    assert sync_all(alice).rekeyed == ["Team"]
    # carol never did: she refuses until she has
    device("c")
    with pytest.raises(KeyNotTrusted, match="never checked"):
        sync_all(carol)
    assert carol.vault_file(vault_id).generation == 0
    keys = with_server(carol, lambda s: account_sync.lookup_contact(carol, s, "bob"))
    account_sync.trust_contact(carol, keys, True)
    assert sync_all(carol).rekeyed == ["Team"]
    assert sites(carol, vault_id) == ["Bank"]


def test_a_second_device_takes_its_own_accounts_vaults(server, team, device):
    alice, vault_id = team
    device("b")
    other, _ = account_sync.sign_in(server.url, "", "alice", PW, alice.kit)
    assert sites(other, vault_id) == ["Bank"]
    assert other.vault_record(vault_id)["key_signer"] == "alice"


def test_a_vault_from_before_signatures_is_vouched_for_by_a_device_that_has_it(
        server, team, device):
    alice, vault_id = team
    members = read_members(server, vault_id)
    members["members"]["alice"].pop("key_sig")
    members["members"]["alice"].pop("key_signer")
    write_members(server, vault_id, members)
    # a new device cannot take it as it is ...
    device("b")
    with pytest.raises(KeyNotTrusted, match="no signature"):
        account_sync.sign_in(server.url, "", "alice", PW, alice.kit)
    # ... until a device that holds the vault has synced once
    device("a")
    sync_all(alice)
    assert read_members(server, vault_id)["members"]["alice"]["key_signer"] == "alice"
    device("c")
    other, _ = account_sync.sign_in(server.url, "", "alice", PW, alice.kit)
    assert sites(other, vault_id) == ["Bank"]


def test_a_server_without_signed_keys_gets_only_the_personal_vault(
        server, team, monkeypatch):
    alice, vault_id = team
    monkeypatch.setattr(account_sync.AccountServer, "has_signed_keys",
                        lambda self: False)
    session = account_sync.logged_in(alice)
    try:
        changes = account_sync.reconcile_vaults(alice, session)
        assert changes.server_too_old is True
        assert account_sync.syncable_vaults(alice, session) == [alice.personal_id]
    finally:
        session.logout()


# ---------------------------------------------------------------------------
# E. Plain http
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("url,plain", [
    ("http://192.168.1.50:8787", True),
    ("http://sync.example.org", True),
    ("HTTP://10.0.0.3:59872/", True),
    ("https://192.168.1.50:8787", False),
    ("http://127.0.0.1:8787", False),
    ("http://127.5.5.5", False),
    ("http://localhost:8787", False),
    ("http://[::1]:8787", False),
    ("", False),
])
def test_only_unencrypted_addresses_of_other_machines_are_flagged(url, plain):
    assert account_sync.is_plain_remote(url) is plain
