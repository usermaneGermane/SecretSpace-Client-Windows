"""
Phase 3: several vaults per account -- names and crypto, vaults on one device,
and vaults between devices through the real (test copy of the) sync server.
"""

import base64
import glob
import os
import threading

import pytest

import account_crypto
import account_sync
import accounts
import sync
import vault
from account_crypto import CryptoError
from sync_client import SyncError

# Reused from the phase 2 sync tests: the server, the "device" switch, the
# cheap Argon2 settings and the two-device helpers.
from test_account_sync import (PW, TOKEN, alice, cheap_argon2, device,  # noqa: F401
                               entry, new_account, passman_server, server)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def make(name="alice", pw=PW):
    return accounts.prepare_account(name, pw).save()


def put_entry(account, vault_id, site, password=None):
    """Add an entry to one vault of the account, on this device."""
    file = account.vault_file(vault_id)
    data = file.load()
    vault.add_account(data, site, "me", password or f"pw-{site}")
    file.save(data)


def sites(account, vault_id=None):
    return sorted(e["site"] for e in account.vault_file(vault_id).load()["accounts"])


def sync_vault(account, vault_id, choices=None):
    """One whole sync of one vault, as the UI runs it; returns its data."""
    session = account_sync.AccountSync(account, None, vault_id)
    try:
        # an adopted vault has no file until its first sync
        local = session.file.load() if session.file.has_file else {"accounts": []}
        result = session.prepare(local)
        if not session.has_work():
            return local
        if result.conflicts and choices is None:
            raise AssertionError(f"unexpected conflicts: {result.conflicts}")
        return session.commit(local, choices)
    finally:
        session.close()


def reconcile(account):
    server = account_sync.logged_in(account)
    try:
        return account_sync.reconcile_vaults(account, server)
    finally:
        server.logout()


def syncable(account):
    server = account_sync.logged_in(account)
    try:
        return account_sync.syncable_vaults(account, server)
    finally:
        server.logout()


def sync_all(account):
    """Reconcile, then sync every syncable vault."""
    changes = reconcile(account)
    for vault_id in syncable(account):
        sync_vault(account, vault_id)
    return changes


def store_bytes(server):
    found = b""
    for folder, _, files in os.walk(server.store.root):
        for name in files:
            with open(os.path.join(folder, name), "rb") as f:
                found += f.read()
    return found


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def start_server(path):
    httpd = passman_server.ThreadingHTTPServer(("127.0.0.1", 0),
                                               passman_server.Handler)
    httpd.store = passman_server.Store(str(path))
    httpd.token = TOKEN
    os.makedirs(httpd.store.root, exist_ok=True)
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    httpd.url = f"http://127.0.0.1:{httpd.server_address[1]}"
    return httpd, thread


def stop_server(httpd, thread):
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


@pytest.fixture
def two_devices(server, device, alice):          # noqa: F811
    """alice on device a, and the same account signed in on device b.
    Returns (a, b); switch with device("a") / device("b") before using one."""
    device("b")
    other, _ = account_sync.sign_in(server.url, "", "alice", PW, alice.kit)
    device("a")
    return alice, other


# ---------------------------------------------------------------------------
# A. Names and crypto
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["Work", "Família 家族 🔐", "a"])
def test_a_sealed_name_opens_again(name):
    key, vid = account_crypto.new_vault_key(), account_crypto.new_vault_id()
    sealed = account_crypto.seal_vault_name(key, vid, name)
    assert account_crypto.open_vault_name(key, vid, sealed) == name


def test_a_sealed_name_hides_the_name_and_differs_each_time():
    key, vid = account_crypto.new_vault_key(), account_crypto.new_vault_id()
    one = account_crypto.seal_vault_name(key, vid, "Secret Project")
    two = account_crypto.seal_vault_name(key, vid, "Secret Project")
    assert one != two
    for sealed in (one, two):
        assert "Secret Project" not in sealed
        assert b"Secret Project" not in base64.b64decode(sealed)


def test_a_name_opens_only_with_its_own_key_and_vault_id():
    key, vid = account_crypto.new_vault_key(), account_crypto.new_vault_id()
    sealed = account_crypto.seal_vault_name(key, vid, "Work")
    with pytest.raises(CryptoError):
        account_crypto.open_vault_name(account_crypto.new_vault_key(), vid, sealed)
    with pytest.raises(CryptoError):
        account_crypto.open_vault_name(key, account_crypto.new_vault_id(), sealed)


def test_seal_refuses_an_empty_or_too_long_name():
    key, vid = account_crypto.new_vault_key(), account_crypto.new_vault_id()
    with pytest.raises(CryptoError):
        account_crypto.seal_vault_name(key, vid, "")
    with pytest.raises(CryptoError):
        account_crypto.seal_vault_name(key, vid, "x" * 201)
    with pytest.raises(CryptoError):
        account_crypto.seal_vault_name(key, vid, "\U0001F510" * 51)   # 204 bytes
    account_crypto.seal_vault_name(key, vid, "x" * 200)               # the limit


def test_a_damaged_sealed_name_is_refused():
    key, vid = account_crypto.new_vault_key(), account_crypto.new_vault_id()
    sealed = account_crypto.seal_vault_name(key, vid, "Work")
    raw = bytearray(base64.b64decode(sealed))
    flipped = bytearray(raw)
    flipped[-1] ^= 1
    for damaged in (base64.b64encode(bytes(raw[:10])).decode(),
                    base64.b64encode(bytes(flipped)).decode(),
                    base64.b64encode(bytes(raw[:-3])).decode(),
                    "", "not base64 !!"):
        with pytest.raises(CryptoError):
            account_crypto.open_vault_name(key, vid, damaged)


def test_clean_vault_name_tidies_whitespace():
    assert accounts.clean_vault_name("  Family   photos \t ") == "Family photos"
    assert accounts.clean_vault_name("a\n b") == "a b"
    assert accounts.clean_vault_name("x" * 60) == "x" * 60


@pytest.mark.parametrize("bad", [None, "", "   \t ", "x" * 61, "a\x00b", "a\x07b",
                                 "a\x7fb", "\U0001F510" * 60])
def test_clean_vault_name_refuses(bad):
    with pytest.raises(ValueError):
        accounts.clean_vault_name(bad)


# ---------------------------------------------------------------------------
# B. Vaults on one device
# ---------------------------------------------------------------------------
def test_a_fresh_account_has_only_its_personal_vault():
    acc = make()
    assert acc.vault_ids() == [acc.personal_id]
    assert acc.personal_id == acc.vault_id.hex()
    file = acc.vault_file()
    assert file.personal and file.name == accounts.PERSONAL_NAME
    assert file.hex == acc.personal_id
    assert acc.vault_file(acc.personal_id).hex == acc.personal_id


def test_create_vault_lists_it_after_the_personal_one_by_name():
    acc = make()
    zed = acc.create_vault("zed")
    bravo = acc.create_vault("bravo")
    alpha = acc.create_vault("Alpha")
    assert acc.vault_ids() == [acc.personal_id, alpha.hex, bravo.hex, zed.hex]
    assert not alpha.personal and alpha.name == "Alpha"
    assert acc.vault_record(alpha.hex)["name"] == "Alpha"
    assert acc.vault_record(acc.personal_id) == {}


def test_a_new_vault_file_is_a_pmv3_blob_of_that_vault():
    acc = make()
    made = acc.create_vault("Work")
    assert os.path.isfile(made.path)
    header = account_crypto.vault_header(read_file(made.path).decode())
    assert header["vault_id"] == bytes.fromhex(made.hex)
    assert header["vault_id"] != acc.vault_id
    assert made.load() == {"accounts": []}


def test_entries_saved_in_a_vault_load_back_and_survive_a_lock():
    acc = make()
    made = acc.create_vault("Work")
    put_entry(acc, made.hex, "intranet")
    assert sites(acc, made.hex) == ["intranet"]
    again = accounts.unlock("alice", PW)
    assert again.vault_ids() == acc.vault_ids()
    assert again.vault_file(made.hex).name == "Work"
    assert sites(again, made.hex) == ["intranet"]
    assert sites(again) == []                    # not in the personal vault


def test_nothing_of_a_vault_is_readable_on_disk():
    acc = make()
    made = acc.create_vault("Work")
    put_entry(acc, made.hex, "marker-site-xyz", "marker-password-xyz")
    key = made._key
    on_disk = read_file(os.path.join(accounts.account_dir("alice"),
                                     "account.json")) + read_file(made.path)
    for needle in (key, key.hex().encode(), account_crypto._b64(key).encode(),
                   b"marker-site-xyz", b"marker-password-xyz"):
        assert needle not in on_disk
    # account.json does hold the (wrapped) key and the name, nothing more
    assert acc.vault_record(made.hex)["wrapped_key"].encode() in on_disk


def test_a_blob_of_one_vault_is_refused_by_another():
    acc = make()
    a, b = acc.create_vault("A"), acc.create_vault("B")
    blob_a = a.encrypt({"accounts": []})
    blob_p = acc.encrypt({"accounts": []})
    with pytest.raises(CryptoError):
        b.decrypt(blob_a)
    with pytest.raises(CryptoError):
        acc.decrypt(blob_a)
    with pytest.raises(CryptoError):
        a.decrypt(blob_p)
    with pytest.raises(CryptoError):
        b.decrypt(blob_p)
    assert a.decrypt(blob_a) == {"accounts": []}


def test_a_blob_with_another_vaults_id_is_refused_even_under_the_same_key():
    """Same key, other vault id: the id check alone has to refuse it."""
    acc = make()
    a = acc.create_vault("A")
    other_id = account_crypto.new_vault_id()
    blob = account_crypto.encrypt_vault(a._key, other_id, 0, {"accounts": []})
    with pytest.raises(CryptoError):
        a.decrypt(blob)


def test_every_vault_has_its_own_key():
    acc = make()
    a, b = acc.create_vault("A"), acc.create_vault("B")
    assert len({a._key, b._key, acc.vault_file()._key}) == 3
    # and a blob made with the personal key, labelled as A, does not open as A
    blob = account_crypto.encrypt_vault(acc.vault_file()._key,
                                        bytes.fromhex(a.hex), 0, {"accounts": []})
    with pytest.raises(CryptoError):
        a.decrypt(blob)


def test_swapped_vault_files_fail_to_load_instead_of_showing_the_other():
    acc = make()
    a, b = acc.create_vault("A"), acc.create_vault("B")
    for f in (a, b):
        for leftover in (f.path + vault.BACKUP_SUFFIX,):
            if os.path.exists(leftover):
                os.remove(leftover)
    blob_a, blob_b = read_file(a.path), read_file(b.path)
    with open(a.path, "wb") as f:
        f.write(blob_b)
    with open(b.path, "wb") as f:
        f.write(blob_a)
    with pytest.raises(CryptoError):
        a.load()
    with pytest.raises(CryptoError):
        b.load()


def test_the_personal_file_in_place_of_another_vault_fails_to_load():
    acc = make()
    a = acc.create_vault("A")
    for leftover in (a.path + vault.BACKUP_SUFFIX,):
        if os.path.exists(leftover):
            os.remove(leftover)
    put_entry(acc, acc.personal_id, "personal-only")
    with open(a.path, "wb") as f:
        f.write(read_file(acc.vault_path))
    os.remove(a.path + vault.BACKUP_SUFFIX) if os.path.exists(
        a.path + vault.BACKUP_SUFFIX) else None
    with pytest.raises(CryptoError):
        a.load()


def test_vault_names_are_unique_ignoring_case_and_never_personal():
    acc = make()
    acc.create_vault("Work")
    for bad in ("work", "WORK", " Work ", "Personal", "personal", "PERSONAL"):
        with pytest.raises(ValueError):
            acc.create_vault(bad)
    assert len(acc.vault_ids()) == 2


def test_a_bad_name_creates_nothing():
    acc = make()
    for bad in ("", "x" * 61, "a\x00"):
        with pytest.raises(ValueError):
            acc.create_vault(bad)
    assert acc.vault_ids() == [acc.personal_id]
    assert os.listdir(os.path.dirname(acc.vault_path)) == [
        acc.personal_id + ".pmv3"]


def test_rename_a_vault():
    acc = make()
    work = acc.create_vault("Work")
    other = acc.create_vault("Other")
    acc.rename_vault(work.hex, "  Office  ")
    assert acc.vault_file(work.hex).name == "Office"
    assert accounts.unlock("alice", PW).vault_file(work.hex).name == "Office"
    # not on a server, so there is nothing to tell it
    assert not acc.vault_record(work.hex)["rename_pending"]
    acc.rename_vault(work.hex, "WORK")                    # its own name, new case
    assert acc.vault_file(work.hex).name == "WORK"
    with pytest.raises(ValueError):
        acc.rename_vault(work.hex, "other")               # taken
    with pytest.raises(ValueError):
        acc.rename_vault(work.hex, "Personal")
    with pytest.raises(ValueError):
        acc.rename_vault(acc.personal_id, "Mine")
    with pytest.raises(ValueError):
        acc.rename_vault(os.urandom(16).hex(), "Ghost")
    with pytest.raises(ValueError):
        acc.rename_vault(work.hex, "")
    assert acc.vault_file(other.hex).name == "Other"


def test_rename_marks_a_name_the_server_does_not_know_yet():
    acc = make()
    work = acc.create_vault("Work")
    acc.mark_vault(work.hex, on_server=True)
    acc.rename_vault(work.hex, "Office")
    assert acc.vault_record(work.hex)["rename_pending"] is True
    acc.rename_vault(work.hex, "Office 2", pending=False)
    assert acc.vault_record(work.hex)["rename_pending"] is False


def test_delete_vault_removes_its_record_and_files_only():
    acc = make()
    a, b = acc.create_vault("A"), acc.create_vault("B")
    put_entry(acc, a.hex, "in-a")
    put_entry(acc, b.hex, "in-b")
    put_entry(acc, acc.personal_id, "in-personal")
    a.save_base({"accounts": []}, {"url": "u", "revision": 1})
    assert all(os.path.exists(p) for p in (a.path, a.path + ".bak", a.base_path))
    acc.delete_vault(a.hex)
    assert not any(os.path.exists(p) for p in (a.path, a.path + ".bak",
                                               a.base_path))
    assert acc.vault_ids() == [acc.personal_id, b.hex]
    with pytest.raises(KeyError):
        acc.vault_file(a.hex)
    again = accounts.unlock("alice", PW)
    assert again.vault_ids() == [acc.personal_id, b.hex]
    assert sites(again, b.hex) == ["in-b"]
    assert sites(again) == ["in-personal"]


def test_delete_vault_refuses_the_personal_vault_and_strangers():
    acc = make()
    with pytest.raises(ValueError):
        acc.delete_vault(acc.personal_id)
    with pytest.raises(ValueError):
        acc.delete_vault(os.urandom(16).hex())
    assert acc.vault_ids() == [acc.personal_id]
    assert acc.vault_file().has_file


def test_a_vault_wrapped_for_another_account_cannot_be_adopted():
    acc_a = make("alice")
    acc_b = make("bob")
    vid = account_crypto.new_vault_id()
    key = account_crypto.new_vault_key()
    wrapped = account_crypto.wrap_key(
        account_crypto.public_key_of(acc_b.keyset), key, vid, "bob")
    sealed = account_crypto.seal_vault_name(key, vid, "Bobs")
    with pytest.raises(CryptoError):
        acc_a.adopt_vault(vid.hex(), wrapped, sealed)
    assert acc_a.vault_ids() == [acc_a.personal_id]
    assert accounts.unlock("alice", PW).vault_ids() == [acc_a.personal_id]
    # ... but bob can
    assert acc_b.adopt_vault(vid.hex(), wrapped, sealed).name == "Bobs"


def test_adopting_with_a_name_that_is_not_the_vaults_is_refused():
    acc = make()
    vid = account_crypto.new_vault_id()
    key = account_crypto.new_vault_key()
    wrapped = account_crypto.wrap_key(account_crypto.public_key_of(acc.keyset),
                                      key, vid, "alice")
    wrong = account_crypto.seal_vault_name(account_crypto.new_vault_key(), vid, "X")
    with pytest.raises(CryptoError):
        acc.adopt_vault(vid.hex(), wrapped, wrong)
    assert acc.vault_ids() == [acc.personal_id]


def test_an_adopted_vault_with_a_taken_name_gets_a_suffix():
    acc = make()
    mine = acc.create_vault("Work")
    vid = account_crypto.new_vault_id()
    key = account_crypto.new_vault_key()
    wrapped = account_crypto.wrap_key(account_crypto.public_key_of(acc.keyset),
                                      key, vid, "alice")
    adopted = acc.adopt_vault(vid.hex(), wrapped,
                              account_crypto.seal_vault_name(key, vid, "work"))
    assert adopted.name == "work (2)"
    assert acc.vault_file(mine.hex).name == "Work"
    assert acc.vault_record(vid.hex())["on_server"] is True
    # a third of the same name goes on counting
    vid2 = account_crypto.new_vault_id()
    key2 = account_crypto.new_vault_key()
    wrapped2 = account_crypto.wrap_key(account_crypto.public_key_of(acc.keyset),
                                       key2, vid2, "alice")
    third = acc.adopt_vault(vid2.hex(), wrapped2,
                            account_crypto.seal_vault_name(key2, vid2, "Work"))
    assert third.name == "Work (3)"
    assert len(acc.vault_ids()) == 4


def test_the_personal_vault_methods_work_as_before():
    acc = make()
    acc.save_vault({"accounts": [entry("one")]})
    assert [e["site"] for e in acc.load_vault()["accounts"]] == ["one"]
    assert acc.has_vault_file
    assert acc.vault_path == acc.vault_file().path
    assert acc.decrypt(acc.encrypt({"accounts": []})) == {"accounts": []}
    acc.save_base({"accounts": []}, {"url": "u", "revision": 3})
    assert acc.load_base()[vault.BASE_ORIGIN_KEY] == {"url": "u", "revision": 3}
    assert acc.base_path == acc.vault_file().base_path


def test_a_damaged_vault_file_falls_back_to_the_previous_save():
    acc = make()
    for vault_id in (None, acc.create_vault("Work").hex):
        file = acc.vault_file(vault_id)
        file.save({"accounts": [entry("first")]})
        file.save({"accounts": [entry("first"), entry("second")]})
        with open(file.path, "wb") as f:
            f.write(b"damaged beyond reading")
        assert [e["site"] for e in file.load()["accounts"]] == ["first"]
    # and for the personal vault through the old method
    assert [e["site"] for e in acc.load_vault()["accounts"]] == ["first"]


# ---------------------------------------------------------------------------
# C. With the server
# ---------------------------------------------------------------------------
def test_a_vault_made_on_a_appears_on_b_with_its_entries(server, device,
                                                         two_devices):
    a, b = two_devices
    work = a.create_vault("Work")
    put_entry(a, work.hex, "intranet")
    put_entry(a, a.personal_id, "personal-site")
    sync_all(a)

    device("b")
    changes = reconcile(b)
    assert changes.added == ["Work"]
    assert b.vault_ids() == [b.personal_id, work.hex]
    assert b.vault_file(work.hex).name == "Work"
    assert syncable(b) == [b.personal_id, work.hex]
    for vault_id in syncable(b):
        sync_vault(b, vault_id)
    assert sites(b, work.hex) == ["intranet"]
    assert sites(b) == ["personal-site"]

    put_entry(b, work.hex, "from-b")
    sync_vault(b, work.hex)
    device("a")
    sync_vault(a, work.hex)
    assert sites(a, work.hex) == ["from-b", "intranet"]
    assert sites(a) == ["personal-site"]


def test_entries_stay_in_their_own_vault_across_devices(server, device,
                                                        two_devices):
    a, b = two_devices
    x, y = a.create_vault("X"), a.create_vault("Y")
    put_entry(a, x.hex, "only-x")
    put_entry(a, y.hex, "only-y")
    put_entry(a, a.personal_id, "only-personal")
    sync_all(a)
    device("b")
    sync_all(b)
    assert sites(b, x.hex) == ["only-x"]
    assert sites(b, y.hex) == ["only-y"]
    assert sites(b) == ["only-personal"]
    put_entry(b, x.hex, "x-from-b")
    sync_vault(b, x.hex)
    device("a")
    sync_all(a)
    assert sites(a, x.hex) == ["only-x", "x-from-b"]
    assert sites(a, y.hex) == ["only-y"]
    assert sites(a) == ["only-personal"]


def test_reconcile_reports_what_it_did_once(server, device, two_devices):
    a, b = two_devices
    a.create_vault("Work")
    first = reconcile(a)
    assert first.uploaded == ["Work"] and not first.added and bool(first)
    again = reconcile(a)
    assert not again and not again.uploaded and not again.added
    assert not (again.gone or again.renamed or again.server_too_old)

    device("b")
    got = reconcile(b)
    assert got.added == ["Work"] and not got.uploaded and bool(got)
    assert not reconcile(b)


def test_sign_in_on_a_new_device_brings_every_vault(server, device, alice):
    x, y = alice.create_vault("Xray"), alice.create_vault("Yankee")
    put_entry(alice, x.hex, "x1")
    put_entry(alice, x.hex, "x2")
    put_entry(alice, y.hex, "y1")
    put_entry(alice, alice.personal_id, "p1")
    sync_all(alice)

    device("b")
    other, _ = account_sync.sign_in(server.url, "", "alice", PW, alice.kit)
    assert other.vault_ids() == [other.personal_id, x.hex, y.hex]
    assert [other.vault_file(v).name for v in other.vault_ids()] == [
        "Personal", "Xray", "Yankee"]
    assert sites(other, x.hex) == ["x1", "x2"]
    assert sites(other, y.hex) == ["y1"]
    assert sites(other) == ["p1"]
    # signed in with everything agreed: nothing more to report or merge
    assert not reconcile(other)
    unlocked = accounts.unlock("alice", PW)
    assert sites(unlocked, x.hex) == ["x1", "x2"]


def test_a_rename_on_a_reaches_b(server, device, two_devices):
    a, b = two_devices
    work = a.create_vault("Work")
    sync_all(a)
    device("b")
    sync_all(b)

    device("a")
    a.rename_vault(work.hex, "Office é家")
    assert a.vault_record(work.hex)["rename_pending"] is True
    assert not reconcile(a).renamed                  # told to the server
    assert a.vault_record(work.hex)["rename_pending"] is False

    device("b")
    changes = reconcile(b)
    assert changes.renamed == [("Work", "Office é家")]
    assert b.vault_file(work.hex).name == "Office é家"
    assert accounts.unlock("alice", PW).vault_file(work.hex).name == \
        "Office é家"
    assert not reconcile(b)                          # and only once


def test_the_server_never_holds_a_name_entry_or_vault_key(server, device,
                                                          alice):
    work = alice.create_vault("Visible-Name-Marker")
    alt = alice.create_vault("Faília 家")
    put_entry(alice, work.hex, "entry-marker-site", "entry-marker-password")
    put_entry(alice, alt.hex, "other-marker-site")
    sync_all(alice)
    alice.rename_vault(work.hex, "Renamed-Name-Marker")
    reconcile(alice)
    everything = store_bytes(server)
    assert len(everything) > 0
    for vault_id in (work.hex, alt.hex):
        key = alice.vault_file(vault_id)._key
        assert key not in everything
        assert key.hex().encode() not in everything
        assert account_crypto._b64(key).encode() not in everything
    for needle in ("Visible-Name-Marker", "Renamed-Name-Marker",
                   "Faília 家", "entry-marker-site",
                   "entry-marker-password", "other-marker-site"):
        assert needle.encode("utf-8") not in everything, needle


def test_delete_on_a_is_seen_by_b_which_keeps_its_vault(server, device,
                                                        two_devices):
    a, b = two_devices
    work = a.create_vault("Work")
    put_entry(a, work.hex, "precious")
    sync_all(a)
    device("b")
    sync_all(b)
    put_entry(b, work.hex, "b-only-entry")             # never synced

    device("a")
    account_sync.delete_vault(a, work.hex)
    assert a.vault_ids() == [a.personal_id]
    assert not os.path.exists(work.path)
    assert not os.path.exists(os.path.join(server.accounts.vaults.root, work.hex))
    graveyard = glob.glob(os.path.join(server.store.root, "_v2", "deleted",
                                       work.hex + "-*"))
    assert len(graveyard) == 1

    device("b")
    changes = reconcile(b)
    assert changes.gone == ["Work"] and bool(changes)
    assert b.vault_ids() == [b.personal_id, work.hex]
    assert sites(b, work.hex) == ["b-only-entry", "precious"]
    assert b.vault_record(work.hex)["gone_from_server"] is True
    assert syncable(b) == [b.personal_id]
    assert not reconcile(b)
    assert syncable(b) == [b.personal_id]
    # and it is still kept after a restart of the app
    assert accounts.unlock("alice", PW).vault_record(work.hex)[
        "gone_from_server"] is True


def test_a_vault_put_back_goes_up_again_with_its_entries(server, device,
                                                         two_devices):
    a, b = two_devices
    work = a.create_vault("Work")
    put_entry(a, work.hex, "precious")
    sync_all(a)
    device("b")
    sync_all(b)
    put_entry(b, work.hex, "b-entry")
    device("a")
    account_sync.delete_vault(a, work.hex)

    device("b")
    assert reconcile(b).gone == ["Work"]
    account_sync.put_vault_back(b, work.hex)
    assert not b.vault_record(work.hex)["gone_from_server"]
    assert not b.vault_record(work.hex)["on_server"]
    assert not os.path.exists(b.vault_file(work.hex).base_path)
    changes = reconcile(b)
    assert changes.uploaded == ["Work"] and not changes.gone
    assert work.hex in syncable(b)
    sync_vault(b, work.hex)

    device("a")
    got = reconcile(a)
    assert got.added == ["Work"]
    sync_vault(a, work.hex)
    assert sites(a, work.hex) == ["b-entry", "precious"]


def test_a_vault_is_not_deleted_when_the_server_cannot_be_reached(server, device,
                                                                  alice):
    work = alice.create_vault("Work")
    put_entry(alice, work.hex, "keep-me")
    sync_all(alice)
    server.shutdown()
    server.server_close()
    with pytest.raises(SyncError):
        account_sync.delete_vault(alice, work.hex)
    assert alice.vault_ids() == [alice.personal_id, work.hex]
    assert sites(alice, work.hex) == ["keep-me"]
    assert accounts.unlock("alice", PW).vault_ids() == [alice.personal_id,
                                                         work.hex]


def test_a_vault_is_not_deleted_when_the_server_address_is_dead(server, device,
                                                                alice):
    work = alice.create_vault("Work")
    sync_all(alice)
    alice.info["server"] = {"url": "http://127.0.0.1:9", "ca_file": ""}
    with pytest.raises(SyncError):
        account_sync.delete_vault(alice, work.hex)
    assert work.hex in alice.vault_ids()
    assert os.path.exists(work.path)


def test_a_vault_is_not_deleted_when_the_server_refuses_the_delete(
        server, device, alice, monkeypatch):
    """The login works, the delete call itself fails."""
    work = alice.create_vault("Work")
    put_entry(alice, work.hex, "keep-me")
    sync_all(alice)

    def refuse(self, vault_id):
        raise SyncError("The server is having a bad day.")
    monkeypatch.setattr(account_sync.AccountServer, "delete_vault", refuse)
    with pytest.raises(SyncError, match="bad day"):
        account_sync.delete_vault(alice, work.hex)
    assert alice.vault_ids() == [alice.personal_id, work.hex]
    assert sites(alice, work.hex) == ["keep-me"]
    assert os.path.isdir(os.path.join(server.accounts.vaults.root, work.hex))


def test_a_vault_never_on_a_server_is_deleted_without_asking_it(server, device,
                                                                alice):
    work = alice.create_vault("Local only")
    server.shutdown()
    server.server_close()
    account_sync.delete_vault(alice, work.hex)           # nothing to tell
    assert alice.vault_ids() == [alice.personal_id]


def _health_without_features(self):
    return {"ok": True, "service": "passman-sync", "api": [1, 2]}


@pytest.mark.parametrize("how", ["no_features_in_health", "has_vaults_false"])
def test_a_server_without_vaults_keeps_extra_vaults_here(server, device, alice,
                                                         monkeypatch, how):
    if how == "no_features_in_health":
        monkeypatch.setattr(account_sync.AccountServer, "health",
                            _health_without_features)
    else:
        monkeypatch.setattr(account_sync.AccountServer, "has_vaults",
                            lambda self: False)
    work = alice.create_vault("Work")
    put_entry(alice, work.hex, "local-entry")
    put_entry(alice, alice.personal_id, "personal-entry")
    changes = reconcile(alice)
    assert changes.server_too_old is True and bool(changes)
    assert not changes.uploaded
    assert syncable(alice) == [alice.personal_id]
    assert not alice.vault_record(work.hex).get("on_server")
    api = account_sync.logged_in(alice)
    try:
        assert [v["id"] for v in api.me()["vaults"]] == [alice.personal_id]
    finally:
        api.logout()
    assert not os.path.exists(os.path.join(server.accounts.vaults.root, work.hex))
    # the personal vault still syncs
    assert sites(alice) == ["personal-entry"]
    sync_vault(alice, alice.personal_id)
    stored = server.accounts.vaults.read(alice.personal_id).decode()
    assert alice.decrypt(stored)["accounts"][0]["site"] == "personal-entry"
    assert sites(alice, work.hex) == ["local-entry"]


def test_without_extra_vaults_an_old_server_is_not_a_problem(server, device,
                                                             alice, monkeypatch):
    monkeypatch.setattr(account_sync.AccountServer, "has_vaults",
                        lambda self: False)
    changes = reconcile(alice)
    assert not changes and not changes.server_too_old


def test_two_accounts_on_one_server_never_see_each_others_vaults(server, device,
                                                                 alice):
    work = alice.create_vault("Work")
    put_entry(alice, work.hex, "alice-secret-entry")
    sync_all(alice)

    bob = new_account("bob", "bobs own password").save()
    assert account_sync.connect(bob, server.url, "", TOKEN) == "created"
    assert not reconcile(bob)
    assert bob.vault_ids() == [bob.personal_id]
    session = account_sync.logged_in(bob)
    try:
        with pytest.raises(SyncError):
            session.get_vault(work.hex)
        with pytest.raises(SyncError):
            session.rename_vault(work.hex, "x")
        with pytest.raises(SyncError):
            session.delete_vault(work.hex)
    finally:
        session.logout()
    # still there for alice
    assert reconcile(alice) is not None
    assert work.hex in alice.vault_ids()
    assert os.path.isdir(os.path.join(server.accounts.vaults.root, work.hex))


def test_conflicts_are_per_vault(server, device, two_devices):
    a, b = two_devices
    work = a.create_vault("Work")
    put_entry(a, work.hex, "shared-site", "v1")
    put_entry(a, a.personal_id, "personal-site", "v1")
    sync_all(a)
    device("b")
    sync_all(b)

    def edit(account, vault_id, password):
        file = account.vault_file(vault_id)
        data = file.load()
        data["accounts"][0]["password"] = password
        file.save(data)

    edit(b, work.hex, "from-b")
    sync_vault(b, work.hex)
    device("a")
    edit(a, work.hex, "from-a")

    in_work = account_sync.AccountSync(a, None, work.hex)
    try:
        result = in_work.prepare(a.vault_file(work.hex).load())
        assert len(result.conflicts) == 1
    finally:
        in_work.close()
    in_personal = account_sync.AccountSync(a, None)
    try:
        result = in_personal.prepare(a.load_vault())
        assert result.conflicts == []
        assert not in_personal.has_work()
    finally:
        in_personal.close()

    # resolving it in X gives B's version there, and leaves the others alone
    session = account_sync.AccountSync(a, None, work.hex)
    try:
        local = a.vault_file(work.hex).load()
        result = session.prepare(local)
        merged = session.commit(local, {result.conflicts[0].id: sync.KEEP_REMOTE})
    finally:
        session.close()
    assert merged["accounts"][0]["password"] == "from-b"
    assert a.load_vault()["accounts"][0]["password"] == "v1"


def test_an_account_sync_works_on_the_vault_it_was_given(server, device, alice):
    work = alice.create_vault("Work")
    put_entry(alice, work.hex, "in-work")
    put_entry(alice, alice.personal_id, "in-personal")
    reconcile(alice)
    session = account_sync.AccountSync(alice, None, work.hex)
    assert session.file.hex == work.hex
    session.close()
    sync_vault(alice, work.hex)
    stored_work = server.accounts.vaults.read(work.hex).decode()
    assert work.decrypt(stored_work)["accounts"][0]["site"] == "in-work"
    # the personal vault on the server is still empty: it was not synced
    api = account_sync.logged_in(alice)
    try:
        assert api.get_vault(alice.personal_id)["blob"] is None
    finally:
        api.logout()
    # the work blob is not a personal blob
    with pytest.raises(CryptoError):
        alice.decrypt(stored_work)


def test_changing_the_server_clears_what_the_old_one_knew(server, device, alice,
                                                          tmp_path):
    work = alice.create_vault("Work")
    gone = alice.create_vault("Gone")
    put_entry(alice, work.hex, "keep-this")
    sync_all(alice)
    alice.rename_vault(work.hex, "Office")
    alice.mark_vault(gone.hex, gone_from_server=True)
    wrapped = {v: alice.vault_record(v)["wrapped_key"] for v in (work.hex, gone.hex)}
    assert alice.vault_record(work.hex)["on_server"]
    assert alice.vault_record(work.hex)["rename_pending"]

    # the same address again changes nothing
    alice.set_server(server.url + "/", "")
    assert alice.vault_record(work.hex)["on_server"]
    assert alice.vault_record(work.hex)["rename_pending"]
    assert alice.vault_record(gone.hex)["gone_from_server"]

    second, thread = start_server(tmp_path / "second-store")
    try:
        alice.set_server(second.url, "")
        for vault_id, name in ((work.hex, "Office"), (gone.hex, "Gone")):
            record = alice.vault_record(vault_id)
            for flag in ("on_server", "gone_from_server", "rename_pending"):
                assert flag not in record
            assert record["name"] == name
            assert record["wrapped_key"] == wrapped[vault_id]
        # persisted too
        assert "on_server" not in accounts.unlock("alice", PW).vault_record(
            work.hex)
        assert account_sync.connect(alice, second.url, "", TOKEN) == "created"
        changes = reconcile(alice)
        assert sorted(changes.uploaded) == ["Gone", "Office"]
        assert alice.vault_record(work.hex)["on_server"] is True
        assert work.hex in syncable(alice)
        sync_vault(alice, work.hex)
        assert os.path.exists(os.path.join(second.accounts.vaults.root, work.hex))
        assert sites(alice, work.hex) == ["keep-this"]
    finally:
        stop_server(second, thread)


def test_forgetting_the_server_clears_the_flags_too(server, device, alice):
    work = alice.create_vault("Work")
    reconcile(alice)
    assert alice.vault_record(work.hex)["on_server"]
    alice.set_server(None)
    assert "on_server" not in alice.vault_record(work.hex)
    assert alice.vault_file(work.hex).name == "Work"
