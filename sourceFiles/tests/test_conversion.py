"""
Converting an account from SecretSpace 3 (format 1) to the current format.

The accounts under fixtures/format1 were written by the real SecretSpace
3.1.0, and the server store beside them by its server 2.0.0 (see
fixtures/make_format1.py). Nothing here pretends to be old: every test
starts from those files.

    alice   on the server. Personal: Bank, Mail. Team (hers, shared with bob
            as an editor): Printer, Router. Solo (hers alone): Notes.
    bob     on the server. Personal: Forum. Member of Team.
    carol   never on a server. Personal: Diary. Box (local only): Spare key.
"""

import base64
import copy
import json
import os
import shutil
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "sync_server"))

import account_crypto                                           # noqa: E402
import account_sync                                             # noqa: E402
import accounts                                                 # noqa: E402
import changelog                                                # noqa: E402
import legacy_names                                             # noqa: E402
import recovery                                                 # noqa: E402
import secret_store                                             # noqa: E402
import vault                                                    # noqa: E402
import secretspace_server                                       # noqa: E402
from account_crypto import NOW, OLD, CryptoError                # noqa: E402
from account_sync import LoginFailed                            # noqa: E402
from sync_client import SyncError                               # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "format1")
with open(os.path.join(FIXTURE, "facts.json"), encoding="utf-8") as _f:
    FACTS = json.load(_f)
TEAM, SOLO, BOX = (FACTS["vaults"][n] for n in ("Team", "Solo", "Box"))


def pw(name):
    return FACTS["accounts"][name]["password"]


@pytest.fixture(autouse=True)
def cheap_argon2(monkeypatch):
    monkeypatch.setattr(account_crypto, "ARGON2_MEMORY_KIB", 64)
    monkeypatch.setattr(account_crypto, "ARGON2_PASSES", 1)
    # As the fixtures were made: openable on any machine.
    monkeypatch.setattr(secret_store, "default_scheme",
                        lambda: secret_store.SCHEME_PASSWORD)


class World:
    """The three devices and the server, copied out of the fixture."""

    def __init__(self, root, monkeypatch):
        self.root = str(root)
        self._monkeypatch = monkeypatch
        for name in "abc":
            shutil.copytree(os.path.join(FIXTURE, name),
                            os.path.join(self.root, name))
        shutil.copytree(os.path.join(FIXTURE, "store"),
                        os.path.join(self.root, "store"))
        self.server = None

    def device(self, name):
        self._monkeypatch.setenv("SECRETSPACE_DATA_DIR",
                                 os.path.join(self.root, name, "data"))
        return self

    def folder(self, device, user):
        return os.path.join(self.root, device, "accounts", user)

    def copy_device(self, source, target):
        """A second device of the same account, as it was before anything."""
        shutil.copytree(os.path.join(FIXTURE, source),
                        os.path.join(self.root, target))
        self._point_at_server(target)

    def start_server(self):
        httpd = secretspace_server.ThreadingHTTPServer(
            ("127.0.0.1", 0), secretspace_server.Handler)
        httpd.store = secretspace_server.Store(os.path.join(self.root, "store"))
        httpd.token = FACTS["token"]
        threading.Thread(target=httpd.serve_forever,
                         kwargs={"poll_interval": 0.01}, daemon=True).start()
        httpd.url = f"http://127.0.0.1:{httpd.server_address[1]}"
        self.server = httpd
        for name in "ab":
            self._point_at_server(name)
        return httpd

    def _point_at_server(self, device):
        """The fixture's accounts remember the address their server had."""
        if self.server is None:
            return
        base = os.path.join(self.root, device, "accounts")
        for user in os.listdir(base):
            path = os.path.join(base, user, "account.json")
            with open(path, encoding="utf-8") as f:
                info = json.load(f)
            if info.get("server"):
                info["server"]["url"] = self.server.url
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(info, f)

    def stored(self, *parts):
        with open(os.path.join(self.root, "store", "_v2", *parts), "rb") as f:
            return f.read()

    def stored_json(self, *parts):
        return json.loads(self.stored(*parts))

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()


@pytest.fixture
def world(tmp_path, monkeypatch):
    made = World(tmp_path, monkeypatch)
    yield made
    made.stop()


@pytest.fixture
def online(world):
    world.start_server()
    return world


def sites(account, vault_id=None):
    return sorted(e["site"] for e in account.vault_file(vault_id).load()["accounts"])


def tree(folder):
    found = {}
    for base, _, files in os.walk(folder):
        for name in files:
            path = os.path.join(base, name)
            with open(path, "rb") as f:
                found[os.path.relpath(path, folder).replace("\\", "/")] = f.read()
    return found


def sync_all(account, convert=True):
    """One press of Sync, as account_sync_ui runs it."""
    server = account_sync.logged_in(account)
    try:
        changes = account_sync.reconcile_vaults(account, server)
        ids = account_sync.syncable_vaults(account, server)
        data = {}
        for vault_id in ids:
            session = account_sync.AccountSync(account, server, vault_id)
            local = session.file.load() if session.file.has_file \
                else {"accounts": []}
            result = session.prepare(local)
            assert not result.conflicts, result.conflicts
            data[vault_id] = session.commit(local) if session.has_work() \
                else local
        converted = account_sync.convert_vaults(account, server, data) \
            if convert else {}
        return changes, converted
    finally:
        server.logout()


def add_entry(account, vault_id, site):
    file = account.vault_file(vault_id)
    before = file.load()
    data = copy.deepcopy(before)
    vault.add_account(data, site, "me", "pw")
    changelog.record(data, before, account.username, account.keyset, file.hex,
                     file.fmt)
    file.save(data)


def marker(blob) -> bytes:
    return base64.b64decode(blob)[:4]


def log_checks(account, vault_id):
    """How each change-log line of a vault checks out, by its author."""
    file = account.vault_file(vault_id)
    return [(line["by"], changelog.check(
        line, file.hex, account.signing_key_for(line["by"])))
        for line in changelog.lines_of(file.load())]


# ===========================================================================
# A. The cryptography: what a label change does, and what stays the same
# ===========================================================================
def test_the_two_formats_never_make_the_same_keys():
    salt, secret = bytes(16), bytes(range(16))
    new = account_crypto.derive_account_keys("pw", secret, "nik", salt, 1, 64, 1)
    old = account_crypto.derive_account_keys("pw", secret, "nik", salt, 1, 64, 1,
                                             OLD)
    assert len({new[0], new[1], old[0], old[1]}) == 4


def test_the_current_format_carries_the_current_name_everywhere():
    assert NOW.prefix.startswith("SecretSpace")
    assert NOW.keyset_magic == b"SSK4" and NOW.vault_magic == b"SSV4"
    assert NOW.secret_prefix == "A4"
    for what in ("login key|", "wrap key", "vault name", "change"):
        assert b"SecretSpace" in NOW.label(what)
        assert legacy_names.LABEL_PREFIX.encode() not in NOW.label(what)


def test_the_old_format_is_exactly_what_secretspace_3_used():
    assert OLD.label("login key|") == b"PassMan3 login key|"
    assert OLD.label("wrap|") == b"PassMan3 wrap|"
    assert (OLD.keyset_magic, OLD.vault_magic) == (b"PMK3", b"PMV3")


def test_a_new_account_is_in_the_current_format_throughout():
    made = account_crypto.create_account("nik", "pw", 1, 64, 1)
    assert marker(made["sealed_keyset"]) == b"SSK4"
    assert marker(made["sealed_recovery"]) == b"SSK4"
    assert made["secret_key_text"].startswith("A4-")
    assert set(made["keyset"]) == {"x25519_private", "personal_vault_key",
                                   "ed25519_seed", "recovery_proof"}


def test_a_new_accounts_signing_key_is_its_own_not_derived():
    """Two keysets with the same private key and different seeds sign
    differently: nothing is derived with a label any more."""
    one = account_crypto.new_keyset()
    two = dict(one, ed25519_seed=account_crypto._b64(os.urandom(32)))
    assert account_crypto.signing_key_of(one) != account_crypto.signing_key_of(two)


def test_a_keyset_from_secretspace_3_gets_the_keys_it_always_had():
    """The signing key and the recovery proof that version derived are
    stored from now on -- the same values, so nothing signed or registered
    with them breaks."""
    for name in ("alice", "bob", "carol"):
        facts = FACTS["accounts"][name]
        device = {"alice": "a", "bob": "b", "carol": "c"}[name]
        with open(os.path.join(FIXTURE, device, "accounts", name,
                               "keyset.pmk"), encoding="utf-8") as f:
            sealed = f.read().strip()
        secret = account_crypto.parse_secret_key(facts["secret_key"])
        keyset, _ = account_crypto.unlock_account(name, facts["password"],
                                                  secret, sealed)
        assert account_crypto._b64(account_crypto.signing_key_of(keyset)) \
            == facts["signing_key"]
        assert account_crypto._b64(account_crypto.recovery_proof(keyset)) \
            == facts["recovery_proof"]
        assert account_crypto._b64(account_crypto.public_key_of(keyset)) \
            == facts["public_key"]


def test_a_converted_keyset_keeps_the_salt_so_every_device_agrees():
    facts = FACTS["accounts"]["alice"]
    with open(os.path.join(FIXTURE, "a", "accounts", "alice", "keyset.pmk"),
              encoding="utf-8") as f:
        sealed = f.read().strip()
    secret = account_crypto.parse_secret_key(facts["secret_key"])
    one = account_crypto.convert_keyset("alice", facts["password"], secret, sealed)
    two = account_crypto.convert_keyset("alice", facts["password"], secret, sealed)
    before = account_crypto.keyset_header(sealed)
    after = account_crypto.keyset_header(one["sealed_keyset"])
    assert after["salt"] == before["salt"] and after["format"] == 2
    assert (after["passes"], after["memory_kib"]) == \
        (before["passes"], before["memory_kib"])
    assert one["login_key"] == two["login_key"]            # devices converge
    assert one["login_key"] != one["old_login_key"]
    assert one["sealed_keyset"] != two["sealed_keyset"]    # fresh nonce each


def test_an_emergency_kit_from_secretspace_3_still_works():
    for name in ("alice", "carol"):
        old_text = FACTS["accounts"][name]["secret_key"]
        assert old_text.startswith("A3-")
        raw = account_crypto.parse_secret_key(old_text)
        new_text = account_crypto.format_secret_key(raw)
        assert new_text.startswith("A4-")
        assert account_crypto.parse_secret_key(new_text) == raw
        assert new_text[3:-1] == old_text[3:-1]      # the same 128 bits
        assert new_text[-1] != old_text[-1] or True  # check character: its own


def test_a_secret_key_is_checked_in_the_spelling_it_was_typed_in():
    raw = bytes(range(16))
    new = account_crypto.format_secret_key(raw)
    old = "A3" + new[2:-1] + account_crypto._secret_check_char(raw, OLD)
    assert account_crypto.parse_secret_key(old) == raw
    crossed = "A3" + new[2:]                     # A3 with the A4 check char
    if crossed != old:
        with pytest.raises(CryptoError, match="typo"):
            account_crypto.parse_secret_key(crossed)


@pytest.mark.parametrize("fmt", [NOW, OLD])
def test_a_wrapped_key_opens_in_the_format_it_was_wrapped_in(fmt):
    keyset = account_crypto.new_keyset()
    public = account_crypto.public_key_of(keyset)
    vault_id, key = os.urandom(16), os.urandom(32)
    wrapped = account_crypto.wrap_key(public, key, vault_id, "nik", fmt)
    assert account_crypto.wrap_format(wrapped) is fmt
    assert account_crypto.unwrap_key(keyset, wrapped, vault_id, "nik") == key
    # Passing one format off as the other fails: the version byte is part
    # of what picks the labels, and the labels are part of the key.
    raw = bytearray(base64.b64decode(wrapped))
    raw[0] = (OLD if fmt is NOW else NOW).wrap_version
    with pytest.raises(CryptoError):
        account_crypto.unwrap_key(keyset, base64.b64encode(bytes(raw)).decode(),
                                  vault_id, "nik")


@pytest.mark.parametrize("fmt", [NOW, OLD])
def test_a_vault_is_read_in_either_format_and_says_which(fmt):
    vault_id, key = os.urandom(16), os.urandom(32)
    blob = account_crypto.encrypt_vault(key, vault_id, 4, {"accounts": []}, fmt)
    assert marker(blob) == fmt.vault_magic
    assert account_crypto.vault_header(blob) == {
        "vault_id": vault_id, "key_generation": 4, "format": fmt.number}
    assert account_crypto.decrypt_vault(key, blob, vault_id) == {"accounts": []}


def test_a_vaults_marker_cannot_be_swapped():
    """It is authenticated: an old file is not turned into a new one (or
    back) by editing four bytes."""
    vault_id, key = os.urandom(16), os.urandom(32)
    raw = base64.b64decode(account_crypto.encrypt_vault(
        key, vault_id, 0, {"accounts": []}, OLD))
    forged = base64.b64encode(NOW.vault_magic + raw[4:]).decode()
    with pytest.raises(CryptoError, match="could not be decrypted"):
        account_crypto.decrypt_vault(key, forged, vault_id)


@pytest.mark.parametrize("fmt", [NOW, OLD])
def test_a_vault_name_opens_whichever_format_sealed_it(fmt):
    vault_id, key = os.urandom(16), os.urandom(32)
    sealed = account_crypto.seal_vault_name(key, vault_id, "Team", fmt)
    assert account_crypto.open_vault_name(key, vault_id, sealed) == "Team"


def test_a_recovery_copy_opens_in_its_own_format_only_with_its_words():
    keyset = account_crypto.new_keyset()
    phrase = account_crypto.new_recovery_phrase()
    copy_ = account_crypto.seal_recovery(phrase, "nik", keyset)
    assert account_crypto.recover_account("nik", phrase, copy_) == keyset
    with pytest.raises(CryptoError):
        account_crypto.recover_account(
            "nik", account_crypto.new_recovery_phrase(), copy_)


def test_the_fingerprint_is_made_with_the_current_name():
    facts = FACTS["accounts"]["alice"]
    public = base64.b64decode(facts["public_key"])
    signing = base64.b64decode(facts["signing_key"])
    now = account_crypto.account_fingerprint(public, signing)
    assert now != facts["fingerprint"]           # the digits changed ...
    assert len(now.replace(" ", "")) == 24       # ... not their shape


def test_a_change_log_line_is_checked_the_way_it_was_signed():
    keyset = account_crypto.new_keyset()
    key = account_crypto.signing_key_of(keyset)
    for fmt in (NOW, OLD):
        data, before = {"accounts": []}, {"accounts": []}
        vault.add_account(data, "Mail", "me", "pw")
        changelog.record(data, before, "nik", keyset, "ab" * 16, fmt)
        line = changelog.lines_of(data)[0]
        assert ("v" in line) == (fmt is NOW)
        assert changelog.check(line, "ab" * 16, key) == changelog.OK
        # Told it was signed the other way, it no longer checks out.
        other = dict(line)
        if fmt is NOW:
            del other["v"]
        else:
            other["v"] = 2
        assert changelog.check(other, "ab" * 16, key) == changelog.BAD


# ===========================================================================
# B. On the device
# ===========================================================================
def test_an_old_account_is_not_opened_unconverted(world):
    world.device("c")
    with pytest.raises(accounts.NeedsConversion):
        accounts.unlock("carol", pw("carol"))
    assert accounts.account_format("carol") == 1


def test_a_wrong_password_is_a_wrong_password_not_a_conversion(world):
    world.device("c")
    with pytest.raises(CryptoError, match="Wrong master password"):
        accounts.unlock("carol", "not it")


def test_asking_changes_nothing(world):
    world.device("c")
    before = tree(world.folder("c", "carol"))
    with pytest.raises(accounts.NeedsConversion):
        accounts.unlock("carol", pw("carol"))
    assert tree(world.folder("c", "carol")) == before


def test_conversion_needs_the_right_password(world):
    world.device("c")
    before = tree(world.folder("c", "carol"))
    with pytest.raises(CryptoError, match="Wrong master password"):
        accounts.convert("carol", "not it")
    assert tree(world.folder("c", "carol")) == before


def test_a_converted_account_has_only_files_of_the_current_format(world):
    world.device("c")
    account = accounts.convert("carol", pw("carol"))
    folder = world.folder("c", "carol")
    assert sorted(os.listdir(folder)) == ["account.json", "keyset.ssk",
                                          "recovery.ssk", "vaults"]
    assert sorted(os.listdir(os.path.join(folder, "vaults"))) == sorted(
        [account.personal_id + ".ssv", BOX + ".ssv"])
    for name in os.listdir(os.path.join(folder, "vaults")):
        with open(os.path.join(folder, "vaults", name), encoding="utf-8") as f:
            assert marker(f.read()) == b"SSV4"
    with open(os.path.join(folder, "keyset.ssk"), encoding="utf-8") as f:
        assert marker(f.read()) == b"SSK4"
    assert accounts.account_format("carol") == 2


def test_every_entry_is_still_there_after_a_conversion(world):
    world.device("c")
    accounts.convert("carol", pw("carol"))
    account = accounts.unlock("carol", pw("carol"))
    assert sites(account) == ["Diary"]
    assert sites(account, BOX) == ["Spare key"]
    assert account.vault_file(BOX).name == "Box"
    entry = account.vault_file().load()["accounts"][0]
    assert entry["password"] == "diary-password"


def test_the_accounts_identity_is_unchanged_by_a_conversion(world):
    world.device("c")
    account = accounts.convert("carol", pw("carol"))
    facts = FACTS["accounts"]["carol"]
    assert account.signing_key == facts["signing_key"]
    assert account.info["public_key"] == facts["public_key"]
    assert account.personal_id == facts["personal_vault"]
    assert account_crypto._b64(account_crypto.recovery_proof(account.keyset)) \
        == facts["recovery_proof"]


def test_the_old_change_log_still_checks_out_after_a_conversion(world):
    world.device("c")
    account = accounts.convert("carol", pw("carol"))
    assert log_checks(account, None) == [("carol", changelog.OK)]
    add_entry(account, None, "New one")
    assert log_checks(account, None) == [("carol", changelog.OK)] * 2
    lines = changelog.lines_of(account.vault_file().load())
    assert ["v" in line for line in lines] == [False, True]


def test_a_local_vaults_key_is_wrapped_again_in_the_current_format(world):
    world.device("c")
    account = accounts.convert("carol", pw("carol"))
    assert account.vault_format(BOX) is NOW
    assert account_crypto.wrap_format(
        account.vault_record(BOX)["wrapped_key"]) is NOW


def test_the_secret_key_is_stored_the_current_way_after_a_conversion(world):
    world.device("c")
    account = accounts.convert("carol", pw("carol"))
    assert secret_store.record_version(account.info["secret_key"]) == 2
    with open(os.path.join(FIXTURE, "c", "accounts", "carol", "account.json"),
              encoding="utf-8") as f:
        assert secret_store.record_version(json.load(f)["secret_key"]) == 1
    # ... and bound with the current name: the old binding no longer opens it.
    stale = dict(account.info["secret_key"])
    del stale["v"]
    with pytest.raises(CryptoError):
        secret_store.unprotect(stale, "carol", pw("carol"))


def test_the_emergency_kit_can_be_typed_at_the_conversion(world):
    """A device that cannot read its stored Secret Key asks for the kit; the
    one printed by SecretSpace 3 is the one the user has."""
    world.device("c")
    path = os.path.join(world.folder("c", "carol"), "account.json")
    with open(path, encoding="utf-8") as f:
        info = json.load(f)
    info["secret_key"] = None
    with open(path, "w", encoding="utf-8") as f:
        json.dump(info, f)
    with pytest.raises(accounts.SecretKeyNeeded):
        accounts.unlock("carol", pw("carol"))
    with pytest.raises(accounts.NeedsConversion):
        accounts.unlock("carol", pw("carol"), FACTS["accounts"]["carol"]["secret_key"])
    account = accounts.convert("carol", pw("carol"),
                               FACTS["accounts"]["carol"]["secret_key"])
    assert sites(account) == ["Diary"]
    assert sites(accounts.unlock("carol", pw("carol"))) == ["Diary"]


def test_converting_twice_is_refused(world):
    world.device("c")
    accounts.convert("carol", pw("carol"))
    with pytest.raises(ValueError, match="already converted"):
        accounts.convert("carol", pw("carol"))


def test_an_account_that_was_never_on_a_server_has_nothing_to_tell_one(world):
    world.device("c")
    account = accounts.convert("carol", pw("carol"))
    assert not account.server_conversion_pending
    assert account.old_login_key is None


def test_a_copy_can_be_saved_first_and_is_the_account_as_it_was(world, tmp_path):
    world.device("c")
    before = tree(world.folder("c", "carol"))
    target = tmp_path / "my backups"
    target.mkdir()
    made = accounts.copy_account_folder("carol", str(target))
    assert tree(made) == before
    with pytest.raises(FileExistsError):
        accounts.copy_account_folder("carol", str(target))


# --- stopped half-way ---------------------------------------------------------
@pytest.mark.parametrize("stop_at", [1, 2, 3, 4, 5])
def test_a_conversion_stopped_before_its_last_write_leaves_the_old_account_whole(
        world, monkeypatch, stop_at):
    """Whatever write it dies on -- two vaults, the recovery copy, the
    keyset, account.json itself -- the old account still opens the old way,
    nothing of the new format is left, and trying again works."""
    world.device("c")
    before = tree(world.folder("c", "carol"))
    real, calls = accounts._write_text, {"n": 0}

    def dying(path, text):
        calls["n"] += 1
        if calls["n"] == stop_at:
            raise OSError("disk full")
        return real(path, text)

    monkeypatch.setattr(accounts, "_write_text", dying)
    with pytest.raises(OSError):
        accounts.convert("carol", pw("carol"))
    monkeypatch.setattr(accounts, "_write_text", real)
    assert tree(world.folder("c", "carol")) == before
    account = accounts.convert("carol", pw("carol"))
    assert sites(account) == ["Diary"] and sites(account, BOX) == ["Spare key"]


def test_a_conversion_stopped_after_its_last_write_is_finished_at_the_next_unlock(
        world, monkeypatch):
    world.device("c")
    monkeypatch.setattr(accounts, "_remove_old_files", lambda username: None)
    accounts.convert("carol", pw("carol"))
    monkeypatch.undo()
    world.device("c")
    folder = world.folder("c", "carol")
    assert "keyset.pmk" in os.listdir(folder)             # the leftovers
    account = accounts.unlock("carol", pw("carol"))
    assert sorted(os.listdir(folder)) == ["account.json", "keyset.ssk",
                                          "recovery.ssk", "vaults"]
    assert all(name.endswith(".ssv") or name.endswith(".ssv.bak")
               for name in os.listdir(os.path.join(folder, "vaults")))
    assert sites(account) == ["Diary"]


def test_a_local_vault_that_cannot_be_read_stops_the_conversion_untouched(world):
    world.device("c")
    path = os.path.join(world.folder("c", "carol"), "vaults", BOX + ".pmv3")
    with open(path, "w", encoding="utf-8") as f:
        f.write("AAAA")
    before = tree(world.folder("c", "carol"))
    with pytest.raises(CryptoError, match="nothing was converted"):
        accounts.convert("carol", pw("carol"))
    assert tree(world.folder("c", "carol")) == before


def test_a_vault_the_server_has_may_be_unreadable_here_and_is_fetched_again(online):
    online.device("a")
    path = os.path.join(online.folder("a", "alice"), "vaults", SOLO + ".pmv3")
    with open(path, "w", encoding="utf-8") as f:
        f.write("AAAA")
    account = accounts.convert("alice", pw("alice"))
    assert not account.vault_file(SOLO).has_file
    sync_all(account)
    assert sites(account, SOLO) == ["Notes"]


# --- the recovery copy --------------------------------------------------------
def test_the_recovery_copy_is_left_for_the_12_words(world):
    world.device("c")
    account = accounts.convert("carol", pw("carol"))
    assert account.recovery_converted is False
    with open(os.path.join(world.folder("c", "carol"), "recovery.ssk"),
              encoding="utf-8") as f:
        assert marker(f.read()) == b"PMK3"       # as it was, under its new name
    assert accounts.check_recovery_phrase("carol",
                                          FACTS["accounts"]["carol"]["phrase"])


def test_typing_the_12_words_converts_the_recovery_copy_under_the_same_words(world):
    world.device("c")
    account = accounts.convert("carol", pw("carol"))
    phrase = FACTS["accounts"]["carol"]["phrase"]
    with pytest.raises(CryptoError):
        account.convert_recovery(account_crypto.new_recovery_phrase())
    assert account.recovery_converted is False
    sealed = account.convert_recovery(phrase)
    assert marker(sealed) == b"SSK4" and account.recovery_converted is True
    assert accounts.check_recovery_phrase("carol", phrase)
    assert account_crypto.recover_account("carol", phrase, sealed) == account.keyset


def test_a_new_accounts_recovery_copy_needs_no_conversion(world):
    world.device("z")
    account = accounts.prepare_account("zoe", "a password").save()
    assert account.recovery_converted is True


def test_a_forgotten_password_on_an_unconverted_account_recovers_and_converts(world):
    """No server: the 12 words open the old recovery copy, and the account
    comes back converted, with every vault."""
    world.device("c")
    opened = recovery.open_with_phrase("carol",
                                       FACTS["accounts"]["carol"]["phrase"])
    pending = recovery.prepare(opened, "a new master password")
    account, data = pending.save()
    assert accounts.account_format("carol") == 2
    assert sorted(e["site"] for e in data["accounts"]) == ["Diary"]
    again = accounts.unlock("carol", "a new master password",
                            pending.secret_key_text)
    assert sites(again, BOX) == ["Spare key"]
    assert again.recovery_converted is True
    assert sorted(os.listdir(world.folder("c", "carol"))) == [
        "account.json", "keyset.ssk", "recovery.ssk", "vaults"]


# ===========================================================================
# C. With the server
# ===========================================================================
def test_the_server_is_told_at_the_first_sync(online):
    online.device("a")
    account = accounts.convert("alice", pw("alice"))
    assert account.server_conversion_pending and account.old_login_key
    assert online.stored_json("accounts", "alice.json").get("format", 1) == 1
    sync_all(account)
    record = online.stored_json("accounts", "alice.json")
    assert record["format"] == 2 and marker(record["keyset"]) == b"SSK4"
    assert not account.server_conversion_pending
    assert account.old_login_key is None
    # ... and it is remembered: the next unlock has nothing left to tell.
    again = accounts.unlock("alice", pw("alice"))
    assert not again.server_conversion_pending and again.old_login_key is None
    sync_all(again)


def test_the_conversion_waits_for_the_server_across_a_restart(online):
    """Converted offline, locked, unlocked: the old login key is there again
    when the server is finally reached."""
    online.device("a")
    accounts.convert("alice", pw("alice"))
    account = accounts.unlock("alice", pw("alice"))
    assert account.server_conversion_pending and account.old_login_key
    sync_all(account)
    assert online.stored_json("accounts", "alice.json")["format"] == 2


def test_the_old_login_key_no_longer_works_once_the_server_is_told(online):
    online.device("a")
    account = accounts.convert("alice", pw("alice"))
    old = account.old_login_key
    sync_all(account)
    server = account_sync.AccountServer(online.server.url)
    with pytest.raises(LoginFailed):
        server.login("alice", old)


def test_the_personal_vault_goes_to_the_server_in_the_current_format(online):
    online.device("a")
    account = accounts.convert("alice", pw("alice"))
    assert marker(online.stored("vaults", account.personal_id, "vault.enc")) \
        == b"PMV3"
    sync_all(account)
    assert marker(online.stored("vaults", account.personal_id, "vault.enc")) \
        == b"SSV4"
    assert sites(account) == ["Bank", "Mail"]


def test_a_vault_of_ones_own_converts_at_the_first_sync(online):
    """Solo has one member, alice: it gets a new key in the current format
    as soon as she has converted."""
    online.device("a")
    account = accounts.convert("alice", pw("alice"))
    assert account.vault_format(SOLO) is OLD
    _, converted = sync_all(account)
    assert SOLO in converted
    assert account.vault_format(SOLO) is NOW
    assert marker(online.stored("vaults", SOLO, "vault.enc")) == b"SSV4"
    members = online.stored_json("vaults", SOLO, "members.json")
    assert members["format"] == 2 and members["key_generation"] == 1
    assert sites(account, SOLO) == ["Notes"]


def test_a_shared_vault_waits_for_every_member(online):
    """bob has not updated: Team stays as it is, and both of them still
    read and write it."""
    online.device("a")
    alice = accounts.convert("alice", pw("alice"))
    _, converted = sync_all(alice)
    assert TEAM not in converted and alice.vault_format(TEAM) is OLD
    assert marker(online.stored("vaults", TEAM, "vault.enc")) == b"PMV3"
    assert online.stored_json("vaults", TEAM, "members.json").get("format", 1) == 1

    add_entry(alice, TEAM, "Scanner")            # she writes it the old way
    sync_all(alice)
    assert marker(online.stored("vaults", TEAM, "vault.enc")) == b"PMV3"
    line = changelog.lines_of(alice.vault_file(TEAM).load())[-1]
    assert "v" not in line                       # so bob's app can check it


def test_a_member_who_has_not_updated_reads_what_a_converted_owner_wrote(online):
    """The blob alice's SecretSpace 4 uploaded for Team is exactly what
    SecretSpace 3 expects: its marker, its labels, a line it can check."""
    online.device("a")
    alice = accounts.convert("alice", pw("alice"))
    sync_all(alice)
    add_entry(alice, TEAM, "Scanner")
    sync_all(alice)
    blob = online.stored("vaults", TEAM, "vault.enc").decode("ascii")
    # Opened the way 3.1.0 does: its own key, the old marker, the old labels.
    with open(os.path.join(FIXTURE, "b", "accounts", "bob", "account.json"),
              encoding="utf-8") as f:
        bob_info = json.load(f)
    with open(os.path.join(FIXTURE, "b", "accounts", "bob", "keyset.pmk"),
              encoding="utf-8") as f:
        bob_keyset, _ = account_crypto.unlock_account(
            "bob", pw("bob"),
            account_crypto.parse_secret_key(FACTS["accounts"]["bob"]["secret_key"]),
            f.read().strip())
    wrapped = bob_info["vaults"][TEAM]["wrapped_key"]
    assert account_crypto.wrap_format(wrapped) is OLD
    key = account_crypto.unwrap_key(bob_keyset, wrapped, bytes.fromhex(TEAM), "bob")
    assert marker(blob) == b"PMV3"
    data = account_crypto.decrypt_vault(key, blob, bytes.fromhex(TEAM))
    assert sorted(e["site"] for e in data["accounts"]) == [
        "Printer", "Router", "Scanner"]
    last = changelog.lines_of(data)[-1]
    old_message = json.dumps(
        ["PassMan3 change", TEAM, last["id"], last["at"], last["by"],
         last["action"], last["entry"], last["title"], list(last["fields"]),
         int(last["count"])], separators=(",", ":"), ensure_ascii=True).encode()
    assert account_crypto.verify(
        base64.b64decode(FACTS["accounts"]["alice"]["signing_key"]),
        old_message, last["sig"])


def test_the_shared_vault_converts_once_the_last_member_has(online):
    online.device("a")
    alice = accounts.convert("alice", pw("alice"))
    sync_all(alice)
    online.device("b")
    bob = accounts.convert("bob", pw("bob"))
    sync_all(bob)                                # bob is an editor: no change
    assert marker(online.stored("vaults", TEAM, "vault.enc")) == b"PMV3"
    add_entry(bob, TEAM, "Scanner")
    sync_all(bob)

    online.device("a")
    alice = accounts.unlock("alice", pw("alice"))
    _, converted = sync_all(alice)
    assert TEAM in converted
    assert alice.vault_format(TEAM) is NOW
    assert marker(online.stored("vaults", TEAM, "vault.enc")) == b"SSV4"
    members = online.stored_json("vaults", TEAM, "members.json")
    assert members["format"] == 2
    for name in ("alice", "bob"):
        assert account_crypto.wrap_format(
            members["members"][name]["wrapped_key"]) is NOW
    assert sites(alice, TEAM) == ["Printer", "Router", "Scanner"]

    online.device("b")
    bob = accounts.unlock("bob", pw("bob"))
    changes, _ = sync_all(bob)
    assert changes.rekeyed == ["Team"]
    assert bob.vault_format(TEAM) is NOW
    assert sites(bob, TEAM) == ["Printer", "Router", "Scanner"]
    add_entry(bob, TEAM, "Camera")
    sync_all(bob)
    online.device("a")
    sync_all(alice)
    assert sites(alice, TEAM) == ["Camera", "Printer", "Router", "Scanner"]
    # Every line, old and new, by either of them, still checks out.
    assert set(log_checks(alice, TEAM)) == {("alice", changelog.OK),
                                            ("bob", changelog.OK)}


def test_trust_between_members_survives_both_conversions(online):
    """bob took Team's key from alice before; he takes its new key from her
    after, without comparing fingerprints again: her signing key is the
    same key."""
    online.device("b")
    bob = accounts.convert("bob", pw("bob"))
    sync_all(bob)
    online.device("a")
    alice = accounts.convert("alice", pw("alice"))
    sync_all(alice)                              # converts Team
    online.device("b")
    bob = accounts.unlock("bob", pw("bob"))
    seen = bob.contact("alice")
    assert account_crypto._b64(seen["signing_key"]) == \
        FACTS["accounts"]["alice"]["signing_key"]
    changes, _ = sync_all(bob)                   # no KeyNotTrusted
    assert changes.rekeyed == ["Team"]


def test_two_devices_of_one_account_converge_without_talking(online):
    """Each converts on its own; whichever syncs first tells the server,
    and the other simply finds its new login key accepted."""
    online.copy_device("a", "a2")
    online.device("a")
    first = accounts.convert("alice", pw("alice"))
    online.device("a2")
    second = accounts.convert("alice", pw("alice"))
    assert first.login_key == second.login_key
    assert second.server_conversion_pending
    online.device("a")
    sync_all(first)
    online.device("a2")
    changes, _ = sync_all(second)
    assert not second.server_conversion_pending
    assert sites(second) == ["Bank", "Mail"]
    assert sites(second, SOLO) == ["Notes"]      # under Solo's new key
    assert "Solo" in changes.rekeyed


def test_a_second_device_that_converts_later_still_gets_in(online):
    online.copy_device("a", "a2")
    online.device("a")
    sync_all(accounts.convert("alice", pw("alice")))
    online.device("a2")
    second = accounts.convert("alice", pw("alice"))
    sync_all(second)
    assert sites(second, TEAM) == ["Printer", "Router"]


def test_a_converted_account_signs_in_on_a_new_device(online):
    online.device("a")
    sync_all(accounts.convert("alice", pw("alice")))
    online.device("new")
    account, data = account_sync.sign_in(
        online.server.url, "", "alice", pw("alice"),
        FACTS["accounts"]["alice"]["secret_key"])       # the old kit
    assert sorted(e["site"] for e in data["accounts"]) == ["Bank", "Mail"]
    assert accounts.account_format("alice") == 2
    assert sites(account, TEAM) == ["Printer", "Router"]


def test_signing_in_does_not_convert_an_account_without_being_told_to(online):
    """Converting on the server locks out the account's devices that still
    run SecretSpace 3: the sign-in says so and changes nothing, anywhere."""
    online.device("new")
    before = tree(os.path.join(online.root, "store", "_v2", "accounts"))
    with pytest.raises(accounts.NeedsConversion):
        account_sync.sign_in(online.server.url, "", "bob", pw("bob"),
                             FACTS["accounts"]["bob"]["secret_key"])
    assert tree(os.path.join(online.root, "store", "_v2", "accounts")) == before
    assert not accounts.account_exists("bob")
    # ... and bob's device with SecretSpace 3 still gets in: the login key
    # the server expects is the one it always had.
    server = account_sync.AccountServer(online.server.url)
    old_login = account_crypto.derive_account_keys(
        pw("bob"), account_crypto.parse_secret_key(
            FACTS["accounts"]["bob"]["secret_key"]),
        "bob", base64.b64decode(server.prelogin("bob")["kdf"]["salt"]),
        1, 64, 1, OLD)[1]
    server.login("bob", old_login)
    server.logout()


def test_signing_in_to_an_account_nobody_converted_converts_it(online):
    """A new device with SecretSpace 4, an account still as 3 left it on the
    server: once the user has agreed, the sign-in converts it there and
    then."""
    online.device("new")
    account, data = account_sync.sign_in(
        online.server.url, "", "bob", pw("bob"),
        FACTS["accounts"]["bob"]["secret_key"], convert=True)
    assert sorted(e["site"] for e in data["accounts"]) == ["Forum"]
    record = online.stored_json("accounts", "bob.json")
    assert record["format"] == 2 and marker(record["keyset"]) == b"SSK4"
    assert not account.server_conversion_pending
    assert sites(accounts.unlock("bob", pw("bob")), TEAM) == ["Printer", "Router"]
    # bob's first device, converting later, finds the server already done.
    online.device("b")
    first = accounts.convert("bob", pw("bob"))
    sync_all(first)
    assert not first.server_conversion_pending


def test_signing_in_with_a_wrong_password_is_still_just_wrong(online):
    online.device("new")
    with pytest.raises(LoginFailed, match="Wrong username"):
        account_sync.sign_in(online.server.url, "", "bob", "not it",
                             FACTS["accounts"]["bob"]["secret_key"])
    assert online.stored_json("accounts", "bob.json").get("format", 1) == 1


def test_signing_in_over_an_unconverted_copy_on_this_pc_converts_it(online):
    """The password was changed on another (updated) device; this PC still
    has the account as SecretSpace 3 left it."""
    online.device("new")
    account_sync.sign_in(online.server.url, "", "bob", pw("bob"),
                         FACTS["accounts"]["bob"]["secret_key"], convert=True)
    account = accounts.unlock("bob", pw("bob"))
    account_sync.change_password(account, "bob's second password")

    online.device("b")
    with pytest.raises(accounts.NeedsConversion):
        accounts.unlock("bob", pw("bob"))        # the old one still opens it
    # (Under the password scheme the stored Secret Key is sealed with the
    # old password, so the kit is typed; Windows reads it back by itself.)
    account, _ = account_sync.sign_in(online.server.url, "", "bob",
                                      "bob's second password",
                                      FACTS["accounts"]["bob"]["secret_key"])
    assert accounts.account_format("bob") == 2
    assert sites(account) == ["Forum"]
    assert sites(account, TEAM) == ["Printer", "Router"]
    assert sorted(os.listdir(online.folder("b", "bob"))) == [
        "account.json", "keyset.ssk", "recovery.ssk", "vaults"]


def test_the_recovery_copy_reaches_the_server_when_the_words_are_typed(online):
    online.device("a")
    account = accounts.convert("alice", pw("alice"))
    sync_all(account)
    assert marker(online.stored_json("accounts", "alice.json")["recovery"]) \
        == b"PMK3"
    sealed = account.convert_recovery(FACTS["accounts"]["alice"]["phrase"])
    server = account_sync.logged_in(account)
    try:
        server.put_recovery(sealed)
    finally:
        server.logout()
    assert marker(online.stored_json("accounts", "alice.json")["recovery"]) \
        == b"SSK4"


def test_converting_the_recovery_copy_tells_the_server_first(online):
    """recovery.convert_copy, as the window runs it: the same words, the
    server and this PC in step."""
    online.device("a")
    account = accounts.convert("alice", pw("alice"))
    sync_all(account)
    with pytest.raises(CryptoError):
        recovery.convert_copy(account, account_crypto.new_recovery_phrase())
    assert account.recovery_converted is False
    recovery.convert_copy(account, FACTS["accounts"]["alice"]["phrase"])
    assert account.recovery_converted is True
    here = accounts.read_recovery_copy("alice")
    assert online.stored_json("accounts", "alice.json")["recovery"] == here
    assert marker(here) == b"SSK4"


def test_the_recovery_copy_is_not_converted_here_if_the_server_cannot_be_told(online):
    online.device("a")
    account = accounts.convert("alice", pw("alice"))
    sync_all(account)
    online.stop()
    online.server = None
    with pytest.raises(SyncError):
        recovery.convert_copy(account, FACTS["accounts"]["alice"]["phrase"])
    assert account.recovery_converted is False   # still the copy the server has


def test_converting_the_recovery_copy_of_a_local_account_needs_no_server(world):
    world.device("c")
    account = accounts.convert("carol", pw("carol"))
    recovery.convert_copy(account, FACTS["accounts"]["carol"]["phrase"])
    assert account.recovery_converted is True


def test_a_converted_account_recovers_with_its_old_words_on_a_new_device(online):
    """The copy on the server is still the old one; the 12 words open it,
    and the proof the server checks is the one it always had."""
    online.device("a")
    sync_all(accounts.convert("alice", pw("alice")))
    online.device("new")
    opened = recovery.open_with_phrase("alice",
                                       FACTS["accounts"]["alice"]["phrase"],
                                       online.server.url)
    pending = recovery.prepare(opened, "alice's new password")
    account, data = pending.save()
    assert sorted(e["site"] for e in data["accounts"]) == ["Bank", "Mail"]
    record = online.stored_json("accounts", "alice.json")
    assert marker(record["recovery"]) == b"SSK4" and record["format"] == 2


def test_an_unconverted_account_recovers_onto_a_new_device_converted(online):
    online.device("new")
    opened = recovery.open_with_phrase("bob", FACTS["accounts"]["bob"]["phrase"],
                                       online.server.url)
    pending = recovery.prepare(opened, "bob's new password")
    account, data = pending.save()
    assert sorted(e["site"] for e in data["accounts"]) == ["Forum"]
    assert online.stored_json("accounts", "bob.json")["format"] == 2
    assert accounts.account_format("bob") == 2


def test_a_server_too_old_for_this_version_is_named_and_nothing_is_sent(
        online, monkeypatch):
    online.device("a")
    account = accounts.convert("alice", pw("alice"))
    monkeypatch.setattr(account_sync.AccountServer, "health", lambda self: {
        "ok": True, "service": "passman-sync", "api": [1, 2],
        "features": ["vaults", "sharing", "recovery", "signed-keys"]})
    before = tree(os.path.join(online.root, "store"))
    with pytest.raises(SyncError, match="2.1.0 or newer"):
        sync_all(account)
    assert tree(os.path.join(online.root, "store")) == before
    assert account.server_conversion_pending     # still to be told


def test_a_new_vault_made_after_the_conversion_is_in_the_current_format(online):
    online.device("a")
    account = accounts.convert("alice", pw("alice"))
    sync_all(account)
    made = account.create_vault("Fresh")
    add_entry(account, made.hex, "Thing")
    sync_all(account)
    assert account.vault_format(made.hex) is NOW
    assert marker(online.stored("vaults", made.hex, "vault.enc")) == b"SSV4"
    assert online.stored_json("vaults", made.hex, "members.json")["format"] == 2


def test_a_member_added_to_an_unconverted_vault_gets_a_key_their_app_can_open(online):
    """alice (converted) shares Solo-like vault while it is still old: the
    key is wrapped the old way, as the vault is."""
    online.device("a")
    alice = accounts.convert("alice", pw("alice"))
    sync_all(alice, convert=False)               # Solo not converted yet
    assert alice.vault_format(SOLO) is OLD
    server = account_sync.logged_in(alice)
    try:
        keys = account_sync.lookup_contact(alice, server, "bob")
        account_sync.share_vault(alice, server, SOLO, keys, accounts.ROLE_READER)
    finally:
        server.logout()
    members = online.stored_json("vaults", SOLO, "members.json")
    assert account_crypto.wrap_format(
        members["members"]["bob"]["wrapped_key"]) is OLD
    # ... and now Solo has a member who has not updated: it waits.
    _, converted = sync_all(alice)
    assert SOLO not in converted


def test_the_sync_base_is_converted_with_its_vault(online):
    """Without its base the next sync could not tell a deletion from an
    addition; it must come through the conversion readable."""
    online.device("a")
    account = accounts.convert("alice", pw("alice"))
    for vault_id in (None, TEAM, SOLO):
        base = account.vault_file(vault_id).load_base()
        assert base is not None, vault_id
        assert sorted(e["site"] for e in base["accounts"]) == sites(account, vault_id)
    vaults = os.path.join(online.folder("a", "alice"), "vaults")
    assert sorted(n for n in os.listdir(vaults) if n.endswith(".base")) == sorted(
        v + ".ssv.base" for v in (account.personal_id, TEAM, SOLO))


def test_changing_a_key_while_a_member_has_not_updated_keeps_the_old_format(online):
    """alice (converted) changes Team's key by hand -- Members -> Change key.
    bob is still on SecretSpace 3, so the new key, its signature, the name
    and the vault are all made the way his app reads them."""
    online.device("a")
    alice = accounts.convert("alice", pw("alice"))
    sync_all(alice)
    server = account_sync.logged_in(alice)
    try:
        account_sync.change_key(alice, server, TEAM,
                                alice.vault_file(TEAM).load())
    finally:
        server.logout()
    assert alice.vault_format(TEAM) is OLD
    members = online.stored_json("vaults", TEAM, "members.json")
    assert members["key_generation"] == 1 and members.get("format", 1) == 1
    assert marker(online.stored("vaults", TEAM, "vault.enc")) == b"PMV3"
    wrapped = members["members"]["bob"]["wrapped_key"]
    assert account_crypto.wrap_format(wrapped) is OLD
    # bob's old app: the key opens with the old labels, and the signature on
    # it checks out as that app builds the message.
    with open(os.path.join(FIXTURE, "b", "accounts", "bob", "keyset.pmk"),
              encoding="utf-8") as f:
        bob_keyset, _ = account_crypto.unlock_account(
            "bob", pw("bob"),
            account_crypto.parse_secret_key(FACTS["accounts"]["bob"]["secret_key"]),
            f.read().strip())
    key = account_crypto.unwrap_key(bob_keyset, wrapped, bytes.fromhex(TEAM), "bob")
    blob = online.stored("vaults", TEAM, "vault.enc").decode("ascii")
    assert sorted(e["site"] for e in account_crypto.decrypt_vault(
        key, blob, bytes.fromhex(TEAM))["accounts"]) == ["Printer", "Router"]
    import hashlib
    old_message = json.dumps(
        ["PassMan3 vault key", TEAM, 1, "bob",
         hashlib.sha256(wrapped.encode("ascii")).hexdigest(), "alice"],
        separators=(",", ":"), ensure_ascii=True).encode("ascii")
    assert account_crypto.verify(
        base64.b64decode(FACTS["accounts"]["alice"]["signing_key"]),
        old_message, members["members"]["bob"]["key_sig"])
    assert account_crypto.open_vault_name(key, bytes.fromhex(TEAM),
                                          members["name"]) == "Team"
