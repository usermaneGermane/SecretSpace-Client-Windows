"""PassMan 3.0 local accounts: files, unlock, Secret Key per device, 2.x import."""

import hashlib
import json
import os
import sys

import pytest

import account_crypto
import accounts
import secret_store
import vault
from account_crypto import CryptoError

PW = "correct horse battery staple"


@pytest.fixture(autouse=True)
def cheap_argon2(monkeypatch):
    # The real cost is 64 MiB x 3; the files record whatever was used, so a
    # small one exercises the same code in a fraction of the time.
    monkeypatch.setattr(account_crypto, "ARGON2_MEMORY_KIB", 64)
    monkeypatch.setattr(account_crypto, "ARGON2_PASSES", 1)


@pytest.fixture(params=["native", "password"])
def scheme(request, monkeypatch):
    """Run the Secret Key tests under this OS's scheme and the portable one."""
    if request.param == "password":
        monkeypatch.setattr(secret_store, "default_scheme",
                            lambda: secret_store.SCHEME_PASSWORD)
    return request.param


def make(name="alice", pw=PW):
    new = accounts.prepare_account(name, pw)
    return new, new.save()


def entry(site, user="u", pw="p", **extra):
    e = {"site": site, "username": user, "password": pw}
    e.update(extra)
    return e


# ---------------------------------------------------------------------------
# Making an account
# ---------------------------------------------------------------------------
def test_files_and_layout(data_dir):
    new, acc = make()
    folder = os.path.join(os.path.dirname(str(data_dir)), "accounts", "alice")
    assert accounts.account_dir("alice") == folder
    assert sorted(os.listdir(folder)) == ["account.json", "keyset.pmk",
                                          "recovery.pmk", "vaults"]
    assert os.listdir(os.path.join(folder, "vaults")) == [
        acc.info["personal_vault"] + ".pmv3"]
    assert accounts.list_accounts() == ["alice"]
    assert acc.load_vault() == {"accounts": []}


def test_account_json_holds_nothing_secret(scheme):
    new, acc = make()
    text = open(os.path.join(accounts.account_dir("alice"), "account.json"),
                encoding="utf-8").read()
    raw = acc._secret
    for secret in (PW, new.secret_key_text, new.recovery_phrase,
                   account_crypto._b64(raw), raw.hex(),
                   acc.keyset["personal_vault_key"], acc.keyset["x25519_private"]):
        assert secret not in text
    info = json.loads(text)
    assert info["mode"] == "personal" and info["server"] is None
    assert info["secret_key"]["scheme"] in (secret_store.SCHEME_DPAPI,
                                            secret_store.SCHEME_PASSWORD)


def test_nothing_is_written_until_save():
    new = accounts.prepare_account("alice", PW)
    assert accounts.list_accounts() == []
    assert not os.path.exists(accounts.accounts_dir())
    assert new.secret_key_text.startswith("A3-")
    assert len(new.recovery_phrase.split()) == 12
    new.save()
    assert accounts.list_accounts() == ["alice"]


def test_duplicate_name_refused():
    make()
    with pytest.raises(FileExistsError):
        accounts.prepare_account("alice", "another password")


def test_leftover_folder_is_not_overwritten():
    os.makedirs(accounts.account_dir("bob"))
    marker = os.path.join(accounts.account_dir("bob"), "keep.txt")
    open(marker, "w").write("mine")
    new = accounts.prepare_account("bob", PW)
    with pytest.raises(FileExistsError, match="holds no account"):
        new.save()
    assert open(marker).read() == "mine"
    assert accounts.list_accounts() == []


def test_failed_save_leaves_no_half_account(monkeypatch):
    new = accounts.prepare_account("alice", PW)

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(accounts, "_write_info", boom)
    with pytest.raises(OSError):
        new.save()
    assert not os.path.exists(accounts.account_dir("alice"))


@pytest.mark.parametrize("bad", ["", "../x", "a/b", "con", " "])
def test_bad_usernames_refused(bad):
    with pytest.raises(ValueError):
        accounts.prepare_account(bad, PW)


def test_empty_password_refused():
    with pytest.raises(ValueError):
        accounts.prepare_account("alice", "")


def test_list_ignores_junk(data_dir):
    make()
    root = accounts.accounts_dir()
    os.makedirs(os.path.join(root, "half"))                 # no account.json
    open(os.path.join(root, "stray.txt"), "w").close()
    assert accounts.list_accounts() == ["alice"]


# ---------------------------------------------------------------------------
# Unlocking
# ---------------------------------------------------------------------------
def test_unlock_with_password_only(scheme):
    new, acc = make()
    acc.save_vault({"accounts": [entry("github")]})
    again = accounts.unlock("alice", PW)
    assert [a["site"] for a in again.load_vault()["accounts"]] == ["github"]
    assert again.fingerprint == new.fingerprint
    assert again.secret_key_text == new.secret_key_text


def test_wrong_password(scheme):
    make()
    with pytest.raises(CryptoError, match="Wrong master password"):
        accounts.unlock("alice", PW + "x")


def test_unknown_account():
    with pytest.raises(FileNotFoundError):
        accounts.unlock("nobody", PW)


def _forget_secret_key(name="alice"):
    """What a copied folder looks like on a new PC: the key does not open."""
    path = os.path.join(accounts.account_dir(name), "account.json")
    info = json.load(open(path, encoding="utf-8"))
    info.pop("secret_key")
    json.dump(info, open(path, "w", encoding="utf-8"))


def test_new_device_asks_for_secret_key_once(scheme):
    new, acc = make()
    _forget_secret_key()
    with pytest.raises(accounts.SecretKeyNeeded):
        accounts.unlock("alice", PW)
    opened = accounts.unlock("alice", PW, secret_key_text=new.secret_key_text)
    assert opened.load_vault() == {"accounts": []}
    # Stored now: the next unlock needs the password only.
    accounts.unlock("alice", PW)


def test_secret_key_typed_loosely_is_accepted():
    new, acc = make()
    _forget_secret_key()
    loose = new.secret_key_text.lower().replace("-", " ")
    accounts.unlock("alice", PW, secret_key_text=loose)


def test_wrong_secret_key_is_not_stored():
    new, acc = make()
    _forget_secret_key()
    other = account_crypto.format_secret_key(account_crypto.new_secret_key())
    with pytest.raises(CryptoError, match="Wrong master password or Secret Key"):
        accounts.unlock("alice", PW, secret_key_text=other)
    with pytest.raises(accounts.SecretKeyNeeded):
        accounts.unlock("alice", PW)


def test_typo_in_secret_key_is_caught_before_unlocking():
    new, acc = make()
    _forget_secret_key()
    text = new.secret_key_text
    last = text[-1]
    typo = text[:-1] + ("A" if last != "A" else "B")
    with pytest.raises(ValueError):
        accounts.unlock("alice", PW, secret_key_text=typo)


def test_secret_key_record_of_another_account_does_not_open(scheme):
    make("alice")
    make("bob")
    a = os.path.join(accounts.account_dir("alice"), "account.json")
    b = os.path.join(accounts.account_dir("bob"), "account.json")
    info_a = json.load(open(a, encoding="utf-8"))
    info_b = json.load(open(b, encoding="utf-8"))
    info_b["secret_key"] = info_a["secret_key"]
    json.dump(info_b, open(b, "w", encoding="utf-8"))
    with pytest.raises((accounts.SecretKeyNeeded, CryptoError)):
        accounts.unlock("bob", PW)


def test_damaged_account_file():
    make()
    path = os.path.join(accounts.account_dir("alice"), "account.json")
    open(path, "w").write("{not json")
    with pytest.raises(ValueError, match="damaged"):
        accounts.unlock("alice", PW)


def test_newer_account_format_refused():
    make()
    path = os.path.join(accounts.account_dir("alice"), "account.json")
    info = json.load(open(path, encoding="utf-8"))
    info["format"] = 99
    json.dump(info, open(path, "w", encoding="utf-8"))
    with pytest.raises(ValueError, match="another PassMan version"):
        accounts.unlock("alice", PW)


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_windows_keeps_the_secret_key_with_dpapi():
    new, acc = make()
    assert acc.info["secret_key"]["scheme"] == secret_store.SCHEME_DPAPI


# ---------------------------------------------------------------------------
# The personal vault file
# ---------------------------------------------------------------------------
def test_vault_file_is_pmv3_bound_to_its_id():
    new, acc = make()
    acc.save_vault({"accounts": [entry("x")]})
    blob = open(acc.vault_path, encoding="utf-8").read()
    head = account_crypto.vault_header(blob)
    assert head["vault_id"] == acc.vault_id and head["key_generation"] == 0


def test_vault_of_another_account_is_refused():
    _, a = make("alice")
    _, b = make("bob")
    a.save_vault({"accounts": [entry("alice-site")]})
    # bob's file replaced by alice's: a different vault id and key.
    os.replace(a.vault_path, b.vault_path)
    if os.path.exists(b.vault_path + ".bak"):
        os.remove(b.vault_path + ".bak")
    with pytest.raises(CryptoError):
        accounts.unlock("bob", PW).load_vault()


def test_save_keeps_previous_as_bak_and_falls_back():
    new, acc = make()
    acc.save_vault({"accounts": [entry("one")]})
    acc.save_vault({"accounts": [entry("one"), entry("two")]})
    open(acc.vault_path, "w").write("garbage")
    sites = [a["site"] for a in acc.load_vault()["accounts"]]
    assert sites == ["one"]


def test_save_validates_like_2x():
    new, acc = make()
    with pytest.raises(ValueError):
        acc.save_vault({"no": "accounts"})


# ---------------------------------------------------------------------------
# Password checks and changes
# ---------------------------------------------------------------------------
def test_check_password():
    new, acc = make()
    assert acc.check_password(PW)
    assert not acc.check_password(PW + "!")


def test_change_password(scheme):
    new, acc = make()
    acc.save_vault({"accounts": [entry("keep")]})
    before = open(acc.vault_path, "rb").read()
    acc.change_password("a brand new password")
    with pytest.raises(CryptoError):
        accounts.unlock("alice", PW)
    again = accounts.unlock("alice", "a brand new password")
    assert [a["site"] for a in again.load_vault()["accounts"]] == ["keep"]
    # Same keyset, so the vault file did not need rewriting.
    assert open(acc.vault_path, "rb").read() == before
    assert again.check_password("a brand new password")
    assert not again.check_password(PW)


def test_change_password_leaves_no_old_keyset_copy():
    new, acc = make()
    acc.change_password("new one here")
    folder = accounts.account_dir("alice")
    assert sorted(os.listdir(folder)) == ["account.json", "keyset.pmk",
                                          "recovery.pmk", "vaults"]


def test_change_password_then_new_device(scheme):
    new, acc = make()
    acc.change_password("second password")
    _forget_secret_key()
    accounts.unlock("alice", "second password",
                    secret_key_text=new.secret_key_text)


# ---------------------------------------------------------------------------
# Recovery phrase (shown at creation; the recovery flow is phase 5)
# ---------------------------------------------------------------------------
def test_recovery_phrase_opens_the_recovery_copy():
    new, acc = make()
    assert accounts.check_recovery_phrase("alice", new.recovery_phrase)
    other = account_crypto.new_recovery_phrase()
    assert not accounts.check_recovery_phrase("alice", other)


def test_recovery_phrase_survives_a_password_change():
    new, acc = make()
    acc.change_password("changed")
    assert accounts.check_recovery_phrase("alice", new.recovery_phrase)


# ---------------------------------------------------------------------------
# Deleting
# ---------------------------------------------------------------------------
def test_delete_account_only_removes_its_folder():
    make("alice")
    make("bob")
    vault.create_new_user("legacy", "pw2x")
    accounts.delete_account("alice")
    assert accounts.list_accounts() == ["bob"]
    assert vault.list_users() == ["legacy"]
    with pytest.raises(FileNotFoundError):
        accounts.delete_account("alice")


# ---------------------------------------------------------------------------
# Emergency Kit
# ---------------------------------------------------------------------------
def test_emergency_kit_has_the_key_but_not_the_phrase():
    new, acc = make()
    kit = accounts.emergency_kit_text("alice", new.secret_key_text)
    assert new.secret_key_text in kit and "alice" in kit
    # Not word by word: the kit is plain English, and the BIP39 list has
    # "account", "page", "file"... -- no two phrase words in a row, though.
    text = " ".join(kit.lower().split())
    words = new.recovery_phrase.split()
    for a, b in zip(words, words[1:]):
        assert f"{a} {b}" not in text
    assert PW not in kit


# ---------------------------------------------------------------------------
# Importing a 2.x vault
# ---------------------------------------------------------------------------
def _two_x_vault():
    data = {"accounts": []}
    vault.add_account(data, "github", "al", "pw1", notes="n", totp="JBSWY3DPEHPK3PXP")
    e = data["accounts"][0]
    vault.update_entry(e, password="pw2")                 # makes history
    vault.add_account(data, "old", "al", "gone")
    vault.archive_account(data, data["accounts"][1]["id"])
    data["sync"] = {"url": "https://server", "token": "SECRET-TOKEN"}
    data["archive_purge_days"] = 30
    return data


def test_import_keeps_entries_whole():
    src = _two_x_vault()
    target = {"accounts": []}
    added, skipped = vault.import_entries(target, src)
    assert (added, skipped) == (2, 0)
    by_site = {a["site"]: a for a in target["accounts"]}
    gh = by_site["github"]
    assert gh["password"] == "pw2" and gh["notes"] == "n"
    assert gh["totp"] == "JBSWY3DPEHPK3PXP"
    assert gh["id"] == src["accounts"][0]["id"]
    assert [r["password"] for r in gh["history"]] == ["pw1"]
    assert vault.is_archived(by_site["old"])
    assert by_site["old"]["archived_at"] == src["accounts"][1]["archived_at"]


def test_import_leaves_2x_settings_behind():
    target = {"accounts": []}
    vault.import_entries(target, _two_x_vault())
    assert set(target) == {"accounts"}


def test_import_does_not_change_the_source():
    src = _two_x_vault()
    before = json.dumps(src, sort_keys=True)
    target = {"accounts": []}
    vault.import_entries(target, src)
    target["accounts"][0]["password"] = "edited after import"
    target["accounts"][0]["history"].append({"x": 1})
    assert json.dumps(src, sort_keys=True) == before


def test_import_twice_adds_nothing():
    src = _two_x_vault()
    target = {"accounts": []}
    vault.import_entries(target, src)
    assert vault.import_entries(target, src) == (0, 2)
    assert len(target["accounts"]) == 2


def test_import_skips_same_login_with_other_id():
    target = {"accounts": []}
    vault.add_account(target, "github", "al", "pw2")
    added, skipped = vault.import_entries(target, _two_x_vault())
    assert (added, skipped) == (1, 1)


def test_import_from_a_2x_file_into_an_account_leaves_the_file_alone():
    src = _two_x_vault()
    vault.create_new_user("legacy", "pw2x")
    vault.save_vault("pw2x", src, "legacy")
    path = vault.get_vault_path("legacy")
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    listing = sorted(os.listdir(vault.get_data_dir()))

    new, acc = make()
    data = acc.load_vault()
    vault.import_entries(data, vault.read_vault_file(path, "pw2x"))
    acc.save_vault(data)

    assert hashlib.sha256(open(path, "rb").read()).hexdigest() == digest
    assert sorted(os.listdir(vault.get_data_dir())) == listing
    again = accounts.unlock("alice", PW).load_vault()
    assert sorted(a["site"] for a in again["accounts"]) == ["github", "old"]


def test_read_vault_file_wrong_password():
    vault.create_new_user("legacy", "pw2x")
    with pytest.raises(ValueError, match="Decryption failed"):
        vault.read_vault_file(vault.get_vault_path("legacy"), "nope")


def test_phrase_type_back_check():
    dialogs = pytest.importorskip("dialogs", reason="needs tkinter")
    phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident"
    assert dialogs.CHECK_WORDS == (3, 7, 11)
    assert dialogs.phrase_mismatches(phrase, {3: " ABLE ", 7: "absorb", 11: "access"}) == []
    assert dialogs.phrase_mismatches(phrase, {3: "able", 7: "absurd", 11: ""}) == [7, 11]
