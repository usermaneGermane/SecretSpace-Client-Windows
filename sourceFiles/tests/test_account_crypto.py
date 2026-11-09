"""SecretSpace 3.0 account cryptography: published vectors first, then the format."""

import base64
import hashlib
import unicodedata

import pytest

import account_crypto as ac
import bip39_words

# Cheap Argon2id settings: the format and the logic are what is under test,
# not the cost (the real cost is pinned separately below).
FAST = dict(passes=1, memory_kib=64, lanes=1)


# ---------------------------------------------------------------------------
# Argon2id
# ---------------------------------------------------------------------------
def test_rfc_9106_argon2id_vector():
    """RFC 9106 section 5.3, through the library the app uses on Windows."""
    argon2 = pytest.importorskip("cryptography.hazmat.primitives.kdf.argon2")
    tag = argon2.Argon2id(salt=b"\x02" * 16, length=32, iterations=3, lanes=4,
                          memory_cost=32, ad=b"\x04" * 12,
                          secret=b"\x03" * 8).derive(b"\x01" * 32)
    assert tag.hex() == ("0d640df58d78766c08c037a34a8b53c9"
                         "d01ef0452d75b65eb52520e96b01e659")


def test_the_wrapper_is_plain_argon2id():
    argon2 = pytest.importorskip("cryptography.hazmat.primitives.kdf.argon2")
    direct = argon2.Argon2id(salt=b"s" * 16, length=32, iterations=2, lanes=1,
                             memory_cost=64).derive(b"pw")
    assert ac.argon2id(b"pw", b"s" * 16, 2, 64, 1) == direct


def test_both_backends_give_the_same_key():
    """Windows (cryptography) and Ubuntu (python3-argon2) must agree, or a
    vault made on one could not be opened on the other."""
    backends = ac.argon2_backends()
    if len(backends) < 2:
        pytest.skip("needs both cryptography>=44 and argon2-cffi")
    outs = {name: fn(b"pass\xc3\xa9", b"salt" * 4, 2, 128, 2, 32)
            for name, fn in backends.items()}
    assert len(set(outs.values())) == 1, outs


def test_new_accounts_cost_64_mib_and_3_passes():
    assert (ac.ARGON2_MEMORY_KIB, ac.ARGON2_PASSES, ac.ARGON2_LANES) == \
        (65536, 3, 1)


# ---------------------------------------------------------------------------
# Secret Key
# ---------------------------------------------------------------------------
def test_secret_key_round_trip_and_shape():
    for _ in range(50):
        raw = ac.new_secret_key()
        text = ac.format_secret_key(raw)
        assert text.startswith("A3-") and len(text.replace("-", "")) == 29
        assert [len(g) for g in text.split("-")] == [2, 5, 5, 5, 6, 6]
        assert ac.parse_secret_key(text) == raw


def test_secret_key_typed_loosely_is_accepted():
    raw = bytes(range(16))
    text = ac.format_secret_key(raw)
    assert ac.parse_secret_key("  " + text.lower().replace("-", " ") + "\n") == raw


def test_typos_read_as_typos_almost_always():
    """
    A typo should say "typo", not "wrong password". The check character
    catches a random one-character typo 31 times in 32 (the rest end as
    "Wrong master password or Secret Key" -- annoying, never unsafe), and a
    typo in the check character itself every time.
    """
    raw = bytes(range(16))
    body = ac.format_secret_key(raw).replace("-", "")[2:]
    tried = missed = 0
    for i, original in enumerate(body):
        for c in ac._B32:
            if c == original:
                continue
            tried += 1
            try:
                ac.parse_secret_key("A3" + body[:i] + c + body[i + 1:])
            except ac.CryptoError:
                continue
            missed += 1
            assert i < 26, "a typo in the check character slipped through"
    assert missed < tried / 16, (missed, tried)


@pytest.mark.parametrize("text,words", [
    ("", "Enter your Secret Key"),
    ("B3-AAAAA", "starts with A3"),
    ("A3-AAAAA-AAAAA", "27 characters"),
    ("A3-AAAA0-AAAAA-AAAAA-AAAAAA-AAAAAA", "never used"),
])
def test_secret_key_mistakes_say_what_is_wrong(text, words):
    with pytest.raises(ac.CryptoError, match=words):
        ac.parse_secret_key(text)


# ---------------------------------------------------------------------------
# Account keys
# ---------------------------------------------------------------------------
SECRET, SALT = b"k" * 16, b"s" * 16


def keys(pw="correct horse", secret=SECRET, user="alex", salt=SALT):
    return ac.derive_account_keys(pw, secret, user, salt, **FAST)


def test_keys_are_deterministic_and_independent():
    auk, login = keys()
    assert (auk, login) == keys()
    assert auk != login and len(auk) == len(login) == 32


@pytest.mark.parametrize("change", [
    dict(pw="correct horsf"), dict(secret=b"K" * 16), dict(user="Alex"),
    dict(salt=b"S" * 16)])
def test_every_input_matters(change):
    assert keys(**change)[0] != keys()[0]


def test_the_same_password_in_two_unicode_forms_is_one_password():
    composed = unicodedata.normalize("NFC", "café-Zürich")
    decomposed = unicodedata.normalize("NFD", "café-Zürich")
    assert composed != decomposed
    assert keys(pw=composed) == keys(pw=decomposed)


def test_an_empty_password_is_refused():
    with pytest.raises(ac.CryptoError, match="master password"):
        keys(pw="")


# ---------------------------------------------------------------------------
# Sealed keyset
# ---------------------------------------------------------------------------
def sealed(key=b"a" * 32, **cost):
    cost = cost or FAST
    return ac.seal_keyset(key, {"x": 1}, SALT, ac.KDF_ARGON2ID, **cost)


def test_keyset_round_trip_and_header():
    blob = sealed()
    assert ac.open_keyset(b"a" * 32, blob) == {"x": 1}
    head = ac.keyset_header(blob)
    assert head == {"kdf": ac.KDF_ARGON2ID, "memory_kib": 64, "passes": 1,
                    "lanes": 1, "salt": SALT}


def test_wrong_key_reads_as_wrong_password_or_secret_key():
    with pytest.raises(ac.CryptoError, match="Wrong master password or Secret Key"):
        ac.open_keyset(b"b" * 32, sealed())


def test_a_lowered_cost_in_the_header_breaks_the_file():
    """The header is associated data: an attacker cannot make the next unlock
    cheaper (or swap the salt) without the file failing to open."""
    raw = bytearray(base64.b64decode(sealed(memory_kib=128, passes=2, lanes=1)))
    raw[10] = 1                                   # passes 2 -> 1
    with pytest.raises(ac.CryptoError, match="Wrong"):
        ac.open_keyset(b"a" * 32, base64.b64encode(bytes(raw)).decode())


@pytest.mark.parametrize("cost", [dict(passes=99, memory_kib=64, lanes=1),
                                  dict(passes=1, memory_kib=4 * 1024 * 1024, lanes=1),
                                  dict(passes=1, memory_kib=64, lanes=0)])
def test_an_absurd_cost_is_refused_before_any_work(cost):
    blob = ac.seal_keyset(b"a" * 32, {}, SALT, ac.KDF_ARGON2ID, **cost)
    with pytest.raises(ac.CryptoError, match="unreasonable"):
        ac.keyset_header(blob)


@pytest.mark.parametrize("mangle,words", [
    (lambda r: b"PMV2" + r[4:], "not a SecretSpace 3 account"),
    (lambda r: r[:4] + b"\x09" + r[5:], "newer SecretSpace"),
    (lambda r: r[:30], "too short"),
])
def test_a_wrong_file_says_so(mangle, words):
    raw = base64.b64decode(sealed())
    with pytest.raises(ac.CryptoError, match=words):
        ac.open_keyset(b"a" * 32, base64.b64encode(mangle(raw)).decode())


# ---------------------------------------------------------------------------
# Wrapped vault keys and fingerprints
# ---------------------------------------------------------------------------
VID = b"v" * 16


def test_a_wrapped_key_opens_only_for_its_member_and_vault():
    alice, bob = ac.new_keyset(), ac.new_keyset()
    vault_key = b"V" * 32
    wrapped = ac.wrap_key(ac.public_key_of(alice), vault_key, VID, "alice")
    assert ac.unwrap_key(alice, wrapped, VID, "alice") == vault_key
    for keyset, vid, member in ((bob, VID, "alice"), (alice, b"w" * 16, "alice"),
                                (alice, VID, "bob")):
        with pytest.raises(ac.CryptoError, match="not made for"):
            ac.unwrap_key(keyset, wrapped, vid, member)


def test_wrapping_twice_gives_different_bytes():
    alice = ac.new_keyset()
    pub = ac.public_key_of(alice)
    assert ac.wrap_key(pub, b"V" * 32, VID, "a") != ac.wrap_key(pub, b"V" * 32, VID, "a")


def test_fingerprint_is_six_groups_of_four_and_stable():
    pub = ac.public_key_of(ac.new_keyset())
    fp = ac.fingerprint(pub)
    assert fp == ac.fingerprint(pub)
    groups = fp.split(" ")
    assert len(groups) == 6 and all(len(g) == 4 and g.isdigit() for g in groups)
    assert fp != ac.fingerprint(ac.public_key_of(ac.new_keyset()))


# ---------------------------------------------------------------------------
# PMV3
# ---------------------------------------------------------------------------
DATA = {"accounts": [{"id": "1", "site": "Router", "password": "pässwörd"}]}


def test_vault_round_trip_and_header():
    blob = ac.encrypt_vault(b"V" * 32, VID, 3, DATA)
    assert ac.decrypt_vault(b"V" * 32, blob, VID) == DATA
    assert ac.vault_header(blob) == {"vault_id": VID, "key_generation": 3}


def test_a_vault_from_another_vault_is_refused():
    blob = ac.encrypt_vault(b"V" * 32, VID, 0, DATA)
    with pytest.raises(ac.CryptoError, match="different vault"):
        ac.decrypt_vault(b"V" * 32, blob, b"w" * 16)


def test_an_edited_vault_header_breaks_decryption():
    raw = bytearray(base64.b64decode(ac.encrypt_vault(b"V" * 32, VID, 0, DATA)))
    raw[24] ^= 1                                  # key generation
    with pytest.raises(ac.CryptoError, match="could not be decrypted"):
        ac.decrypt_vault(b"V" * 32, base64.b64encode(bytes(raw)).decode())


def test_wrong_vault_key():
    with pytest.raises(ac.CryptoError, match="could not be decrypted"):
        ac.decrypt_vault(b"W" * 32, ac.encrypt_vault(b"V" * 32, VID, 0, DATA))


def test_a_2x_vault_is_not_mistaken_for_pmv3():
    import crypto_utils
    blob = crypto_utils.encrypt("pw", DATA, iterations=1000)
    blob = blob.decode() if isinstance(blob, bytes) else blob
    with pytest.raises(ac.CryptoError, match="not a SecretSpace 3 vault"):
        ac.vault_header(blob)


# ---------------------------------------------------------------------------
# Recovery phrase
# ---------------------------------------------------------------------------
def test_the_word_list_is_the_official_one():
    text = "\n".join(bip39_words.WORDS) + "\n"
    assert hashlib.sha256(text.encode()).hexdigest() == \
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


@pytest.mark.parametrize("entropy,phrase", [
    ("00" * 16, "abandon abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon about"),
    ("7f" * 16, "legal winner thank year wave sausage worth useful legal "
                "winner thank yellow"),
    ("80" * 16, "letter advice cage absurd amount doctor acoustic avoid "
                "letter advice cage above"),
    ("ff" * 16, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
    ("9e885d952ad362caeb4efe34a8e91bd2",
     "ozone drill grab fiber curtain grace pudding thank cruise elder eight "
     "picnic"),
])
def test_bip39_reference_vectors(entropy, phrase):
    assert ac.entropy_to_phrase(bytes.fromhex(entropy)) == phrase
    assert ac.phrase_to_entropy(phrase) == bytes.fromhex(entropy)


def test_a_phrase_typed_in_capitals_with_extra_spaces():
    phrase = ac.new_recovery_phrase()
    assert ac.phrase_to_entropy("  " + phrase.upper().replace(" ", "   ")) == \
        ac.phrase_to_entropy(phrase)


def test_swapped_words_are_caught_by_the_checksum():
    words = ("legal winner thank year wave sausage worth useful legal winner "
             "thank yellow").split()
    words[2], words[3] = words[3], words[2]
    with pytest.raises(ac.CryptoError, match="not in this order"):
        ac.phrase_to_entropy(" ".join(words))


def test_an_unknown_word_is_named_with_its_position():
    with pytest.raises(ac.CryptoError, match="3. “thenk”"):
        ac.phrase_to_entropy("legal winner thenk year wave sausage worth useful "
                             "legal winner thank yellow")


def test_wrong_word_count():
    with pytest.raises(ac.CryptoError, match="12 words; 11"):
        ac.phrase_to_entropy("zoo " * 11)


# ---------------------------------------------------------------------------
# An account, end to end
# ---------------------------------------------------------------------------
@pytest.fixture
def account():
    return ac.create_account("alex", "correct horse", **FAST)


def test_create_then_unlock(account):
    keyset, login = ac.unlock_account("alex", "correct horse",
                                      account["secret_key"],
                                      account["sealed_keyset"])
    assert keyset == account["keyset"] and login == account["login_key"]
    assert ac.parse_secret_key(account["secret_key_text"]) == account["secret_key"]
    assert ac.public_key_of(keyset) == account["public_key"]


def test_password_alone_or_secret_key_alone_is_not_enough(account):
    with pytest.raises(ac.CryptoError, match="Wrong"):
        ac.unlock_account("alex", "correct horse", b"x" * 16,
                          account["sealed_keyset"])
    with pytest.raises(ac.CryptoError, match="Wrong"):
        ac.unlock_account("alex", "wrong horse", account["secret_key"],
                          account["sealed_keyset"])


def test_the_phrase_alone_recovers_the_same_keyset(account):
    keyset = ac.recover_account("alex", account["recovery_phrase"],
                                account["sealed_recovery"])
    assert keyset == account["keyset"]


def test_another_phrase_does_not(account):
    with pytest.raises(ac.CryptoError, match="not the one for this account"):
        ac.recover_account("alex", ac.new_recovery_phrase(),
                           account["sealed_recovery"])


def test_the_two_files_cannot_be_used_for_each_other(account):
    with pytest.raises(ac.CryptoError, match="recovery copy"):
        ac.unlock_account("alex", "correct horse", account["secret_key"],
                          account["sealed_recovery"])
    with pytest.raises(ac.CryptoError, match="not its recovery copy"):
        ac.recover_account("alex", account["recovery_phrase"],
                           account["sealed_keyset"])


def test_after_recovery_a_new_password_keeps_every_vault_key(account):
    keyset = ac.recover_account("alex", account["recovery_phrase"],
                                account["sealed_recovery"])
    wrapped = ac.wrap_key(account["public_key"], b"V" * 32, VID, "alex")
    resealed, login = ac.reseal_with_new_password(
        "alex", keyset, "new password 2026", account["secret_key"], **FAST)
    opened, login2 = ac.unlock_account("alex", "new password 2026",
                                       account["secret_key"], resealed)
    assert ac.unwrap_key(opened, wrapped, VID, "alex") == b"V" * 32
    assert login == login2 != account["login_key"]
    with pytest.raises(ac.CryptoError, match="Wrong"):
        ac.unlock_account("alex", "correct horse", account["secret_key"], resealed)


def test_nothing_secret_is_in_the_sealed_files(account):
    for blob in (account["sealed_keyset"], account["sealed_recovery"]):
        raw = base64.b64decode(blob)
        assert account["secret_key"] not in raw
        assert b"correct horse" not in raw
        assert base64.b64decode(account["keyset"]["x25519_private"]) not in raw
