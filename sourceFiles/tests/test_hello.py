"""
Windows Hello: what is kept while locked, and that it needs the gesture.
The Hello key itself is stood in for by an RSA key here.
"""

import os
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import account_crypto
import accounts
import hello

PW = "master-pass-ü-1"


@pytest.fixture(autouse=True)
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRETSPACE_DATA_DIR", str(tmp_path / "vault"))
    monkeypatch.setattr(account_crypto, "ARGON2_MEMORY_KIB", 64)
    monkeypatch.setattr(account_crypto, "ARGON2_PASSES", 1)
    monkeypatch.setattr(hello, "_kept", {})


@pytest.fixture
def gestures(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    asked = []
    monkeypatch.setattr(hello, "_wrap", lambda data: key.public_key().encrypt(
        data, padding.PKCS1v15()))

    def unwrap(data, window, text):
        asked.append(text)
        return key.decrypt(data, padding.PKCS1v15())

    monkeypatch.setattr(hello, "_unwrap", unwrap)
    return asked


@pytest.fixture
def account():
    return accounts.prepare_account("alex", PW).save()


def everything(folder):
    for path, _, names in os.walk(folder):
        for name in names:
            with open(os.path.join(path, name), "rb") as f:
                yield f.read()


def test_off_by_default_and_kept_in_the_account(account):
    assert not hello.is_enabled(account) and not hello.is_enabled(None)
    hello.set_enabled(account, True)
    assert hello.is_enabled(accounts.unlock("alex", PW))
    hello.set_enabled(account, False)
    assert not hello.is_enabled(accounts.unlock("alex", PW))


def test_only_a_real_true_counts(account):
    for value in ("yes", 1, None):
        account.info[hello.SETTING] = value
        assert not hello.is_enabled(account)


def test_nothing_is_kept_while_off(account, gestures):
    assert not hello.keep(account, PW)
    assert not hello.can_unlock("alex")
    with pytest.raises(hello.Failed):
        hello.password_for("alex", 0)


def test_a_lock_and_an_unlock(account, gestures, tmp_path):
    hello.set_enabled(account, True)
    assert hello.keep(account, PW) and hello.can_unlock("alex")
    assert not hello.can_unlock("maria") and gestures == []
    assert hello.password_for("alex", 0) == PW
    assert len(gestures) == 1 and "alex" in gestures[0]
    hello.forget("alex")
    assert not hello.can_unlock("alex")


def test_locked_it_is_readable_neither_in_memory_nor_on_disk(
        account, gestures, tmp_path):
    hello.set_enabled(account, True)
    before = sorted(everything(tmp_path))
    hello.keep(account, PW)
    assert sorted(everything(tmp_path)) == before
    assert PW.encode() not in b"".join(hello._kept["alex"])


def test_turning_it_off_forgets(account, gestures):
    hello.set_enabled(account, True)
    hello.keep(account, PW)
    hello.set_enabled(account, False)
    assert not hello.can_unlock("alex")


def test_a_later_lock_replaces_the_password(account, gestures):
    hello.set_enabled(account, True)
    hello.keep(account, PW)
    hello.keep(account, "the-new-one")
    assert hello.password_for("alex", 0) == "the-new-one"


def test_one_accounts_does_not_open_as_anothers(account, gestures):
    hello.set_enabled(account, True)
    hello.keep(account, PW)
    hello._kept["maria"] = hello._kept["alex"]
    with pytest.raises(hello.Failed):
        hello.password_for("maria", 0)


def test_a_failing_hello_never_stops_a_lock(account, monkeypatch):
    hello.set_enabled(account, True)
    for error in (hello.Failed("x"), hello.Cancelled(), OSError(), KeyError()):
        def wrap(data, error=error):
            raise error
        monkeypatch.setattr(hello, "_wrap", wrap)
        assert not hello.keep(account, PW)
        assert not hello.can_unlock("alex")


def test_an_older_one_does_not_outlive_a_failed_lock(account, gestures,
                                                     monkeypatch):
    hello.set_enabled(account, True)
    hello.keep(account, PW)

    def wrap(_):
        raise hello.Failed("x")

    monkeypatch.setattr(hello, "_wrap", wrap)
    hello.keep(account, "the-new-one")
    assert not hello.can_unlock("alex")


def test_a_cancelled_gesture_can_be_tried_again(account, gestures, monkeypatch):
    hello.set_enabled(account, True)
    hello.keep(account, PW)
    good = hello._unwrap

    def no(*_):
        raise hello.Cancelled()

    monkeypatch.setattr(hello, "_unwrap", no)
    with pytest.raises(hello.Cancelled):
        hello.password_for("alex", 0)
    monkeypatch.setattr(hello, "_unwrap", good)
    assert hello.password_for("alex", 0) == PW


def test_the_proof_asks_once(gestures):
    hello.prove(0)
    assert len(gestures) == 1


def test_a_hello_that_returns_something_else(account, gestures, monkeypatch):
    for wrong in (bytes(32), b"short"):
        monkeypatch.setattr(hello, "_unwrap", lambda *_: wrong)
        with pytest.raises(hello.Failed):
            hello.prove(0)


# ---------------------------------------------------------------------------
# The calls to Windows, against a stand-in for the key
# ---------------------------------------------------------------------------
class Key:
    statuses, log = [], []

    def __init__(self, silent):
        self.log.append("silent" if silent else "may ask")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def ask(self, window, text):
        self.log.append(("ask", window, text))

    def encrypt(self, data):
        return b"e" + data

    def decrypt(self, data):
        if self.statuses:
            hello._check(self.statuses.pop(0), "test")
        return data[1:]


@pytest.fixture
def key(monkeypatch):
    Key.statuses, Key.log = [], []
    monkeypatch.setattr(hello, "_Key", Key)
    monkeypatch.setattr(hello, "_PAUSE", 0)
    return Key


def test_wrapping_is_silent_and_unwrapping_always_asks(key):
    assert hello._unwrap(hello._wrap(b"k"), 7, "why") == b"k"
    assert key.log == ["silent", "may ask", ("ask", 7, "why")]


def test_a_busy_tpm_is_tried_again_but_not_for_ever(key):
    key.statuses = [0x8028008B - 2**32]         # as ctypes gives it: signed
    assert hello._unwrap(b"ek", 0, "") == b"k"
    key.statuses = [0x8028008B] * 9
    with pytest.raises(hello.Failed):
        hello._unwrap(b"ek", 0, "")
    assert len(key.statuses) == 6


def test_a_no_is_not_asked_again(key):
    for status in (0x80090036, 0x800704C7):
        key.statuses = [status] * 2
        with pytest.raises(hello.Cancelled):
            hello._unwrap(b"ek", 0, "")
        assert len(key.statuses) == 1
    key.statuses = [0x80090016] * 2
    with pytest.raises(hello.Failed, match="0x80090016"):
        hello._unwrap(b"ek", 0, "")
    assert len(key.statuses) == 1


def test_status_codes():
    hello._check(0, "fine")
    hello._check(0x80090005, "ignored", 0x80090005)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows")
def test_the_real_windows_calls_answer():
    """Set up or not, each of these must answer and not crash."""
    assert hello._user_sid().startswith("S-1-5-")
    if not hello.available():
        with pytest.raises(hello.Failed):
            hello._wrap(b"k" * 32)
    else:
        assert len(hello._wrap(b"k" * 32)) == 256


@pytest.mark.skipif(sys.platform != "win32", reason="Windows")
def test_the_key_calls_against_a_software_key(monkeypatch):
    """The same CNG calls, on a key Windows keeps for this test only."""
    import ctypes
    n = ctypes.WinDLL("ncrypt", winmode=0x800)
    name = "SecretSpace-test-" + os.urandom(8).hex()
    provider, made = ctypes.c_size_t(), ctypes.c_size_t()
    software = "Microsoft Software Key Storage Provider"
    assert n.NCryptOpenStorageProvider(
        ctypes.byref(provider), ctypes.c_wchar_p(software), 0) == 0
    assert n.NCryptCreatePersistedKey(
        provider, ctypes.byref(made), ctypes.c_wchar_p("RSA"),
        ctypes.c_wchar_p(name), 0, 0) == 0
    size = ctypes.c_ulong(2048)
    assert n.NCryptSetProperty(made, ctypes.c_wchar_p("Length"),
                               ctypes.byref(size), 4, 0) == 0
    try:
        assert n.NCryptFinalizeKey(made, 0x40) == 0
        monkeypatch.setattr(hello, "_PROVIDER", software)
        monkeypatch.setattr(hello, "_key_name", lambda: name)
        with hello._Key(silent=True) as key:
            secret = os.urandom(32)
            wrapped = key.encrypt(secret)
            assert len(wrapped) == 256 and secret not in wrapped
        with hello._Key(silent=False) as key:
            key._set("Use Context", "why".encode("utf-16-le") + bytes(2))
            assert key.decrypt(wrapped) == secret
            with pytest.raises(hello.Failed):
                key.decrypt(wrapped[:-1])
            with pytest.raises(hello.Failed):      # a setting that is refused
                key._set("Length", (2048).to_bytes(4, "little"))
    finally:
        assert n.NCryptDeleteKey(made, 0) == 0
        n.NCryptFreeObject(provider)
