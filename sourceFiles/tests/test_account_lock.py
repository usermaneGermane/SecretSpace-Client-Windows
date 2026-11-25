"""One program at a time in an account."""

import os
import subprocess
import sys
import types

import pytest

import account_lock
import gui
import sync_ui

SOURCE = os.path.dirname(os.path.abspath(account_lock.__file__))


@pytest.fixture(autouse=True)
def data(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRETSPACE_DATA_DIR", str(tmp_path / "data"))


def elsewhere(code):
    """Run ``code`` in another process; what it printed."""
    done = subprocess.run(
        [sys.executable, "-c", f"import sys; sys.path.insert(0, {SOURCE!r})\n"
         "import account_lock\n" + code],
        capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


TRY = ("try:\n    account_lock.take('alice')\n    print('free')\n"
       "except account_lock.Busy:\n    print('busy')\n")


def test_another_process_is_kept_out_until_it_is_released():
    hold = account_lock.take("alice")
    assert elsewhere(TRY) == "busy"
    assert elsewhere(TRY.replace("alice", "bob")) == "free"
    hold.release()
    assert elsewhere(TRY) == "free"


def test_so_is_another_holder_in_this_process():
    with account_lock.take("alice"):
        with pytest.raises(account_lock.Busy):
            account_lock.take("alice", wait=0.1)
    account_lock.take("alice").release()


def test_a_program_that_died_holds_nothing():
    assert elsewhere("import os\nh = account_lock.take('alice')\n"
                     "print('had it', flush=True)\nos._exit(0)") == "had it"
    account_lock.take("alice").release()


def test_every_holder_has_to_let_go():
    hold = account_lock.take("alice")
    assert hold.retain()
    hold.release()
    with pytest.raises(account_lock.Busy):
        account_lock.take("alice")
    hold.release()
    account_lock.take("alice").release()
    assert not hold.retain()
    hold.release()                                  # once more does no harm


def test_waiting_gets_it_when_it_comes_free():
    import threading
    hold = account_lock.take("alice")
    threading.Timer(0.3, hold.release).start()
    account_lock.take("alice", wait=10).release()


def test_without_such_locks_it_works_as_before(monkeypatch):
    def none(file):
        raise OSError(95, "not supported")
    monkeypatch.setattr(account_lock, "_lock", none)
    account_lock.take("alice").release()


def test_a_lock_file_is_not_an_account():
    import accounts
    account_lock.take("alice").release()
    assert accounts.list_accounts() == []


# --- the app -----------------------------------------------------------------
def test_locking_the_app_lets_go(monkeypatch):
    from test_sync_on_unlock import FakeWindow
    w = FakeWindow(False)
    w._hold, w._holding = account_lock.take("alice"), True
    w.lock_vault()
    assert elsewhere(TRY) == "free"


class Window:
    _hold = gui.PasswordManagerGUI._hold
    _holding = gui.PasswordManagerGUI._holding
    _hold_account = gui.PasswordManagerGUI._hold_account
    _release_account = gui.PasswordManagerGUI._release_account
    unlock_vault = gui.PasswordManagerGUI.unlock_vault
    open_account = gui.PasswordManagerGUI.open_account

    def __init__(self, opens=True):
        self.account, self._login_user = None, "alice"
        self.errors, self.opens, self.tried = [], opens, 0
        self._login_error = self.errors.append
        self.toast = lambda m, k="": self.errors.append(m)

    def _unlock_vault(self, secret, password=None):
        self.tried += 1
        if self.opens:
            self.account = object()

    def lock(self):
        self.account = None
        self._release_account()


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch):
    real = account_lock.take            # (3 s, the app's, is too long here)
    monkeypatch.setattr(account_lock, "take", lambda u, wait=0:
                        real(u, 0 if wait == 3 else wait))


def test_the_app_holds_an_open_account_and_only_that():
    w = Window()
    w.unlock_vault()
    assert elsewhere(TRY) == "busy"
    w.lock()
    assert elsewhere(TRY) == "free"
    wrong = Window(opens=False)
    wrong.unlock_vault()
    assert wrong.tried == 1 and elsewhere(TRY) == "free"


def test_a_second_window_says_it_is_in_use():
    one, two = Window(), Window()
    one.unlock_vault()
    two.unlock_vault()
    assert two.tried == 0 and two.account is None and "in use" in two.errors[0]
    two.open_account(types.SimpleNamespace(username="alice"), {}, "pw")
    assert two.account is None and len(two.errors) == 2
    one.lock()
    two.unlock_vault()
    assert two.account


def test_another_account_lets_the_first_one_go():
    w = Window()
    w.unlock_vault()
    w.account, w._login_user = None, "bob"
    w.unlock_vault()
    assert elsewhere(TRY) == "free"
    assert elsewhere(TRY.replace("alice", "bob")) == "busy"


def test_a_sync_that_outlives_the_lock_keeps_the_account():
    import threading
    go, seen = threading.Event(), threading.Event()
    w = Window()
    w.root = types.SimpleNamespace(after=lambda *_: seen.set())
    w.unlock_vault()
    sync_ui._in_background(w, go.wait, None, None)
    w.lock()
    assert elsewhere(TRY) == "busy"
    # This window itself gets back in meanwhile, and holds it afterwards.
    w.unlock_vault()
    assert w.account
    go.set()
    assert seen.wait(10)
    assert elsewhere(TRY) == "busy"
    w.lock()
    for _ in range(50):
        if elsewhere(TRY) == "free":
            break
    else:
        pytest.fail("never let go")
