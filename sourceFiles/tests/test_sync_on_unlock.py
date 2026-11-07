"""
Sync on unlock: a setting in Settings -> Sync, off by default (owner,
2026-11-06), and the guard that keeps a late sync result away from a vault
that was locked in the meantime.

No display needed: the app and its Tk root are stubbed.
"""

import queue

import pytest

import sync
import sync_client

sync_ui = pytest.importorskip("sync_ui",
                              reason="needs tkinter (bundled with Python)")
gui = pytest.importorskip("gui", reason="needs tkinter (bundled with Python)")


def configured(**extra):
    v = {"accounts": []}
    sync_client.set_settings(v, "http://127.0.0.1:8787", "token")
    v["sync"].update(extra)
    return v


# ---------------------------------------------------------------------------
# The setting
# ---------------------------------------------------------------------------
def test_off_by_default():
    assert sync_client.sync_on_unlock(configured()) is False


def test_on_once_switched_on_and_off_again():
    v = configured()
    sync_client.set_sync_on_unlock(v, True)
    assert sync_client.sync_on_unlock(v) is True
    sync_client.set_sync_on_unlock(v, False)
    assert sync_client.sync_on_unlock(v) is False


def test_never_on_without_a_server():
    """Switched on, then the settings went: nothing to sync with."""
    v = {"accounts": [], "sync": {"on_unlock": True}}
    assert sync_client.sync_on_unlock(v) is False
    assert sync_client.sync_on_unlock(None) is False


@pytest.mark.parametrize("value", ["yes", 1, "true", None])
def test_only_a_real_true_counts(value):
    assert sync_client.sync_on_unlock(configured(on_unlock=value)) is False


def test_editing_the_address_keeps_the_switch():
    v = configured()
    sync_client.set_sync_on_unlock(v, True)
    sync_client.set_settings(v, "http://10.0.0.9:8787", "new-token")
    assert sync_client.sync_on_unlock(v) is True


def test_a_merge_keeps_this_pcs_own_choice():
    """The other PC's copy says on; this PC said off. This PC's stays."""
    local = configured()
    merged = sync.merged_vault(local, [{"id": "a"}])
    assert sync_client.sync_on_unlock(merged) is False
    sync_client.set_sync_on_unlock(local, True)
    assert sync_client.sync_on_unlock(sync.merged_vault(local, [])) is True


# ---------------------------------------------------------------------------
# A sync that outlives its vault
# ---------------------------------------------------------------------------
class FakeRoot:
    def __init__(self):
        self.scheduled = queue.Queue()

    def after(self, _delay, callback):
        self.scheduled.put(callback)

    def run_next(self, timeout=5):
        self.scheduled.get(timeout=timeout)()


class FakeApp:
    def __init__(self):
        self.root = FakeRoot()
        self.toasts = []
        self.vault = configured()
        self.current_user = "alex"
        self.master_password = "pw"
        self._session = 1
        self._syncing = False
        self.refreshed = 0

    def toast(self, message, kind="info"):
        self.toasts.append((message, kind))

    def refresh_account_list(self):
        self.refreshed += 1

    def lock(self):
        """What lock_vault does to the state sync looks at."""
        self._session += 1
        self.vault = self.master_password = self.current_user = None


class FakeResult:
    conflicts = []

    def summary(self):
        return "1 change"


class FakeSession:
    password_changed = upgrade = base_ignored = False
    committed = []

    def __init__(self, *_args):
        pass

    def prepare(self, _vault, _password):
        return FakeResult()

    def has_work(self):
        return True

    def commit(self, _vault, _choices, _drop):
        FakeSession.committed.append(True)
        return {"accounts": [{"id": "merged"}], "sync": {}}


@pytest.fixture
def stub_network(monkeypatch):
    FakeSession.committed = []
    monkeypatch.setattr(sync_client, "client_for", lambda v: object())
    monkeypatch.setattr(sync_client, "SyncSession", FakeSession)


def test_an_ordinary_sync_still_lands(stub_network):
    app = FakeApp()
    sync_ui.run_sync(app)
    app.root.run_next()                 # prepare done -> commit
    app.root.run_next()                 # commit done
    assert app.vault == {"accounts": [{"id": "merged"}], "sync": {}}
    assert app._syncing is False and app.refreshed == 1
    assert app.toasts[-1] == ("Synced — 1 change", "info")


def test_locked_before_the_server_answered(stub_network):
    app = FakeApp()
    sync_ui.run_sync(app)
    app.lock()
    app.root.run_next()                 # the late prepare result
    assert app.vault is None
    assert FakeSession.committed == []  # nothing pushed for a locked vault
    assert app._syncing is False        # the next unlock can sync again
    assert app.root.scheduled.empty()


def test_locked_while_the_merge_was_being_pushed(stub_network):
    """The merged vault must not come back into memory behind the login
    screen -- it is on disk already."""
    app = FakeApp()
    sync_ui.run_sync(app)
    app.root.run_next()                 # prepare done -> commit started
    app.lock()
    app.root.run_next()                 # the late commit result
    assert app.vault is None and app.refreshed == 0
    assert app._syncing is False


def test_locked_and_another_vault_unlocked_meanwhile(stub_network):
    app = FakeApp()
    sync_ui.run_sync(app)
    app.root.run_next()
    app.lock()
    other = {"accounts": [{"id": "other-vault"}]}
    app.vault, app.current_user, app.master_password = other, "sam", "pw2"
    app._session += 1
    app.root.run_next()
    assert app.vault is other           # not replaced by alex's merge


def test_a_late_failure_after_lock_asks_nothing(monkeypatch):
    app = FakeApp()
    asked = []
    monkeypatch.setattr(sync_ui, "password_mismatch_dialog",
                        lambda *a, **k: asked.append(a))
    attempt = {"retry_allowed": True, "server_password": None,
               "drop_history": False, "from_prompt": False,
               "offline_hint": "", "session": app._session}
    app._syncing = True
    app.lock()
    sync_ui._sync_failed(app, sync_client.PasswordMismatch.__new__(
        sync_client.PasswordMismatch), attempt)
    assert asked == [] and app.toasts == [] and app._syncing is False


# ---------------------------------------------------------------------------
# The window: after unlock, and lock
# ---------------------------------------------------------------------------
class FakeWindow:
    _sync_after_unlock = gui.PasswordManagerGUI._sync_after_unlock
    lock_vault = gui.PasswordManagerGUI.lock_vault

    def __init__(self, on):
        self.root = FakeRoot()
        self.vault = configured(on_unlock=on)
        self.master_password = "pw"
        self.current_user = "alex"
        self._session = 1
        self._syncing = False
        self.syncs = []
        self.saves = 0
        self._clip_text = None

    def sync_now(self, **options):
        self.syncs.append(options)

    def _save(self, rekey=False):
        self.saves += 1
        return True

    def _cancel_idle_timer(self):
        pass

    def _cancel_totp(self):
        pass

    def show_login_screen(self):
        pass

    def toast(self, *a, **k):
        pass


def test_switched_off_unlock_does_not_sync():
    w = FakeWindow(on=False)
    w._sync_after_unlock()
    assert w.root.scheduled.empty() and w.syncs == []


def test_switched_on_unlock_syncs_once_the_window_is_up():
    w = FakeWindow(on=True)
    w._sync_after_unlock()
    assert w.syncs == []                # not inline: the window draws first
    w.root.run_next()
    assert len(w.syncs) == 1
    assert "can't be reached" in w.syncs[0]["offline_hint"]


def test_locked_before_the_delayed_start_means_no_sync():
    w = FakeWindow(on=True)
    w._sync_after_unlock()
    w.lock_vault()
    w.root.run_next()
    assert w.syncs == []


def test_lock_saves_normally():
    w = FakeWindow(on=False)
    w.lock_vault()
    assert w.saves == 1


def test_lock_does_not_save_over_a_running_sync():
    """Its save could land after the sync wrote the merged vault and put the
    pre-merge copy back on disk."""
    w = FakeWindow(on=True)
    w._syncing = True
    w.lock_vault()
    assert w.saves == 0 and w.vault is None


def test_a_vault_restored_onto_a_new_pc_starts_with_it_off():
    fetched = configured()
    sync_client.set_sync_on_unlock(fetched, True)      # the other PC's choice
    sync_ui._settings_for_restored(fetched, "http://10.0.0.9:8787", "t2")
    assert sync_client.sync_on_unlock(fetched) is False
    assert sync_client.get_settings(fetched)["url"] == "http://10.0.0.9:8787"
