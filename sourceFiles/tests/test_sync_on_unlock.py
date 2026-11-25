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
    _release_account = gui.PasswordManagerGUI._release_account
    _close_ai = gui.PasswordManagerGUI._close_ai
    ai_guard = None
    _holding = False

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

# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------
class FakeAccount:
    username, personal_id = "alex", "p"

    def __init__(self, on, server=True):
        self.info = {"sync_on_unlock": on}
        self.server = {"url": "http://s"} if server else None


def account_window(on, server=True):
    w = FakeWindow(on=False)
    w.vault = {"accounts": []}
    w.account = FakeAccount(on, server)
    return w


def test_an_account_syncs_at_unlock_only_when_asked_to():
    w = account_window(True)
    w._sync_after_unlock()
    assert w.syncs == []
    w.root.run_next()
    assert "can't be reached" in w.syncs[0]["offline_hint"]
    for w in (account_window(None), account_window(False),
              account_window("yes"), account_window(True, server=False)):
        w._sync_after_unlock()
        assert w.root.scheduled.empty()


def test_the_choice_is_kept_on_this_device(tmp_path, monkeypatch):
    import account_crypto
    import account_sync
    import accounts
    monkeypatch.setenv("SECRETSPACE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(account_crypto, "ARGON2_MEMORY_KIB", 64)
    monkeypatch.setattr(account_crypto, "ARGON2_PASSES", 1)
    account = accounts.prepare_account("alex", "a long password").save()
    account.set_server("http://10.0.0.1:1")
    assert not account_sync.sync_on_unlock(account)
    account_sync.set_sync_on_unlock(account, True)
    again = accounts.unlock("alex", "a long password")
    assert account_sync.sync_on_unlock(again)
    again.set_server(None)
    assert not account_sync.sync_on_unlock(again)
    account_sync.set_sync_on_unlock(again, False)
    again.set_server("http://10.0.0.1:1")
    assert not account_sync.sync_on_unlock(again)


class SyncApp:
    """Just enough of the app for account_sync_ui.run_sync."""

    def __init__(self):
        self.account = FakeAccount(True)
        self.vaults = {"p": {"accounts": []}}
        self.vault = self.vaults["p"]
        self._session, self._syncing = 1, False
        self.toasts = []

    def toast(self, message, kind="info"):
        self.toasts.append((message, kind))

    def load_vaults(self):
        pass

    def refresh_account_list(self):
        pass

    def vault_name(self, vault_id):
        return "Personal"

    def set_vault_data(self, vault_id, data, saved=False):
        pass

    def finish_moves(self):
        return []


def run_account_sync(monkeypatch, error=None, conflicts=(), **options):
    import account_sync
    import account_sync_ui
    asked, committed = [], []

    class Server:
        def logout(self):
            pass

    class One:
        first_push = base_ignored = False

        def __init__(self, *a):
            pass

        def prepare(self, data):
            return type("R", (), {"conflicts": list(conflicts),
                                  "summary": lambda self: "x"})()

        def has_work(self):
            return True

        def commit(self, data, choices=None):
            committed.append(choices)
            return data

    def logged_in(account):
        if error:
            raise error
        return Server()

    def at_once(app, work, done, on_error):
        try:
            got = work()
        except Exception as e:
            return on_error(e)
        done(got)
    monkeypatch.setattr(account_sync, "logged_in", logged_in)
    monkeypatch.setattr(account_sync, "reconcile_vaults",
                        lambda a, s: account_sync.VaultChanges())
    monkeypatch.setattr(account_sync, "syncable_vaults", lambda a, s: ["p"])
    monkeypatch.setattr(account_sync, "AccountSync", One)
    monkeypatch.setattr(account_sync_ui, "_in_background", at_once)
    monkeypatch.setattr(account_sync_ui, "_convert_step",
                        lambda app, run, attempt: account_sync_ui._all_done(app, run))
    monkeypatch.setattr(account_sync_ui, "conflict_dialog",
                        lambda *a: asked.append(1) or None)
    app = SyncApp()
    account_sync_ui.run_sync(app, **options)
    assert app._syncing is False
    return app, asked, committed


def test_a_server_out_of_reach_is_a_hint_at_unlock_and_an_error_otherwise(monkeypatch):
    down = sync_client.ServerUnreachable("no route")
    app, _, _ = run_account_sync(monkeypatch, down, offline_hint="Not synced")
    assert app.toasts[-1] == ("Not synced", "warn")
    app, _, _ = run_account_sync(monkeypatch, down)
    assert app.toasts[-1] == ("no route", "error")
    app, _, _ = run_account_sync(monkeypatch, sync_client.SyncError("bad"),
                                 offline_hint="Not synced")
    assert app.toasts[-1] == ("bad", "error")


def test_a_conflict_is_not_asked_about_at_unlock(monkeypatch):
    app, asked, committed = run_account_sync(
        monkeypatch, conflicts=[1], offline_hint="x")
    assert not asked and not committed
    assert "press Sync" in app.toasts[-1][0] and app.toasts[-1][1] == "warn"
    app, asked, committed = run_account_sync(monkeypatch, conflicts=[1])
    assert asked and not committed                      # asked, and cancelled
    app, asked, committed = run_account_sync(monkeypatch, offline_hint="x")
    assert committed


# ---------------------------------------------------------------------------
# The shared mark
# ---------------------------------------------------------------------------
def test_a_row_is_built_again_when_its_vault_becomes_shared():
    class Window:
        _row_label = gui.PasswordManagerGUI._row_label
        _row_mark = gui.PasswordManagerGUI._row_mark
        _row_shared = gui.PasswordManagerGUI._row_shared
        vaults, vault_filter, _entry_vault = {"p": {}}, None, {"e": "p"}
        account = type("A", (), {"shared": False,
                                 "is_shared": lambda s, v: s.shared})()
    w, entry = Window(), {"id": "e", "site": "Mail"}
    assert not w._row_shared(entry)
    before = gui._row_signature(entry, w._row_mark(entry))
    w.account.shared = True
    assert w._row_shared(entry)
    assert gui._row_signature(entry, w._row_mark(entry)) != before
