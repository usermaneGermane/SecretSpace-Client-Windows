"""
Locking the vault leaves a copied password on the clipboard.

The auto-clear timer started by the copy keeps running, so the password can
still be pasted after a lock until that timer fires.
"""

import pytest

gui = pytest.importorskip("gui", reason="needs tkinter (bundled with Python)")


class FakeRoot:
    def __init__(self):
        self.cancelled = []

    def after_cancel(self, job):
        self.cancelled.append(job)


class FakeApp:
    """Just enough of PasswordManagerGUI for lock_vault to run."""

    lock_vault = gui.PasswordManagerGUI.lock_vault

    def __init__(self):
        self.root = FakeRoot()
        self.master_password = None     # nothing unlocked → no save
        self.current_user = None
        self.vault = {}
        self._clip_text = "s3cret"
        self._clip_job = "clear-job"
        self.cleared = []

    def _cancel_idle_timer(self):
        pass

    def show_login_screen(self):
        pass

    def toast(self, message, kind="info"):
        pass

    def _clear_clipboard(self, expected, quiet=False):
        self.cleared.append(expected)


@pytest.mark.parametrize("auto", [False, True])
def test_lock_keeps_the_copied_password_and_its_timer(auto):
    app = FakeApp()

    app.lock_vault(auto=auto)

    assert app.cleared == []
    assert app.root.cancelled == []
    assert app._clip_job == "clear-job"
    assert app._clip_text == "s3cret"
