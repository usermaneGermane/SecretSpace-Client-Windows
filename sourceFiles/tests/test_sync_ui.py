"""
The worker-thread plumbing behind the sync screens.

No tkinter here: the app and its root are stubbed, which is enough to pin the
marshalling contract and lets these run on a machine with no display.
"""

import queue

import pytest

# sync_ui pulls in customtkinter, which needs tkinter. tkinter ships with
# Python, so this only bites on a stripped-down interpreter -- skip rather
# than fail the whole suite there.
sync_ui = pytest.importorskip("sync_ui",
                              reason="needs tkinter (bundled with Python)")


class FakeRoot:
    """Stands in for a Tk root: records what `after` was asked to run."""

    def __init__(self):
        self.scheduled = queue.Queue()

    def after(self, _delay, callback):
        self.scheduled.put(callback)

    def run_next(self, timeout=5):
        """Run the next queued callback, the way the Tk main loop would."""
        self.scheduled.get(timeout=timeout)()


class FakeApp:
    def __init__(self):
        self.root = FakeRoot()
        self.toasts = []

    def toast(self, message, kind="info"):
        self.toasts.append((message, kind))


def test_a_result_is_handed_back_on_the_main_thread():
    app = FakeApp()
    seen = []

    sync_ui._in_background(app, lambda: "payload", seen.append,
                           on_error=lambda e: seen.append(("error", e)))
    app.root.run_next()

    assert seen == ["payload"]


def test_a_failure_reaches_on_error_with_the_exception_intact():
    """
    Regression: the handler closed over the name bound by `except ... as e`.
    Python deletes that name when the block ends, so by the time `after` ran
    the lambda it raised NameError instead -- every network error in the sync
    screens was swallowed, leaving the dialog saying "Contacting the
    server..." with nothing to show for it.
    """
    app = FakeApp()
    boom = RuntimeError("the VPN is down")
    seen = []

    def work():
        raise boom

    sync_ui._in_background(app, work, done=lambda r: seen.append(("ok", r)),
                           on_error=lambda e: seen.append(("error", e)))
    app.root.run_next()

    assert seen == [("error", boom)]


def test_work_runs_off_the_calling_thread():
    """Blocking the Tk thread is what freezes the window on a flaky VPN."""
    import threading

    app = FakeApp()
    where = {}

    def work():
        where["thread"] = threading.current_thread().name
        return None

    sync_ui._in_background(app, work, done=lambda r: None,
                           on_error=lambda e: None)
    app.root.run_next()

    assert where["thread"] != threading.current_thread().name


@pytest.mark.parametrize("failure", [
    RuntimeError("plain"),
    OSError("socket went away"),
    ValueError("nonsense from the server"),
])
def test_any_exception_type_is_reported_rather_than_escaping(failure):
    app = FakeApp()
    seen = []

    def work():
        raise failure

    sync_ui._in_background(app, work, done=lambda r: seen.append(r),
                           on_error=lambda e: seen.append(e))
    app.root.run_next()

    assert seen == [failure]
