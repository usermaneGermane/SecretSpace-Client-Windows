"""A worker thread must never free Tk fonts: it deadlocks the window.

Python's cycle collector runs in whichever thread allocates. If a worker
collects garbage that holds a Tk font, the font's __del__ calls Tk from the
worker and waits for the main thread; when the main thread is in
Thread.start() waiting for that same worker, both wait forever. Seen on Sync
(19 Nov 2026). widgets.collect_on_main_thread keeps collection on the Tk
thread.

The scenario runs in a child process with a time limit, so a deadlock fails
the test instead of hanging the suite.
"""

import os
import subprocess
import sys
import textwrap

import pytest

SOURCE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SCENARIO = textwrap.dedent("""
    import gc, sys, threading, tkinter as tk, tkinter.font as tkfont
    sys.path.insert(0, {source!r})
    try:
        root = tk.Tk()
    except tk.TclError:
        print("NO-DISPLAY"); sys.exit(0)
    root.withdraw()
    if {fixed}:
        import widgets
        widgets.collect_on_main_thread(root)

    class Holder:                       # a cycle, so only the collector frees it
        pass

    def worker(go):
        go.wait()                       # the main thread is in join() by now
        gc.set_threshold(1)             # the next allocation collects, HERE
        junk = [[object()] for _ in range(500)]
        gc.set_threshold(700)

    def run():
        for _ in range(5):
            was = gc.isenabled()
            gc.disable()                # make the garbage without collecting it
            for _ in range(20):
                h = Holder(); h.me = h; h.font = tkfont.Font(root=root, size=12)
            del h
            if was:
                gc.enable()
            go = threading.Event()
            t = threading.Thread(target=worker, args=(go,))
            t.start(); go.set(); t.join()
        gc.collect()
        print("DONE"); root.destroy()

    root.after(50, run)
    root.mainloop()
""")


def _run(fixed, timeout):
    script = SCENARIO.format(source=SOURCE, fixed=fixed)
    try:
        out = subprocess.run([sys.executable, "-c", script], capture_output=True,
                             text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    if "NO-DISPLAY" in out.stdout:
        pytest.skip("no display for Tk")
    return out.stdout.strip() or out.stderr.strip()[-300:]


def test_starting_threads_with_font_garbage_does_not_deadlock():
    assert _run(fixed=True, timeout=60) == "DONE"


def test_control_without_the_fix_the_scenario_deadlocks():
    # Proves the scenario above can see the bug at all. If Tk or Python
    # ever stop deadlocking here, this fails and the guard can be revisited.
    assert _run(fixed=False, timeout=20) == "TIMEOUT"


def test_automatic_collection_comes_back_when_the_window_goes():
    import gc
    import tkinter as tk
    import widgets
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display for Tk")
    root.withdraw()
    try:
        widgets.collect_on_main_thread(root, every_ms=10)
        assert not gc.isenabled()
    finally:
        root.destroy()
        restored = gc.isenabled()
        gc.enable()                     # never leave the suite without it
    assert restored
