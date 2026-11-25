"""
AI agents: the window that asks, and the one that marks a vault (ai_access).

Questions come in on worker threads; widgets are touched only on the main
one. Nothing is ever allowed without a click in the window, not even twice
the same.
"""

import threading

import customtkinter as ctk

import ai_access
from history_ui import local_time
from theme import T, SP, R, F, MONO, TEXT, MUTED, BORDER, INPUT_BG
from widgets import (accent_button, danger_button, dialog_shell, ghost_button,
                     note)

#: Allow cannot be pressed at once: a click meant for something else, as the
#: window appears, must not count.
WAIT_MS = 1500


def printable(text) -> str:
    """Nothing in what an AI sends may hide what will run."""
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}"
                   for c in str(text))


def shown_command(command) -> str:
    """Each argument on its own line: how they are split cannot be faked."""
    return "\n".join(("    " if i else "") + printable(c)
                     for i, c in enumerate(command))


class Guard:
    """Answers AI agents while an account is open."""

    def __init__(self, app):
        self.app = app
        self.account = app.account
        self._door = None
        self._closed = False
        self._one = threading.Lock()         # one window at a time
        self._pending = None

    def refresh(self):
        """Open or close the door as the marks say."""
        wanted = bool(not self._closed and
                      ai_access.allowed_vaults(self.account))
        if wanted and self._door is None:
            try:
                self._door = ai_access.Door(self.account.username, self._answer)
            except OSError as e:
                self.app.toast(f"AI agents cannot connect: {e}", "error")
        elif not wanted and self._door is not None:
            self._door.close()
            self._door = None

    def close(self):
        """The account is locked: no more answers, and no window left."""
        self._closed = True
        self.refresh()
        if self._pending is not None:
            self._pending(False)

    # -- on a worker thread ----------------------------------------------------
    def _on_main(self, work, seconds):
        """Run ``work(done)`` on the main thread; what it gave ``done``."""
        result, ready = [], threading.Event()

        def done(value):
            if not result:
                result.append(value)
                ready.set()

        try:
            self.app.root.after(0, lambda: work(done))
        except RuntimeError:
            raise ai_access.Refused("SecretSpace is closing.") from None
        if not ready.wait(seconds):
            raise ai_access.Refused("SecretSpace did not answer.")
        if isinstance(result[0], ai_access.Refused):
            raise result[0]
        return result[0]

    def _answer(self, request):
        if request.get("ask") == "list":
            return self._on_main(self._list(request), 10)
        if request.get("ask") == "use":
            wanted = ai_access.check_request(request)
            if not self._one.acquire(blocking=False):
                raise ai_access.Refused("SecretSpace is asking the user about "
                                        "another request. Try again after it.")
            try:
                return self._on_main(lambda done: self._use(wanted, done),
                                     ai_access.DECIDE_SECONDS + 5)
            finally:
                self._one.release()
        raise ai_access.Refused("The question was not understood.")

    # -- on the main thread ------------------------------------------------------
    def _safely(self, done, work):
        """Whatever goes wrong is a no, not a program left waiting."""
        try:
            if self._closed or self.app.account is not self.account:
                raise ai_access.Refused("SecretSpace was locked.")
            return work()
        except ai_access.Refused as e:
            done(e)
        except Exception:
            done(ai_access.Refused("Something went wrong in SecretSpace."))

    def _log(self, client, what, result):
        try:
            ai_access.add_to_log(self.account, client, what, result)
        except Exception:
            self.app.toast("The AI log could not be written", "error")

    def _list(self, request):
        def work(done):
            def go():
                entries = ai_access.describe(self.account, self.app.vaults)
                self._log(str(request.get("client") or "unknown")[:60],
                          f"listed {len(entries)} entries", "no secrets")
                done({"entries": entries})
            self._safely(done, go)
        return work

    def _use(self, wanted, done):
        def go():
            found = ai_access.find_entries(self.account, self.app.vaults,
                                           wanted["env"])
            what = "run: " + " ".join(wanted["command"])[:300] + "  with " + \
                ", ".join(f"{wanted['env'][n]['field']} of "
                          f"“{found[n][1]['site']}”" for n in found)

            def decided(yes):
                if self._pending is None:
                    return
                self._pending = None

                def finish():
                    if not yes:
                        self._log(wanted["client"], what, "refused")
                        raise ai_access.Refused("The user did not allow it.")
                    # As they are now: a sync may have changed or removed them
                    # while the window was open.
                    values = ai_access.values_of(ai_access.find_entries(
                        self.account, self.app.vaults, wanted["env"]),
                        wanted["env"])
                    self._log(wanted["client"], what, "allowed")
                    done({"values": values})
                self._safely(done, finish)

            self._pending = request_window(self.app, wanted, found, decided)
        self._safely(done, go)


def request_window(app, wanted, found, decided):
    """
    Ask the user about one command. ``decided(True/False)`` is called once;
    closing the window, or no answer in time, is a no. Returns a function
    that ends it.
    """
    top = app._modal("An AI agent asks", 600, 640)
    shell = dialog_shell(
        top, "Allow this command?",
        f"“{printable(wanted['client'])}” wants to run a command on this "
        "device with credentials of yours. It can do anything with them: "
        "allow it only if you know what it does.", scroll=True)
    width = shell.text_width
    state = {"over": False}

    def end(yes):
        if state["over"]:
            return
        state["over"] = True
        if top.winfo_exists():
            top.destroy()
        decided(yes)

    if wanted["reason"]:
        note(shell.body, "It says: " + printable(wanted["reason"]), width,
             color=TEXT, size=T.label, pady=(SP.m, SP.s))
    parts = len(wanted["command"])
    note(shell.body, f"Command, {parts} part{'' if parts == 1 else 's'}", width,
         pady=(SP.m, SP.xs))
    box = ctk.CTkTextbox(shell.body, height=150, corner_radius=R.inner,
                         fg_color=INPUT_BG, border_color=BORDER, border_width=1,
                         font=ctk.CTkFont(family=MONO, size=T.small))
    box.insert("1.0", shown_command(wanted["command"]))
    box.configure(state="disabled")
    box.pack(fill="x")
    note(shell.body, "in  " + printable(wanted["cwd"] or "(its own folder)"),
         width, pady=(SP.xs, SP.m))
    note(shell.body, "It gets", width, pady=(SP.s, SP.xs))
    for name, (vault_id, entry) in found.items():
        note(shell.body,
             f"{wanted['env'][name]['field']} of “{printable(entry['site'])}”"
             + (f" ({printable(entry['username'])})" if entry["username"] else "")
             + f"  —  vault “{printable(app.vault_name(vault_id))}”, as {name}",
             width, color=TEXT, size=T.label, pady=(0, SP.xs))

    # Refuse is the easy one; Allow has no key and waits a moment.
    ghost_button(shell.buttons, "Refuse", lambda: end(False),
                 width=120).pack(side="left")
    allow = danger_button(shell.buttons, "Allow once", lambda: end(True),
                          width=150)
    allow.pack(side="right")
    allow.configure(state="disabled")
    top.after(WAIT_MS, lambda: allow.winfo_exists()
              and allow.configure(state="normal"))
    left = ctk.CTkLabel(shell.buttons, text="", font=F(T.small),
                        text_color=MUTED)
    left.pack(side="right", padx=SP.m)

    def tick(seconds):
        if not top.winfo_exists():
            return
        if seconds <= 0:
            return end(False)
        left.configure(text=f"{seconds} s")
        top.after(1000, lambda: tick(seconds - 1))

    tick(ai_access.DECIDE_SECONDS)
    top.protocol("WM_DELETE_WINDOW", lambda: end(False))
    top.bind("<Escape>", lambda e: end(False))
    # However it is destroyed (with the main window, by a lock): a no.
    top.bind("<Destroy>", lambda e: e.widget is top and end(False))
    # Seen also when the app is behind the AI tool's window.
    try:
        app.root.deiconify()
        top.lift()
        top.attributes("-topmost", True)
        top.bell()
    except Exception:
        pass
    return end


def vault_dialog(app, vault_id, changed=lambda: None):
    """Mark a vault for AI on this device, and see what was asked."""
    import dialogs                       # late: it imports this module's users
    account = app.account
    name = app.vault_name(vault_id)
    on = vault_id in ai_access.allowed_vaults(account)
    top = app._modal("AI agents", 600, 640)
    shell = dialog_shell(
        top, f"AI agents and “{name}”",
        "An AI agent on this device can use what is in this vault for a "
        "command, while the app is unlocked." if on else
        "Not available to AI agents.", scroll=True)
    width = shell.text_width
    for text in (
            "The agent sees the entries' names, usernames and web addresses, "
            "never a password, 2FA code or note.",
            "For each command that needs one, SecretSpace shows you the "
            "command and asks. An allowed command gets the values as "
            "environment variables; they are taken out of its output, but a "
            "command can always send them elsewhere.",
            "The mark is for this device only. Keep what agents may use in a "
            "vault of its own."):
        note(shell.body, "•  " + text, width, color=TEXT, size=T.label,
             pady=(SP.s, 0))
    if account.is_shared(vault_id):
        note(shell.body, "•  This vault is shared: its other members' logins "
             "are in it too.", width, color=TEXT, size=T.label, pady=(SP.s, 0))
    note(shell.body, "To connect an agent, have it start:  secretspace-cli mcp",
         width, size=T.label, pady=(SP.m, SP.m))
    note(shell.body, "What was asked on this device, in every vault, newest "
         "first", width, pady=(SP.m, SP.xs))
    lines = list(reversed(ai_access.read_log(account)))[:50]
    for line in lines:
        note(shell.body, f"{local_time(line.get('at', ''))}   "
             f"{printable(line.get('client', ''))}   "
             f"{printable(line.get('result', ''))}\n"
             f"{printable(line.get('what', ''))}", width, color=TEXT,
             pady=(SP.xs, SP.xs))
    if not lines:
        note(shell.body, "Nothing yet.", width)

    def switch():
        if not on and not dialogs.ask_master_password(
                app, f"Make “{name}” available to AI agents",
                "Every use is still asked about. Enter your master password "
                "to confirm.", action="Make available"):
            return
        if app.account is not account:
            return                       # locked meanwhile
        ai_access.allow_vault(account, vault_id, not on)
        app.ai_guard.refresh()
        top.destroy()
        changed()
        app.toast(f"“{name}” is " + ("no longer" if on else "now") +
                  " available to AI agents")

    ghost_button(shell.buttons, "Close", top.destroy, width=110).pack(side="left")
    accent_button(shell.buttons, "Stop" if on else "Make available…", switch,
                  width=170).pack(side="right")
    top.bind("<Escape>", lambda e: top.destroy())
