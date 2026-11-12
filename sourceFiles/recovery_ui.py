"""
The recovery screens (phase 5): "Forgot your master password?" on the login
screen, and Settings -> New recovery phrase.

Recovery is three or four short steps, reusing the windows that make an
account: (1) the account and its 12 words, (2) a new master password,
(3) a new Emergency Kit when a new Secret Key was needed, (4) the new
phrase, written down and checked. Nothing is written before the last step.

The network and Argon2id run on a worker thread (sync_ui._in_background);
widgets are touched only on the main one.
"""

import customtkinter as ctk

import account_crypto
import accounts
import dialogs
import recovery
from sync_ui import _in_background
from theme import F, MUTED, DANGER, TEXT, BORDER, INPUT_BG, MONO
from widgets import note, error_label, dialog_shell, field, field_label


def _words_box(parent, width):
    box = ctk.CTkTextbox(parent, height=92, wrap="word", fg_color=INPUT_BG,
                         border_width=1, border_color=BORDER, text_color=TEXT,
                         corner_radius=10,
                         font=ctk.CTkFont(family=MONO, size=14))
    box.pack(fill="x")
    return box


# ==========================================================================
# Forgot your master password?
# ==========================================================================
def recover_dialog(app, username=""):
    """Step 1: the account and its 12 words."""
    top = app._modal("Recover an account", 500, 700)
    shell = dialog_shell(
        top, "Forgot your master password?",
        "Your 12-word recovery phrase opens the account again. You then set "
        "a new master password and get a new phrase; the old one stops "
        "working.")
    wrap = shell.body
    user_entry = app._field(wrap, "Account name")
    if username:
        user_entry.insert(0, username)
    field_label(wrap, "Recovery phrase (12 words, in order)")
    words = _words_box(wrap, shell.text_width)
    url_entry = field(wrap, "Server address (only if this PC does not have "
                      "the account)", placeholder="http://192.168.1.50:8787")
    note(wrap, "On a PC that already has the account, the phrase is all it "
         "takes. On a new PC, the account comes from its server.",
         shell.text_width, size=11, pady=(8, 0))
    err = error_label(wrap, shell.text_width)
    busy = {"on": False}

    def go():
        if busy["on"]:
            return
        name = user_entry.get().strip()
        phrase = " ".join(words.get("1.0", "end").split())
        busy["on"] = True
        err.configure(text="Opening the account — this takes a moment…",
                      text_color=MUTED)

        def done(opened):
            busy["on"] = False
            if top.winfo_exists():
                top.destroy()
            _password_step(app, opened)

        def failed(e):
            busy["on"] = False
            if top.winfo_exists():
                err.configure(text=str(e), text_color=DANGER)

        _in_background(app, lambda: recovery.open_with_phrase(
            name, phrase, url_entry.get()), done, on_error=failed)

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=110).pack(side="left")
    app._accent_button(shell.buttons, "Next", go, width=150).pack(side="right")
    top.bind("<Escape>", lambda e: top.destroy())
    top.after(200, (words if username else user_entry).focus)
    app._fit_modal(top)


def _password_step(app, opened):
    """Step 2: a new master password."""
    top = app._modal("New master password", 460, 520)
    shell = dialog_shell(
        top, "A new master password",
        f"The phrase opened “{opened.username}”. Choose the master password "
        "it opens with from now on.")
    wrap = shell.body
    pw_entry = app._field(wrap, "New master password", show="•")
    bar, label, update_strength = app._strength_widget(wrap)
    confirm_entry = app._field(wrap, "Confirm password", show="•")
    pw_entry.bind("<KeyRelease>", lambda e: update_strength(pw_entry.get()))
    if opened.server:
        note(wrap, "Your other devices then sign in again with it (Sign in "
             "from a server).", shell.text_width, size=11, pady=(10, 0))
    err = error_label(wrap, shell.text_width)
    busy = {"on": False}

    def go():
        if busy["on"]:
            return
        p, c = pw_entry.get(), confirm_entry.get()
        if len(p) < 8:
            return err.configure(text="Use at least 8 characters.",
                                 text_color=DANGER)
        if p != c:
            return err.configure(text="Passwords do not match.",
                                 text_color=DANGER)
        busy["on"] = True
        err.configure(text="Preparing…", text_color=MUTED)

        def done(pending):
            busy["on"] = False
            if top.winfo_exists():
                top.destroy()
            flow = _RecoveryFlow(pending)
            if pending.new_secret:
                dialogs._emergency_kit_dialog(app, flow, p)
            else:
                dialogs._phrase_dialog(app, flow, p)

        def failed(e):
            busy["on"] = False
            if top.winfo_exists():
                err.configure(text=str(e), text_color=DANGER)

        _in_background(app, lambda: recovery.prepare(opened, p), done,
                       on_error=failed)

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=110).pack(side="left")
    app._accent_button(shell.buttons, "Next", go, width=150).pack(side="right")
    for e in (pw_entry, confirm_entry):
        e.bind("<Return>", lambda ev: go())
    top.after(200, pw_entry.focus)


class _RecoveryFlow:
    """What the kit and phrase windows of dialogs.py need, for a recovery."""

    kit_subtitle = ("This PC could not keep your old Secret Key, so the "
                    "account gets a new one. With your new master password "
                    "it opens the account on your other devices. The old "
                    "kit stops working.")
    phrase_subtitle = ("Your NEW recovery phrase. The old one stops working "
                       "when you finish. Write these on paper, in order.")
    finish_label = "Recover account"

    def __init__(self, pending):
        self.pending = pending
        self.username = pending.username
        self.secret_key_text = pending.secret_key_text
        self.recovery_phrase = pending.recovery_phrase

    def finish(self, app, top, err):
        err.configure(text="Recovering — this takes a moment…",
                      text_color=MUTED)

        def done(payload):
            account, loaded = payload
            if top.winfo_exists():
                top.destroy()
            app.open_account(account, loaded, self.pending.password)
            app.toast(f"“{account.username}” recovered — your new master "
                      "password and phrase are in use")

        def failed(e):
            if top.winfo_exists():
                err.configure(text=str(e), text_color=DANGER)

        _in_background(app, self.pending.save, done, on_error=failed)


# ==========================================================================
# Settings -> New recovery phrase
# ==========================================================================
class _NewPhraseFlow:
    phrase_subtitle = ("Your NEW recovery phrase. The old one stops working "
                       "when you finish. Write these on paper, in order.")
    finish_label = "Use the new phrase"

    def __init__(self, account):
        self.pending = recovery.NewPhrase(account)
        self.username = account.username
        self.recovery_phrase = self.pending.recovery_phrase

    def finish(self, app, top, err):
        err.configure(text="Saving…", text_color=MUTED)

        def done(_):
            if top.winfo_exists():
                top.destroy()
            app.toast("New recovery phrase in use — the old one opens "
                      "nothing any more")

        def failed(e):
            if top.winfo_exists():
                err.configure(text=f"Nothing was changed: {e}",
                              text_color=DANGER)

        _in_background(app, self.pending.save, done, on_error=failed)


def new_phrase_dialog(app):
    if app.account is None:
        return
    if not dialogs.ask_master_password(
            app, "New recovery phrase",
            "Make a new 12-word phrase if the old one was lost or someone may "
            "have seen it. The old phrase stops working. Enter your master "
            "password to continue.", action="Continue"):
        return
    dialogs._phrase_dialog(app, _NewPhraseFlow(app.account), app.master_password)
