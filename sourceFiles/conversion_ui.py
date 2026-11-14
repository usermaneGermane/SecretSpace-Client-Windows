"""
The windows of a conversion from SecretSpace 3.

An account made by SecretSpace 3 is written again in the current format the
first time it is unlocked here (accounts.convert). Two questions go with it:

* before -- "this account will be converted", with the chance to save a
  copy first, because SecretSpace 3 cannot open it afterwards;
* after -- the 12 recovery words, once, to convert the recovery copy too:
  that copy opens only with the words, which the app does not have.

And one notice, at start: what happened to the data folder of the old name
(vault.settle_home).
"""

import customtkinter as ctk
from tkinter import filedialog

import accounts
import recovery
import vault
from sync_ui import _in_background
from theme import F, MUTED, GREEN
from widgets import dialog_shell, error_label, field_label, note


def ask_conversion(app, username, on_server=False) -> bool:
    """
    Tell the user their account is about to be converted and let them save
    a copy first. True to go ahead, False to stay locked (nothing changed).
    ``on_server``: asked while signing in from a server, where it is the
    server's copy of the account that gets converted.
    """
    top = app._modal("Convert this account", 520, 420)
    shell = dialog_shell(
        top, f"“{username}” will be converted",
        "This account was made with SecretSpace 3. This version keeps "
        "accounts in a new format, and converts yours now. Your entries, "
        "vaults, master password and recovery phrase stay the same.")
    wrap = shell.body
    note(wrap, "Afterwards SecretSpace 3.0 and 3.1 can no longer open this "
         "account. If you use it on other devices, update SecretSpace there "
         "too before you sync them again.", shell.text_width, pady=(0, 10))
    has_copy = accounts.account_exists(username)
    if on_server:
        note(wrap, "Signing in converts the account on the server now. A "
             "device that still runs SecretSpace 3 cannot sync it after "
             "that until it is updated.", shell.text_width, size=11,
             pady=(0, 8))
    if has_copy:
        note(wrap, "To be able to go back, save a copy of the account as it "
             "is on this PC now. It is a folder of encrypted files; keep it "
             "or delete it as you like.", shell.text_width, size=11)
    saved = ctk.CTkLabel(wrap, text="", font=F(11), text_color=GREEN,
                         wraplength=shell.text_width, justify="left")
    saved.pack(anchor="w", pady=(8, 0))
    err = error_label(wrap, shell.text_width)
    out = {"go": False}

    def save_copy():
        folder = filedialog.askdirectory(
            parent=top, title="Where to save a copy of the account")
        if not folder:
            return
        try:
            made = accounts.copy_account_folder(username, folder)
        except Exception as e:                       # noqa: BLE001 - shown
            saved.configure(text="")
            err.configure(text=f"The copy was not saved: {e}")
            return
        err.configure(text="")
        saved.configure(text=f"Copy saved in {made}")

    def convert():
        out["go"] = True
        top.destroy()

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=100).pack(side="left")
    app._accent_button(shell.buttons, "Convert", convert,
                       width=120).pack(side="right")
    if has_copy:
        app._ghost_button(shell.buttons, "Save a copy first…", save_copy,
                          width=170).pack(side="right", padx=(0, 8))
    top.bind("<Escape>", lambda e: top.destroy())
    app.root.wait_window(top)
    return out["go"]


def offer_recovery_conversion(app, asked=False):
    """
    Ask once for the 12 recovery words, to convert the recovery copy of an
    account that came from SecretSpace 3. Nothing happens for an account
    whose copy is already in the current format. ``asked``: the user chose
    this in Settings (so no "Later" framing is needed).
    """
    account = app.account
    if account is None or account.recovery_converted:
        if asked:
            app.toast("The recovery copy is already in the new format")
        return
    import recovery_ui                  # late: it imports dialogs' users
    top = app._modal("Recovery copy", 500, 470)
    shell = dialog_shell(
        top, "Convert the recovery copy too",
        "Your account is converted. One thing is left: the copy that your "
        "12 recovery words open. Only the words can open it, so type them "
        "once and it is converted as well — under the same words, no new "
        "paper.")
    wrap = shell.body
    field_label(wrap, "Recovery phrase (12 words, in order)")
    words = recovery_ui._words_box(wrap, shell.text_width)
    note(wrap, "You can do this later in Settings → Security. Until then "
         "the words keep working for a recovery exactly as before.",
         shell.text_width, size=11, pady=(8, 0))
    err = error_label(wrap, shell.text_width)
    busy = {"on": False}
    session = getattr(app, "_session", 0)

    def done(_):
        top.destroy()
        if getattr(app, "_session", 0) == session:
            app.toast("Recovery copy converted — the same 12 words open it")

    def failed(error):
        busy["on"] = False
        if top.winfo_exists():
            err.configure(text=str(error))

    def go():
        if busy["on"]:
            return
        phrase = " ".join(words.get("1.0", "end").split())
        busy["on"] = True
        err.configure(text="")
        _in_background(app, lambda: recovery.convert_copy(account, phrase),
                       done, on_error=failed)

    app._ghost_button(shell.buttons, "Later", top.destroy,
                      width=100).pack(side="left")
    app._accent_button(shell.buttons, "Convert", go,
                       width=120).pack(side="right")
    top.bind("<Escape>", lambda e: top.destroy())
    top.after(200, words.focus)


def home_notice(app, outcome) -> None:
    """Say what vault.settle_home did with the data folder of the old name."""
    status, old, new = outcome
    if status == vault.HOME_MOVED:
        app.toast(f"Your data folder has its new name: {new}")
    elif status == vault.HOME_BUSY:
        app.toast(f"The data folder {old} could not be renamed (something "
                  "has it open). It is used where it is; SecretSpace tries "
                  "again at its next start.", "warn")
    elif status == vault.HOME_BOTH:
        app.toast(f"There are two data folders. SecretSpace uses {new}; "
                  f"{old} was left alone — look at it, and delete it if "
                  "nothing in it is needed.", "warn")
