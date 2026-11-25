"""Windows Hello in the windows: the row in Settings (hello.py does it)."""

import customtkinter as ctk

import hello
from sync_ui import _in_background
from theme import GREEN
from widgets import setting_row

ABOUT = ("Fingerprint, face or PIN opens it again after a lock. The master "
         "password is needed once each time SecretSpace starts.")
NOT_SET_UP = ("Not set up for this Windows user: Windows Settings → "
              "Accounts → Sign-in options.")


def setting(app, parent, hint):
    """Settings -> Security: the Windows Hello row."""
    import dialogs                       # late: it imports this module's users
    account = app.account
    there, on = hello.available(), hello.is_enabled(account)
    box = ctk.CTkSwitch(
        setting_row(parent, "Unlock with Windows Hello",
                    ABOUT if there else NOT_SET_UP, hint),
        text="", width=46, progress_color=GREEN)
    if on:
        box.select()
    # One that is on and gone from Windows since can still be turned off.
    if not there and not on:
        box.configure(state="disabled")
    box.pack()

    def back(enabled):
        if box.winfo_exists():
            box.configure(state="normal")
            (box.select if enabled else box.deselect)()

    def proven(_):
        if app.account is not account:
            return                      # locked meanwhile
        hello.set_enabled(account, True)
        back(True)
        app.toast("Windows Hello is on")

    def failed(e):
        back(False)
        if app.account is account and not isinstance(e, hello.Cancelled):
            app.toast(str(e) if isinstance(e, hello.Failed)
                      else "Windows Hello did not work.", "error")

    def switched():
        if not box.get():
            hello.set_enabled(account, False)
            return
        if not dialogs.ask_master_password(
                app, "Windows Hello",
                "Your Windows Hello fingerprint, face or PIN will open this "
                "account after a lock. So can anyone who knows that PIN.",
                action="Turn on") or app.account is not account:
            back(False)
            return
        if not box.winfo_exists():
            return
        box.configure(state="disabled")
        window = hello.window_of(box)
        _in_background(app, lambda: hello.prove(window), proven, failed)

    box.configure(command=switched)
    return box
