"""
The Vaults window (phase 3): the vaults of the open account -- add one,
rename one, delete one.

An account always has its personal vault. Any further vault has its own
random key, kept wrapped to the account's key, so each can later be shared
with other people without touching the rest.

The same rules as the other screens: the network (deleting a vault on the
server) runs on a worker thread, widgets are touched only on the main one.
"""

import customtkinter as ctk

import account_sync
from sync_ui import _in_background
from theme import F, TEXT, MUTED, CARD, BORDER, WARN
from widgets import (dialog_shell, ghost_button, accent_button, small_button,
                     field, error_label)


def _count(data) -> str:
    live = sum(1 for a in data.get("accounts", []) if not a.get("archived"))
    return f"{live} entr{'y' if live == 1 else 'ies'}"


def _status(app, vault_id):
    """(text, colour) under a vault's name: where it lives."""
    account = app.account
    if vault_id == account.personal_id:
        return "Your own vault. It comes with the account.", MUTED
    record = account.vault_record(vault_id)
    if record.get("gone_from_server"):
        return ("Deleted on another device. Kept on this PC only, and no "
                "longer synced.", WARN)
    if not account.server:
        return "On this PC.", MUTED
    if record.get("on_server"):
        return "On the server — your other devices get it when they sync.", MUTED
    return "On this PC until the next sync puts it on the server.", MUTED


def vaults_dialog(app):
    account = app.account
    if account is None:
        return
    top = app._modal("Vaults", 580, 640)
    shell = dialog_shell(
        top, "Vaults",
        "Keep logins apart: home, work, a project. Every vault has its own "
        "key. Sharing a vault with other people comes in a later version.",
        scroll=True)
    listing = shell.body
    listing.grid_columnconfigure(0, weight=1)

    def changed(message=None, kind="info"):
        app.load_vaults()
        app.refresh_account_list()
        if top.winfo_exists():
            rebuild()
        if message:
            app.toast(message, kind)

    def rebuild():
        for child in listing.winfo_children():
            child.destroy()
        for i, vault_id in enumerate(account.vault_ids()):
            _vault_row(app, listing, i, vault_id, changed)

    def new_vault():
        name = _ask_name(app, "New vault", "What should it be called? You can "
                         "change the name later.", "", "Create vault",
                         lambda text: account.create_vault(text))
        if name:
            changed(f"Vault “{name}” created" + (
                " — it goes to the server with the next sync"
                if account.server else ""))

    rebuild()
    ghost_button(shell.buttons, "Close", top.destroy, width=110).pack(side="left")
    accent_button(shell.buttons, "New vault…", new_vault,
                  width=150).pack(side="right")
    top.bind("<Escape>", lambda e: top.destroy())


def _vault_row(app, parent, index, vault_id, changed):
    account = app.account
    personal = vault_id == account.personal_id
    name = app.vault_name(vault_id)
    record = account.vault_record(vault_id)

    row = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=14,
                       border_width=1, border_color=BORDER)
    row.grid(row=index, column=0, sticky="ew", padx=2,
             pady=(10 if index == 0 else 4, 4))
    row.grid_columnconfigure(0, weight=1)

    info = ctk.CTkFrame(row, fg_color="transparent")
    info.grid(row=0, column=0, sticky="w", padx=(16, 8), pady=12)
    ctk.CTkLabel(info, text=name, anchor="w", font=F(14, "bold"),
                 text_color=TEXT).pack(anchor="w")
    text, colour = _status(app, vault_id)
    ctk.CTkLabel(info, text=f"{_count(app.vaults.get(vault_id, {}))}  ·  {text}",
                 anchor="w", justify="left", wraplength=300, font=F(12),
                 text_color=colour).pack(anchor="w")
    if personal:
        return

    buttons = ctk.CTkFrame(row, fg_color="transparent")
    buttons.grid(row=0, column=1, padx=(0, 14))

    def rename():
        new = _ask_name(app, f"Rename “{name}”", "The new name shows on all "
                        "your devices after they sync.", name, "Rename",
                        lambda text: account.rename_vault(vault_id, text))
        if new:
            changed(f"Renamed to “{new}”")

    def put_back():
        account_sync.put_vault_back(account, vault_id)
        changed(f"“{name}” goes back onto the server with the next sync")

    def delete():
        _delete_vault(app, vault_id, name, changed)

    if record.get("gone_from_server") and account.server:
        small_button(buttons, "Put back", put_back, accent=True,
                     width=84).pack(side="left", padx=(0, 6))
    else:
        small_button(buttons, "Rename", rename, width=78).pack(
            side="left", padx=(0, 6))
    small_button(buttons, "Delete", delete, danger=True,
                 width=72).pack(side="left")


def _ask_name(app, title, subtitle, initial, action, apply):
    """
    Ask for a vault name and run ``apply(name)``, which raises ValueError
    with the reason when the name will not do. Returns the name as it was
    stored, or None when the window was closed.
    """
    top = app._modal(title, 460, 280)
    shell = dialog_shell(top, title, subtitle)
    box = field(shell.body, "Name", placeholder="e.g. Home")
    box.insert(0, initial)
    err = error_label(shell.body, shell.text_width)
    outcome = {"name": None}

    def go():
        try:
            apply(box.get())
        except ValueError as e:
            err.configure(text=str(e))
            return
        outcome["name"] = " ".join(box.get().split())
        top.destroy()

    ghost_button(shell.buttons, "Cancel", top.destroy, width=110).pack(side="left")
    accent_button(shell.buttons, action, go, width=150).pack(side="right")
    box.bind("<Return>", lambda e: go())
    top.bind("<Escape>", lambda e: top.destroy())
    top.after(200, box.focus)
    app.root.wait_window(top)
    return outcome["name"]


def _delete_vault(app, vault_id, name, changed):
    account = app.account
    record = account.vault_record(vault_id)
    on_server = bool(account.server and record.get("on_server")
                     and not record.get("gone_from_server"))
    stored = len(app.vaults.get(vault_id, {}).get("accounts", []))
    where = ("on this PC and on the server, so it disappears from your other "
             "devices too" if on_server else "on this PC")
    import dialogs                       # late: dialogs imports this module's users
    if not dialogs.ask_master_password(
            app, f"Delete “{name}”",
            f"This deletes the vault and everything in it "
            f"({stored} entr{'y' if stored == 1 else 'ies'}, archive included) "
            f"{where}. It cannot be undone here. Enter your master password "
            "to confirm.", action="Delete vault"):
        return
    if getattr(app, "_syncing", False):
        return app.toast("Wait for the sync to finish, then delete the vault",
                         "warn")

    def done(_):
        if app.account is not account:
            return                       # locked meanwhile
        changed(f"Vault “{name}” deleted", "warn")

    def failed(error):
        if app.account is account:
            app.toast(f"The vault was not deleted: {error}", "error")

    app.toast("Deleting…")
    _in_background(app, lambda: account_sync.delete_vault(account, vault_id),
                   done, on_error=failed)
