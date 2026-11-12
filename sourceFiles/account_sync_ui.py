"""
The account sync screens (phase 2): put an account on a server, sync it,
sign in from a server on another device.

The same rules as sync_ui.py, whose helpers this reuses: the network and the
crypto (Argon2id takes a moment) run on a worker thread, widgets are touched
only back on the main thread, and a sync whose account was locked meanwhile
does nothing when it returns.
"""

import threading

import customtkinter as ctk

import account_sync
import accounts
import sync_client
from sync_ui import _in_background, _still_open, _finish, conflict_dialog
from theme import F, MUTED, GREEN, DANGER
from widgets import ghost_button, accent_button, field, note, dialog_shell


# ==========================================================================
# The Sync button
# ==========================================================================
def run_sync(app):
    """
    One press of Sync: log in once, make the list of vaults the same here
    and on the server (account_sync.reconcile_vaults), then sync each vault
    in turn -- its own merge, its own conflict questions.
    """
    if app.account is None or app.vault is None:
        return
    if not app.account.server:
        app.toast("This account is not on a server yet — Settings → Sync", "warn")
        return server_dialog(app)
    if getattr(app, "_syncing", False):
        return app.toast("A sync is already running")
    app._syncing = True
    app.toast("Syncing…")
    account = app.account
    attempt = {"session": getattr(app, "_session", 0)}

    def work():
        server = account_sync.logged_in(account)
        try:
            changes = account_sync.reconcile_vaults(account, server)
            return server, changes, account_sync.syncable_vaults(account, server)
        except BaseException:
            server.logout()
            raise

    def done(payload):
        server, changes, vault_ids = payload
        if not _still_open(app, attempt):
            return _logout_in_background(server)
        app.load_vaults()               # vaults that just arrived, or left
        run = {"server": server, "changes": changes, "queue": list(vault_ids),
               "many": len(vault_ids) > 1, "updated": [], "summary": None,
               "account": account}
        _next_vault(app, run, attempt)

    _in_background(app, work, done,
                   on_error=lambda e: _finish(app, str(e), "error")
                   if _still_open(app, attempt) else None)


def _next_vault(app, run, attempt):
    if not run["queue"]:
        return _all_done(app, run)
    _sync_step(app, run, attempt, run["queue"].pop(0), retry_allowed=True)


def _sync_step(app, run, attempt, vault_id, retry_allowed):
    def failed(error):
        if not _still_open(app, attempt):
            return _logout_in_background(run["server"])
        if isinstance(error, sync_client.Conflict409) and retry_allowed:
            app.toast("The server moved on — merging again")
            return _sync_step(app, run, attempt, vault_id, retry_allowed=False)
        _logout_in_background(run["server"])
        app.refresh_account_list()
        _finish(app, str(error), "error")

    def work():
        session = account_sync.AccountSync(run["account"], run["server"], vault_id)
        return session, session.prepare(app.vaults[vault_id])

    def prepared(payload):
        session, result = payload
        if not _still_open(app, attempt):
            return _logout_in_background(run["server"])
        if not session.has_work():
            return _next_vault(app, run, attempt)
        choices = None
        if result.conflicts:
            choices = conflict_dialog(
                app, result, app.vault_name(vault_id) if run["many"] else "")
            if choices is None:
                _logout_in_background(run["server"])
                app.refresh_account_list()
                return _finish(
                    app, "Sync cancelled — nothing changed" + (
                        f" in “{app.vault_name(vault_id)}”" if run["many"] else ""),
                    "warn")

        def commit():
            return session.commit(app.vaults[vault_id], choices)

        def committed(merged):
            if not _still_open(app, attempt):
                return _logout_in_background(run["server"])
            app.set_vault_data(vault_id, merged, saved=True)
            run["updated"].append(vault_id)
            summary = f"Synced — {result.summary()}"
            if session.first_push:
                summary = "Synced — the server now has this account's vault"
            elif session.base_ignored:
                summary += " (first sync with this server)"
            run["summary"] = summary
            _next_vault(app, run, attempt)

        _in_background(app, commit, committed, on_error=failed)

    _in_background(app, work, prepared, on_error=failed)


def _all_done(app, run):
    _logout_in_background(run["server"])
    app.refresh_account_list()
    changes, updated = run["changes"], run["updated"]
    if not run["many"] and not changes:
        # An account with only its personal vault: what phase 2 said.
        return _finish(app, run["summary"] or "Already up to date")
    parts = []
    if updated:
        parts.append(f"{len(updated)} vault{'s' if len(updated) != 1 else ''} "
                     "updated")
    if changes.added:
        parts.append("new from the server: " + ", ".join(changes.added))
    if changes.uploaded:
        parts.append("now on the server: " + ", ".join(changes.uploaded))
    for old, new in changes.renamed:
        parts.append(f"“{old}” is now “{new}”")
    if changes.rekeyed:
        parts.append("new key for: " + ", ".join(changes.rekeyed))
    for name, role in changes.roles:
        parts.append(f"you are now {role} of “{name}”")
    kind = "info"
    if changes.gone:
        parts.append("no longer on the server for you (deleted, or you were "
                     "removed), kept on this PC only: " +
                     ", ".join(changes.gone) + " (see Vaults)")
        kind = "warn"
    if changes.server_too_old:
        parts.append("this server keeps only the Personal vault — the others "
                     "need SecretSpace Server 2.0.0-alpha.5 or newer")
        kind = "warn"
    _finish(app, "Synced — " + "; ".join(parts) if parts else "Already up to date",
            kind)


def plain_http_ok(app, url) -> bool:
    """Ask before an unencrypted address of another machine is used. True
    to go on (always for https:// and for this PC itself)."""
    if not account_sync.is_plain_remote(url):
        return True
    return app._confirm(
        "This connection is not encrypted",
        "The address starts with http://, so what this PC and the server "
        "say to each other can be read on the network in between.\n\n"
        "Your vaults stay safe: they are encrypted on this PC before they "
        "leave it. But someone listening could take over the account ON "
        "THE SERVER: lock you out there, or delete what it holds.\n\n"
        "Fine inside a network you trust (your home, your office). Anywhere "
        "else use an https:// address.\n\nContinue?", danger=False)


def _logout_in_background(server):
    """Log out without the window waiting: a logout is a network call too,
    and a slow server must never freeze the window (Lab flow, 2026-11-10:
    on the main thread it stalled the UI for 20 s)."""
    threading.Thread(target=server.logout, daemon=True).start()


# ==========================================================================
# Settings -> Sync: put this account on a server
# ==========================================================================
def server_dialog(app, on_done=None):
    """
    Connect the open account to a server. If the server already has it (set
    up from another device) logging in is enough; otherwise it is created
    there, with the server's token as the sign-up code.
    """
    account = app.account
    top = app._modal("Sync with a server", 560, 620)
    shell = dialog_shell(
        top, "Sync with a server",
        "The server keeps this account's vault encrypted — it never gets your "
        "master password, your Secret Key or anything it could open your "
        "vault with. It needs SecretSpace Server 2.0 or newer.")
    wrap = shell.body

    url_entry = field(wrap, "Server address", placeholder="http://192.168.1.50:8787")
    token_entry = field(wrap, "Server token (only to create the account there)",
                        show="•")
    ca_entry = field(wrap, "Certificate file (only for https, optional)",
                     placeholder="C:\\SecretSpace\\server.crt")
    if account.server:
        url_entry.insert(0, account.server["url"])
        ca_entry.insert(0, account.server.get("ca_file", ""))

    note(wrap, "The token is the one the server's setup shows (the same one 2.x "
         "vaults use). It lets you make an account there; it does not open "
         "anyone's vault.", shell.text_width, size=11, pady=(10, 0))
    status = ctk.CTkLabel(wrap, text="", font=F(12), text_color=MUTED,
                          wraplength=shell.text_width, justify="left", anchor="w")
    status.pack(anchor="w", fill="x", pady=(10, 0))

    def connect():
        url = url_entry.get().strip()
        if not url.startswith(("http://", "https://")):
            return status.configure(text="Enter the server address, starting "
                                         "with http:// or https://",
                                    text_color=DANGER)
        token, ca_file = token_entry.get().strip(), ca_entry.get().strip()
        if not plain_http_ok(app, url):
            return
        status.configure(text="Contacting the server…", text_color=MUTED)

        def done(outcome):
            top.destroy()
            if on_done:
                on_done()
            app.toast("Account created on the server — syncing…"
                      if outcome == "created" else
                      "Connected to the server — syncing…")
            run_sync(app)

        _in_background(app, lambda: account_sync.connect(account, url, ca_file, token),
                       done, on_error=lambda e: status.configure(
                           text=str(e), text_color=DANGER))

    ghost_button(shell.buttons, "Cancel", top.destroy, width=110).pack(side="left")
    accent_button(shell.buttons, "Connect & sync", connect,
                  width=160).pack(side="right")
    top.bind("<Escape>", lambda e: top.destroy())
    app._fit_modal(top)


def forget_server(app):
    """Stop syncing this account from this device. The server keeps its copy."""
    app.account.set_server(None)
    app.toast("This PC no longer syncs the account. The server's copy is kept.")


# ==========================================================================
# The login screen: sign in from a server
# ==========================================================================
def sign_in_dialog(app):
    """
    Bring an account onto this device from its server -- a new PC, or this
    one after the master password was changed on another.
    """
    top = app._modal("Sign in from a server", 540, 720)
    shell = dialog_shell(
        top, "Sign in from a server",
        "For an account you already use on another device. You need the "
        "server address, your username and master password, and — on a new "
        "device — the Secret Key from your Emergency Kit.")
    wrap = shell.body

    url_entry = field(wrap, "Server address", placeholder="http://192.168.1.50:8787")
    ca_entry = field(wrap, "Certificate file (only for https, optional)",
                     placeholder="C:\\SecretSpace\\server.crt")
    user_entry = field(wrap, "Username")
    pw_entry = field(wrap, "Master password", show="•")
    key_entry = field(wrap, "Secret Key (from the Emergency Kit)",
                      placeholder="A3-XXXXXX-XXXXX-…")
    note(wrap, "Already have this account on this PC? Leave the Secret Key "
         "empty; this PC keeps it.", shell.text_width, size=11, pady=(8, 0))
    status = ctk.CTkLabel(wrap, text="", font=F(12), text_color=DANGER,
                          wraplength=shell.text_width, justify="left", anchor="w")
    status.pack(anchor="w", fill="x", pady=(10, 0))

    def sign_in():
        url = url_entry.get().strip()
        username = user_entry.get().strip()
        password = pw_entry.get()
        if not url.startswith(("http://", "https://")):
            return status.configure(text="Enter the server address, starting "
                                         "with http:// or https://",
                                    text_color=DANGER)
        if not (username and password):
            return status.configure(text="Enter your username and master password.",
                                    text_color=DANGER)
        if not plain_http_ok(app, url):
            return
        status.configure(text="Signing in — this takes a moment…", text_color=MUTED)

        def work():
            return account_sync.sign_in(url, ca_entry.get().strip(), username,
                                        password, key_entry.get().strip() or None)

        def done(payload):
            account, data = payload
            top.destroy()
            loaded = data if data is not None else account.load_vault()
            app.open_account(account, loaded, password)
            app.toast(f"Signed in as “{account.username}”")
            if data is None:            # this PC had it: merge its own changes
                run_sync(app)

        def failed(e):
            if isinstance(e, accounts.SecretKeyNeeded):
                text = ("Enter the Secret Key from your Emergency Kit — this PC "
                        "does not have it for this password.")
            else:
                text = str(e)
            status.configure(text=text, text_color=DANGER)

        _in_background(app, work, done, on_error=failed)

    ghost_button(shell.buttons, "Cancel", top.destroy, width=110).pack(side="left")
    accent_button(shell.buttons, "Sign in", sign_in, width=140).pack(side="right")
    pw_entry.bind("<Return>", lambda e: sign_in())
    top.bind("<Escape>", lambda e: top.destroy())
    app._fit_modal(top)
