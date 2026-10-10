"""
The sync and archive screens.

Kept apart from dialogs.py, which is already long, and strictly separate from
sync.py / sync_client.py: nothing here decides a merge, it only shows one and
collects the answer.

Threading rule for this whole module: tkinter is single-threaded and every
network call here can block for as long as the timeout. So the network and the
crypto run on a worker thread, and anything that touches a widget comes back
through ``root.after``. Doing it inline freezes the window, which on a flaky
VPN looks exactly like a crash.
"""

import threading

import customtkinter as ctk

import sync
import sync_client
import vault
from theme import (F, TEXT, MUTED, GREEN, GREEN_HOVER, DANGER, DANGER_HOVER,
                   INPUT_BG, BORDER, CARD, CARD_HOVER, ON_ACCENT, WARN, MONO)
from widgets import ghost_button, accent_button, field

#: Labels for the three ways out of a conflict. "Keep both" is first and is
#: the default: it is the only one that cannot hide anything.
CHOICE_LABELS = {
    sync.KEEP_BOTH: "Keep both",
    sync.KEEP_LOCAL: "This PC",
    sync.KEEP_REMOTE: "Server",
}
CHOICE_ORDER = [sync.KEEP_BOTH, sync.KEEP_LOCAL, sync.KEEP_REMOTE]


# ==========================================================================
# Running a sync
# ==========================================================================
def run_sync(app, server_password=None, drop_history=False, offline_hint=""):
    """
    The Sync button.

    Pull, merge, ask if needed, push. The user sees a toast on the way in and
    a summary on the way out; the only times they are interrupted are a
    genuine conflict and a master password that differs from the server's.

    The keyword arguments are for the Change master password dialog, which
    already knows the previous password and so can bring the server up to
    date without asking for it again. ``offline_hint`` replaces the usual
    error when the server cannot be reached.
    """
    if app.vault is None:
        return
    if not sync_client.is_configured(app.vault):
        app.toast("Sync is not set up yet — Settings → Sync", "warn")
        return sync_settings_dialog(app)
    if getattr(app, "_syncing", False):
        return app.toast("A sync is already running")

    app._syncing = True
    app.toast("Syncing…")
    _sync_step(app, {"retry_allowed": True, "server_password": server_password,
                     "drop_history": drop_history, "from_prompt": False,
                     "offline_hint": offline_hint})


def _sync_step(app, attempt):
    """
    One attempt: prepare on a worker, then resolve and commit.

    ``attempt`` carries what a retry needs to repeat it: the server's
    password if the user already supplied one, and whether the history is to
    be dropped.
    """
    def work():
        client = sync_client.client_for(app.vault)
        session = sync_client.SyncSession(client, app.current_user,
                                          app.master_password)
        return session, session.prepare(app.vault, attempt["server_password"])

    def done(payload):
        session, result = payload
        if not session.has_work():
            return _finish(app, "Already up to date")

        choices = None
        if result.conflicts:
            choices = conflict_dialog(app, result)
            if choices is None:
                return _finish(app, "Sync cancelled — nothing changed", "warn")

        _commit(app, session, result, choices, attempt)

    _in_background(app, work, done,
                   on_error=lambda e: _sync_failed(app, e, attempt))


def _commit(app, session, result, choices, attempt):
    def work():
        return session.commit(app.vault, choices, attempt["drop_history"])

    def done(merged):
        app.vault = merged
        summary = f"Synced — {result.summary()}"
        if session.password_changed:
            # This PC's vault is now under the other PC's password. The app
            # must use it from here on, or its next save would write the
            # vault back under the old one.
            app.master_password = session.master_password
            summary = ("Synced — this vault now uses the master password set "
                       "on your other PC")
        elif session.upgrade:
            summary = "Synced — the server now has your new master password"
        elif session.base_ignored:
            # The first sync with this server: nothing was deleted or
            # reverted, so say why entries may have come up for review.
            summary += " (first sync with this server)"
        app.refresh_account_list()
        _finish(app, summary)

    _in_background(app, work, done,
                   on_error=lambda e: _sync_failed(app, e, attempt))


def _sync_failed(app, error, attempt):
    """
    Two failures are not errors to show as such.

    A 409 means the server moved on while we were working -- most likely the
    other PC pushed mid-dialog. Start over once, merging against what is
    there now.

    A password mismatch means the master password was changed on one PC and
    not yet the other. Ask for the server's password and go again; the
    session works out from there which way to catch up.
    """
    if isinstance(error, sync_client.Conflict409) and attempt["retry_allowed"]:
        app.toast("The server moved on — merging again")
        return _sync_step(app, dict(attempt, retry_allowed=False))

    if isinstance(error, sync_client.PasswordMismatch):
        # "Wrong" only when the user typed it. The Change password dialog
        # passes the previous password on its own, and that not fitting just
        # means someone else's change got to the server first.
        answer = password_mismatch_dialog(
            app, adopt=error.adopt, wrong=error.wrong and attempt["from_prompt"])
        if answer is None:
            return _finish(app, "Sync cancelled — nothing changed", "warn")
        password, drop_history = answer
        return _sync_step(app, dict(attempt, server_password=password,
                                    drop_history=drop_history,
                                    from_prompt=True))

    if attempt["offline_hint"] and isinstance(error,
                                              sync_client.ServerUnreachable):
        return _finish(app, attempt["offline_hint"], "warn")
    _finish(app, str(error), "error")


def _finish(app, message, kind="info"):
    app._syncing = False
    app.toast(message, kind)


def _in_background(app, work, done, on_error):
    """
    Run ``work`` off the main thread and hand its result to ``done`` back on
    it. Exceptions arrive at ``on_error`` the same way, so a network failure
    can never leave the UI wedged with the Sync button disabled.
    """
    def runner():
        try:
            payload = work()
        except Exception as error:                 # noqa: BLE001 - reported
            # Bound as a default argument, not captured. Python deletes the
            # name an `except ... as` clause binds when the block ends, so a
            # lambda closing over it raises NameError by the time `after`
            # runs it -- which swallowed every network error in this module
            # and left the dialog saying "Contacting the server..." forever.
            app.root.after(0, lambda err=error: on_error(err))
            return
        app.root.after(0, lambda result=payload: done(result))

    threading.Thread(target=runner, daemon=True).start()


# ==========================================================================
# Conflict resolution
# ==========================================================================
def conflict_dialog(app, result):
    """
    Show every entry both sides changed and collect a decision for each.

    Returns a {entry_id: choice} mapping, or None if the user backed out, in
    which case the caller must not write anything. Only conflicts are listed:
    a screenful of rows that need no decision is how people learn to click
    through the one that did.
    """
    top = app._modal("Review sync conflicts", 820, 620)
    answers = {c.id: sync.DEFAULT_RESOLUTION for c in result.conflicts}
    outcome = {"choices": None}
    revealed = {"on": False}
    rows = []

    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=24, pady=20)

    ctk.CTkLabel(wrap, text="Review sync conflicts", font=F(20, "bold"),
                 text_color=TEXT).pack(anchor="w")
    count = len(result.conflicts)
    ctk.CTkLabel(
        wrap,
        text=(f"{count} entr{'y' if count == 1 else 'ies'} changed on both "
              f"this PC and the server. Everything else merged on its own: "
              f"{result.summary()}."),
        font=F(12), text_color=MUTED, wraplength=760,
        justify="left").pack(anchor="w", pady=(2, 2))
    ctk.CTkLabel(
        wrap,
        text="Whichever side you do not keep is saved in that entry's "
             "history — open History on the entry to revert. (An entry "
             "deleted on one side goes to the Archive instead.)",
        font=F(12), text_color=GREEN, wraplength=760,
        justify="left").pack(anchor="w", pady=(0, 10))

    listing = ctk.CTkScrollableFrame(wrap, fg_color="transparent")
    listing.pack(fill="both", expand=True)
    listing.grid_columnconfigure(0, weight=1)

    for i, conflict in enumerate(result.conflicts):
        rows.append(_conflict_row(listing, i, conflict, answers))

    # -- bulk actions + commit -------------------------------------------
    def set_all(choice):
        for conflict in result.conflicts:
            answers[conflict.id] = choice
        for setter in rows:
            setter(choice)

    def toggle_reveal():
        revealed["on"] = not revealed["on"]
        reveal_btn.configure(text="Hide passwords" if revealed["on"]
                             else "Show passwords")
        for widget, secret in _secret_labels:
            widget.configure(text=secret if revealed["on"] else "•" * 10)

    def apply():
        outcome["choices"] = dict(answers)
        top.destroy()

    bar = ctk.CTkFrame(wrap, fg_color="transparent")
    bar.pack(fill="x", pady=(14, 0))

    reveal_btn = ghost_button(bar, "Show passwords", toggle_reveal, width=150)
    reveal_btn.pack(side="left")
    ghost_button(bar, "All: this PC",
                 lambda: set_all(sync.KEEP_LOCAL), width=120).pack(
                     side="left", padx=(8, 0))
    ghost_button(bar, "All: server",
                 lambda: set_all(sync.KEEP_REMOTE), width=120).pack(
                     side="left", padx=(8, 0))

    accent_button(bar, "Apply and sync", apply, width=170).pack(side="right")
    ghost_button(bar, "Cancel", top.destroy, width=110).pack(
        side="right", padx=(0, 8))

    top.bind("<Escape>", lambda e: top.destroy())
    app.root.wait_window(top)
    return outcome["choices"]


#: Password labels in the open conflict dialog, so the reveal toggle can find
#: them. Rebuilt per dialog; the dialog is modal so only one exists at a time.
_secret_labels = []


def _conflict_row(parent, index, conflict, answers):
    """One conflict: both versions side by side, and the choice."""
    if index == 0:
        _secret_labels.clear()

    card = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=12)
    card.grid(row=index, column=0, sticky="ew", pady=6, padx=2)
    card.grid_columnconfigure((0, 1), weight=1, uniform="sides")

    header = ctk.CTkFrame(card, fg_color="transparent")
    header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14, pady=(12, 0))
    ctk.CTkLabel(header, text=conflict.site or "(no site)",
                 font=F(15, "bold"), text_color=TEXT).pack(side="left")
    ctk.CTkLabel(header, text=f"   {_kind_note(conflict)}", font=F(12),
                 text_color=WARN).pack(side="left")

    gone = "not on the server" if conflict.kind == "missing" else "deleted"
    _version_panel(card, 1, 0, "On this PC", conflict.local, gone)
    _version_panel(card, 1, 1, "On the server", conflict.remote, gone)

    choice_row = ctk.CTkFrame(card, fg_color="transparent")
    choice_row.grid(row=2, column=0, columnspan=2, sticky="ew",
                    padx=14, pady=(6, 12))
    ctk.CTkLabel(choice_row, text="Keep:", font=F(12, "bold"),
                 text_color=MUTED).pack(side="left", padx=(0, 8))

    segmented = ctk.CTkSegmentedButton(
        choice_row, values=[CHOICE_LABELS[c] for c in CHOICE_ORDER],
        font=F(12, "bold"), selected_color=GREEN,
        selected_hover_color=GREEN_HOVER, text_color=TEXT,
        command=lambda label: answers.__setitem__(conflict.id,
                                                  _choice_from(label)))
    segmented.pack(side="left")
    segmented.set(CHOICE_LABELS[sync.DEFAULT_RESOLUTION])

    def setter(choice):
        segmented.set(CHOICE_LABELS[choice])

    return setter


def _choice_from(label):
    for choice, text in CHOICE_LABELS.items():
        if text == label:
            return choice
    return sync.DEFAULT_RESOLUTION


def _kind_note(conflict):
    if conflict.kind == "archive":
        return "archived on one side, edited on the other"
    if conflict.kind == "purge":
        return "permanently deleted on one side, edited on the other"
    if conflict.kind == "missing":
        return ("still in use here, missing from the server — "
                "keep it unless you deleted it on purpose")
    return "edited on both sides"


def _version_panel(parent, row, column, title, entry, gone="deleted"):
    """
    One side of a conflict. Passwords are masked until the user asks.
    ``gone`` is what an absent side says.
    """
    panel = ctk.CTkFrame(parent, fg_color="transparent")
    panel.grid(row=row, column=column, sticky="nsew", padx=14, pady=8)

    ctk.CTkLabel(panel, text=title, font=F(12, "bold"),
                 text_color=MUTED).pack(anchor="w")

    if entry is None:
        ctk.CTkLabel(panel, text=gone, font=F(13), text_color=DANGER,
                     anchor="w").pack(anchor="w", pady=(4, 0))
        return

    if vault.is_archived(entry):
        ctk.CTkLabel(panel, text="archived", font=F(12, "bold"),
                     text_color=WARN, anchor="w").pack(anchor="w", pady=(4, 0))

    for label, value in (("user", entry.get("username", "")),
                         ("site", entry.get("site", ""))):
        ctk.CTkLabel(panel, text=f"{label}: {value or '—'}", font=F(12),
                     text_color=TEXT, anchor="w").pack(anchor="w")

    secret = entry.get("password", "")
    pwd = ctk.CTkLabel(panel, text="•" * 10, anchor="w",
                       font=ctk.CTkFont(family=MONO, size=13),
                       text_color=TEXT)
    pwd.pack(anchor="w", pady=(2, 0))
    _secret_labels.append((pwd, secret))

    for label, key in (("notes", "notes"), ("2FA", "totp")):
        if entry.get(key):
            ctk.CTkLabel(panel, text=f"{label}: {entry[key][:40]}", font=F(11),
                         text_color=MUTED, anchor="w").pack(anchor="w")

    when = entry.get("updated_at", "")
    ctk.CTkLabel(panel, text=f"edited {when or 'at an unknown time'}",
                 font=F(11), text_color=MUTED, anchor="w").pack(anchor="w",
                                                                pady=(4, 0))


# ==========================================================================
# Master password differs from the server's
# ==========================================================================
def password_mismatch_dialog(app, adopt, wrong=False):
    """
    Ask for the password the server's copy is under.

    Worded by direction, because the user needs to know which password is
    wanted and what happens to their vault:

    ``adopt``      the password was changed on another PC. They give the NEW
                   one, and this vault switches to it.
    not ``adopt``  they changed it here while the server was out of reach.
                   They give their PREVIOUS one, once, and keep the new one.

    Returns (password, drop_history), or None if they backed out -- in which
    case nothing has been written anywhere.
    """
    if adopt:
        title = "Master password changed on another PC"
        body = ("The copy of this vault on your server now uses a different "
                "master password — it was changed on another PC.\n\n"
                "Enter that new master password to keep syncing. This vault "
                "switches to it: from now on you unlock it with the new "
                "password on this PC too. Nothing in the vault is lost.")
        label = "The new master password (set on the other PC)"
        note = ("If you also changed it here, the other PC's change reached "
                "the server first and takes precedence.")
    else:
        title = "Update the server to your new password"
        body = ("You changed this vault's master password while the server "
                "could not be reached, so its copy is still under your "
                "previous password.\n\n"
                "Enter the previous password once. PassMan reads the server's "
                "copy with it, merges, and uploads everything again under "
                "your new password.")
        label = "Your previous master password"
        note = ""

    top = app._modal(title, 500, 520)
    outcome = {"answer": None}

    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=28, pady=24)

    ctk.CTkLabel(wrap, text=title, font=F(18, "bold"),
                 text_color=TEXT).pack(anchor="w")
    ctk.CTkLabel(wrap, text=body, font=F(12), text_color=MUTED,
                 wraplength=430, justify="left").pack(anchor="w", pady=(4, 0))
    if note:
        ctk.CTkLabel(wrap, text=note, font=F(11), text_color=MUTED,
                     wraplength=430, justify="left").pack(anchor="w",
                                                          pady=(6, 0))

    entry = field(wrap, label, show="•")

    drop = None
    if not adopt:
        # Checked by default: people change a master password because they
        # think the old one is exposed, and these copies still open with it.
        # The PCs keep full copies, so nothing current is lost.
        drop = ctk.CTkCheckBox(
            wrap, text="Also delete the older copies on the server — they "
                       "still open with your previous password",
            font=F(12), text_color=TEXT, fg_color=GREEN,
            hover_color=GREEN_HOVER)
        drop.select()
        drop.pack(anchor="w", pady=(12, 0))

    err = ctk.CTkLabel(wrap, font=F(12), text_color=DANGER,
                       wraplength=430, justify="left",
                       text=("That password does not open the server's copy. "
                             "Try again." if wrong else ""))
    err.pack(anchor="w", pady=(8, 0))

    def go():
        password = entry.get()
        if not password:
            return err.configure(text="Enter the password first.")
        outcome["answer"] = (password, bool(drop.get()) if drop else False)
        top.destroy()

    row = ctk.CTkFrame(wrap, fg_color="transparent")
    row.pack(fill="x", side="bottom", pady=(16, 0))
    ghost_button(row, "Cancel", top.destroy, width=110).pack(side="left")
    accent_button(row, "Continue", go, width=140).pack(side="right")

    entry.bind("<Return>", lambda e: go())
    top.bind("<Escape>", lambda e: top.destroy())
    top.after(200, entry.focus)
    app.root.wait_window(top)
    return outcome["answer"]


# ==========================================================================
# Archive
# ==========================================================================
def archive_dialog(app):
    """
    Everything that used to be a delete.

    Restoring is one click. Purging is the only way to actually destroy an
    entry, so it confirms and says plainly that it is final.
    """
    top = app._modal("Archive", 720, 560)
    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=24, pady=20)

    ctk.CTkLabel(wrap, text="Archive", font=F(20, "bold"),
                 text_color=TEXT).pack(anchor="w")
    ctk.CTkLabel(
        wrap,
        text="Deleted entries are kept here rather than destroyed, and they "
             "still hold their passwords. Restore one, or delete it for good.",
        font=F(12), text_color=MUTED, wraplength=650,
        justify="left").pack(anchor="w", pady=(2, 12))

    listing = ctk.CTkScrollableFrame(wrap, fg_color="transparent")
    listing.pack(fill="both", expand=True)
    listing.grid_columnconfigure(0, weight=1)

    def rebuild():
        for child in listing.winfo_children():
            child.destroy()

        entries = vault.archived_accounts(app.vault)
        if not entries:
            ctk.CTkLabel(listing, text="The archive is empty",
                         font=F(15, "bold"), text_color=TEXT).grid(row=0,
                                                                   column=0,
                                                                   pady=60)
            return

        for i, entry in enumerate(entries):
            _archive_row(app, listing, i, entry, rebuild)

    rebuild()
    ghost_button(wrap, "Close", top.destroy, width=110).pack(side="right",
                                                             pady=(14, 0))
    top.bind("<Escape>", lambda e: top.destroy())


def _archive_row(app, parent, index, entry, rebuild):
    row = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=12)
    row.grid(row=index, column=0, sticky="ew", pady=5, padx=2)
    row.grid_columnconfigure(0, weight=1)

    info = ctk.CTkFrame(row, fg_color="transparent")
    info.grid(row=0, column=0, sticky="w", padx=14, pady=10)
    ctk.CTkLabel(info, text=entry.get("site", "—"), anchor="w",
                 font=F(14, "bold"), text_color=TEXT).pack(anchor="w")
    ctk.CTkLabel(info,
                 text=f"{entry.get('username') or '—'}   ·   archived "
                      f"{entry.get('archived_at', 'at an unknown time')}",
                 anchor="w", font=F(11), text_color=MUTED).pack(anchor="w")

    buttons = ctk.CTkFrame(row, fg_color="transparent")
    buttons.grid(row=0, column=1, padx=(0, 12))

    def restore():
        vault.restore_account(app.vault, entry["id"])
        app._save()
        app.refresh_account_list()
        rebuild()
        app.toast(f"Restored {entry.get('site', '')}".strip())

    def purge():
        if not app._confirm(
                "Delete permanently",
                f"Permanently delete the saved login for "
                f"\u201c{entry.get('site', '')}\u201d?\n\n"
                "This cannot be undone, and it is the only action in PassMan "
                "that really destroys a password."):
            return
        vault.purge_account(app.vault, entry["id"])
        app._save()
        app.refresh_account_list()
        rebuild()
        app.toast("Deleted permanently", "warn")

    ctk.CTkButton(buttons, text="Restore", width=90, height=34,
                  corner_radius=8, fg_color=GREEN, hover_color=GREEN_HOVER,
                  text_color=ON_ACCENT, font=F(12, "bold"),
                  command=restore).grid(row=0, column=0, padx=4)
    ctk.CTkButton(buttons, text="Delete", width=80, height=34,
                  corner_radius=8, fg_color="transparent", border_width=1,
                  border_color=BORDER, hover_color=DANGER_HOVER,
                  text_color=DANGER, font=F(12, "bold"),
                  command=purge).grid(row=0, column=1, padx=4)


# ==========================================================================
# Settings
# ==========================================================================
def _first_merge_accepted(app, meta) -> bool:
    """
    Warn before the one sync that can genuinely surprise someone, and return
    whether to go ahead.

    That sync is the first between two vaults built independently -- both
    sides already hold accounts, and there is no base recording any earlier
    agreement. Entries that predate this version line up, because their ids
    are derived from their contents; entries added separately on each PC
    since do not, so the same login typed into both machines merges as two.
    That is defensible behaviour but a poor surprise, and it is worth one
    sentence beforehand.
    """
    if meta.get("revision", 0) == 0:
        return True                      # nothing on the server: a plain upload
    if not vault.active_accounts(app.vault):
        return True                      # nothing here: a plain download
    if vault.load_base(app.master_password, app.current_user) is not None:
        return True                      # synced before, so there is a base

    return app._confirm(
        "First sync between two vaults",
        "This PC and the server both already hold accounts, and they have "
        "never synced with each other.\n\n"
        "Logins that existed before this version will line up. Anything "
        "added separately on each PC since will merge as two entries, which "
        "you can tidy up afterwards from the archive.\n\n"
        "Nothing is deleted either way. Sync now?",
        danger=False)


def sync_settings_dialog(app):
    """Server address, token and optional pinned certificate."""
    top = app._modal("Sync settings", 560, 640)
    settings = sync_client.get_settings(app.vault)

    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=28, pady=24)

    ctk.CTkLabel(wrap, text="Sync", font=F(20, "bold"),
                 text_color=TEXT).pack(anchor="w")
    ctk.CTkLabel(
        wrap,
        text="Your vault is encrypted before it is sent, so the server stores "
             "ciphertext it has no key for. These settings are kept inside the "
             "vault itself, not in config.json.",
        font=F(12), text_color=MUTED, wraplength=450,
        justify="left").pack(anchor="w", pady=(2, 4))

    url_entry = field(wrap, "Server address",
                      placeholder="http://192.168.1.50:8787")
    url_entry.insert(0, settings.get("url", ""))

    token_entry = field(wrap, "Sync token", show="•")
    token_entry.insert(0, settings.get("token", ""))

    ca_entry = field(wrap, "Certificate file (only for https, optional)",
                     placeholder="C:\\PassMan\\server.crt")
    ca_entry.insert(0, settings.get("ca_file", ""))

    status = ctk.CTkLabel(wrap, text="", font=F(12), text_color=MUTED,
                          wraplength=450, justify="left")
    status.pack(anchor="w", pady=(10, 0))

    def _validate():
        """Shared by Test and Save: the typed fields, or None once the
        reason has been shown."""
        url = url_entry.get().strip()
        token = token_entry.get().strip()
        if not url:
            status.configure(text="Enter the server address first.",
                             text_color=DANGER)
            return None
        if not url.startswith(("http://", "https://")):
            status.configure(
                text="The address needs to start with http:// or https://",
                text_color=DANGER)
            return None
        if not token:
            status.configure(text="A token is required.", text_color=DANGER)
            return None
        return url, token, ca_entry.get().strip()

    def _check(url, token, ca_file, then):
        """Reach the server, then hand its metadata to ``then``."""
        status.configure(text="Contacting the server\u2026", text_color=MUTED)

        def work():
            client = sync_client.SyncClient(url, token, ca_file, timeout=10)
            client.health()
            return client.meta(app.current_user)

        _in_background(app, work, then,
                       on_error=lambda e: status.configure(text=str(e),
                                                           text_color=DANGER))

    def _describe(meta) -> str:
        """Say whether the next sync is an upload or a merge -- the one thing
        worth knowing before pressing it."""
        revision = meta.get("revision", 0)
        if revision == 0:
            return ("Connected. The server has no vault for "
                    f"\u201c{app.current_user}\u201d yet, so the first sync "
                    "will upload this one.")
        return (f"Connected. The server holds revision {revision}, last "
                f"updated {meta.get('updated_at', 'unknown')}.")

    def test():
        fields = _validate()
        if fields:
            _check(*fields,
                   then=lambda meta: status.configure(text=_describe(meta),
                                                      text_color=GREEN))

    def save():
        """
        Check the connection, store the settings, then sync straight away.

        The check comes first because settings that were never reached are
        how someone ends up believing sync is set up when it is not. A
        failure leaves the dialog open with the reason showing rather than
        quietly accepting a typo in the address.
        """
        fields = _validate()
        if not fields:
            return
        url, token, ca_file = fields

        def then(meta):
            sync_client.set_settings(app.vault, url, token, ca_file)
            app._save()
            top.destroy()
            if not _first_merge_accepted(app, meta):
                return app.toast("Sync settings saved")
            app.toast("Sync settings saved \u2014 syncing\u2026")
            app.sync_now()

        _check(url, token, ca_file, then)

    def save_offline():
        """
        Keep the settings without reaching the server.

        Configuring while the VPN is down is an ordinary thing to want, so
        refusing to save at all would be the wrong kind of strict.
        """
        fields = _validate()
        if not fields:
            return
        sync_client.set_settings(app.vault, *fields)
        app._save()
        top.destroy()
        app.toast("Saved \u2014 press Sync once you are connected")

    ctk.CTkLabel(
        wrap,
        text="Plain http is reasonable over a VPN you trust. For https with a "
             "self-signed certificate, copy the .crt here and point the field "
             "above at it.",
        font=F(11), text_color=MUTED, wraplength=450,
        justify="left").pack(anchor="w", pady=(12, 0))

    row = ctk.CTkFrame(wrap, fg_color="transparent")
    row.pack(fill="x", side="bottom", pady=(16, 0))
    ghost_button(row, "Test connection", test, width=140).pack(side="left")
    accent_button(row, "Save & sync", save, width=130).pack(side="right")
    ghost_button(row, "Save only", save_offline, width=100).pack(
        side="right", padx=(0, 8))
    ghost_button(row, "Cancel", top.destroy, width=90).pack(side="right",
                                                            padx=(0, 8))
    top.bind("<Escape>", lambda e: top.destroy())
    app._fit_modal(top)


# ==========================================================================
# First run on a second PC
# ==========================================================================
def restore_from_server_dialog(app):
    """
    Pull a vault down onto a PC that has none.

    Separate from an ordinary sync because there is nothing local to merge
    against: this is a straight download, and it refuses to run if a vault
    for that username already exists so it can never overwrite one.
    """
    top = app._modal("Restore from server", 520, 660)
    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=28, pady=24)

    ctk.CTkLabel(wrap, text="Restore from server", font=F(20, "bold"),
                 text_color=TEXT).pack(anchor="w")
    ctk.CTkLabel(
        wrap,
        text="Download a vault you already sync from another PC. You will "
             "need the server address, its token, and the master password "
             "that vault was created with.",
        font=F(12), text_color=MUTED, wraplength=450,
        justify="left").pack(anchor="w", pady=(2, 4))

    url_entry = field(wrap, "Server address", placeholder="http://192.168.1.50:8787")
    token_entry = field(wrap, "Sync token", show="•")
    user_entry = field(wrap, "Username", placeholder="the name on the other PC")
    pw_entry = field(wrap, "Master password", show="•")

    status = ctk.CTkLabel(wrap, text="", font=F(12), text_color=DANGER,
                          wraplength=450, justify="left")
    status.pack(anchor="w", pady=(10, 0))

    def restore():
        url = url_entry.get().strip()
        token = token_entry.get().strip()
        username = user_entry.get().strip()
        password = pw_entry.get()

        if not (url and token and username and password):
            return status.configure(text="Every field is required.",
                                    text_color=DANGER)
        try:
            vault.validate_username(username)
        except ValueError as e:
            return status.configure(text=str(e), text_color=DANGER)

        import os
        if os.path.exists(vault.get_vault_path(username)):
            return status.configure(
                text=f"This PC already has a vault for \u201c{username}\u201d. "
                     "Unlock it and press Sync instead — that merges the two "
                     "rather than replacing one with the other.",
                text_color=DANGER)

        status.configure(text="Downloading…", text_color=MUTED)

        def work():
            client = sync_client.SyncClient(url, token, timeout=20)
            fetched, revision = sync_client.download_vault(client, username,
                                                           password)
            if fetched is None:
                raise sync_client.SyncError(
                    f"The server holds no vault for \u201c{username}\u201d.")
            sync_client.set_settings(fetched, url, token)
            vault.create_new_user(username, password)
            vault.save_vault(password, fetched, username)
            # Both sides agree right now, so this download is the base for
            # every later merge.
            vault.save_base(password, fetched, username,
                            origin=sync_client.base_origin_for(url, revision))
            return fetched

        def done(fetched):
            top.destroy()
            count = len(vault.active_accounts(fetched))
            app.toast(f"Restored {count} account{'s' if count != 1 else ''}")
            app.show_login_screen()

        _in_background(app, work, done,
                       on_error=lambda e: status.configure(text=str(e),
                                                           text_color=DANGER))

    row = ctk.CTkFrame(wrap, fg_color="transparent")
    row.pack(fill="x", side="bottom", pady=(16, 0))
    ghost_button(row, "Cancel", top.destroy, width=110).pack(side="left")
    accent_button(row, "Restore", restore, width=140).pack(side="right")
    top.bind("<Escape>", lambda e: top.destroy())
    app._fit_modal(top)
