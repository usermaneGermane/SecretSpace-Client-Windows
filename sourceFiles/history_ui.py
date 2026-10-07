"""
The revision history drop-down under each account row.

Presentation only: recording, reverting and clearing revisions all live in
vault.py (update_entry, revert_entry, clear_history), and merging them across
PCs in sync.py. Nothing here decides what a revision is.
"""

from datetime import datetime, timezone

import customtkinter as ctk

import vault
from theme import (F, TEXT, MUTED, GREEN, GREEN_HOVER, DANGER, DANGER_HOVER,
                   BORDER, CARD_HOVER, ON_ACCENT, HEADER_BG, MONO)
from widgets import Tooltip

#: How the fields are named to the user.
FIELD_LABELS = {"site": "site", "username": "username",
                "password": "password", "notes": "notes", "totp": "2FA"}

#: Seconds a revealed earlier password stays visible, as on the row itself.
REVEAL_SECONDS = 10


def local_time(stamp: str) -> str:
    """A stored UTC timestamp, in this PC's time zone, for display."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            moment = datetime.strptime(stamp, fmt).replace(tzinfo=timezone.utc)
            return moment.astimezone().strftime("%d %b %Y, %H:%M")
        except (TypeError, ValueError):
            continue
    return "unknown time"


def describe(rev: dict) -> str:
    """What the edit that replaced this version changed, in a few words."""
    changed = rev.get("changed") or []
    if not changed:
        return "earlier version"
    text = ", ".join(FIELD_LABELS.get(f, f) for f in changed) + " changed"
    # The password is shown on the line itself; a changed site or username
    # would otherwise be invisible, so name what it used to be.
    was = []
    if "site" in changed:
        was.append(f"site was {rev.get('site') or '—'}")
    if "username" in changed:
        was.append(f"username was {rev.get('username') or '—'}")
    return text + ("  ·  " + ", ".join(was) if was else "")


def _small_button(parent, text, command, accent=False, danger=False, width=62):
    if accent:
        return ctk.CTkButton(parent, text=text, command=command, width=width,
                             height=30, corner_radius=8, fg_color=GREEN,
                             hover_color=GREEN_HOVER, text_color=ON_ACCENT,
                             font=F(11, "bold"))
    return ctk.CTkButton(parent, text=text, command=command, width=width,
                         height=30, corner_radius=8, fg_color="transparent",
                         border_width=1, border_color=BORDER,
                         hover_color=DANGER_HOVER if danger else CARD_HOVER,
                         text_color=DANGER if danger else TEXT,
                         font=F(11, "bold"))


def attach(app, row, acc, buttons, column):
    """
    Give an account row its History button (in ``buttons`` at ``column``)
    and the drop-down beneath the row.

    Which rows are open is remembered on the app, so the panel stays open
    across the list refresh that a revert or a sync triggers.
    """
    count = len(acc.get("history") or [])
    toggle_btn = ctk.CTkButton(
        buttons, text="History", width=70, height=34, corner_radius=8,
        fg_color="transparent", border_width=1, border_color=BORDER,
        hover_color=CARD_HOVER, text_color=TEXT if count else MUTED,
        font=F(13, "bold"))
    toggle_btn.grid(row=0, column=column, padx=4)
    Tooltip(toggle_btn,
            f"History — {count} earlier version{'s' if count != 1 else ''}"
            if count else "History — no earlier versions yet")

    state = {"panel": None}

    def open_panel():
        state["panel"] = _build_panel(app, row, acc)
        app._history_open.add(acc["id"])

    def close_panel():
        if state["panel"] is not None:
            state["panel"].destroy()
            state["panel"] = None
        app._history_open.discard(acc["id"])

    toggle_btn.configure(
        command=lambda: close_panel() if state["panel"] else open_panel())
    if acc["id"] in app._history_open:
        open_panel()


def _build_panel(app, row, acc):
    panel = ctk.CTkFrame(row, fg_color=HEADER_BG, corner_radius=10)
    panel.grid(row=1, column=0, columnspan=5, sticky="ew",
               padx=14, pady=(0, 12))
    panel.grid_columnconfigure(1, weight=1)

    history = acc.get("history") or []
    head = ctk.CTkFrame(panel, fg_color="transparent")
    head.grid(row=0, column=0, columnspan=6, sticky="ew", padx=12, pady=(10, 4))
    ctk.CTkLabel(head, text="Earlier versions", font=F(13, "bold"),
                 text_color=TEXT).pack(side="left")
    ctk.CTkLabel(head, text=f"   newest first · the last {vault.HISTORY_LIMIT} "
                            "are kept", font=F(11),
                 text_color=MUTED).pack(side="left")

    if not history:
        ctk.CTkLabel(panel, text="None yet. Each time you edit this entry, "
                     "the version you replace is kept here.", font=F(12),
                     text_color=MUTED, anchor="w").grid(
            row=1, column=0, columnspan=6, sticky="w", padx=12, pady=(0, 12))
        return panel

    for i, rev in enumerate(history, start=1):
        _revision_line(app, panel, i, acc, rev)

    clear = _small_button(panel, "Clear history",
                          lambda: _clear(app, acc), danger=True, width=110)
    clear.grid(row=len(history) + 1, column=0, columnspan=6, sticky="e",
               padx=12, pady=(6, 10))
    Tooltip(clear, "Forget these versions here and on your other PCs")
    return panel


def _revision_line(app, panel, line, acc, rev):
    ctk.CTkLabel(panel, text=local_time(rev.get("replaced_at", "")), width=150,
                 anchor="w", font=F(12), text_color=TEXT).grid(
        row=line, column=0, sticky="w", padx=(12, 8), pady=3)
    ctk.CTkLabel(panel, text=describe(rev), anchor="w", font=F(11),
                 text_color=MUTED).grid(row=line, column=1, sticky="w", pady=3)

    secret = rev.get("password", "")
    pwd = ctk.CTkLabel(panel, text="•" * 8, width=140, anchor="e",
                       font=ctk.CTkFont(family=MONO, size=13),
                       text_color=MUTED)
    pwd.grid(row=line, column=2, padx=(8, 8), pady=3)

    reveal = {"shown": False, "job": None}

    def toggle():
        if reveal["shown"]:
            pwd.configure(text="•" * 8, text_color=MUTED)
            show.configure(text="Show")
            reveal["shown"] = False
            if reveal["job"]:
                app.root.after_cancel(reveal["job"])
                reveal["job"] = None
        else:
            pwd.configure(text=secret or "—", text_color=TEXT)
            show.configure(text="Hide")
            reveal["shown"] = True
            reveal["job"] = app.root.after(REVEAL_SECONDS * 1000, toggle)

    show = _small_button(panel, "Show", toggle)
    show.grid(row=line, column=3, padx=2, pady=3)
    _small_button(panel, "Copy",
                  lambda: app._copy(secret, "Earlier password copied",
                                    sensitive=True)).grid(
        row=line, column=4, padx=2, pady=3)
    revert = _small_button(panel, "Revert", lambda: _revert(app, acc, rev),
                           accent=True)
    revert.grid(row=line, column=5, padx=(2, 12), pady=3)
    Tooltip(revert, "Make this version current again — the current one is "
                    "kept here, so this can be undone")


def _revert(app, acc, rev):
    when = local_time(rev.get("replaced_at", ""))
    if not app._confirm(
            "Revert to an earlier version",
            f"Make the version of “{acc['site']}” replaced on {when} "
            "current again?\n\nThe current version is kept in this entry's "
            "history, so you can switch back.", danger=False):
        return
    if vault.revert_entry(acc, rev["rid"]):
        app._save()
        app.refresh_account_list()
        app.toast("Reverted — the previous version is in its history")


def _clear(app, acc):
    if not app._confirm(
            "Clear history",
            f"Forget every earlier version of “{acc['site']}”?\n\n"
            "This cannot be undone, and your other PCs forget them too on "
            "their next sync. Worth doing if an old password was exposed."):
        return
    vault.clear_history(acc)
    app._save()
    app.refresh_account_list()
    app.toast("History cleared", "warn")
