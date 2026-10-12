"""
PassMan - a modern desktop password manager.

Only the presentation layer lives here, and only the application shell: the
login screen, the account list and the session lifecycle. The palette lives in
theme.py, reusable widgets in widgets.py and the modal dialogs in dialogs.py.

The vault is still encrypted exactly as before with AES-GCM + PBKDF2 (see
crypto_utils.py / vault.py); this file never touches the cipher, it just talks
to load_vault / save_vault.
"""

import os
import time

import customtkinter as ctk
import pyperclip

import appconfig
import dialogs
import history_ui
import lockout
import sync_ui
from theme import (F, HEADER_BG, CARD, CARD_HOVER, INPUT_BG, BORDER, TEXT,
                   MUTED, GREEN, GREEN_HOVER, DANGER, DANGER_HOVER,
                   ON_ACCENT, WARN, MONO,
                   avatar_color, asset_candidates)
from widgets import (Tooltip, ghost_button, accent_button, field,
                     strength_widget, modal, fit_modal, safe_grab, confirm)
from vault import (load_vault, save_vault, needs_rekey, active_accounts,
                   archive_account, sort_accounts, SORT_ORDERS,
                   auto_purge_archive, archive_purge_days,
                   window_title)
from version import version_string

CLIPBOARD_CLEAR_MS = 30_000     # auto-clear copied passwords after 30s
IDLE_POLL_MS = 15_000           # how often the auto-lock timer checks in

SEARCH_DEBOUNCE_MS = 150        # wait for a pause in typing before filtering
ROW_SLICE_SECONDS = 0.1         # list work per step before redrawing the window

#: What the Sort menu shows for each of vault.SORT_ORDERS.
SORT_LABELS = {
    "modified_desc": "Recently modified",
    "modified_asc": "Oldest modified",
    "name_asc": "Name A → Z",
    "name_desc": "Name Z → A",
}


def _row_signature(acc):
    """
    Everything an account row shows or closes over. A cached row is reused
    only while this is unchanged; ``id(acc)`` covers a sync or a reload that
    replaces the entry dicts, which the row's buttons hold on to.
    """
    return (id(acc), acc.get("site"), acc.get("username"),
            acc.get("password"), bool(acc.get("notes")), bool(acc.get("totp")),
            tuple(r.get("rid") for r in acc.get("history") or []))


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(window_title())
        self.root.geometry("980x660")
        self.root.minsize(840, 580)

        self.vault = None
        self.master_password = None
        self.current_user = None

        self.search_query = ""
        self.sort_order = appconfig.sort_order()
        self._search_job = None
        # Account rows by entry id, as (row_signature, frame). Building a row
        # is slow -- each CTk button draws itself on a canvas -- so a refresh
        # reuses every row whose entry has not changed and only re-grids it.
        self._rows = {}
        self._row_job = None
        self._empty_box = None
        self._toast_job = None
        self._toast = None
        self.icon_path = None
        self._clip_job = None
        self._clip_text = None
        self._idle_job = None
        self._lockout_job = None
        self._last_activity = time.monotonic()
        self._autolock_seconds = appconfig.DEFAULT_AUTOLOCK_MINUTES * 60
        self._syncing = False
        # Entry ids whose history drop-down is open, so it survives the list
        # being rebuilt after a revert or a sync.
        self._history_open = set()

        self._load_branding()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        # Bound once for the life of the app: binding these in
        # show_main_window() would stack another handler on every unlock.
        for seq in ("<Any-KeyPress>", "<Any-Button>", "<MouseWheel>"):
            self.root.bind_all(seq, self._mark_activity, add="+")
        self.show_login_screen()

    # ------------------------------------------------------------------
    # Branding (window icon + login logo) - all optional / best effort
    # ------------------------------------------------------------------
    def _load_branding(self):
        for p in asset_candidates("PassMan-logo.ico"):
            if os.path.exists(p):
                try:
                    self.root.iconbitmap(p)
                    self.icon_path = p
                    break
                except Exception:
                    pass

        self.logo_image = None
        for p in asset_candidates("PassMan-logo.png"):
            if os.path.exists(p):
                try:
                    from PIL import Image
                    img = Image.open(p)
                    self.logo_image = ctk.CTkImage(light_image=img,
                                                   dark_image=img, size=(72, 72))
                    break
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Small shared helpers
    # ------------------------------------------------------------------
    def _clear(self):
        self._cancel_row_build()
        if self._search_job:
            self.root.after_cancel(self._search_job)
            self._search_job = None
        for w in self.root.winfo_children():
            w.destroy()
        self._toast = None
        self._rows = {}
        self._empty_box = None

    def _avatar_color(self, s):
        return avatar_color(s)

    # ------------------------------------------------------------------
    # Thin wrappers over widgets.py, so dialog code reads the same as before
    # ------------------------------------------------------------------
    def _ghost_button(self, parent, text, command, width=120, danger=False):
        return ghost_button(parent, text, command, width, danger)

    def _accent_button(self, parent, text, command, width=140):
        return accent_button(parent, text, command, width)

    def _modal(self, title, w, h):
        return modal(self.root, title, w, h, self.icon_path)

    def _safe_grab(self, top):
        safe_grab(self.root, top, self.icon_path)

    def _fit_modal(self, top):
        fit_modal(self.root, top)

    def toast(self, message, kind="info"):
        """Small auto-dismissing status pill at the bottom of the window."""
        color = {"info": GREEN, "error": DANGER, "warn": WARN}.get(kind, GREEN)
        if self._toast is not None:
            self._toast.destroy()
        if self._toast_job:
            self.root.after_cancel(self._toast_job)
        self._toast = ctk.CTkLabel(
            self.root, text=f"   {message}   ", height=38, corner_radius=12,
            fg_color=color, text_color=ON_ACCENT if kind == "info" else "white",
            font=F(13, "bold"),
        )
        self._toast.place(relx=0.5, rely=1.0, anchor="s", y=-22)
        self._toast_job = self.root.after(2400, self._hide_toast)

    def _hide_toast(self):
        if self._toast is not None:
            self._toast.destroy()
            self._toast = None

    def _save(self, rekey=False):
        try:
            save_vault(self.master_password, self.vault, self.current_user,
                       rekey=rekey)
            return True
        except Exception as e:
            self.toast(f"Save failed: {e}", "error")
            return False

    def _copy(self, text, message, sensitive=False):
        if not text:
            self.toast("Nothing to copy", "warn")
            return
        try:
            pyperclip.copy(text)
        except Exception:
            self.toast("Could not access clipboard", "error")
            return
        if sensitive:
            # Auto-clear so a copied password can't be pasted hours later.
            self.toast(f"{message} · clears in {CLIPBOARD_CLEAR_MS // 1000}s")
            # NB: this clears the live clipboard only. Windows clipboard
            # history (Win+V) and cloud sync keep their own copy that no
            # application can reach.
            if self._clip_job:
                self.root.after_cancel(self._clip_job)
            self._clip_text = text
            self._clip_job = self.root.after(
                CLIPBOARD_CLEAR_MS, lambda: self._clear_clipboard(text))
        else:
            self.toast(message)

    def _clear_clipboard(self, expected, quiet=False):
        """Clear the clipboard if it still holds the password we put there."""
        self._clip_job = None
        self._clip_text = None
        try:
            if pyperclip.paste() == expected:
                pyperclip.copy("")
                if not quiet:
                    self.toast("Clipboard cleared")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Idle auto-lock
    # ------------------------------------------------------------------
    def _mark_activity(self, _=None):
        """Any keystroke or click counts as the user still being here."""
        self._last_activity = time.monotonic()

    def _start_idle_timer(self):
        """
        Begin polling for inactivity. Polling a timestamp every few seconds is
        cheaper than rescheduling an `after` job on every mouse move, and it
        keeps working if a modal dialog is holding the grab.
        """
        self._cancel_idle_timer()
        self._mark_activity()
        # Cached here rather than read from disk on every poll; settings_dialog
        # calls this again whenever the value changes.
        self._autolock_seconds = appconfig.autolock_minutes() * 60
        self._idle_job = self.root.after(IDLE_POLL_MS, self._idle_check)

    def _cancel_idle_timer(self):
        if self._idle_job:
            try:
                self.root.after_cancel(self._idle_job)
            except Exception:
                pass
            self._idle_job = None

    def _idle_check(self):
        self._idle_job = None
        if not self.current_user:
            return
        limit = self._autolock_seconds
        if limit and (time.monotonic() - self._last_activity) >= limit:
            self.lock_vault(auto=True)
            return
        self._idle_job = self.root.after(IDLE_POLL_MS, self._idle_check)

    # ==================================================================
    # Login screen
    # ==================================================================
    def show_login_screen(self):
        self._cancel_lockout_timer()
        self._clear()

        outer = ctk.CTkFrame(self.root, fg_color="transparent")
        outer.pack(expand=True)

        card = ctk.CTkFrame(outer, fg_color=CARD, corner_radius=20)
        card.pack(padx=24, pady=24)
        pad = ctk.CTkFrame(card, fg_color="transparent")
        pad.pack(padx=44, pady=40)

        if self.logo_image is not None:
            ctk.CTkLabel(pad, image=self.logo_image, text="").pack(pady=(0, 10))
        ctk.CTkLabel(pad, text="PassMan", font=F(30, "bold"),
                     text_color=GREEN).pack()
        ctk.CTkLabel(pad, text="Unlock your secure vault", font=F(13),
                     text_color=MUTED).pack(pady=(2, 0))
        ctk.CTkLabel(pad, text=version_string(), font=F(11),
                     text_color=MUTED).pack(pady=(2, 20))

        self.username_entry = ctk.CTkEntry(
            pad, width=300, height=46, corner_radius=10, fg_color=INPUT_BG,
            border_color=BORDER, font=F(14), placeholder_text="Username")
        self.username_entry.pack(pady=7)

        pw_row = ctk.CTkFrame(pad, fg_color="transparent", width=300, height=46)
        pw_row.pack(pady=7)
        pw_row.grid_propagate(False)
        pw_row.grid_columnconfigure(0, weight=1)
        self.password_entry = ctk.CTkEntry(
            pw_row, height=46, corner_radius=10, fg_color=INPUT_BG, show="•",
            border_color=BORDER, font=F(14), placeholder_text="Master password")
        self.password_entry.grid(row=0, column=0, sticky="ew")
        reveal_btn = ctk.CTkButton(
            pw_row, text="Show", width=58, height=46, corner_radius=10,
            fg_color="transparent", border_width=1, border_color=BORDER,
            hover_color=CARD_HOVER, text_color=MUTED, font=F(12, "bold"))
        reveal_btn.grid(row=0, column=1, padx=(8, 0))

        def toggle_pw():
            if self.password_entry.cget("show"):
                self.password_entry.configure(show="")
                reveal_btn.configure(text="Hide")
            else:
                self.password_entry.configure(show="•")
                reveal_btn.configure(text="Show")
        reveal_btn.configure(command=toggle_pw)

        self.login_error = ctk.CTkLabel(pad, text="", font=F(12),
                                        text_color=DANGER)
        self.login_error.pack(pady=(8, 2))

        unlock = self._accent_button(pad, "Unlock Vault", self.unlock_vault, width=300)
        unlock.configure(height=46)
        unlock.pack(pady=(4, 14))
        self.unlock_button = unlock

        ctk.CTkLabel(pad, text="New here?", font=F(12), text_color=MUTED).pack()
        self._ghost_button(pad, "Create a new user",
                           self.create_user_dialog, width=300).pack(pady=(6, 0))
        # The second PC's starting point: there is no vault here yet, so there
        # is nothing to unlock and nothing to merge -- just a download.
        self._ghost_button(pad, "Restore from server",
                           self.restore_from_server_dialog,
                           width=300).pack(pady=(8, 0))

        self.username_entry.bind("<Return>", lambda e: self.password_entry.focus())
        self.password_entry.bind("<Return>", lambda e: self.unlock_vault())

        # Prefill the last-used username (not a secret) and go straight to
        # the password field, so a returning user only types one thing.
        last = appconfig.load_config().get("last_username", "")
        if last:
            self.username_entry.insert(0, last)
            self.password_entry.focus()
            # A penalty earned before the app was closed is still in force.
            if lockout.remaining(last):
                self._begin_lockout(last, lockout.remaining(last))
        else:
            self.username_entry.focus()

    def _begin_lockout(self, username, seconds):
        """Disable unlocking and tick down the remaining wait."""
        self._cancel_lockout_timer()

        def tick():
            left = lockout.remaining(username)
            if left <= 0:
                self._lockout_job = None
                try:
                    self.unlock_button.configure(state="normal",
                                                 text="Unlock Vault")
                    self._login_error("")
                except Exception:
                    pass
                return
            try:
                self.unlock_button.configure(state="disabled",
                                             text=f"Locked ({left}s)")
                self._login_error(
                    f"Too many attempts. Try again in {left} second(s).")
            except Exception:
                self._lockout_job = None
                return
            self._lockout_job = self.root.after(1000, tick)

        tick()

    def _cancel_lockout_timer(self):
        if self._lockout_job:
            try:
                self.root.after_cancel(self._lockout_job)
            except Exception:
                pass
            self._lockout_job = None

    def _login_error(self, msg):
        self.login_error.configure(text=msg)

    def unlock_vault(self):
        username = self.username_entry.get().strip()
        master_password = self.password_entry.get()
        if not username or not master_password:
            self._login_error("Enter your username and master password.")
            return

        wait = lockout.remaining(username)
        if wait:
            self._begin_lockout(username, wait)
            return
        # Load first and only switch screens once it has succeeded. Doing the
        # two together meant a failure inside show_main_window() was caught by
        # the handler below, which then wrote to a login widget that
        # show_main_window()'s _clear() had already destroyed.
        try:
            loaded = load_vault(master_password, username)
        except FileNotFoundError:
            self._login_error("No vault found for that username.")
            return
        except ValueError as e:
            msg = str(e)
            if "Decryption failed" not in msg:
                self._login_error(msg)       # a real vault problem, not a typo
                return
            wait = lockout.record_failure(username)
            if wait:
                self._begin_lockout(username, wait)
            else:
                left = lockout.FREE_ATTEMPTS - lockout.failures(username)
                self._login_error("Incorrect username or master password." +
                                  (f" {left} attempt(s) before a delay."
                                   if left else ""))
            return
        except Exception as e:
            self._login_error(str(e))
            return

        lockout.reset(username)
        self.vault = loaded
        self.master_password = master_password
        self.current_user = username
        appconfig.save_config(last_username=username)

        # Silently bring an older vault up to the current KDF cost.
        if needs_rekey(username):
            self._save()

        # Archived entries past this vault's keep-for limit (Settings).
        purged = auto_purge_archive(self.vault)
        if purged:
            self._save()

        self.show_main_window()
        if purged:
            self.toast(f"Deleted {purged} archived "
                       f"entr{'y' if purged == 1 else 'ies'} older than "
                       f"{archive_purge_days(self.vault)} days", "warn")


    # ==================================================================
    # Main window
    # ==================================================================
    def show_main_window(self):
        self._clear()
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        # ---- header ----
        header = ctk.CTkFrame(self.root, fg_color=HEADER_BG, corner_radius=0,
                              height=76)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.grid_columnconfigure(1, weight=1)

        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.grid(row=0, column=0, padx=22, pady=14, sticky="w")
        ctk.CTkLabel(brand, text="PassMan", font=F(20, "bold"),
                     text_color=GREEN).pack(anchor="w")
        ctk.CTkLabel(brand, text=f"Vault · {self.current_user}", font=F(12),
                     text_color=MUTED).pack(anchor="w")

        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.grid(row=0, column=2, padx=22, sticky="e")

        self.search_entry = ctk.CTkEntry(
            controls, width=190, height=40, corner_radius=10, fg_color=INPUT_BG,
            border_color=BORDER, font=F(13), placeholder_text="Search accounts...")
        self.search_entry.grid(row=0, column=0, padx=(0, 10))
        self.search_entry.bind("<KeyRelease>", self._on_search)

        sync_btn = self._ghost_button(controls, "Sync", self.sync_now, width=80)
        sync_btn.grid(row=0, column=1, padx=(0, 10))
        Tooltip(sync_btn, "Merge this vault with the one on your server")

        imp = self._ghost_button(controls, "Import", self.import_dialog, width=90)
        imp.grid(row=0, column=2, padx=(0, 10))
        Tooltip(imp, "Import accounts from a CSV or JSON file")
        self._ghost_button(controls, "Generate", self.generator_dialog,
                           width=100).grid(row=0, column=3, padx=(0, 10))
        self._accent_button(controls, "+  Add account", self.add_account_dialog,
                            width=145).grid(row=0, column=4, padx=(0, 10))
        gear = self._ghost_button(controls, "⚙", self.settings_dialog, width=44)
        gear.grid(row=0, column=5, padx=(0, 10))
        Tooltip(gear, "Settings")
        lock = self._ghost_button(controls, "Lock", self.lock_vault, width=80)
        lock.grid(row=0, column=6)
        Tooltip(lock, "Lock the vault and sign out")

        # ---- account list ----
        self.list_frame = ctk.CTkScrollableFrame(self.root, fg_color="transparent")
        self.list_frame.grid(row=1, column=0, sticky="nsew", padx=18, pady=(12, 6))
        self.list_frame.grid_columnconfigure(0, weight=1)

        # ---- footer ----
        footer = ctk.CTkFrame(self.root, fg_color=HEADER_BG, corner_radius=0,
                              height=46)
        footer.grid(row=2, column=0, sticky="ew")
        footer.grid_propagate(False)
        self.count_label = ctk.CTkLabel(footer, text="", font=F(11),
                                        text_color=MUTED)
        self.count_label.pack(side="left", padx=(20, 12))

        # The archive lives down here rather than in the crowded header: it is
        # somewhere you go occasionally, and it belongs next to the count that
        # tells you there is something in it.
        self.archive_btn = ctk.CTkButton(
            footer, text="Archive", command=self.archive_dialog, width=110,
            height=28, corner_radius=8, fg_color="transparent", border_width=1,
            border_color=BORDER, hover_color=CARD_HOVER, text_color=MUTED,
            font=F(11, "bold"))
        self.archive_btn.pack(side="left", pady=8)
        Tooltip(self.archive_btn, "Entries you removed, kept so they can be "
                                  "restored")

        ctk.CTkLabel(footer, text=version_string(), font=F(11),
                     text_color=MUTED).pack(side="right", padx=20)

        sort_menu = ctk.CTkOptionMenu(
            footer, width=160, height=28, corner_radius=8,
            values=[SORT_LABELS[o] for o in SORT_ORDERS],
            fg_color=INPUT_BG, button_color=BORDER,
            button_hover_color=CARD_HOVER, text_color=TEXT, font=F(11),
            command=self._on_sort)
        sort_menu.set(SORT_LABELS[self.sort_order])
        sort_menu.pack(side="right", pady=8)
        ctk.CTkLabel(footer, text="Sort", font=F(11),
                     text_color=MUTED).pack(side="right", padx=(0, 8))

        self.refresh_account_list()
        self._start_idle_timer()

    def _on_search(self, _=None):
        # Every keystroke lands here, so filter once typing pauses rather
        # than re-gridding the whole list per letter.
        if self._search_job:
            self.root.after_cancel(self._search_job)
        self._search_job = self.root.after(SEARCH_DEBOUNCE_MS,
                                           self._apply_search)

    def _apply_search(self):
        self._search_job = None
        query = self.search_entry.get()
        if query != self.search_query:
            self.search_query = query
            self.refresh_account_list()

    def _on_sort(self, label):
        for order, text in SORT_LABELS.items():
            if text == label:
                self.sort_order = order
                appconfig.save_config(sort_order=order)
                break
        self.refresh_account_list()

    def refresh_account_list(self):
        self._cancel_row_build()
        if self._empty_box is not None:
            self._empty_box.destroy()
            self._empty_box = None

        accounts = active_accounts(self.vault)
        active = {a["id"]: a for a in accounts}
        total = len(accounts)
        archived = len(self.vault["accounts"]) - total
        q = self.search_query.strip().lower()
        if q:
            accounts = [a for a in accounts
                        if q in a["site"].lower() or q in a["username"].lower()]
        accounts = sort_accounts(accounts, self.sort_order)

        self.count_label.configure(
            text=f"{total} account{'s' if total != 1 else ''} stored"
                 + (f"   ·   {archived} archived" if archived else ""))
        if hasattr(self, "archive_btn"):
            self.archive_btn.configure(text=f"Archive ({archived})" if archived
                                       else "Archive")

        # Drop the rows of entries that are gone or have changed. Hide every
        # row that is filtered out or moving: hiding is cheap, and a moving
        # row left in place until its turn would overlap its new neighbour.
        # Rows already where they belong are not touched at all.
        position = {a["id"]: i for i, a in enumerate(accounts)}
        for eid, cached in list(self._rows.items()):
            sig, frame, pos = cached
            acc = active.get(eid)
            if acc is None or _row_signature(acc) != sig:
                frame.destroy()
                del self._rows[eid]
            elif pos is not None and position.get(eid) != pos:
                frame.grid_remove()
                cached[2] = None

        if not accounts:
            self._empty_state(filtered=bool(q))
            return

        self._place_rows([(i, a) for i, a in enumerate(accounts)
                          if a["id"] not in self._rows
                          or self._rows[a["id"]][2] is None])

    def _place_rows(self, pending):
        """
        Show rows a slice at a time, yielding to the event loop in between,
        so a long vault fills in while the window keeps responding. Cached
        rows are only re-gridded; new or changed ones are built. Each lands
        at its final position, top first, so what is on screen is right.
        """
        self._row_job = None
        deadline = time.perf_counter() + ROW_SLICE_SECONDS
        while pending and time.perf_counter() < deadline:
            i, acc = pending.pop(0)
            cached = self._rows.get(acc["id"])
            if cached:
                cached[1].grid(row=i, column=0, sticky="ew", pady=6, padx=2)
                cached[2] = i
            else:
                self._rows[acc["id"]] = [_row_signature(acc),
                                         self._add_row(i, acc), i]
        if pending:
            self._row_job = self.root.after(1, lambda: self._place_rows(pending))

    def _cancel_row_build(self):
        if self._row_job:
            self.root.after_cancel(self._row_job)
            self._row_job = None

    def _empty_state(self, filtered):
        box = self._empty_box = ctk.CTkFrame(self.list_frame,
                                             fg_color="transparent")
        box.grid(row=0, column=0, pady=90)
        if filtered:
            ctk.CTkLabel(box, text="No matching accounts", font=F(17, "bold"),
                         text_color=TEXT).pack()
            ctk.CTkLabel(box, text="Try a different search term.", font=F(13),
                         text_color=MUTED).pack(pady=(4, 0))
        else:
            ctk.CTkLabel(box, text="Your vault is empty", font=F(18, "bold"),
                         text_color=TEXT).pack()
            ctk.CTkLabel(box, text="Add your first login to get started.",
                         font=F(13), text_color=MUTED).pack(pady=(4, 16))
            self._accent_button(box, "+  Add account",
                                self.add_account_dialog, width=170).pack()
            self._ghost_button(box, "Import from file",
                               self.import_dialog, width=170).pack(pady=(10, 0))

    def _add_row(self, i, acc):
        row = ctk.CTkFrame(self.list_frame, fg_color=CARD, corner_radius=12)
        row.grid(row=i, column=0, sticky="ew", pady=6, padx=2)
        row.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(row, text=(acc["site"][:1].upper() or "?"), width=46,
                     height=46, corner_radius=23, text_color="#FFFFFF",
                     fg_color=self._avatar_color(acc["site"]),
                     font=F(18, "bold")).grid(row=0, column=0, padx=(14, 14),
                                              pady=12)

        info = ctk.CTkFrame(row, fg_color="transparent")
        info.grid(row=0, column=1, sticky="w", pady=12)
        ctk.CTkLabel(info, text=acc["site"], anchor="w", font=F(15, "bold"),
                     text_color=TEXT).pack(anchor="w")
        subtitle = acc["username"] or "—"
        extras = [name for name, key in (("2FA", "totp"), ("note", "notes"))
                  if acc.get(key)]
        if extras:
            subtitle += "   ·   " + " · ".join(extras)
        ctk.CTkLabel(info, text=subtitle, anchor="w",
                     font=F(12), text_color=MUTED).pack(anchor="w")

        pwd_lbl = ctk.CTkLabel(row, text="•" * 8, width=150, anchor="e",
                               font=ctk.CTkFont(family=MONO, size=15),
                               text_color=MUTED)
        pwd_lbl.grid(row=0, column=3, padx=(8, 14))

        btns = ctk.CTkFrame(row, fg_color="transparent")
        btns.grid(row=0, column=4, padx=(0, 12))

        state = {"shown": False, "job": None}

        def toggle():
            if state["shown"]:
                pwd_lbl.configure(text="•" * 8, text_color=MUTED)
                show_btn.configure(text="Show")
                state["shown"] = False
                if state["job"]:
                    self.root.after_cancel(state["job"]); state["job"] = None
            else:
                pwd_lbl.configure(text=acc["password"], text_color=TEXT)
                show_btn.configure(text="Hide")
                state["shown"] = True
                state["job"] = self.root.after(10000, toggle)

        show_btn = ctk.CTkButton(
            btns, text="Show", width=58, height=34, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=BORDER,
            hover_color=CARD_HOVER, text_color=TEXT, font=F(12, "bold"),
            command=toggle)
        show_btn.grid(row=0, column=0, padx=4)
        Tooltip(show_btn, "Show / hide password")

        copy_pw = ctk.CTkButton(
            btns, text="Copy", width=58, height=34, corner_radius=8,
            fg_color=GREEN, hover_color=GREEN_HOVER, text_color=ON_ACCENT,
            font=F(12, "bold"),
            command=lambda: self._copy(acc["password"], "Password copied",
                                       sensitive=True))
        copy_pw.grid(row=0, column=1, padx=4)
        Tooltip(copy_pw, "Copy password — cleared after "
                         f"{CLIPBOARD_CLEAR_MS // 1000}s, but Windows "
                         "clipboard history (Win+V) may keep its own copy")

        copy_user = ctk.CTkButton(
            btns, text="User", width=58, height=34, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=BORDER,
            hover_color=CARD_HOVER, text_color=TEXT, font=F(12, "bold"),
            command=lambda: self._copy(acc["username"], "Username copied"))
        copy_user.grid(row=0, column=2, padx=4)
        Tooltip(copy_user, "Copy username")

        edit_btn = ctk.CTkButton(
            btns, text="✎", width=40, height=34, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=BORDER,
            hover_color=CARD_HOVER, text_color=TEXT, font=F(13, "bold"),
            command=lambda: self.account_dialog(acc))
        edit_btn.grid(row=0, column=4, padx=4)
        Tooltip(edit_btn, "Edit account")

        # History button at column 3, and the drop-down beneath this row.
        history_ui.attach(self, row, acc, btns, column=3)

        del_btn = ctk.CTkButton(
            btns, text="✕", width=40, height=34, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=BORDER,
            hover_color=DANGER_HOVER, text_color=DANGER, font=F(13, "bold"),
            command=lambda: self._archive_account(acc))
        del_btn.grid(row=0, column=5, padx=4)
        Tooltip(del_btn, "Move to archive — restorable, and it still syncs "
                         "the removal to your other PCs")
        return row

    def _archive_account(self, acc):
        """
        What used to be a delete.

        The entry keeps its password and moves to the archive, which is both
        an undo for the user and the tombstone the sync merge reads -- a hard
        delete would be resurrected by the next sync from the other PC.
        """
        if not self._confirm(
                "Move to archive",
                f"Move the saved login for “{acc['site']}” to the archive?\n\n"
                "It leaves this list but stays in your vault, and you can "
                "restore it at any time.", danger=False):
            return
        archive_account(self.vault, acc["id"])
        self._save()
        self.refresh_account_list()
        self.toast("Moved to archive")

    # ==================================================================
    # Import from file
    # ==================================================================



    # ==================================================================
    # Add / edit account (same dialog; acc=None means "add new")
    # ==================================================================


    # ==================================================================
    # Standalone password generator
    # ==================================================================

    # ==================================================================
    # Settings (danger zone)
    # ==================================================================

    # ------------------------------------------------------------------
    # Backup / export
    # ------------------------------------------------------------------




    # ==================================================================
    # Reusable widgets
    # ==================================================================
    def _field(self, parent, label, show=None, placeholder=""):
        return field(parent, label, show, placeholder)

    def _strength_widget(self, parent):
        return strength_widget(parent)

    def _confirm(self, title, message, danger=True):
        return confirm(self.root, title, message, danger, self.icon_path)

    # ------------------------------------------------------------------
    # Dialogs (implemented in dialogs.py)
    # ------------------------------------------------------------------
    def create_user_dialog(self):
        dialogs.create_user_dialog(self)

    def import_dialog(self):
        dialogs.import_dialog(self)

    def add_account_dialog(self):
        dialogs.account_dialog(self, None)

    def account_dialog(self, acc):
        dialogs.account_dialog(self, acc)

    def generator_dialog(self):
        dialogs.generator_dialog(self)

    def settings_dialog(self):
        dialogs.settings_dialog(self)

    def archive_dialog(self):
        sync_ui.archive_dialog(self)

    def sync_settings_dialog(self):
        sync_ui.sync_settings_dialog(self)

    def restore_from_server_dialog(self):
        sync_ui.restore_from_server_dialog(self)

    def sync_now(self, **options):
        sync_ui.run_sync(self, **options)

    # ==================================================================
    # Session lifecycle
    # ==================================================================
    def lock_vault(self, auto=False):
        self._cancel_idle_timer()
        if self.master_password and self.current_user:
            self._save()
        if self._clip_text is not None:
            if self._clip_job:
                self.root.after_cancel(self._clip_job)
            self._clear_clipboard(self._clip_text, quiet=True)
        self.vault = self.master_password = self.current_user = None
        self._history_open.clear()
        self.search_query = ""
        self.show_login_screen()
        if auto:
            self.toast("Vault locked after inactivity", "warn")

    def _on_close(self):
        self._cancel_idle_timer()
        self._cancel_lockout_timer()
        try:
            if self.master_password and self.current_user and self.vault is not None:
                self._save()
            if self._clip_text is not None:
                self._clear_clipboard(self._clip_text, quiet=True)
        except Exception:
            pass
        self.root.destroy()


if __name__ == "__main__":
    root = ctk.CTk()
    app = PasswordManagerGUI(root)
    root.mainloop()
