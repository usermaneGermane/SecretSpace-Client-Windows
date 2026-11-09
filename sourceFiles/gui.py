"""
SecretSpace - a modern desktop password manager.

Only the presentation layer lives here, and only the application shell: the
login screen, the account list with its details pane and the session
lifecycle. The palette lives in theme.py, reusable widgets in widgets.py and
the modal dialogs in dialogs.py.

The vault is still encrypted exactly as before with AES-GCM + PBKDF2 (see
crypto_utils.py / vault.py); this file never touches the cipher, it just talks
to load_vault / save_vault.
"""

import os
import time
import tkinter as tk

import customtkinter as ctk
import pyperclip

import appconfig
import dialogs
import history_ui
import lockout
import sync_client
import sync_ui
import totp
from theme import (F, BG, HEADER_BG, CARD, CARD_HOVER, SELECTED, INPUT_BG,
                   BORDER, TEXT, MUTED, GREEN, GREEN_HOVER, DANGER,
                   ON_ACCENT, WARN, MONO,
                   tile_colors, asset_candidates)
from widgets import (Tooltip, ghost_button, accent_button, field,
                     strength_widget, modal, fit_modal, safe_grab, confirm,
                     STRENGTH_SEGMENTS)
from password_generator import estimate_strength
from vault import (load_vault, save_vault, needs_rekey, active_accounts,
                   archive_account, sort_accounts, SORT_ORDERS,
                   auto_purge_archive, archive_purge_days, list_users,
                   window_title)
from version import version_string

CLIPBOARD_CLEAR_MS = 30_000     # auto-clear copied passwords after 30s
IDLE_POLL_MS = 15_000           # how often the auto-lock timer checks in
REVEAL_MS = 10_000              # a shown password hides itself again

SEARCH_DEBOUNCE_MS = 150        # wait for a pause in typing before filtering
ROW_SLICE_SECONDS = 0.1         # list work per step before redrawing the window

LOGIN_TILES_PER_ROW = 3

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
            acc.get("updated_at"),
            tuple(r.get("rid") for r in acc.get("history") or []))


def _clip(text, limit):
    """Shorten ``text`` for a fixed-width spot; Tk labels never truncate."""
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _initials(name):
    """Two letters for a vault avatar: 'alex.morgan' -> 'AM'."""
    parts = [p for p in name.replace("_", ".").replace("-", ".")
             .replace(" ", ".").split(".") if p]
    if len(parts) >= 2:
        return (parts[0][0] + parts[1][0]).upper()
    return (name[:2] or "?").upper()


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(window_title())
        self.root.geometry("1180x760")
        self.root.minsize(980, 640)
        self.root.configure(fg_color=BG)

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
        # Counts unlocks and locks, so a sync that finishes after its
        # vault was locked can tell (sync_ui._still_open).
        self._session = 0
        # The entry shown in the details pane, by id, so it survives the list
        # being rebuilt after an edit, a revert or a sync.
        self._selected_id = None
        self._reveal_job = None
        # The ticking 2FA code, while one is shown.
        self._totp_job = None
        self._login_user = ""
        self.search_entry = None

        self._load_branding()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        # Bound once for the life of the app: binding these in
        # show_main_window() would stack another handler on every unlock.
        for seq in ("<Any-KeyPress>", "<Any-Button>", "<MouseWheel>"):
            self.root.bind_all(seq, self._mark_activity, add="+")
        self.root.bind("<Control-f>", self._focus_search)
        self.show_login_screen()

    # ------------------------------------------------------------------
    # Branding (window icon + logo) - all optional / best effort
    # ------------------------------------------------------------------
    def _load_branding(self):
        for p in asset_candidates("SecretSpace-logo.ico"):
            if os.path.exists(p):
                try:
                    self.root.iconbitmap(p)
                    self.icon_path = p
                    break
                except Exception:
                    pass

        self.logo_image = self.logo_small = None
        for p in asset_candidates("SecretSpace-logo.png"):
            if os.path.exists(p):
                try:
                    from PIL import Image, ImageChops
                    img = Image.open(p).convert("RGBA")
                    # The PNG has a near-black square behind the shield; let
                    # the card show through it instead (channel ops, so it
                    # costs nothing at startup).
                    r, g, b, a = img.split()
                    lit = ImageChops.lighter(ImageChops.lighter(r, g), b)
                    img.putalpha(ImageChops.multiply(
                        a, lit.point(lambda v: 0 if v < 24 else 255)))
                    self.logo_image = ctk.CTkImage(light_image=img,
                                                   dark_image=img, size=(60, 60))
                    self.logo_small = ctk.CTkImage(light_image=img,
                                                   dark_image=img, size=(32, 32))
                    break
                except Exception:
                    pass

    def _logo(self, parent, small=False):
        """The logo image, or a green lettered square if it is missing."""
        image = self.logo_small if small else self.logo_image
        if image is not None:
            return ctk.CTkLabel(parent, image=image, text="")
        size = 32 if small else 60
        return ctk.CTkLabel(parent, text="P", width=size, height=size,
                            corner_radius=size // 3, fg_color=GREEN,
                            text_color=ON_ACCENT,
                            font=F(16 if small else 28, "bold"))

    @staticmethod
    def _circle(parent, text, size, bg, ink, font):
        """
        A round avatar. A CTkLabel cannot be one: it pads its text by its
        corner radius, so a radius of half the size turns it into a pill.
        Returns (frame, label) so callers can bind clicks on both.
        """
        disc = ctk.CTkFrame(parent, width=size, height=size,
                            corner_radius=size // 2, fg_color=bg)
        disc.pack_propagate(False)
        label = ctk.CTkLabel(disc, text=text, fg_color="transparent",
                             text_color=ink, font=font)
        label.place(relx=0.5, rely=0.5, anchor="center")
        return disc, label

    # ------------------------------------------------------------------
    # Small shared helpers
    # ------------------------------------------------------------------
    def _clear(self):
        self._cancel_row_build()
        self._cancel_reveal()
        if self._search_job:
            self.root.after_cancel(self._search_job)
            self._search_job = None
        for w in self.root.winfo_children():
            w.destroy()
        self._toast = None
        self._rows = {}
        self._empty_box = None
        self.search_entry = None

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
            fg_color=color,
            text_color=ON_ACCENT if kind in ("info", "warn") else "white",
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

        # A drawn backdrop behind the card: shapes only, redrawn to the
        # window's size.
        backdrop = tk.Canvas(self.root, bg=BG, highlightthickness=0, bd=0)
        backdrop.place(relx=0, rely=0, relwidth=1, relheight=1)
        backdrop.bind("<Configure>",
                      lambda e: self._draw_backdrop(backdrop, e.width, e.height))

        card = ctk.CTkFrame(backdrop, fg_color=CARD, corner_radius=24,
                            bg_color=BG, border_width=1, border_color=BORDER)
        card.place(relx=0.5, rely=0.5, anchor="center")
        pad = ctk.CTkFrame(card, fg_color="transparent")
        pad.pack(padx=40, pady=36)

        self._logo(pad).pack()
        ctk.CTkLabel(pad, text="Welcome back", font=F(26, "bold"),
                     text_color=TEXT).pack(pady=(12, 0))
        ctk.CTkLabel(pad, text="Pick your vault and enter its master password.",
                     font=F(13), text_color=MUTED).pack(pady=(4, 20))

        users = list_users()
        last = appconfig.load_config().get("last_username", "")
        self._login_user = last if last in users else (users[0] if users else "")
        self._login_tiles = ctk.CTkFrame(pad, fg_color="transparent")
        self._login_tiles.pack(fill="x")
        self._draw_login_tiles(users)

        ctk.CTkLabel(pad, text="Master password", font=F(12, "bold"),
                     text_color=MUTED, anchor="w").pack(fill="x", pady=(20, 6))
        pw_row = ctk.CTkFrame(pad, fg_color="transparent")
        pw_row.pack(fill="x")
        pw_row.grid_columnconfigure(0, weight=1)
        self.password_entry = ctk.CTkEntry(
            pw_row, height=50, corner_radius=14, fg_color=INPUT_BG, show="•",
            border_color=BORDER, font=F(15), placeholder_text="Master password")
        self.password_entry.grid(row=0, column=0, sticky="ew")
        reveal_btn = ctk.CTkButton(
            pw_row, text="Show", width=64, height=50, corner_radius=14,
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
                                        text_color=DANGER, wraplength=360)
        self.login_error.pack(pady=(8, 2))

        self.unlock_button = self._accent_button(
            pad, self._unlock_text(), self.unlock_vault, width=360)
        self.unlock_button.configure(height=52, corner_radius=14,
                                     font=F(15, "bold"))
        self.unlock_button.pack(fill="x", pady=(4, 16))

        links = ctk.CTkFrame(pad, fg_color="transparent")
        links.pack(fill="x")
        # The second PC's starting point: there is no vault here yet, so there
        # is nothing to unlock and nothing to merge -- just a download.
        for text, command, side in (
                ("Create a new user", self.create_user_dialog, "left"),
                ("Restore from server", self.restore_from_server_dialog,
                 "right")):
            ctk.CTkButton(links, text=text, command=command, width=10,
                          height=32, fg_color="transparent",
                          hover_color=CARD_HOVER, text_color=GREEN,
                          font=F(13, "bold")).pack(side=side)
        ctk.CTkLabel(pad, text=version_string(), font=F(11),
                     text_color=MUTED).pack(pady=(14, 0))

        self.password_entry.bind("<Return>", lambda e: self.unlock_vault())
        self.password_entry.focus()
        # A penalty earned before the app was closed is still in force.
        if self._login_user and lockout.remaining(self._login_user):
            self._begin_lockout(self._login_user,
                                lockout.remaining(self._login_user))

    def _draw_backdrop(self, canvas, w, h):
        canvas.delete("all")
        r1, r2 = max(w, h) * 0.17, max(w, h) * 0.21
        canvas.create_oval(w * 0.1 - r1, h * 0.16 - r1, w * 0.1 + r1,
                           h * 0.16 + r1, fill="#0F2117", outline="")
        canvas.create_oval(w * 0.93 - r2, h * 0.9 - r2, w * 0.93 + r2,
                           h * 0.9 + r2, fill="#101A14", outline="")
        # A lock, top right.
        x, y = w * 0.86, h * 0.2
        canvas.create_rectangle(x - 26, y - 6, x + 26, y + 34, outline=GREEN,
                                width=4)
        canvas.create_arc(x - 17, y - 32, x + 17, y + 2, start=0, extent=180,
                          style="arc", outline=GREEN, width=4)
        # A key, bottom left.
        x, y = w * 0.15, h * 0.8
        canvas.create_oval(x - 40, y - 18, x - 4, y + 18, outline="#7BE0A6",
                           width=4)
        canvas.create_line(x - 4, y, x + 44, y, fill="#7BE0A6", width=4)
        canvas.create_line(x + 30, y, x + 30, y + 16, fill="#7BE0A6", width=4)
        canvas.create_line(x + 42, y, x + 42, y + 12, fill="#7BE0A6", width=4)
        for fx, fy in ((0.3, 0.1), (0.7, 0.92), (0.96, 0.48), (0.05, 0.55)):
            canvas.create_oval(w * fx - 4, h * fy - 4, w * fx + 4, h * fy + 4,
                               fill="#1F3A2A", outline="")

    def _draw_login_tiles(self, users):
        """One tile per vault on this PC, plus one to create another."""
        for w in self._login_tiles.winfo_children():
            w.destroy()
        for c in range(LOGIN_TILES_PER_ROW):
            self._login_tiles.grid_columnconfigure(c, weight=1, uniform="tile")
        if not users:
            ctk.CTkLabel(self._login_tiles,
                         text="There is no vault on this PC yet. Create one, "
                              "or restore one from your server.",
                         font=F(13), text_color=MUTED, wraplength=360).grid(
                row=0, column=0, columnspan=LOGIN_TILES_PER_ROW)
            return
        for i, name in enumerate(users + [None]):
            tile = self._login_tile(name)
            tile.grid(row=i // LOGIN_TILES_PER_ROW,
                      column=i % LOGIN_TILES_PER_ROW, padx=6, pady=6,
                      sticky="ew")

    def _login_tile(self, name):
        picked = name is not None and name == self._login_user
        tile = ctk.CTkFrame(self._login_tiles, width=112, height=108,
                            corner_radius=18, border_width=2,
                            border_color=GREEN if picked else BORDER,
                            fg_color=SELECTED if picked else CARD)
        tile.pack_propagate(False)
        if name is None:
            avatar, letters = self._circle(tile, "+", 50, INPUT_BG, MUTED,
                                           F(22, "bold"))
            label = "Add vault"
            command = self.create_user_dialog
        else:
            bg, ink, _ = tile_colors(name)
            avatar, letters = self._circle(tile, _initials(name), 50, bg, ink,
                                           F(16, "bold"))
            label = _clip(name, 14)
            command = lambda: self._pick_login_user(name)
        avatar.pack(pady=(14, 6))
        caption = ctk.CTkLabel(tile, text=label, font=F(12, "bold"),
                               text_color=TEXT)
        caption.pack()
        for w in (tile, avatar, letters, caption):
            w.bind("<Button-1>", lambda e: command())
        if name is not None and len(name) > 14:
            Tooltip(tile, name)
        return tile

    def _pick_login_user(self, name):
        self._login_user = name
        self._draw_login_tiles(list_users())
        self._cancel_lockout_timer()
        wait = lockout.remaining(name)
        if wait:
            self._begin_lockout(name, wait)
        else:
            self.unlock_button.configure(state="normal",
                                         text=self._unlock_text())
            self._login_error("")
        self.password_entry.focus()

    def _unlock_text(self):
        return (f"Unlock {_clip(self._login_user, 24)}" if self._login_user
                else "Unlock")

    def _begin_lockout(self, username, seconds):
        """Disable unlocking and tick down the remaining wait."""
        self._cancel_lockout_timer()

        def tick():
            left = lockout.remaining(username)
            if left <= 0:
                self._lockout_job = None
                try:
                    self.unlock_button.configure(state="normal",
                                                 text=self._unlock_text())
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
        username = self._login_user
        master_password = self.password_entry.get()
        if not username:
            self._login_error("Create a vault or restore one from your "
                              "server first.")
            return
        if not master_password:
            self._login_error("Enter the master password.")
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
                self._login_error("Incorrect master password." +
                                  (f" {left} attempt(s) before a delay."
                                   if left else ""))
            return
        except Exception as e:
            self._login_error(str(e))
            return

        lockout.reset(username)
        self._session += 1
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
        self._sync_after_unlock()

    def _sync_after_unlock(self):
        """
        Settings -> Sync -> "Sync when I unlock", off by default. Started a
        moment after the main window is up, so the window draws first; a
        server that cannot be reached is a warning, not an error -- the vault
        is open and usable either way.
        """
        if not sync_client.sync_on_unlock(self.vault):
            return
        session = self._session

        def go():
            if self._session == session and self.vault is not None:
                self.sync_now(offline_hint="Not synced — the server can't be "
                                           "reached. Press Sync once you "
                                           "are connected.")

        self.root.after(400, go)


    # ==================================================================
    # Main window
    # ==================================================================
    def show_main_window(self):
        self._clear()
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        # ---- top bar ----
        bar = ctk.CTkFrame(self.root, fg_color=HEADER_BG, corner_radius=0,
                           height=72)
        bar.grid(row=0, column=0, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_rowconfigure(0, weight=1)
        bar.grid_columnconfigure(2, weight=1)

        brand = ctk.CTkFrame(bar, fg_color="transparent")
        brand.grid(row=0, column=0, padx=(24, 14))
        self._logo(brand, small=True).pack(side="left")
        ctk.CTkLabel(brand, text="SecretSpace", font=F(17, "bold"),
                     text_color=TEXT).pack(side="left", padx=(10, 0))

        bg, ink, _ = tile_colors(self.current_user)
        chip = ctk.CTkFrame(bar, fg_color=INPUT_BG, corner_radius=20,
                            border_width=1, border_color=BORDER, height=40)
        chip.grid(row=0, column=1)
        self._circle(chip, _initials(self.current_user), 30, bg, ink,
                     F(11, "bold"))[0].pack(side="left", padx=(5, 8), pady=5)
        ctk.CTkLabel(chip, text=_clip(self.current_user, 24),
                     font=F(13, "bold"), text_color=TEXT).pack(
            side="left", padx=(0, 14))
        Tooltip(chip, "The vault you unlocked. Lock to switch to another.")

        self.search_entry = ctk.CTkEntry(
            bar, height=44, corner_radius=22, fg_color=INPUT_BG,
            border_color=INPUT_BG, font=F(14),
            placeholder_text="Search sites and usernames   (Ctrl+F)")
        self.search_entry.grid(row=0, column=2, sticky="ew", padx=24)
        self.search_entry.bind("<KeyRelease>", self._on_search)

        controls = ctk.CTkFrame(bar, fg_color="transparent")
        controls.grid(row=0, column=3, padx=(0, 24))
        sync_btn = self._ghost_button(controls, "Sync", self.sync_now, width=74)
        sync_btn.pack(side="left", padx=(0, 8))
        Tooltip(sync_btn, "Merge this vault with the one on your server")
        imp = self._ghost_button(controls, "Import", self.import_dialog, width=80)
        imp.pack(side="left", padx=(0, 8))
        Tooltip(imp, "Import accounts from a CSV or JSON file")
        gen = self._ghost_button(controls, "Generate", self.generator_dialog,
                                 width=92)
        gen.pack(side="left", padx=(0, 8))
        Tooltip(gen, "Make a strong password")
        gear = self._ghost_button(controls, "⚙", self.settings_dialog, width=44)
        gear.pack(side="left", padx=(0, 8))
        Tooltip(gear, "Settings")
        lock = self._ghost_button(controls, "Lock", self.lock_vault, width=70)
        lock.pack(side="left")
        Tooltip(lock, "Lock the vault and sign out")

        # ---- body: the list on the left, the selected entry on the right ----
        body = ctk.CTkFrame(self.root, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=24, pady=20)
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=2, minsize=340)
        body.grid_columnconfigure(1, weight=3, minsize=480)

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        chips = ctk.CTkFrame(left, fg_color="transparent")
        chips.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        self.all_chip = ctk.CTkLabel(chips, text="All", height=34,
                                     corner_radius=17, fg_color=GREEN,
                                     text_color=ON_ACCENT, font=F(12, "bold"))
        self.all_chip.pack(side="left")
        # The archive sits beside the count: somewhere you go occasionally,
        # next to the number that tells you there is something in it.
        self.archive_btn = ctk.CTkButton(
            chips, text="Archive", command=self.archive_dialog, width=90,
            height=34, corner_radius=17, fg_color="transparent",
            border_width=1, border_color=BORDER, hover_color=CARD_HOVER,
            text_color=TEXT, font=F(12, "bold"))
        self.archive_btn.pack(side="left", padx=(8, 0))
        Tooltip(self.archive_btn, "Entries you removed, kept so they can be "
                                  "restored")
        sort_menu = ctk.CTkOptionMenu(
            chips, width=160, height=34, corner_radius=10,
            values=[SORT_LABELS[o] for o in SORT_ORDERS],
            fg_color=INPUT_BG, button_color=BORDER,
            button_hover_color=CARD_HOVER, text_color=TEXT, font=F(12),
            dropdown_fg_color=CARD, dropdown_hover_color=CARD_HOVER,
            dropdown_text_color=TEXT, command=self._on_sort)
        sort_menu.set(SORT_LABELS[self.sort_order])
        sort_menu.pack(side="right")

        list_card = ctk.CTkFrame(left, fg_color=CARD, corner_radius=20,
                                 border_width=1, border_color=BORDER)
        list_card.grid(row=1, column=0, sticky="nsew")
        self.list_frame = ctk.CTkScrollableFrame(list_card, fg_color=CARD,
                                                 corner_radius=0)
        self.list_frame.pack(fill="both", expand=True, padx=6, pady=8)
        self.list_frame.grid_columnconfigure(0, weight=1)

        add = self._accent_button(left, "+  Add an entry",
                                  self.add_account_dialog)
        add.configure(height=48, corner_radius=16, font=F(14, "bold"))
        add.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        ctk.CTkLabel(left, text=version_string(), font=F(11),
                     text_color=MUTED).grid(row=3, column=0, pady=(8, 0))

        self.detail = ctk.CTkFrame(body, fg_color=CARD, corner_radius=24,
                                   border_width=1, border_color=BORDER)
        self.detail.grid(row=0, column=1, sticky="nsew")

        self.refresh_account_list()
        self._start_idle_timer()

    def _focus_search(self, _=None):
        if self.search_entry is not None and self.search_entry.winfo_exists():
            self.search_entry.focus()
            return "break"

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

        self.all_chip.configure(text=f"   All  {total}   ")
        self.archive_btn.configure(text=f"Archive  {archived}" if archived
                                   else "Archive")

        # Keep the selected entry while it is still listed; otherwise show
        # the first one, so the details pane is never stale.
        if self._selected_id not in {a["id"] for a in accounts}:
            self._selected_id = accounts[0]["id"] if accounts else None

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
            else:
                frame.configure(fg_color=SELECTED if eid == self._selected_id
                                else CARD)
                if pos is not None and position.get(eid) != pos:
                    frame.grid_remove()
                    cached[2] = None

        self._show_detail()
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
                cached[1].grid(row=i, column=0, sticky="ew", pady=2, padx=2)
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
            self._ghost_button(box, "Import from file",
                               self.import_dialog, width=170).pack()

    def _add_row(self, i, acc):
        """A compact list row; clicking it shows the entry in the details."""
        row = ctk.CTkFrame(
            self.list_frame, corner_radius=14,
            fg_color=SELECTED if acc["id"] == self._selected_id else CARD)
        row.grid(row=i, column=0, sticky="ew", pady=2, padx=2)
        row.grid_columnconfigure(1, weight=1)

        bg, ink, _ = tile_colors(acc["site"])
        tile = ctk.CTkLabel(row, text=(acc["site"][:1].upper() or "?"),
                            width=42, height=42, corner_radius=12,
                            fg_color=bg, text_color=ink, font=F(16, "bold"))
        tile.grid(row=0, column=0, padx=(10, 12), pady=9)

        info = ctk.CTkFrame(row, fg_color="transparent")
        info.grid(row=0, column=1, sticky="w")
        site = ctk.CTkLabel(info, text=_clip(acc["site"], 30), anchor="w",
                            font=F(14, "bold"), text_color=TEXT)
        site.pack(anchor="w")
        subtitle = acc["username"] or "—"
        extras = [name for name, key in (("2FA", "totp"), ("note", "notes"))
                  if acc.get(key)]
        subtitle = _clip(subtitle, 30 if not extras else 22)
        if extras:
            subtitle += "  ·  " + " · ".join(extras)
        user = ctk.CTkLabel(info, text=subtitle, anchor="w", font=F(12),
                            text_color=MUTED)
        user.pack(anchor="w")

        when = ctk.CTkLabel(row, text=history_ui.short_when(
            acc.get("updated_at", "")), font=F(11), text_color=MUTED)
        when.grid(row=0, column=2, padx=(8, 14))

        for w in (row, tile, info, site, user, when):
            w.bind("<Button-1>", lambda e, eid=acc["id"]: self._select(eid))
        return row

    def _select(self, eid):
        previous, self._selected_id = self._selected_id, eid
        for key in {previous, eid}:
            cached = self._rows.get(key)
            if cached:
                cached[1].configure(fg_color=SELECTED if key == eid else CARD)
        self._show_detail()

    # ------------------------------------------------------------------
    # Details pane
    # ------------------------------------------------------------------
    def _selected_entry(self):
        if self._selected_id is None or self.vault is None:
            return None
        for acc in active_accounts(self.vault):
            if acc["id"] == self._selected_id:
                return acc
        return None

    def _cancel_totp(self):
        if self._totp_job:
            try:
                self.root.after_cancel(self._totp_job)
            except Exception:
                pass
            self._totp_job = None

    def _cancel_reveal(self):
        # A shown 2FA code goes with it: leaving the entry hides the code,
        # and the next look asks for the master password again.
        self._cancel_totp()
        if self._reveal_job:
            try:
                self.root.after_cancel(self._reveal_job)
            except Exception:
                pass
            self._reveal_job = None

    def _show_detail(self):
        self._cancel_reveal()
        for w in self.detail.winfo_children():
            w.destroy()
        acc = self._selected_entry()
        if acc is None:
            box = ctk.CTkFrame(self.detail, fg_color="transparent")
            box.place(relx=0.5, rely=0.5, anchor="center")
            ctk.CTkLabel(box, text="Nothing selected", font=F(17, "bold"),
                         text_color=TEXT).pack()
            ctk.CTkLabel(box, text="Pick an entry on the left, or add one.",
                         font=F(13), text_color=MUTED).pack(pady=(4, 0))
            return

        bg, ink, band_color = tile_colors(acc["site"])
        band = ctk.CTkFrame(self.detail, fg_color=band_color, corner_radius=18,
                            height=112)
        band.pack(fill="x", padx=8, pady=(8, 0))
        band.pack_propagate(False)
        band.grid_columnconfigure(1, weight=1)
        band.grid_rowconfigure(0, weight=1)
        ctk.CTkLabel(band, text=(acc["site"][:1].upper() or "?"), width=72,
                     height=72, corner_radius=20, fg_color=bg, text_color=ink,
                     bg_color=band_color, font=F(30, "bold")).grid(
            row=0, column=0, padx=(22, 18))
        names = ctk.CTkFrame(band, fg_color="transparent")
        names.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(names, text=_clip(acc["site"], 34), font=F(24, "bold"),
                     text_color=TEXT, anchor="w").pack(anchor="w")
        changed = acc.get("updated_at")
        ctk.CTkLabel(names, text=("Last changed " + history_ui.local_time(
            changed)) if changed else "", font=F(12), text_color=MUTED,
                     anchor="w").pack(anchor="w")
        actions = ctk.CTkFrame(band, fg_color="transparent")
        actions.grid(row=0, column=2, padx=(8, 22))
        self._ghost_button(actions, "Edit", lambda: self.account_dialog(acc),
                           width=74).pack(side="left", padx=(0, 8))
        arch = self._ghost_button(actions, "Archive",
                                  lambda: self._archive_account(acc), width=88)
        arch.pack(side="left")
        Tooltip(arch, "Move to archive — restorable, and it still syncs the "
                      "removal to your other PCs")

        scroll = ctk.CTkScrollableFrame(self.detail, fg_color=CARD,
                                        corner_radius=0)
        scroll.pack(fill="both", expand=True, padx=14, pady=(14, 14))

        fields = ctk.CTkFrame(scroll, fg_color="transparent")
        fields.pack(fill="x", padx=8)
        fields.grid_columnconfigure((0, 1), weight=1, uniform="field")
        self._username_box(fields, acc).grid(row=0, column=0, sticky="nsew",
                                             padx=(0, 7))
        self._password_box(fields, acc).grid(row=0, column=1, sticky="nsew",
                                             padx=(7, 0))

        self._strength_row(scroll, acc.get("password", ""))

        if acc.get("totp"):
            self._totp_box(scroll, acc).pack(fill="x", padx=8, pady=(14, 0))

        self._section_title(scroll, "Notes")
        ctk.CTkLabel(scroll, text=acc.get("notes") or "No notes.",
                     font=F(13), text_color=TEXT if acc.get("notes") else MUTED,
                     wraplength=520, justify="left", anchor="w").pack(
            anchor="w", fill="x", padx=8)

        count = len(acc.get("history") or [])
        self._section_title(
            scroll, f"History  ·  {count} earlier version"
                    f"{'s' if count != 1 else ''}")
        history_ui.panel(self, scroll, acc).pack(fill="x", padx=8,
                                                 pady=(0, 8))

    def _section_title(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=F(12, "bold"), text_color=MUTED,
                     anchor="w").pack(anchor="w", padx=8, pady=(20, 6))

    def _field_box(self, parent, label):
        box = ctk.CTkFrame(parent, fg_color=INPUT_BG, corner_radius=16)
        box.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(box, text=label, font=F(12, "bold"), text_color=MUTED,
                     anchor="w").grid(row=0, column=0, sticky="w",
                                      padx=16, pady=(12, 0))
        return box

    def _small_button(self, parent, text, command, accent=False, width=60):
        return ctk.CTkButton(
            parent, text=text, command=command, width=width, height=36,
            corner_radius=10,
            fg_color=GREEN if accent else "transparent",
            hover_color=GREEN_HOVER if accent else CARD_HOVER,
            border_width=0 if accent else 1, border_color=BORDER,
            text_color=ON_ACCENT if accent else TEXT, font=F(12, "bold"))

    def _username_box(self, parent, acc):
        box = self._field_box(parent, "Username")
        ctk.CTkLabel(box, text=_clip(acc["username"] or "—", 26),
                     font=F(15, "bold"), text_color=TEXT, anchor="w").grid(
            row=1, column=0, sticky="w", padx=16, pady=(2, 12))
        copy_user = self._small_button(
            box, "Copy", lambda: self._copy(acc["username"], "Username copied"))
        copy_user.grid(row=0, column=1, rowspan=2, padx=(4, 12))
        Tooltip(copy_user, "Copy username")
        return box

    def _password_box(self, parent, acc):
        box = self._field_box(parent, "Password")
        pwd = ctk.CTkLabel(box, text="•" * 12, anchor="w",
                           font=ctk.CTkFont(family=MONO, size=15),
                           text_color=TEXT)
        pwd.grid(row=1, column=0, sticky="w", padx=16, pady=(2, 12))
        buttons = ctk.CTkFrame(box, fg_color="transparent")
        buttons.grid(row=0, column=1, rowspan=2, padx=(4, 12))

        def toggle():
            self._cancel_reveal()
            if show.cget("text") == "Hide":
                pwd.configure(text="•" * 12)
                show.configure(text="Show")
            else:
                pwd.configure(text=_clip(acc["password"], 24) or "—")
                show.configure(text="Hide")
                self._reveal_job = self.root.after(REVEAL_MS, toggle)

        show = self._small_button(buttons, "Show", toggle)
        show.pack(side="left", padx=(0, 6))
        Tooltip(show, "Show / hide password")
        copy_pw = self._small_button(
            buttons, "Copy",
            lambda: self._copy(acc["password"], "Password copied",
                               sensitive=True), accent=True)
        copy_pw.pack(side="left")
        Tooltip(copy_pw, "Copy password — cleared after "
                         f"{CLIPBOARD_CLEAR_MS // 1000}s, but Windows "
                         "clipboard history (Win+V) may keep its own copy")
        return box

    def _totp_box(self, parent, acc):
        """
        The entry's 2FA code: hidden until asked for, and every Show asks
        for the master password (owner, 2026-11-06). Once shown it ticks
        over with the period until the entry is left or the vault locks.
        """
        box = self._field_box(parent, "2FA code")
        problem = totp.check(acc.get("totp", ""))
        if problem:
            ctk.CTkLabel(box, text="No codes from this secret: " + problem,
                         font=F(12), text_color=WARN, wraplength=440,
                         justify="left", anchor="w").grid(
                row=1, column=0, columnspan=2, sticky="w", padx=16,
                pady=(2, 12))
            return box

        params = totp.parse(acc["totp"])
        masked = totp.spaced("•" * params.digits)
        hint = "Hidden — Show asks for your master password"
        shown = ctk.CTkLabel(box, text=masked, anchor="w",
                             font=ctk.CTkFont(family=MONO, size=20,
                                              weight="bold"),
                             text_color=TEXT)
        shown.grid(row=1, column=0, sticky="w", padx=16, pady=(2, 0))
        status = ctk.CTkLabel(box, text=hint, font=F(11), text_color=MUTED,
                              anchor="w")
        status.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 12))
        buttons = ctk.CTkFrame(box, fg_color="transparent")
        buttons.grid(row=0, column=1, rowspan=3, padx=(4, 12))

        def tick():
            now = time.time()
            left = totp.seconds_left(params, now)
            shown.configure(text=totp.spaced(totp.code(params, now)))
            status.configure(text=f"Changes in {left} s",
                             text_color=GREEN if left > 5 else WARN)
            # Wake just after the next whole second, so the count is exact.
            self._totp_job = self.root.after(
                max(1, 1000 - int((now % 1) * 1000)), tick)

        def hide():
            self._cancel_totp()
            shown.configure(text=masked)
            status.configure(text=hint, text_color=MUTED)
            show.configure(text="Show")
            copy.pack_forget()

        def toggle():
            if show.cget("text") == "Hide":
                return hide()
            if not dialogs.ask_master_password(
                    self, "Show 2FA code",
                    f"Enter your master password to see the code for "
                    f"“{_clip(acc['site'], 40)}”. SecretSpace asks every time.",
                    action="Show code"):
                return
            if not shown.winfo_exists():
                return                      # the entry changed meanwhile
            show.configure(text="Hide")
            copy.pack(side="left", padx=(6, 0))
            tick()

        def copy_code():
            if self._totp_job is not None:          # only while shown
                self._copy(totp.code(params), "2FA code copied",
                           sensitive=True)

        show = self._small_button(buttons, "Show", toggle)
        show.pack(side="left")
        Tooltip(show, "Asks for your master password each time")
        copy = self._small_button(buttons, "Copy", copy_code, accent=True)
        return box

    def _strength_row(self, parent, password):
        name, frac, color = estimate_strength(password)
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=(16, 0))
        ctk.CTkLabel(row, text="Strength", font=F(12, "bold"),
                     text_color=MUTED).pack(side="left", padx=(0, 14))
        lit = round(frac * STRENGTH_SEGMENTS) if password else 0
        lit = max(lit, 1) if password else 0
        for n in range(STRENGTH_SEGMENTS):
            ctk.CTkFrame(row, width=38, height=6, corner_radius=3,
                         fg_color=color if n < lit else BORDER).pack(
                side="left", padx=(0, 4))
        ctk.CTkLabel(row, text=name, font=F(12, "bold"),
                     text_color=color).pack(side="left", padx=(10, 0))

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
        self._cancel_totp()
        self._session += 1
        # Every change is saved as it is made, so this save is only a safety
        # net -- and while a sync runs it would be a hazard: it could land
        # after the sync wrote the merged vault and put the pre-merge copy
        # back on disk, which the next sync would read as edits undoing the
        # other PC's changes.
        if self.master_password and self.current_user and not self._syncing:
            self._save()
        # A copied password outlives the lock: the usual auto-clear timer
        # keeps running, so it can still be pasted until that fires.
        self.vault = self.master_password = self.current_user = None
        self._selected_id = None
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
