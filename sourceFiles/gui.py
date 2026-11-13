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

import hashlib
import json
import os
import time
import tkinter as tk

import customtkinter as ctk
import pyperclip

import accounts
import appconfig
import changelog
import dialogs
import history_ui
from icons import icon
import lockout
import sync_client
import sync_ui
import account_sync_ui
import vaults_ui
import recovery_ui
import totp
from theme import (F, BG, CARD, CARD_HOVER, SELECTED, INPUT_BG,
                   BORDER, TEXT, MUTED, GREEN, GREEN_HOVER, DANGER,
                   ON_ACCENT, WARN, MONO, DECOR_DISC_A, DECOR_DISC_B,
                   DECOR_DOT, DECOR_INK, pick, apply_appearance,
                   strength_color,
                   tile_colors, asset_candidates)
from widgets import (Tooltip, ghost_button, accent_button, field,
                     strength_widget, modal, fit_modal, safe_grab, confirm,
                     STRENGTH_SEGMENTS)
from password_generator import estimate_strength
from account_crypto import CryptoError
from vault import (active_accounts, archive_account, sort_accounts,
                   SORT_ORDERS, auto_purge_archive, archive_purge_days,
                   window_title)
from version import version_string

CLIPBOARD_CLEAR_MS = 30_000     # auto-clear copied passwords after 30s
IDLE_POLL_MS = 15_000           # how often the auto-lock timer checks in
REVEAL_MS = 10_000              # a shown password hides itself again

SEARCH_DEBOUNCE_MS = 150        # wait for a pause in typing before filtering
ROW_SLICE_SECONDS = 0.1         # list work per step before redrawing the window

LOGIN_TILES_PER_ROW = 3

BACKDROP_REDRAW_MS = 60         # the login backdrop waits for a resize to settle
BACKDROP_MODE_MS = 1000         # how often the login screen looks for a mode change
BACKDROP_OVERSAMPLE = 3         # painted this many times larger, then scaled down

#: The vault filter's entry that shows every vault of the account.
ALL_VAULTS = "All vaults"

#: What the Sort menu shows for each of vault.SORT_ORDERS.
SORT_LABELS = {
    "modified_desc": "Recently modified",
    "modified_asc": "Oldest modified",
    "name_asc": "Name A → Z",
    "name_desc": "Name Z → A",
}


def _row_signature(acc, label=""):
    """
    Everything an account row shows or closes over. A cached row is reused
    only while this is unchanged; ``id(acc)`` covers a sync or a reload that
    replaces the entry dicts, which the row's buttons hold on to. ``label``
    is the vault's name, when the row shows it.
    """
    return (label, id(acc), acc.get("site"), acc.get("username"),
            acc.get("password"), bool(acc.get("notes")), bool(acc.get("totp")),
            acc.get("updated_at"),
            tuple(r.get("rid") for r in acc.get("history") or []))


def backdrop_picture(w, h):
    """
    The login backdrop: two soft discs, a padlock, a key and a few dots,
    with smooth edges. None when the window has no size yet.
    """
    from PIL import Image, ImageDraw
    if w < 2 or h < 2:
        return None
    k = BACKDROP_OVERSAMPLE
    img = Image.new("RGB", (w * k, h * k), pick(BG))
    green = pick(GREEN)
    d = ImageDraw.Draw(img)

    def box(x0, y0, x1, y1):
        return [round(x0 * k), round(y0 * k), round(x1 * k), round(y1 * k)]

    def dot(x, y, r, fill):
        d.ellipse(box(x - r, y - r, x + r, y + r), fill=fill)

    def stroke(points, fill, width=4):
        """A line with round ends and joints."""
        d.line([(round(x * k), round(y * k)) for x, y in points], fill=fill,
               width=width * k, joint="curve")
        for x, y in (points[0], points[-1]):
            dot(x, y, width / 2, fill)

    r1, r2 = max(w, h) * 0.17, max(w, h) * 0.21
    dot(w * 0.1, h * 0.16, r1, pick(DECOR_DISC_A))
    dot(w * 0.93, h * 0.9, r2, pick(DECOR_DISC_B))

    # A padlock, top right: a rounded body, a shackle, a keyhole.
    x, y = w * 0.86, h * 0.2
    d.arc(box(x - 17, y - 32, x + 17, y + 2), start=180, end=360, fill=green,
          width=4 * k)
    stroke([(x - 15, y - 15), (x - 15, y - 4)], green)
    stroke([(x + 15, y - 15), (x + 15, y - 4)], green)
    d.rounded_rectangle(box(x - 26, y - 6, x + 26, y + 34), radius=9 * k,
                        outline=green, width=4 * k)
    dot(x, y + 11, 4.5, green)
    stroke([(x, y + 13), (x, y + 21)], green)

    # A key, bottom left: a ring, a shaft, two teeth.
    x, y = w * 0.15, h * 0.8
    ink = pick(DECOR_INK)
    d.ellipse(box(x - 40, y - 18, x - 4, y + 18), outline=ink, width=4 * k)
    stroke([(x - 5, y), (x + 44, y)], ink)
    stroke([(x + 30, y), (x + 30, y + 15)], ink)
    stroke([(x + 42, y), (x + 42, y + 11)], ink)

    for fx, fy in ((0.3, 0.1), (0.7, 0.92), (0.96, 0.48), (0.05, 0.55)):
        dot(w * fx, h * fy, 4, pick(DECOR_DOT))
    return img.resize((w, h), Image.LANCZOS)


def backdrop_image(w, h):
    """:func:`backdrop_picture` as an image a Tk canvas can show."""
    from PIL import ImageTk
    picture = backdrop_picture(w, h)
    return None if picture is None else ImageTk.PhotoImage(picture)


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


class VaultNav:
    """
    The vaults down the left side of the main window: one row each, with its
    tile, its name and how many entries it has. It answers to the few calls
    an option menu takes (``configure(values=)``, ``cget("values")``,
    ``get``, ``set``), which is what the rest of the window speaks.
    """

    def __init__(self, parent, command):
        self.frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.frame.grid_columnconfigure(0, weight=1)
        self._command = command
        self._values, self._notes, self._current = [], {}, None
        self._rows = {}

    def winfo_exists(self):
        return self.frame.winfo_exists()

    def cget(self, key):
        if key != "values":
            raise ValueError(key)
        return list(self._values)

    def get(self):
        return self._current

    def configure(self, values=None, notes=None):
        """``notes``: what stands at the right of each row (a count)."""
        values = self._values if values is None else list(values)
        notes = self._notes if notes is None else dict(notes)
        if values == self._values and notes == self._notes and self._rows:
            return
        self._values, self._notes = values, notes
        for child in self.frame.winfo_children():
            child.destroy()
        self._rows = {}
        for i, label in enumerate(values):
            self._rows[label] = self._row(i, label)
        self._paint()

    def set(self, label):
        self._current = label
        self._paint()

    def _dropdown_callback(self, label):
        self.set(label)
        self._command(label)

    def _paint(self):
        for label, row in self._rows.items():
            row.configure(fg_color=CARD if label == self._current
                          else "transparent")

    def _row(self, index, label):
        row = ctk.CTkFrame(self.frame, fg_color="transparent",
                           corner_radius=12, height=44)
        row.grid(row=index, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(1, weight=1)
        if label == ALL_VAULTS:
            bg, ink, letter = GREEN, ON_ACCENT, "≡"
        else:
            bg, ink, _ = tile_colors(label)
            letter = label[:1].upper() or "?"
        tile = ctk.CTkLabel(row, text=letter, width=28, height=28,
                            corner_radius=8, fg_color=bg, text_color=ink,
                            font=F(12, "bold"))
        tile.grid(row=0, column=0, padx=(10, 10), pady=8)
        name = ctk.CTkLabel(row, text=_clip(label, 16), anchor="w",
                            font=F(13, "bold"), text_color=TEXT)
        name.grid(row=0, column=1, sticky="w")
        note = ctk.CTkLabel(row, text=self._notes.get(label, ""), font=F(11),
                            text_color=MUTED)
        note.grid(row=0, column=2, padx=(6, 12))
        for w in (row, tile, name, note):
            w.bind("<Button-1>",
                   lambda e, label=label: self._dropdown_callback(label))
        return row


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(window_title())
        self.root.geometry("1320x800")
        self.root.minsize(1120, 640)
        self.root.configure(fg_color=BG)

        # Every vault of the open account, by id, as account.vault_ids()
        # orders them. ``self.vault`` (a property) is the one new entries go
        # to: the vault picked in the filter, or the personal one.
        self.vaults = {}
        self._saved = {}                # vault id -> its content when last saved
        self.vault_filter = None        # None = all vaults
        self._entry_vault = {}          # listed entry id -> its vault's id
        self.vault_menu = None
        self.master_password = None
        self.current_user = None
        # The unlocked 3.0 account (accounts.Account): its keys, its files.
        self.account = None

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
        self._backdrop_job = None
        self._mode_job = None
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
    # The open account's vaults
    # ------------------------------------------------------------------
    @property
    def active_vault_id(self):
        """The vault new entries go to: the one picked in the filter, else
        the personal one."""
        if self.account is None:
            return None
        # A vault this account may only read cannot take a new entry.
        if self.vault_filter in self.vaults and \
                self.account.can_write(self.vault_filter):
            return self.vault_filter
        return self.account.personal_id

    def entry_writable(self, entry_id):
        """May the open account change this entry (it is not in a vault
        shared with it for reading only)?"""
        if self.account is None:
            return False
        return self.account.can_write(self._entry_vault.get(entry_id)
                                      or self._vault_id_of(entry_id))

    def _vault_id_of(self, entry_id):
        for vault_id, data in self.vaults.items():
            if any(a.get("id") == entry_id for a in data["accounts"]):
                return vault_id
        return None

    def read_only_notice(self):
        self.toast("This vault is shared with you for reading only", "warn")

    @property
    def vault(self):
        return self.vaults.get(self.active_vault_id) if self.vaults else None

    @vault.setter
    def vault(self, data):
        if data is None:                # locking: nothing stays in memory
            self.vaults, self._saved = {}, {}
            self.vault_filter = None
            self._entry_vault = {}
        else:
            self.vaults[self.active_vault_id] = data

    @staticmethod
    def _content_mark(data):
        return hashlib.sha256(json.dumps(data, sort_keys=True, default=str)
                              .encode("utf-8")).hexdigest()

    def load_vaults(self):
        """
        Bring ``self.vaults`` in line with the account's list: read vaults
        that are new (made here, or arrived with a sync), forget ones that
        are gone, keep the rest as they are in memory. Returns the names of
        vaults whose file could not be read.
        """
        if self.account is None:
            return []
        unreadable, current = [], {}
        for vault_id in self.account.vault_ids():
            if vault_id in self.vaults:
                current[vault_id] = self.vaults[vault_id]
                continue
            file = self.account.vault_file(vault_id)
            if not file.has_file:
                # Known from the server, its entries not fetched yet: the
                # sync that listed it fills it in.
                current[vault_id] = {"accounts": []}
                continue
            try:
                current[vault_id] = file.load()
                self._saved[vault_id] = self._content_mark(current[vault_id])
            except Exception:
                unreadable.append(file.name)
        self.vaults = current
        self._saved = {v: m for v, m in self._saved.items() if v in current}
        if self.vault_filter not in self.vaults:
            self.vault_filter = None
        return unreadable

    def set_vault_data(self, vault_id, data, saved=False):
        """Replace a vault's data (a sync's merge). ``saved``: it is already
        on disk like this."""
        self.vaults[vault_id] = data
        if saved:
            self._saved[vault_id] = self._content_mark(data)

    def scope_ids(self):
        """The vaults the list shows: the picked one, or all of them."""
        if self.vault_filter in self.vaults:
            return [self.vault_filter]
        return list(self.vaults)

    def scope_vaults(self):
        return [self.vaults[v] for v in self.scope_ids()]

    def scope_data(self):
        """Every entry in view as one vault-shaped dict (the export)."""
        return {"accounts": [a for data in self.scope_vaults()
                             for a in data["accounts"]]}

    def vault_name(self, vault_id):
        if self.account is None or vault_id == self.account.personal_id:
            return accounts.PERSONAL_NAME
        return self.account.vault_record(vault_id).get("name", "")

    def vault_holding(self, entry_id):
        """The data of the vault that holds this entry (the active one if
        none does)."""
        for data in self.vaults.values():
            if any(a.get("id") == entry_id for a in data["accounts"]):
                return data
        return self.vault

    def vault_phrase(self, vault_id=None):
        """“your vault”, or the vault by name once there are several."""
        if len(self.vaults) < 2:
            return "your vault"
        return f"the vault “{self.vault_name(vault_id or self.active_vault_id)}”"

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
        if self._backdrop_job:
            self.root.after_cancel(self._backdrop_job)
            self._backdrop_job = None
        if self._mode_job:
            self.root.after_cancel(self._mode_job)
            self._mode_job = None
        for w in self.root.winfo_children():
            w.destroy()
        self._toast = None
        self._rows = {}
        self._empty_box = None
        self.search_entry = None
        self.vault_menu = None

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
        """
        Write every vault that changed since it was last written, noting in
        each who changed what (changelog). A vault this account may only
        read is never written: should a change to one get this far, it is
        undone from the file.
        """
        try:
            refused = []
            for vault_id, data in list(self.vaults.items()):
                if self._saved.get(vault_id) == self._content_mark(data):
                    continue
                file = self.account.vault_file(vault_id)
                if not file.can_write:
                    self.vaults[vault_id] = (file.load() if file.has_file
                                             else {"accounts": []})
                    self._saved[vault_id] = self._content_mark(
                        self.vaults[vault_id])
                    refused.append(file.name)
                    continue
                self._note_changes(file, data)
                file.save(data)
                self._saved[vault_id] = self._content_mark(data)
            if refused:
                # After the caller's own message, so this is the one read.
                self.root.after(60, lambda: (
                    self.refresh_account_list(),
                    self.toast("“" + "”, “".join(refused) + "” is shared with "
                               "you for reading only — nothing was changed "
                               "there", "warn")))
            return not refused
        except Exception as e:
            self.toast(f"Save failed: {e}", "error")
            return False

    def _note_changes(self, file, data):
        """Add to ``data``'s change log what differs from the vault as it was
        last written. Never stops a save: a log line is worth less than the
        change it describes."""
        try:
            before = file.load() if file.has_file else {"accounts": []}
            changelog.record(data, before, self.account.username,
                             self.account.keyset, file.hex)
        except Exception:
            pass

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
        backdrop = tk.Canvas(self.root, bg=pick(BG), highlightthickness=0,
                             bd=0)
        backdrop.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._watch_backdrop_mode(backdrop)
        backdrop.bind("<Configure>",
                      lambda e: self._backdrop_resized(backdrop, e.width,
                                                       e.height))

        card = ctk.CTkFrame(backdrop, fg_color=CARD, corner_radius=24,
                            bg_color=BG)
        card.place(relx=0.5, rely=0.5, anchor="center")
        pad = ctk.CTkFrame(card, fg_color="transparent")
        pad.pack(padx=40, pady=36)

        self._logo(pad).pack()
        ctk.CTkLabel(pad, text="Welcome back", font=F(26, "bold"),
                     text_color=TEXT).pack(pady=(12, 0))
        ctk.CTkLabel(pad, text="Pick your account and enter its master "
                              "password.",
                     font=F(13), text_color=MUTED).pack(pady=(4, 20))

        users = accounts.list_accounts()
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
        # 2.x vaults come in through Import once an account is open; an
        # account used on another device comes in through its server.
        ctk.CTkButton(links, text="Create an account",
                      command=self.create_user_dialog, width=10, height=32,
                      fg_color="transparent", hover_color=CARD_HOVER,
                      text_color=GREEN, font=F(13, "bold")).pack(side="left")
        ctk.CTkButton(links, text="Sign in from a server",
                      command=lambda: account_sync_ui.sign_in_dialog(self),
                      width=10, height=32, fg_color="transparent",
                      hover_color=CARD_HOVER, text_color=GREEN,
                      font=F(13, "bold")).pack(side="right")
        ctk.CTkButton(pad, text="Forgot your master password?",
                      command=lambda: recovery_ui.recover_dialog(
                          self, self._login_user or ""),
                      width=10, height=28, fg_color="transparent",
                      hover_color=CARD_HOVER, text_color=MUTED,
                      font=F(12)).pack(pady=(6, 0))
        ctk.CTkLabel(pad, text=version_string(), font=F(11),
                     text_color=MUTED).pack(pady=(8, 0))

        self.password_entry.bind("<Return>", lambda e: self.unlock_vault())
        self.password_entry.focus()
        # A penalty earned before the app was closed is still in force.
        if self._login_user and lockout.remaining(self._login_user):
            self._begin_lockout(self._login_user,
                                lockout.remaining(self._login_user))

    def _backdrop_resized(self, canvas, w, h):
        """Redraw once the window stops changing size, not on every step."""
        if self._backdrop_job:
            self.root.after_cancel(self._backdrop_job)
            self._backdrop_job = None
        if not canvas.find_all():
            self._draw_backdrop(canvas, w, h)
            return

        def draw():
            self._backdrop_job = None
            if canvas.winfo_exists():
                self._draw_backdrop(canvas, w, h)
        self._backdrop_job = self.root.after(BACKDROP_REDRAW_MS, draw)

    def _watch_backdrop_mode(self, canvas, seen=None):
        """
        The backdrop is a painting, not a widget, so it does not turn light
        or dark by itself: look once a second while the login screen shows,
        and paint it again when the mode has changed.
        """
        self._mode_job = None
        if not canvas.winfo_exists():
            return
        now = ctk.get_appearance_mode()
        if seen is not None and now != seen:
            canvas.configure(bg=pick(BG))
            self._draw_backdrop(canvas, canvas.winfo_width(),
                                canvas.winfo_height())
        self._mode_job = self.root.after(
            BACKDROP_MODE_MS, lambda: self._watch_backdrop_mode(canvas, now))

    def _draw_backdrop(self, canvas, w, h):
        """
        The shapes behind the login card. A Tk canvas draws without
        smoothing, so they are painted larger with Pillow and scaled down;
        without Pillow the plain canvas shapes still do.
        """
        canvas.delete("all")
        try:
            image = backdrop_image(w, h)
        except Exception:
            image = None
        if image is None:
            self._draw_backdrop_plain(canvas, w, h)
            return
        canvas.image = image          # Tk keeps no reference of its own
        canvas.create_image(0, 0, anchor="nw", image=image)

    @staticmethod
    def _draw_backdrop_plain(canvas, w, h):
        green, ink = pick(GREEN), pick(DECOR_INK)
        r1, r2 = max(w, h) * 0.17, max(w, h) * 0.21
        canvas.create_oval(w * 0.1 - r1, h * 0.16 - r1, w * 0.1 + r1,
                           h * 0.16 + r1, fill=pick(DECOR_DISC_A), outline="")
        canvas.create_oval(w * 0.93 - r2, h * 0.9 - r2, w * 0.93 + r2,
                           h * 0.9 + r2, fill=pick(DECOR_DISC_B), outline="")
        # A lock, top right.
        x, y = w * 0.86, h * 0.2
        canvas.create_rectangle(x - 26, y - 6, x + 26, y + 34, outline=green,
                                width=4)
        canvas.create_arc(x - 17, y - 32, x + 17, y + 2, start=0, extent=180,
                          style="arc", outline=green, width=4)
        # A key, bottom left.
        x, y = w * 0.15, h * 0.8
        canvas.create_oval(x - 40, y - 18, x - 4, y + 18, outline=ink,
                           width=4)
        canvas.create_line(x - 4, y, x + 44, y, fill=ink, width=4)
        canvas.create_line(x + 30, y, x + 30, y + 16, fill=ink, width=4)
        canvas.create_line(x + 42, y, x + 42, y + 12, fill=ink, width=4)
        for fx, fy in ((0.3, 0.1), (0.7, 0.92), (0.96, 0.48), (0.05, 0.55)):
            canvas.create_oval(w * fx - 4, h * fy - 4, w * fx + 4, h * fy + 4,
                               fill=pick(DECOR_DOT), outline="")

    def _draw_login_tiles(self, users):
        """One tile per account on this PC, plus one to create another."""
        for w in self._login_tiles.winfo_children():
            w.destroy()
        for c in range(LOGIN_TILES_PER_ROW):
            self._login_tiles.grid_columnconfigure(c, weight=1, uniform="tile")
        if not users:
            ctk.CTkLabel(self._login_tiles,
                         text="There is no SecretSpace 3 account on this PC yet. "
                              "Create one, then import your 2.x vaults into "
                              "it.",
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
            label = "Add account"
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
        self._draw_login_tiles(accounts.list_accounts())
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

    def unlock_vault(self, secret_key_text=None):
        username = self._login_user
        master_password = self.password_entry.get()
        if not username:
            self._login_error("Create an account first.")
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
            account = accounts.unlock(username, master_password,
                                      secret_key_text)
            loaded = account.load_vault()
        except accounts.SecretKeyNeeded:
            # A new PC, or another Windows user: the Secret Key is asked for
            # once, from the Emergency Kit, then kept on this device.
            typed = dialogs.ask_secret_key(self, username)
            if typed:
                self.unlock_vault(secret_key_text=typed)
            return
        except FileNotFoundError:
            self._login_error("No account found with that name.")
            return
        except ValueError as e:
            msg = str(e)
            if not (isinstance(e, CryptoError)
                    and msg.startswith("Wrong master password")):
                self._login_error(msg)    # a real file problem, not a typo
                return
            wait = lockout.record_failure(username)
            if wait:
                self._begin_lockout(username, wait)
            else:
                left = lockout.FREE_ATTEMPTS - lockout.failures(username)
                self._login_error(("Incorrect master password or Secret Key."
                                   if secret_key_text else
                                   "Incorrect master password.") +
                                  (f" {left} attempt(s) before a delay."
                                   if left else ""))
            return
        except Exception as e:
            self._login_error(str(e))
            return

        lockout.reset(username)
        self.open_account(account, loaded, master_password)
        if secret_key_text:
            self.toast("Secret Key saved on this PC — it won't be asked "
                       "for again here")

    def open_account(self, account, loaded, master_password):
        """After an unlock or a new account: the main window."""
        self._session += 1
        self.account = account
        self.vaults, self._saved, self.vault_filter = {}, {}, None
        self.vault = loaded                         # the personal vault
        self._saved[account.personal_id] = self._content_mark(loaded)
        unreadable = self.load_vaults()             # and every other one
        self.master_password = master_password
        self.current_user = account.username
        appconfig.save_config(last_username=account.username)

        # Archived entries past the keep-for limit (Settings), in every vault
        # this account may change.
        purged = sum(auto_purge_archive(data)
                     for vault_id, data in self.vaults.items()
                     if account.can_write(vault_id))
        if purged:
            self._save()

        self.show_main_window()
        if unreadable:
            self.toast("Could not read the vault “" + "”, “".join(unreadable) +
                       "” on this PC — sync to fetch it again", "error")
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
    def _nav_button(self, parent, text, command, picture):
        """A quiet row of the side bar: an icon and a name."""
        return ctk.CTkButton(
            parent, text=text, command=command, height=38, corner_radius=12,
            fg_color="transparent", hover_color=CARD_HOVER, anchor="w",
            text_color=MUTED, font=F(13, "bold"),
            image=icon(picture, 18, MUTED), compound="left")

    def show_main_window(self):
        self._clear()
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        # Three columns: the vaults, the entries of the one picked, and the
        # selected entry.
        shell = ctk.CTkFrame(self.root, fg_color="transparent")
        shell.grid(row=1, column=0, sticky="nsew", padx=16, pady=16)
        shell.grid_rowconfigure(0, weight=1)
        shell.grid_columnconfigure(1, weight=1, minsize=320)
        shell.grid_columnconfigure(2, weight=2, minsize=520)

        # ---- side bar ----
        side = ctk.CTkFrame(shell, fg_color="transparent", width=204)
        side.grid(row=0, column=0, sticky="ns", padx=(0, 16))
        side.pack_propagate(False)

        brand = ctk.CTkFrame(side, fg_color="transparent")
        brand.pack(fill="x", padx=8, pady=(6, 18))
        self._logo(brand, small=True).pack(side="left")
        ctk.CTkLabel(brand, text="SecretSpace", font=F(17, "bold"),
                     text_color=TEXT).pack(side="left", padx=(10, 0))

        # Which vault the list shows. New entries go to the one picked.
        self.vault_menu = VaultNav(side, self._on_vault_pick)
        self.vault_menu.frame.pack(fill="x")
        manage = self._nav_button(side, "Manage vaults…", self.vaults_dialog,
                                  "vaults")
        manage.pack(fill="x", pady=(6, 0))
        Tooltip(manage, "Add, rename, share or delete vaults")

        # Bottom up: the account, then the places you go occasionally.
        ctk.CTkLabel(side, text=version_string(), font=F(11),
                     text_color=MUTED).pack(side="bottom", pady=(6, 0))
        me = ctk.CTkFrame(side, fg_color=CARD, corner_radius=14)
        me.pack(side="bottom", fill="x")
        bg, ink, _ = tile_colors(self.current_user)
        who = ctk.CTkFrame(me, fg_color="transparent")
        who.pack(fill="x", padx=12, pady=(12, 8))
        self._circle(who, _initials(self.current_user), 34, bg, ink,
                     F(12, "bold"))[0].pack(side="left")
        ctk.CTkLabel(who, text=_clip(self.current_user, 16),
                     font=F(13, "bold"), text_color=TEXT).pack(
            side="left", padx=(10, 0))
        Tooltip(who, "The account you unlocked. Lock to switch to another.")
        pair = ctk.CTkFrame(me, fg_color="transparent")
        pair.pack(fill="x", padx=12, pady=(0, 12))
        pair.grid_columnconfigure((0, 1), weight=1, uniform="pair")
        syn = self._small_button(pair, "Sync", self.sync_now)
        syn.configure(image=icon("sync", 16), compound="left")
        syn.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        Tooltip(syn, "Sync this account with its server (Settings → Sync)")
        lock = self._small_button(pair, "Lock", self.lock_vault)
        lock.configure(image=icon("lock", 16), compound="left")
        lock.grid(row=0, column=1, sticky="ew", padx=(4, 0))
        Tooltip(lock, "Lock the account and sign out")

        gear = self._nav_button(side, "Settings", self.settings_dialog,
                                "settings")
        gear.pack(side="bottom", fill="x", pady=(0, 10))
        imp = self._nav_button(side, "Import", self.import_dialog, "import")
        imp.pack(side="bottom", fill="x")
        Tooltip(imp, "Import a PassMan 2.x vault, or a CSV or JSON file")
        gen = self._nav_button(side, "Password generator",
                               self.generator_dialog, "key")
        gen.pack(side="bottom", fill="x")
        Tooltip(gen, "Make a strong password")
        # The archive: somewhere you go occasionally; its count tells you
        # there is something in it.
        self.archive_btn = self._nav_button(side, "Archive",
                                            self.archive_dialog, "archive")
        self.archive_btn.pack(side="bottom", fill="x")
        Tooltip(self.archive_btn, "Entries you removed, kept so they can be "
                                  "restored")

        # ---- the entries ----
        left = ctk.CTkFrame(shell, fg_color="transparent")
        left.grid(row=0, column=1, sticky="nsew", padx=(0, 16))
        left.grid_rowconfigure(2, weight=1)
        left.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(left, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew")
        top.grid_columnconfigure(0, weight=1)
        self.search_entry = ctk.CTkEntry(
            top, height=46, corner_radius=12, fg_color=CARD,
            border_color=CARD, font=F(14),
            placeholder_text="Search   (Ctrl+F)")
        self.search_entry.grid(row=0, column=0, sticky="ew")
        self.search_entry.bind("<KeyRelease>", self._on_search)
        add = ctk.CTkButton(
            top, text="+", command=self.add_account_dialog, width=46,
            height=46, corner_radius=12, fg_color=GREEN,
            hover_color=GREEN_HOVER, text_color=ON_ACCENT, font=F(22, "bold"))
        add.grid(row=0, column=1, padx=(10, 0))
        Tooltip(add, "Add an entry")

        info = ctk.CTkFrame(left, fg_color="transparent")
        info.grid(row=1, column=0, sticky="ew", pady=(12, 6))
        self.all_chip = ctk.CTkLabel(info, text="", font=F(12, "bold"),
                                     text_color=MUTED)
        self.all_chip.pack(side="left", padx=(6, 0))
        sort_menu = ctk.CTkOptionMenu(
            info, width=160, height=32, corner_radius=10,
            values=[SORT_LABELS[o] for o in SORT_ORDERS],
            fg_color=CARD, button_color=CARD,
            button_hover_color=CARD_HOVER, text_color=TEXT, font=F(12),
            dropdown_fg_color=CARD, dropdown_hover_color=CARD_HOVER,
            dropdown_text_color=TEXT, command=self._on_sort)
        sort_menu.set(SORT_LABELS[self.sort_order])
        sort_menu.pack(side="right")

        # Rows are cards of their own, straight on the window colour.
        self.list_frame = ctk.CTkScrollableFrame(left, fg_color="transparent",
                                                 corner_radius=0)
        self.list_frame.grid(row=2, column=0, sticky="nsew")
        self.list_frame.grid_columnconfigure(0, weight=1)

        self.detail = ctk.CTkFrame(shell, fg_color=CARD, corner_radius=20)
        self.detail.grid(row=0, column=2, sticky="nsew")

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

    def _on_vault_pick(self, label):
        picked = None
        for vault_id in self.vaults:
            if self.vault_name(vault_id) == label:
                picked = vault_id
        self.vault_filter = None if label == ALL_VAULTS else picked
        self.refresh_account_list()

    def _refresh_vault_menu(self):
        if self.vault_menu is None or not self.vault_menu.winfo_exists():
            return
        names = [self.vault_name(v) for v in self.vaults]
        notes, everything = {}, 0
        for vault_id, name in zip(self.vaults, names):
            count = len(active_accounts(self.vaults[vault_id]))
            everything += count
            notes[name] = (f"shared · {count}"
                           if self.account.is_shared(vault_id) else str(count))
        notes[ALL_VAULTS] = str(everything)
        # One vault needs no "all of them".
        self.vault_menu.configure(
            values=names if len(names) < 2 else [ALL_VAULTS] + names,
            notes=notes)
        self.vault_menu.set(self.vault_name(self.vault_filter)
                            if self.vault_filter in self.vaults
                            else (ALL_VAULTS if len(names) > 1 else names[0]))

    def _row_label(self, acc):
        """The vault's name on a row -- only where rows of several vaults
        are mixed."""
        if self.vault_filter in self.vaults or len(self.vaults) < 2:
            return ""
        return self.vault_name(self._entry_vault.get(acc["id"]))

    def refresh_account_list(self):
        self._cancel_row_build()
        if self._empty_box is not None:
            self._empty_box.destroy()
            self._empty_box = None
        self._refresh_vault_menu()

        accounts, stored = [], 0
        self._entry_vault = {}
        for vault_id in self.scope_ids():
            data = self.vaults[vault_id]
            stored += len(data["accounts"])
            for a in active_accounts(data):
                accounts.append(a)
                self._entry_vault[a["id"]] = vault_id
        active = {a["id"]: a for a in accounts}
        total = len(accounts)
        archived = stored - total
        q = self.search_query.strip().lower()
        if q:
            accounts = [a for a in accounts
                        if q in a["site"].lower() or q in a["username"].lower()]
        accounts = sort_accounts(accounts, self.sort_order)

        self.all_chip.configure(
            text=f"{total} entr{'y' if total == 1 else 'ies'}")
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
            if acc is None or _row_signature(acc, self._row_label(acc)) != sig:
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
                cached[1].grid(row=i, column=0, sticky="ew", pady=3, padx=2)
                cached[2] = i
            else:
                self._rows[acc["id"]] = [_row_signature(acc,
                                                        self._row_label(acc)),
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
        row.grid(row=i, column=0, sticky="ew", pady=3, padx=2)
        row.grid_columnconfigure(1, weight=1)

        bg, ink, _ = tile_colors(acc["site"])
        tile = ctk.CTkLabel(row, text=(acc["site"][:1].upper() or "?"),
                            width=42, height=42, corner_radius=12,
                            fg_color=bg, text_color=ink, font=F(16, "bold"))
        tile.grid(row=0, column=0, padx=(12, 12), pady=11)

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

        side = ctk.CTkFrame(row, fg_color="transparent")
        side.grid(row=0, column=2, padx=(8, 14))
        when = ctk.CTkLabel(side, text=history_ui.short_when(
            acc.get("updated_at", "")), font=F(11), text_color=MUTED)
        when.pack(anchor="e")
        clickable = [row, tile, info, site, user, side, when]
        label = self._row_label(acc)
        if label:
            where = ctk.CTkLabel(side, text=_clip(label, 16), font=F(11, "bold"),
                                 text_color=MUTED, height=16)
            where.pack(anchor="e")
            clickable.append(where)

        for w in clickable:
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
        for data in self.scope_vaults():
            for acc in active_accounts(data):
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
        band.grid_propagate(False)
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
        line = ("Last changed " + history_ui.local_time(changed)) if changed else ""
        home = self._entry_vault.get(acc["id"])
        writable = self.entry_writable(acc["id"])
        # In a vault other people are in, a change has a name.
        if line and acc.get("updated_by") and self.account.is_shared(home):
            line += " by " + _clip(acc["updated_by"], 24)
        # The vault's name on a line of its own: beside the date it ran
        # under the buttons.
        if len(self.vaults) > 1:
            line += ("\n" if line else "") + "In " + _clip(self.vault_name(
                self._entry_vault.get(acc["id"])), 28)
        ctk.CTkLabel(names, text=line, font=F(12), text_color=MUTED,
                     anchor="w", justify="left").pack(anchor="w")
        actions = ctk.CTkFrame(band, fg_color="transparent")
        actions.grid(row=0, column=2, padx=(8, 22))
        if writable:
            edit = self._ghost_button(actions, "Edit",
                                      lambda: self.account_dialog(acc),
                                      width=92)
            edit.configure(image=icon("edit", 16), compound="left")
            edit.pack(side="left", padx=(0, 8))
            arch = self._ghost_button(actions, "Archive",
                                      lambda: self._archive_account(acc),
                                      width=112)
            arch.configure(image=icon("archive", 16), compound="left")
            arch.pack(side="left")
            Tooltip(arch, "Move to archive — restorable, and it still syncs "
                          "the removal to your other PCs")
        else:
            only = ctk.CTkLabel(actions, text="Read only", font=F(12, "bold"),
                                text_color=MUTED, fg_color=CARD,
                                corner_radius=8, width=92, height=32)
            only.pack(side="left")
            Tooltip(only, "This vault is shared with you for reading: you can "
                          "see and copy, not change")

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
        name, frac, _ = estimate_strength(password)
        color = strength_color(name)
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
        if not self.entry_writable(acc["id"]):
            return self.read_only_notice()
        if not self._confirm(
                "Move to archive",
                f"Move the saved login for “{acc['site']}” to the archive?\n\n"
                "It leaves this list but stays in your vault, and you can "
                "restore it at any time.", danger=False):
            return
        archive_account(self.vault_holding(acc["id"]), acc["id"])
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

    def vaults_dialog(self):
        vaults_ui.vaults_dialog(self)

    def sync_settings_dialog(self):
        sync_ui.sync_settings_dialog(self)

    def restore_from_server_dialog(self):
        sync_ui.restore_from_server_dialog(self)

    def sync_now(self, **options):
        if self.account is not None:
            return account_sync_ui.run_sync(self)
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
        self.account = None
        self._selected_id = None
        self.search_query = ""
        self.show_login_screen()
        if auto:
            self.toast("Locked after inactivity", "warn")

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
    apply_appearance(appconfig.appearance())
    root = ctk.CTk()
    app = PasswordManagerGUI(root)
    root.mainloop()
