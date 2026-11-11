"""
Modal dialogs.

Each function takes the running :class:`gui.PasswordManagerGUI` as ``app`` and
uses its helpers (``app._modal``, ``app.toast``, ``app._save`` ...). Splitting
them out keeps gui.py to the application shell: the login screen, the account
list and the session lifecycle.

Every dialog is laid out by :func:`widgets.dialog_shell`: a header band, the
body, and the buttons in a footer bar.
"""

import os
import subprocess
import sys

import customtkinter as ctk
from tkinter import filedialog

import account_crypto
import account_sync
import account_sync_ui
import accounts
import appconfig
import importers
import sync_client
import totp
import vault
from theme import (F, TEXT, MUTED, GREEN, GREEN_HOVER, INPUT_BG, BORDER,
                   CARD, CARD_HOVER, ON_ACCENT, MONO, DANGER, tile_colors)
from vault import (add_account, validate_username, export_csv, export_json,
                   update_entry, find_duplicate)
from widgets import (Tooltip, dialog_shell, section, setting_row, option_menu, note,
                     error_label, check, field_label, entry, danger_button)
from crypto_utils import password_matches
from password_generator import generate_password
from sync_ui import _in_background
from version import long_version_string


def _site_tile(site):
    bg, ink, _ = tile_colors(site)
    return (site[:1].upper() or "?"), bg, ink


#: The words typed back after the phrase is shown, to prove it was written down.
CHECK_WORDS = (3, 7, 11)


def create_user_dialog(app):
    """
    A new SecretSpace 3 account, in three steps: name and master password, the
    Emergency Kit (Secret Key), the 12-word recovery phrase. Nothing is
    written until the last step, so closing a window half-way leaves no
    account behind.
    """
    top = app._modal("Create an account", 460, 600)
    shell = dialog_shell(top, "Create an account",
                         "Step 1 of 3 · Your master password opens this "
                         "account on this PC. Nobody can reset it for you.")
    wrap = shell.body

    user_entry = app._field(wrap, "Account name", placeholder="e.g. alex")
    pw_entry = app._field(wrap, "Master password", show="•")
    bar, label, update_strength = app._strength_widget(wrap)
    confirm_entry = app._field(wrap, "Confirm password", show="•")
    pw_entry.bind("<KeyRelease>", lambda e: update_strength(pw_entry.get()))

    show = ctk.CTkSwitch(wrap, text="Show passwords", font=F(12),
                         text_color=MUTED, progress_color=GREEN)
    show.pack(anchor="w", pady=(14, 0))

    def toggle():
        s = "" if show.get() else "•"
        pw_entry.configure(show=s)
        confirm_entry.configure(show=s)
    show.configure(command=toggle)

    err = error_label(wrap, shell.text_width)

    def create():
        u = user_entry.get().strip()
        p = pw_entry.get()
        c = confirm_entry.get()
        try:
            u = validate_username(u)
        except ValueError as e:
            err.configure(text=str(e)); return
        if not p:
            err.configure(text="Master password is required."); return
        if p != c:
            err.configure(text="Passwords do not match."); return
        if accounts.account_exists(u):
            err.configure(text="There is already an account with that "
                               "name."); return
        if len(p) < 8:
            err.configure(text="Use at least 8 characters — nobody can "
                               "reset this password for you."); return
        try:
            new = accounts.prepare_account(u, p)
        except (ValueError, FileExistsError) as e:
            err.configure(text=str(e)); return
        top.destroy()
        _emergency_kit_dialog(app, new, p)

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=120).pack(side="left")
    app._accent_button(shell.buttons, "Next", create,
                       width=150).pack(side="right")
    for e in (user_entry, pw_entry, confirm_entry):
        e.bind("<Return>", lambda ev: create())
    user_entry.focus()


def _save_kit_file(app, username, secret_key_text):
    """Save Emergency Kit… -- True once a file is written."""
    path = filedialog.asksaveasfilename(
        parent=app.root, title="Save Emergency Kit",
        defaultextension=".txt",
        initialfile=f"SecretSpace Emergency Kit - {username}.txt",
        filetypes=[("Text file", "*.txt"), ("All files", "*.*")])
    if not path:
        return False
    try:
        accounts.write_emergency_kit(path, username, secret_key_text)
    except OSError as e:
        app.toast(f"Could not save the kit: {e}", "error")
        return False
    app.toast("Emergency Kit saved — print it or keep it offline")
    return True


def _secret_key_box(parent, text):
    box = entry(parent, height=52, font=ctk.CTkFont(family=MONO, size=15))
    box.pack(fill="x")
    box.insert(0, text)
    box.configure(state="readonly")
    return box


def _emergency_kit_dialog(app, new, password):
    top = app._modal("Emergency Kit", 500, 600)
    shell = dialog_shell(top, "Your Emergency Kit",
                         "Step 2 of 3 · With your master password, this "
                         "Secret Key opens your account on another PC. "
                         "SecretSpace keeps a copy on this PC only.")
    wrap = shell.body

    field_label(wrap, "Account")
    ctk.CTkLabel(wrap, text=new.username, font=F(15, "bold"),
                 text_color=TEXT, anchor="w").pack(anchor="w")
    field_label(wrap, "Secret Key")
    _secret_key_box(wrap, new.secret_key_text)

    row = ctk.CTkFrame(wrap, fg_color="transparent")
    row.pack(fill="x", pady=(10, 0))
    app._accent_button(row, "Save Emergency Kit…",
                       lambda: _save_kit_file(app, new.username,
                                              new.secret_key_text),
                       width=190).pack(side="left")
    app._ghost_button(row, "Copy", lambda: app._copy(
        new.secret_key_text, "Secret Key copied", sensitive=True),
        width=90).pack(side="left", padx=(8, 0))

    note(wrap, "Print the kit, or keep the file somewhere offline — not next "
         "to your master password. Without the Secret Key, a stolen copy "
         "of your account cannot be opened by guessing the password.",
         shell.text_width, pady=(14, 0))
    saved = check(wrap, "I have saved my Emergency Kit", shell.text_width)
    err = error_label(wrap, shell.text_width)

    def next_step():
        if not saved.get():
            err.configure(text="Save or print the kit, then tick the box."); return
        top.destroy()
        _phrase_dialog(app, new, password)

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=120).pack(side="left")
    app._accent_button(shell.buttons, "Next", next_step,
                       width=150).pack(side="right")


def _phrase_dialog(app, new, password):
    top = app._modal("Recovery phrase", 520, 600)
    shell = dialog_shell(top, "Your recovery phrase",
                         "Step 3 of 3 · These 12 words open your account if "
                         "you forget your master password. Write them on "
                         "paper, in order.")
    wrap = shell.body

    grid = ctk.CTkFrame(wrap, fg_color=CARD, corner_radius=16,
                        border_width=1, border_color=BORDER)
    grid.pack(fill="x", pady=(14, 0))
    for c in range(3):
        grid.grid_columnconfigure(c, weight=1, uniform="word")
    for i, word in enumerate(new.recovery_phrase.split()):
        cell = ctk.CTkFrame(grid, fg_color="transparent")
        cell.grid(row=i // 3, column=i % 3, sticky="w", padx=16, pady=8)
        ctk.CTkLabel(cell, text=f"{i + 1:>2}", font=F(12), text_color=MUTED,
                     width=22, anchor="e").pack(side="left")
        ctk.CTkLabel(cell, text=word, text_color=TEXT,
                     font=ctk.CTkFont(family=MONO, size=15, weight="bold")
                     ).pack(side="left", padx=(8, 0))

    note(wrap, "Anyone with these words can open everything in this account. "
         "Keep them like a passport: not in a file or a photo, and not with "
         "the Emergency Kit. SecretSpace does not show them again.",
         shell.text_width, pady=(14, 0))

    def next_step():
        top.destroy()
        _phrase_check_dialog(app, new, password)

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=120).pack(side="left")
    app._accent_button(shell.buttons, "I wrote them down", next_step,
                       width=170).pack(side="right")


def phrase_mismatches(phrase, typed):
    """The word numbers in ``typed`` ({n: text}) that do not match ``phrase``."""
    words = phrase.split()
    return [n for n, text in sorted(typed.items())
            if text.strip().lower() != words[n - 1]]


def _phrase_check_dialog(app, new, password):
    top = app._modal("Check your phrase", 460, 460)
    shell = dialog_shell(top, "Check your phrase",
                         "Type words " + ", ".join(map(str, CHECK_WORDS[:-1]))
                         + f" and {CHECK_WORDS[-1]} from your paper copy.")
    wrap = shell.body
    boxes = {n: app._field(wrap, f"Word {n}") for n in CHECK_WORDS}
    err = error_label(wrap, shell.text_width)

    def finish():
        wrong = phrase_mismatches(new.recovery_phrase,
                                  {n: b.get() for n, b in boxes.items()})
        if wrong:
            err.configure(text="Word " + ", ".join(map(str, wrong)) +
                               (" does" if len(wrong) == 1 else " do") +
                               " not match. Look at your paper copy again.")
            return
        try:
            account = new.save()
            loaded = account.load_vault()
        except Exception as e:
            err.configure(text=str(e)); return
        top.destroy()
        app.open_account(account, loaded, password)
        app.toast(f"Welcome, {account.username}! Import brings in your 2.x "
                  "vaults.")

    def back():
        top.destroy()
        _phrase_dialog(app, new, password)

    app._ghost_button(shell.buttons, "Show the words again", back,
                      width=170).pack(side="left")
    app._accent_button(shell.buttons, "Create account", finish,
                       width=150).pack(side="right")
    for b in boxes.values():
        b.bind("<Return>", lambda ev: finish())
    boxes[CHECK_WORDS[0]].focus()


def ask_secret_key(app, username):
    """
    The Secret Key, for a PC that has not opened this account before. The
    text typed (checked for typos), or None if the dialog is closed.
    """
    top = app._modal("Secret Key", 480, 360)
    shell = dialog_shell(top, "Enter your Secret Key",
                         f"This PC does not hold the Secret Key of "
                         f"“{username}” — it is new here, or it can no "
                         "longer read the copy it kept. It is on your "
                         "Emergency Kit and starts with A3-.")
    box = app._field(shell.body, "Secret Key", placeholder="A3-XXXXX-XXXXX-…")
    box.configure(font=ctk.CTkFont(family=MONO, size=14))
    err = error_label(shell.body, shell.text_width)
    out = {"text": None}

    def go():
        try:
            account_crypto.parse_secret_key(box.get())
        except ValueError as e:
            err.configure(text=str(e)); return
        out["text"] = box.get()
        top.destroy()

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=110).pack(side="left")
    app._accent_button(shell.buttons, "Unlock", go,
                       width=150).pack(side="right")
    box.bind("<Return>", lambda e: go())
    top.bind("<Escape>", lambda e: top.destroy())
    top.after(200, box.focus)
    app.root.wait_window(top)
    return out["text"]


def import_dialog(app):
    """Where to import from: a 2.x vault (whole entries) or a CSV/JSON file."""
    top = app._modal("Import", 520, 560)
    shell = dialog_shell(top, "Import",
                         f"Bring logins into “{app.current_user}”. What you "
                         "import from is only read, never changed.",
                         scroll=True)
    wrap = shell.body
    hint = shell.text_width - 190

    def go(action):
        top.destroy()
        action()

    two = section(wrap, "PassMan 2.x vaults on this PC", first=True)
    names = vault.list_users()
    if not names:
        setting_row(two, "None found",
                    f"No 2.x vault in {vault.get_data_dir()}.", hint,
                    first=True)
    for i, name in enumerate(names):
        app._ghost_button(
            setting_row(two, name, "With its history and archive.", hint,
                        first=i == 0),
            "Import…", lambda n=name: go(lambda: _import_2x(
                app, vault.get_vault_path(n), n)), width=130).pack()

    other = section(wrap, "From a file")
    app._ghost_button(
        setting_row(other, "A 2.x vault file",
                    "A backup (.vault.enc) or a copy from another PC.", hint,
                    first=True),
        "Choose…", lambda: go(lambda: _import_2x_file(app)), width=130).pack()
    app._ghost_button(
        setting_row(other, "CSV or JSON",
                    "Exported from another password manager or a browser.",
                    hint),
        "Choose…", lambda: go(lambda: _import_plain_file(app)),
        width=130).pack()

    app._ghost_button(shell.buttons, "Close", top.destroy,
                      width=120).pack(side="right")
    top.bind("<Escape>", lambda e: top.destroy())


def _import_2x_file(app):
    path = filedialog.askopenfilename(
        parent=app.root, title="Import a PassMan 2.x vault",
        filetypes=[("SecretSpace vault", "*.enc *.vault *.bak"),
                   ("All files", "*.*")])
    if path:
        _import_2x(app, path, os.path.basename(path))


def _import_plain_file(app):
    path = filedialog.askopenfilename(
        parent=app.root, title="Import accounts from file",
        filetypes=[
            ("All supported", "*.csv *.json"),
            ("CSV files", "*.csv"),
            ("JSON files", "*.json"),
            ("All files", "*.*")])
    if not path:
        return
    try:
        parsed = importers.parse_import_file(path)
    except Exception as e:
        app.toast(f"Could not read file: {e}", "error")
        return
    _finish_import(app, parsed, path)


def _import_2x(app, path, label):
    """
    A 2.x vault into the open account, entries whole (ids, history, archive).
    The 2.x file is read once and left as it was; its sync settings stay
    with it.
    """
    top = app._modal("Import a 2.x vault", 460, 300)
    shell = dialog_shell(top, f"Import “{label}”",
                         "Enter the master password of that 2.x vault. "
                         "Its file is only read.")
    pw = app._field(shell.body, "Its master password", show="•")
    err = error_label(shell.body, shell.text_width)

    def unlock():
        try:
            data = vault.read_vault_file(path, pw.get())
        except OSError as e:
            err.configure(text=f"Could not read the file: {e}"); return
        except ValueError:
            err.configure(text="Wrong password, or not a SecretSpace vault file.")
            return
        import copy
        trial = copy.deepcopy(app.vault)
        added, skipped = vault.import_entries(trial, data)
        top.destroy()
        if not added:
            app.toast("Everything in that vault is already here", "warn")
            return
        msg = (f"Import {added} entr{'y' if added == 1 else 'ies'} from "
               f"“{label}” into {app.vault_phrase()}, with their history "
               "and archive state?")
        if skipped:
            msg += (f"\n\n{skipped} already in that vault will be "
                    "skipped.")
        msg += ("\n\nThe 2.x vault is not changed, and its sync settings "
                "stay with it.")
        if not app._confirm("Import a 2.x vault", msg, danger=False):
            return
        app.vault = trial
        if app._save():
            app.refresh_account_list()
            app.toast(f"Imported {added} entr{'y' if added == 1 else 'ies'}")

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=110).pack(side="left")
    app._accent_button(shell.buttons, "Import", unlock,
                       width=150).pack(side="right")
    pw.bind("<Return>", lambda e: unlock())
    top.after(200, pw.focus)


def _finish_import(app, parsed, path):
    # keep rows that carry at least something useful
    candidates = [a._replace(site=a.site or "(unknown)")
                  for a in parsed.rows if a.site or a.username or a.password]
    if not candidates:
        app.toast("No accounts found in that file", "warn")
        return

    # skip entries identical to ones already stored (or repeated in the file)
    seen = {(a["site"], a["username"], a["password"])
            for a in app.vault["accounts"]}
    new_items, dupes = [], 0
    for item in candidates:
        key = (item.site, item.username, item.password)
        if key in seen:
            dupes += 1
            continue
        seen.add(key)
        new_items.append(item)
    if not new_items:
        app.toast("Those entries are already in your vault", "warn")
        return

    name = os.path.basename(path)
    msg = f"Found {len(new_items)} new account(s) in “{name}”."
    if dupes:
        msg += f"\n{dupes} duplicate(s) will be skipped."
    carried = importers.imported_fields(new_items)
    if carried:
        msg += "\n\nAlso importing: " + ", ".join(carried) + "."
    if parsed.dropped:
        # Say so up front: silently losing data is how people get locked
        # out of their accounts after a migration.
        msg += ("\n\nThis file also contains " + ", ".join(parsed.dropped) +
                ", which SecretSpace cannot store. Keep the original file "
                "until you have checked you still have them.")
    msg += f"\n\nAdd them to {app.vault_phrase()}?"
    if not app._confirm("Import accounts", msg, danger=False):
        return

    for item in new_items:
        add_account(app.vault, item.site, item.username, item.password,
                    notes=item.notes, totp=item.totp)
    app._save()
    app.refresh_account_list()
    app.toast(f"Imported {len(new_items)} account(s)")


def account_dialog(app, acc):
    editing = acc is not None
    title = "Edit entry" if editing else "Add an entry"
    subtitle = ("Update this login; the version it replaces is kept in its "
                "history." if editing else "Store a new login in your vault.")

    top = app._modal(title, 500, 760)
    shell = dialog_shell(top, acc["site"] if editing else title,
                         subtitle, tile=_site_tile(acc["site"] if editing
                                                   else ""))
    wrap = shell.body

    # A new entry goes to the vault picked in the main window; with several
    # vaults it can be changed here. An edit stays in the entry's own vault.
    # (The picker sits in the button bar, so the form is no taller.)
    target = {"id": app.active_vault_id}

    def target_vault():
        return app.vault_holding(acc["id"]) if editing else app.vaults[target["id"]]

    site_entry = app._field(wrap, "Website / App", placeholder="e.g. GitHub")
    user_entry = app._field(wrap, "Username / Email",
                            placeholder="e.g. you@example.com")

    field_label(wrap, "Password")
    pw_row = ctk.CTkFrame(wrap, fg_color="transparent")
    pw_row.pack(fill="x")
    pw_row.grid_columnconfigure(0, weight=1)
    pw_entry = entry(pw_row, show="•",
                     font=ctk.CTkFont(family=MONO, size=14))
    pw_entry.grid(row=0, column=0, sticky="ew")
    show_btn = ctk.CTkButton(
        pw_row, text="Show", width=64, height=44, corner_radius=12,
        fg_color="transparent", border_width=1, border_color=BORDER,
        hover_color=CARD_HOVER, text_color=TEXT, font=F(12, "bold"))
    show_btn.grid(row=0, column=1, padx=(8, 8))
    gen_btn = ctk.CTkButton(
        pw_row, text="Generate", width=96, height=44, corner_radius=12,
        fg_color=GREEN, hover_color=GREEN_HOVER, text_color=ON_ACCENT,
        font=F(12, "bold"))
    gen_btn.grid(row=0, column=2)

    bar, label, update_strength = app._strength_widget(wrap)

    totp_entry = app._field(
        wrap, "2FA secret (optional)",
        placeholder="the secret or otpauth:// link the site shows")

    field_label(wrap, "Notes (optional)")
    notes_box = ctk.CTkTextbox(wrap, height=76, corner_radius=12,
                               fg_color=INPUT_BG, border_color=BORDER,
                               border_width=1, font=F(13))
    notes_box.pack(fill="x")

    def toggle():
        if pw_entry.cget("show"):
            pw_entry.configure(show=""); show_btn.configure(text="Hide")
        else:
            pw_entry.configure(show="•"); show_btn.configure(text="Show")
    show_btn.configure(command=toggle)

    def gen():
        pw = generate_password(20)
        pw_entry.delete(0, "end"); pw_entry.insert(0, pw)
        pw_entry.configure(show=""); show_btn.configure(text="Hide")
        update_strength(pw)
    gen_btn.configure(command=gen)
    pw_entry.bind("<KeyRelease>", lambda e: update_strength(pw_entry.get()))

    def retitle(_=None):
        # The header follows the site as it is typed, tile and all, so the
        # dialog looks like the details card the entry will get.
        site = site_entry.get().strip()
        letter, bg, ink = _site_tile(site)
        shell.tile.configure(text=letter, fg_color=bg, text_color=ink)
        shell.heading.configure(text=site or title)
    site_entry.bind("<KeyRelease>", retitle, add="+")

    if editing:
        site_entry.insert(0, acc["site"])
        user_entry.insert(0, acc["username"])
        pw_entry.insert(0, acc["password"])
        totp_entry.insert(0, acc.get("totp", ""))
        notes_box.insert("1.0", acc.get("notes", ""))
        update_strength(acc["password"])

    err = error_label(wrap, shell.text_width)

    def save():
        site = site_entry.get().strip()
        if not site:
            err.configure(text="Website / App is required."); return
        password = pw_entry.get()
        if not password:
            err.configure(text="Password is required."); return
        notes = notes_box.get("1.0", "end").strip()
        totp_secret = totp_entry.get().strip()
        problem = totp.check(totp_secret)
        if problem:
            # Refused here rather than discovered when a code is needed.
            err.configure(text="2FA secret: " + problem); return
        username = user_entry.get().strip()
        # Ask before the same login is stored twice -- on add, or when an
        # edit would turn this entry into a copy of another one.
        twin = find_duplicate(target_vault(), site, username,
                              exclude_id=acc["id"] if editing else None)
        if twin is not None and not app._confirm(
                "Already saved",
                f"There is already a login for {twin['site']} with the "
                f"username {twin['username'] or '(none)'}. Save another "
                "one anyway?", danger=False):
            return
        if editing:
            # Through update_entry, so the version being replaced is kept in
            # the entry's history, and saving with no real change records
            # nothing. It also stamps updated_at -- shown in the conflict
            # dialog, never used by the merge, which goes by the sync base.
            update_entry(acc, site=site, username=username,
                         password=password, notes=notes, totp=totp_secret)
        else:
            add_account(target_vault(), site, username,
                        password, notes=notes, totp=totp_secret)
        app._save()
        top.destroy()
        app.refresh_account_list()
        app.toast("Account updated" if editing else "Account added")

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=120).pack(side="left")
    app._accent_button(shell.buttons,
                       "Save changes" if editing else "Save entry",
                       save, width=150).pack(side="right")
    if not editing and len(app.vaults) > 1:
        names = {app.vault_name(v): v for v in app.vaults}
        picker = option_menu(
            shell.buttons, list(names),
            lambda label: target.update(id=names[label]), width=140)
        picker.configure(height=40)
        picker.pack(side="right", padx=(0, 10))
        picker.set(app.vault_name(target["id"]))
        Tooltip(picker, "The vault this entry is saved in")
    for e in (site_entry, user_entry, pw_entry, totp_entry):
        e.bind("<Return>", lambda ev: save())
    site_entry.focus()


def generator_dialog(app):
    top = app._modal("Password generator", 480, 520)
    shell = dialog_shell(top, "Password generator",
                         "A new password appears with every change. Nothing "
                         "is saved — copy it, or use Generate in an entry.")
    wrap = shell.body

    field_label(wrap, "Password")
    result = entry(wrap, height=52, font=ctk.CTkFont(family=MONO, size=16))
    result.pack(fill="x")
    bar, strength_label, update_strength = app._strength_widget(wrap)

    card = section(wrap, "Options")
    length = ctk.IntVar(value=20)
    opts = {k: ctk.BooleanVar(value=True)
            for k in ("upper", "lower", "digits", "symbols")}

    def regenerate(*_):
        n = int(length.get())
        pw = generate_password(
            n, use_upper=opts["upper"].get(), use_lower=opts["lower"].get(),
            use_digits=opts["digits"].get(), use_symbols=opts["symbols"].get())
        result.delete(0, "end"); result.insert(0, pw)
        update_strength(pw)

    len_row = ctk.CTkFrame(card, fg_color="transparent")
    len_row.pack(fill="x", padx=16, pady=(14, 0))
    ctk.CTkLabel(len_row, text="Length", font=F(13, "bold"),
                 text_color=TEXT).pack(side="left")
    len_val = ctk.CTkLabel(len_row, text="20", font=F(13, "bold"),
                           text_color=GREEN)
    len_val.pack(side="right")
    ctk.CTkSlider(card, from_=6, to=64, number_of_steps=58, variable=length,
                  progress_color=GREEN, button_color=GREEN,
                  button_hover_color=GREEN_HOVER,
                  command=lambda v: (len_val.configure(text=str(int(float(v)))),
                                     regenerate())
                  ).pack(fill="x", padx=12, pady=(8, 6))

    checks = ctk.CTkFrame(card, fg_color="transparent")
    checks.pack(fill="x", padx=16, pady=(4, 14))
    for idx, (key, lab) in enumerate((("upper", "A-Z"), ("lower", "a-z"),
                                      ("digits", "0-9"), ("symbols", "!@#"))):
        ctk.CTkCheckBox(checks, text=lab, variable=opts[key], font=F(13),
                        text_color=TEXT, fg_color=GREEN,
                        hover_color=GREEN_HOVER, border_color=MUTED,
                        command=regenerate, checkbox_width=22,
                        checkbox_height=22, width=80
                        ).grid(row=0, column=idx, sticky="w", pady=4)

    app._ghost_button(shell.buttons, "Regenerate", regenerate,
                      width=130).pack(side="left")
    app._accent_button(
        shell.buttons, "Copy", lambda: app._copy(result.get(),
                                                 "Password copied",
                                                 sensitive=True),
        width=150).pack(side="right")

    regenerate()


def settings_dialog(app):
    # The sections scroll and the header and Close row stay put: together
    # they are taller than many screens (display scaling, Linux font
    # metrics), and growing the window to fit pushed Close off the screen.
    top = app._modal("Settings", 540, 660)
    shell = dialog_shell(top, "Settings",
                         f"For the account “{app.current_user}” on this PC.",
                         scroll=True)
    wrap = shell.body
    hint = shell.text_width - 210

    # ---- security ----
    sec = section(wrap, "Security", first=True)
    app._ghost_button(
        setting_row(sec, "Master password",
                    "Your Secret Key and recovery phrase stay the same.",
                    hint, first=True),
        "Change…", lambda: _change_master_dialog(app, top),
        width=150).pack()
    app._ghost_button(
        setting_row(sec, "Emergency Kit",
                    "Your Secret Key again — needed to open this account on "
                    "another PC.", hint),
        "Save kit…", lambda: _save_kit_again(app), width=150).pack()

    def label_for(m):
        return "Never" if m == 0 else f"{m} minute{'s' if m != 1 else ''}"

    def set_autolock(choice):
        for m in appconfig.AUTOLOCK_CHOICES:
            if label_for(m) == choice:
                appconfig.save_config(autolock_minutes=m)
                app._start_idle_timer()
                break

    lock_menu = option_menu(
        setting_row(sec, "Lock after inactivity",
                    "Locking keeps a copied password until it clears.", hint),
        [label_for(m) for m in appconfig.AUTOLOCK_CHOICES], set_autolock,
        width=150)
    lock_menu.pack()
    lock_menu.set(label_for(appconfig.autolock_minutes()))

    # ---- sync ----
    syn = section(wrap, "Sync")
    server = app.account.server
    if server:
        app._ghost_button(
            setting_row(syn, "Synced with", server["url"], hint, first=True),
            "Sync now", lambda: (top.destroy(), app.sync_now()), width=150).pack()
        app._ghost_button(
            setting_row(syn, "Stop syncing on this PC",
                        "The server keeps its copy; connect again any time.",
                        hint),
            "Disconnect", lambda: (account_sync_ui.forget_server(app),
                                   top.destroy()), width=150).pack()
    else:
        app._ghost_button(
            setting_row(syn, "Not on a server yet",
                        "Keep this account in step across your devices "
                        "through your own SecretSpace Server (2.0 or newer).",
                        hint, first=True),
            "Set up…", lambda: (top.destroy(),
                               account_sync_ui.server_dialog(app)),
            width=150).pack()

    # ---- archive ----
    arc = section(wrap, "Archive")

    def days_label(d):
        return "Never" if d == 0 else f"After {d} days"

    def set_purge(choice):
        days = next(d for d in vault.ARCHIVE_PURGE_CHOICES
                    if days_label(d) == choice)
        due = ([e for data in app.vaults.values()
                for e in vault.archived_before(data, vault.purge_cutoff(days))]
               if days else [])
        if due and not app._confirm(
                "Delete archived entries",
                f"{len(due)} archived entr"
                f"{'y is' if len(due) == 1 else 'ies are'} older than "
                f"{days} days and will be deleted permanently now.\n\n"
                "This cannot be undone."):
            purge_menu.set(days_label(vault.archive_purge_days(app.vault)))
            return
        purged = 0
        for data in app.vaults.values():         # one setting, every vault
            vault.set_archive_purge_days(data, days)
            purged += vault.auto_purge_archive(data)
        if app._save():
            app.refresh_account_list()
            if purged:
                app.toast(f"Deleted {purged} archived "
                          f"entr{'y' if purged == 1 else 'ies'}", "warn")

    purge_menu = option_menu(
        setting_row(arc, "Delete archived entries",
                    "Counted from when an entry was archived, and applied "
                    "each time you unlock. Deleted entries are gone for good, "
                    "from your other PC too after its next sync.", hint,
                    first=True),
        [days_label(d) for d in vault.ARCHIVE_PURGE_CHOICES], set_purge,
        width=150)
    purge_menu.pack()
    purge_menu.set(days_label(vault.archive_purge_days(app.vault)))

    # ---- backup & export ----
    exp = section(wrap, "Backup & export")
    app._ghost_button(
        setting_row(exp, "Backup",
                    "Copy this account's folder. The copy opens only with "
                    "your master password and Secret Key.", hint, first=True),
        "Open folder", lambda: _open_account_folder(app), width=150).pack()
    app._ghost_button(
        setting_row(exp, "Plain export",
                    "Readable by anyone who opens the file.", hint),
        "Export…", lambda: _export_plaintext(app), width=150,
        danger=True).pack()

    # ---- danger zone ----
    danger = section(wrap, "Danger zone", danger=True)
    danger_button(
        setting_row(danger, "Delete this account",
                    f"Permanently deletes “{app.current_user}” and its vault "
                    "on this PC. 2.x vaults are not touched.", hint,
                    first=True),
        "Delete…", lambda: _delete_user_flow(app, top), width=150).pack()
    ctk.CTkFrame(wrap, height=8, fg_color="transparent").pack()

    ctk.CTkLabel(shell.buttons, text=long_version_string(), font=F(11),
                 text_color=MUTED).pack(side="left")
    app._ghost_button(shell.buttons, "Close", top.destroy,
                      width=120).pack(side="right")
    top.bind("<Escape>", lambda e: top.destroy())


def _save_kit_again(app):
    if ask_master_password(app, "Emergency Kit",
                           "Enter your master password to save your Secret "
                           "Key again.", action="Continue"):
        _save_kit_file(app, app.current_user, app.account.secret_key_text)


def _open_account_folder(app):
    folder = accounts.account_dir(app.current_user)
    try:
        if sys.platform == "win32":
            os.startfile(folder)                # Explorer
        else:
            subprocess.Popen(["xdg-open", folder])  # the desktop's file manager
    except OSError as e:
        app.toast(f"The folder is {folder} ({e})", "warn")


def _export_plaintext(app):
    if not app._confirm(
            "Export unencrypted",
            "This writes every stored password to a file in plain text, "
            "with no protection at all. Anyone who opens that file — or "
            "recovers it from the disk later — can read all of them.\n\n"
            "Only do this to move into another password manager, and "
            "delete the file as soon as you are done.\n\n"
            "Continue?"):
        return
    path = filedialog.asksaveasfilename(
        parent=app.root, title="Export unencrypted",
        defaultextension=".csv",
        initialfile=f"{app.current_user}-passwords.csv",
        filetypes=[("CSV file", "*.csv"), ("JSON file", "*.json")])
    if not path:
        return
    try:
        writer = export_json if path.lower().endswith(".json") else export_csv
        count = writer(app.scope_data(), path)
    except Exception as e:
        app.toast(f"Export failed: {e}", "error")
        return
    app.toast(f"Exported {count} account(s) in plain text", "warn")


def _change_master_dialog(app, parent_top):
    top = app._modal("Change master password", 460, 520)
    shell = dialog_shell(top, "Change master password",
                         "Takes effect at once. Your Secret Key and recovery "
                         "phrase stay the same.")
    wrap = shell.body

    cur_entry = app._field(wrap, "Current master password", show="•")
    new_entry = app._field(wrap, "New master password", show="•")
    bar, label, update_strength = app._strength_widget(wrap)
    confirm_entry = app._field(wrap, "Confirm new password", show="•")
    new_entry.bind("<KeyRelease>", lambda e: update_strength(new_entry.get()))
    err = error_label(wrap, shell.text_width)

    def change():
        if not password_matches(cur_entry.get(), app.master_password):
            err.configure(text="Current master password is incorrect."); return
        new = new_entry.get()
        if not new:
            err.configure(text="New master password is required."); return
        if new != confirm_entry.get():
            err.configure(text="New passwords do not match."); return
        if new == app.master_password:
            err.configure(text="That is already your master password."); return
        if len(new) < 8:
            err.configure(text="Use at least 8 characters."); return
        # The keyset is resealed; the vault file is not touched. An account
        # on a server tells the server first (account_sync.change_password),
        # so this runs off the main thread.
        err.configure(text="Changing…", text_color=MUTED)

        def done(_):
            app.master_password = new
            top.destroy()
            parent_top.destroy()
            app.toast("Master password changed")

        def failed(e):
            text = (str(e) if isinstance(e, sync_client.SyncError)
                    else "Could not save. Password unchanged.")
            if isinstance(e, sync_client.SyncError):
                text += " The password was not changed anywhere."
            err.configure(text=text, text_color=DANGER)

        _in_background(app, lambda: account_sync.change_password(app.account, new),
                       done, failed)

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=110).pack(side="left")
    app._accent_button(shell.buttons, "Change password", change,
                       width=170).pack(side="right")
    for e in (cur_entry, new_entry, confirm_entry):
        e.bind("<Return>", lambda ev: change())
    cur_entry.focus()


def ask_master_password(app, title, subtitle, action="Continue"):
    """
    Ask for the master password again while the vault is open -- before a
    2FA code is shown, every time. True once it is typed right; False if the
    dialog is closed.
    """
    top = app._modal(title, 460, 300)
    shell = dialog_shell(top, title, subtitle)
    pw = app._field(shell.body, "Master password", show="•")
    err = error_label(shell.body, shell.text_width)
    outcome = {"ok": False}

    def go():
        if not password_matches(pw.get(), app.master_password):
            pw.delete(0, "end")
            err.configure(text="Incorrect master password.")
            return
        outcome["ok"] = True
        top.destroy()

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=110).pack(side="left")
    app._accent_button(shell.buttons, action, go,
                       width=150).pack(side="right")
    pw.bind("<Return>", lambda e: go())
    top.bind("<Escape>", lambda e: top.destroy())
    top.after(200, pw.focus)
    app.root.wait_window(top)
    return outcome["ok"]


def _delete_user_flow(app, parent_top):
    top = app._modal("Delete account", 440, 300)
    shell = dialog_shell(top, f"Delete “{app.current_user}”",
                         "Re-enter your master password to confirm. This "
                         "deletes the account and its vault on this PC "
                         "permanently.", danger=True)
    pw = app._field(shell.body, "Master password", show="•")
    err = error_label(shell.body, shell.text_width)

    def do_delete():
        if not password_matches(pw.get(), app.master_password):
            err.configure(text="Incorrect master password."); return
        try:
            accounts.delete_account(app.current_user)
        except Exception as e:
            err.configure(text=str(e)); return
        top.destroy(); parent_top.destroy()
        app.vault = app.master_password = app.current_user = None
        app.account = None
        app.show_login_screen()
        app.toast("Account deleted")

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=110).pack(side="left")
    danger_button(shell.buttons, "Delete", do_delete,
                  width=120).pack(side="right")
    pw.bind("<Return>", lambda e: do_delete())
    pw.focus()
