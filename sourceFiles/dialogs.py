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

import customtkinter as ctk
from tkinter import filedialog

import appconfig
import importers
import sync_client
import totp
import vault
from theme import (F, TEXT, MUTED, GREEN, GREEN_HOVER, INPUT_BG, BORDER,
                   CARD_HOVER, ON_ACCENT, MONO, tile_colors)
from vault import (add_account, create_new_user, delete_user, get_vault_path,
                   validate_username, export_encrypted, export_csv,
                   export_json, update_entry, change_master_password,
                   find_duplicate)
from widgets import (dialog_shell, section, setting_row, option_menu, note,
                     error_label, check, field_label, entry, danger_button)
from crypto_utils import decrypt, password_matches
from password_generator import generate_password
from version import long_version_string


def _site_tile(site):
    bg, ink, _ = tile_colors(site)
    return (site[:1].upper() or "?"), bg, ink


def create_user_dialog(app):
    top = app._modal("Create new user", 460, 560)
    shell = dialog_shell(top, "Create new user",
                         "Your master password encrypts the vault and "
                         "cannot be recovered.")
    wrap = shell.body

    user_entry = app._field(wrap, "Username", placeholder="e.g. alex")
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
        if os.path.exists(get_vault_path(u)):
            err.configure(text="That user already exists."); return
        if len(p) < 8:
            err.configure(text="Use at least 8 characters — this password "
                               "cannot be recovered or reset."); return
        try:
            create_new_user(u, p)
        except FileExistsError:
            err.configure(text="That user already exists."); return
        except Exception as e:
            err.configure(text=str(e)); return
        app.vault = {"accounts": []}
        app.master_password = p
        app.current_user = u
        appconfig.save_config(last_username=u)
        top.destroy()
        app.show_main_window()
        app.toast(f"Welcome, {u}!")

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=120).pack(side="left")
    app._accent_button(shell.buttons, "Create user", create,
                       width=150).pack(side="right")
    for e in (user_entry, pw_entry, confirm_entry):
        e.bind("<Return>", lambda ev: create())
    user_entry.focus()


def import_dialog(app):
    path = filedialog.askopenfilename(
        parent=app.root, title="Import accounts from file",
        filetypes=[
            ("All supported", "*.csv *.json *.vault *.enc"),
            ("CSV files", "*.csv"),
            ("JSON files", "*.json"),
            ("Encrypted vault", "*.vault *.enc"),
            ("All files", "*.*")])
    if not path:
        return

    # Encrypted SecretSpace vault files (.vault / .vault.enc / .enc) must be
    # decrypted with their own master password before we can read accounts.
    ext = os.path.splitext(path)[1].lower()
    if ext in (".vault", ".enc"):
        _import_encrypted_vault(app, path)
        return

    try:
        parsed = importers.parse_import_file(path)
    except Exception as e:
        app.toast(f"Could not read file: {e}", "error")
        return
    _finish_import(app, parsed, path)


def _import_encrypted_vault(app, path):
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except Exception as e:
        app.toast(f"Could not read file: {e}", "error")
        return

    top = app._modal("Unlock vault file", 460, 280)
    shell = dialog_shell(top, "Unlock vault file",
                         f"“{os.path.basename(path)}” is encrypted. Enter its "
                         "master password to import the accounts inside.")
    pw = app._field(shell.body, "Master password of the file", show="•")
    err = error_label(shell.body, shell.text_width)

    def unlock():
        try:
            data = decrypt(pw.get(), blob)
        except Exception:
            err.configure(text="Wrong password or not a valid vault file.")
            return
        result = importers.accounts_from_vault(data)
        top.destroy()
        if not result.rows:
            app.toast("That vault file has no accounts", "warn")
            return
        _finish_import(app, result, path)

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=110).pack(side="left")
    app._accent_button(shell.buttons, "Unlock & import", unlock,
                       width=170).pack(side="right")
    pw.bind("<Return>", lambda e: unlock())
    pw.focus()


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
    msg += "\n\nAdd them to your vault?"
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
        twin = find_duplicate(app.vault, site, username,
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
            add_account(app.vault, site, username,
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
                         f"For the vault “{app.current_user}” on this PC.",
                         scroll=True)
    wrap = shell.body
    hint = shell.text_width - 210

    # ---- security ----
    sec = section(wrap, "Security", first=True)
    app._ghost_button(
        setting_row(sec, "Master password",
                    "Re-encrypts your vault with a new one.", hint, first=True),
        "Change…", lambda: _change_master_dialog(app, top),
        width=150).pack()

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
    configured = sync_client.is_configured(app.vault)
    app._ghost_button(
        setting_row(syn, "Syncing" if configured else "Not set up",
                    (f"With {sync_client.get_settings(app.vault)['url']}"
                     if configured else
                     "Keep this vault in step with another PC through your "
                     "own server. It is encrypted before it is sent."),
                    hint, first=True),
        "Sync settings" if configured else "Set up sync",
        lambda: (top.destroy(), app.sync_settings_dialog()),
        width=150).pack()

    if configured:
        def set_on_unlock():
            on = on_unlock.get() == 1
            sync_client.set_sync_on_unlock(app.vault, on)
            if app._save():
                app.toast("This vault now syncs each time you unlock it" if on
                          else "Sync on unlock is off — press Sync yourself")

        on_unlock = ctk.CTkSwitch(
            setting_row(syn, "Sync when I unlock",
                        "Off: nothing is sent until you press Sync. On: "
                        "SecretSpace syncs right after you unlock; a conflict "
                        "still waits for your choice.", hint),
            text="", width=46, switch_width=42, switch_height=22,
            progress_color=GREEN, button_color=TEXT,
            button_hover_color=TEXT, fg_color=BORDER,
            command=set_on_unlock)
        on_unlock.pack()
        if sync_client.sync_on_unlock(app.vault):
            on_unlock.select()

    # ---- archive ----
    arc = section(wrap, "Archive")

    def days_label(d):
        return "Never" if d == 0 else f"After {d} days"

    def set_purge(choice):
        days = next(d for d in vault.ARCHIVE_PURGE_CHOICES
                    if days_label(d) == choice)
        due = (vault.archived_before(app.vault, vault.purge_cutoff(days))
               if days else [])
        if due and not app._confirm(
                "Delete archived entries",
                f"{len(due)} archived entr"
                f"{'y is' if len(due) == 1 else 'ies are'} older than "
                f"{days} days and will be deleted permanently now.\n\n"
                "This cannot be undone."):
            purge_menu.set(days_label(vault.archive_purge_days(app.vault)))
            return
        vault.set_archive_purge_days(app.vault, days)
        purged = vault.auto_purge_archive(app.vault)
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
        setting_row(exp, "Encrypted backup",
                    "Stays protected by your master password, so it is safe "
                    "on a USB stick or in cloud storage.", hint, first=True),
        "Save backup…", lambda: _backup_encrypted(app), width=150).pack()
    app._ghost_button(
        setting_row(exp, "Plain export",
                    "Readable by anyone who opens the file.", hint),
        "Export…", lambda: _export_plaintext(app), width=150,
        danger=True).pack()

    # ---- danger zone ----
    danger = section(wrap, "Danger zone", danger=True)
    danger_button(
        setting_row(danger, "Delete this user",
                    f"Permanently deletes the vault for "
                    f"“{app.current_user}” on this PC.", hint, first=True),
        "Delete…", lambda: _delete_user_flow(app, top), width=150).pack()
    ctk.CTkFrame(wrap, height=8, fg_color="transparent").pack()

    ctk.CTkLabel(shell.buttons, text=long_version_string(), font=F(11),
                 text_color=MUTED).pack(side="left")
    app._ghost_button(shell.buttons, "Close", top.destroy,
                      width=120).pack(side="right")
    top.bind("<Escape>", lambda e: top.destroy())


def _backup_encrypted(app):
    path = filedialog.asksaveasfilename(
        parent=app.root, title="Save encrypted backup",
        defaultextension=".vault.enc",
        initialfile=f"{app.current_user}-backup.vault.enc",
        filetypes=[("Encrypted vault", "*.enc"), ("All files", "*.*")])
    if not path:
        return
    try:
        # Save first so the backup includes anything not yet written.
        if not app._save():
            return
        export_encrypted(app.current_user, path)
    except Exception as e:
        app.toast(f"Backup failed: {e}", "error")
        return
    app.toast("Encrypted backup saved")


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
        count = writer(app.vault, path)
    except Exception as e:
        app.toast(f"Export failed: {e}", "error")
        return
    app.toast(f"Exported {count} account(s) in plain text", "warn")


def _change_master_dialog(app, parent_top):
    top = app._modal("Change master password", 460, 560)
    shell = dialog_shell(top, "Change master password",
                         "The vault is re-encrypted immediately. The new "
                         "password cannot be recovered if forgotten.")
    wrap = shell.body

    cur_entry = app._field(wrap, "Current master password", show="•")
    new_entry = app._field(wrap, "New master password", show="•")
    bar, label, update_strength = app._strength_widget(wrap)
    confirm_entry = app._field(wrap, "Confirm new password", show="•")
    new_entry.bind("<KeyRelease>", lambda e: update_strength(new_entry.get()))

    syncing = sync_client.is_configured(app.vault)
    drop = None
    if syncing:
        note(wrap, "This vault syncs. Your server is updated straight away, "
             "and your other PCs ask for the new password on their next "
             "sync.", shell.text_width, pady=(14, 0))
        # Checked by default: a master password is usually changed because
        # the old one may be exposed, and these copies still open with it.
        drop = check(wrap, "Also delete the older copies on the server — "
                     "they still open with the old password",
                     shell.text_width, checked=True)

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
        old = app.master_password

        # The generation is stored inside the vault, so it is bumped before
        # the save that writes it. Other PCs compare it with the server's to
        # tell "the server is ahead" from "the server is behind".
        generation = sync_client.key_generation(app.vault)
        if syncing:
            sync_client.note_password_change(app.vault)
        try:
            # Re-encrypts the vault, its .bak and the sync base together.
            # The base matters: dropping it would turn the next sync into a
            # merge with no common ancestor and a wall of needless conflicts.
            change_master_password(app.vault, app.current_user, old, new)
        except Exception:
            if syncing:
                sync_client.set_key_generation(app.vault, generation)
            err.configure(text="Could not save the vault. Password unchanged.")
            return
        app.master_password = new
        top.destroy()
        parent_top.destroy()

        if not syncing:
            return app.toast("Master password changed")
        app.toast("Master password changed — updating the server…")
        # The old password is handed over rather than asked for again: it is
        # what the server's copy is still under.
        app.sync_now(
            server_password=old, drop_history=bool(drop.get()),
            offline_hint="Master password changed. The server could not be "
                         "reached — the next Sync will ask for your previous "
                         "password once to update it.")

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
    top = app._modal("Delete user", 440, 300)
    shell = dialog_shell(top, f"Delete “{app.current_user}”",
                         "Re-enter your master password to confirm. This "
                         "deletes the vault file permanently.", danger=True)
    pw = app._field(shell.body, "Master password", show="•")
    err = error_label(shell.body, shell.text_width)

    def do_delete():
        if not password_matches(pw.get(), app.master_password):
            err.configure(text="Incorrect master password."); return
        try:
            delete_user(app.current_user, app.master_password)
        except Exception as e:
            err.configure(text=str(e)); return
        top.destroy(); parent_top.destroy()
        app.vault = app.master_password = app.current_user = None
        app.show_login_screen()
        app.toast("User deleted")

    app._ghost_button(shell.buttons, "Cancel", top.destroy,
                      width=110).pack(side="left")
    danger_button(shell.buttons, "Delete", do_delete,
                  width=120).pack(side="right")
    pw.bind("<Return>", lambda e: do_delete())
    pw.focus()
