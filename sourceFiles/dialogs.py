"""
Modal dialogs.

Each function takes the running :class:`gui.PasswordManagerGUI` as ``app`` and
uses its helpers (``app._modal``, ``app.toast``, ``app._save`` ...). Splitting
them out keeps gui.py to the application shell: the login screen, the account
list and the session lifecycle.
"""

import os

import customtkinter as ctk
from tkinter import filedialog

import appconfig
import importers
import sync_client
from theme import (F, TEXT, MUTED, GREEN, GREEN_HOVER, DANGER, DANGER_HOVER,
                   INPUT_BG, BORDER, CARD_HOVER, ON_ACCENT, MONO)
from vault import (add_account, create_new_user, delete_user, get_vault_path,
                   validate_username, export_encrypted, export_csv,
                   export_json, update_entry, change_master_password,
                   find_duplicate)
from crypto_utils import decrypt
from password_generator import generate_password
from version import long_version_string


def create_user_dialog(app):
    top = app._modal("Create new user", 440, 560)
    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=30, pady=26)

    ctk.CTkLabel(wrap, text="Create new user", font=F(20, "bold"),
                 text_color=TEXT).pack(anchor="w")
    ctk.CTkLabel(wrap, text="Your master password encrypts the vault and "
                 "cannot be recovered.", font=F(12), text_color=MUTED,
                 wraplength=380, justify="left").pack(anchor="w", pady=(2, 6))

    user_entry = app._field(wrap, "Username", placeholder="e.g. alex")
    pw_entry = app._field(wrap, "Master password", show="•")
    confirm_entry = app._field(wrap, "Confirm password", show="•")

    bar, label, update_strength = app._strength_widget(wrap)
    pw_entry.bind("<KeyRelease>", lambda e: update_strength(pw_entry.get()))

    show = ctk.CTkSwitch(wrap, text="Show passwords", font=F(12),
                         text_color=MUTED, progress_color=GREEN)
    show.pack(anchor="w", pady=(10, 4))

    def toggle():
        s = "" if show.get() else "•"
        pw_entry.configure(show=s)
        confirm_entry.configure(show=s)
    show.configure(command=toggle)

    err = ctk.CTkLabel(wrap, text="", font=F(12), text_color=DANGER)
    err.pack(anchor="w", pady=(4, 0))

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

    row = ctk.CTkFrame(wrap, fg_color="transparent")
    row.pack(fill="x", side="bottom", pady=(14, 0))
    app._ghost_button(row, "Cancel", top.destroy, width=120).pack(side="left")
    app._accent_button(row, "Create user", create, width=150).pack(side="right")
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

    # Encrypted PassMan vault files (.vault / .vault.enc / .enc) must be
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

    top = app._modal("Unlock vault file", 430, 260)
    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=28, pady=24)
    ctk.CTkLabel(wrap, text="Unlock vault file", font=F(18, "bold"),
                 text_color=TEXT).pack(anchor="w")
    ctk.CTkLabel(wrap, text=f"“{os.path.basename(path)}” is encrypted. Enter "
                 "its master password to import the accounts inside.",
                 font=F(12), text_color=MUTED, wraplength=370,
                 justify="left").pack(anchor="w", pady=(4, 12))
    pw = ctk.CTkEntry(wrap, height=42, corner_radius=10, fg_color=INPUT_BG,
                      border_color=BORDER, show="•", font=F(14),
                      placeholder_text="Master password of the file")
    pw.pack(fill="x")
    err = ctk.CTkLabel(wrap, text="", font=F(12), text_color=DANGER)
    err.pack(anchor="w", pady=(6, 0))

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

    row = ctk.CTkFrame(wrap, fg_color="transparent")
    row.pack(fill="x", side="bottom", pady=(14, 0))
    app._ghost_button(row, "Cancel", top.destroy, width=110).pack(side="left")
    app._accent_button(row, "Unlock & import", unlock,
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
    for entry in candidates:
        key = (entry.site, entry.username, entry.password)
        if key in seen:
            dupes += 1
            continue
        seen.add(key)
        new_items.append(entry)
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
                ", which PassMan cannot store. Keep the original file "
                "until you have checked you still have them.")
    msg += "\n\nAdd them to your vault?"
    if not app._confirm("Import accounts", msg, danger=False):
        return

    for entry in new_items:
        add_account(app.vault, entry.site, entry.username, entry.password,
                    notes=entry.notes, totp=entry.totp)
    app._save()
    app.refresh_account_list()
    app.toast(f"Imported {len(new_items)} account(s)")


def account_dialog(app, acc):
    editing = acc is not None
    title = "Edit account" if editing else "Add account"
    subtitle = ("Update this login; changes are saved to your vault."
                if editing else "Store a new login in your vault.")

    top = app._modal(title, 460, 720)
    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=30, pady=26)

    ctk.CTkLabel(wrap, text=title, font=F(20, "bold"),
                 text_color=TEXT).pack(anchor="w")
    ctk.CTkLabel(wrap, text=subtitle, font=F(12),
                 text_color=MUTED).pack(anchor="w", pady=(2, 6))

    site_entry = app._field(wrap, "Website / App",
                             placeholder="e.g. GitHub")
    user_entry = app._field(wrap, "Username / Email",
                             placeholder="e.g. you@example.com")

    ctk.CTkLabel(wrap, text="Password", anchor="w", font=F(13, "bold"),
                 text_color=MUTED).pack(anchor="w", pady=(12, 4))
    pw_row = ctk.CTkFrame(wrap, fg_color="transparent")
    pw_row.pack(fill="x")
    pw_row.grid_columnconfigure(0, weight=1)
    pw_entry = ctk.CTkEntry(pw_row, height=42, corner_radius=10,
                            fg_color=INPUT_BG, border_color=BORDER,
                            show="•", font=F(14))
    pw_entry.grid(row=0, column=0, sticky="ew")
    show_btn = ctk.CTkButton(
        pw_row, text="Show", width=58, height=42, corner_radius=10,
        fg_color="transparent", border_width=1, border_color=BORDER,
        hover_color=CARD_HOVER, text_color=MUTED, font=F(12, "bold"))
    show_btn.grid(row=0, column=1, padx=(8, 8))
    gen_btn = ctk.CTkButton(
        pw_row, text="Generate", width=92, height=42, corner_radius=10,
        fg_color=GREEN, hover_color=GREEN_HOVER, text_color=ON_ACCENT,
        font=F(12, "bold"))
    gen_btn.grid(row=0, column=2)

    bar, label, update_strength = app._strength_widget(wrap)

    totp_entry = app._field(
        wrap, "TOTP secret (optional)",
        placeholder="stored for safekeeping — codes are not generated")

    ctk.CTkLabel(wrap, text="Notes (optional)", anchor="w",
                 font=F(13, "bold"), text_color=MUTED).pack(anchor="w",
                                                            pady=(12, 4))
    notes_box = ctk.CTkTextbox(wrap, height=70, corner_radius=10,
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

    if editing:
        site_entry.insert(0, acc["site"])
        user_entry.insert(0, acc["username"])
        pw_entry.insert(0, acc["password"])
        totp_entry.insert(0, acc.get("totp", ""))
        notes_box.insert("1.0", acc.get("notes", ""))
        update_strength(acc["password"])

    err = ctk.CTkLabel(wrap, text="", font=F(12), text_color=DANGER)
    err.pack(anchor="w", pady=(6, 0))

    def save():
        site = site_entry.get().strip()
        if not site:
            err.configure(text="Website / App is required."); return
        password = pw_entry.get()
        if not password:
            err.configure(text="Password is required."); return
        notes = notes_box.get("1.0", "end").strip()
        totp = totp_entry.get().strip()
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
                         password=password, notes=notes, totp=totp)
        else:
            add_account(app.vault, site, username,
                        password, notes=notes, totp=totp)
        app._save()
        top.destroy()
        app.refresh_account_list()
        app.toast("Account updated" if editing else "Account added")

    row = ctk.CTkFrame(wrap, fg_color="transparent")
    row.pack(fill="x", side="bottom", pady=(14, 0))
    app._ghost_button(row, "Cancel", top.destroy, width=120).pack(side="left")
    app._accent_button(row, "Save changes" if editing else "Save account",
                        save, width=150).pack(side="right")
    for e in (site_entry, user_entry, pw_entry, totp_entry):
        e.bind("<Return>", lambda ev: save())
    site_entry.focus()


def generator_dialog(app):
    top = app._modal("Password generator", 470, 480)
    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=30, pady=26)

    ctk.CTkLabel(wrap, text="Password generator", font=F(20, "bold"),
                 text_color=TEXT).pack(anchor="w")

    # result field
    result = ctk.CTkEntry(wrap, height=48, corner_radius=10, fg_color=INPUT_BG,
                          border_color=BORDER,
                          font=ctk.CTkFont(family=MONO, size=16))
    result.pack(fill="x", pady=(16, 10))

    bar, strength_label, update_strength = app._strength_widget(wrap)

    # length
    len_row = ctk.CTkFrame(wrap, fg_color="transparent")
    len_row.pack(fill="x", pady=(14, 2))
    len_val = ctk.CTkLabel(len_row, text="Length: 20", font=F(13, "bold"),
                           text_color=TEXT)
    len_val.pack(side="left")
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

    slider = ctk.CTkSlider(wrap, from_=6, to=64, number_of_steps=58,
                           variable=length, progress_color=GREEN,
                           button_color=GREEN, button_hover_color=GREEN_HOVER,
                           command=lambda v: (len_val.configure(
                               text=f"Length: {int(float(v))}"), regenerate()))
    slider.pack(fill="x", pady=(2, 12))

    checks = ctk.CTkFrame(wrap, fg_color="transparent")
    checks.pack(fill="x")
    for idx, (key, lab) in enumerate((("upper", "A-Z"), ("lower", "a-z"),
                                      ("digits", "0-9"), ("symbols", "!@#"))):
        ctk.CTkCheckBox(checks, text=lab, variable=opts[key], font=F(13),
                        text_color=TEXT, fg_color=GREEN,
                        hover_color=GREEN_HOVER, command=regenerate,
                        checkbox_width=22, checkbox_height=22
                        ).grid(row=0, column=idx, padx=(0, 18), pady=6)

    row = ctk.CTkFrame(wrap, fg_color="transparent")
    row.pack(fill="x", side="bottom", pady=(16, 0))
    app._ghost_button(row, "Regenerate", regenerate, width=130).pack(side="left")
    app._accent_button(
        row, "Copy", lambda: app._copy(result.get(), "Password copied",
                                        sensitive=True),
        width=150).pack(side="right")

    regenerate()


def settings_dialog(app):
    top = app._modal("Settings", 460, 620)
    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=30, pady=26)

    ctk.CTkLabel(wrap, text="Settings", font=F(20, "bold"),
                 text_color=TEXT).pack(anchor="w", pady=(0, 16))

    # ---- security ----
    ctk.CTkLabel(wrap, text="Security", font=F(13, "bold"),
                 text_color=MUTED).pack(anchor="w")
    sec = ctk.CTkFrame(wrap, fg_color="transparent", border_width=1,
                       border_color=BORDER, corner_radius=10)
    sec.pack(fill="x", pady=(6, 18))
    ctk.CTkLabel(sec, text="Re-encrypts your vault with a new master "
                 "password.", font=F(12), text_color=MUTED,
                 wraplength=340, justify="left").pack(anchor="w", padx=14,
                                                      pady=(12, 8))
    app._ghost_button(sec, "Change master password",
                       lambda: _change_master_dialog(app, top),
                       width=210).pack(anchor="w", padx=14, pady=(0, 12))

    lock_row = ctk.CTkFrame(sec, fg_color="transparent")
    lock_row.pack(fill="x", padx=14, pady=(0, 14))
    ctk.CTkLabel(lock_row, text="Lock after inactivity", font=F(12),
                 text_color=TEXT).pack(side="left")

    def label_for(m):
        return "Never" if m == 0 else f"{m} minute{'s' if m != 1 else ''}"

    def set_autolock(choice):
        for m in appconfig.AUTOLOCK_CHOICES:
            if label_for(m) == choice:
                appconfig.save_config(autolock_minutes=m)
                app._start_idle_timer()
                break

    ctk.CTkOptionMenu(
        lock_row, width=130, height=32, corner_radius=8,
        values=[label_for(m) for m in appconfig.AUTOLOCK_CHOICES],
        fg_color=INPUT_BG, button_color=BORDER, button_hover_color=CARD_HOVER,
        text_color=TEXT, font=F(12), command=set_autolock,
    ).pack(side="right")
    # reflect the stored value
    for child in lock_row.winfo_children():
        if isinstance(child, ctk.CTkOptionMenu):
            child.set(label_for(appconfig.autolock_minutes()))

    # ---- sync ----
    ctk.CTkLabel(wrap, text="Sync", font=F(13, "bold"),
                 text_color=MUTED).pack(anchor="w")
    syn = ctk.CTkFrame(wrap, fg_color="transparent", border_width=1,
                       border_color=BORDER, corner_radius=10)
    syn.pack(fill="x", pady=(6, 18))
    configured = sync_client.is_configured(app.vault)
    ctk.CTkLabel(
        syn,
        text=(f"Syncing with {sync_client.get_settings(app.vault)['url']}"
              if configured else
              "Keep this vault in step with another PC through your own "
              "server. The vault is encrypted before it is sent."),
        font=F(12), text_color=GREEN if configured else MUTED,
        wraplength=340, justify="left").pack(anchor="w", padx=14, pady=(12, 8))
    app._ghost_button(syn,
                      "Sync settings" if configured else "Set up sync",
                      lambda: (top.destroy(), app.sync_settings_dialog()),
                      width=210).pack(anchor="w", padx=14, pady=(0, 14))

    # ---- backup & export ----
    ctk.CTkLabel(wrap, text="Backup & export", font=F(13, "bold"),
                 text_color=MUTED).pack(anchor="w")
    exp = ctk.CTkFrame(wrap, fg_color="transparent", border_width=1,
                       border_color=BORDER, corner_radius=10)
    exp.pack(fill="x", pady=(6, 18))
    ctk.CTkLabel(exp, text="An encrypted backup stays protected by your "
                 "master password, so it is safe to keep on a USB stick "
                 "or in cloud storage.", font=F(12), text_color=MUTED,
                 wraplength=340, justify="left").pack(anchor="w", padx=14,
                                                      pady=(12, 8))
    app._ghost_button(exp, "Save encrypted backup",
                       lambda: _backup_encrypted(app), width=210
                       ).pack(anchor="w", padx=14, pady=(0, 10))
    ctk.CTkLabel(exp, text="A plain export is readable by anyone who "
                 "opens the file.", font=F(12), text_color=MUTED,
                 wraplength=340, justify="left").pack(anchor="w", padx=14,
                                                      pady=(0, 8))
    app._ghost_button(exp, "Export unencrypted…", lambda: _export_plaintext(app),
                       width=210, danger=True).pack(anchor="w", padx=14,
                                                    pady=(0, 14))

    # ---- danger zone ----
    ctk.CTkLabel(wrap, text="Danger zone", font=F(13, "bold"),
                 text_color=DANGER).pack(anchor="w")
    danger = ctk.CTkFrame(wrap, fg_color="transparent", border_width=1,
                          border_color=DANGER, corner_radius=10)
    danger.pack(fill="x", pady=(6, 0))
    ctk.CTkLabel(danger, text=f"Permanently delete the vault for "
                 f"“{app.current_user}”.", font=F(12),
                 text_color=MUTED, wraplength=340, justify="left"
                 ).pack(anchor="w", padx=14, pady=(12, 8))
    ctk.CTkButton(
        danger, text="Delete this user", height=38, corner_radius=10,
        fg_color=DANGER, hover_color=DANGER_HOVER, text_color="white",
        font=F(13, "bold"),
        command=lambda: _delete_user_flow(app, top)).pack(
        anchor="w", padx=14, pady=(0, 14))

    foot = ctk.CTkFrame(wrap, fg_color="transparent")
    foot.pack(fill="x", side="bottom", pady=(14, 0))
    ctk.CTkLabel(foot, text=long_version_string(), font=F(11),
                 text_color=MUTED).pack(side="left")
    app._ghost_button(foot, "Close", top.destroy, width=120).pack(side="right")


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
    top = app._modal("Change master password", 440, 540)
    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=30, pady=26)

    ctk.CTkLabel(wrap, text="Change master password", font=F(18, "bold"),
                 text_color=TEXT).pack(anchor="w")
    ctk.CTkLabel(wrap, text="The vault is re-encrypted immediately. The "
                 "new password cannot be recovered if forgotten.",
                 font=F(12), text_color=MUTED, wraplength=370,
                 justify="left").pack(anchor="w", pady=(2, 4))

    cur_entry = app._field(wrap, "Current master password", show="•")
    new_entry = app._field(wrap, "New master password", show="•")
    confirm_entry = app._field(wrap, "Confirm new password", show="•")

    bar, label, update_strength = app._strength_widget(wrap)
    new_entry.bind("<KeyRelease>", lambda e: update_strength(new_entry.get()))

    syncing = sync_client.is_configured(app.vault)
    drop = None
    if syncing:
        ctk.CTkLabel(wrap, text="This vault syncs. Your server is updated "
                     "straight away, and your other PCs ask for the new "
                     "password on their next sync.", font=F(12),
                     text_color=MUTED, wraplength=370,
                     justify="left").pack(anchor="w", pady=(10, 0))
        # Checked by default: a master password is usually changed because
        # the old one may be exposed, and these copies still open with it.
        drop = ctk.CTkCheckBox(
            wrap, text="Also delete the older copies on the server — they "
                       "still open with the old password",
            font=F(12), text_color=TEXT, fg_color=GREEN,
            hover_color=GREEN_HOVER)
        drop.select()
        drop.pack(anchor="w", pady=(8, 0))

    err = ctk.CTkLabel(wrap, text="", font=F(12), text_color=DANGER)
    err.pack(anchor="w", pady=(6, 0))

    def change():
        if cur_entry.get() != app.master_password:
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

    row = ctk.CTkFrame(wrap, fg_color="transparent")
    row.pack(fill="x", side="bottom", pady=(14, 0))
    app._ghost_button(row, "Cancel", top.destroy, width=110).pack(side="left")
    app._accent_button(row, "Change password", change,
                        width=170).pack(side="right")
    for e in (cur_entry, new_entry, confirm_entry):
        e.bind("<Return>", lambda ev: change())
    cur_entry.focus()


def _delete_user_flow(app, parent_top):
    top = app._modal("Delete user", 410, 270)
    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=28, pady=24)

    ctk.CTkLabel(wrap, text="Delete user", font=F(18, "bold"),
                 text_color=DANGER).pack(anchor="w")
    ctk.CTkLabel(wrap, text="Re-enter your master password to confirm. "
                 "This deletes the vault file permanently.", font=F(12),
                 text_color=MUTED, wraplength=350, justify="left"
                 ).pack(anchor="w", pady=(4, 12))

    pw = ctk.CTkEntry(wrap, height=42, corner_radius=10, fg_color=INPUT_BG,
                      border_color=BORDER, show="•", font=F(14),
                      placeholder_text="Master password")
    pw.pack(fill="x")
    err = ctk.CTkLabel(wrap, text="", font=F(12), text_color=DANGER)
    err.pack(anchor="w", pady=(6, 0))

    def do_delete():
        if pw.get() != app.master_password:
            err.configure(text="Incorrect master password."); return
        try:
            delete_user(app.current_user, app.master_password)
        except Exception as e:
            err.configure(text=str(e)); return
        top.destroy(); parent_top.destroy()
        app.vault = app.master_password = app.current_user = None
        app.show_login_screen()
        app.toast("User deleted")

    row = ctk.CTkFrame(wrap, fg_color="transparent")
    row.pack(fill="x", side="bottom", pady=(14, 0))
    app._ghost_button(row, "Cancel", top.destroy, width=110).pack(side="left")
    ctk.CTkButton(row, text="Delete", width=120, height=40, corner_radius=10,
                  fg_color=DANGER, hover_color=DANGER_HOVER, text_color="white",
                  font=F(13, "bold"), command=do_delete).pack(side="right")
    pw.bind("<Return>", lambda e: do_delete())
    pw.focus()
