"""
Sharing a vault and reading its record of changes (phase 4).

Two windows, both opened from the Vaults window:

- **Members**: who is in a vault and what they may do. An owner adds a
  person (after comparing fingerprints with them), changes a role, removes
  someone -- which gives the vault a new key in the same step -- or changes
  the key on its own.
- **Activity**: the vault's change log (changelog.py) -- who added, changed,
  archived or deleted what, and when. Every member can read it. Owners can
  also read what the server noted (uploads, members, logins are not here).

Nothing here records who looked at an entry or copied a password.

The same rules as the other screens: the network runs on a worker thread,
widgets are touched only on the main one.
"""

import customtkinter as ctk

import account_sync
import accounts
import changelog
from history_ui import local_time
from sync_ui import _in_background
from theme import (F, TEXT, MUTED, CARD, BORDER, WARN, DANGER, GREEN, MONO,
                   tile_colors)
from widgets import (dialog_shell, ghost_button, accent_button, small_button,
                     field, error_label, note, option_menu, Tooltip, avatar)

ROLE_LABELS = {accounts.ROLE_OWNER: "Owner", accounts.ROLE_EDITOR: "Editor",
               accounts.ROLE_READER: "Reader"}
ROLE_NOTES = {
    accounts.ROLE_OWNER: "reads, changes, and manages the members",
    accounts.ROLE_EDITOR: "reads and changes entries",
    accounts.ROLE_READER: "reads entries, changes nothing",
}

#: Lines the Activity window shows (the newest).
ACTIVITY_SHOWN = 200


def role_label(role: str) -> str:
    return ROLE_LABELS.get(role, role or "Member")


def _role_from(label: str) -> str:
    return next((r for r, text in ROLE_LABELS.items() if text == label),
                accounts.ROLE_READER)


def can_share(app, vault_id) -> str:
    """Why this vault cannot be shared right now, or "" when it can."""
    account = app.account
    if vault_id == account.personal_id:
        return "The Personal vault is yours alone. Make another vault to share."
    if not account.server:
        return "Put the account on a server first (Settings → Sync)."
    record = account.vault_record(vault_id)
    if record.get("gone_from_server"):
        return "This vault is no longer on the server."
    if not record.get("on_server"):
        return "Press Sync once, so the vault is on the server."
    return ""


def _with_server(app, work, done, failed):
    """Run ``work(server)`` logged in, off the main thread."""
    account = app.account

    def run():
        server = account_sync.logged_in(account)
        try:
            if not server.has_sharing() or not server.has_signed_keys():
                raise account_sync.SyncError(
                    "This server cannot share vaults yet: it needs SecretSpace "
                    "Server 2.0.0 or newer.")
            return work(server)
        finally:
            server.logout()

    def if_open(callback):
        return lambda value: callback(value) if app.account is account else None

    _in_background(app, run, if_open(done), on_error=if_open(failed))


# ==========================================================================
# Members
# ==========================================================================
def members_dialog(app, vault_id, changed=None):
    account = app.account
    name = app.vault_name(vault_id)
    owner = account.vault_role(vault_id) == accounts.ROLE_OWNER
    top = app._modal(f"Members of “{name}”", 620, 680)
    tile_bg, tile_ink, band = tile_colors(name)
    shell = dialog_shell(
        top, f"Members of “{name}”",
        "Everyone here can open this vault. Owners manage the members; "
        "editors change entries; readers only read." if owner else
        f"You are {_a(role_label(account.vault_role(vault_id)).lower())} of "
        "this vault. Its owners manage the members.", scroll=True,
        tile=(name[:1].upper() or "?", tile_bg, tile_ink), band=band)
    listing = shell.body
    listing.grid_columnconfigure(0, weight=1)
    state = {"members": [], "busy": False}

    def status(text, colour=MUTED):
        if top.winfo_exists():
            status_label.configure(text=text, text_color=colour)

    def failed(error):
        state["busy"] = False
        status(str(error), DANGER)

    def show(members):
        state["members"], state["busy"] = members, False
        if not top.winfo_exists():
            return
        for child in listing.winfo_children():
            child.destroy()
        fp = ctk.CTkFrame(listing, fg_color=CARD, corner_radius=14)
        fp.grid(row=0, column=0, sticky="ew", padx=2, pady=(10, 4))
        fp.grid_columnconfigure(0, weight=1)
        words = ctk.CTkFrame(fp, fg_color="transparent")
        words.grid(row=0, column=0, sticky="w", padx=(16, 8), pady=(10, 0))
        ctk.CTkLabel(words, text="Your fingerprint", font=F(12),
                     text_color=MUTED).pack(anchor="w")
        ctk.CTkLabel(words, text=account.fingerprint,
                     font=ctk.CTkFont(family=MONO, size=15),
                     text_color=TEXT).pack(anchor="w")

        def copy_fingerprint():
            # The app's own copy: the clipboard differs per system.
            app._copy(account.fingerprint, "Fingerprint copied")

        small_button(fp, "Copy", copy_fingerprint, width=70).grid(
            row=0, column=1, padx=(0, 14), pady=(10, 0))
        ctk.CTkLabel(fp, text="Read it to someone who is about to share a "
                     "vault with you, so they know the key is yours.",
                     font=F(11), text_color=MUTED,
                     wraplength=shell.text_width - 40,
                     justify="left").grid(row=1, column=0, columnspan=2,
                                          sticky="w", padx=16, pady=(2, 10))
        for i, member in enumerate(members, start=1):
            _member_row(listing, i, member)
        status(f"{len(members)} member{'s' if len(members) != 1 else ''}")
        if changed:
            changed()

    def reload():
        state["busy"] = True
        status("Asking the server…")
        _with_server(app, lambda server: account_sync.list_members(
            account, server, vault_id), show, failed)

    def busy():
        if state["busy"] or getattr(app, "_syncing", False):
            status("Wait for the current step to finish.", WARN)
            return True
        return False

    def run(work, message):
        """A change on the server, then the list again."""
        if busy():
            return
        state["busy"] = True
        status(message)

        def both(server):
            outcome = work(server)
            return outcome, account_sync.list_members(account, server, vault_id)

        def done(payload):
            outcome, members = payload
            if isinstance(outcome, dict) and "accounts" in outcome:
                # The vault as it is after a key change (synced first).
                app.set_vault_data(vault_id, outcome, saved=True)
                app.refresh_account_list()
            show(members)

        _with_server(app, both, done, failed)

    def _member_row(parent, index, member):
        row = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=14)
        row.grid(row=index, column=0, sticky="ew", padx=2, pady=4)
        row.grid_columnconfigure(1, weight=1)
        avatar(row, member["username"]).grid(row=0, column=0, padx=(14, 0),
                                             pady=12)
        info = ctk.CTkFrame(row, fg_color="transparent")
        info.grid(row=0, column=1, sticky="w", padx=(12, 8), pady=10)
        who = member["username"] + ("  (you)" if member["me"] else "")
        ctk.CTkLabel(info, text=who, anchor="w", font=F(14, "bold"),
                     text_color=TEXT).pack(anchor="w")
        if member["me"]:
            detail, colour = role_label(member["role"]), MUTED
        elif member["verified"]:
            detail, colour = (role_label(member["role"]) +
                              "  ·  fingerprint checked on this PC"), MUTED
        else:
            detail, colour = (role_label(member["role"]) +
                              "  ·  fingerprint not checked on this PC"), WARN
        ctk.CTkLabel(info, text=detail, anchor="w", font=F(12),
                     text_color=colour).pack(anchor="w")
        # (An empty frame would take its default 200 x 200: none for a row
        # without buttons.)
        if member["me"] or (member["verified"] and not owner):
            return
        buttons = ctk.CTkFrame(row, fg_color="transparent")
        buttons.grid(row=0, column=2, padx=(0, 14))
        who = member["username"]
        if not member["verified"]:
            check = small_button(buttons, "Check", lambda: check_person(who),
                                 width=70)
            check.pack(side="left", padx=(0, 6))
            Tooltip(check, "Compare this person's fingerprint with them")
        if not owner:
            return
        menu = option_menu(buttons, list(ROLE_LABELS.values()),
                           lambda label: set_role(who, _role_from(label)),
                           width=104)
        menu.set(role_label(member["role"]))
        menu.pack(side="left", padx=(0, 6))
        small_button(buttons, "Remove", lambda: remove(who), danger=True,
                     width=80).pack(side="left")

    def set_role(who, role):
        run(lambda server: server.put_member(vault_id, who, role),
            f"Changing what {who} may do…")

    def unchecked(leaving=None):
        """A paragraph naming the members who stay and whose keys were never
        compared on this PC: the new key goes to whatever key the server
        gives for them."""
        names = [m["username"] for m in state["members"]
                 if not m["me"] and not m["verified"]
                 and m["username"] != leaving]
        if not names:
            return ""
        return ("\n\nNot checked on this PC: " + ", ".join(names) + ". The "
                "new key goes to the keys the server gives for them. Compare "
                "fingerprints first (Check) if you can.")

    def remove(who):
        if not app._confirm(
                f"Remove {who}",
                f"Remove {who} from “{name}”?\n\n"
                "The vault gets a new key in the same step, so they can open "
                "nothing that is written from now on. What they have already "
                "seen they may have kept: change those passwords if it "
                "matters.\n\nThe vault is synced first." + unchecked(who)):
            return
        run(lambda server: account_sync.change_key(
            account, server, vault_id, app.vaults[vault_id], remove=[who]),
            f"Removing {who} and changing the key…")

    def change_key():
        if not app._confirm(
                "Change the vault's key",
                f"Give “{name}” a new key?\n\nEvery member gets it with their "
                "next sync. Worth doing after someone left the vault, or if a "
                "device that had it was lost. The vault is synced first."
                + unchecked(), danger=False):
            return
        run(lambda server: account_sync.change_key(
            account, server, vault_id, app.vaults[vault_id]),
            "Changing the key…")

    def check_person(who):
        if busy():
            return

        def looked_up(keys):
            if _fingerprint_dialog(app, keys, sharing=False):
                account_sync.trust_contact(account, keys, True)
                reload()
            else:
                status("")

        status(f"Asking the server for {who}'s keys…")
        _with_server(app, lambda server: account_sync.lookup_contact(
            account, server, who), looked_up, failed)

    def add():
        if busy():
            return
        if _add_member_dialog(app, vault_id, name):
            reload()

    status_label = ctk.CTkLabel(shell.buttons, text="", font=F(12),
                                text_color=MUTED, anchor="w", justify="left",
                                wraplength=230)
    ghost_button(shell.buttons, "Close", top.destroy, width=100).pack(side="left")
    status_label.pack(side="left", padx=(12, 0))
    if owner:
        accent_button(shell.buttons, "Add a person…", add,
                      width=140).pack(side="right")
        rekey = ghost_button(shell.buttons, "Change key", change_key, width=110)
        rekey.pack(side="right", padx=(0, 8))
        Tooltip(rekey, "Give the vault a new key without removing anyone")
    top.bind("<Escape>", lambda e: top.destroy())
    reload()


def _a(word: str) -> str:
    return ("an " if word[:1] in "aeiou" else "a ") + word


def _add_member_dialog(app, vault_id, vault_name) -> bool:
    """Ask who and as what, look them up, compare fingerprints, share.
    True when someone was added."""
    account = app.account
    top = app._modal("Add a person", 500, 420)
    shell = dialog_shell(
        top, f"Share “{vault_name}”",
        "With someone who has an account on the same server. They get the "
        "vault with their next sync.")
    who = field(shell.body, "Their username", placeholder="e.g. user1")
    ctk.CTkLabel(shell.body, text="They can", anchor="w", font=F(12, "bold"),
                 text_color=MUTED).pack(anchor="w", pady=(14, 6))
    choices = {f"{ROLE_LABELS[r]} — {ROLE_NOTES[r]}": r
               for r in (accounts.ROLE_EDITOR, accounts.ROLE_READER,
                         accounts.ROLE_OWNER)}
    role = {"value": accounts.ROLE_EDITOR}
    menu = option_menu(shell.body, list(choices),
                       lambda label: role.update(value=choices[label]),
                       width=shell.text_width)
    menu.pack(anchor="w")
    err = error_label(shell.body, shell.text_width)
    outcome = {"added": False, "busy": False}

    def failed(error):
        outcome["busy"] = False
        if top.winfo_exists():
            err.configure(text=str(error), text_color=DANGER)

    def go():
        name = who.get().strip()
        if not name:
            return err.configure(text="Enter their username.", text_color=DANGER)
        if outcome["busy"]:
            return
        outcome["busy"] = True
        err.configure(text="Asking the server…", text_color=MUTED)

        def looked_up(keys):
            outcome["busy"] = False
            if not top.winfo_exists():
                return
            err.configure(text="")
            if not _fingerprint_dialog(app, keys, sharing=True):
                return
            outcome["busy"] = True
            err.configure(text="Sharing…", text_color=MUTED)

            def shared(_):
                outcome["added"] = True
                app.toast(f"“{vault_name}” is now shared with {keys['username']}")
                if top.winfo_exists():
                    top.destroy()

            _with_server(app, lambda server: account_sync.share_vault(
                account, server, vault_id, keys, role["value"]), shared, failed)

        _with_server(app, lambda server: account_sync.lookup_contact(
            account, server, name), looked_up, failed)

    ghost_button(shell.buttons, "Cancel", top.destroy, width=110).pack(side="left")
    accent_button(shell.buttons, "Continue", go, width=140).pack(side="right")
    who.bind("<Return>", lambda e: go())
    top.bind("<Escape>", lambda e: top.destroy())
    top.after(200, who.focus)
    app._fit_modal(top)
    app.root.wait_window(top)
    return outcome["added"]


def _fingerprint_dialog(app, keys, sharing) -> bool:
    """
    The one check that keeps a dishonest server out: the person reads their
    fingerprint (Vaults → Members on their device) and it must be the one
    shown here. True when the user says it matches.
    """
    who = keys["username"]
    changed = keys["status"] == "changed"
    title = f"Is this {who}?"
    top = app._modal(title, 520, 460)
    shell = dialog_shell(
        top, title,
        f"Ask {who} to open Vaults → Members in their SecretSpace and read "
        "you the fingerprint shown at the top — in person or on the phone, "
        "not by a message through this server.", danger=changed)
    if changed:
        note(shell.body,
             f"Warning: the server now gives DIFFERENT keys for {who} than "
             "this PC has seen before. That happens when an account was "
             "deleted and made again — or when someone is pretending to be "
             f"{who}. Go on only if {who} confirms the fingerprint below.",
             shell.text_width, color=DANGER, pady=(12, 0))
    ctk.CTkLabel(shell.body, text=f"{who}'s fingerprint must be",
                 font=F(12, "bold"), text_color=MUTED).pack(anchor="w",
                                                            pady=(16, 4))
    ctk.CTkLabel(shell.body, text=keys["fingerprint"],
                 font=ctk.CTkFont(family=MONO, size=20, weight="bold"),
                 text_color=GREEN).pack(anchor="w")
    note(shell.body,
         "If it is different, stop: the vault's key would go to someone "
         "else." if sharing else
         "If it is different, do not trust changes shown under this name.",
         shell.text_width, size=11, pady=(10, 0))
    outcome = {"ok": False}

    def yes():
        outcome["ok"] = True
        top.destroy()

    ghost_button(shell.buttons, "It is different", top.destroy,
                 width=140).pack(side="left")
    accent_button(shell.buttons,
                  "It matches — share" if sharing else "It matches", yes,
                  width=170).pack(side="right")
    top.bind("<Escape>", lambda e: top.destroy())
    app._fit_modal(top)
    app.root.wait_window(top)
    return outcome["ok"]


# ==========================================================================
# Activity
# ==========================================================================
def activity_rows(account, vault_id, data) -> list:
    """
    The vault's log for the screen, newest first: (when, who, what, state)
    with state one of changelog.OK / BAD / UNKNOWN.
    """
    rows = []
    for line in reversed(changelog.lines_of(data)[-ACTIVITY_SHOWN:]):
        state = changelog.check(line, vault_id,
                                account.signing_key_for(line["by"]))
        rows.append((line["at"], line["by"], changelog.describe(line), state))
    return rows


def activity_dialog(app, vault_id):
    account = app.account
    name = app.vault_name(vault_id)
    top = app._modal(f"Activity in “{name}”", 660, 640)
    shell = dialog_shell(
        top, f"Activity in “{name}”",
        "Who changed what, newest first. Values are never recorded, and "
        "neither is who looked at an entry or copied a password.",
        scroll=True)
    listing = shell.body
    listing.grid_columnconfigure(1, weight=1)

    def rebuild():
        for child in listing.winfo_children():
            child.destroy()
        rows = activity_rows(account, vault_id, app.vaults.get(vault_id, {}))
        if not rows:
            ctk.CTkLabel(listing, text="Nothing yet. Changes made from this "
                         "version on are listed here.", font=F(13),
                         text_color=MUTED).grid(row=0, column=0, columnspan=2,
                                                pady=60)
        unknown = set()
        for i, (when, who, what, state) in enumerate(rows):
            ctk.CTkLabel(listing, text=local_time(when), width=140, anchor="w",
                         font=F(12), text_color=MUTED).grid(
                row=i, column=0, sticky="nw", padx=(8, 8), pady=4)
            text, colour = f"{who} {what}", TEXT
            if state == changelog.BAD:
                text += "\n⚠ The signature does not match " \
                        f"{who}'s key: this line may not be theirs."
                colour = DANGER
            elif state == changelog.UNKNOWN:
                text += f"\n(not checked: this PC has not seen {who}'s key)"
                colour = WARN
                unknown.add(who)
            ctk.CTkLabel(listing, text=text, anchor="w", justify="left",
                         wraplength=440, font=F(13), text_color=colour).grid(
                row=i, column=1, sticky="w", pady=4)
        check.configure(state="normal" if unknown and account.server
                        else "disabled")
        return unknown

    def fetch_keys():
        names = sorted(rebuild())
        if not names:
            return

        def work(server):
            for who in names:
                try:
                    keys = account_sync.lookup_contact(account, server, who)
                except account_sync.SyncError:
                    continue            # no such account any more
                if keys["status"] == "new":
                    account_sync.trust_contact(account, keys, False)

        _with_server(app, work, lambda _: top.winfo_exists() and rebuild(),
                     lambda e: app.toast(str(e), "error"))

    ghost_button(shell.buttons, "Close", top.destroy, width=110).pack(side="left")
    check = ghost_button(shell.buttons, "Check signatures", fetch_keys, width=150)
    check.pack(side="right")
    Tooltip(check, "Fetch the keys of people this PC has not met, to check "
                   "their lines")
    if account.vault_role(vault_id) == accounts.ROLE_OWNER \
            and not can_share(app, vault_id):
        server_log = ghost_button(shell.buttons, "Server log…",
                                  lambda: server_log_dialog(app, vault_id),
                                  width=120)
        server_log.pack(side="right", padx=(0, 8))
        Tooltip(server_log, "What the server noted: uploads, members, key "
                            "changes (owners only)")
    top.bind("<Escape>", lambda e: top.destroy())
    rebuild()


_SERVER_EVENTS = {
    "vault_created": "made the vault",
    "vault_renamed": "renamed the vault",
    "vault_deleted": "deleted the vault",
    "member_left": "left the vault",
}


def describe_server_line(line: dict) -> str:
    """One line of the server's log as a sentence without its author."""
    event = line.get("event", "")
    if event == "upload":
        return f"uploaded changes (revision {line.get('revision', '?')})"
    if event == "member_added":
        return (f"added {line.get('member', '?')} as "
                f"{role_label(line.get('role', '')).lower()}")
    if event == "member_role":
        return (f"made {line.get('member', '?')} "
                f"{_a(role_label(line.get('role', '')).lower())}")
    if event == "key_changed":
        gone = [str(n) for n in line.get("removed") or []]
        return ("changed the vault's key" +
                (" and removed " + ", ".join(gone) if gone else ""))
    return _SERVER_EVENTS.get(event, event or "did something")


def server_log_dialog(app, vault_id):
    name = app.vault_name(vault_id)
    top = app._modal(f"Server log of “{name}”", 660, 600)
    shell = dialog_shell(
        top, f"Server log of “{name}”",
        "What the server noted about this vault, newest first, with the "
        "address each request came from. The server cannot see inside the "
        "vault: which entry changed is in Activity.", scroll=True)
    listing = shell.body
    listing.grid_columnconfigure(1, weight=1)
    waiting = ctk.CTkLabel(listing, text="Asking the server…", font=F(13),
                           text_color=MUTED)
    waiting.grid(row=0, column=0, columnspan=2, pady=60)

    def show(lines):
        if not top.winfo_exists():
            return
        waiting.destroy()
        for i, line in enumerate(reversed(lines)):
            ctk.CTkLabel(listing, text=local_time(str(line.get("at", ""))),
                         width=140, anchor="w", font=F(12),
                         text_color=MUTED).grid(row=i, column=0, sticky="nw",
                                                padx=(8, 8), pady=4)
            text = f"{line.get('by', '?')} {describe_server_line(line)}"
            if line.get("address"):
                text += f"   ·   from {line['address']}"
            ctk.CTkLabel(listing, text=text, anchor="w", justify="left",
                         wraplength=440, font=F(13), text_color=TEXT).grid(
                row=i, column=1, sticky="w", pady=4)

    def failed(error):
        if top.winfo_exists():
            waiting.configure(text=str(error), text_color=DANGER)

    ghost_button(shell.buttons, "Close", top.destroy, width=110).pack(side="right")
    top.bind("<Escape>", lambda e: top.destroy())
    _with_server(app, lambda server: server.vault_log(vault_id), show, failed)
