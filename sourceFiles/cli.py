"""
SecretSpace on the command line: the same accounts and vaults as the app.

Rules it keeps:

* The master password is typed at a hidden prompt. It is never an argument,
  an environment variable or piped in, so nothing can unlock unattended.
* A secret is never an argument either (other users of a machine can see
  those, and the shell remembers them): it is typed at a hidden prompt,
  generated, or read from a pipe.
* A secret goes to a pipe or the clipboard; to the screen only with
  ``--print``.
* A change is written only while no other program has the account open
  (account_lock), and through the same functions as the app's.
"""

import argparse
import getpass
import json
import os
import sys
import time
import unicodedata
import warnings

import account_lock
import account_sync
import accounts
import appconfig
import changelog
import cli_agent
import cli_clipboard
import lockout
import mcp_server
import moves
import sync_client
import totp
import vault
import version
import weblink
from account_crypto import CryptoError
from password_generator import generate_password

PROGRAM = "secretspace-cli"
ACCOUNT_VARIABLE = "SECRETSPACE_ACCOUNT"
CLIPBOARD_SECONDS = 30
#: Exit codes: something went wrong, the command was not understood, a sync
#: left something for the app to decide.
FAILED, USAGE, UNDECIDED = 1, 2, 3
#: The fields `get` and `copy` know, and which of them are secret.
FIELDS = ("password", "username", "url", "notes", "name", "otp")
SECRET_FIELDS = ("password", "notes", "otp")


class Problem(Exception):
    """Told to the user as it is."""

    def __init__(self, text, code=FAILED):
        super().__init__(text)
        self.code = code


# ---------------------------------------------------------------------------
# The terminal
# ---------------------------------------------------------------------------
def printable(text) -> str:
    """For the screen: a name somebody else chose (a shared vault) must not
    be able to send the terminal commands."""
    return "".join("\N{REPLACEMENT CHARACTER}"
                   if unicodedata.category(c)[0] == "C" else c
                   for c in str(text))


class Terminal:
    """What a command reads and writes. Tests use their own."""

    def out(self, text=""):
        print(text)

    def err(self, text):
        print(text, file=sys.stderr)

    def raw(self, text):
        """A field, exactly, for the program at the other end of a pipe."""
        sys.stdout.flush()
        sys.stdout.buffer.write(text.encode("utf-8"))
        sys.stdout.buffer.flush()

    @property
    def shows_output(self):
        return sys.stdout is not None and sys.stdout.isatty()

    @property
    def piped_input(self):
        return sys.stdin is not None and not sys.stdin.isatty()

    def read_all(self):
        if not self.piped_input:
            raise Problem("There is nothing piped in.", USAGE)
        return sys.stdin.buffer.read()

    def ask_hidden(self, prompt):
        """Typed at the keyboard, also when the input is a pipe."""
        _need_keyboard()
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                return getpass.getpass(prompt)
            except getpass.GetPassWarning:
                raise Problem(_NO_KEYBOARD) from None
            except EOFError:
                raise Problem("Cancelled.") from None

    def ask(self, prompt):
        if self.piped_input:
            raise Problem("This needs an answer from the keyboard (or --yes).")
        try:
            # Not to stdout: that may be a pipe.
            sys.stderr.write(prompt)
            sys.stderr.flush()
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            raise Problem("Cancelled.") from None
        if not line:
            raise Problem("Cancelled.")
        return line.rstrip("\r\n")


_NO_KEYBOARD = ("There is no keyboard to type the master password at. It is "
                "never read from a pipe or a variable, so " + PROGRAM +
                " cannot run unattended.")


def _need_keyboard():
    """getpass would wait for ever without one, or echo what is typed."""
    if os.name != "nt":
        return                          # getpass itself opens /dev/tty
    if os.environ.get("MSYSTEM") and not sys.stdin.isatty():
        raise Problem("This window has no Windows console to type at. Use "
                      "PowerShell, cmd or Windows Terminal, or start it as "
                      "`winpty " + PROGRAM + " ...`.")
    try:
        with open("CONIN$", "r"):
            pass
    except OSError:
        raise Problem(_NO_KEYBOARD) from None
    if sys.stdin is not sys.__stdin__ or sys.stdin is None:
        raise Problem(_NO_KEYBOARD)


# ---------------------------------------------------------------------------
# The account
# ---------------------------------------------------------------------------
def pick_account(wanted) -> str:
    there = accounts.list_accounts()
    wanted = wanted or os.environ.get(ACCOUNT_VARIABLE)
    if wanted:
        for name in there:
            if name == wanted or name.lower() == wanted.lower():
                return name
        raise Problem(f"There is no account “{printable(wanted)}” on this "
                      "device.")
    if not there:
        raise Problem("There is no account on this device yet. Create one, "
                      "or sign in to one, in the SecretSpace app.")
    if len(there) == 1:
        return there[0]
    last = appconfig.load_config().get("last_username")
    if last in there:
        return last
    raise Problem("There are several accounts here; say which with "
                  "--account: " + ", ".join(there), USAGE)


def unlock_with_password(term, username):
    wait = lockout.remaining(username)
    if wait:
        raise Problem(f"Too many wrong passwords. Try again in {wait} s.")
    password = term.ask_hidden(f"Master password of {username}: ")
    if not password:
        raise Problem("Cancelled.")
    try:
        account = accounts.unlock(username, password)
    except accounts.NeedsConversion:
        raise Problem("This account is from SecretSpace 3. Open it in the app "
                      "once, which converts it.") from None
    except accounts.SecretKeyNeeded:
        raise Problem("This device does not have the account's Secret Key. "
                      "Open it in the app once; it asks for the Emergency "
                      "Kit.") from None
    except CryptoError as e:
        if not str(e).startswith("Wrong master password"):
            raise
        wait = lockout.record_failure(username)
        raise Problem("Wrong master password." + (
            f" Try again in {wait} s." if wait else "")) from None
    lockout.reset(username)
    return account


def open_account(term, args):
    """The account a command works in: from its session, else asked for."""
    username = pick_account(args.account)
    found = cli_agent.opened(username)
    if found:
        return found[0]
    return unlock_with_password(term, username)


class Vaults:
    """The vaults of an open account, read as they are now."""

    def __init__(self, account, term):
        self.account = account
        self.data, self._before = {}, {}
        for vault_id in account.vault_ids():
            file = account.vault_file(vault_id)
            try:
                self.data[vault_id] = file.load() if file.has_file \
                    else {"accounts": []}
            except (OSError, ValueError):
                term.err(f"The vault “{printable(file.name)}” could not be "
                         "read; sync to fetch it again.")
                continue
            self._before[vault_id] = json.dumps(self.data[vault_id],
                                                sort_keys=True)

    def name(self, vault_id) -> str:
        return self.account.vault_file(vault_id).name

    def by_name(self, name) -> str:
        found = [v for v in self.data if self.name(v).lower() == name.lower()]
        if not found:
            raise Problem(f"There is no vault “{printable(name)}”. There are: "
                          + ", ".join(printable(self.name(v))
                                      for v in self.data))
        return found[0]

    def need_write(self, vault_id):
        if self.account.needs_newer_app(vault_id):
            raise Problem(f"“{printable(self.name(vault_id))}” was changed by "
                          "a newer SecretSpace and is read-only here. Update "
                          "to " + self.account.newer_app_text(vault_id) +
                          " to change it.")
        if not self.account.can_write(vault_id):
            raise Problem(f"“{printable(self.name(vault_id))}” is shared with "
                          "you for reading only.")

    def entries(self, within=None, archived=False):
        for vault_id, data in self.data.items():
            if within in (None, vault_id):
                for entry in data["accounts"]:
                    if vault.is_archived(entry) == archived:
                        yield vault_id, entry

    def find(self, wanted, within=None, archived=False):
        """
        The one entry meant: by id (or its start), by name, or by a part of
        the name if only one has it. Never a guess.
        """
        pool = list(self.entries(within, archived))
        text = wanted.strip().casefold()
        if not text:
            raise Problem("Which entry?", USAGE)
        found = [x for x in pool if x[1]["id"] == wanted]
        found = found or [x for x in pool if x[1]["site"].casefold() == text]
        found = found or ([x for x in pool if x[1]["id"].startswith(text)]
                          if len(text) >= 4 else [])
        found = found or [x for x in pool if text in x[1]["site"].casefold()]
        if not found:
            raise Problem(f"There is no {'archived ' if archived else ''}entry "
                          f"“{printable(wanted)}”.")
        if len(found) > 1:
            raise Problem(
                f"“{printable(wanted)}” fits {len(found)} entries; say which "
                "by its id:\n" + "\n".join(self.line(*x) for x in found))
        return found[0]

    def line(self, vault_id, entry) -> str:
        parts = [entry["id"][:8], printable(entry["site"]),
                 printable(entry["username"])]
        if len(self.data) > 1:
            parts.append(f"[{printable(self.name(vault_id))}]")
        return "  ".join(p for p in parts if p)

    def save(self):
        """Every vault that changed, with who changed what, as the app."""
        for vault_id, data in self.data.items():
            if json.dumps(data, sort_keys=True) == self._before[vault_id]:
                continue
            self.need_write(vault_id)
            file = self.account.vault_file(vault_id)
            try:
                before = file.load() if file.has_file else {"accounts": []}
                changelog.record(data, before, self.account.username,
                                 self.account.keyset, file.hex, file.fmt)
            except Exception:
                pass          # a log line is worth less than the change
            file.save(data)
            self._before[vault_id] = json.dumps(data, sort_keys=True)

    def settle_moves(self) -> list:
        arrived = moves.arrived_in(self.account, self.data)
        changed = [v for v, data in self.data.items()
                   if self.account.can_write(v) and moves.settle(data, arrived)]
        if changed:
            self.save()
        return changed


def hold(username):
    try:
        return account_lock.take(username, wait=3)
    except account_lock.Busy:
        raise Problem("The account is in use: open in the SecretSpace app, or "
                      "another command is running. Lock it there first, then "
                      "try again. (Reading works meanwhile.)") from None


def confirm(term, args, question):
    if not args.yes and term.ask(question + " [y/N] ").strip().lower() \
            not in ("y", "yes"):
        raise Problem("Nothing was changed.")


# ---------------------------------------------------------------------------
# Commands: the session
# ---------------------------------------------------------------------------
def cmd_accounts(term, args):
    for name in accounts.list_accounts():
        term.out(name + ("  (unlocked)" if cli_agent.opened(name) else ""))


def cmd_unlock(term, args):
    if not 1 <= args.minutes <= cli_agent.MAX_MINUTES:
        raise Problem(f"--minutes is 1 to {cli_agent.MAX_MINUTES}.", USAGE)
    account = unlock_with_password(term, pick_account(args.account))
    cli_agent.start(account, args.minutes)
    term.out(f"{account.username} is unlocked for {args.minutes} min. "
             f"`{PROGRAM} lock` ends it.")


def cmd_lock(term, args):
    if args.account or os.environ.get(ACCOUNT_VARIABLE):
        names = [pick_account(args.account)]
    else:
        names = accounts.list_accounts()
    ended = [name for name in names if cli_agent.stop(name)]
    term.out("Locked: " + ", ".join(ended) if ended else "Nothing was unlocked.")


def cmd_status(term, args):
    username = pick_account(args.account)
    found = cli_agent.opened(username)
    if not found:
        term.out(f"{username}: locked")
        return
    left = max(0, int(found[1] - time.time()))
    term.out(f"{username}: unlocked for {left // 60} min {left % 60} s more")


# ---------------------------------------------------------------------------
# Commands: reading
# ---------------------------------------------------------------------------
def describe(vaults, vault_id, entry) -> dict:
    """An entry without its secrets."""
    out = {"id": entry["id"], "name": entry["site"],
           "username": entry["username"], "url": entry.get("url", ""),
           "vault": vaults.name(vault_id),
           "has_notes": bool(entry.get("notes")),
           "has_otp": bool(entry.get("totp")),
           "updated_at": entry.get("updated_at", "")}
    if vault.is_archived(entry):
        out["archived_at"] = entry["archived_at"]
    return out


def cmd_vaults(term, args):
    vaults = Vaults(open_account(term, args), term)
    for vault_id in vaults.data:
        n = len(list(vaults.entries(vault_id)))
        notes = [f"{n} entr{'y' if n == 1 else 'ies'}"]
        if vaults.account.is_shared(vault_id):
            notes.append("shared")
        if not vaults.account.can_write(vault_id):
            notes.append("read only")
        term.out(f"{printable(vaults.name(vault_id))}  ({', '.join(notes)})")


def cmd_list(term, args):
    vaults = Vaults(open_account(term, args), term)
    within = vaults.by_name(args.vault) if args.vault else None
    text = (args.text or "").casefold()
    found = [x for x in vaults.entries(within, args.archived)
             if text in x[1]["site"].casefold()
             or text in x[1]["username"].casefold()
             or text in x[1].get("url", "").casefold()]
    found.sort(key=lambda x: (x[1]["site"].casefold(),
                              x[1]["username"].casefold()))
    if args.json:
        term.out(json.dumps([describe(vaults, *x) for x in found], indent=2))
        return
    for item in found:
        term.out(vaults.line(*item))


def cmd_show(term, args):
    vaults = Vaults(open_account(term, args), term)
    within = vaults.by_name(args.vault) if args.vault else None
    info = describe(vaults, *vaults.find(args.entry, within, args.archived))
    if args.json:
        term.out(json.dumps(info, indent=2))
        return
    for label, value in (
            ("Name", info["name"]), ("Username", info["username"]),
            ("Web address", info["url"]), ("Vault", info["vault"]),
            ("Password", "(get or copy it)"),
            ("2FA", "(get or copy otp)" if info["has_otp"] else ""),
            ("Notes", "(get notes)" if info["has_notes"] else ""),
            ("Changed", info["updated_at"]),
            ("Archived", info.get("archived_at", "")), ("Id", info["id"])):
        if value:
            term.out(f"{label + ':':<13}{printable(value)}")


def field_of(entry, field) -> str:
    if field == "otp":
        if not entry.get("totp"):
            raise Problem("This entry has no 2FA secret.")
        try:
            return totp.code(totp.parse(entry["totp"]))
        except ValueError as e:
            raise Problem(f"The 2FA secret cannot be used: {e}") from None
    value = entry.get("site" if field == "name" else field, "")
    if not value:
        raise Problem(f"This entry has no {field}.")
    return value


def cmd_get(term, args):
    if args.field in SECRET_FIELDS and term.shows_output and not args.print:
        raise Problem(f"This would show the {args.field} on the screen. Pipe "
                      "it into a program, use copy, or add --print.", USAGE)
    vaults = Vaults(open_account(term, args), term)
    within = vaults.by_name(args.vault) if args.vault else None
    value = field_of(vaults.find(args.entry, within)[1], args.field)
    if term.shows_output:
        term.out("\n".join(printable(line) for line in value.split("\n")))
    else:
        term.raw(value)


def cmd_copy(term, args):
    vaults = Vaults(open_account(term, args), term)
    within = vaults.by_name(args.vault) if args.vault else None
    entry = vaults.find(args.entry, within)[1]
    value = field_of(entry, args.field)
    term.err(f"{args.field} of “{printable(entry['site'])}” copied; cleared "
             f"in {CLIPBOARD_SECONDS} s (Ctrl+C: now)")
    try:
        cli_clipboard.hold(value, CLIPBOARD_SECONDS)
    except cli_clipboard.NoClipboard as e:
        raise Problem(str(e)) from None


def cmd_generate(term, args):
    if not 6 <= args.length <= 128:
        raise Problem("The length is 6 to 128.", USAGE)
    password = generate_password(args.length, use_symbols=not args.no_symbols)
    if args.copy:
        term.err(f"Copied; cleared in {CLIPBOARD_SECONDS} s (Ctrl+C: now)")
        try:
            cli_clipboard.hold(password, CLIPBOARD_SECONDS)
        except cli_clipboard.NoClipboard as e:
            raise Problem(str(e)) from None
    elif term.shows_output:
        term.out(password)              # belongs to nothing yet
    else:
        term.raw(password)


# ---------------------------------------------------------------------------
# Commands: changing
# ---------------------------------------------------------------------------
def new_password(term, args) -> str:
    """From --generate, a pipe, or typed twice."""
    if args.generate is not None:
        if not 6 <= args.generate <= 128:
            raise Problem("The length is 6 to 128.", USAGE)
        return generate_password(args.generate)
    if args.password_stdin:
        try:
            text = term.read_all().decode("utf-8-sig")
        except UnicodeDecodeError:
            raise Problem("The piped password is not UTF-8 text.") from None
        if text.endswith("\n"):
            text = text[:-1].removesuffix("\r")
        if not text or "\n" in text or "\r" in text:
            raise Problem("A password is one line of text.")
        return text
    first = term.ask_hidden("Password of the entry: ")
    if not first:
        raise Problem("A password is needed. Nothing was changed.")
    if term.ask_hidden("Again: ") != first:
        raise Problem("The two are not the same. Nothing was changed.")
    return first


def new_totp(term) -> str:
    secret = term.ask_hidden("2FA secret or otpauth:// link: ").strip()
    problem = totp.check(secret) if secret else "nothing was typed"
    if problem:
        raise Problem("2FA secret: " + problem)
    return secret


def clean_url(text) -> str:
    url, problem = weblink.clean(text or "")
    if problem:
        raise Problem("Web address: " + problem)
    return url


def clean_name(text) -> str:
    text = text.strip()
    if not text:
        raise Problem("A name is needed.")
    return text


def check_twin(vaults, vault_id, args, site, username, except_id=None):
    twin = vault.find_duplicate(vaults.data[vault_id], site, username, except_id)
    if twin is not None and not args.allow_duplicate:
        raise Problem(f"There is already a login for “{printable(twin['site'])}”"
                      f" with the username “{printable(twin['username'])}” "
                      f"({twin['id'][:8]}). To keep both, add "
                      "--allow-duplicate.")


def cmd_add(term, args):
    name, url = clean_name(args.name), clean_url(args.url)
    account = open_account(term, args)
    vaults = Vaults(account, term)
    into = vaults.by_name(args.vault) if args.vault else account.personal_id
    if into not in vaults.data:
        raise Problem("That vault could not be read. Nothing was changed.")
    vaults.need_write(into)
    username = args.username.strip()
    check_twin(vaults, into, args, name, username)
    # Ask before the account is held: the app must not wait for a typist.
    password = new_password(term, args)
    secret = new_totp(term) if args.totp else ""
    with hold(account.username):
        vaults = fresh(term, account)
        target = vault_still_here(vaults, into)
        check_twin(vaults, into, args, name, username)
        entry = vault.add_account(target, name, username, password,
                                  notes=args.notes, totp=secret, url=url)
        vaults.save()
    term.out("Added  " + vaults.line(into, entry))


def fresh(term, account):
    """The vaults as they are now, for a change (the account is held)."""
    account.info = accounts._read_info(account.username)
    return Vaults(account, term)


def vault_still_here(vaults, vault_id) -> dict:
    if vault_id not in vaults.data:
        raise Problem("The vault is no longer here. Nothing was changed.")
    vaults.need_write(vault_id)
    return vaults.data[vault_id]


def cmd_edit(term, args):
    changes = {}
    if args.name is not None:
        changes["site"] = clean_name(args.name)
    if args.username is not None:
        changes["username"] = args.username.strip()
    if args.url is not None:
        changes["url"] = clean_url(args.url)
    if args.notes is not None:
        changes["notes"] = args.notes.strip()
    for field in args.clear or ():
        key = "totp" if field == "otp" else field
        if key in changes or key == "totp" and args.totp:
            raise Problem(f"--clear {field} and a new one?", USAGE)
        changes[key] = ""
    wants_password = args.password or args.password_stdin \
        or args.generate is not None
    if not (changes or wants_password or args.totp):
        raise Problem("What should be changed? See edit --help.", USAGE)
    account = open_account(term, args)
    vaults = Vaults(account, term)
    within = vaults.by_name(args.vault) if args.vault else None
    vault_id, entry = vaults.find(args.entry, within)
    vaults.need_write(vault_id)
    if wants_password:
        changes["password"] = new_password(term, args)
    if args.totp:
        changes["totp"] = new_totp(term)
    with hold(account.username):
        vaults = fresh(term, account)
        entry = entry_still_here(vaults, vault_id, entry["id"])
        if "site" in changes or "username" in changes:
            check_twin(vaults, vault_id, args,
                       changes.get("site", entry["site"]),
                       changes.get("username", entry["username"]), entry["id"])
        changed = vault.update_entry(entry, **changes)
        if changed:
            vaults.save()
    term.out(("Changed  " if changed else "Nothing to change in  ")
             + vaults.line(vault_id, entry))


def entry_still_here(vaults, vault_id, entry_id, archived=False) -> dict:
    data = vault_still_here(vaults, vault_id)
    entry = vault.find_entry(data, entry_id)
    if entry is None or vault.is_archived(entry) != archived:
        raise Problem("The entry was changed meanwhile. Nothing was changed "
                      "here; try again.")
    return entry


def one_entry(term, args, archived, change, done, question=None):
    """archive, restore and delete: find one, ask, change it, save."""
    account = open_account(term, args)
    vaults = Vaults(account, term)
    within = vaults.by_name(args.vault) if args.vault else None
    vault_id, entry = vaults.find(args.entry, within, archived)
    vaults.need_write(vault_id)
    if question:
        confirm(term, args, question.format(vaults.line(vault_id, entry)))
    with hold(account.username):
        vaults = fresh(term, account)
        entry = entry_still_here(vaults, vault_id, entry["id"], archived)
        line = vaults.line(vault_id, entry)
        change(vaults.data[vault_id], entry["id"])
        vaults.save()
    term.out(f"{done}  {line}")


def cmd_archive(term, args):
    one_entry(term, args, False, vault.archive_account, "Archived")


def cmd_restore(term, args):
    one_entry(term, args, True, vault.restore_account, "Restored")


def cmd_delete(term, args):
    one_entry(term, args, True, vault.purge_account, "Deleted",
              "Delete for good, with its earlier versions: {}\n"
              "This cannot be undone.")


def cmd_move(term, args):
    account = open_account(term, args)
    vaults = Vaults(account, term)
    within = vaults.by_name(args.vault) if args.vault else None
    home, entry = vaults.find(args.entry, within)
    into = vaults.by_name(args.to)
    if home == into:
        raise Problem(f"It is in “{printable(vaults.name(into))}” already.")
    vaults.need_write(home)
    vaults.need_write(into)
    question = f"Move “{printable(entry['site'])}” from " \
               f"“{printable(vaults.name(home))}” to " \
               f"“{printable(vaults.name(into))}”, with its earlier versions?"
    if account.is_shared(into):
        question += "\nEveryone in the new vault can then see it, earlier " \
                    "passwords included."
    if account.is_shared(home):
        question += "\nThe other people in the old vault lose it. Someone may " \
                    "have a copy: change the password if they should not have " \
                    "it any more."
    check_twin(vaults, into, args, entry["site"], entry["username"])
    confirm(term, args, question)
    with hold(account.username):
        vaults = fresh(term, account)
        entry = entry_still_here(vaults, home, entry["id"])
        target = vault_still_here(vaults, into)
        check_twin(vaults, into, args, entry["site"], entry["username"])
        moved = moves.move(vaults.data[home], target, entry["id"], into)
        # The copy first: stopped in between, the entry is there twice
        # rather than only in the Archive.
        vaults.data = {v: vaults.data[v] for v in
                       sorted(vaults.data, key=lambda v: v != into)}
        vaults.save()
        if not account.server:
            vaults.settle_moves()           # with one: after the next sync
    term.out("Moved  " + vaults.line(into, moved))
    if account.server:
        term.out("The original waits in the Archive until the next sync.")


# ---------------------------------------------------------------------------
# Commands: syncing
# ---------------------------------------------------------------------------
def sync_vault(vaults, server, vault_id) -> str:
    """One vault: "" (in step), "updated", or why not."""
    account = vaults.account
    for attempt in (1, 2):
        one = account_sync.AccountSync(account, server, vault_id)
        try:
            data = vaults.data[vault_id]
            result = one.prepare(data)
            if result.conflicts:
                return "undecided"
            if not one.has_work():
                return ""
            vaults.data[vault_id] = one.commit(data)
            vaults._before[vault_id] = json.dumps(vaults.data[vault_id],
                                                  sort_keys=True)
            return "updated"
        except sync_client.Conflict409:
            if attempt == 2:
                raise
            vaults.data[vault_id] = account.vault_file(vault_id).load()
        except account_sync.NeedsNewerApp as e:
            return str(e)
    return ""


def cmd_sync(term, args):
    account = open_account(term, args)
    if not account.server:
        raise Problem("This account is not on a server. Connect it in the "
                      "app: Settings, Sync.")
    if account.server_conversion_pending:
        raise Problem("This account was converted and its server has not been "
                      "told yet. Sync once in the app.")
    with hold(account.username):
        account.info = accounts._read_info(account.username)
        server = account_sync.logged_in(account)
        try:
            changes = account_sync.reconcile_vaults(account, server)
            vaults = Vaults(account, term)
            # One that cannot be read here is left alone: an empty stand-in
            # would look like every entry had been deleted.
            ids = [v for v in account_sync.syncable_vaults(account, server)
                   if v in vaults.data]
            said = {v: sync_vault(vaults, server, v) for v in ids}
            for vault_id in vaults.settle_moves():
                if vault_id in said and said[vault_id] in ("", "updated"):
                    said[vault_id] = sync_vault(vaults, server, vault_id)
        finally:
            server.logout()
    updated = [v for v in said if said[v] == "updated"]
    undecided = [v for v in said if said[v] == "undecided"]
    for name in changes.added:
        term.out(f"New from the server: {printable(name)}")
    for name in changes.gone:
        term.out(f"No longer on the server, kept here: {printable(name)}")
    for vault_id in updated:
        term.out(f"Updated: {printable(vaults.name(vault_id))}")
    for vault_id, text in said.items():
        if text not in ("", "updated", "undecided"):
            term.err(printable(text))
    if undecided:
        raise Problem("Changed here and on another device, so not synced: "
                      + ", ".join(printable(vaults.name(v)) for v in undecided)
                      + ". Press Sync in the app, which asks what to keep.",
                      UNDECIDED)
    if any(text not in ("", "updated") for text in said.values()):
        raise Problem("Not everything was synced.", UNDECIDED)
    if not (updated or changes):
        term.out("Already up to date.")


# ---------------------------------------------------------------------------
# For AI tools
# ---------------------------------------------------------------------------
def cmd_mcp(term, args):
    wanted = args.account or os.environ.get(ACCOUNT_VARIABLE)
    # Not pick_account: without a name, the one that is open in the app.
    mcp_server.serve(pick_account(wanted) if wanted else None)


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        prog=PROGRAM, allow_abbrev=False,
        description="SecretSpace on the command line. Without `unlock`, each "
                    "command asks for the master password.")
    parser.add_argument("--version", action="version",
                        version=f"SecretSpace {version.__version__}")
    # On every command as well, where most people put it.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--account", "-a", metavar="NAME", default=None,
                        help="the account (default: the only one, "
                             f"${ACCOUNT_VARIABLE}, or the last one used)")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    def command(name, run, text):
        p = commands.add_parser(name, help=text, description=text,
                                parents=[common], allow_abbrev=False)
        p.set_defaults(run=run)
        return p

    def entry(p, within=True):
        p.add_argument("entry", metavar="ENTRY",
                       help="its name, a part of it, or its id")
        if within:
            p.add_argument("--vault", "-v", metavar="VAULT",
                           help="look in this vault only")

    def password(p):
        g = p.add_mutually_exclusive_group()
        g.add_argument("--generate", "-g", nargs="?", const=20, type=int,
                       metavar="LENGTH", help="make a new password (20)")
        g.add_argument("--password-stdin", action="store_true",
                       help="read the password from a pipe")
        p.add_argument("--totp", action="store_true",
                       help="ask for a 2FA secret")
        p.add_argument("--allow-duplicate", action="store_true",
                       help="even if that login exists already")
        return g

    command("accounts", cmd_accounts, "the accounts on this device")
    p = command("unlock", cmd_unlock, "stay unlocked for a few minutes")
    p.add_argument("--minutes", "-m", type=int, metavar="N",
                   default=cli_agent.DEFAULT_MINUTES,
                   help=f"1 to {cli_agent.MAX_MINUTES} (%(default)s)")
    command("lock", cmd_lock, "end that now")
    command("status", cmd_status, "is the account unlocked?")
    command("vaults", cmd_vaults, "the vaults of the account")

    p = command("list", cmd_list, "entries, without their secrets")
    p.add_argument("text", nargs="?", help="only those with this in them")
    p.add_argument("--vault", "-v", metavar="VAULT")
    p.add_argument("--archived", action="store_true", help="the Archive")
    p.add_argument("--json", action="store_true")

    p = command("show", cmd_show, "one entry, without its secrets")
    entry(p)
    p.add_argument("--archived", action="store_true", help="in the Archive")
    p.add_argument("--json", action="store_true")

    p = command("get", cmd_get, "one field, for a pipe")
    entry(p)
    p.add_argument("field", nargs="?", choices=FIELDS, default="password")
    p.add_argument("--print", action="store_true",
                   help="also when that shows a secret on the screen")

    p = command("copy", cmd_copy, "one field, to the clipboard")
    entry(p)
    p.add_argument("field", nargs="?", choices=FIELDS, default="password")

    p = command("add", cmd_add, "add an entry")
    p.add_argument("name", metavar="NAME")
    p.add_argument("--username", "-u", default="")
    p.add_argument("--url", default="")
    p.add_argument("--notes", default="")
    p.add_argument("--vault", "-v", metavar="VAULT",
                   help="(default: the personal one)")
    password(p)

    p = command("edit", cmd_edit, "change an entry; the old version is kept")
    entry(p)
    p.add_argument("--name")
    p.add_argument("--username", "-u")
    p.add_argument("--url")
    p.add_argument("--notes")
    p.add_argument("--clear", action="append", choices=("url", "notes", "otp"))
    password(p).add_argument("--password", "-p", action="store_true",
                             help="ask for a new password")

    entry(command("archive", cmd_archive, "move an entry to the Archive"))
    entry(command("restore", cmd_restore, "bring one back from the Archive"))
    p = command("delete", cmd_delete, "delete an archived entry for good")
    entry(p)
    p.add_argument("--yes", "-y", action="store_true", help="do not ask")
    p = command("move", cmd_move, "move an entry to another vault")
    entry(p)
    p.add_argument("to", metavar="NEW_VAULT")
    p.add_argument("--yes", "-y", action="store_true", help="do not ask")
    p.add_argument("--allow-duplicate", action="store_true",
                   help="even if that login exists there already")

    p = command("generate", cmd_generate, "make a password, saved nowhere")
    p.add_argument("--length", "-l", type=int, default=20)
    p.add_argument("--no-symbols", action="store_true")
    p.add_argument("--copy", "-c", action="store_true", help="to the clipboard")
    command("sync", cmd_sync, "sync with the server")
    command("mcp", cmd_mcp, "for AI tools: an MCP server that asks the "
            "unlocked app")
    return parser


def main(argv=None, term=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == [cli_agent.AGENT_ARGUMENT]:
        cli_agent.serve()
        return 0
    term = term or Terminal()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return USAGE
    try:
        args.run(term, args)
        return 0
    except Problem as e:
        term.err(str(e))
        return e.code
    except KeyboardInterrupt:
        term.err("Cancelled.")
        return 130
    except BrokenPipeError:
        # The program at the other end has read enough.
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return FAILED
    except (OSError, ValueError, RuntimeError, sync_client.SyncError) as e:
        term.err(printable(e))          # CryptoError is a ValueError
        return FAILED


def start() -> int:
    for stream in (sys.stdout, sys.stderr):
        # A name this console cannot show is no reason to stop.
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace",
                               **({} if stream.isatty() else
                                  {"encoding": "utf-8"}))
    return main()


if __name__ == "__main__":
    sys.exit(start())
