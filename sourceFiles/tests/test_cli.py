"""The command line: what it changes, what it never shows, its session."""

import json
import os
import subprocess
import sys
import time

import pytest

import account_lock
import account_sync
import accounts
import appconfig
import changelog
import cli
import cli_agent
import cli_clipboard
import lockout
import vault
from test_account_sync import (PW, alice, cheap_argon2, device,  # noqa: F401
                               secretspace_server, server)

SECRET = "s3cret-of-the-entry"
SOURCE = os.path.dirname(os.path.abspath(cli.__file__))


class Term(cli.Terminal):
    def __init__(self, hidden=(), answers=(), piped=None, screen=True):
        self.hidden, self.answers = list(hidden), list(answers)
        self.piped, self.screen = piped, screen
        self.said, self.complained, self.sent = [], [], []
        self.prompts = 0

    def out(self, text=""):
        self.said.append(text)

    def err(self, text):
        self.complained.append(text)

    def raw(self, text):
        self.sent.append(text)

    shows_output = property(lambda self: self.screen)
    piped_input = property(lambda self: self.piped is not None)

    def read_all(self):
        return self.piped if self.piped is not None else super().read_all()

    def ask_hidden(self, prompt):
        self.prompts += 1
        return self.hidden.pop(0)

    def ask(self, prompt):
        return self.answers.pop(0) if self.answers else super().ask(prompt)

    @property
    def text(self):
        return "\n".join(self.said)

    @property
    def trouble(self):
        return "\n".join(self.complained)


@pytest.fixture(autouse=True)
def quiet(tmp_path, monkeypatch, request):
    monkeypatch.setattr(appconfig, "config_file",
                        lambda: str(tmp_path / "config.json"))
    monkeypatch.delenv(cli.ACCOUNT_VARIABLE, raising=False)
    real = account_lock.take
    monkeypatch.setattr(account_lock, "take", lambda u, wait=0: real(u))


@pytest.fixture
def acc(device):                                                # noqa: F811
    account = accounts.prepare_account("alice", PW).save()
    data = account.load_vault()
    vault.add_account(data, "GitHub", "ally", SECRET, notes="a note",
                      url="https://github.com", totp="JBSWY3DPEHPK3PXP")
    vault.add_account(data, "GitLab", "ally", "p2")
    account.save_vault(data)
    yield account
    cli_agent.stop("alice")


def run(*argv, code=0, pw=True, **kw):
    """One command; the password prompt answered unless told otherwise."""
    hidden = ([PW] if pw else []) + list(kw.pop("hidden", ()))
    term = Term(hidden=hidden, **kw)
    got = cli.main(list(argv), term)
    assert got == code, (got, term.said, term.complained)
    return term


def live(account, vault_id=None):
    return {a["site"]: a for a in account.vault_file(vault_id).load()["accounts"]
            if not vault.is_archived(a)}


# --- reading -----------------------------------------------------------------
def test_list_and_show_hold_no_secret(acc):
    for argv in (("list",), ("list", "--json"), ("show", "github"),
                 ("show", "github", "--json")):
        text = run(*argv).text
        assert "GitHub" in text and "ally" in text
        for secret in (SECRET, "a note", "JBSWY3DPEHPK3PXP"):
            assert secret not in text
    assert "GitLab" not in run("list", "hub").text
    assert json.loads(run("list", "--json", "hub").text)[0]["has_otp"] is True


def test_a_secret_goes_to_a_pipe_and_not_to_the_screen(acc):
    assert run("get", "GitHub", screen=False).sent == [SECRET]
    for field in ("password", "notes", "otp"):
        term = run("get", "GitHub", field, code=cli.USAGE)
        assert term.said == term.sent == [] and "--print" in term.trouble
        assert term.prompts == 0
    assert run("get", "GitHub", "--print").said == [SECRET]
    assert run("get", "GitHub", "username").said == ["ally"]
    assert run("get", "GitHub", "url", screen=False).sent == ["https://github.com"]


def test_otp_gives_a_code_and_never_the_secret(acc):
    code = run("get", "GitHub", "otp", screen=False).sent[0]
    assert len(code) == 6 and code.isdigit()
    assert "no 2FA" in run("get", "GitLab", "otp", screen=False, code=1).trouble


def test_copy_holds_the_field_and_prints_nothing_of_it(acc, monkeypatch):
    held = []
    monkeypatch.setattr(cli_clipboard, "hold", lambda t, s: held.append((t, s)))
    term = run("copy", "GitHub")
    assert held == [(SECRET, cli.CLIPBOARD_SECONDS)]
    assert SECRET not in term.text + term.trouble


def test_an_entry_is_found_and_never_guessed(acc):
    entry = live(acc)["GitHub"]
    for wanted in ("GitHub", "github", "hub", entry["id"], entry["id"][:8]):
        assert run("get", wanted, "name", screen=False).sent == ["GitHub"]
    term = run("get", "git", screen=False, code=1)
    assert "fits 2 entries" in term.trouble and entry["id"][:8] in term.trouble
    assert not term.sent
    assert "no entry" in run("get", "zzz", screen=False, code=1).trouble
    # An exact name wins over names that contain it.
    data = acc.load_vault()
    vault.add_account(data, "Git", "x", "p3")
    acc.save_vault(data)
    assert run("get", "git", screen=False).sent == ["p3"]


def test_a_name_cannot_send_the_terminal_commands(acc):
    data = acc.load_vault()
    vault.add_account(data, "Evil\x1b[2J\x9b‮", "u\r\nx", "a\x1bb")
    acc.save_vault(data)
    text = run("list").text + run("show", "Evil").text \
        + run("get", "Evil", "--print").text
    assert not set("\x1b\x9b‮\r") & set(text)
    assert run("get", "Evil", screen=False).sent == ["a\x1bb"]      # exact


def test_vaults(acc):
    work = acc.create_vault("Work")
    data = work.load()
    vault.add_account(data, "Box", "u", "p")
    work.save(data)
    assert "Work  (1 entry)" in run("vaults").text
    assert "[Work]" in run("list").text
    assert "GitHub" not in run("list", "--vault", "work").text
    assert "There are:" in run("list", "--vault", "nope", code=1).trouble


# --- changing ----------------------------------------------------------------
def test_add(acc):
    term = run("add", " Mail ", "-u", "me", "--url", "mail.example",
               "--notes", "n", "--totp", hidden=["pw1", "pw1", "JBSWY3DPEHPK3PXP"])
    e = live(acc)["Mail"]
    assert (e["username"], e["password"], e["url"], e["notes"], e["totp"]) == \
        ("me", "pw1", "https://mail.example", "n", "JBSWY3DPEHPK3PXP")
    assert "pw1" not in term.text
    assert e["updated_by"] == "alice"
    log = changelog.lines_of(acc.load_vault())
    assert log[-1]["action"] == changelog.ADDED


def test_add_generated_or_piped(acc):
    run("add", "A", "--generate", "30")
    assert len(live(acc)["A"]["password"]) == 30
    for n, piped, expect in ((1, b"x y \r\n", "x y "), (2, "﻿pü".encode(), "pü")):
        run("add", f"P{n}", "--password-stdin", piped=piped)
        assert live(acc)[f"P{n}"]["password"] == expect
    for bad in (b"", b"\n", b"a\nb\n", b"\xff"):
        run("add", "Bad", "--password-stdin", piped=bad, code=1)
    run("add", "Bad", "--generate", "3", code=cli.USAGE)
    assert "Bad" not in live(acc)


def test_nothing_is_added_on_a_mistake(acc):
    before = open(acc.vault_path, "rb").read()
    run("add", "X", hidden=["one", "two"], code=1)
    run("add", "X", hidden=[""], code=1)
    run("add", "  ", code=1)
    run("add", "X", "--url", "javascript:alert(1)", code=1)
    run("add", "X", "--totp", hidden=["p", "p", "not!base32"], code=1)
    run("add", "X", "--vault", "Nope", code=1)
    assert "already a login" in run("add", "github", "-u", "ALLY", code=1).trouble
    assert open(acc.vault_path, "rb").read() == before
    run("add", "github", "-u", "ALLY", "-g", "--allow-duplicate")
    assert len(acc.load_vault()["accounts"]) == 3


def test_edit_keeps_the_old_version(acc):
    run("edit", "GitHub", "--name", "Hub", "--password", "--clear", "notes",
        "--clear", "otp", hidden=["new", "new"])
    e = live(acc)["Hub"]
    assert e["password"] == "new" and e["username"] == "ally"
    assert "notes" not in e and "totp" not in e
    assert e["history"][0]["password"] == SECRET
    assert "Nothing to change" in run("edit", "Hub", "--name", "Hub").text
    assert len(live(acc)["Hub"]["history"]) == 1
    run("edit", "Hub", code=cli.USAGE)
    run("edit", "Hub", "--clear", "url", "--url", "a.b", code=cli.USAGE)
    run("edit", "Hub", "--name", "gitlab", code=1)          # a twin
    assert "Hub" in live(acc)


def test_archive_restore_delete(acc):
    run("delete", "GitHub", "--yes", code=1)                # only archived ones
    run("archive", "GitHub")
    assert "GitHub" not in live(acc) and "GitHub" in run("list", "--archived").text
    run("get", "GitHub", screen=False, code=1)
    run("restore", "GitHub")
    assert live(acc)["GitHub"]["password"] == SECRET
    run("archive", "GitHub")
    run("delete", "GitHub", answers=["n"], code=1)
    run("delete", "GitHub", code=1, piped=b"y\n")           # not from a pipe
    assert len(acc.load_vault()["accounts"]) == 2
    run("delete", "GitHub", answers=["y"])
    assert len(acc.load_vault()["accounts"]) == 1


def test_move_without_a_server(acc):
    work = acc.create_vault("Work").hex
    run("move", "GitHub", "Work", answers=["no"], code=1)
    assert "GitHub" in live(acc)
    run("move", "GitHub", "Work", "--yes")
    assert live(acc, work)["GitHub"]["password"] == SECRET
    assert [a["site"] for a in acc.load_vault()["accounts"]] == ["GitLab"]
    run("move", "GitHub", "work", "--yes", code=1)          # it is there already


def test_a_read_only_vault_is_not_changed(acc, monkeypatch):
    before = open(acc.vault_path, "rb").read()
    monkeypatch.setattr(accounts.Account, "vault_role",
                        lambda self, v: accounts.ROLE_READER)
    for argv in (("add", "X", "-g"), ("edit", "GitHub", "--name", "Y"),
                 ("archive", "GitHub")):
        assert "reading only" in run(*argv, code=1).trouble
    assert open(acc.vault_path, "rb").read() == before


def test_nor_one_from_a_newer_version(acc):
    data = acc.load_vault()
    vault.require_level(data, vault.DATA_LEVEL + 1, windows="9.0", linux="9.0")
    acc.save_vault(data)
    before = open(acc.vault_path, "rb").read()
    assert "9.0 or newer" in run("add", "X", "-g", code=1).trouble
    assert open(acc.vault_path, "rb").read() == before
    assert run("get", "GitHub", screen=False).sent == [SECRET]


def test_the_app_has_it_open(acc):
    before = open(acc.vault_path, "rb").read()
    with account_lock.take("alice"):
        for argv in (("add", "X", "-g"), ("edit", "GitHub", "--name", "Y"),
                     ("archive", "GitHub")):
            assert "in use" in run(*argv, code=1).trouble
        assert run("get", "GitHub", screen=False).sent == [SECRET]
    assert open(acc.vault_path, "rb").read() == before
    run("archive", "GitHub")


def test_a_change_made_while_the_password_was_typed_is_kept(acc):
    class Slow(Term):
        def ask_hidden(self, prompt):
            if len(self.hidden) == 1:
                data = acc.load_vault()
                vault.add_account(data, "Meanwhile", "u", "p")
                acc.save_vault(data)
            return super().ask_hidden(prompt)
    assert cli.main(["add", "Mine"], Slow([PW, "p", "p"])) == 0
    assert {"Meanwhile", "Mine"} <= set(live(acc))


def test_an_entry_archived_meanwhile_is_not_changed(acc):
    class Slow(Term):
        def ask_hidden(self, prompt):
            if len(self.hidden) == 1:
                data = acc.load_vault()
                vault.archive_account(data, data["accounts"][0]["id"])
                acc.save_vault(data)
            return super().ask_hidden(prompt)
    term = Slow([PW, "p", "p"])
    assert cli.main(["edit", "GitHub", "--password"], term) == 1
    assert "meanwhile" in term.trouble
    assert acc.load_vault()["accounts"][0]["password"] == SECRET


# --- the password and the session --------------------------------------------
def test_a_wrong_password_counts_like_in_the_app(acc):
    for n in range(lockout.FREE_ATTEMPTS + 1):
        assert "Wrong master password" in run(
            "list", pw=False, hidden=["no"], code=1).trouble
    term = run("list", pw=False, hidden=[PW], code=1)
    assert "Too many" in term.trouble and term.prompts == 0


def test_the_right_password_clears_the_count(acc):
    run("list", pw=False, hidden=["no"], code=1)
    assert lockout.failures("alice") == 1
    run("list")
    assert lockout.failures("alice") == 0


def test_every_command_asks_without_a_session(acc):
    assert run("list").prompts == 1
    assert run("list").prompts == 1
    assert "locked" in run("status", pw=False).text


def test_a_session(acc):
    run("unlock", "--minutes", "2")
    term = run("get", "GitHub", screen=False, pw=False)
    assert term.sent == [SECRET] and term.prompts == 0
    assert "unlocked for 1 min" in run("status", pw=False).text
    assert "(unlocked)" in run("accounts", pw=False).text
    run("edit", "GitHub", "--name", "Hub", pw=False)
    assert "Hub" in live(acc)
    assert "alice" in run("lock", pw=False).text
    assert not os.path.exists(cli_agent.session_path("alice"))
    assert run("list").prompts == 1
    assert "Nothing was unlocked" in run("lock", pw=False).text


def test_the_session_file_holds_no_key_of_the_account(acc):
    run("unlock")
    raw = open(cli_agent.session_path("alice"), encoding="utf-8").read()
    for secret in (PW, acc.keyset["personal_vault_key"], acc.kit
                   if hasattr(acc, "kit") else acc.secret_key_text,
                   acc._secret.hex()):
        assert secret not in raw
    if os.name != "nt":
        assert os.stat(cli_agent.session_path("alice")).st_mode & 0o077 == 0


def test_a_session_ends_by_itself(acc):
    cli_agent.start(acc, 0.04)                               # 2.4 s
    assert cli_agent.opened("alice")
    found = json.load(open(cli_agent.session_path("alice")))
    time.sleep(4)
    assert not os.path.exists(cli_agent.session_path("alice"))
    # Nobody answers there any more, whatever a file says.
    found["until"] = time.time() + 100
    json.dump(found, open(cli_agent.session_path("alice"), "w"))
    assert cli_agent.opened("alice") is None


def test_a_stranger_gets_nothing(acc):
    run("unlock")
    path = cli_agent.session_path("alice")
    raw = open(path).read()
    wrong = dict(json.loads(raw), key="00" * 32)
    json.dump(wrong, open(path, "w"))
    assert cli_agent.opened("alice") is None
    open(path, "w").write(raw)
    assert cli_agent.opened("alice")                 # it is still there
    # One that connects and says nothing does not keep others out.
    if os.name != "nt":
        import socket
        s = socket.socket(socket.AF_UNIX)
        s.connect(json.loads(raw)["address"])
        s.close()
        assert cli_agent.opened("alice")


def test_a_changed_master_password_ends_the_session(acc):
    run("unlock")
    acc.change_password("another one entirely")
    assert cli_agent.opened("alice") is None
    assert not os.path.exists(cli_agent.session_path("alice"))


def test_unlocking_again_replaces_the_session(acc):
    run("unlock")
    first = open(cli_agent.session_path("alice")).read()
    run("unlock")
    second = open(cli_agent.session_path("alice")).read()
    assert json.loads(second)["address"] != json.loads(first)["address"]
    open(cli_agent.session_path("alice"), "w").write(first)
    assert cli_agent.opened("alice") is None         # the first one is gone
    open(cli_agent.session_path("alice"), "w").write(second)
    assert cli_agent.opened("alice")
    for bad in ("0", "61"):
        run("unlock", "--minutes", bad, code=cli.USAGE, pw=False)


def test_which_account(acc, monkeypatch):
    accounts.prepare_account("bob", PW).save()
    assert "several accounts" in run("list", pw=False, code=cli.USAGE).trouble
    assert run("list", "-a", "ALICE").text
    monkeypatch.setenv(cli.ACCOUNT_VARIABLE, "bob")
    assert run("list").text == ""
    monkeypatch.delenv(cli.ACCOUNT_VARIABLE)
    appconfig.save_config(last_username="alice")
    assert "GitHub" in run("list").text
    assert "no account" in run("list", "-a", "x", pw=False, code=1).trouble


def test_no_account_yet(device):                             # noqa: F811
    assert "no account on this device" in run("list", pw=False, code=1).trouble


def test_nothing_unlocks_unattended(acc):
    """A real process with a pipe for a keyboard."""
    env = dict(os.environ, PYTHONPATH=SOURCE)
    env.pop("MSYSTEM", None)            # run from Git Bash
    options = {"creationflags": subprocess.DETACHED_PROCESS} \
        if os.name == "nt" else {"start_new_session": True}
    done = subprocess.run([sys.executable, os.path.join(SOURCE, "cli.py"),
                           "list"], input=(PW + "\n").encode(),
                          capture_output=True, env=env, timeout=60, **options)
    assert done.returncode == cli.FAILED
    assert b"unattended" in done.stderr, done.stderr
    assert b"GitHub" not in done.stdout


def test_a_real_process_pipes_bytes_exactly(acc):
    run("unlock")
    data = acc.load_vault()
    vault.add_account(data, "Uni", "u", "pä€ß ")
    acc.save_vault(data)
    env = dict(os.environ, PYTHONPATH=SOURCE)
    done = subprocess.run([sys.executable, os.path.join(SOURCE, "cli.py"),
                           "get", "Uni"], capture_output=True, env=env, timeout=60)
    assert done.stdout == "pä€ß ".encode("utf-8"), done.stderr
    done = subprocess.run([sys.executable, os.path.join(SOURCE, "cli.py"),
                           "--version"], capture_output=True, env=env, timeout=60)
    assert b"SecretSpace" in done.stdout


def test_generate():
    assert len(run("generate", screen=False, pw=False).sent[0]) == 20
    text = run("generate", "-l", "40", "--no-symbols", pw=False).text
    assert len(text) == 40 and text.isalnum()
    run("generate", "-l", "5", code=cli.USAGE, pw=False)


def test_the_command_line_has_no_window_in_it():
    """The Windows program is built without Tk."""
    code = ("import sys; import cli; print([m for m in ('tkinter', "
            "'customtkinter', 'PIL') if m in sys.modules])")
    done = subprocess.run([sys.executable, "-c", code], cwd=SOURCE,
                          capture_output=True, text=True, timeout=60)
    assert done.stdout.strip() == "[]", done.stderr


# --- syncing -----------------------------------------------------------------
def other_device(device, server, kit):                       # noqa: F811
    device("b")
    if accounts.account_exists("alice"):
        return accounts.unlock("alice", PW)
    return account_sync.sign_in(server.url, "", "alice", PW, kit)[0]


def test_sync(server, device, alice, monkeypatch):           # noqa: F811
    left, out = [], account_sync.AccountServer.logout
    monkeypatch.setattr(account_sync.AccountServer, "logout",
                        lambda self: (left.append(1), out(self)))
    run("add", "From A", "-g")
    assert "Updated" in run("sync").text
    assert left
    assert "up to date" in run("sync").text
    work = alice.create_vault("Work").hex
    run("add", "In work", "-v", "Work", "-g")
    run("sync")

    other_device(device, server, alice.kit)
    run("sync")
    run("edit", "From A", "--username", "b")
    run("move", "From A", "Work", "--yes")
    term = run("sync")
    b = accounts.unlock("alice", PW)
    assert set(live(b, work)) == {"In work", "From A"}
    assert b.load_vault()["accounts"] == []             # settled in one sync

    device("a")
    run("sync")
    a = accounts.unlock("alice", PW)
    assert live(a, work)["From A"]["username"] == "b"
    assert a.load_vault()["accounts"] == []
    assert "up to date" in run("sync").text


def test_a_conflict_is_left_for_the_app(server, device, alice):   # noqa: F811
    run("add", "Mail", "--password-stdin", piped=b"p0")
    run("sync")
    other_device(device, server, alice.kit)
    run("sync")
    run("edit", "Mail", "--password-stdin", piped=b"from b")
    run("sync")
    device("a")
    run("edit", "Mail", "--password-stdin", piped=b"from a")
    a = accounts.unlock("alice", PW)
    before = open(a.vault_path, "rb").read()
    term = run("sync", code=cli.UNDECIDED)
    assert "Press Sync in the app" in term.trouble
    assert open(a.vault_path, "rb").read() == before
    assert live(a)["Mail"]["password"] == "from a"


def test_a_vault_that_cannot_be_read_is_never_synced(server, device, alice):  # noqa: F811
    run("add", "Mail", "-g")
    run("sync")
    for path in (alice.vault_path, alice.vault_path + vault.BACKUP_SUFFIX):
        open(path, "w").write("broken")
    stored = server.accounts.vaults.read(alice.vault_id.hex()) \
        if hasattr(server, "accounts") else None
    term = run("sync")
    assert "could not be read" in term.trouble
    assert open(alice.vault_path).read() == "broken"
    if stored is not None:
        assert server.accounts.vaults.read(alice.vault_id.hex()) == stored


def test_sync_without_a_server(acc):
    assert "not on a server" in run("sync", code=1).trouble


def test_sync_waits_for_the_app(server, device, alice):      # noqa: F811
    with account_lock.take("alice"):
        assert "in use" in run("sync", code=1).trouble


def test_a_server_that_is_down(server, device, alice):       # noqa: F811
    server.shutdown()
    server.server_close()
    assert run("sync", code=1).trouble
    account_lock.take("alice").release()                     # and it let go
