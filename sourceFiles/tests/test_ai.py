"""AI agents: what the app answers, what the MCP server says, what neither does."""

import base64
import json
import os
import subprocess
import sys
import threading
import time

import pytest

import accounts
import ai_access
import ai_ui
import mcp_server
import vault
from ai_access import Refused
from test_account_sync import PW, cheap_argon2                  # noqa: F401

SECRET = "s3cret pässwörd+/=\"x"
SOURCE = os.path.dirname(os.path.abspath(ai_access.__file__))


@pytest.fixture
def acc(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRETSPACE_DATA_DIR", str(tmp_path / "data"))
    return accounts.prepare_account("alice", PW).save()


@pytest.fixture
def vaults(acc):
    """Personal (not marked) and Agents (marked), as the app holds them."""
    work = acc.create_vault("Agents")
    ours, theirs = {"accounts": []}, {"accounts": []}
    vault.add_account(ours, "Bank", "me", "bank-pass")
    vault.add_account(theirs, "GitHub", "bot", SECRET, notes="a note",
                      url="https://github.com", totp="JBSWY3DPEHPK3PXP")
    vault.add_account(theirs, "Old", "bot", "old-pass")
    vault.archive_account(theirs, theirs["accounts"][1]["id"])
    ai_access.allow_vault(acc, work.hex, True)
    return {acc.personal_id: ours, work.hex: theirs}


def eid(vaults, site):
    return next(a["id"] for d in vaults.values() for a in d["accounts"]
                if a["site"] == site)


def use(vaults, site="GitHub", field="password", **more):
    return dict({"ask": "use", "command": ["prog", "arg"],
                 "env": {"TOKEN": {"entry": eid(vaults, site),
                                   "field": field}}}, **more)


# --- marking -----------------------------------------------------------------
def test_nothing_is_marked_at_first_and_marks_are_kept(acc):
    assert ai_access.allowed_vaults(acc) == []
    work = acc.create_vault("Work").hex
    ai_access.allow_vault(acc, work, True)
    ai_access.allow_vault(acc, work, True)
    assert ai_access.allowed_vaults(accounts.unlock("alice", PW)) == [work]
    acc.delete_vault(work)
    assert ai_access.allowed_vaults(acc) == []
    ai_access.allow_vault(acc, acc.personal_id, True)
    ai_access.allow_vault(acc, acc.personal_id, False)
    assert ai_access.allowed_vaults(acc) == []
    acc.info = dict(acc.info, ai_vaults="junk")
    assert ai_access.allowed_vaults(acc) == []


# --- the questions -----------------------------------------------------------
def test_list_holds_marked_live_entries_and_no_secret(acc, vaults):
    found = ai_access.describe(acc, vaults)
    assert [e["name"] for e in found] == ["GitHub"]
    assert found[0]["fields"] == list(ai_access.FIELDS)
    text = json.dumps(found, ensure_ascii=False)
    for secret in (SECRET, "a note", "JBSW", "bank-pass"):
        assert secret not in text


def test_only_marked_live_entries_are_given(acc, vaults):
    for site in ("Bank", "Old"):
        with pytest.raises(Refused, match="no such entry"):
            ai_access.find_entries(acc, vaults, use(vaults, site)["env"])
    env = use(vaults)["env"]
    found = ai_access.find_entries(acc, vaults, env)
    assert ai_access.values_of(found, env) == {"TOKEN": SECRET}
    ai_access.allow_vault(acc, ai_access.allowed_vaults(acc)[0], False)
    with pytest.raises(Refused):
        ai_access.find_entries(acc, vaults, env)


def test_otp_is_a_code_and_an_empty_field_is_refused(acc, vaults):
    env = use(vaults, field="otp")["env"]
    code = ai_access.values_of(ai_access.find_entries(acc, vaults, env), env)
    assert code["TOKEN"].isdigit() and len(code["TOKEN"]) == 6
    data = vaults[ai_access.allowed_vaults(acc)[0]]
    vault.add_account(data, "Plain", "u", "p")
    for field in ("otp", "notes", "url"):
        with pytest.raises(Refused, match="has no " + field):
            ai_access.find_entries(acc, vaults,
                                   use(vaults, "Plain", field)["env"])


@pytest.mark.parametrize("change", [
    {"command": []}, {"command": "ls"}, {"command": ["a", 1]},
    {"command": [""]}, {"command": ["a\0b"]}, {"command": None},
    {"command": ["x" * (ai_access.COMMAND_CHARS + 1)]},
    {"cwd": "a\0"}, {"cwd": 5}, {"env": {}}, {"env": None},
    {"env": {"A B": {"entry": "x"}}}, {"env": {"PATH": {"entry": "x"}}},
    {"env": {"ld_preload": {"entry": "x"}}}, {"env": {"A": "x"}},
    {"env": {"NODE_OPTIONS": {"entry": "x"}}},
    {"env": {"A": {"entry": 5}}}, {"env": {"A": {"entry": "x", "field": "id"}}},
    {"env": {"A": {"entry": "x"}, "a": {"entry": "y"}}},
    {"env": {f"A{i}": {"entry": "x"} for i in range(21)}}])
def test_a_bad_question_is_refused(change):
    good = {"command": ["a"], "env": {"A": {"entry": "x"}}}
    assert ai_access.check_request(good)["env"]["A"]["field"] == "password"
    with pytest.raises(Refused):
        ai_access.check_request(dict(good, **change))


def test_what_is_shown_cannot_be_faked():
    text = ai_ui.shown_command(["sh", "-c", "ls\n\n‮evil\x1b[2J", "a b"])
    assert text.split("\n") == ["sh", "    -c",
                                "    ls\\u000a\\u000a\\u202eevil\\u001b[2J",
                                "    a b"]


# --- the log -----------------------------------------------------------------
def test_the_log_is_encrypted_kept_short_and_survives(acc):
    for i in range(3):
        ai_access.add_to_log(acc, "agent", f"run: thing{i}", "allowed")
    raw = open(ai_access._log_path("alice"), "rb").read()
    assert b"thing" not in raw
    again = accounts.unlock("alice", PW)
    assert [x["what"] for x in ai_access.read_log(again)] == \
        ["run: thing0", "run: thing1", "run: thing2"]
    many = [{"what": str(i)} for i in range(ai_access.LOG_LINES)]
    original = ai_access.read_log
    try:
        ai_access.read_log = lambda a: many
        ai_access.add_to_log(acc, "a", "last", "refused")
    finally:
        ai_access.read_log = original
    lines = ai_access.read_log(acc)
    assert len(lines) == ai_access.LOG_LINES and lines[-1]["what"] == "last"
    open(ai_access._log_path("alice"), "wb").write(b"broken")
    assert ai_access.read_log(acc) == []


# --- the pipe ----------------------------------------------------------------
@pytest.fixture
def door(acc):
    doors = []

    def make(answer):
        doors.append(ai_access.Door("alice", answer))
        return doors[-1]
    yield make
    for d in doors:
        d.close()


def test_the_pipe(door):
    with pytest.raises(Refused, match="not open for AI"):
        ai_access.ask("alice", {"ask": "list"})
    d = door(lambda r: {"got": r["ask"]})
    assert ai_access.open_accounts() == ["alice"]
    assert ai_access.ask("alice", {"ask": "list"}) == {"got": "list"}
    path = ai_access.session_path("alice")
    if os.name != "nt":
        assert os.stat(path).st_mode & 0o077 == 0
    raw = open(path).read()
    json.dump(dict(json.loads(raw), key="00" * 32), open(path, "w"))
    with pytest.raises(Refused):                        # a stranger
        ai_access.ask("alice", {})
    open(path, "w").write(raw)
    assert ai_access.ask("alice", {"ask": "x"}) == {"got": "x"}
    d.close()
    assert not os.path.exists(path) and ai_access.open_accounts() == []
    open(path, "w").write(raw)
    with pytest.raises(Refused):
        ai_access.ask("alice", {})


def test_an_answer_that_comes_after_the_lock_is_not_given(door):
    go = threading.Event()

    def answer(request):
        go.wait(10)
        return {"values": {"A": "secret"}}
    d = door(answer)
    said = []

    def ask():
        try:
            said.append(ai_access.ask("alice", {}))
        except Refused as e:
            said.append(str(e))
    t = threading.Thread(target=ask)
    t.start()
    time.sleep(0.5)
    d.close()
    go.set()
    t.join(10)
    assert said and "secret" not in str(said[0])


def test_one_that_says_nothing_does_not_block_the_others(door):
    door(lambda r: {"ok": 1})
    found = json.load(open(ai_access.session_path("alice")))
    quiet = ai_access.Client(found["address"], authkey=bytes.fromhex(found["key"]))
    assert ai_access.ask("alice", {}) == {"ok": 1}
    quiet.send_bytes(b"\xff not json")
    assert "not understood" in json.loads(quiet.recv_bytes())["refused"]
    quiet.close()


def test_the_door_of_an_older_session_does_not_remove_the_new_file(door):
    old, new = door(lambda r: {}), door(lambda r: {"new": 1})
    old.close()
    assert ai_access.ask("alice", {}) == {"new": 1}
    new.close()


# --- the app -----------------------------------------------------------------
class Root:
    """after() runs at once, as if the main thread were idle."""

    def after(self, ms, work):
        work()


class App:
    def __init__(self, account, vaults):
        self.root, self.account, self.vaults = Root(), account, vaults
        self.toasts = []
        self.toast = lambda m, k="info": self.toasts.append(m)
        self.vault_name = lambda v: account.vault_file(v).name


@pytest.fixture
def app(acc, vaults, monkeypatch):
    app = App(acc, vaults)
    app.windows, app.answers = [], []

    def window(app_, wanted, found, decided):
        app.windows.append((wanted, found))
        answer = app.answers.pop(0)
        if callable(answer):
            answer(decided)
        else:
            app.root_later = threading.Timer(0.1, decided, (answer,))
            app.root_later.start()
        return decided
    monkeypatch.setattr(ai_ui, "request_window", window)
    app.ai_guard = ai_ui.Guard(app)
    app.ai_guard.refresh()
    yield app
    app.ai_guard.close()


def last(acc):
    line = ai_access.read_log(acc)[-1]
    return line["what"], line["result"]


def test_the_user_decides_every_time(app, acc, vaults):
    app.answers = [True, False, True]
    request = use(vaults, client="agent")
    assert ai_access.ask("alice", request) == {"values": {"TOKEN": SECRET}}
    assert last(acc)[1] == "allowed" and "prog arg" in last(acc)[0]
    with pytest.raises(Refused, match="did not allow"):
        ai_access.ask("alice", request)
    assert last(acc)[1] == "refused"
    ai_access.ask("alice", request)
    assert len(app.windows) == 3
    assert SECRET not in json.dumps(ai_access.read_log(acc), ensure_ascii=False)


def test_list_is_not_asked_about_but_noted(app, acc):
    assert [e["name"] for e in ai_access.ask(
        "alice", {"ask": "list"})["entries"]] == ["GitHub"]
    assert not app.windows and "listed 1" in last(acc)[0]


def test_what_cannot_be_given_is_not_asked_about(app, vaults):
    for request in (use(vaults, "Bank"), use(vaults, command=[]), {"ask": "x"},
                    {}):
        with pytest.raises(Refused):
            ai_access.ask("alice", request)
    assert not app.windows


def test_one_window_at_a_time(app, vaults):
    held = []
    app.answers = [held.append]
    t = threading.Thread(target=lambda: ai_access.ask("alice", use(vaults)))
    t.start()
    for _ in range(100):
        if held:
            break
        time.sleep(0.05)
    with pytest.raises(Refused, match="another request"):
        ai_access.ask("alice", use(vaults))
    held[0](True)
    t.join(10)
    assert len(app.windows) == 1


def test_a_change_while_the_window_was_open_counts(app, acc, vaults):
    marked = ai_access.allowed_vaults(acc)[0]

    def archived(decided):
        vault.archive_account(vaults[marked], eid(vaults, "GitHub"))
        threading.Timer(0.1, decided, (True,)).start()

    def unmarked(decided):
        ai_access.allow_vault(acc, marked, False)
        threading.Timer(0.1, decided, (True,)).start()
    for change in (archived, unmarked):
        app.answers = [change]
        with pytest.raises(Refused, match="no such entry"):
            ai_access.ask("alice", use(vaults))
        vault.restore_account(vaults[marked], eid(vaults, "GitHub"))


def test_locking_ends_everything(app, vaults):
    held = []
    app.answers = [held.append]
    said = []

    def ask():
        try:
            said.append(ai_access.ask("alice", use(vaults)))
        except Refused as e:
            said.append(str(e))
    t = threading.Thread(target=ask)
    t.start()
    for _ in range(100):
        if held:
            break
        time.sleep(0.05)
    app.account = None
    app.ai_guard.close()
    held[0](True)                       # a click that comes too late
    t.join(10)
    assert said and isinstance(said[0], str)
    assert not os.path.exists(ai_access.session_path("alice"))


def test_another_account_is_not_answered_for(app, vaults):
    app.account = object()
    for request in (use(vaults), {"ask": "list"}):
        with pytest.raises(Refused, match="locked"):
            ai_access.ask("alice", request)
    assert not app.windows


def test_the_door_follows_the_marks(app, acc):
    marked = ai_access.allowed_vaults(acc)[0]
    ai_access.allow_vault(acc, marked, False)
    app.ai_guard.refresh()
    assert ai_access.open_accounts() == []
    ai_access.allow_vault(acc, marked, True)
    app.ai_guard.refresh()
    assert ai_access.open_accounts() == ["alice"]
    app.ai_guard.close()
    app.ai_guard.refresh()                              # locked stays closed
    assert ai_access.open_accounts() == []


# --- taking values out of the output -----------------------------------------
def test_hide():
    raw = SECRET.encode()
    import urllib.parse
    for form in (SECRET, base64.b64encode(raw).decode(), raw.hex(),
                 base64.b64encode(raw + b"\n").decode(),
                 base64.urlsafe_b64encode(raw).decode(), raw.hex().upper(),
                 urllib.parse.quote(SECRET, safe=""), json.dumps(SECRET)[1:-1],
                 urllib.parse.quote_plus(SECRET)):
        assert ai_access.hide(f"a{form}b", [SECRET]) == "a[hidden]b", form
    assert ai_access.hide("abcdef abc", ["abc", "abcdef"]) == "[hidden] [hidden]"
    assert ai_access.hide("as is", ["", "s"]) == "as is"
    key = "-----BEGIN KEY-----\nlongenoughline1\nlongenoughline2"
    assert "enough" not in ai_access.hide("> longenoughline2\r\n> longenoughline1",
                                          [key])


# --- the MCP server ----------------------------------------------------------
def call(server, name, args, mid=1):
    return server.handle({"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                          "params": {"name": name, "arguments": args}})


def text_of(reply):
    return reply["result"]["content"][0]["text"], reply["result"]["isError"]


PRINT = "import os,sys; print('T=' + os.environ['TOKEN']); " \
        "print(os.environ['USERNAME_'], file=sys.stderr); sys.exit(3)"


def test_run_with_secrets(app, vaults, tmp_path):
    app.answers = [True]
    server = mcp_server.Server()
    server.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params":
                   {"protocolVersion": "2025-03-26",
                    "clientInfo": {"name": "Robot"}}})
    env = {"TOKEN": {"entry": eid(vaults, "GitHub")},
           "USERNAME_": {"entry": eid(vaults, "GitHub"), "field": "username"}}
    text, wrong = text_of(call(server, "run_with_secrets", {
        "command": [sys.executable, "-X", "utf8", "-c", PRINT], "env": env,
        "cwd": str(tmp_path), "reason": "why"}))
    assert not wrong and text.startswith("exit code 3")
    assert "T=[hidden]" in text and SECRET not in text
    assert "bot" in text                                # not a secret
    wanted = app.windows[0][0]
    assert (wanted["client"], wanted["reason"], wanted["cwd"]) == \
        ("Robot", "why", str(tmp_path))


def test_nothing_runs_when_refused(app, vaults, tmp_path):
    app.answers = [False]
    text, wrong = text_of(call(mcp_server.Server(), "run_with_secrets", {
        "command": [sys.executable, "-c", "open('made', 'w')"],
        "env": use(vaults)["env"], "cwd": str(tmp_path)}))
    assert wrong and "did not allow" in text
    assert not (tmp_path / "made").exists()


def test_the_folder_shown_is_the_one_it_runs_in(app, vaults):
    app.answers = [True]
    text, _ = text_of(call(mcp_server.Server(), "run_with_secrets", {
        "command": [sys.executable, "-c", "import os; print(os.getcwd())"],
        "env": use(vaults)["env"]}))
    assert app.windows[0][0]["cwd"] == os.getcwd() and os.getcwd() in text
    _, wrong = text_of(call(mcp_server.Server(), "run_with_secrets", {
        "command": ["x"], "env": use(vaults)["env"], "cwd": "/no/such/folder"}))
    assert wrong and len(app.windows) == 1


def test_a_program_that_hangs_or_floods(tmp_path):
    started = time.time()
    done = mcp_server.run_command([sys.executable, "-c",
        "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',"
        "'import time; time.sleep(60)']); time.sleep(60)"], {}, None, 2)
    assert done["timed_out"] and time.time() - started < 20
    assert done["exit_code"] is not None                # it was ended
    done = mcp_server.run_command([sys.executable, "-c",
        "print('x' * 3_000_000)"], {}, None, 60)
    assert done["exit_code"] == 0
    with pytest.raises(Refused, match="could not be started"):
        mcp_server.run_command(["no-such-program-here"], {}, None, 5)


def test_list_entries_tool(app):
    server = mcp_server.Server()
    assert json.loads(text_of(call(server, "list_entries", {}))[0])[0][
        "name"] == "GitHub"
    assert json.loads(text_of(call(server, "list_entries",
                                   {"search": "zzz"}))[0]) == []


def test_a_locked_app(acc):
    text, wrong = text_of(call(mcp_server.Server(), "list_entries", {}))
    assert wrong and "unlock" in text


def test_a_failure_does_not_show_its_text():
    def broken(username, request):
        raise RuntimeError("holds " + SECRET)
    text, wrong = text_of(call(mcp_server.Server("alice", broken),
                               "list_entries", {}))
    assert wrong and SECRET not in text


@pytest.mark.parametrize("message, code", [
    ([], -32600), ("x", -32600), ({"id": 1, "method": "ping"}, -32600),
    ({"jsonrpc": "2.0", "id": 1, "method": 5}, -32600),
    ({"jsonrpc": "2.0", "id": 1, "method": "nope"}, -32601),
    ({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": [1]}, -32602),
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
      "params": {"name": ["x"]}}, -32602),
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params":
      {"name": "run_with_secrets", "arguments": {"timeout_seconds": 0}}},
     -32602)])
def test_protocol_errors(message, code):
    assert mcp_server.Server().handle(message)["error"]["code"] == code


def test_the_protocol_over_a_real_process(app, vaults):
    """As an AI tool starts it: only protocol on stdout, ends with stdin."""
    app.answers = [True]
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params":
         {"protocolVersion": "1999-01-01", "clientInfo": {"name": "T"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": "two", "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params":
         {"name": "list_entries", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params":
         {"name": "run_with_secrets", "arguments": {
             "command": [sys.executable, "-X", "utf8", "-c",
                         "import os; print(len(os.environ['TOKEN']))"],
             "env": use(vaults)["env"]}}}]
    raw = b"not json\n\n" + b"".join(json.dumps(x).encode() + b"\n"
                                     for x in lines)
    done = subprocess.run(
        [sys.executable, os.path.join(SOURCE, "cli.py"), "mcp"], input=raw,
        capture_output=True, timeout=60, env=dict(os.environ, PYTHONPATH=SOURCE))
    replies = [json.loads(x) for x in done.stdout.splitlines()]
    assert [r["id"] for r in replies] == [None, 1, "two", 3, 4], done.stderr
    assert replies[1]["result"]["protocolVersion"] == mcp_server.PROTOCOLS[0]
    assert [t["name"] for t in replies[2]["result"]["tools"]] == \
        ["list_entries", "run_with_secrets"]
    assert "GitHub" in replies[3]["result"]["content"][0]["text"]
    assert str(len(SECRET)) in replies[4]["result"]["content"][0]["text"]
    assert SECRET.encode() not in done.stdout and done.returncode == 0
