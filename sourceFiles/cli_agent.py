"""
The command line's short unlock session.

``secretspace-cli unlock`` starts this as a process of its own. It keeps the
account's open keys in memory, gives them to later commands of the same
user, and ends by itself after a few minutes, or at ``lock``. The master
password is not kept, and the keys are never written to disk.

Commands find it through a small file beside the account's folder, readable
by this user only: the address (a Unix socket, on Windows a named pipe) and
a random key both sides prove they know (multiprocessing.connection's HMAC
handshake). Like the memory of the app itself, the session is open to
anything that already runs as the same user; it is not a wall against that.
"""

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from multiprocessing import AuthenticationError
from multiprocessing.connection import Client, Listener

import account_crypto
import accounts
import vault

DEFAULT_MINUTES = 10
MAX_MINUTES = 60
#: The argument that makes the program the agent instead of a command.
AGENT_ARGUMENT = "_agent"
#: How long a command waits for an agent that does not answer.
ANSWER_SECONDS = 5


def session_path(username: str) -> str:
    return os.path.join(accounts.accounts_dir(),
                        "." + vault.validate_username(username) + ".session")


def _keyset_mark(username: str) -> str:
    """Changes with the password or a recovery, which end a session."""
    sealed = accounts._read_text(accounts._path(username, accounts.KEYSET_FILE))
    return hashlib.sha256(sealed.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The commands' side
# ---------------------------------------------------------------------------
def start(account, minutes: int) -> float:
    """Keep ``account`` open for ``minutes``. Returns when it ends (time)."""
    stop(account.username)
    until = time.time() + minutes * 60
    payload = {
        "username": account.username, "until": until,
        "mark": _keyset_mark(account.username), "keyset": account.keyset,
        "secret": account_crypto._b64(account._secret),
        "login_key": account_crypto._b64(account.login_key)
        if account.login_key else "",
        "session": session_path(account.username)}
    options = {"creationflags": subprocess.DETACHED_PROCESS
               | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" \
        else {"start_new_session": True}
    child = subprocess.Popen(_command(), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, close_fds=True,
                             cwd=os.path.abspath(os.sep), **options)
    try:
        child.stdin.write(json.dumps(payload).encode("utf-8"))
        child.stdin.close()
        ready = child.stdout.readline().strip() == b"ready"
        child.stdout.close()
    except OSError:
        ready = False
    if not ready:
        child.kill()
        raise RuntimeError("The unlock session could not be started.")
    child.returncode = 0            # it stays; nobody waits for it
    return until


def _command() -> list:
    """This program again, as the agent."""
    program = vault.frozen_dir()
    if program:
        here = os.path.dirname(os.path.abspath(
            __file__ if "__compiled__" in globals() else sys.executable))
        return [os.path.join(here, "secretspace-cli.exe"), AGENT_ARGUMENT]
    # -I, like the installed program: only the folders already in use.
    return [sys.executable, "-I", "-c",
            f"import sys; sys.path[:0] = {[p for p in sys.path if p]!r}; "
            "import cli_agent; cli_agent.serve()"]


def _read_session(username: str):
    try:
        with open(session_path(username), encoding="utf-8") as f:
            found = json.load(f)
        if found["until"] <= time.time():
            return None
        return {"address": str(found["address"]),
                "key": bytes.fromhex(found["key"]), "until": found["until"]}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _ask(username: str, question: bytes):
    """The agent's answer, or None. One that hangs is given up on."""
    found = _read_session(username)
    if found is None:
        return None
    answer = []

    def talk():
        try:
            with Client(found["address"], authkey=found["key"]) as c:
                c.send_bytes(question)
                if c.poll(ANSWER_SECONDS):
                    answer.append(c.recv_bytes())
        except (OSError, EOFError, AuthenticationError, ValueError):
            pass

    worker = threading.Thread(target=talk, daemon=True)
    worker.start()
    worker.join(ANSWER_SECONDS)
    return answer[0] if answer else None


def opened(username: str):
    """(the open account, when the session ends), or None: not unlocked."""
    raw = _ask(username, b"keys")
    if raw is None:
        return None
    try:
        kept = json.loads(raw.decode("utf-8"))
        if kept["username"] != username:
            return None
        if kept["mark"] != _keyset_mark(username):
            stop(username)              # the password was changed since
            return None
        account = accounts.Account(
            username, accounts._read_info(username), kept["keyset"],
            account_crypto._unb64(kept["secret"], "Secret Key"),
            account_crypto._unb64(kept["login_key"], "login key")
            if kept["login_key"] else None)
        return account, kept["until"]
    except (OSError, ValueError, KeyError, TypeError,
            accounts.NeedsConversion):
        return None


def stop(username: str) -> bool:
    """End the session. Returns whether there was one."""
    was = _ask(username, b"stop") is not None
    try:
        os.remove(session_path(username))
    except OSError:
        pass
    return was


# ---------------------------------------------------------------------------
# The agent itself
# ---------------------------------------------------------------------------
def _not_dumpable() -> None:
    """Linux: no core dump, and no other process of this user reads the
    memory through /proc or ptrace."""
    if sys.platform.startswith("linux"):
        try:
            import ctypes
            ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)      # PR_SET_DUMPABLE
        except (OSError, AttributeError):
            pass


def serve() -> None:
    _not_dumpable()
    payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    path, until = payload.pop("session"), payload["until"]
    key = secrets.token_bytes(32)
    folder = None
    if os.name == "nt":
        address = r"\\.\pipe\SecretSpace-cli-" + secrets.token_hex(16)
        listener = Listener(address, "AF_PIPE", authkey=key)
    else:
        # A short path (a socket's may not be longer than 107 bytes), in a
        # folder only this user can enter.
        folder = tempfile.mkdtemp(prefix="secretspace-cli-",
                                  dir=os.environ.get("XDG_RUNTIME_DIR") or None)
        address = os.path.join(folder, "s")
        listener = Listener(address, "AF_UNIX", authkey=key)
    # mkstemp inside: the file is this user's only from the start.
    vault._write_file_atomic(path, json.dumps(
        {"address": address, "key": key.hex(), "until": until}).encode())

    def tidy():
        try:
            with open(path, encoding="utf-8") as f:
                ours = json.load(f).get("address") == address
            if ours:                    # not one that was started since
                os.remove(path)
        except (OSError, ValueError, AttributeError):
            pass
        if folder:
            shutil.rmtree(folder, ignore_errors=True)

    started, span = time.monotonic(), until - time.time()

    def clock():
        # Both clocks: one set back must not lengthen a session, and a PC
        # that slept must not either.
        while time.time() < until and time.monotonic() - started < span:
            time.sleep(0.5)
        tidy()
        os._exit(0)

    threading.Thread(target=clock, daemon=True).start()
    answer = json.dumps(payload).encode("utf-8")
    sys.stdout.buffer.write(b"ready\n")
    sys.stdout.buffer.flush()
    sys.stdout.close()

    def handle(connection):
        try:
            if connection.poll(ANSWER_SECONDS):
                question = connection.recv_bytes(64)
                if question == b"keys":
                    connection.send_bytes(answer)
                elif question == b"stop":
                    # Before the answer: whoever asked deletes the file too,
                    # and on Windows the two would be in each other's way.
                    tidy()
                    connection.send_bytes(b"ok")
                    connection.close()
                    os._exit(0)
        except (OSError, EOFError, ValueError):
            pass
        finally:
            connection.close()

    while True:
        try:
            connection = listener.accept()
        except (OSError, EOFError, AuthenticationError, ValueError):
            time.sleep(0.05)            # a stranger, or one that hung up
            continue
        threading.Thread(target=handle, args=(connection,),
                         daemon=True).start()
