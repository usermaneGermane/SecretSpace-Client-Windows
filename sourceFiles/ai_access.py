"""
AI agents and the open account: what the app lets them ask, and the log.

The unlocked app is the only one that answers. The MCP server
(mcp_server.py, a program the AI tool starts) asks it over a local pipe;
nothing is stored that could open a vault without the app. Two questions:

``list``  the entries of the vaults marked for AI on this device, without
          their secrets;
``use``   some fields of them, for one command the user sees and allows in a
          window of the app -- every time. They go to the MCP server, which
          gives them to that command as environment variables and takes them
          out of its output. The AI model never gets them from here.

Like the memory of the app itself, this is no wall against programs that
already run as the same user, and an allowed command can do anything with
what it is given: the window shows what will run, the user decides.
"""

import json
import os
import re
import secrets
import shutil
import tempfile
import threading
from multiprocessing import AuthenticationError
from multiprocessing.connection import Client, Listener

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import account_crypto
import accounts
import vault

#: Fields a command can be given, and those of them that are secret.
FIELDS = ("password", "username", "url", "notes", "otp")
SECRET_FIELDS = ("password", "notes", "otp")
#: How long the window waits for the user.
DECIDE_SECONDS = 60
#: How long a program may take to say what it wants.
ASK_SECONDS = 5
MESSAGE_BYTES = 64 * 1024
COMMAND_CHARS = 4000
MAX_VARIABLES = 20
LOG_LINES = 200
_VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
#: Variables that change what is run rather than tell it something.
_NOT_FOR_SECRETS = re.compile(
    r"PATH|PATHEXT|COMSPEC|SHELL|IFS|HOME|USERPROFILE|BASH_ENV|ENV|LD_.*|"
    r"DYLD_.*|PYTHON.*|NODE_.*|PERL.*|RUBY.*|JAVA_.*|GIT_.*|SECRETSPACE_.*",
    re.IGNORECASE)


class Refused(Exception):
    """Told to the AI as it is."""


def session_path(username: str) -> str:
    return os.path.join(accounts.accounts_dir(),
                        "." + vault.validate_username(username) + ".ai")


# ---------------------------------------------------------------------------
# Which vaults
# ---------------------------------------------------------------------------
def allowed_vaults(account) -> list:
    """The vaults marked for AI on this device."""
    found = account.info.get("ai_vaults")
    if not isinstance(found, list):
        return []
    return [v for v in account.vault_ids() if v in found]


def allow_vault(account, vault_id: str, on: bool) -> None:
    info = dict(account.info)
    keep = [v for v in allowed_vaults(account) if v != vault_id]
    info["ai_vaults"] = keep + [vault_id] if on else keep
    accounts._write_info(account.username, info)
    account.info = info


# ---------------------------------------------------------------------------
# The log, on this device only
# ---------------------------------------------------------------------------
def _log_path(username):
    return os.path.join(accounts.account_dir(username), "ai-log.ssl")


def _log_cipher(account):
    return AESGCM(account_crypto._hkdf(account._vault_key, b"",
                                       b"SecretSpace AI log"))


def read_log(account) -> list:
    """Newest last: {"at", "client", "what", "result"}. No secret is in it."""
    try:
        with open(_log_path(account.username), "rb") as f:
            raw = f.read()
        lines = json.loads(_log_cipher(account).decrypt(
            raw[:12], raw[12:], account.vault_id))
        return [x for x in lines if isinstance(x, dict)]
    except Exception:
        return []                       # none yet, or damaged: start again


def add_to_log(account, client: str, what: str, result: str) -> None:
    lines = read_log(account)
    lines.append({"at": vault.utc_now(), "client": client, "what": what,
                  "result": result})
    raw = json.dumps(lines[-LOG_LINES:]).encode("utf-8")
    nonce = os.urandom(12)
    vault._write_file_atomic(
        _log_path(account.username),
        nonce + _log_cipher(account).encrypt(nonce, raw, account.vault_id))


# ---------------------------------------------------------------------------
# The two questions
# ---------------------------------------------------------------------------
def describe(account, vaults: dict) -> list:
    out = []
    for vault_id in allowed_vaults(account):
        for entry in vault.active_accounts(vaults.get(vault_id)
                                           or {"accounts": []}):
            out.append({"id": entry["id"], "name": entry["site"],
                        "username": entry["username"],
                        "url": entry.get("url", ""),
                        "vault": account.vault_file(vault_id).name,
                        "fields": [f for f in FIELDS if entry.get(
                            "totp" if f == "otp" else f)]})
    return out


def check_request(request: dict) -> dict:
    """A ``use`` question as it must be, or Refused."""
    command, cwd = request.get("command"), request.get("cwd") or ""
    if not isinstance(command, list) or not command or \
            not all(isinstance(c, str) and c and "\0" not in c for c in command):
        raise Refused("command must be a list of strings: the program and its "
                      "arguments.")
    # What cannot be shown whole cannot be agreed to.
    if sum(len(c) for c in command) > COMMAND_CHARS:
        raise Refused(f"The command is longer than {COMMAND_CHARS} characters.")
    if not isinstance(cwd, str) or "\0" in cwd or len(cwd) > 1000:
        raise Refused("cwd must be a folder.")
    wanted = request.get("env")
    if not isinstance(wanted, dict) or not wanted or len(wanted) > MAX_VARIABLES:
        raise Refused(f"env must name 1 to {MAX_VARIABLES} variables.")
    clean, seen = {}, set()
    for name, what in wanted.items():
        if not _VARIABLE.fullmatch(name) or _NOT_FOR_SECRETS.fullmatch(name) \
                or name.upper() in seen:
            raise Refused(f"“{name[:80]}” cannot be a variable for a secret.")
        seen.add(name.upper())
        if not isinstance(what, dict) or not isinstance(what.get("entry"), str) \
                or what.get("field", "password") not in FIELDS:
            raise Refused(f"{name}: give an entry's id and a field, one of "
                          + ", ".join(FIELDS) + ".")
        clean[name] = {"entry": what["entry"],
                       "field": what.get("field", "password")}
    return {"command": command, "cwd": cwd, "env": clean,
            "client": str(request.get("client") or "unknown")[:60],
            "reason": str(request.get("reason") or "")[:300]}


def find_entries(account, vaults: dict, env: dict) -> dict:
    """variable -> (vault id, entry), only from the vaults marked for AI."""
    found = {}
    for name, what in env.items():
        for vault_id in allowed_vaults(account):
            entry = vault.find_entry(vaults.get(vault_id)
                                     or {"accounts": []}, what["entry"])
            if entry is not None and not vault.is_archived(entry):
                found[name] = (vault_id, entry)
                break
        else:
            raise Refused(f"{name}: there is no such entry in a vault marked "
                          "for AI. list_entries gives the ids.")
        field = what["field"]
        if not entry.get("totp" if field == "otp" else field):
            raise Refused(f"{name}: that entry has no {field}.")
    return found


def values_of(found: dict, env: dict) -> dict:
    import totp
    out = {}
    for name, (_, entry) in found.items():
        field = env[name]["field"]
        if field == "otp":
            try:
                value = totp.code(totp.parse(entry["totp"]))
            except ValueError:
                raise Refused(f"{name}: the 2FA secret cannot be used.") from None
        else:
            value = entry[field]
        if "\0" in value:
            raise Refused(f"{name}: its value cannot be a variable.")
        out[name] = value
    return out


# ---------------------------------------------------------------------------
# The app's end of the pipe
# ---------------------------------------------------------------------------
class Door:
    """Open while an account with a vault marked for AI is."""

    def __init__(self, username: str, answer):
        """``answer(request)`` runs on a worker thread; returns a dict or
        raises Refused."""
        self._answer = answer
        self._path = session_path(username)
        self._key = secrets.token_bytes(32)
        self._folder = None
        self._open = True
        if os.name == "nt":
            self.address = r"\\.\pipe\SecretSpace-ai-" + secrets.token_hex(16)
            self._listener = Listener(self.address, "AF_PIPE", authkey=self._key)
        else:
            self._folder = tempfile.mkdtemp(
                prefix="secretspace-ai-",
                dir=os.environ.get("XDG_RUNTIME_DIR") or None)
            self.address = os.path.join(self._folder, "s")
            self._listener = Listener(self.address, "AF_UNIX",
                                      authkey=self._key)
        vault._write_file_atomic(self._path, json.dumps(
            {"address": self.address, "key": self._key.hex()}).encode())
        threading.Thread(target=self._listen, daemon=True).start()

    def close(self) -> None:
        if not self._open:
            return
        self._open = False
        try:
            with open(self._path, encoding="utf-8") as f:
                ours = json.load(f).get("address") == self.address
            if ours:
                os.remove(self._path)
        except (OSError, ValueError, AttributeError):
            pass
        # Closing a listener does not wake an accept() that waits: knock.
        def knock():
            try:
                Client(self.address, authkey=self._key).close()
            except Exception:
                pass
            try:
                self._listener.close()
            except Exception:
                pass
            if self._folder:
                shutil.rmtree(self._folder, ignore_errors=True)
        threading.Thread(target=knock, daemon=True).start()

    def _listen(self):
        import time
        while self._open:
            try:
                connection = self._listener.accept()
            except (OSError, EOFError, AuthenticationError, ValueError):
                time.sleep(0.05)
                continue
            if not self._open:
                connection.close()
                return
            threading.Thread(target=self._handle, args=(connection,),
                             daemon=True).start()

    def _handle(self, connection):
        try:
            if not connection.poll(ASK_SECONDS):
                return
            try:
                request = json.loads(connection.recv_bytes(MESSAGE_BYTES))
                if not isinstance(request, dict):
                    raise ValueError
                reply = self._answer(request)
            except Refused as e:
                reply = {"refused": str(e)}
            except (ValueError, UnicodeDecodeError, RecursionError):
                reply = {"refused": "The question was not understood."}
            if not self._open:
                reply = {"refused": "SecretSpace was locked."}
            connection.send_bytes(json.dumps(reply).encode("utf-8"))
        except (OSError, EOFError):
            pass                        # hung up
        finally:
            connection.close()


# ---------------------------------------------------------------------------
# The other end
# ---------------------------------------------------------------------------
_CLOSED = ("SecretSpace is not open for AI. The user has to unlock the "
           "SecretSpace app and mark a vault for AI (Vaults, AI).")


def ask(username: str, request: dict) -> dict:
    """Ask the open app. Refused when it says no or is not there."""
    try:
        with open(session_path(username), encoding="utf-8") as f:
            found = json.load(f)
        with Client(str(found["address"]),
                    authkey=bytes.fromhex(found["key"])) as c:
            c.send_bytes(json.dumps(request).encode("utf-8"))
            if not c.poll(DECIDE_SECONDS + 15):
                raise Refused("SecretSpace did not answer.")
            reply = json.loads(c.recv_bytes())
    except (OSError, EOFError, ValueError, KeyError, TypeError,
            AuthenticationError):
        raise Refused(_CLOSED) from None
    if "refused" in reply:
        raise Refused(reply["refused"])
    return reply


def open_accounts() -> list:
    return [name for name in accounts.list_accounts()
            if os.path.isfile(session_path(name))]


def hide(text: str, values) -> str:
    """``text`` without the values, also as they are often encoded. A help
    against accidents: a program can always write one some other way."""
    import base64
    import urllib.parse
    forms = set()
    # A key of many lines may come out with something before each of them.
    values = list(values)
    values += [line.strip() for v in values for line in v.splitlines()
               if line.strip() != v and len(line.strip()) >= 8]
    for value in values:
        # A very short one would blank out half the output, hiding nothing.
        if len(value) < 3:
            continue
        raw = value.encode("utf-8")
        forms |= {value, json.dumps(value)[1:-1],
                  json.dumps(value, ensure_ascii=False)[1:-1],
                  urllib.parse.quote(value, safe=""), urllib.parse.quote(value),
                  urllib.parse.quote_plus(value), raw.hex(), raw.hex().upper()}
        for r in (raw, raw + b"\n"):
            forms |= {base64.b64encode(r).decode(),
                      base64.b64encode(r).decode().rstrip("="),
                      base64.urlsafe_b64encode(r).decode()}
    for form in sorted(forms, key=len, reverse=True):
        text = text.replace(form, "[hidden]")
    return text
