"""
The MCP server: ``secretspace-cli mcp``, started by an AI tool.

Speaks the Model Context Protocol over stdin / stdout (JSON-RPC, one message
a line). It opens no vault: it asks the unlocked app (ai_access), which asks
the user. Two tools, and neither gives the model a secret:

``list_entries``      the entries of the vaults marked for AI, no secrets;
``run_with_secrets``  run a command with fields as environment variables;
                      the output comes back with them taken out.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import threading

import ai_access
import version

PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
OUTPUT_CHARS = 50_000
DEFAULT_SECONDS, MAX_SECONDS = 120, 600

INSTRUCTIONS = (
    "SecretSpace is the user's password manager. Use run_with_secrets when a "
    "command needs a credential, instead of asking for it or writing it into "
    "a .env or other file. You never see the values: they are environment "
    "variables of the command only. The user sees the exact command and "
    "allows or refuses it. Do not try to print, encode or store the values.")

TOOLS = [
    {"name": "list_entries",
     "description": "The credentials the user has made available to AI: id, "
                    "name, username, web address, vault and which fields each "
                    "has. Never their secrets.",
     "inputSchema": {"type": "object", "properties": {
         "search": {"type": "string",
                    "description": "only entries with this in their name, "
                                   "username or web address"}},
         "additionalProperties": False}},
    {"name": "run_with_secrets",
     "description": "Run one command with credentials as environment "
                    "variables. The user is asked to allow it, every time. "
                    "Returns exit code and output, with the credentials "
                    "replaced by [hidden]. No shell: for a pipe or $VAR, make "
                    "a shell the command, e.g. [\"sh\", \"-c\", \"...\"].",
     "inputSchema": {"type": "object", "properties": {
         "command": {"type": "array", "items": {"type": "string"},
                     "minItems": 1,
                     "description": "the program and its arguments"},
         "env": {"type": "object", "description":
                 "variable name -> which field of which entry",
                 "additionalProperties": {
                     "type": "object", "properties": {
                         "entry": {"type": "string", "description":
                                   "the entry's id from list_entries"},
                         "field": {"type": "string",
                                   "enum": list(ai_access.FIELDS),
                                   "default": "password"}},
                     "required": ["entry"]}},
         "cwd": {"type": "string", "description": "folder to run it in"},
         "reason": {"type": "string",
                    "description": "shown to the user: what it is for"},
         "timeout_seconds": {"type": "integer", "minimum": 1,
                             "maximum": MAX_SECONDS,
                             "default": DEFAULT_SECONDS}},
         "required": ["command", "env"], "additionalProperties": False}}]


class BadCall(Exception):
    """JSON-RPC: invalid params."""


def run_command(command, values, cwd, seconds) -> dict:
    """{"exit_code", "output", "timed_out"}; the output still unredacted."""
    env = dict(os.environ)
    if os.name == "nt":                 # names there ignore case
        taken = {name.upper() for name in values}
        env = {k: v for k, v in env.items() if k.upper() not in taken}
    env.update(values)
    program = shutil.which(command[0], path=env.get("PATH")) or command[0]
    options = {"creationflags": subprocess.CREATE_NO_WINDOW
               | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" \
        else {"start_new_session": True}
    try:
        child = subprocess.Popen(
            [program, *command[1:]], env=env, cwd=cwd or None,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, **options)
    except (OSError, ValueError) as e:
        raise ai_access.Refused(f"It could not be started: {e}") from None
    pieces, size = [], 0

    def read():
        # To the end, or a full pipe would stop the program; but only so
        # much is kept.
        nonlocal size
        for piece in iter(lambda: child.stdout.read1(65536), b""):
            if size < 4 * OUTPUT_CHARS:
                pieces.append(piece)
                size += len(piece)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    timed_out = False
    try:
        child.wait(seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
    if timed_out:
        _kill(child)
    # A program it left running may keep the pipe open: do not wait for it.
    reader.join(5)
    return {"exit_code": child.returncode, "timed_out": timed_out,
            "output": b"".join(list(pieces)).decode("utf-8", "replace")}


def _kill(child):
    """The program and what it started."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(child.pid)],
                           capture_output=True, timeout=10,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            os.killpg(child.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    child.kill()
    try:
        child.wait(5)
    except subprocess.TimeoutExpired:
        pass


class Server:
    def __init__(self, account=None, ask=ai_access.ask):
        self._account, self._ask = account, ask
        self.client = "unknown"

    def _username(self):
        if self._account:
            return self._account
        there = ai_access.open_accounts()
        if len(there) == 1:
            return there[0]
        raise ai_access.Refused(
            "Several accounts are open for AI: start the server with "
            "--account NAME." if there else ai_access._CLOSED)

    # -- the tools ------------------------------------------------------------
    def list_entries(self, args):
        found = self._ask(self._username(), {"ask": "list",
                                             "client": self.client})["entries"]
        text = args.get("search", "")
        if not isinstance(text, str):
            raise BadCall("search is text")
        text = text.casefold()
        return json.dumps([e for e in found if any(
            text in e[k].casefold() for k in ("name", "username", "url"))],
            indent=1, ensure_ascii=False)

    def run_with_secrets(self, args):
        seconds = args.get("timeout_seconds", DEFAULT_SECONDS)
        if not isinstance(seconds, int) or isinstance(seconds, bool) \
                or not 1 <= seconds <= MAX_SECONDS:
            raise BadCall(f"timeout_seconds is 1 to {MAX_SECONDS}")
        request = ai_access.check_request({**args, "client": self.client})
        # What the user is shown is where it runs, also if none was given.
        request["cwd"] = os.path.abspath(request["cwd"] or os.getcwd())
        if not os.path.isdir(request["cwd"]):
            raise ai_access.Refused("There is no folder " + request["cwd"])
        values = self._ask(self._username(), {"ask": "use", **request})["values"]
        done = run_command(request["command"], values, request["cwd"], seconds)
        secret = [v for name, v in values.items()
                  if request["env"][name]["field"] in ai_access.SECRET_FIELDS]
        output = ai_access.hide(done["output"], secret)
        if len(output) > OUTPUT_CHARS:
            output = output[:OUTPUT_CHARS] + "\n[cut]"
        head = f"exit code {done['exit_code']}"
        if done["timed_out"]:
            head = f"stopped after {seconds} s"
        return head + "\n" + output

    # -- the protocol ---------------------------------------------------------
    def handle(self, message):
        """The reply to one message, or None (a notification, a response)."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" \
                or "method" in message and not isinstance(message["method"], str):
            return self._error(None, -32600, "Invalid Request")
        if "method" not in message or "id" not in message:
            return None
        mid, method = message["id"], message["method"]
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return self._error(mid, -32602, "params must be an object")
        if method == "initialize":
            info = params.get("clientInfo")
            if isinstance(info, dict) and isinstance(info.get("name"), str):
                self.client = info["name"][:60]
            asked = params.get("protocolVersion")
            return self._result(mid, {
                "protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "secretspace",
                               "version": version.__version__},
                "instructions": INSTRUCTIONS})
        if method == "ping":
            return self._result(mid, {})
        if method == "tools/list":
            return self._result(mid, {"tools": TOOLS})
        if method == "tools/call":
            return self._call(mid, params)
        return self._error(mid, -32601, "Method not found")

    def _call(self, mid, params):
        tool = {"list_entries": self.list_entries,
                "run_with_secrets": self.run_with_secrets}.get(
                    params.get("name") if isinstance(params.get("name"), str)
                    else None)
        args = params.get("arguments") or {}
        if tool is None or not isinstance(args, dict):
            return self._error(mid, -32602, "Unknown tool or arguments")
        try:
            text, wrong = tool(args), False
        except BadCall as e:
            return self._error(mid, -32602, str(e))
        except ai_access.Refused as e:
            text, wrong = str(e), True
        except Exception:
            # Not its text: that might hold something of the command's.
            text, wrong = "Something went wrong in SecretSpace.", True
        return self._result(mid, {"content": [{"type": "text", "text": text}],
                                  "isError": wrong})

    @staticmethod
    def _result(mid, result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    @staticmethod
    def _error(mid, code, text):
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": code, "message": text}}


def serve(account=None, source=None, sink=None) -> None:
    source, sink = source or sys.stdin.buffer, sink or sys.stdout.buffer
    server = Server(account)
    for line in iter(source.readline, b""):
        if not line.strip():
            continue
        try:
            reply = server.handle(json.loads(line.decode("utf-8")))
        except (ValueError, RecursionError):
            reply = server._error(None, -32700, "Parse error")
        if reply is not None:
            try:
                sink.write(json.dumps(reply).encode("utf-8") + b"\n")
                sink.flush()
            except OSError:
                return                  # the AI tool is gone
