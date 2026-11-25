"""
CI only: does the installed command line work? Run with its path, on a PC
that has no account in %APPDATA%\\SecretSpace (it makes one).

There is no keyboard in CI, so the session a command needs is started by
this script -- but the session itself is the installed program.
"""

import os
import subprocess
import sys

EXE = sys.argv[1]
HOME = os.path.join(os.environ["APPDATA"], "SecretSpace")
if not os.environ.get("CI") or os.path.exists(os.path.join(HOME, "accounts")):
    sys.exit("only for CI, on a PC without accounts")
# Where the installed program looks by itself.
os.environ["SECRETSPACE_DATA_DIR"] = os.path.join(HOME, "vault")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "sourceFiles"))
import accounts                                                 # noqa: E402
import cli_agent                                                # noqa: E402
import vault                                                    # noqa: E402

account = accounts.prepare_account("ci", "only for this check").save()
data = account.load_vault()
vault.add_account(data, "Mail", "me", "p\u00e4ss")
account.save_vault(data)
env = {k: v for k, v in os.environ.items() if k != "SECRETSPACE_DATA_DIR"}


def run(*args, code=0, **kw):
    done = subprocess.run([EXE, *args], capture_output=True, env=env,
                          timeout=60, **kw)
    print(args, done.returncode, done.stdout, done.stderr, flush=True)
    assert done.returncode == code
    return done.stdout


assert b"SecretSpace" in run("--version")
assert b"locked" in run("status")
assert b"ci" in run("accounts")
# Without a session and without a keyboard: refused, and it does not hang.
run("list", code=1, creationflags=subprocess.DETACHED_PROCESS,
    stdin=subprocess.DEVNULL)

cli_agent._command = lambda: [EXE, cli_agent.AGENT_ARGUMENT]
cli_agent.start(account, 5)
assert b"unlocked for" in run("status")
assert b"Mail" in run("list")
assert run("get", "Mail") == "p\u00e4ss".encode("utf-8")
run("add", "Bank", "--username", "me", "--generate", "30")
assert len(run("get", "Bank")) == 30
run("archive", "Bank")
assert b"Bank" not in run("list")
assert b"Locked: ci" in run("lock")
assert b"locked" in run("status")
cli_agent.start(account, 5)         # left running: uninstalling must end it
print("the installed command line works")
