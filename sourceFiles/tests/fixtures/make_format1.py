"""
How the folder ``format1/`` beside this file was made. Not a test, and not
run by the tests: it needs the source of SecretSpace **3.1.0**.

The conversion to the current format must be proved on accounts that the
old program really wrote, not on ones the new program pretends are old. So
this script was run once, with the 3.1.0 source on the path, and what it
left behind is kept:

    git worktree add <somewhere> v3.1.0
    py -3 make_format1.py <somewhere>/sourceFiles <output folder>

What it makes, all with SecretSpace 3.1.0 and its copy of server 2.0.0:

    a/accounts/alice    on the server. Personal vault: Mail, Bank.
                        Vault "Team" (she owns it; bob is an editor):
                        Router (hers), Printer (bob's).
                        Vault "Solo" (hers alone, on the server): Notes.
    b/accounts/bob      on the server. Personal vault: Forum. Member of Team.
    c/accounts/carol    never on a server. Personal vault: Diary.
                        Vault "Box" (local only): Spare key.
    store/              the server's store after all of it was synced
    facts.json          passwords, Secret Keys, recovery phrases, vault ids

The Secret Key is stored under the master password on every "device"
(``secret_store.SCHEME_PASSWORD``), not with Windows DPAPI, so the fixture
opens on any machine. The Argon2id cost is the cheapest allowed, so the
tests are quick; the cost is in each file's header, as always.
"""

import copy
import json
import os
import shutil
import sys
import threading

SOURCE, OUT = sys.argv[1], os.path.abspath(sys.argv[2])
sys.path.insert(0, SOURCE)
sys.path.insert(0, os.path.join(SOURCE, "tests", "sync_server"))

import account_crypto                                           # noqa: E402
import account_sync                                             # noqa: E402
import accounts                                                 # noqa: E402
import changelog                                                # noqa: E402
import secret_store                                             # noqa: E402
import vault                                                    # noqa: E402
import version                                                  # noqa: E402
import passman_server                                           # noqa: E402

assert version.__version__ == "3.1.0", version.__version__
account_crypto.ARGON2_MEMORY_KIB = 64
account_crypto.ARGON2_PASSES = 1
secret_store.default_scheme = lambda: secret_store.SCHEME_PASSWORD

TOKEN = "fixture-token-that-is-long-enough"
PASSWORDS = {"alice": "correct horse battery staple",
             "bob": "bob's own master password",
             "carol": "carol never syncs"}

if os.path.exists(OUT):
    shutil.rmtree(OUT)
os.makedirs(OUT)


def device(name):
    os.environ["PASSMAN_DATA_DIR"] = os.path.join(OUT, name, "data")


def add(account, vault_id, site, password):
    file = account.vault_file(vault_id)
    before = file.load()
    data = copy.deepcopy(before)
    vault.add_account(data, site, "me", password)
    changelog.record(data, before, account.username, account.keyset, file.hex)
    file.save(data)


def sync_all(account):
    server = account_sync.logged_in(account)
    try:
        account_sync.reconcile_vaults(account, server)
        ids = account_sync.syncable_vaults(account, server)
    finally:
        server.logout()
    for vault_id in ids:
        session = account_sync.AccountSync(account, None, vault_id)
        try:
            local = session.file.load() if session.file.has_file \
                else {"accounts": []}
            result = session.prepare(local)
            assert not result.conflicts
            if session.has_work():
                session.commit(local)
        finally:
            session.close()


httpd = passman_server.ThreadingHTTPServer(("127.0.0.1", 0),
                                           passman_server.Handler)
httpd.store = passman_server.Store(os.path.join(OUT, "store"))
httpd.token = TOKEN
os.makedirs(httpd.store.root)
threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.01},
                 daemon=True).start()
url = f"http://127.0.0.1:{httpd.server_address[1]}"
facts = {"made_with": version.__version__, "token": TOKEN, "url": url,
         "accounts": {}}


def make(name, on_server=True):
    new = accounts.prepare_account(name, PASSWORDS[name])
    account = new.save()
    facts["accounts"][name] = {
        "password": PASSWORDS[name], "secret_key": new.secret_key_text,
        "phrase": new.recovery_phrase, "personal_vault": account.personal_id,
        "public_key": account.info["public_key"],
        "signing_key": account.signing_key, "fingerprint": account.fingerprint,
        "recovery_proof": account_crypto._b64(
            account_crypto.recovery_proof(account.keyset))}
    if on_server:
        assert account_sync.connect(account, url, "", TOKEN) == "created"
    return account


device("a")
alice = make("alice")
add(alice, None, "Mail", "mail-password")
add(alice, None, "Bank", "bank-password")
team = alice.create_vault("Team").hex
add(alice, team, "Router", "router-password")
solo = alice.create_vault("Solo").hex
add(alice, solo, "Notes", "notes-password")
sync_all(alice)

device("b")
bob = make("bob")
add(bob, None, "Forum", "forum-password")
sync_all(bob)

device("a")
server = account_sync.logged_in(alice)
try:
    keys = account_sync.lookup_contact(alice, server, "bob")
    account_sync.share_vault(alice, server, team, keys, accounts.ROLE_EDITOR)
finally:
    server.logout()
sync_all(alice)

device("b")
sync_all(bob)
add(bob, team, "Printer", "printer-password")
sync_all(bob)

device("a")
sync_all(alice)

device("c")
carol = make("carol", on_server=False)
add(carol, None, "Diary", "diary-password")
box = carol.create_vault("Box").hex
add(carol, box, "Spare key", "spare-password")

facts["vaults"] = {"Team": team, "Solo": solo, "Box": box}
facts["entries"] = {
    "alice": {"personal": ["Bank", "Mail"], "Team": ["Printer", "Router"],
              "Solo": ["Notes"]},
    "bob": {"personal": ["Forum"], "Team": ["Printer", "Router"]},
    "carol": {"personal": ["Diary"], "Box": ["Spare key"]}}
httpd.shutdown()
httpd.server_close()

# Nothing the fixture needs: sessions, and the empty 2.x data folders.
shutil.rmtree(os.path.join(OUT, "store", "_v2", "sessions"), ignore_errors=True)
for name in "abc":
    shutil.rmtree(os.path.join(OUT, name, "data"), ignore_errors=True)
with open(os.path.join(OUT, "facts.json"), "w", encoding="utf-8",
          newline="\n") as f:
    json.dump(facts, f, indent=2, sort_keys=True)
    f.write("\n")
print("made", OUT)
