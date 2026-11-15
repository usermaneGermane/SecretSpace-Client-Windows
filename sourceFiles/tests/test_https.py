"""
Turning HTTPS on for a server the account already syncs with.

The server's setup makes a certificate and the server answers on the same
address and port, now with https://. The app is then told the new address
and the certificate file. That is the same server: what this device knows
about its vaults there -- each vault's agreed state (the sync base), its key
generation, its role -- must survive, or the next sync merges without a
base and can quietly bring back entries that were deleted.
"""

import os
import shutil
import socket
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "sync_server"))

import account_sync                                             # noqa: E402
import accounts                                                 # noqa: E402
import sync_client                                              # noqa: E402
import vault                                                    # noqa: E402
import secretspace_server                                       # noqa: E402
from sync_client import SyncError                               # noqa: E402

from test_account_sync import (PW, TOKEN, cheap_argon2, device,  # noqa: F401
                               new_account)
from test_account_vaults import put_entry, sites, sync_all, sync_vault

OPENSSL = shutil.which("openssl")


# ---------------------------------------------------------------------------
# Which addresses are the same server
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("a,b,same", [
    ("http://10.0.0.3:59872", "https://10.0.0.3:59872", True),
    ("http://10.0.0.3:59872/", "https://10.0.0.3:59872", True),
    ("http://Server.LAN:8787", "https://server.lan:8787", True),
    ("http://10.0.0.3:59872", "https://10.0.0.3:59873", False),
    ("http://10.0.0.3:59872", "https://10.0.0.4:59872", False),
    ("http://10.0.0.3", "https://10.0.0.3", False),        # ports 80 and 443
    ("https://10.0.0.3", "https://10.0.0.3:443", True),
    ("http://10.0.0.3:8787/a", "http://10.0.0.3:8787/b", False),
    ("", "http://10.0.0.3:8787", False),
    (None, None, False),
])
def test_which_addresses_are_the_same_server(a, b, same):
    assert sync_client.same_server(a, b) is same


def test_a_base_from_before_https_is_trusted_after_it():
    base = {"accounts": [], vault.BASE_ORIGIN_KEY:
            sync_client.base_origin_for("http://10.0.0.3:59872", 4)}
    assert sync_client.base_matches(base, "https://10.0.0.3:59872", 4)
    assert not sync_client.base_matches(base, "https://10.0.0.9:59872", 4)
    assert not sync_client.base_matches(base, "https://10.0.0.3:59872", 3)


# ---------------------------------------------------------------------------
# The real switch: one server, first plain, then with TLS on the same port
# ---------------------------------------------------------------------------
class Server:
    """The test copy of the server on a fixed port, startable twice."""

    def __init__(self, root):
        self.root = root
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.httpd = None

    def start(self, tls=None):
        httpd = secretspace_server.bind("127.0.0.1", self.port, 1)
        httpd.store = secretspace_server.Store(os.path.join(self.root, "store"))
        httpd.token = TOKEN
        os.makedirs(httpd.store.root, exist_ok=True)
        if tls:
            httpd.ssl_context = secretspace_server.tls_context(*tls)
        threading.Thread(target=httpd.serve_forever,
                         kwargs={"poll_interval": 0.01}, daemon=True).start()
        self.httpd = httpd
        return f"{'https' if tls else 'http'}://127.0.0.1:{self.port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def certificate(folder):
    cert = os.path.join(folder, "server.crt")
    key = os.path.join(folder, "server.key")
    made = subprocess.run(
        [OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt",
         "ec_paramgen_curve:prime256v1", "-nodes", "-sha256", "-days", "30",
         "-keyout", key, "-out", cert, "-subj", "/CN=SecretSpace sync server",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
         "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
         "-addext", "keyUsage=critical,digitalSignature,keyCertSign",
         "-addext", "extendedKeyUsage=serverAuth"],
        capture_output=True, text=True)
    assert made.returncode == 0, made.stderr
    return cert, key


@pytest.fixture
def switched(tmp_path, device):
    """alice syncs a vault Team over plain HTTP, the vault gets a new key
    (generation 1), then the server is restarted with HTTPS on the same port
    and alice is told the new address and certificate."""
    if OPENSSL is None:
        pytest.skip("no openssl here")
    server = Server(str(tmp_path / "srv"))
    url = server.start()
    alice = new_account().save()
    assert account_sync.connect(alice, url, "", TOKEN) == "created"
    team = alice.create_vault("Team").hex
    for site in ("Router", "Printer", "Old"):
        put_entry(alice, team, site)
    put_entry(alice, None, "Mail")
    sync_all(alice)
    session = account_sync.logged_in(alice)
    try:
        account_sync.change_key(alice, session, team,
                                alice.vault_file(team).load())
    finally:
        session.logout()
    sync_all(alice)
    before = alice.vault_record(team)
    server.stop()

    cert, key = certificate(str(tmp_path))
    https = server.start((cert, key))
    alice = accounts.unlock("alice", PW)
    assert account_sync.connect(alice, https, cert, "") == "joined"
    try:
        yield alice, team, before, https, cert
    finally:
        server.stop()


def test_the_vaults_records_survive_the_switch(switched):
    alice, team, before, https, cert = switched
    assert alice.server == {"url": https, "ca_file": cert}
    after = alice.vault_record(team)
    for key in ("on_server", "key_generation", "role", "key_signer"):
        assert after.get(key) == before.get(key), key
    assert after["key_generation"] == 1


def test_the_first_sync_over_https_uses_the_agreed_state(switched):
    """A deletion made on this device right after the switch must reach the
    server, not be undone by a merge that has lost its base."""
    alice, team, _, _, _ = switched
    file = alice.vault_file(team)
    data = file.load()
    data["accounts"] = [e for e in data["accounts"] if e["site"] != "Old"]
    file.save(data)
    session = account_sync.AccountSync(alice, None, team)
    try:
        result = session.prepare(file.load())
        assert session.base_ignored is False
        assert not result.conflicts
        session.commit(file.load())
    finally:
        session.close()
    assert sites(alice, team) == ["Printer", "Router"]
    # ... and the server has it that way: a fresh device sees it so.
    sync_all(alice)
    assert sites(alice, team) == ["Printer", "Router"]


def test_every_vault_syncs_over_https_with_nothing_to_ask(switched):
    alice, team, _, _, _ = switched
    changes = sync_all(alice)
    assert not changes.rekeyed and not changes.gone and not changes.added
    assert sites(alice) == ["Mail"]
    assert sites(alice, team) == ["Old", "Printer", "Router"]


def test_without_the_certificate_file_the_app_refuses_the_server(switched):
    alice, _, _, https, _ = switched
    with pytest.raises(SyncError):
        account_sync.connect(alice, https, "", "")


def test_a_certificate_that_is_not_the_servers_is_refused(switched, tmp_path):
    alice, _, _, https, _ = switched
    other = tmp_path / "other"
    other.mkdir()
    impostor, _ = certificate(str(other))
    with pytest.raises(SyncError):
        account_sync.connect(alice, https, impostor, "")


def test_another_server_still_starts_the_vaults_afresh(switched):
    """The rule that keeps a base from another server out still holds."""
    alice, team, _, _, _ = switched
    alice.set_server("https://10.9.9.9:4443", "")
    assert alice.vault_record(team).get("key_generation") is None
    assert alice.vault_record(team).get("on_server") is None
