"""
End to end: two PCs, one real server, over a real socket.

The merge is unit-tested in test_sync.py. What this file checks is everything
around it -- that the blob survives the round trip, that the revision check
actually stops a blind overwrite, and above all that a deletion on one PC
does not come back from the other on the next sync, which is the failure mode
the whole design exists to prevent.
"""

import os
import sys
import json
import hashlib
import threading
import contextlib

import pytest

# A copy of the server, from PassMan-Server-Windows / PassMan-Server-Linux
# (sync_server/README.md says how to refresh it).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "sync_server"))

import vault                                                    # noqa: E402
import crypto_utils                                             # noqa: E402
import sync                                                     # noqa: E402
import sync_client                                              # noqa: E402
import passman_server                                           # noqa: E402

TOKEN = "test-token-that-is-long-enough"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """
    600k PBKDF2 iterations are the point in production and a waste here: this
    file does dozens of encrypt/decrypt round trips and would spend a minute
    inside the KDF. Both encrypt and decrypt go through derive_key, so one
    stub keeps them consistent.
    """
    def quick(master_password, salt, iterations=1000):
        return hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt,
                                   1000, dklen=32)
    monkeypatch.setattr(crypto_utils, "derive_key", quick)


@pytest.fixture
def server(tmp_path):
    """A real ThreadingHTTPServer on a free port, torn down after the test."""
    httpd = passman_server.ThreadingHTTPServer(
        ("127.0.0.1", 0), passman_server.Handler)
    httpd.store = passman_server.Store(str(tmp_path / "store"))
    httpd.token = TOKEN
    os.makedirs(httpd.store.root, exist_ok=True)

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


class PC:
    """One machine: its own vault directory, its own copy of the vault."""

    def __init__(self, data_dir, url, username="alice", password="master-pw"):
        self.data_dir = str(data_dir)
        self.url = url
        self.username = username
        self.password = password
        self.vault = None

    @contextlib.contextmanager
    def at_keyboard(self):
        """Point the vault module at THIS machine's data directory."""
        previous = os.environ.get("PASSMAN_DATA_DIR")
        os.environ["PASSMAN_DATA_DIR"] = self.data_dir
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop("PASSMAN_DATA_DIR", None)
            else:
                os.environ["PASSMAN_DATA_DIR"] = previous

    def create(self):
        with self.at_keyboard():
            vault.create_new_user(self.username, self.password)
            self.vault = vault.load_vault(self.password, self.username)
        return self

    def add(self, site, username="u", password="p"):
        with self.at_keyboard():
            entry = vault.add_account(self.vault, site, username, password)
            vault.save_vault(self.password, self.vault, self.username)
        return entry

    def edit(self, entry_id, password):
        with self.at_keyboard():
            entry = vault.find_entry(self.vault, entry_id)
            entry["password"] = password
            vault.touch(entry)
            vault.save_vault(self.password, self.vault, self.username)

    def archive(self, entry_id):
        with self.at_keyboard():
            vault.archive_account(self.vault, entry_id)
            vault.save_vault(self.password, self.vault, self.username)

    def session(self):
        client = sync_client.SyncClient(self.url, TOKEN)
        return sync_client.SyncSession(client, self.username, self.password)

    def sync(self, choices=None, server_password=None, drop_history=False):
        """A full sync, as the Sync button will do it -- including following
        a password change, as the GUI does once the user has answered."""
        with self.at_keyboard():
            session = self.session()
            result = session.prepare(self.vault, server_password)
            self.vault = session.commit(self.vault, choices, drop_history)
            if session.password_changed:
                self.password = session.master_password
            return result

    def change_password(self, new, sync=True, drop_history=False):
        """What the Change master password dialog does."""
        old = self.password
        with self.at_keyboard():
            sync_client.note_password_change(self.vault)
            vault.change_master_password(self.vault, self.username, old, new)
        self.password = new
        if sync:
            return self.sync(server_password=old, drop_history=drop_history)

    def opens_with(self, password):
        """Whether this PC's vault files open with ``password``."""
        with self.at_keyboard():
            try:
                vault.load_vault(password, self.username)
                return True
            except ValueError:
                return False

    def prepare(self):
        """Pull and merge, but stop before committing -- the dialog's moment."""
        with self.at_keyboard():
            session = self.session()
            return session, session.prepare(self.vault)

    def restore_from_server(self):
        """The first-run path on a second PC: no local vault at all."""
        with self.at_keyboard():
            client = sync_client.SyncClient(self.url, TOKEN)
            fetched, revision = sync_client.download_vault(
                client, self.username, self.password)
            vault.create_new_user(self.username, self.password)
            vault.save_vault(self.password, fetched, self.username)
            vault.save_base(self.password, fetched, self.username,
                            origin=sync_client.base_origin_for(self.url,
                                                               revision))
            self.vault = fetched
        return self

    def sites(self):
        return sorted(a["site"] for a in vault.active_accounts(self.vault))

    def archived_sites(self):
        return sorted(a["site"] for a in vault.archived_accounts(self.vault))


@pytest.fixture
def two_pcs(server, tmp_path):
    pc1 = PC(tmp_path / "pc1", server).create()
    pc2 = PC(tmp_path / "pc2", server)
    return pc1, pc2


# --- the round trip -------------------------------------------------------
def test_health_needs_no_token(server):
    client = sync_client.SyncClient(server, "")
    assert client.health()["ok"] is True


def test_a_bad_token_is_refused(server):
    client = sync_client.SyncClient(server, "wrong-token")
    with pytest.raises(sync_client.SyncError, match="token"):
        client.meta("alice")


def test_an_unreachable_server_says_so_plainly():
    client = sync_client.SyncClient("http://127.0.0.1:1", "t", timeout=2)
    with pytest.raises(sync_client.SyncError, match="Could not reach"):
        client.meta("alice")


def test_the_server_never_receives_a_readable_password(two_pcs, server, tmp_path):
    """The blob on disk server-side must not contain the plaintext."""
    pc1, _ = two_pcs
    pc1.add("github", "u", "hunter2-in-the-clear")
    pc1.sync()

    stored = (tmp_path / "store" / "alice" / "vault.enc").read_bytes()
    assert b"hunter2-in-the-clear" not in stored
    assert b"github" not in stored


def test_a_second_pc_picks_up_the_whole_vault(two_pcs):
    pc1, pc2 = two_pcs
    pc1.add("github")
    pc1.add("gmail")
    pc1.sync()

    pc2.restore_from_server()

    assert pc2.sites() == ["github", "gmail"]


# --- the case the design exists for --------------------------------------
def test_an_archived_entry_does_not_come_back_from_the_other_pc(two_pcs):
    """
    PC1 deletes an entry. PC2 has not touched it. Sync both ways twice. With a
    two-way merge the entry reappears on PC1 every time; it must not here.
    """
    pc1, pc2 = two_pcs
    github = pc1.add("github")
    pc1.add("gmail")
    pc1.sync()
    pc2.restore_from_server()

    pc1.archive(github["id"])
    pc1.sync()
    pc2.sync()

    assert pc2.sites() == ["gmail"]
    assert pc2.archived_sites() == ["github"]

    # And it stays gone when the vaults go round again.
    pc1.sync()
    pc2.sync()
    assert pc1.sites() == ["gmail"]
    assert pc2.sites() == ["gmail"]


def test_an_archived_entry_can_be_restored_and_that_propagates_too(two_pcs):
    pc1, pc2 = two_pcs
    github = pc1.add("github")
    pc1.sync()
    pc2.restore_from_server()

    pc1.archive(github["id"])
    pc1.sync()
    pc2.sync()
    assert pc2.sites() == []

    with pc1.at_keyboard():
        vault.restore_account(pc1.vault, github["id"])
        vault.save_vault(pc1.password, pc1.vault, pc1.username)
    pc1.sync()
    pc2.sync()

    assert pc2.sites() == ["github"]


# --- ordinary two-way traffic --------------------------------------------
def test_additions_on_both_sides_survive(two_pcs):
    pc1, pc2 = two_pcs
    pc1.add("github")
    pc1.sync()
    pc2.restore_from_server()

    pc1.add("from-pc1")
    pc2.add("from-pc2")
    pc1.sync()
    pc2.sync()
    pc1.sync()

    assert pc1.sites() == ["from-pc1", "from-pc2", "github"]
    assert pc2.sites() == ["from-pc1", "from-pc2", "github"]


def test_an_edit_on_one_side_reaches_the_other(two_pcs):
    pc1, pc2 = two_pcs
    github = pc1.add("github", "u", "old")
    pc1.sync()
    pc2.restore_from_server()

    pc1.edit(github["id"], "rotated")
    pc1.sync()
    pc2.sync()

    assert vault.find_entry(pc2.vault, github["id"])["password"] == "rotated"


def test_syncing_twice_with_nothing_to_do_changes_nothing(two_pcs):
    pc1, _ = two_pcs
    pc1.add("github")
    pc1.sync()

    result = pc1.sync()

    assert result.clean
    assert not result.changed
    assert result.summary() == "already up to date"


# --- conflicts ------------------------------------------------------------
def test_both_sides_editing_the_same_entry_stops_for_the_user(two_pcs):
    pc1, pc2 = two_pcs
    github = pc1.add("github", "u", "old")
    pc1.sync()
    pc2.restore_from_server()

    pc1.edit(github["id"], "changed-on-pc1")
    pc2.edit(github["id"], "changed-on-pc2")
    pc1.sync()

    _session, result = pc2.prepare()

    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.local["password"] == "changed-on-pc2"
    assert conflict.remote["password"] == "changed-on-pc1"


@pytest.mark.parametrize("choice,expected_live", [
    (sync.KEEP_LOCAL, "changed-on-pc2"),
    (sync.KEEP_REMOTE, "changed-on-pc1"),
])
def test_resolving_a_conflict_keeps_the_loser_in_its_history(
        two_pcs, choice, expected_live):
    pc1, pc2 = two_pcs
    github = pc1.add("github", "u", "old")
    pc1.sync()
    pc2.restore_from_server()

    pc1.edit(github["id"], "changed-on-pc1")
    pc2.edit(github["id"], "changed-on-pc2")
    pc1.sync()

    session, result = pc2.prepare()
    with pc2.at_keyboard():
        pc2.vault = session.commit(pc2.vault, {github["id"]: choice})

    [kept] = vault.active_accounts(pc2.vault)
    assert kept["password"] == expected_live
    assert vault.archived_accounts(pc2.vault) == [], "nothing archived now"
    loser = kept["history"][0]["password"]
    assert loser != expected_live and loser.startswith("changed-on-"), \
        "the version not chosen must still be there"

    pc1.sync()                       # and it reaches the other PC too
    assert vault.find_entry(pc1.vault, github["id"])["history"][0]["password"] \
        == loser


def test_keeping_both_sides_of_a_conflict_gives_two_entries(two_pcs):
    pc1, pc2 = two_pcs
    github = pc1.add("github", "u", "old")
    pc1.sync()
    pc2.restore_from_server()

    pc1.edit(github["id"], "changed-on-pc1")
    pc2.edit(github["id"], "changed-on-pc2")
    pc1.sync()

    session, _result = pc2.prepare()
    with pc2.at_keyboard():
        pc2.vault = session.commit(pc2.vault, {github["id"]: sync.KEEP_BOTH})
    pc1.sync()

    assert sorted(a["password"] for a in vault.active_accounts(pc1.vault)) == [
        "changed-on-pc1", "changed-on-pc2"]


# --- the revision check ---------------------------------------------------
def test_a_stale_push_is_refused_rather_than_overwriting(two_pcs):
    """
    Both PCs prepared against revision N; the first commit wins and the second
    must be told to merge again instead of clobbering it.
    """
    pc1, pc2 = two_pcs
    pc1.add("github")
    pc1.sync()
    pc2.restore_from_server()

    # Both PCs make a local change and then prepare, so both are holding a
    # merge computed against the same revision.
    pc1.add("added-by-pc1")
    pc2.add("added-by-pc2")
    session1, _ = pc1.prepare()
    session2, _ = pc2.prepare()

    with pc1.at_keyboard():
        session1.commit(pc1.vault)          # first one home wins

    with pytest.raises(sync_client.Conflict409):
        with pc2.at_keyboard():
            session2.commit(pc2.vault)


def test_nothing_is_lost_when_a_stale_push_is_retried(two_pcs):
    pc1, pc2 = two_pcs
    pc1.add("github")
    pc1.sync()
    pc2.restore_from_server()

    pc2.add("added-by-pc2")
    session2, _ = pc2.prepare()

    pc1.add("added-by-pc1")
    pc1.sync()                              # pc2's prepared revision is now stale

    with pytest.raises(sync_client.Conflict409):
        with pc2.at_keyboard():
            session2.commit(pc2.vault)

    pc2.sync()          # the retry the GUI performs
    pc1.sync()

    assert pc1.sites() == ["added-by-pc1", "added-by-pc2", "github"]


def test_editing_the_vault_mid_sync_is_refused_rather_than_dropped(two_pcs):
    """
    commit() applies the list prepare() computed, so a local edit made in
    between would vanish. The GUI holds a modal dialog across that gap and
    cannot reach it -- which is precisely why it must fail loudly instead of
    being left to trust.
    """
    pc1, _ = two_pcs
    pc1.add("github")
    pc1.sync()

    session, _ = pc1.prepare()
    pc1.add("added-after-prepare")

    with pytest.raises(sync_client.SyncError, match="changed while"):
        with pc1.at_keyboard():
            session.commit(pc1.vault)

    pc1.sync()
    assert "added-after-prepare" in pc1.sites()


def test_a_pull_only_sync_does_not_burn_a_revision(two_pcs):
    pc1, pc2 = two_pcs
    pc1.add("github")
    pc1.sync()
    pc2.restore_from_server()

    pc1.add("only-on-pc1")
    pc1.sync()
    client = sync_client.SyncClient(pc1.url, TOKEN)
    before = client.meta("alice")["revision"]

    pc2.sync()          # pc2 has nothing of its own to send

    assert client.meta("alice")["revision"] == before
    assert "only-on-pc1" in pc2.sites()


def test_the_first_sync_actually_uploads(two_pcs):
    """
    Regression: nothing changes locally on a first sync, and an earlier
    version read that as "already up to date" and uploaded nothing at all.
    """
    pc1, _ = two_pcs
    pc1.add("github")
    client = sync_client.SyncClient(pc1.url, TOKEN)
    assert client.meta("alice")["revision"] == 0

    result = pc1.sync()

    assert result.changed and result.needs_push
    assert client.meta("alice")["revision"] == 1


def test_the_revision_advances_by_one_per_push(two_pcs):
    pc1, _ = two_pcs
    client = sync_client.SyncClient(pc1.url, TOKEN)

    assert client.meta("alice")["revision"] == 0
    pc1.add("github")
    pc1.sync()
    assert client.meta("alice")["revision"] == 1
    pc1.add("gmail")
    pc1.sync()
    assert client.meta("alice")["revision"] == 2


def test_the_server_keeps_previous_revisions(two_pcs, tmp_path):
    pc1, _ = two_pcs
    pc1.add("github")
    pc1.sync()
    pc1.add("gmail")
    pc1.sync()

    history = tmp_path / "store" / "alice" / "history"
    assert len(list(history.glob("*.enc"))) == 1


# --- the server's own guards ---------------------------------------------
def test_a_wrong_master_password_is_a_clear_message_not_a_crash(two_pcs):
    pc1, pc2 = two_pcs
    pc1.add("github")
    pc1.sync()

    pc2.password = "not-the-master-password"
    with pc2.at_keyboard():
        client = sync_client.SyncClient(pc2.url, TOKEN)
        with pytest.raises(sync_client.SyncError, match="master password"):
            sync_client.fetch_vault(client, "alice", pc2.password)


@pytest.mark.parametrize("bad", ["../../etc/passwd", "a/b", "con"])
def test_the_server_rejects_dangerous_usernames(server, bad):
    client = sync_client.SyncClient(server, TOKEN)
    with pytest.raises(sync_client.SyncError):
        client.meta(bad)


def test_the_server_refuses_a_body_that_is_not_a_vault(server):
    client = sync_client.SyncClient(server, TOKEN)
    with pytest.raises(sync_client.SyncError):
        client.push("alice", b"bm90LWEtdmF1bHQ=", 0)     # valid b64, too short


def test_an_empty_store_reports_revision_zero_rather_than_failing(server):
    client = sync_client.SyncClient(server, TOKEN)
    blob, revision = client.pull("nobody-yet")
    assert blob is None and revision == 0


# ==========================================================================
# Changing the master password
# ==========================================================================
def server_opens_with(tmp_path, password, user="alice"):
    """Whether the copy the server holds decrypts with ``password``."""
    blob = (tmp_path / "store" / user / "vault.enc").read_bytes()
    try:
        crypto_utils.decrypt(password, blob)
        return True
    except ValueError:
        return False


@pytest.fixture
def synced(two_pcs):
    """Two PCs agreeing on one vault, as after a normal first setup."""
    pc1, pc2 = two_pcs
    pc1.add("github", "u", "p")
    pc1.sync()
    pc2.restore_from_server()
    return pc1, pc2


def test_a_password_change_reaches_the_server_under_the_new_password(
        synced, tmp_path):
    """Regression: the change was local only and every later sync failed."""
    pc1, _ = synced
    pc1.change_password("new-pw")

    assert server_opens_with(tmp_path, "new-pw")
    assert not server_opens_with(tmp_path, "master-pw")
    assert pc1.sync().clean, "syncing afterwards is back to normal"


def test_the_other_pc_is_told_the_password_changed_elsewhere(synced):
    pc1, pc2 = synced
    pc1.change_password("new-pw")

    with pytest.raises(sync_client.PasswordMismatch) as caught:
        pc2.sync()

    assert caught.value.adopt, "the server is ahead, so PC2 should follow it"
    assert not caught.value.wrong


def test_adopting_the_new_password_switches_this_pc_over(synced):
    pc1, pc2 = synced
    pc1.change_password("new-pw")

    pc2.sync(server_password="new-pw")

    assert pc2.password == "new-pw"
    assert pc2.opens_with("new-pw")
    # Not the main file, and not the .bak either -- load_vault falls back to
    # it, so a stale backup would keep the old password working on PC2.
    assert not pc2.opens_with("master-pw")
    assert pc2.sites() == ["github"]
    assert pc2.sync().clean and pc1.sync().clean


@pytest.mark.parametrize("changed_here", [True, False])
def test_a_password_catch_up_counts_as_work_even_with_no_edits(
        synced, changed_here):
    """
    Regression guard for the GUI: it skips commit when there is nothing to do.
    After a password change the entries usually match exactly, and skipping
    the commit then would leave sync failing on every attempt.
    """
    pc1, pc2 = synced
    if changed_here:
        pc1.change_password("new-pw", sync=False)
        who, answer = pc1, "master-pw"
    else:
        pc1.change_password("new-pw")
        who, answer = pc2, "new-pw"

    with who.at_keyboard():
        session = who.session()
        result = session.prepare(who.vault, answer)

    assert result.clean and result.pulled == 0, "no content changes at all"
    assert session.has_work()


def test_a_wrong_password_in_the_prompt_is_reported_as_wrong(synced):
    pc1, pc2 = synced
    pc1.change_password("new-pw")

    with pytest.raises(sync_client.PasswordMismatch) as caught:
        pc2.sync(server_password="not-it")

    assert caught.value.wrong
    assert pc2.opens_with("master-pw"), "a failed attempt changes nothing"


def test_a_password_changed_offline_is_uploaded_on_the_next_sync(
        synced, tmp_path):
    """Changed while the server was unreachable: the server is BEHIND."""
    pc1, pc2 = synced
    pc1.change_password("new-pw", sync=False)

    with pytest.raises(sync_client.PasswordMismatch) as caught:
        pc1.sync()
    assert not caught.value.adopt, "this PC is ahead; it must not adopt"

    pc1.sync(server_password="master-pw")

    assert pc1.password == "new-pw", "PC1 keeps the password it chose"
    assert server_opens_with(tmp_path, "new-pw")
    pc2.sync(server_password="new-pw")
    assert pc2.opens_with("new-pw")


def test_when_both_pcs_change_it_the_first_to_the_server_wins(synced, tmp_path):
    pc1, pc2 = synced
    pc1.change_password("pc1-pw")
    pc2.change_password("pc2-pw", sync=False)

    with pytest.raises(sync_client.PasswordMismatch) as caught:
        pc2.sync()
    assert caught.value.adopt, "the server already has PC1's change"

    pc2.sync(server_password="pc1-pw")

    assert pc2.password == "pc1-pw"
    assert server_opens_with(tmp_path, "pc1-pw")


def test_edits_on_both_sides_merge_quietly_across_a_password_change(synced):
    """
    The base is carried across the change, so a one-sided edit on each PC is
    still recognised as one-sided -- no wall of conflicts for the user.
    """
    pc1, pc2 = synced
    github = vault.find_entry(pc1.vault, pc1.vault["accounts"][0]["id"])
    pc2.add("added-on-pc2")
    pc2.sync()
    pc1.edit(github["id"], "edited-on-pc1")

    result = pc1.change_password("new-pw")
    assert result.clean

    result = pc2.sync(server_password="new-pw")
    assert result.clean
    assert pc2.sites() == ["added-on-pc2", "github"]
    assert vault.find_entry(pc2.vault, github["id"])["password"] == "edited-on-pc1"


def test_pending_edits_on_the_catching_up_pc_are_kept(synced):
    pc1, pc2 = synced
    pc2.add("added-on-pc2-before-it-knew")
    pc1.change_password("new-pw")

    result = pc2.sync(server_password="new-pw")

    assert result.clean
    pc1.sync()
    assert pc1.sites() == ["added-on-pc2-before-it-knew", "github"]


def test_old_password_history_is_dropped_only_when_asked(synced, tmp_path):
    pc1, _ = synced
    history = tmp_path / "store" / "alice" / "history"
    pc1.add("second")
    pc1.sync()
    assert list(history.glob("*.enc")), "a normal sync keeps history"

    pc1.change_password("kept-pw")
    assert list(history.glob("*.enc")), "not dropped unless asked"

    pc1.change_password("dropped-pw", drop_history=True)
    assert not list(history.glob("*.enc"))


def test_editing_the_address_keeps_the_password_generation():
    """
    Regression: set_settings replaced the whole settings dict, resetting the
    generation to 0. The next change would then look OLDER than the server's
    copy, and this PC would be told to adopt its own previous password.
    """
    data = {"accounts": []}
    sync_client.set_settings(data, "http://a:1", "tok")
    sync_client.note_password_change(data)
    sync_client.note_password_change(data)

    sync_client.set_settings(data, "http://b:2", "tok")

    assert sync_client.key_generation(data) == 2
    assert sync_client.get_settings(data)["url"] == "http://b:2"


def test_a_store_from_before_key_generations_reads_as_zero(tmp_path):
    """Upgrading the server must not change how an existing vault reads."""
    store = passman_server.Store(str(tmp_path / "store"))
    (tmp_path / "store" / "alice").mkdir(parents=True)
    (tmp_path / "store" / "alice" / "meta.json").write_text(
        json.dumps({"revision": 3, "sha256": "x", "updated_at": "", "size": 1}))

    assert store.meta("alice")["key_generation"] == 0


def test_the_server_rejects_a_nonsense_generation(server):
    client = sync_client.SyncClient(server, TOKEN)
    blob = __import__("base64").b64encode(b"PMV2" + b"\0" * 60)
    with pytest.raises(sync_client.SyncError):
        client._request("PUT", "/vault/alice", body={"blob": blob.decode()},
                        headers={"X-PassMan-Key-Generation": "-3"})


# ==========================================================================
# Revision history across PCs
# ==========================================================================
def _revise(pc, entry_id, **fields):
    """An edit through the same path the edit dialog uses."""
    with pc.at_keyboard():
        assert vault.update_entry(vault.find_entry(pc.vault, entry_id), **fields)
        vault.save_vault(pc.password, pc.vault, pc.username)


def test_an_edits_history_reaches_the_other_pc(synced):
    pc1, pc2 = synced
    eid = pc1.vault["accounts"][0]["id"]
    _revise(pc1, eid, password="v2")
    pc1.sync()

    pc2.sync()

    [rev] = vault.find_entry(pc2.vault, eid)["history"]
    assert rev["password"] == "p"


def test_a_cleared_history_is_cleared_everywhere(synced):
    """The other PC must not hand the cleared revisions back."""
    pc1, pc2 = synced
    eid = pc1.vault["accounts"][0]["id"]
    _revise(pc1, eid, password="v2")
    pc1.sync()
    pc2.sync()
    assert vault.find_entry(pc2.vault, eid).get("history")

    with pc1.at_keyboard():
        vault.clear_history(vault.find_entry(pc1.vault, eid))
        vault.save_vault(pc1.password, pc1.vault, pc1.username)
    assert pc1.sync().needs_push, "a clear alone must still be uploaded"
    pc2.sync()
    pc1.sync()

    assert "history" not in vault.find_entry(pc1.vault, eid)
    assert "history" not in vault.find_entry(pc2.vault, eid)


def test_histories_settle_and_stop_syncing(synced):
    """Two PCs exchanging history must converge, not trade copies forever."""
    pc1, pc2 = synced
    eid = pc1.vault["accounts"][0]["id"]
    pc2.add("other")
    other = pc2.vault["accounts"][-1]["id"]
    _revise(pc1, eid, password="v2")
    _revise(pc2, other, password="w2")
    for pc in (pc1, pc2, pc1, pc2):
        pc.sync()

    assert vault.history_signature(vault.find_entry(pc1.vault, eid)) == \
        vault.history_signature(vault.find_entry(pc2.vault, eid))
    for pc in (pc1, pc2):
        with pc.at_keyboard():
            session = pc.session()
            session.prepare(pc.vault)
            assert not session.has_work(), f"{pc.data_dir} still finds work"


def test_reverting_syncs_as_an_ordinary_edit(synced):
    pc1, pc2 = synced
    eid = pc1.vault["accounts"][0]["id"]
    _revise(pc1, eid, password="v2")
    with pc1.at_keyboard():
        acc = vault.find_entry(pc1.vault, eid)
        vault.revert_entry(acc, acc["history"][0]["rid"])
        vault.save_vault(pc1.password, pc1.vault, pc1.username)
    pc1.sync()

    result = pc2.sync()

    assert result.clean
    acc2 = vault.find_entry(pc2.vault, eid)
    assert acc2["password"] == "p"
    assert [r["password"] for r in acc2["history"]] == ["v2"]


def test_a_history_clear_from_the_other_pc_counts_as_work(synced):
    """The GUI only commits when the session says there is work."""
    pc1, pc2 = synced
    eid = pc1.vault["accounts"][0]["id"]
    _revise(pc1, eid, password="v2")
    pc1.sync()
    pc2.sync()
    with pc1.at_keyboard():
        vault.clear_history(vault.find_entry(pc1.vault, eid))
        vault.save_vault(pc1.password, pc1.vault, pc1.username)
    pc1.sync()

    with pc2.at_keyboard():
        session = pc2.session()
        session.prepare(pc2.vault)
        assert session.has_work()


# ==========================================================================
# The server losing a vault
# ==========================================================================
def test_a_vault_removed_on_the_server_is_uploaded_again_not_wiped(
        synced, tmp_path):
    """
    Regression: with the vault folder deleted on the server, the next sync
    read every entry as "deleted on the other side" and emptied this PC.
    """
    import shutil
    pc1, pc2 = synced
    pc1.add("second")
    pc1.sync()
    shutil.rmtree(tmp_path / "store" / "alice")

    result = pc1.sync()

    assert pc1.sites() == ["github", "second"], "nothing deleted on the PC"
    assert result.needs_push and result.stats["removed"] == 0
    assert server_opens_with(tmp_path, "master-pw"), "uploaded again"

    pc2.sync()                         # the other PC is unaffected
    assert pc2.sites() == ["github", "second"]


def test_moving_to_a_brand_new_server_uploads_the_vault(synced, tmp_path):
    """Same situation from the other side: a new, empty server."""
    pc1, _ = synced
    fresh_store = passman_server.Store(str(tmp_path / "new-store"))
    httpd = passman_server.ThreadingHTTPServer(
        ("127.0.0.1", 0), passman_server.Handler)
    httpd.store, httpd.token = fresh_store, TOKEN
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        pc1.url = f"http://127.0.0.1:{httpd.server_address[1]}"
        pc1.sync()
        assert pc1.sites() == ["github"]
        assert fresh_store.exists("alice")
    finally:
        httpd.shutdown()
        httpd.server_close()


def _purge(pc, entry_id):
    with pc.at_keyboard():
        vault.purge_account(pc.vault, entry_id)
        vault.save_vault(pc.password, pc.vault, pc.username)


def test_a_real_deletion_still_reaches_the_other_pc(synced):
    """
    The fix must not stop genuine deletions from propagating. A real one
    goes through the Archive: archived, synced, then purged.
    """
    pc1, pc2 = synced
    eid = pc1.vault["accounts"][0]["id"]
    pc1.archive(eid)
    pc1.sync()
    pc2.sync()
    _purge(pc1, eid)
    pc1.sync()

    result = pc2.sync()

    assert result.clean and result.stats["removed"] == 1
    assert pc2.vault["accounts"] == []


def test_a_live_entry_purged_elsewhere_is_put_to_the_user(synced):
    """
    Purged on one PC while the other still had it live -- not something the
    app offers, but if it happens the other PC asks, and keeps it by default.
    """
    pc1, pc2 = synced
    _purge(pc1, pc1.vault["accounts"][0]["id"])
    pc1.sync()

    _session, result = pc2.prepare()
    assert [c.kind for c in result.conflicts] == ["missing"]

    pc2.sync()
    assert pc2.sites() == ["github"]


# ==========================================================================
# One vault, two servers
# ==========================================================================
@contextlib.contextmanager
def another_server(path):
    """A second, independent server -- the Ubuntu box beside the Windows one."""
    httpd = passman_server.ThreadingHTTPServer(
        ("127.0.0.1", 0), passman_server.Handler)
    httpd.store = passman_server.Store(str(path))
    httpd.token = TOKEN
    os.makedirs(httpd.store.root, exist_ok=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _switch(pc, url):
    """What editing the address in Settings -> Sync does."""
    pc.url = url
    sync_client.set_settings(pc.vault, url, TOKEN)


def test_switching_to_a_server_with_an_older_copy_deletes_nothing(
        synced, tmp_path):
    """
    Regression (Windows 2.4.0, Linux 0.3.0): the owner's vault held two entries on the Windows
    server; the Ubuntu server still had the one from days earlier. Syncing
    with Ubuntu removed the second entry from the PC without a word.
    """
    pc1, _ = synced
    windows = pc1.url
    with another_server(tmp_path / "ubuntu") as ubuntu:
        _switch(pc1, ubuntu)
        pc1.sync()                                  # Ubuntu: github only
        _switch(pc1, windows)
        pc1.add("second")
        pc1.sync()                                  # Windows: both

        _switch(pc1, ubuntu)
        session, result = pc1.prepare()

        assert session.base_ignored
        assert result.stats["removed"] == 0 and result.clean
        pc1.sync()
        assert pc1.sites() == ["github", "second"]

        _switch(pc1, windows)                       # and back: still both
        pc1.sync()
        assert pc1.sites() == ["github", "second"]


def test_switching_servers_does_not_revert_an_edit(synced, tmp_path):
    """
    The case the deletion prompt cannot catch: the other server's copy of an
    entry is simply older. With the Windows base it read as "changed on the
    server" and silently replaced the newer password.
    """
    pc1, _ = synced
    windows = pc1.url
    eid = pc1.vault["accounts"][0]["id"]
    with another_server(tmp_path / "ubuntu") as ubuntu:
        _switch(pc1, ubuntu)
        pc1.sync()                                  # Ubuntu: password "p"
        _switch(pc1, windows)
        pc1.edit(eid, "newer")
        pc1.sync()                                  # Windows: "newer"

        _switch(pc1, ubuntu)
        _session, result = pc1.prepare()

        assert [c.kind for c in result.conflicts] == ["edit"]
        pc1.sync({eid: sync.KEEP_LOCAL})
        assert vault.find_entry(pc1.vault, eid)["password"] == "newer"


def test_after_a_switch_the_new_server_becomes_the_base(synced, tmp_path):
    """Once agreed with the new server, merges there trust the base again."""
    pc1, _ = synced
    with another_server(tmp_path / "ubuntu") as ubuntu:
        _switch(pc1, ubuntu)
        pc1.sync()
        session, _result = pc1.prepare()

        assert not session.base_ignored
        assert not session.has_work()


def test_a_switch_with_nothing_to_merge_still_records_the_new_server(
        synced, tmp_path):
    pc1, _ = synced
    windows = pc1.url
    with another_server(tmp_path / "ubuntu") as ubuntu:
        _switch(pc1, ubuntu)
        pc1.sync()
        _switch(pc1, windows)
        session, _result = pc1.prepare()

        assert session.base_ignored and session.has_work()
        pc1.sync()
        with pc1.at_keyboard():
            origin = vault.base_origin(vault.load_base(pc1.password, "alice"))
        assert origin["url"] == windows


def test_a_server_restored_from_an_older_backup_is_not_trusted(
        synced, tmp_path):
    """Same address, but the revision went backwards: the base is newer
    than anything the server now holds."""
    import shutil
    pc1, _ = synced
    store = tmp_path / "store" / "alice"
    saved = tmp_path / "server-backup"
    shutil.copytree(store, saved)
    pc1.add("second")
    pc1.sync()
    pc1.add("third")
    pc1.sync()
    shutil.rmtree(store)
    shutil.copytree(saved, store)                   # back to one entry

    session, result = pc1.prepare()

    assert session.base_ignored
    assert result.stats["removed"] == 0


def test_a_restored_pc_records_where_it_restored_from(synced):
    _pc1, pc2 = synced
    with pc2.at_keyboard():
        origin = vault.base_origin(vault.load_base(pc2.password, "alice"))
    assert origin == {"url": pc2.url, "revision": 1}


@pytest.mark.parametrize("origin,url,revision,trusted", [
    ({}, "http://b", 1, True),                                 # pre-2.5.0 base
    ({"url": "http://a", "revision": 3}, "http://a", 3, True),
    ({"url": "http://a", "revision": 3}, "http://a/", 5, True),
    ({"url": "http://A", "revision": 3}, "http://a", 3, True),
    ({"url": "http://a", "revision": 3}, "http://b", 3, False),
    ({"url": "http://a", "revision": 3}, "http://a", 2, False),
])
def test_base_matches(origin, url, revision, trusted):
    base = {"accounts": []}
    if origin:
        base[vault.BASE_ORIGIN_KEY] = origin
    assert sync_client.base_matches(base, url, revision) is trusted
