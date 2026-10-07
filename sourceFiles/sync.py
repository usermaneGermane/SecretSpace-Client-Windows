"""
Three-way merge of two copies of a vault.

Everything here is a pure function over plain dicts: no network, no files, no
crypto. The transport in sync_client.py decides *when* to merge; this module
decides *what* the answer is, which makes the hard part testable without a
server.

Why three versions and not two
------------------------------
Comparing the local vault with the server's cannot tell you what happened.
"Present on the server, absent here" is both "they added it" and "I removed
it", and those want opposite outcomes. The third input is the *base*: this
vault as it stood at the end of the last successful sync (vault.load_base).
With it, the side that actually changed is a fact rather than a guess -- no
clock comparison required, which matters because the two PCs' clocks
disagree.

``updated_at`` is therefore never consulted for a merge decision. It is
carried for display, so the conflict dialog can say "edited here 20 minutes
ago, on the server three weeks ago".

Nothing is ever dropped
-----------------------
A conflict resolved as "keep theirs" keeps our version as an earlier revision
of the entry, and vice versa; "keep both" keeps two live entries. Every
outcome this module can produce is reversible from the entry's history, so a
wrong click costs a revert, not a password.

History never conflicts
-----------------------
Revision history is not compared at all. Whichever side's fields win, the
merged entry carries the union of both sides' histories, normalised so every
PC computes the same list (vault.normalize_history). A difference in history
alone is still synced, in both directions, but never asks a question.
"""

from vault import (is_archived, new_id, utc_now, snapshot, changed_fields,
                   add_revision, merge_history, history_signature)

#: What makes two versions of an entry "the same". ``id`` is identity rather
#: than content, and ``updated_at`` is a note about when, not what -- comparing
#: it would turn "we both made the same edit" into a conflict. ``history`` is
#: merged, never compared.
CONTENT_FIELDS = ("site", "username", "password", "notes", "totp", "archived_at")

#: Conflict resolutions.
KEEP_LOCAL = "local"
KEEP_REMOTE = "remote"
KEEP_BOTH = "both"

#: What an unresolved conflict does. Keeping both sides is the only choice
#: that cannot lose anything, so it is what happens if the dialog is somehow
#: bypassed.
DEFAULT_RESOLUTION = KEEP_BOTH


def content(entry: dict) -> tuple:
    """
    The part of an entry a merge compares.

    For ``archived_at`` only whether it is set counts, not when. Two PCs that
    both archived the same entry agree on what happened; comparing the
    timestamps made that an "edited on both sides" conflict.
    """
    values = [str(entry.get(f, "") or "") for f in CONTENT_FIELDS
              if f != "archived_at"]
    values.append("archived" if is_archived(entry) else "")
    return tuple(values)


def same(a: dict, b: dict) -> bool:
    return content(a) == content(b)


def _newer(a: dict, b: dict) -> dict:
    """
    Of two entries with identical content, the one to keep.

    Only their ``updated_at`` differs, which changes nothing that matters --
    but picking deterministically means both PCs compute the same merged
    vault, instead of trading cosmetically different copies forever.
    """
    return a if str(a.get("updated_at", "")) >= str(b.get("updated_at", "")) else b


class Conflict:
    """
    One entry both sides changed, left for the user to settle.

    ``kind`` is a hint for the dialog's wording, not a behaviour switch:

    ``edit``    both sides edited the entry
    ``archive`` one side archived it while the other edited it
    ``purge``   one side purged it outright while the other edited it
    """

    def __init__(self, entry_id, base, local, remote, kind="edit"):
        self.id = entry_id
        self.base = base
        self.local = local
        self.remote = remote
        self.kind = kind

    @property
    def site(self) -> str:
        for candidate in (self.local, self.remote, self.base):
            if candidate:
                return candidate.get("site", "")
        return ""

    def __repr__(self):
        return f"<Conflict {self.kind} {self.site!r} id={self.id[:8]}>"


class MergeResult:
    """
    ``accounts``  the entries that merged without a question being asked
    ``conflicts`` the ones that need the user
    ``stats``     what changed locally, for the summary line

    ``accounts`` is NOT the final vault: the conflicting entries are missing
    from it until :func:`resolve` puts them back.
    """

    def __init__(self, accounts, conflicts, stats):
        self.accounts = accounts
        self.conflicts = conflicts
        self.stats = stats

    @property
    def clean(self) -> bool:
        """True when the merge needs nothing from the user."""
        return not self.conflicts

    @property
    def pulled(self) -> int:
        """How many entries this merge changes locally."""
        return sum(self.stats[k]
                   for k in ("new", "updated", "archived", "removed"))

    @property
    def needs_push(self) -> bool:
        """
        True when the server's copy is behind ours.

        Tracked separately from :attr:`pulled` because the two are genuinely
        independent, and conflating them is a silent no-op on the most
        important sync of all: the very first one, where nothing changes
        locally and the entire vault has to be uploaded.
        """
        return (bool(self.conflicts) or self.stats["push"] > 0
                or self.stats["history_out"] > 0)

    @property
    def changed(self) -> bool:
        """
        True when there is any work to do, in either direction -- including a
        difference in revision history alone, which no field shows but which
        still has to reach both sides.
        """
        return (self.needs_push or self.pulled > 0
                or self.stats["history_in"] > 0)

    def summary(self) -> str:
        """One line for the toast / dialog header."""
        bits = [(self.stats["new"], "added"),
                (self.stats["updated"], "updated"),
                (self.stats["archived"], "archived"),
                (self.stats["removed"], "removed")]
        parts = [f"{n} {label}" for n, label in bits if n]
        if self.stats["push"]:
            parts.append(f"{self.stats['push']} uploaded")
        if self.conflicts:
            parts.append(f"{len(self.conflicts)} to review")
        if not parts and (self.stats["history_in"] or self.stats["history_out"]):
            return "revision history updated"
        return ", ".join(parts) if parts else "already up to date"


def _by_id(vault) -> dict:
    if not vault:
        return {}
    return {a["id"]: a for a in vault.get("accounts", []) if a.get("id")}


def merge_vaults(base, local, remote) -> MergeResult:
    """
    Merge ``remote`` into ``local``, using ``base`` as the common ancestor.

    ``base`` may be None (this PC has never synced). Everything is then either
    an addition or a conflict -- more questions than necessary, but nothing is
    assumed and nothing is lost.
    """
    base_by_id = _by_id(base)
    local_by_id = _by_id(local)
    remote_by_id = _by_id(remote)

    merged = []
    conflicts = []
    stats = {"new": 0, "updated": 0, "archived": 0, "removed": 0,
             "unchanged": 0, "push": 0,
             # History-only differences: synced, never shown as a change.
             "history_in": 0, "history_out": 0}

    def take_remote(entry, was):
        """Record a remote entry landing locally, for the summary."""
        if was is None:
            stats["new"] += 1
        elif is_archived(entry) and not is_archived(was):
            stats["archived"] += 1
        else:
            stats["updated"] += 1
        merged.append(entry)

    def keep_local(entry):
        """Our version stands, so the server's copy is the stale one."""
        stats["push"] += 1
        merged.append(entry)

    def joined(chosen, l, r):
        """
        ``chosen``'s fields with both sides' history.

        A copy: the inputs are the caller's live vault, and SyncSession
        fingerprints that to detect edits made while a sync was open. Merging
        history into it in place would trip that check on every sync.
        """
        out = dict(chosen)
        merge_history(out, l, r)
        signature = history_signature(out)
        if signature != history_signature(l):
            stats["history_in"] += 1
        if signature != history_signature(r):
            stats["history_out"] += 1
        return out

    # Local order first, so the user's list does not reshuffle on every sync;
    # entries only the server has are appended afterwards, in its order.
    ordered_ids = list(local_by_id)
    ordered_ids += [i for i in remote_by_id if i not in local_by_id]
    ordered_ids += [i for i in base_by_id
                    if i not in local_by_id and i not in remote_by_id]

    for entry_id in ordered_ids:
        b = base_by_id.get(entry_id)
        l = local_by_id.get(entry_id)
        r = remote_by_id.get(entry_id)

        # Purged on both sides, or never existed anywhere but the base.
        if l is None and r is None:
            continue

        # Only the server has it.
        if l is None:
            if b is None:
                take_remote(r, None)                 # added there
            elif same(r, b):
                stats["push"] += 1                   # purged here; server drops it
            else:
                conflicts.append(Conflict(entry_id, b, None, r, kind="purge"))
            continue

        # Only this PC has it.
        if r is None:
            if b is None:
                keep_local(l)                        # added here, not pushed yet
            elif same(l, b):
                stats["removed"] += 1                # purged there, untouched here
            else:
                conflicts.append(Conflict(entry_id, b, l, None, kind="purge"))
            continue

        # Both have it. Whichever fields win, history is the union of both.
        if same(l, r):
            merged.append(joined(_newer(l, r), l, r))
            stats["unchanged"] += 1
        elif b is None:
            # No ancestor to appeal to: the same id arrived on both sides with
            # different contents. Only reachable with no base, or with an id
            # backfilled from content on two PCs that then diverged.
            conflicts.append(Conflict(entry_id, None, l, r, kind="edit"))
        elif same(l, b):
            take_remote(joined(r, l, r), l)          # only the server changed
        elif same(r, b):
            keep_local(joined(l, l, r))              # only this PC changed
        else:
            kind = "archive" if is_archived(l) != is_archived(r) else "edit"
            conflicts.append(Conflict(entry_id, b, l, r, kind=kind))

    return MergeResult(merged, conflicts, stats)


def _archived_copy(entry: dict) -> dict:
    """
    The losing side of a conflict, kept as a new archived entry.

    A new id is essential: reusing the original would put two entries with the
    same identity in one vault, and the next merge would not be able to tell
    them apart.
    """
    copy = dict(entry)
    copy["id"] = new_id()
    copy["archived_at"] = entry.get("archived_at") or utc_now()
    copy["updated_at"] = utc_now()
    return copy


def _active_copy(entry: dict) -> dict:
    """The other side of a "keep both", as a second live entry."""
    copy = dict(entry)
    copy["id"] = new_id()
    copy["updated_at"] = utc_now()
    return copy


def _winner(kept: dict, lost: dict) -> dict:
    """
    The version the user kept, with the one they did not as its most recent
    revision -- the same entry, revertable in one click, rather than a second
    entry cluttering the archive. Both sides' histories come along.
    """
    out = dict(kept)
    merge_history(out, kept, lost)
    add_revision(out, snapshot(lost), changed_fields(lost, kept))
    return out


def resolve(result: MergeResult, choices=None) -> list:
    """
    Fold the user's decisions back in and return the final accounts list.

    ``choices`` maps a conflict id to KEEP_LOCAL / KEEP_REMOTE / KEEP_BOTH.
    Anything missing falls back to DEFAULT_RESOLUTION, which keeps both sides.

    Whichever side loses becomes a revision of the kept entry, so every
    branch here is reversible from that entry's history. The one exception
    is a purge conflict, where there is no kept entry to attach a revision
    to; there the edited version is archived instead.
    """
    choices = choices or {}
    accounts = list(result.accounts)

    for conflict in result.conflicts:
        choice = choices.get(conflict.id, DEFAULT_RESOLUTION)
        local, remote = conflict.local, conflict.remote

        # A purge conflict has only one surviving side, so "keep both" and
        # "keep the side that still exists" are the same thing.
        if local is None or remote is None:
            survivor = local if local is not None else remote
            if choice == (KEEP_REMOTE if local is None else KEEP_LOCAL) \
                    or choice == KEEP_BOTH:
                accounts.append(survivor)
            else:
                # The user chose the side that purged it -- honour that, but
                # keep the edited version in the archive rather than losing it.
                accounts.append(_archived_copy(survivor))
            continue

        if choice == KEEP_LOCAL:
            accounts.append(_winner(local, remote))
        elif choice == KEEP_REMOTE:
            accounts.append(_winner(remote, local))
        else:                                        # KEEP_BOTH
            accounts.append(local)
            accounts.append(_active_copy(remote))

    return accounts


def merged_vault(local, accounts) -> dict:
    """
    Rebuild a full vault dict around a merged accounts list, preserving any
    top-level keys (sync settings and the like) the vault already carried.
    """
    out = dict(local or {})
    out["accounts"] = accounts
    return out
