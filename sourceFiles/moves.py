"""
Moving an entry from one vault to another.

Two vaults are two files with two keys, and each syncs on its own, so nothing
can change both at once. A move is therefore done in an order that can stop
anywhere without losing the entry:

1. a full copy (fields, history, 2FA, what a newer version added) goes into
   the target under a new id;
2. the original is archived where it was, marked as moved (``moved``);
3. the original is deleted once the copy has arrived: the server has it, or,
   for an account without a server, it is on disk (:func:`settle`).

If the copy never arrives (no network, or the account lost its right to write
there) the original stays in the Archive, restorable. It stays too if it was
changed after it was copied, so no such change goes with it.

Another device that still has the entry live then finds it gone from the
server. Normally that is a question; here the vault's own change log says it
was moved, so it simply goes (sync.merge_vaults).
"""

import copy
import hashlib
import json

import vault

#: The mark on an archived original: {"vault", "id": where the copy went,
#: "at": its archived_at, "sum": what was copied}.
MOVED_KEY = vault.MOVED_KEY


def _sum(entry: dict) -> str:
    """What a move copies, as one value. Not who made a revision (``by``):
    that is filled in when the vault is saved."""
    material = [list(vault._content_key(vault.snapshot(entry))),
                [rev.get("rid") for rev in entry.get("history") or []],
                str(entry.get("history_cleared_at", "") or "")]
    return hashlib.sha256(json.dumps(material).encode("utf-8")).hexdigest()


def marker(entry: dict):
    """The mark of an entry that was moved away and not touched since, else
    None. One that was restored, or archived again, is an ordinary entry."""
    mark = entry.get(MOVED_KEY)
    if not isinstance(mark, dict) or not vault.is_archived(entry):
        return None
    return mark if mark.get("at") == entry["archived_at"] else None


def move(source: dict, target: dict, entry_id: str, target_id: str):
    """
    Move a live entry from ``source`` into ``target`` (vault ``target_id``);
    both are changed in place and left to the caller to save. Returns the
    copy, or None when there is no such live entry.
    """
    entry = vault.find_entry(source, entry_id)
    if entry is None or vault.is_archived(entry) or source is target:
        return None
    moved = copy.deepcopy(entry)
    moved.pop(MOVED_KEY, None)
    # The same on every device: two that move one entry to the same vault
    # before they sync end up with one copy, not two.
    moved["id"] = hashlib.sha256(
        f"move|{entry_id}|{target_id}".encode("utf-8")).hexdigest()[:32]
    if vault.find_entry(target, moved["id"]) is not None:
        moved["id"] = vault.new_id()
    target["accounts"].append(moved)
    vault.archive_account(source, entry_id)
    entry[MOVED_KEY] = {"vault": target_id, "id": moved["id"],
                        "at": entry["archived_at"], "sum": _sum(moved)}
    return moved


def settle(data: dict, arrived) -> int:
    """
    Delete from ``data`` the originals whose copy has arrived, as
    ``arrived(vault_id, entry_id)`` says. Returns how many went.
    """
    done = []
    for entry in data["accounts"]:
        mark = marker(entry)
        if mark and mark.get("sum") == _sum(entry) \
                and arrived(mark.get("vault"), mark.get("id")):
            done.append(entry["id"])
    for entry_id in done:
        vault.purge_account(data, entry_id)
    return len(done)
