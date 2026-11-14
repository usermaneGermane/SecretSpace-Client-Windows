"""
The change log inside a vault (phase 4): who changed what, and when.

Before 3.0 everyone who could open a vault was the same person to the app,
so a change carried no name. Now every save by an account adds lines to the
vault's own log -- "nikola added Router", "user1 changed the password of
Mail" -- which travel with the vault (encrypted under its key, merged by
sync) and can be read by every member.

What a line holds: who, when, what kind of change, which entry (its id and
its title at that time) and which *fields* changed. Never a value: no
password, no username, no note.

What is not recorded, on purpose: who looked at an entry or copied a
password. This is accounting of changes, not surveillance.

Every line is signed with its author's account key (Ed25519). All editors
of a vault hold the vault's key, so without a signature any of them could
write a line under someone else's name; with it, a line whose signature
does not match its author's key is shown as such.

A line says which format it was signed in (``v``; none means 1, from
SecretSpace 3). Lines are never signed again -- only their author could --
so an old line keeps being checked the way it was signed, and a vault that
a member with an older app still opens gets its new lines the old way too.

Pure: dicts in, dicts out. Nothing here touches a file, a server or a widget.
"""

import json
import os

import account_crypto
import vault

#: The vault's top-level key holding the log. Top-level keys other than
#: "accounts" pass through vault.validate_vault untouched.
CHANGES_KEY = "changes"

#: Lines kept per vault, newest first out. At a dozen changes a day that is
#: most of a year; an entry's own History keeps its earlier versions anyway.
CHANGES_LIMIT = 1000

#: More added (or deleted) entries than this in one save become one line:
#: an import of 400 entries is one event, not 400.
BULK = 20

ADDED, EDITED, ARCHIVED, RESTORED, DELETED, REVERTED = (
    "added", "edited", "archived", "restored", "deleted", "reverted")
IMPORTED, DELETED_MANY, HISTORY_CLEARED = (
    "imported", "deleted_many", "history_cleared")
ACTIONS = (ADDED, EDITED, ARCHIVED, RESTORED, DELETED, REVERTED, IMPORTED,
           DELETED_MANY, HISTORY_CLEARED)

#: What check() says about a line.
OK, BAD, UNKNOWN = "ok", "bad", "unknown"

_TITLE_CHARS = 120


def _clean(line):
    """A stored line in its one form, or None for junk."""
    if not isinstance(line, dict):
        return None
    action = line.get("action")
    if action not in ACTIONS:
        return None
    fields = line.get("fields")
    try:
        count = max(0, int(line.get("count", 0) or 0))
    except (TypeError, ValueError):
        count = 0
    clean = {
        "id": str(line.get("id", "") or "")[:32],
        "at": str(line.get("at", "") or "")[:40],
        "by": str(line.get("by", "") or "")[:64],
        "action": action,
        "entry": str(line.get("entry", "") or "")[:64],
        "title": str(line.get("title", "") or "")[:_TITLE_CHARS],
        "fields": ([f for f in vault.REVISION_FIELDS if f in fields]
                   if isinstance(fields, list) else []),
        "count": count,
        "sig": str(line.get("sig", "") or "")[:200],
    }
    if account_crypto.format_of(line.get("v")) is account_crypto.NOW:
        clean["v"] = account_crypto.NOW.number
    if not clean["id"] or not clean["at"] or not clean["by"]:
        return None
    return clean


def lines_of(data) -> list:
    """A vault's log, cleaned, oldest first."""
    raw = data.get(CHANGES_KEY) if isinstance(data, dict) else None
    return merge(raw if isinstance(raw, list) else [])


def merge(*logs) -> list:
    """
    The union of several copies of a log: each line once (by id), oldest
    first, the newest CHANGES_LIMIT kept. Deterministic, so two devices that
    hold the same lines end up with the same list.
    """
    found = {}
    for log in logs:
        for raw in log or []:
            line = _clean(raw)
            if line is not None and line["id"] not in found:
                found[line["id"]] = line
    ordered = sorted(found.values(), key=lambda l: (l["at"], l["id"]))
    return ordered[-CHANGES_LIMIT:]


# ---------------------------------------------------------------------------
# What changed between two states of a vault
# ---------------------------------------------------------------------------
def _by_id(data) -> dict:
    return {a.get("id"): a for a in (data or {}).get("accounts", [])
            if isinstance(a, dict) and a.get("id")}


def _was_a_version(before: dict, after: dict) -> bool:
    """Is ``after``'s content one of ``before``'s earlier versions?"""
    now = vault._content_key(vault.snapshot(after))
    return any(vault._content_key(rev) == now
               for rev in before.get("history") or [])


def diff(before: dict, after: dict) -> list:
    """
    The changes from ``before`` to ``after`` as unsigned records
    ({"action", "entry", "title", "fields", "count"}), in the order of
    ``after``'s entries, deletions last.
    """
    old, new = _by_id(before), _by_id(after)
    added, deleted, rest = [], [], []
    for entry_id, entry in new.items():
        was = old.get(entry_id)
        title = str(entry.get("site", "") or "")[:_TITLE_CHARS]
        if was is None:
            added.append({"action": ADDED, "entry": entry_id, "title": title,
                          "fields": [], "count": 0})
            continue
        fields = vault.changed_fields(was, entry)
        if vault.is_archived(was) != vault.is_archived(entry):
            action = ARCHIVED if vault.is_archived(entry) else RESTORED
        elif fields:
            action = REVERTED if _was_a_version(was, entry) else EDITED
        elif str(was.get("history_cleared_at", "") or "") != \
                str(entry.get("history_cleared_at", "") or ""):
            action = HISTORY_CLEARED
        else:
            continue
        rest.append({"action": action, "entry": entry_id, "title": title,
                     "fields": fields, "count": 0})
    for entry_id, was in old.items():
        if entry_id not in new:
            deleted.append({"action": DELETED, "entry": entry_id,
                            "title": str(was.get("site", "") or "")[:_TITLE_CHARS],
                            "fields": [], "count": 0})
    if len(added) > BULK:
        added = [{"action": IMPORTED, "entry": "", "title": "", "fields": [],
                  "count": len(added)}]
    if len(deleted) > BULK:
        deleted = [{"action": DELETED_MANY, "entry": "", "title": "",
                    "fields": [], "count": len(deleted)}]
    return added + rest + deleted


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------
def message(vault_hex: str, line: dict) -> bytes:
    """
    What a line's signature covers: everything in it, and the vault it is
    in -- so a line cannot be copied into another vault, or its author, time
    or entry changed, without the signature failing.
    """
    label = account_crypto.format_of(line.get("v")).label("change")
    return json.dumps([label.decode("ascii"), vault_hex, line["id"], line["at"],
                       line["by"], line["action"], line["entry"], line["title"],
                       list(line["fields"]), int(line["count"])],
                      separators=(",", ":"), ensure_ascii=True).encode("ascii")


def check(line: dict, vault_hex: str, signing_key) -> str:
    """
    OK when ``signing_key`` (the author's public signing key, 32 bytes)
    signed this line, BAD when it did not, UNKNOWN when there is no key to
    check against.
    """
    if not signing_key:
        return UNKNOWN
    line = _clean(line)
    if line is None:
        return BAD
    return OK if account_crypto.verify(signing_key, message(vault_hex, line),
                                       line["sig"]) else BAD


def record(data: dict, before: dict, username: str, keyset: dict,
           vault_hex: str, fmt=account_crypto.NOW) -> int:
    """
    Note in ``data`` what ``username`` changed since ``before`` (the vault as
    it was last saved): signed lines in the log, ``updated_by`` on each entry
    they touched, and ``by`` on each earlier version that became history.
    Returns how many lines were added. ``data`` is changed in place.
    ``fmt`` is the vault's format (see the module docstring).
    """
    found = diff(before, data)
    if not found:
        return 0
    old, new = _by_id(before), _by_id(data)
    lines = []
    for item in found:
        line = dict(item)
        line.update({"id": os.urandom(8).hex(), "at": vault.history_now(),
                     "by": username, "sig": ""})
        if fmt is account_crypto.NOW:
            line["v"] = fmt.number
        line["sig"] = account_crypto.sign(keyset, message(vault_hex, line))
        lines.append(line)
        entry = new.get(item["entry"])
        if entry is None:
            continue
        entry["updated_by"] = username
        seen = {rev.get("rid") for rev in
                (old.get(item["entry"]) or {}).get("history") or []}
        for rev in entry.get("history") or []:
            if rev.get("rid") not in seen and not rev.get("by"):
                rev["by"] = username
    if any(item["action"] == IMPORTED for item in found):
        # One line for the lot, but each entry still says who brought it in.
        for entry_id, entry in new.items():
            if entry_id not in old:
                entry["updated_by"] = username
    data[CHANGES_KEY] = merge(lines_of(data), lines)
    return len(lines)


# ---------------------------------------------------------------------------
# For the screen
# ---------------------------------------------------------------------------
_FIELD_LABELS = {"site": "site", "username": "username", "password": "password",
                 "notes": "notes", "totp": "2FA"}


def describe(line: dict) -> str:
    """A line as a sentence without its author: “changed the password of
    “Mail””."""
    title = f"“{line.get('title') or 'an entry'}”"
    action = line.get("action")
    fields = [_FIELD_LABELS[f] for f in line.get("fields") or []
              if f in _FIELD_LABELS]
    what = " and ".join([", ".join(fields[:-1]), fields[-1]]
                        if len(fields) > 1 else fields)
    count = line.get("count", 0)
    if action == ADDED:
        return f"added {title}"
    if action == EDITED:
        return f"changed the {what or 'details'} of {title}"
    if action == REVERTED:
        return f"put back an earlier version of {title}" + (
            f" ({what})" if what else "")
    if action == ARCHIVED:
        return f"archived {title}"
    if action == RESTORED:
        return f"restored {title} from the archive"
    if action == DELETED:
        return f"deleted {title} for good"
    if action == IMPORTED:
        return f"added {count} entries at once (an import)"
    if action == DELETED_MANY:
        return f"deleted {count} entries for good"
    if action == HISTORY_CLEARED:
        return f"cleared the earlier versions of {title}"
    return "changed something"
