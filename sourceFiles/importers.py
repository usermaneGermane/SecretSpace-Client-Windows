"""
Parsing of CSV / JSON exports from browsers and other password managers.

Lives outside gui.py so it can be tested without a display. Every parser
returns a :class:`ImportResult`: the mapped rows plus the names of any
columns that carried data we cannot store, so the UI can tell the user what
is about to be lost instead of silently dropping it.
"""

import os
import re
import csv
import json
from collections import namedtuple

#: One parsed entry. notes/totp are "" when the export did not carry them.
Account = namedtuple("Account", "site username password notes totp")

#: rows: list of Account; dropped: sorted labels for data still not imported
ImportResult = namedtuple("ImportResult", "rows dropped")

# Header synonyms used to map arbitrary export columns onto site/user/password.
SITE_KEYS = ("name", "title", "site", "website", "url", "uri", "login_uri",
             "hostname", "web/app", "webapp", "account", "grouping")
USER_KEYS = ("username", "user", "login_username", "login", "email", "e-mail",
             "user/email", "useremail", "user name")
PASS_KEYS = ("password", "login_password", "pass", "pwd", "passwd",
             "passphrase")
NOTE_KEYS = ("notes", "note", "comments", "comment", "extra", "description")
TOTP_KEYS = ("totp", "login_totp", "otp", "otpauth", "authenticator",
             "two_factor", "2fa")

#: Columns whose contents SecretSpace has nowhere to put. Reported to the user
#: rather than discarded quietly -- losing a TOTP seed without being told is
#: how people get locked out of their accounts after a migration.
LOSSY_KEYS = (
    ("custom", "custom fields"),
    ("fields", "custom fields"),
    ("card", "card details"),
    ("identity", "identity details"),
    ("attachment", "attachments"),
    ("history", "password history"),
)


def _pick(row, keys, exclude=()):
    """Return the first matching value from a normalized {header: value} row."""
    # exact header match first (most reliable for known export formats)
    for k in keys:
        if k in row and str(row[k]).strip():
            return str(row[k]).strip()
    # then a loose substring match, skipping excluded header fragments
    for header, value in row.items():
        if any(ex in header for ex in exclude):
            continue
        if any(k in header for k in keys) and str(value).strip():
            return str(value).strip()
    return ""


def _clean_site(value):
    """Turn a URL-looking value into a tidy site name; keep plain names as-is."""
    v = (value or "").strip()
    looks_url = ("://" in v or v.lower().startswith("www.") or
                 (" " not in v and re.search(r"\.[a-z]{2,}", v.lower())))
    if looks_url:
        if "://" in v:
            v = v.split("://", 1)[1]
        if v.lower().startswith("www."):
            v = v[4:]
        v = v.split("/")[0]
    return v or (value or "").strip()


def _row_to_account(row):
    """Map one normalized row dict onto an :class:`Account`."""
    site = _clean_site(_pick(row, SITE_KEYS, exclude=("pass", "user", "email")))
    user = _pick(row, USER_KEYS, exclude=("pass", "url", "uri", "totp", "note"))
    pwd = _pick(row, PASS_KEYS, exclude=("hint", "note", "totp", "reused", "weak"))
    notes = _pick(row, NOTE_KEYS, exclude=("pass", "user", "totp"))
    totp = _pick(row, TOTP_KEYS, exclude=("pass", "user", "note"))
    return Account(site, user, pwd, notes, totp)


#: Every column name we recognise, for telling a header row from data.
_KNOWN_COLUMNS = frozenset(SITE_KEYS + USER_KEYS + PASS_KEYS + NOTE_KEYS
                           + TOTP_KEYS)


def _is_header_row(headers) -> bool:
    """
    Whether the first row names columns rather than holding an account:
    at least two cells that are exactly a known column name.

    Real exports pass easily (Chrome's name,url,username,password,note has
    five; KeePass's Account,...,Password,...,Comments has three). A data row
    would need two cells spelled exactly like column names.

    Two heuristics this replaces each lost data. csv.Sniffer().has_header()
    guesses from cell shape, reports True for "example.com,alice,pw1", and on
    Python 3.12 reports False for a real header once blank lines are in the
    sample; matching substrings took "github,username1,pass123" for a header.
    Either way the first account, or the header itself, was mis-imported.
    """
    return sum(h in _KNOWN_COLUMNS for h in headers) >= 2


def _find_dropped(rows):
    """Labels for columns that hold data we are about to discard."""
    found = set()
    for row in rows:
        for header, value in row.items():
            if not str(value or "").strip():
                continue
            for fragment, label in LOSSY_KEYS:
                if fragment in header:
                    found.add(label)
    return sorted(found)


def _from_dicts(dict_rows):
    rows = [_row_to_account(r) for r in dict_rows]
    return ImportResult([r for r in rows if any(r)], _find_dropped(dict_rows))


def imported_fields(rows):
    """Labels for the optional data actually carried by ``rows``."""
    found = []
    if any(r.totp for r in rows):
        found.append("TOTP / 2FA secrets")
    if any(r.notes for r in rows):
        found.append("notes")
    return found


def parse_import_file(path) -> ImportResult:
    """Parse a CSV or JSON export."""
    if os.path.splitext(path)[1].lower() == ".json":
        return parse_json(path)
    return parse_csv(path)


def parse_csv(path) -> ImportResult:
    with open(path, newline="", encoding="utf-8-sig") as f:
        sample = f.read(8192)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except Exception:
            dialect = csv.excel
        rows = [r for r in csv.reader(f, dialect)
                if any(str(c).strip() for c in r)]
    if not rows:
        return ImportResult([], [])

    headers = [str(h).strip().lower() for h in rows[0]]
    if _is_header_row(headers):
        dict_rows = [{headers[i]: r[i] for i in range(min(len(headers), len(r)))}
                     for r in rows[1:]]
        return _from_dicts(dict_rows)

    # no header -> assume site, username, password order
    out = [Account(_clean_site(r[0]) if r else "",
                   r[1].strip() if len(r) > 1 else "",
                   r[2].strip() if len(r) > 2 else "", "", "") for r in rows]
    return ImportResult(out, [])


def parse_json(path) -> ImportResult:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "accounts" in data:
        items = data["accounts"]
    elif isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = [data]
    else:
        return ImportResult([], [])
    dict_rows = [{str(k).strip().lower(): v for k, v in it.items()}
                 for it in items if isinstance(it, dict)]
    return _from_dicts(dict_rows)


def accounts_from_vault(vault_dict) -> ImportResult:
    """Pull rows out of an already-decrypted vault dict."""
    items = vault_dict.get("accounts", []) if isinstance(vault_dict, dict) else []
    dict_rows = [{str(k).strip().lower(): v for k, v in it.items()}
                 for it in items if isinstance(it, dict)]
    return _from_dicts(dict_rows)
