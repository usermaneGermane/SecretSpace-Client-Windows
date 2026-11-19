"""
An entry's web address: checking what the user typed, and opening it.

Lives outside the GUI so it can be tested without a display, and so both
clients share it unchanged.

Only http and https are ever opened. The address comes from the vault, and a
shared vault can be written by other people: a ``file:``, ``javascript:`` or
custom-scheme link handed to the system's opener could start a program
instead of a browser. Such addresses are refused when saved, and refused
again when clicked, for vaults written before this check existed.
"""

import webbrowser
from urllib.parse import urlsplit

#: The schemes a link may use.
SCHEMES = ("http", "https")

#: Longest address kept; real login pages are far shorter.
MAX_CHARS = 2048


def clean(text: str):
    """
    ``(address, problem)`` for what the user typed into the field.

    ``address`` is what gets stored: trimmed, with ``https://`` put in front
    of a bare ``github.com/login``. ``problem`` is a sentence for the form,
    or "" when the address is fine. An empty field is fine: the address is
    optional.
    """
    value = (text or "").strip()
    if not value:
        return "", ""
    if len(value) > MAX_CHARS:
        return value, "the address is too long."
    if any(c.isspace() for c in value):
        return value, "a web address has no spaces."
    if "://" not in value:
        scheme = value.split(":", 1)[0].lower() if ":" in value else ""
        # "localhost:8080" and "10.0.0.1:443" are a host and a port, not a
        # scheme; "mailto:x" or "javascript:x" are schemes.
        if scheme and not value.split(":", 1)[1][:1].isdigit():
            return value, "only http:// and https:// addresses can be links."
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in SCHEMES:
        return value, "only http:// and https:// addresses can be links."
    if not parts.hostname:
        return value, "the address has no site name in it."
    return value, ""


def openable(address: str):
    """The address if it is safe to hand to a browser, else None."""
    value, problem = clean(address)
    return value if value and not problem else None


def display(address: str) -> str:
    """The address as shown on the details card: without ``https://``."""
    value = (address or "").strip()
    for prefix in ("https://", "http://"):
        if value.lower().startswith(prefix):
            value = value[len(prefix):]
            break
    return value.rstrip("/") if value.count("/") == 1 else value


def open_in_browser(address: str, opener=None) -> bool:
    """Open the address in the default browser. False when it was refused
    (not http/https) or no browser could be started."""
    link = openable(address)
    if link is None:
        return False
    try:
        return bool((opener or webbrowser.open)(link))
    except Exception:
        return False
