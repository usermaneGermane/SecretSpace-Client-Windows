"""
"Is there a newer SecretSpace?" - asked of GitHub, only when the user wants.

Settings -> Updates has *Check now*, and a switch (off until turned on) to
check once each time SecretSpace starts. A check is one HTTPS request to
api.github.com for this app's newest release; it sends nothing about the
user or their vaults (GitHub sees the PC's address, as any web page would).
Nothing is downloaded or installed: a newer version opens its download page
in the browser, and installing stays the user's choice.
"""

import json
import re
import ssl
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass

from version import __version__

REPO = "usermaneGermane/SecretSpace-Client-Windows"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
TIMEOUT = 8

_VERSION = re.compile(r"v?(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?")
_STAGES = {"alpha": 0, "beta": 1, "rc": 2}


@dataclass
class Release:
    version: str          # "4.2.0", without the tag's "v"
    page: str             # the release's page on GitHub


def version_key(text: str):
    """
    A sortable key for '4.2.0' or 'v4.2.0-rc.1', None if it is not one.
    A test version comes before its release: 4.2.0-rc.1 < 4.2.0.
    """
    m = _VERSION.fullmatch(text.strip())
    if not m:
        return None
    major, minor, patch, stage, number = m.groups()
    pre = (_STAGES[stage], int(number)) if stage else (3, 0)
    return (int(major), int(minor), int(patch)) + pre


def is_newer(tag: str, current: str = __version__) -> bool:
    new, have = version_key(tag), version_key(current)
    return new is not None and have is not None and new > have


def latest(opener=urllib.request.urlopen, timeout=TIMEOUT) -> Release:
    """
    The newest published release (GitHub leaves drafts and test versions
    out of 'latest'). Raises OSError or ValueError with a readable message.
    """
    request = urllib.request.Request(API_URL, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "SecretSpace-update-check"})
    try:
        with opener(request, timeout=timeout,
                    context=ssl.create_default_context()) as response:
            data = json.loads(response.read(1_000_000).decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise OSError(f"GitHub answered {e.code}") from None
    except urllib.error.URLError as e:
        raise OSError(f"could not reach GitHub ({e.reason})") from None
    tag = data.get("tag_name") if isinstance(data, dict) else None
    if not isinstance(tag, str) or version_key(tag) is None:
        raise ValueError("GitHub's answer has no version in it")
    page = data.get("html_url")
    if not (isinstance(page, str) and page.startswith("https://github.com/")):
        page = f"https://github.com/{REPO}/releases/latest"
    return Release(tag.strip().lstrip("v"), page)


# ---------------------------------------------------------------------------
# In the app
# ---------------------------------------------------------------------------
def check_now(app):
    """Settings -> Updates -> Check now: always says what it found."""
    from sync_ui import _in_background          # late: it imports the UI

    def done(release):
        if is_newer(release.version):
            offer(app, release)
        else:
            app.toast(f"You have the newest version (v{__version__})")

    app.toast("Checking for a new version…")
    _in_background(app, latest, done,
                   lambda error: app.toast(f"Could not check: {error}", "warn"))


def check_at_start(app):
    """The switch is on: check quietly; say something only if there is news."""
    import appconfig
    if not appconfig.check_updates():
        return
    from sync_ui import _in_background

    def done(release):
        if is_newer(release.version):
            app.toast(f"SecretSpace {release.version} is out — "
                      "Settings → Updates")

    _in_background(app, latest, done, lambda error: None)


def offer(app, release):
    if app._confirm("A new version",
                    f"SecretSpace {release.version} is out; you have "
                    f"{__version__}.\n\nOpen its download page? Installing it "
                    "keeps your accounts and vaults.", danger=False):
        webbrowser.open(release.page)
