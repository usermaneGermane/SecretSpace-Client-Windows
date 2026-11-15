"""The 'is there a newer version' check: never calls GitHub from the tests."""
import io
import json
import urllib.error

import pytest

import appconfig
import update_check
from update_check import is_newer, latest, version_key


@pytest.mark.parametrize("newer, older", [
    ("4.2.0", "4.1.0"),
    ("v4.1.1", "4.1.0"),
    ("5.0.0", "4.99.99"),
    ("4.10.0", "4.9.0"),                  # numbers, not text
    ("4.2.0", "4.2.0-rc.1"),              # a release beats its test version
    ("4.2.0-beta.1", "4.2.0-alpha.3"),
    ("4.2.0-rc.2", "4.2.0-rc.1"),
])
def test_order(newer, older):
    assert is_newer(newer, older)
    assert not is_newer(older, newer)


def test_same_version_is_not_newer():
    assert not is_newer("v4.2.0", "4.2.0")


@pytest.mark.parametrize("junk", ["", "latest", "4.2", "4.2.0.1", "v4.2.0-dev",
                                  "4.2.0 ; rm"])
def test_junk_is_never_newer(junk):
    assert version_key(junk) is None
    assert not is_newer(junk, "0.0.1")


def test_the_running_version_parses():
    assert version_key(update_check.__version__) is not None


class Answer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def opener_for(payload, seen=None):
    def opener(request, timeout, context):
        if seen is not None:
            seen.append(request)
        return Answer(json.dumps(payload).encode())
    return opener


def test_latest_reads_tag_and_page():
    seen = []
    release = latest(opener_for({
        "tag_name": "v9.1.0",
        "html_url": "https://github.com/usermaneGermane/SecretSpace-Client-Windows/releases/tag/v9.1.0"},
        seen))
    assert release.version == "9.1.0"
    assert release.page.endswith("/releases/tag/v9.1.0")
    request = seen[0]
    assert request.full_url == update_check.API_URL
    assert request.full_url.startswith("https://api.github.com/repos/")
    # Only the standard headers: nothing about the user or the vaults.
    assert set(h.lower() for h in request.headers) == {"accept", "user-agent"}


def test_a_page_that_is_not_github_is_not_opened():
    release = latest(opener_for({"tag_name": "v9.1.0",
                                 "html_url": "https://evil.example/x"}))
    assert release.page == ("https://github.com/" + update_check.REPO
                            + "/releases/latest")


@pytest.mark.parametrize("payload", [{}, {"tag_name": "nightly"}, [], {"tag_name": 5}])
def test_an_answer_without_a_version_is_an_error(payload):
    with pytest.raises(ValueError):
        latest(opener_for(payload))


def test_network_errors_are_readable():
    def offline(request, timeout, context):
        raise urllib.error.URLError("no route")

    with pytest.raises(OSError, match="could not reach GitHub"):
        latest(offline)


def test_the_switch_is_off_until_turned_on(tmp_path, monkeypatch):
    monkeypatch.setattr(appconfig, "config_file", lambda: str(tmp_path / "c.json"))
    assert appconfig.check_updates() is False
    appconfig.save_config(check_updates=True)
    assert appconfig.check_updates() is True
    appconfig.save_config(check_updates="yes")      # only a real true counts
    assert appconfig.check_updates() is False


def test_at_start_does_nothing_when_off(tmp_path, monkeypatch):
    monkeypatch.setattr(appconfig, "config_file", lambda: str(tmp_path / "c.json"))
    called = []
    monkeypatch.setattr(update_check, "latest", lambda *a, **k: called.append(1))
    update_check.check_at_start(app=None)          # would fail on app if it ran
    assert called == []
