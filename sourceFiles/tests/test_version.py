"""The version label shown in the UI."""

import re

import pytest

import account_crypto
import crypto_utils
import version


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+(-(alpha|beta|rc)\.\d+)?",
                        version.__version__)


@pytest.mark.parametrize("text, numbers", [
    ("2.11.0", (2, 11, 0, 0)), ("3.0.0-alpha.1", (3, 0, 0, 1)),
    ("3.0.0-beta.2", (3, 0, 0, 2)), ("3.0.0", (3, 0, 0, 0))])
def test_file_version(text, numbers):
    assert version.file_version(text) == numbers


@pytest.mark.parametrize("bad", ["3.0", "3.0.0-alpha", "3.0.0-dev.1", "v3.0.0"])
def test_file_version_refuses_junk(bad):
    with pytest.raises(ValueError):
        version.file_version(bad)


def test_current_version_has_a_file_version():
    assert len(version.file_version()) == 4


def test_version_string_is_prefixed():
    assert version.version_string() == f"v{version.__version__}"


def test_long_version_mentions_app_and_format():
    text = version.long_version_string()
    assert "SecretSpace" in text
    assert version.version_string() in text
    assert version.VAULT_FORMAT in text


def test_declared_format_matches_what_we_actually_write():
    """The label must not drift from the container the code emits."""
    assert version.VAULT_FORMAT.encode() == account_crypto.VAULT_MAGIC
    assert version.LEGACY_VAULT_FORMAT.encode() == crypto_utils.MAGIC
