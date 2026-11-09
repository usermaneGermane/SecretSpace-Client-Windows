"""The version label shown in the UI."""

import re

import crypto_utils
import version


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", version.__version__)


def test_version_string_is_prefixed():
    assert version.version_string() == f"v{version.__version__}"


def test_long_version_mentions_app_and_format():
    text = version.long_version_string()
    assert "SecretSpace" in text
    assert version.version_string() in text
    assert version.VAULT_FORMAT in text


def test_declared_format_matches_what_we_actually_write():
    """The label must not drift from the container the code emits."""
    assert version.VAULT_FORMAT.encode() == crypto_utils.MAGIC
