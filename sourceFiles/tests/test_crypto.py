"""Container format, key derivation and backward compatibility."""

import os
import json
import base64

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_utils as C

SAMPLE = {"accounts": [{"site": "github", "username": "me", "password": "hunter2"}]}


def legacy_blob(password, data):
    """A vault exactly as SecretSpace wrote them before the PMV2 header existed."""
    salt, nonce = os.urandom(16), os.urandom(12)
    key = C.derive_key(password, salt, C.LEGACY_ITERATIONS)
    ct = AESGCM(key).encrypt(nonce, json.dumps(data).encode(), None)
    return base64.b64encode(salt + nonce + ct)


def test_round_trip():
    assert C.decrypt("pw", C.encrypt("pw", SAMPLE)) == SAMPLE


def test_new_vaults_use_the_current_iteration_count():
    assert C.blob_iterations(C.encrypt("pw", SAMPLE)) == C.DEFAULT_ITERATIONS
    assert C.DEFAULT_ITERATIONS >= 600_000


def test_salt_and_nonce_differ_every_write():
    blobs = {bytes(C.encrypt("pw", SAMPLE)) for _ in range(5)}
    assert len(blobs) == 5


def test_wrong_password_is_rejected():
    with pytest.raises(ValueError):
        C.decrypt("nope", C.encrypt("pw", SAMPLE))


# --- backward compatibility: existing users must not be locked out ---------
def test_legacy_vault_still_opens():
    assert C.decrypt("pw", legacy_blob("pw", SAMPLE)) == SAMPLE


def test_legacy_vault_reports_its_own_iteration_count():
    assert C.blob_iterations(legacy_blob("pw", SAMPLE)) == C.LEGACY_ITERATIONS


def test_legacy_vault_rejects_wrong_password():
    with pytest.raises(ValueError):
        C.decrypt("nope", legacy_blob("pw", SAMPLE))


# --- the header is authenticated, not merely carried -----------------------
def test_iteration_count_cannot_be_downgraded():
    raw = bytearray(base64.b64decode(C.encrypt("pw", SAMPLE)))
    raw[5:9] = (1).to_bytes(4, "big")           # 600_000 -> 1
    with pytest.raises(ValueError):
        C.decrypt("pw", base64.b64encode(bytes(raw)))


def test_absurd_iteration_count_is_refused_without_running_the_kdf():
    raw = bytearray(base64.b64decode(C.encrypt("pw", SAMPLE)))
    raw[5:9] = (0xFFFFFFFF).to_bytes(4, "big")
    with pytest.raises(ValueError, match="implausible"):
        C.decrypt("pw", base64.b64encode(bytes(raw)))


def test_unknown_kdf_id_is_reported_clearly():
    raw = bytearray(base64.b64decode(C.encrypt("pw", SAMPLE)))
    raw[4] = 99
    with pytest.raises(ValueError, match="newer version"):
        C.decrypt("pw", base64.b64encode(bytes(raw)))


def test_ciphertext_tampering_is_detected():
    raw = bytearray(base64.b64decode(C.encrypt("pw", SAMPLE)))
    raw[-1] ^= 0xFF
    with pytest.raises(ValueError):
        C.decrypt("pw", base64.b64encode(bytes(raw)))


@pytest.mark.parametrize("junk", [b"", b"!!!!", b"x", base64.b64encode(b"PMV2\x01\x00\x00\x00\x01")])
def test_garbage_input_raises_valueerror_not_indexerror(junk):
    with pytest.raises(ValueError):
        C.decrypt("pw", junk)


def test_password_matches_only_the_exact_password():
    from crypto_utils import password_matches
    assert password_matches("correct horse", "correct horse")
    assert not password_matches("correct hors", "correct horse")
    assert not password_matches("correct horse ", "correct horse")
    assert not password_matches("", "correct horse")
    assert not password_matches(None, "correct horse")
    assert password_matches("pässwörd ✓", "pässwörd ✓")
