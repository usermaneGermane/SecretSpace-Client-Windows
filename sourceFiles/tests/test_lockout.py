"""Rate limiting of master-password attempts."""

import pytest

import appconfig
import lockout


@pytest.fixture(autouse=True)
def config_in_tmp(tmp_path, monkeypatch):
    """Keep config.json (where the counters live) out of the real app dir."""
    monkeypatch.setattr(appconfig, "config_file",
                        lambda: str(tmp_path / "config.json"))


def test_first_attempts_are_not_delayed():
    for _ in range(lockout.FREE_ATTEMPTS):
        assert lockout.record_failure("alice") == 0
    assert lockout.remaining("alice") == 0


def test_delay_appears_after_the_free_attempts():
    for _ in range(lockout.FREE_ATTEMPTS):
        lockout.record_failure("alice")
    assert lockout.record_failure("alice") == lockout.PENALTIES[0]
    assert lockout.remaining("alice") > 0


def test_delay_escalates_then_caps():
    seen = [lockout.record_failure("alice") for _ in range(12)]
    penalties = [s for s in seen if s]
    assert penalties[:len(lockout.PENALTIES)] == list(lockout.PENALTIES)
    assert penalties[-1] == lockout.PENALTIES[-1]


def test_success_clears_the_counter():
    for _ in range(6):
        lockout.record_failure("alice")
    lockout.reset("alice")
    assert lockout.remaining("alice") == 0
    assert lockout.failures("alice") == 0


def test_lockout_expires_with_time():
    for _ in range(4):
        lockout.record_failure("alice", now=1000.0)
    assert lockout.remaining("alice", now=1000.0) > 0
    assert lockout.remaining("alice", now=1000.0 + lockout.PENALTIES[0]) == 0


def test_users_are_tracked_separately():
    for _ in range(6):
        lockout.record_failure("alice")
    assert lockout.remaining("alice") > 0
    assert lockout.remaining("bob") == 0


def test_counters_survive_a_restart():
    """The whole point: closing the app must not reset the penalty."""
    for _ in range(4):
        lockout.record_failure("alice")
    before = lockout.remaining("alice")
    import importlib
    importlib.reload(lockout)          # a fresh process would re-read the file
    assert lockout.remaining("alice") == pytest.approx(before, abs=1)


def test_corrupt_state_is_ignored_rather_than_crashing():
    appconfig.save_config(unlock_failures="not a dict")
    assert lockout.remaining("alice") == 0
    assert lockout.record_failure("alice") == 0


def test_corrupt_entry_is_ignored():
    appconfig.save_config(unlock_failures={"alice": {"until": "soon"}})
    assert lockout.remaining("alice") == 0
