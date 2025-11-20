from guarddog.checks.screen_lock import ScreenLockState, _classify_screen_lock_state


def test_screen_lock_high_when_disabled():
    state = ScreenLockState(active=False, secure=None, timeout_seconds=None)
    status, summary, details = _classify_screen_lock_state(state)
    assert status == "HIGH"
    assert "turned OFF" in summary
    assert "DISABLED" in details


def test_screen_lock_ok_when_secure_and_short_timeout():
    state = ScreenLockState(active=True, secure=True, timeout_seconds=10 * 60)
    status, summary, details = _classify_screen_lock_state(state)
    assert status == "OK"
    assert "automatic screen lock is enabled" in summary.lower()
    assert "Idle timeout" in details or "timeout" in details


def test_screen_lock_warn_when_long_timeout():
    state = ScreenLockState(active=True, secure=True, timeout_seconds=45 * 60)
    status, summary, _ = _classify_screen_lock_state(state)
    assert status == "WARN"
    assert "quite long" in summary


def test_screen_lock_warn_when_not_secure():
    state = ScreenLockState(active=True, secure=False, timeout_seconds=10 * 60)
    status, summary, details = _classify_screen_lock_state(state)
    assert status == "WARN"
    assert "password does NOT appear to be required" in summary
    assert "Require password on resume" in details


def test_screen_lock_unknown_when_all_unknown():
    state = ScreenLockState(active=None, secure=None, timeout_seconds=None)
    status, summary, _ = _classify_screen_lock_state(state)
    assert status == "UNKNOWN"
    assert "could not determine" in summary
