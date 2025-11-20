from guarddog.checks.defender import DefenderState, _classify_defender_state


def test_defender_disabled_is_high():
    state = DefenderState(disabled_local=True, disabled_policy=None)
    status, summary, details = _classify_defender_state(state)
    assert status == "HIGH"
    assert "turned OFF" in summary
    assert "DISABLED" in details


def test_defender_policy_disabled_is_high():
    state = DefenderState(disabled_local=None, disabled_policy=True)
    status, summary, details = _classify_defender_state(state)
    assert status == "HIGH"
    assert "policy" in details.lower()


def test_defender_enabled_hint_is_ok():
    state = DefenderState(disabled_local=False, disabled_policy=None)
    status, summary, details = _classify_defender_state(state)
    assert status == "OK"
    assert "real-time protection appears to be turned ON" in summary
    assert "NOT disabled" in details


def test_defender_unknown_is_unknown():
    state = DefenderState(disabled_local=None, disabled_policy=None)
    status, summary, _ = _classify_defender_state(state)
    assert status == "UNKNOWN"
    # Wording changed to "could not find clear settings ..."
    assert "could not find clear settings" in summary