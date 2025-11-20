from guarddog.checks.rdp import RdpState, _classify_rdp_state


def test_rdp_disabled_is_ok():
    state = RdpState(rdp_enabled=False, nla_required=None)
    status, summary, details = _classify_rdp_state(state)
    assert status == "OK"
    assert "turned OFF" in summary
    assert "DISABLED" in details


def test_rdp_enabled_with_nla_ok():
    state = RdpState(rdp_enabled=True, nla_required=True)
    status, summary, details = _classify_rdp_state(state)
    assert status == "OK"
    assert "NLA" in summary
    assert "ENABLED" in details
    assert "REQUIRED" in details


def test_rdp_enabled_without_nla_high():
    state = RdpState(rdp_enabled=True, nla_required=False)
    status, summary, _ = _classify_rdp_state(state)
    assert status == "HIGH"
    assert "NOT required" in summary or "NOT required" in _  # wording check


def test_rdp_unknown_is_unknown():
    state = RdpState(rdp_enabled=None, nla_required=None)
    status, summary, _ = _classify_rdp_state(state)
    assert status == "UNKNOWN"
    assert "could not determine" in summary
