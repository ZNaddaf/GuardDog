from guarddog.checks.firewall import _parse_netsh_allprofiles, _classify_firewall_status


def test_parse_netsh_allprofiles_basic():
    sample = """
    Domain Profile Settings:
        State                                 ON

    Private Profile Settings:
        State                                 OFF

    Public Profile Settings:
        State                                 ON
    """
    states = _parse_netsh_allprofiles(sample)
    assert states == {
        "domain": "ON",
        "private": "OFF",
        "public": "ON",
    }


def test_classify_firewall_status_ok():
    states = {"domain": "ON", "private": "ON", "public": "ON"}
    status, summary, details = _classify_firewall_status(states)
    assert status == "OK"
    assert "Firewall is turned ON" in summary
    assert "Domain profile" in details


def test_classify_firewall_status_high_if_any_off():
    states = {"domain": "ON", "private": "OFF"}
    status, summary, _ = _classify_firewall_status(states)
    assert status == "HIGH"
    assert "turned OFF" in summary
