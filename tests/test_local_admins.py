from guarddog.checks.local_admins import LocalAdminsState, _classify_local_admins_state


def test_local_admins_unknown_when_empty():
    state = LocalAdminsState(members=[], local_admins=[], extra_local_admins=[])
    status, summary, details = _classify_local_admins_state(state)
    assert status == "UNKNOWN"
    assert "could not read" in summary
    assert "No members were returned" in details


def test_local_admins_ok_when_only_builtin_or_domain():
    state = LocalAdminsState(
        members=["MYPC\\Administrator", "MYDOMAIN\\Domain Admins"],
        local_admins=["MYPC\\Administrator"],
        extra_local_admins=[],
    )
    status, summary, details = _classify_local_admins_state(state)
    assert status == "OK"
    assert "built-in or domain accounts" in summary
    assert "MYPC\\Administrator" in details
    assert "MYDOMAIN\\Domain Admins" in details


def test_local_admins_warn_when_extra_local_admins_present():
    state = LocalAdminsState(
        members=["MYPC\\Administrator", "MYPC\\Alice", "MYDOMAIN\\Domain Admins"],
        local_admins=["MYPC\\Administrator", "MYPC\\Alice"],
        extra_local_admins=["MYPC\\Alice"],
    )
    status, summary, details = _classify_local_admins_state(state)
    assert status == "WARN"
    assert "local user accounts have administrator rights" in summary
    assert "MYPC\\Alice" in details
