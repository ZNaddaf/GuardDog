"""Remote Desktop (RDP) + Network Level Authentication checks.

This check inspects Windows registry keys to determine:

- Whether Remote Desktop connections are allowed.
- If allowed, whether Network Level Authentication (NLA) is required.

Keys (Windows 10/11, typical):

- HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections
    0 = Allow connections (RDP enabled)
    1 = Do not allow connections (RDP disabled)

- HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication
    0 = NLA not required
    1 = NLA required

This is a non-admin, read-only check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

try:
    import winreg  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - should exist on Windows
    winreg = None  # type: ignore[assignment]


RDP_KEY_PATH = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP_TCP_KEY_PATH = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"


@dataclass
class RdpState:
    """Simple container for RDP status."""

    rdp_enabled: bool | None  # True/False if known, None if unknown
    nla_required: bool | None  # True/False if known, None if unknown


def _read_registry_dword(root, subkey: str, value_name: str) -> int | None:
    """
    Helper: read a REG_DWORD value from HKLM.

    Returns:
        int value, or None if the key/value is missing or cannot be read.
    """
    if winreg is None:
        return None

    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
            value, reg_type = winreg.QueryValueEx(key, value_name)
            if reg_type != winreg.REG_DWORD:
                return None
            return int(value)
    except OSError:
        return None


def _get_rdp_state() -> RdpState:
    """
    Read registry values and return an RdpState.

    fDenyTSConnections:
        0 -> RDP enabled
        1 -> RDP disabled

    UserAuthentication:
        0 -> NLA not required
        1 -> NLA required
    """
    if winreg is None:
        return RdpState(rdp_enabled=None, nla_required=None)

    # HKLM root
    root = winreg.HKEY_LOCAL_MACHINE

    # fDenyTSConnections
    deny = _read_registry_dword(root, RDP_KEY_PATH, "fDenyTSConnections")
    if deny is None:
        rdp_enabled = None
    else:
        # If deny == 0, we allow RDP connections.
        rdp_enabled = deny == 0

    # UserAuthentication
    user_auth = _read_registry_dword(root, RDP_TCP_KEY_PATH, "UserAuthentication")
    if user_auth is None:
        nla_required = None
    else:
        nla_required = user_auth == 1

    return RdpState(rdp_enabled=rdp_enabled, nla_required=nla_required)


def _classify_rdp_state(state: RdpState) -> Tuple[str, str, str]:
    """
    Decide check status, summary and details given an RdpState.

    Returns:
        (status, summary, details)
    """
    # Build human-readable details
    detail_lines = []

    if state.rdp_enabled is True:
        detail_lines.append("- Remote Desktop connections: ENABLED")
    elif state.rdp_enabled is False:
        detail_lines.append("- Remote Desktop connections: DISABLED")
    else:
        detail_lines.append("- Remote Desktop connections: UNKNOWN")

    if state.nla_required is True:
        detail_lines.append("- Network Level Authentication (NLA): REQUIRED")
    elif state.nla_required is False:
        detail_lines.append("- Network Level Authentication (NLA): NOT required")
    else:
        detail_lines.append("- Network Level Authentication (NLA): UNKNOWN")

    details = "\n".join(detail_lines)

    # Classification logic
    if state.rdp_enabled is False:
        status = "OK"
        summary = (
            "Remote Desktop is turned OFF. This reduces the risk of remote logins to this computer."
        )
    elif state.rdp_enabled is True and state.nla_required is True:
        status = "OK"
        summary = (
            "Remote Desktop is turned ON, and Network Level Authentication (NLA) is required."
        )
    elif state.rdp_enabled is True and state.nla_required is False:
        status = "HIGH"
        summary = (
            "Remote Desktop is ON and Network Level Authentication (NLA) is NOT required. "
            "This makes it easier for attackers to try to sign in remotely."
        )
    elif state.rdp_enabled is True and state.nla_required is None:
        status = "WARN"
        summary = (
            "Remote Desktop is ON, but GuardDog could not confirm whether NLA is required."
        )
    else:
        # Covers cases where rdp_enabled is None
        status = "UNKNOWN"
        summary = (
            "GuardDog could not determine the Remote Desktop settings from the registry."
        )

    return status, summary, details


def run():
    """
    Run the RDP + NLA check and return a standardized result dict.

    Schema:
        id, title, status, summary, details, remediation
    """
    try:
        state = _get_rdp_state()
        status, summary, details = _classify_rdp_state(state)
    except Exception as exc:  # noqa: BLE001
        return {
            "id": "rdp",
            "title": "Remote Desktop (RDP)",
            "status": "UNKNOWN",
            "summary": "GuardDog could not read the Remote Desktop settings due to an internal error.",
            "details": f"Error: {exc!r}",
            "remediation": (
                "You can open the System settings, go to 'Remote Desktop', and check whether "
                "Remote Desktop is enabled and if Network Level Authentication is required."
            ),
        }

    # Remediation text based on status
    if status == "OK":
        remediation = (
            "No urgent action needed. If you do not need Remote Desktop at all, you can turn it off "
            "in Settings → System → Remote Desktop."
        )
    elif status == "HIGH":
        remediation = (
            "Open Settings → System → Remote Desktop. If you do not need Remote Desktop, turn it off. "
            "If you do need it, ensure that 'Require devices to use Network Level Authentication' is turned ON."
        )
    elif status == "WARN":
        remediation = (
            "Open Settings → System → Remote Desktop and check whether Remote Desktop is enabled. "
            "If it is enabled, make sure that 'Require devices to use Network Level Authentication' is turned ON."
        )
    else:  # UNKNOWN
        remediation = (
            "GuardDog could not reliably read the Remote Desktop settings. "
            "You can manually open Settings → System → Remote Desktop to check whether Remote Desktop "
            "is enabled, and whether Network Level Authentication is required."
        )

    return {
        "id": "rdp",
        "title": "Remote Desktop (RDP)",
        "status": status,
        "summary": summary,
        "details": details,
        "remediation": remediation,
    }
