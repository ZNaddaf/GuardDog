"""Remote Desktop (RDP) + Network Level Authentication checks.

This check inspects registry keys to determine:
- Whether Remote Desktop connections are allowed.
- If allowed, whether Network Level Authentication (NLA) is required.

Keys (typical):
- HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections
    0 = Allow connections (RDP enabled)
    1 = Do not allow connections (RDP disabled)

- HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication
    0 = NLA not required
    1 = NLA required

Supporting signal (optional, but helpful):
- HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\SecurityLayer
    0 = RDP Security Layer
    1 = Negotiate
    2 = SSL (TLS)
  (This is not a perfect NLA indicator, but helps interpret posture.)

Non-admin, read-only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

try:
    import winreg  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore[assignment]


RDP_KEY_PATH = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP_TCP_KEY_PATH = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"


@dataclass
class RdpState:
    rdp_enabled: bool | None
    nla_required: bool | None

    security_layer: int | None = None
    data_source: str = "registry"
    error: str | None = None


def _read_registry_dword(root, subkey: str, value_name: str) -> int | None:
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
    if winreg is None:
        return RdpState(
            rdp_enabled=None,
            nla_required=None,
            security_layer=None,
            data_source="none",
            error="winreg unavailable (not running on Windows Python).",
        )

    root = winreg.HKEY_LOCAL_MACHINE

    deny = _read_registry_dword(root, RDP_KEY_PATH, "fDenyTSConnections")
    if deny is None:
        rdp_enabled = None
    else:
        rdp_enabled = (deny == 0)

    user_auth = _read_registry_dword(root, RDP_TCP_KEY_PATH, "UserAuthentication")
    if user_auth is None:
        nla_required = None
    else:
        nla_required = (user_auth == 1)

    security_layer = _read_registry_dword(root, RDP_TCP_KEY_PATH, "SecurityLayer")

    return RdpState(
        rdp_enabled=rdp_enabled,
        nla_required=nla_required,
        security_layer=security_layer,
        data_source="registry",
        error=None,
    )


def _security_layer_text(v: int | None) -> str:
    if v is None:
        return "UNKNOWN"
    if v == 0:
        return "RDP (0)"
    if v == 1:
        return "Negotiate (1)"
    if v == 2:
        return "TLS/SSL (2)"
    return f"UNKNOWN({v})"


def _classify_rdp_state(state: RdpState) -> Tuple[str, str, str]:
    detail_lines: list[str] = []
    detail_lines.append(f"Data source: {state.data_source}")

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

    detail_lines.append(f"- Security layer (supporting): {_security_layer_text(state.security_layer)}")

    if state.error:
        detail_lines.append(f"Error: {state.error}")

    details = "\n".join(detail_lines)

    # Classification logic (keep simple and user-facing)
    if state.rdp_enabled is False:
        return (
            "OK",
            "Remote Desktop is turned OFF. This reduces the risk of remote logins to this computer.",
            details,
        )

    if state.rdp_enabled is True and state.nla_required is True:
        return (
            "OK",
            "Remote Desktop is turned ON, and Network Level Authentication (NLA) is required.",
            details,
        )

    if state.rdp_enabled is True and state.nla_required is False:
        return (
            "HIGH",
            "Remote Desktop is ON and Network Level Authentication (NLA) is NOT required. This increases risk.",
            details,
        )

    if state.rdp_enabled is True and state.nla_required is None:
        return (
            "WARN",
            "Remote Desktop is ON, but GuardDog could not confirm whether NLA is required.",
            details,
        )

    return (
        "UNKNOWN",
        "GuardDog could not determine the Remote Desktop settings from the registry.",
        details,
    )


def run():
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
                "Open Settings → System → Remote Desktop and check whether Remote Desktop is enabled "
                "and whether NLA is required."
            ),
        }

    if status == "OK":
        remediation = (
            "No urgent action needed. If you do not need Remote Desktop, you can turn it off in "
            "Settings → System → Remote Desktop."
        )
    elif status == "HIGH":
        remediation = (
            "Open Settings → System → Remote Desktop. If you do not need Remote Desktop, turn it off. "
            "If you do need it, ensure 'Require devices to use Network Level Authentication' is ON."
        )
    elif status == "WARN":
        remediation = (
            "Open Settings → System → Remote Desktop and confirm NLA is required if Remote Desktop is enabled."
        )
    else:
        remediation = (
            "GuardDog could not reliably read the Remote Desktop settings. Manually check "
            "Settings → System → Remote Desktop."
        )

    return {
        "id": "rdp",
        "title": "Remote Desktop (RDP)",
        "status": status,
        "summary": summary,
        "details": details,
        "remediation": remediation,
    }
