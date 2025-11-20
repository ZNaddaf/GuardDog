"""Microsoft Defender antivirus / real-time protection checks.

This check inspects Microsoft Defender status to determine whether real-time
protection is enabled or disabled.

It prefers using the Defender PowerShell cmdlet:

    Get-MpComputerStatus | Select-Object -Property AMServiceEnabled, RealTimeProtectionEnabled

If that fails (e.g. Defender module not present), it falls back to checking
registry values:

- HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring
- HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring

Values (typical):

    0 = real-time monitoring is NOT disabled (i.e., ON)
    1 = real-time monitoring is disabled (i.e., OFF)

This is a non-admin, read-only check.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Tuple

try:
    import winreg  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - should exist on Windows
    winreg = None  # type: ignore[assignment]


BASE_KEY_PATH = r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
POLICY_KEY_PATH = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
VALUE_NAME = "DisableRealtimeMonitoring"


@dataclass
class DefenderState:
    """Container for Defender real-time protection status."""

    disabled_local: bool | None   # True/False if known, None if unknown/missing
    disabled_policy: bool | None  # True/False if known, None if unknown/missing


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


def _query_defender_powershell() -> dict | None:
    """
    Try to query Defender status using the Get-MpComputerStatus PowerShell cmdlet.

    Returns:
        dict with keys like "AMServiceEnabled" and "RealTimeProtectionEnabled",
        or None if the command is not available or fails.

    This is a non-admin, read-only query.
    """
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            "(Get-MpComputerStatus | "
            "Select-Object -Property AMServiceEnabled,RealTimeProtectionEnabled) "
            "| ConvertTo-Json -Compress"
        ),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=5,
        )
    except Exception:
        return None

    if proc.returncode != 0:
        return None

    stdout = proc.stdout.strip()
    if not stdout:
        return None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return None

    # ConvertTo-Json can return an object or an array with one element.
    if isinstance(data, list):
        if not data:
            return None
        data = data[0]

    if not isinstance(data, dict):
        return None

    return data


def _get_defender_state() -> DefenderState:
    """
    Read Defender state using PowerShell first, then registry fallback.

    DisableRealtimeMonitoring (registry):
        0 -> real-time protection NOT disabled (ON)
        1 -> real-time protection disabled (OFF)
    """
    # 1) Try PowerShell (preferred, more accurate on modern Windows).
    data = _query_defender_powershell()
    if data is not None:
        # If PowerShell gives us booleans, we can map them directly.
        rtp_enabled = data.get("RealTimeProtectionEnabled")
        # We treat "False" (or false) as "disabled", True as "not disabled".
        disabled_local: bool | None
        if isinstance(rtp_enabled, bool):
            disabled_local = not rtp_enabled
        else:
            disabled_local = None

        # We don't get explicit policy info from this call, so leave as None.
        return DefenderState(
            disabled_local=disabled_local,
            disabled_policy=None,
        )

    # 2) Fallback: registry-based heuristic (older approach).
    if winreg is None:
        return DefenderState(disabled_local=None, disabled_policy=None)

    root = winreg.HKEY_LOCAL_MACHINE

    local_val = _read_registry_dword(root, BASE_KEY_PATH, VALUE_NAME)
    policy_val = _read_registry_dword(root, POLICY_KEY_PATH, VALUE_NAME)

    def interp(v: int | None) -> bool | None:
        if v is None:
            return None
        # 1 -> disabled; 0 -> not disabled
        return v == 1

    return DefenderState(
        disabled_local=interp(local_val),
        disabled_policy=interp(policy_val),
    )


def _classify_defender_state(state: DefenderState) -> Tuple[str, str, str]:
    """
    Given a DefenderState, decide the check status, summary, and details.

    Returns:
        (status, summary, details)
    """
    # Build human-readable details
    detail_lines = []

    if state.disabled_local is True:
        detail_lines.append("- Local setting: real-time protection is DISABLED.")
    elif state.disabled_local is False:
        detail_lines.append("- Local setting: real-time protection is NOT disabled.")
    else:
        detail_lines.append("- Local setting: real-time protection status is UNKNOWN.")

    if state.disabled_policy is True:
        detail_lines.append("- Policy: real-time protection is DISABLED by policy.")
    elif state.disabled_policy is False:
        detail_lines.append("- Policy: real-time protection is NOT disabled by policy.")
    else:
        detail_lines.append("- Policy: real-time protection policy status is UNKNOWN.")

    details = "\n".join(detail_lines)

    # Classification logic
    any_disabled = (state.disabled_local is True) or (state.disabled_policy is True)
    any_enabled_hint = (state.disabled_local is False) or (state.disabled_policy is False)

    if any_disabled:
        status = "HIGH"
        summary = (
            "Microsoft Defender real-time protection appears to be turned OFF. "
            "This makes it easier for malware to run without being noticed."
        )
    elif any_enabled_hint:
        status = "OK"
        summary = (
            "Microsoft Defender real-time protection appears to be turned ON "
            "(it is not marked as disabled in local or policy settings)."
        )
    else:
        status = "UNKNOWN"
        summary = (
            "GuardDog could not find clear settings for Microsoft Defender real-time protection. "
            "This can happen if another antivirus product is managing protection, or if this "
            "Windows version stores these settings differently."
        )

    return status, summary, details


def run():
    """
    Run the Defender check and return a standardized result dict.

    Schema:
        id, title, status, summary, details, remediation
    """
    try:
        state = _get_defender_state()
        status, summary, details = _classify_defender_state(state)
    except Exception as exc:  # noqa: BLE001
        return {
            "id": "defender",
            "title": "Microsoft Defender",
            "status": "UNKNOWN",
            "summary": "GuardDog could not read the Microsoft Defender settings due to an internal error.",
            "details": f"Error: {exc!r}",
            "remediation": (
                "You can open the Windows Security app, go to 'Virus & threat protection', and "
                "check whether real-time protection is turned on."
            ),
        }

    # Remediation guidance based on status
    if status == "OK":
        remediation = (
            "No action needed. Microsoft Defender real-time protection appears to be enabled. "
            "You can confirm this in the Windows Security app under 'Virus & threat protection'."
        )
    elif status == "HIGH":
        remediation = (
            "Open the Windows Security app, go to 'Virus & threat protection', choose "
            "any link such as 'Manage settings' or 'Virus & threat protection settings', and make "
            "sure real-time or always-on protection is turned ON. If you use another antivirus "
            "product, check that it is active and up to date."
        )
    else:  # UNKNOWN
        remediation = (
            "GuardDog could not clearly read the Defender real-time protection settings. "
            "Open the Windows Security app, go to 'Virus & threat protection', and look for links "
            "such as 'Manage settings' or 'Virus & threat protection settings'. Check whether "
            "real-time or always-on protection is turned on. If another antivirus product is "
            "installed, open that product's settings and confirm that its real-time protection is active."
        )

    return {
        "id": "defender",
        "title": "Microsoft Defender",
        "status": status,
        "summary": summary,
        "details": details,
        "remediation": remediation,
    }