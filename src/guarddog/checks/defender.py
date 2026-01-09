"""Microsoft Defender antivirus / real-time protection checks.

Goal:
- Non-admin, read-only.
- Determine whether Microsoft Defender real-time protection is enabled.

Primary method:
- PowerShell: Get-MpComputerStatus (most accurate when available)

Fallback method:
- Registry heuristic: DisableRealtimeMonitoring flags (best-effort only)

Important:
- Registry flags are not always a perfect reflection of the effective state on modern Windows.
- For MVP, we treat registry as a fallback indicator only.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Tuple, Optional

try:
    import winreg  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore[assignment]


BASE_KEY_PATH = r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
POLICY_KEY_PATH = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
VALUE_NAME = "DisableRealtimeMonitoring"


@dataclass
class DefenderState:
    # Core fields (tests already use these)
    disabled_local: bool | None
    disabled_policy: bool | None

    # Optional hints (defaults keep tests lightweight)
    am_service_enabled: bool | None = None
    antivirus_enabled: bool | None = None
    rtp_enabled: bool | None = None

    # Optional metadata (defaults)
    data_source: str = "none"
    error: str | None = None


def _find_powershell_exe() -> str:
    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidate = os.path.join(windir, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    if os.path.isfile(candidate):
        return candidate
    return "powershell"


def _run_powershell_json(script: str, timeout_seconds: int = 8) -> str | None:
    ps_exe = _find_powershell_exe()
    wrapped = (
        "$ErrorActionPreference = 'Stop'; "
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        + script
    )
    cmd = [ps_exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", wrapped]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return None

    if proc.returncode != 0:
        return None

    out = proc.stdout.strip()
    return out if out else None


def _query_defender_powershell() -> dict | None:
    ps_script = r"""
    $obj = Get-MpComputerStatus | Select-Object -Property `
      AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled
    $obj | ConvertTo-Json -Compress
    """.strip()

    out = _run_powershell_json(ps_script)
    if not out:
        return None

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None

    if isinstance(data, list):
        if not data:
            return None
        data = data[0]

    return data if isinstance(data, dict) else None


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


def _get_defender_state() -> DefenderState:
    # 1) PowerShell path (preferred)
    data = _query_defender_powershell()
    if data is not None:
        rtp = data.get("RealTimeProtectionEnabled")
        ams = data.get("AMServiceEnabled")
        av = data.get("AntivirusEnabled")

        rtp_enabled = rtp if isinstance(rtp, bool) else None
        am_service_enabled = ams if isinstance(ams, bool) else None
        antivirus_enabled = av if isinstance(av, bool) else None

        disabled_local: bool | None
        if rtp_enabled is True:
            disabled_local = False
        elif rtp_enabled is False:
            disabled_local = True
        else:
            disabled_local = None

        return DefenderState(
            disabled_local=disabled_local,
            disabled_policy=None,
            am_service_enabled=am_service_enabled,
            antivirus_enabled=antivirus_enabled,
            rtp_enabled=rtp_enabled,
            data_source="powershell",
            error=None,
        )

    # 2) Registry fallback (heuristic)
    if winreg is None:
        return DefenderState(
            disabled_local=None,
            disabled_policy=None,
            am_service_enabled=None,
            antivirus_enabled=None,
            rtp_enabled=None,
            data_source="none",
            error="winreg unavailable (not running on Windows Python).",
        )

    root = winreg.HKEY_LOCAL_MACHINE
    local_val = _read_registry_dword(root, BASE_KEY_PATH, VALUE_NAME)
    policy_val = _read_registry_dword(root, POLICY_KEY_PATH, VALUE_NAME)

    def interp(v: int | None) -> bool | None:
        if v is None:
            return None
        return v == 1  # 1 -> disabled, 0 -> not disabled

    return DefenderState(
        disabled_local=interp(local_val),
        disabled_policy=interp(policy_val),
        am_service_enabled=None,
        antivirus_enabled=None,
        rtp_enabled=None,
        data_source="registry",
        error=None,
    )


def _classify_defender_state(state: DefenderState) -> Tuple[str, str, str]:
    """
    Given a DefenderState, decide the check status, summary, and details.

    Returns:
        (status, summary, details)

    Note: unit tests expect specific wording in summary/details.
    """
    detail_lines: list[str] = []

    # Always include local/policy interpretation if we have it, regardless of data_source.
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

    # Optional metadata (nice to have)
    if getattr(state, "data_source", None):
        detail_lines.append(f"- Data source: {state.data_source}")
    if getattr(state, "error", None):
        detail_lines.append(f"- Error: {state.error}")

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
        return status, summary, details

    if any_enabled_hint:
        status = "OK"
        summary = (
            "Microsoft Defender real-time protection appears to be turned ON "
            "(it is not marked as disabled in local or policy settings)."
        )
        return status, summary, details

    status = "UNKNOWN"
    summary = (
        "GuardDog could not find clear settings for Microsoft Defender real-time protection. "
        "This can happen if another antivirus product is managing protection, or if this "
        "Windows version stores these settings differently."
    )
    return status, summary, details



def run():
    """
    Run the Defender check and return:
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
                "Open Windows Security → 'Virus & threat protection' and check whether real-time protection is on."
            ),
        }

    if status == "OK":
        remediation = (
            "No action needed. You can confirm this in Windows Security → 'Virus & threat protection'."
        )
    elif status == "HIGH":
        remediation = (
            "Open Windows Security → 'Virus & threat protection' → 'Manage settings' and turn real-time protection ON. "
            "If you use another antivirus product, confirm it is active and up to date."
        )
    else:
        remediation = (
            "GuardDog could not clearly read Defender’s status. Open Windows Security → 'Virus & threat protection' "
            "and confirm real-time protection (or another antivirus product) is active."
        )

    return {
        "id": "defender",
        "title": "Microsoft Defender",
        "status": status,
        "summary": summary,
        "details": details,
        "remediation": remediation,
    }