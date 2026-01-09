"""Firewall status checks (Windows Defender Firewall).

Primary method:
- netsh advfirewall show allprofiles (best effort, but locale-dependent)

Fallback method:
- Registry reads for EnableFirewall under FirewallPolicy profile keys (locale-agnostic)

- Non-admin.
- Read-only.
- No network access.
"""

from __future__ import annotations

import os
import subprocess
from typing import Dict, Tuple, Optional

import winreg


_NETSH_PATH = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "netsh.exe")


def _run_netsh_allprofiles(timeout_seconds: int = 8) -> str:
    """
    Run `netsh advfirewall show allprofiles` and return stdout as text.

    - Uses absolute path to netsh.exe to reduce binary-hijack risk.
    - Uses a timeout to avoid hangs.
    """
    proc = subprocess.run(
        [_NETSH_PATH, "advfirewall", "show", "allprofiles"],
        capture_output=True,
        text=True,                  # use system default encoding for this host
        errors="replace",
        timeout=timeout_seconds,
        stdin=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"netsh advfirewall failed with code {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc.stdout


def _parse_netsh_allprofiles(output: str) -> Dict[str, str]:
    """
    Parse netsh output for firewall State lines (English only).

    Returns profile -> state ("ON"/"OFF"/other).
    """
    profiles: Dict[str, str] = {}
    current_profile: Optional[str] = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        lower = line.lower()

        if "domain profile settings" in lower:
            current_profile = "domain"
            continue
        if "private profile settings" in lower:
            current_profile = "private"
            continue
        if "public profile settings" in lower:
            current_profile = "public"
            continue

        if current_profile is None:
            continue

        if lower.startswith("state"):
            parts = line.split()
            if len(parts) >= 2:
                profiles[current_profile] = parts[-1].upper()

    return profiles


def _read_reg_dword(root, path: str, name: str) -> Optional[int]:
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            value, vtype = winreg.QueryValueEx(key, name)
            if vtype == winreg.REG_DWORD:
                return int(value)
    except OSError:
        return None
    return None


def _registry_firewall_states() -> Dict[str, str]:
    """
    Read firewall enabled state from registry.

    Prefer policy locations when present (common on managed systems),
    otherwise fall back to current control set.

    Returns profile -> "ON"/"OFF"/"UNKNOWN".
    """
    result: Dict[str, str] = {}

    # Policy path (can override/represent enforced settings)
    policy_base = r"SOFTWARE\Policies\Microsoft\WindowsFirewall"
    policy_profiles = {
        "domain": policy_base + r"\DomainProfile",
        "private": policy_base + r"\PrivateProfile",
        "public": policy_base + r"\PublicProfile",
    }

    # Non-policy operational path
    ops_base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    ops_profiles = {
        "domain": ops_base + r"\DomainProfile",
        "private": ops_base + r"\StandardProfile",  # StandardProfile corresponds to "Private" historically
        "public": ops_base + r"\PublicProfile",
    }

    for profile in ("domain", "private", "public"):
        enabled = _read_reg_dword(winreg.HKEY_LOCAL_MACHINE, policy_profiles[profile], "EnableFirewall")
        if enabled is None:
            enabled = _read_reg_dword(winreg.HKEY_LOCAL_MACHINE, ops_profiles[profile], "EnableFirewall")

        if enabled is None:
            result[profile] = "UNKNOWN"
        elif enabled == 1:
            result[profile] = "ON"
        elif enabled == 0:
            result[profile] = "OFF"
        else:
            result[profile] = f"UNKNOWN({enabled})"

    return result


def _classify_firewall_status(profile_states: Dict[str, str]) -> Tuple[str, str, str]:
    if not profile_states:
        return (
            "UNKNOWN",
            "GuardDog could not read the firewall status.",
            "No firewall status data was available.",
        )

    any_off = any(state == "OFF" for state in profile_states.values())
    any_unknown = any(state.startswith("UNKNOWN") for state in profile_states.values())
    all_on = all(state == "ON" for state in profile_states.values())

    detail_lines = [f"- {p.title()} profile: {profile_states.get(p, 'UNKNOWN')}" for p in ("domain", "private", "public")]
    details = "\n".join(detail_lines)

    if any_off:
        return (
            "HIGH",
            "Windows Firewall is turned OFF for at least one network profile.",
            details,
        )
    if all_on:
        return (
            "OK",
            "Windows Firewall is turned ON for all network profiles.",
            details,
        )
    if any_unknown:
        return (
            "WARN",
            "GuardDog could not verify the firewall state for every profile.",
            details,
        )
    return (
        "WARN",
        "GuardDog could not confirm that Windows Firewall is turned on for all profiles.",
        details,
    )


def run():
    """
    Run the firewall check and return a standardized result dict:
        id, title, status, summary, details, remediation
    """
    title = "Windows Firewall"

    # Try netsh first (nice output when it works), then fallback to registry for widest net.
    profile_states: Dict[str, str] = {}
    netsh_error: Optional[str] = None

    try:
        output = _run_netsh_allprofiles()
        profile_states = _parse_netsh_allprofiles(output)
    except Exception as exc:  # noqa: BLE001
        netsh_error = repr(exc)

    if not profile_states:
        profile_states = _registry_firewall_states()

    status, summary, details = _classify_firewall_status(profile_states)

    if netsh_error:
        details = (details + "\n\n" + f"(Note: netsh parsing failed; used registry fallback. Error: {netsh_error})").strip()

    remediation = (
        "Open the Windows Security app → 'Firewall & network protection' and make sure the firewall is ON "
        "for Domain, Private, and Public networks."
    )
    if status == "OK":
        remediation = "No action needed. Windows Firewall appears to be ON for all profiles."

    return {
        "id": "firewall",
        "title": title,
        "status": status,
        "summary": summary,
        "details": details,
        "remediation": remediation,
    }