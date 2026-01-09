"""Local Administrators group membership checks.

Goal:
- Non-admin, read-only.
- Determine who is in the local Administrators group.
- Highlight "extra local admins" (local user accounts beyond the built-in Administrator).

Primary method:
- PowerShell: Get-LocalGroupMember -Group 'Administrators' | ConvertTo-Json

Fallback method (when Get-LocalGroupMember fails):
- ADSI WinNT provider: WinNT://./Administrators,group

Notes:
- This intentionally does NOT try to handle non-English group names as a project goal.
- Output is structured to support plain-language reporting.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import List, Tuple, Optional


@dataclass
class LocalAdminsState:
    members: List[str]
    local_admins: List[str]
    extra_local_admins: List[str]

    data_source: str = "none"
    error: str | None = None


def _find_powershell_exe() -> str:
    """
    Prefer Windows PowerShell if present at the well-known path.
    Fallback to just 'powershell' (let PATH resolve it).
    """
    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidate = os.path.join(windir, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    if os.path.isfile(candidate):
        return candidate
    return "powershell"


def _run_powershell_json(script: str, timeout_seconds: int = 8) -> str | None:
    """
    Run a PowerShell script and return stdout (expected JSON), or None on failure.
    Forces UTF-8 output encoding to match Python decoding.
    """
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


def _parse_names_from_json(stdout: str) -> list[str] | None:
    """
    ConvertTo-Json can return:
    - a dict (single object)
    - a list of dicts
    We extract item['Name'] for each.
    """
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return None

    items: list[dict]
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = [x for x in data if isinstance(x, dict)]
    else:
        return None

    names: list[str] = []
    for item in items:
        name = item.get("Name")
        if isinstance(name, str) and name.strip():
            names.append(name.strip())

    return names or None


def _query_local_admins() -> Tuple[list[str] | None, str, str | None]:
    """
    Try PowerShell Get-LocalGroupMember first.
    If that fails, try ADSI WinNT provider.
    Returns: (names_or_none, data_source, error_or_none)
    """
    # 1) Try Get-LocalGroupMember (preferred)
    ps_script_primary = r"""
    Get-LocalGroupMember -Group 'Administrators' |
      Select-Object -Property Name,ObjectClass |
      ConvertTo-Json -Compress
    """.strip()

    out = _run_powershell_json(ps_script_primary)
    if out:
        names = _parse_names_from_json(out)
        if names:
            return (names, "powershell", None)

    # 2) Fallback: ADSI WinNT provider (often works when LocalAccounts module doesn't)
    ps_script_fallback = r"""
    $group = [ADSI]"WinNT://./Administrators,group"
    $members = @($group.psbase.Invoke("Members"))
    $out = @()
    foreach ($m in $members) {
      $name  = $m.GetType().InvokeMember("Name",'GetProperty',$null,$m,$null)
      $class = $m.GetType().InvokeMember("Class",'GetProperty',$null,$m,$null)
      $out += [PSCustomObject]@{ Name = [string]$name; ObjectClass = [string]$class }
    }
    $out | ConvertTo-Json -Compress
    """.strip()

    out2 = _run_powershell_json(ps_script_fallback)
    if out2:
        names2 = _parse_names_from_json(out2)
        if names2:
            return (names2, "adsi", None)

    return (None, "none", "PowerShell query failed or returned no usable data.")


def _get_local_admins_state() -> LocalAdminsState:
    names, source, err = _query_local_admins()
    members = names or []

    computer_name = os.environ.get("COMPUTERNAME", "").strip()
    local_admins: list[str] = []
    extra_local_admins: list[str] = []

    if computer_name and members:
        prefix = (computer_name + "\\").upper()
        for name in members:
            if name.upper().startswith(prefix):
                local_admins.append(name)

        builtin_admin_upper = f"{computer_name}\\Administrator".upper()
        for name in local_admins:
            if name.upper() != builtin_admin_upper:
                extra_local_admins.append(name)

    return LocalAdminsState(
        members=members,
        local_admins=local_admins,
        extra_local_admins=extra_local_admins,
        data_source=source,
        error=err,
    )


def _classify_local_admins_state(state: LocalAdminsState) -> Tuple[str, str, str]:
    if not state.members:
        return (
            "UNKNOWN",
            "GuardDog could not read the list of administrator accounts.",
            "No members were returned for the local Administrators group. "
            f"Data source: {state.data_source}. "
            + (f"Error: {state.error}" if state.error else ""),
        )

    detail_lines: list[str] = []
    detail_lines.append("The following accounts have administrator rights on this computer:")

    # Mark local accounts
    extras_upper = {x.upper() for x in state.extra_local_admins}
    locals_upper = {x.upper() for x in state.local_admins}

    for name in state.members:
        name_u = name.upper()
        if name_u in extras_upper:
            marker = " (local user account)"
        elif name_u in locals_upper:
            marker = " (built-in local account)"
        else:
            marker = ""
        detail_lines.append(f"- {name}{marker}")

    detail_lines.append("")
    detail_lines.append(f"Data source: {state.data_source}")

    details = "\n".join(detail_lines)

    if state.extra_local_admins:
        return (
            "WARN",
            "One or more local user accounts have administrator rights on this computer.",
            details,
        )

    return (
        "OK",
            "Only built-in or domain accounts were found in the local Administrators group.",
        details,
    )


def run():
    """
    Run the local administrators check and return:
        id, title, status, summary, details, remediation
    """
    try:
        state = _get_local_admins_state()
        status, summary, details = _classify_local_admins_state(state)
    except Exception as exc:  # noqa: BLE001
        return {
            "id": "local_admins",
            "title": "Local Administrators",
            "status": "UNKNOWN",
            "summary": "GuardDog could not read the local administrator accounts due to an internal error.",
            "details": f"Error: {exc!r}",
            "remediation": (
                "Open Computer Management → Local Users and Groups → Groups → Administrators "
                "to see which accounts have administrator rights."
            ),
        }

    if status == "OK":
        remediation = (
            "No urgent action needed. If you are not sure who should have administrator rights, "
            "review the list and remove admin rights from everyday accounts when possible."
        )
    elif status == "WARN":
        remediation = (
            "Review the local user accounts listed here that have administrator rights. "
            "If you do not recognize an account, or if a day-to-day account has admin rights, "
            "consider removing those rights. It is safer to use a standard (non-admin) account for "
            "everyday work and a separate admin account only when needed."
        )
    else:
        remediation = (
            "GuardDog could not clearly read the local administrator accounts. "
            "You can manually check: Computer Management → Local Users and Groups → Groups → Administrators."
        )

    return {
        "id": "local_admins",
        "title": "Local Administrators",
        "status": status,
        "summary": summary,
        "details": details,
        "remediation": remediation,
    }