"""Local Administrators group membership checks.

This check inspects the local "Administrators" group and reports which accounts
have administrator rights on this computer.

It uses the PowerShell cmdlet:

    Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass

and classifies the result based on whether there are local user accounts with
administrator rights in addition to the built-in Administrator account.

This is a non-admin, read-only check.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class LocalAdminsState:
    """Container for local administrators group membership."""

    members: List[str]              # All member names as reported
    local_admins: List[str]         # Local accounts (COMPUTERNAME\user)
    extra_local_admins: List[str]   # Local admins excluding the built-in Administrator (if present)


def _query_local_admins_powershell() -> list[str] | None:
    """
    Query the local Administrators group using PowerShell.

    Returns:
        List of member names (strings), or None if the command fails.
    """
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            "Get-LocalGroupMember -Group 'Administrators' "
            "| Select-Object -Property Name,ObjectClass "
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

    # ConvertTo-Json can return an object or an array of objects.
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = [item for item in data if isinstance(item, dict)]
    else:
        return None

    names: list[str] = []
    for item in items:
        name = item.get("Name")
        if isinstance(name, str) and name.strip():
            names.append(name.strip())

    return names or None


def _get_local_admins_state() -> LocalAdminsState:
    """
    Build a LocalAdminsState using PowerShell output.

    We consider "local accounts" to be those whose names start with
    COMPUTERNAME\\ (case-insensitive).
    """
    names = _query_local_admins_powershell() or []
    computer_name = os.environ.get("COMPUTERNAME", "").strip()
    local_admins: list[str] = []
    extra_local_admins: list[str] = []

    if computer_name:
        prefix = (computer_name + "\\").upper()
        for name in names:
            if name.upper().startswith(prefix):
                local_admins.append(name)

        # Built-in local Administrator account (if present) is treated as expected.
        builtin_admin = f"{computer_name}\\Administrator".upper()
        for name in local_admins:
            if name.upper() != builtin_admin:
                extra_local_admins.append(name)

    return LocalAdminsState(
        members=names,
        local_admins=local_admins,
        extra_local_admins=extra_local_admins,
    )


def _classify_local_admins_state(state: LocalAdminsState) -> Tuple[str, str, str]:
    """
    Given a LocalAdminsState, decide the check status, summary, and details.

    Returns:
        (status, summary, details)
    """
    if not state.members:
        status = "UNKNOWN"
        summary = (
            "GuardDog could not read the list of administrator accounts. "
            "This does not necessarily mean there is a problem."
        )
        details = "No members were returned for the local Administrators group."
        return status, summary, details

    # Build details: show all members, highlight local accounts
    detail_lines: list[str] = []

    detail_lines.append("The following accounts have administrator rights on this computer:")
    for name in state.members:
        marker = ""
        if name in state.extra_local_admins:
            marker = " (local user account)"
        elif name in state.local_admins:
            marker = " (built-in local account)"
        detail_lines.append(f"- {name}{marker}")

    if state.extra_local_admins:
        detail_lines.append("")
        detail_lines.append(
            "Local user accounts with administrator rights can be convenient, but they also "
            "increase risk if their passwords are weak or reused."
        )

    details = "\n".join(detail_lines)

    # Classification
    if state.extra_local_admins:
        status = "WARN"
        summary = (
            "One or more local user accounts have administrator rights on this computer."
        )
    else:
        status = "OK"
        summary = (
            "Only built-in or domain accounts were found in the local Administrators group."
        )

    return status, summary, details


def run():
    """
    Run the local administrators check and return a standardized result dict.

    Schema:
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
                "You can open the Computer Management console, go to 'Local Users and Groups' "
                "→ 'Groups' → 'Administrators' to see which accounts have administrator rights."
            ),
        }

    # Remediation guidance based on status
    if status == "OK":
        remediation = (
            "No urgent action needed. If you are not sure who should have administrator rights, "
            "you can still review this list with a trusted IT person."
        )
    elif status == "WARN":
        remediation = (
            "Review the local user accounts listed here that have administrator rights. If you do not "
            "recognize an account, or if a day-to-day account has administrator rights, consider "
            "removing those rights or asking a trusted IT person to review them. It is safer to use a "
            "standard (non-admin) account for everyday work and a separate admin account only when needed."
        )
    else:  # UNKNOWN
        remediation = (
            "GuardDog could not clearly read the local administrator accounts. "
            "You can manually open the Computer Management console, go to 'Local Users and Groups' "
            "→ 'Groups' → 'Administrators' to see which accounts have administrator rights."
        )

    return {
        "id": "local_admins",
        "title": "Local Administrators",
        "status": status,
        "summary": summary,
        "details": details,
        "remediation": remediation,
    }