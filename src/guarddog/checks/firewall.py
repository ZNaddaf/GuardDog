"""Firewall status checks (Windows Defender Firewall).

This check uses the built-in `netsh advfirewall show allprofiles` command
to determine whether the firewall is enabled for each profile.

- Non-admin.
- Read-only.
- No network access.
"""

from __future__ import annotations

import subprocess
from typing import Dict, Tuple


def _run_netsh_allprofiles() -> str:
    """
    Run `netsh advfirewall show allprofiles` and return its stdout as text.

    If the command fails, raises RuntimeError.
    """
    # `text=True` -> return string; `errors="ignore"` -> avoid crashes on weird encoding.
    proc = subprocess.run(
        ["netsh", "advfirewall", "show", "allprofiles"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"netsh advfirewall failed with code {proc.returncode}: {proc.stderr.strip()}")
    return proc.stdout


def _parse_netsh_allprofiles(output: str) -> Dict[str, str]:
    """
    Parse the output of `netsh advfirewall show allprofiles`.

    Returns a dict mapping profile name -> state string ("ON", "OFF", or other).

    Example expected patterns (English):

        Domain Profile Settings:
            State                                 ON

        Private Profile Settings:
            State                                 OFF

        Public Profile Settings:
            State                                 ON

    We keep parsing fairly forgiving and case-insensitive, but note this is
    language/locale-dependent. For MVP we assume an English-ish environment.
    """
    profiles: Dict[str, str] = {}
    current_profile: str | None = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        lower = line.lower()

        # Detect start of each profile section
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

        # Look for the "State" line within the current profile block
        if lower.startswith("state"):
            # Example: "State                                 ON"
            parts = line.split()
            # parts[0] is "State", last token is usually "ON"/"OFF"
            if len(parts) >= 2:
                state = parts[-1].upper()
                profiles[current_profile] = state
            # Don't `continue`; no more processing in this line anyway.

    return profiles


def _classify_firewall_status(profile_states: Dict[str, str]) -> Tuple[str, str, str]:
    """
    Given profile->state mapping, decide check status and build summary+details.

    Returns a tuple: (status, summary, details)
    """
    if not profile_states:
        return (
            "UNKNOWN",
            "GuardDog could not read the firewall status.",
            "The `netsh advfirewall show allprofiles` output was empty or unrecognized.",
        )

    any_off = False
    any_on = False
    unknown_profiles = []

    for profile, state in profile_states.items():
        if state == "ON":
            any_on = True
        elif state == "OFF":
            any_off = True
        else:
            unknown_profiles.append((profile, state))

    # Build a human-readable details string.
    detail_lines = []
    for profile in ("domain", "private", "public"):
        if profile in profile_states:
            state = profile_states[profile]
            detail_lines.append(f"- {profile.title()} profile: {state}")
    if unknown_profiles:
        detail_lines.append("")
        detail_lines.append("Some firewall states could not be interpreted reliably.")

    details = "\n".join(detail_lines) if detail_lines else ""

    # Classification
    if any_off:
        status = "HIGH"
        summary = (
            "Windows Firewall is turned OFF for at least one network profile. "
            "This makes it easier for other devices on the network to reach this computer."
        )
    elif any_on and not unknown_profiles:
        status = "OK"
        summary = "Windows Firewall is turned ON for all network profiles reported by Windows."
    elif any_on:
        status = "WARN"
        summary = (
            "Windows reported the firewall as ON for some profiles, but at least one profile "
            "could not be interpreted cleanly."
        )
    else:
        status = "WARN"
        summary = (
            "GuardDog could not confirm that Windows Firewall is turned ON. "
            "This does not necessarily mean it is off, but it is worth checking."
        )

    return status, summary, details


def run():
    """
    Run the firewall check and return a standardized result dict.

    Schema:
        id, title, status, summary, details, remediation
    """
    try:
        output = _run_netsh_allprofiles()
        profile_states = _parse_netsh_allprofiles(output)
        status, summary, details = _classify_firewall_status(profile_states)
    except Exception as exc:  # noqa: BLE001
        return {
            "id": "firewall",
            "title": "Windows Firewall",
            "status": "UNKNOWN",
            "summary": "GuardDog could not read the firewall status due to an internal error.",
            "details": f"Error: {exc!r}",
            "remediation": (
                "You can open the Windows Security app, go to 'Firewall & network protection', "
                "and check that the firewall is turned on for all network types."
            ),
        }

    # User-facing remediation guidance based on status
    if status == "OK":
        remediation = "No action needed. Windows Firewall is turned on for all reported network profiles."
    else:
        remediation = (
            "Open the Windows Security app, go to 'Firewall & network protection', and make sure "
            "the firewall is turned on for Domain, Private, and Public networks. If you are not sure, "
            "you can ask a trusted IT person to help with this."
        )

    return {
        "id": "firewall",
        "title": "Windows Firewall",
        "status": status,
        "summary": summary,
        "details": details,
        "remediation": remediation,
    }
