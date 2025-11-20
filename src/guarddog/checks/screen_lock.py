"""Screen lock / idle timeout checks.

This check inspects per-user desktop settings to estimate whether the screen
is configured to lock automatically after a period of inactivity.

It looks at registry values under:

    HKCU\\Control Panel\\Desktop

Relevant values (strings):

    ScreenSaveActive
        "1" -> screen saver / lock is enabled
        "0" -> no screen saver / lock

    ScreenSaverIsSecure
        "1" -> require password on resume (lock the session)
        "0" -> do not require password on resume

    ScreenSaveTimeOut
        "<seconds>" -> time in seconds before screen saver starts

This is an approximation: modern Windows can also be influenced by other
power and security policies, but these values give a useful signal for
basic screen lock hygiene.

Non-admin, read-only check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

try:
    import winreg  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - should exist on Windows
    winreg = None  # type: ignore[assignment]


DESKTOP_KEY_PATH = r"Control Panel\Desktop"

# Thresholds (seconds)
OK_TIMEOUT_SECONDS = 15 * 60       # 15 minutes
WARN_TIMEOUT_SECONDS = 30 * 60     # 30 minutes


@dataclass
class ScreenLockState:
    """Container for screen lock related settings."""

    active: bool | None         # True if ScreenSaveActive == "1"
    secure: bool | None         # True if ScreenSaverIsSecure == "1"
    timeout_seconds: int | None # Parsed ScreenSaveTimeOut, or None


def _read_hkcu_desktop_value(value_name: str) -> str | None:
    """
    Helper: read a string value from HKCU\\Control Panel\\Desktop.

    Returns:
        value string, or None if missing or on error.
    """
    if winreg is None:
        return None

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, DESKTOP_KEY_PATH, 0, winreg.KEY_READ) as key:
            value, reg_type = winreg.QueryValueEx(key, value_name)
            # These values are typically REG_SZ
            if reg_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                return None
            if isinstance(value, str):
                return value.strip()
            return str(value).strip()
    except OSError:
        return None


def _get_screen_lock_state() -> ScreenLockState:
    """
    Read the relevant HKCU desktop values and return a ScreenLockState.
    """
    active_raw = _read_hkcu_desktop_value("ScreenSaveActive")
    secure_raw = _read_hkcu_desktop_value("ScreenSaverIsSecure")
    timeout_raw = _read_hkcu_desktop_value("ScreenSaveTimeOut")

    def to_bool_flag(v: str | None) -> bool | None:
        if v is None:
            return None
        return v.strip() == "1"

    def to_int_seconds(v: str | None) -> int | None:
        if v is None:
            return None
        try:
            seconds = int(v.strip())
            if seconds <= 0:
                return None
            return seconds
        except ValueError:
            return None

    return ScreenLockState(
        active=to_bool_flag(active_raw),
        secure=to_bool_flag(secure_raw),
        timeout_seconds=to_int_seconds(timeout_raw),
    )


def _classify_screen_lock_state(state: ScreenLockState) -> Tuple[str, str, str]:
    """
    Given a ScreenLockState, decide the check status, summary, and details.

    Returns:
        (status, summary, details)
    """
    # Build human-readable details
    detail_lines = []

    if state.active is True:
        detail_lines.append("- Automatic screen lock: ENABLED (screen saver active).")
    elif state.active is False:
        detail_lines.append("- Automatic screen lock: DISABLED (no screen saver).")
    else:
        detail_lines.append("- Automatic screen lock: UNKNOWN (setting not found).")

    if state.secure is True:
        detail_lines.append("- Require password on resume: ENABLED.")
    elif state.secure is False:
        detail_lines.append("- Require password on resume: DISABLED.")
    else:
        detail_lines.append("- Require password on resume: UNKNOWN.")

    if state.timeout_seconds is not None:
        detail_lines.append(f"- Idle timeout before lock: approximately {state.timeout_seconds} seconds.")
    else:
        detail_lines.append("- Idle timeout before lock: UNKNOWN (could not read a valid timeout).")

    details = "\n".join(detail_lines)

    # Classification logic
    if state.active is False:
        status = "HIGH"
        summary = (
            "Automatic screen lock appears to be turned OFF. If you walk away from this computer, "
            "someone could use it without signing in."
        )
    elif state.active is True:
        # Screen lock is active; now check timeout & secure flag
        if state.timeout_seconds is not None and state.timeout_seconds <= OK_TIMEOUT_SECONDS and state.secure is True:
            status = "OK"
            summary = (
                "Automatic screen lock is enabled with a reasonable timeout, and a password is required on resume."
            )
        elif state.timeout_seconds is not None and state.timeout_seconds > WARN_TIMEOUT_SECONDS:
            status = "WARN"
            summary = (
                "Automatic screen lock is enabled, but the timeout is quite long. It may stay unlocked for an "
                "extended period if you forget to lock it manually."
            )
        elif state.secure is False:
            status = "WARN"
            summary = (
                "Automatic screen lock is enabled, but a password does NOT appear to be required when it resumes."
            )
        else:
            status = "WARN"
            summary = (
                "Automatic screen lock appears to be enabled, but some details (timeout or password requirement) "
                "could not be confirmed."
            )
    else:
        status = "UNKNOWN"
        summary = (
            "GuardDog could not determine the automatic screen lock settings from the current user profile."
        )

    return status, summary, details


def run():
    """
    Run the screen lock check and return a standardized result dict.

    Schema:
        id, title, status, summary, details, remediation
    """
    try:
        state = _get_screen_lock_state()
        status, summary, details = _classify_screen_lock_state(state)
    except Exception as exc:  # noqa: BLE001
        return {
            "id": "screen_lock",
            "title": "Screen Lock",
            "status": "UNKNOWN",
            "summary": "GuardDog could not read the screen lock settings due to an internal error.",
            "details": f"Error: {exc!r}",
            "remediation": (
                "You can open Settings → Accounts → Sign-in options (or 'Lock screen' settings) and "
                "check how and when the screen locks after inactivity."
            ),
        }

    # Remediation based on status
    if status == "OK":
        remediation = (
            "No urgent action needed. Your screen should lock automatically after a reasonable period of inactivity, "
            "and a password is required to unlock it."
        )
    elif status == "HIGH":
        remediation = (
            "Turn on automatic locking so that this computer requires a sign-in if you leave it unattended. "
            "On Windows 10/11, open Settings → Accounts → Sign-in options (or 'Lock screen' settings) and set a "
            "short timeout before the screen locks, with a password required to sign back in."
        )
    elif status == "WARN":
        remediation = (
            "Consider shortening the idle time before the screen locks, and make sure a password is required when "
            "you wake it. On Windows 10/11, open Settings → Accounts → Sign-in options (or 'Lock screen' settings) "
            "and look for options related to 'If you've been away, when should Windows require you to sign in again?'."
        )
    else:  # UNKNOWN
        remediation = (
            "GuardDog could not clearly read the screen lock settings. You can manually open Settings → Accounts "
            "→ Sign-in options (or 'Lock screen' settings) and review how and when the screen locks after inactivity."
        )

    return {
        "id": "screen_lock",
        "title": "Screen Lock",
        "status": status,
        "summary": summary,
        "details": details,
        "remediation": remediation,
    }