"""
Main entry logic for GuardDog.

Phase 1 goal:
- Detect where GuardDog is running from (USB or dev environment).
- Run a set of non-admin, read-only checks (placeholders for now).
- Generate a self-contained HTML report into a `reports/` folder next to GuardDog.
"""

from __future__ import annotations

import sys
import webbrowser
from pathlib import Path
from typing import List, Dict, Any

from .checks import firewall, rdp, defender, local_admins, screen_lock
from .reporting.html_report import build_report_html, default_report_path


def _detect_base_dir() -> Path:
    """
    Detect the directory where GuardDog is running from.

    - When running as a bundled EXE (PyInstaller, later), sys.frozen is True and
      sys.executable points to GuardDog.exe.
    - When running as `python -m guarddog` from source, we fall back to the
      package directory.
    """
    if getattr(sys, "frozen", False):
        # Bundled EXE case.
        return Path(sys.executable).resolve().parent

    # Source / dev case.
    return Path(__file__).resolve().parent


def _run_all_checks() -> List[Dict[str, Any]]:
    """
    Run all configured checks and collect their results in a list.

    Each check module exposes a `run()` function returning a dict with:
        id, title, status, summary, details, remediation
    """
    results: List[Dict[str, Any]] = []

    # As we implement real checks, this is where we can handle exceptions per-check
    # to avoid one failure killing the entire run.
    for check in (firewall, rdp, defender, local_admins, screen_lock):
        try:
            result = check.run()
        except Exception as exc:  # noqa: BLE001
            # In an MVP, we keep error handling simple: mark the check as failed to run.
            result = {
                "id": getattr(check, "__name__", "unknown_check"),
                "title": getattr(check, "__doc__", "Unknown check").strip().splitlines()[0]
                if getattr(check, "__doc__", None)
                else "Unknown check",
                "status": "UNKNOWN",
                "summary": "This check failed to run due to an internal error.",
                "details": f"Error: {exc!r}",
                "remediation": "You can ignore this for now or try a newer version of GuardDog later.",
            }
        results.append(result)

    return results


def main() -> int:
    """
    Entry point for GuardDog.

    Returns a process exit code:
        0 on success (report written),
        non-zero on unexpected/unrecoverable errors.
    """
    base_dir = _detect_base_dir()

    # Run checks (placeholders for now).
    check_results = _run_all_checks()

    # Build HTML report from results.
    html = build_report_html(check_results)

    # Decide where to write the report (e.g. <base_dir>/reports/GuardDog_Report_YYYYMMDD_HHMMSS.html).
    report_path = default_report_path(base_dir)

    try:
        report_path.write_text(html, encoding="utf-8")
    except OSError as exc:
        # If we can't write the report, this is a hard failure.
        print(f"[GuardDog] Failed to write report to {report_path}: {exc}", file=sys.stderr)
        return 1

    print(f"[GuardDog] Report written to: {report_path}")

    # Best-effort: try to open the report in the default browser.
    try:
        webbrowser.open(report_path.as_uri())
    except Exception:
        # Non-fatal; user can always open the HTML manually.
        pass

    return 0
