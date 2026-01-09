"""
Functions to build a self-contained HTML report from check results.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable, Mapping, Any, Tuple
import html


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def classify_overall_status(check_results: Iterable[Mapping[str, Any]]) -> Tuple[str, str]:
    """
    Given all check results, decide an overall status and a short summary message.

    Status priority (recommended):
        HIGH > WARN > UNKNOWN > OK

    Rationale:
        - If anything is HIGH, user should act.
        - WARN means improvements.
        - UNKNOWN means we couldn't verify something important (restricted env, parsing issues).
        - OK only when everything relevant is verified OK (or there are no checks).
    """
    has_high = False
    has_warn = False
    has_unknown = False
    has_ok = False

    for result in check_results:
        status = str(result.get("status", "UNKNOWN")).upper()
        if status == "HIGH":
            has_high = True
        elif status == "WARN":
            has_warn = True
        elif status == "OK":
            has_ok = True
        else:
            has_unknown = True

    if has_high:
        return ("HIGH", "GuardDog found some important security issues that you should fix soon.")
    if has_warn:
        return ("WARN", "GuardDog found some things that could be improved to make this computer safer.")
    if has_unknown:
        return ("UNKNOWN", "GuardDog could not verify everything. Some checks were blocked or unclear.")
    if has_ok:
        return ("OK", "GuardDog did not find any obvious high-risk issues in the checks it ran.")
    return ("UNKNOWN", "GuardDog did not run any checks.")


def build_report_html(check_results: Iterable[Mapping[str, Any]]) -> str:
    """
    Build a complete HTML document as a string from the given check results.
    This HTML is self-contained (inline CSS, no external scripts or styles).
    """
    check_results = list(check_results)
    overall_status, overall_message = classify_overall_status(check_results)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    css = """
        body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
               margin: 2rem; background: #fdfdfd; color: #222; }
        h1 { margin-bottom: 0.25rem; }
        .meta { color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }
        .summary { margin-bottom: 1.5rem; padding: 1rem; border-radius: 0.5rem; }
        .summary-OK { background: #e8f5e9; border: 1px solid #c8e6c9; }
        .summary-WARN { background: #fff8e1; border: 1px solid #ffe082; }
        .summary-HIGH { background: #ffebee; border: 1px solid #ef9a9a; }
        .summary-UNKNOWN { background: #eceff1; border: 1px solid #cfd8dc; }
        .checks { display: flex; flex-direction: column; gap: 1rem; }
        .check { padding: 1rem; border-radius: 0.5rem; border: 1px solid #ddd; background: #fff; }
        .check h2 { margin-top: 0; margin-bottom: 0.25rem; }
        .check-status { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .status-badge-OK { color: #2e7d32; }
        .status-badge-WARN { color: #f9a825; }
        .status-badge-HIGH { color: #c62828; }
        .status-badge-UNKNOWN { color: #455a64; }
        .check-summary { margin: 0.5rem 0; }
        .check-section-title { font-weight: 600; margin-top: 0.75rem; margin-bottom: 0.25rem; }
        .check-section-body { margin-top: 0; margin-bottom: 0; }
        pre.evidence {
            background: #f7f7f7;
            border: 1px solid #e0e0e0;
            padding: 0.75rem;
            border-radius: 0.5rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-word;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
            font-size: 0.9rem;
        }
    """

    html_lines = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "  <meta charset='utf-8'>",
        "  <title>GuardDog Security Check Report</title>",
        f"  <style>{css}</style>",
        "</head>",
        "<body>",
        "  <h1>GuardDog Security Check Report</h1>",
        f"  <div class='meta'>Generated at {_esc(generated_at)}</div>",
        f"  <div class='summary summary-{_esc(overall_status)}'>",
        f"    <p>{_esc(overall_message)}</p>",
        "  </div>",
        "  <div class='checks'>",
    ]

    for result in check_results:
        status = str(result.get("status", "UNKNOWN")).upper()
        title = result.get("title", "Unknown check")
        summary = result.get("summary", "")
        details = result.get("details", "")
        remediation = result.get("remediation", "")

        html_lines.append("    <section class='check'>")
        html_lines.append(f"      <h2>{_esc(title)}</h2>")
        html_lines.append(
            f"      <div class='check-status status-badge-{_esc(status)}'>Status: {_esc(status)}</div>"
        )

        if summary:
            html_lines.append(f"      <p class='check-summary'>{_esc(summary)}</p>")

        if details:
            html_lines.append("      <div class='check-section-title'>Details</div>")
            html_lines.append(f"      <pre class='evidence'>{_esc(details)}</pre>")

        if remediation:
            html_lines.append("      <div class='check-section-title'>What you can do</div>")
            html_lines.append(f"      <p class='check-section-body'>{_esc(remediation)}</p>")

        html_lines.append("    </section>")

    html_lines.extend(["  </div>", "</body>", "</html>"])
    return "\n".join(html_lines)


def default_report_path(base_dir: Path) -> Path:
    reports_dir = base_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"GuardDog_Report_{timestamp}.html"
    return reports_dir / filename