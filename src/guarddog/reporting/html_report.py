"""
Functions to build a self-contained HTML report from check results.
"""

from pathlib import Path
from typing import Iterable, Mapping, Any

def build_report_html(check_results: Iterable[Mapping[str, Any]]) -> str:
    """
    Placeholder: build a very simple HTML string from check results.
    Phase 1 will replace this with a proper template-driven report.
    """
    lines = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'><title>GuardDog Report</title></head>",
        "<body>",
        "<h1>GuardDog Report (placeholder)</h1>",
        "<ul>",
    ]
    for result in check_results:
        lines.append(f"<li>{result.get('title', 'Unknown check')}: {result.get('status', 'UNKNOWN')}</li>")
    lines.extend(["</ul>", "</body></html>"])
    return "\n".join(lines)


def default_report_path(base_dir: Path) -> Path:
    """
    Placeholder path helper: given the directory where GuardDog.exe lives,
    return a path under `reports/` for the HTML file.
    """
    reports_dir = base_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir / "GuardDog_Report_PLACEHOLDER.html"
