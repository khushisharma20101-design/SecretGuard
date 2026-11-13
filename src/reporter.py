"""
src/reporter.py

Output layer for SecretGuard.

Converts a `ScanSummary` into human-readable console output and/or a
machine-readable JSON report. Kept deliberately separate from
`scanner.py` so the detection logic has no knowledge of how results
are eventually displayed — you could add an HTML or CSV reporter
later without touching the scanner at all.

Design notes:
    - Console output uses plain ANSI color codes (no external
      dependency like `colorama`/`rich`) so the project stays
      dependency-light, appropriate for a minor project setup.
    - Findings are sorted by severity (Critical first) then by file
      path, so the most important results surface at the top of a
      long scan regardless of discovery order.
    - JSON export uses stdlib `dataclasses.asdict` plus a custom
      default handler for `Path`/`datetime`/`Enum`, avoiding the need
      for Pydantic just to get serialization.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from src.models import Finding, ScanSummary, SeverityEnum

# ---------------------------------------------------------------------------
# Console formatting
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[SeverityEnum, int] = {
    SeverityEnum.CRITICAL: 0,
    SeverityEnum.HIGH: 1,
    SeverityEnum.MEDIUM: 2,
    SeverityEnum.LOW: 3,
}

_SEVERITY_COLOR: dict[SeverityEnum, str] = {
    SeverityEnum.CRITICAL: "\033[91m",  # red
    SeverityEnum.HIGH: "\033[93m",      # yellow
    SeverityEnum.MEDIUM: "\033[94m",    # blue
    SeverityEnum.LOW: "\033[90m",       # grey
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity (Critical first), then by location."""
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER[f.severity], str(f.file_path), f.line_number),
    )


def format_console_report(summary: ScanSummary, use_color: bool = True) -> str:
    """
    Render a `ScanSummary` as a readable console report.

    Args:
        summary: The completed scan summary to render.
        use_color: Whether to include ANSI color codes. Disable for
            output that's piped to a file or a terminal that doesn't
            support ANSI (e.g. some CI logs).

    Returns:
        The formatted report as a single string, ready to `print()`.
    """
    lines: list[str] = []
    lines.append(f"{_BOLD}SecretGuard Scan Report{_RESET}" if use_color else "SecretGuard Scan Report")
    lines.append(f"  Root path      : {summary.root_path}")
    lines.append(f"  Files scanned  : {summary.files_scanned}")
    lines.append(f"  Total findings : {summary.total_findings}")

    if summary.duration_seconds is not None:
        lines.append(f"  Duration       : {summary.duration_seconds:.3f}s")

    lines.append("")
    lines.append("  Severity breakdown:")
    for severity in (SeverityEnum.CRITICAL, SeverityEnum.HIGH, SeverityEnum.MEDIUM, SeverityEnum.LOW):
        count = summary.severity_breakdown[severity]
        color = _SEVERITY_COLOR[severity] if use_color else ""
        reset = _RESET if use_color else ""
        lines.append(f"    {color}{severity.value:<8}{reset}: {count}")

    if not summary.findings:
        lines.append("")
        lines.append("  No secrets detected. ✅")
        return "\n".join(lines)

    lines.append("")
    lines.append(f"{_BOLD}  Findings (sorted by severity):{_RESET}" if use_color else "  Findings (sorted by severity):")
    lines.append("  " + "-" * 76)

    for finding in _sorted_findings(summary.findings):
        color = _SEVERITY_COLOR[finding.severity] if use_color else ""
        reset = _RESET if use_color else ""
        lines.append(
            f"  {color}[{finding.severity.value:<8}]{reset} {finding.secret_type}"
        )
        lines.append(f"      Location   : {finding.location}")
        lines.append(f"      Value      : {finding.redacted_value}")
        lines.append(
            f"      Detected by: {finding.detection_method.value}"
            + (
                f" (entropy={finding.entropy_score})"
                if finding.entropy_score is not None
                else ""
            )
        )
        lines.append(f"      Confidence : {finding.confidence_score:.2f}")
        lines.append(f"      Fix        : {finding.recommendation}")
        lines.append("  " + "-" * 76)

    return "\n".join(lines)


def print_console_report(summary: ScanSummary, use_color: bool = True) -> None:
    """Render and print a `ScanSummary` directly to stdout."""
    print(format_console_report(summary, use_color=use_color))


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


def _json_default(value: Any) -> Any:
    """
    Fallback serializer for `json.dumps`, handling the types
    `dataclasses.asdict` can't turn into plain JSON on its own.
    """
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def to_json(summary: ScanSummary, indent: int = 2) -> str:
    """
    Serialize a `ScanSummary` to a JSON string.

    Findings are sorted by severity before serialization so downstream
    consumers (CI pipelines, dashboards) don't need to re-sort.

    Args:
        summary: The completed scan summary to serialize.
        indent: JSON indentation level for readability.

    Returns:
        A JSON string representing the summary, its metadata, and all
        findings.
    """
    payload = {
        "root_path": summary.root_path,
        "files_scanned": summary.files_scanned,
        "total_findings": summary.total_findings,
        "started_at": summary.started_at,
        "finished_at": summary.finished_at,
        "duration_seconds": summary.duration_seconds,
        "severity_breakdown": {
            severity.value: count
            for severity, count in summary.severity_breakdown.items()
        },
        "findings": [asdict(f) for f in _sorted_findings(summary.findings)],
    }
    return json.dumps(payload, indent=indent, default=_json_default)


def write_json_report(summary: ScanSummary, output_path: Path, indent: int = 2) -> None:
    """
    Serialize a `ScanSummary` to JSON and write it to disk.

    Args:
        summary: The completed scan summary to serialize.
        output_path: File path to write the JSON report to.
        indent: JSON indentation level for readability.
    """
    output_path.write_text(to_json(summary, indent=indent), encoding="utf-8")