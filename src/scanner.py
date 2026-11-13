"""
Core scanning engine for SecretGuard.

The scanner:
1. Discovers eligible source files.
2. Reads files line by line.
3. Checks known secret patterns using Regex.
4. Uses entropy detection when Regex finds nothing.
5. Uses Context Analysis to refine the confidence of findings.
6. Aggregates findings into a ScanSummary.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from src.detectors.context_check import (
    extract_assignment_name,
    has_secret_context,
    is_placeholder,
)
from src.detectors.entropy_check import scan_line as scan_entropy
from src.detectors.regex_rules import scan_line as scan_regex
from src.models import Finding, ScanSummary


# Directories that should not be scanned.
DEFAULT_IGNORE_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
    ".idea",
    ".vscode",
}


# File types that SecretGuard considers source/config/text files.
DEFAULT_ALLOWED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".rs",
    ".swift",
    ".kt",
    ".sh",
    ".bash",
    ".yml",
    ".yaml",
    ".json",
    ".xml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".toml",
    ".properties",
    ".txt",
    ".md",
    ".sql",
    ".html",
    ".htm",
    ".css",
}


MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024


def _is_binary(path: Path) -> bool:
    """Return True if a file appears to contain binary data."""

    try:
        with path.open("rb") as file:
            chunk = file.read(1024)
        return b"\x00" in chunk
    except OSError:
        return True


def iter_source_files(
    root: Path,
    ignore_dirs: set[str] | None = None,
    allowed_extensions: set[str] | None = None,
):
    """
    Recursively yield source/config/text files suitable for scanning.
    """

    ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS
    allowed_extensions = allowed_extensions or DEFAULT_ALLOWED_EXTENSIONS

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        # Skip files inside ignored directories.
        if any(part in ignore_dirs for part in path.parts):
            continue

        # Skip unsupported file extensions.
        if path.suffix.lower() not in allowed_extensions:
            continue

        # Skip files that are too large.
        try:
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
        except OSError:
            continue

        # Skip binary files.
        if _is_binary(path):
            continue

        yield path


def _refine_with_context(
    finding: Finding,
    line: str,
) -> Finding:
    """
    Refine a finding using surrounding code context.

    Context does not create a new finding.
    It only adjusts the confidence of an existing finding.
    """

    assignment_name = extract_assignment_name(line)

    confidence = finding.confidence_score

    # Secret-related variable/key names strengthen the evidence.
    if has_secret_context(assignment_name):
        confidence += 0.05

    # Placeholder/example values weaken the evidence.
    if is_placeholder(line):
        confidence -= 0.15

    # Keep confidence safely inside the valid 0.0 - 1.0 range.
    confidence = max(0.0, min(1.0, confidence))

    # Return a new Finding because Finding is immutable/frozen.
    return replace(
        finding,
        confidence_score=confidence,
    )


def scan_file(path: Path) -> list[Finding]:
    """
    Scan a single file and return all findings.
    """

    findings: list[Finding] = []

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return findings

    for line_number, line in enumerate(lines, start=1):

        # ---------------------------------------------------------
        # 1. Regex detection
        # ---------------------------------------------------------
        regex_findings = scan_regex(
            line,
            file_path=path,
            line_number=line_number,
        )

        if regex_findings:
            for finding in regex_findings:
                finding = _refine_with_context(finding, line)
                findings.append(finding)

            # Do not run entropy on the same line.
            continue

        # ---------------------------------------------------------
        # 2. Entropy detection
        # ---------------------------------------------------------
        entropy_findings = scan_entropy(
            line,
            file_path=path,
            line_number=line_number,
        )

        for finding in entropy_findings:
            finding = _refine_with_context(finding, line)
            findings.append(finding)

    return findings


def scan_directory(
    root: Path,
    ignore_dirs: set[str] | None = None,
    allowed_extensions: set[str] | None = None,
) -> ScanSummary:
    """
    Recursively scan a project directory and return a ScanSummary.
    """

    summary = ScanSummary(root_path=root)

    for path in iter_source_files(
        root,
        ignore_dirs=ignore_dirs,
        allowed_extensions=allowed_extensions,
    ):
        summary.files_scanned += 1

        findings = scan_file(path)

        for finding in findings:
            summary.add_finding(finding)

    summary.mark_complete()

    return summary