"""
src/models.py

Core data schema for SecretGuard.

Defines the strongly-typed structures used across the scanner, detectors,
and reporter layers:
    - SeverityEnum   : Standardized severity levels for a finding.
    - Finding        : A single detected secret/API key with full metadata.
    - ScanSummary    : Aggregated results of a full scan run.

Design notes:
    - Uses stdlib `dataclasses` (no external dependency required).
    - `frozen=True` on Finding makes each finding immutable once created,
      which is desirable since findings represent a fact about a scan
      at a point in time and shouldn't be mutated afterward.
    - ScanSummary is left mutable since it's built up incrementally as
      the scanner processes files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class SeverityEnum(str, Enum):
    """
    Severity classification for a detected finding.

    Inherits from `str` so values serialize cleanly to JSON/str output
    (e.g. str(SeverityEnum.CRITICAL) == "Critical") without needing a
    custom encoder.
    """

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class DetectionMethod(str, Enum):
    """How a given finding was flagged by the scanner."""

    REGEX = "Regex"
    ENTROPY = "Entropy"
    CONTEXT = "Context"


@dataclass(frozen=True, slots=True)
class Finding:
    """
    Represents a single detected secret or API key in the source code.

    Attributes:
        file_path: Path to the file where the secret was found.
        line_number: 1-indexed line number of the match within the file.
        secret_type: Human-readable label for what was matched
            (e.g. "AWS Access Key", "Generic API Key", "Private Key").
        redacted_value: The matched string with most characters masked
            (e.g. "AKIA****************"). Never store the raw secret.
        detection_method: Which strategy flagged this finding.
        entropy_score: Shannon entropy of the matched string, if the
            detection method used entropy analysis. None otherwise.
        severity: Assessed severity of this finding.
        confidence_score: Model/heuristic confidence that this is a
            true positive, in the range [0.0, 1.0].
        recommendation: Short, actionable remediation advice for the
            developer (e.g. "Rotate this key and move it to an
            environment variable.").
        detected_at: Timestamp of when this finding was created.
    """

    file_path: Path
    line_number: int
    secret_type: str
    redacted_value: str
    detection_method: DetectionMethod
    severity: SeverityEnum
    confidence_score: float
    recommendation: str
    entropy_score: float | None = None
    detected_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self) -> None:
        # Basic invariants — fail loudly at construction time rather than
        # letting an invalid Finding silently corrupt a report later.
        if self.line_number < 1:
            raise ValueError(
                f"line_number must be >= 1, got {self.line_number}"
            )
        if not (0.0 <= self.confidence_score <= 1.0):
            raise ValueError(
                "confidence_score must be between 0.0 and 1.0, "
                f"got {self.confidence_score}"
            )
        if self.entropy_score is not None and self.entropy_score < 0.0:
            raise ValueError(
                f"entropy_score cannot be negative, got {self.entropy_score}"
            )

    @property
    def location(self) -> str:
        """Convenience string like 'src/config.py:42' for reports/logs."""
        return f"{self.file_path}:{self.line_number}"


@dataclass(slots=True)
class ScanSummary:
    """
    Aggregated results of a full scan run over a project directory.

    This is built incrementally by the scanner as it walks files, then
    handed to the reporter for final output (console table, JSON, etc.).

    Attributes:
        root_path: The directory that was scanned.
        files_scanned: Total number of files inspected.
        findings: All findings collected during the scan, in the order
            they were discovered.
        started_at: When the scan began.
        finished_at: When the scan completed. None while still running.
    """

    root_path: Path
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None

    def add_finding(self, finding: Finding) -> None:
        """Append a single finding to the summary."""
        self.findings.append(finding)

    def mark_complete(self) -> None:
        """Mark the scan as finished, stamping the completion time."""
        self.finished_at = datetime.now()

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def severity_breakdown(self) -> dict[SeverityEnum, int]:
        """Count of findings per severity level, e.g. {Critical: 2, High: 5}."""
        breakdown: dict[SeverityEnum, int] = {level: 0 for level in SeverityEnum}
        for finding in self.findings:
            breakdown[finding.severity] += 1
        return breakdown

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock duration of the scan, or None if still in progress."""
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def has_critical_findings(self) -> bool:
        """True if at least one Critical-severity finding was recorded."""
        return any(f.severity == SeverityEnum.CRITICAL for f in self.findings)