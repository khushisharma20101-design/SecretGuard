"""
tests/test_models.py

Unit tests for src/models.py — Finding, ScanSummary, SeverityEnum.

Covers:
    - Valid construction of a Finding.
    - Validation errors for bad line_number / confidence_score / entropy_score.
    - Immutability of Finding (frozen dataclass).
    - ScanSummary aggregation behavior (add_finding, severity_breakdown,
      total_findings, has_critical_findings, duration_seconds).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from src.models import DetectionMethod, Finding, ScanSummary, SeverityEnum


def make_finding(**overrides) -> Finding:
    """Helper to build a valid Finding with sensible defaults, overridable per test."""
    defaults = dict(
        file_path=Path("app/config.py"),
        line_number=10,
        secret_type="AWS Access Key ID",
        redacted_value="AKIA**************OP",
        detection_method=DetectionMethod.REGEX,
        severity=SeverityEnum.CRITICAL,
        confidence_score=0.95,
        recommendation="Rotate this key.",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Finding construction & validation
# ---------------------------------------------------------------------------


def test_finding_valid_construction():
    finding = make_finding()
    assert finding.secret_type == "AWS Access Key ID"
    assert finding.severity == SeverityEnum.CRITICAL
    assert finding.location == f"{Path('app/config.py')}:10"


def test_finding_rejects_invalid_line_number():
    with pytest.raises(ValueError, match="line_number"):
        make_finding(line_number=0)


def test_finding_rejects_negative_line_number():
    with pytest.raises(ValueError, match="line_number"):
        make_finding(line_number=-5)


@pytest.mark.parametrize("bad_confidence", [-0.1, 1.1, 2.0, -100.0])
def test_finding_rejects_out_of_range_confidence(bad_confidence):
    with pytest.raises(ValueError, match="confidence_score"):
        make_finding(confidence_score=bad_confidence)


@pytest.mark.parametrize("good_confidence", [0.0, 0.5, 1.0])
def test_finding_accepts_boundary_confidence(good_confidence):
    finding = make_finding(confidence_score=good_confidence)
    assert finding.confidence_score == good_confidence


def test_finding_rejects_negative_entropy_score():
    with pytest.raises(ValueError, match="entropy_score"):
        make_finding(entropy_score=-1.0)


def test_finding_accepts_none_entropy_score():
    finding = make_finding(entropy_score=None)
    assert finding.entropy_score is None


def test_finding_is_immutable():
    finding = make_finding()
    with pytest.raises(FrozenInstanceError):
        finding.severity = SeverityEnum.LOW  # type: ignore[misc]


def test_finding_location_property_formats_correctly():
    finding = make_finding(file_path=Path("src/utils/db.py"), line_number=42)
    assert finding.location == f"{Path('src/utils/db.py')}:42"


# ---------------------------------------------------------------------------
# ScanSummary aggregation
# ---------------------------------------------------------------------------


def test_scan_summary_starts_empty():
    summary = ScanSummary(root_path=Path("."))
    assert summary.total_findings == 0
    assert summary.files_scanned == 0
    assert summary.has_critical_findings() is False
    assert summary.finished_at is None
    assert summary.duration_seconds is None


def test_scan_summary_add_finding_increments_total():
    summary = ScanSummary(root_path=Path("."))
    summary.add_finding(make_finding())
    summary.add_finding(make_finding(line_number=20))
    assert summary.total_findings == 2


def test_scan_summary_severity_breakdown_counts_all_levels():
    summary = ScanSummary(root_path=Path("."))
    summary.add_finding(make_finding(severity=SeverityEnum.CRITICAL))
    summary.add_finding(make_finding(severity=SeverityEnum.CRITICAL))
    summary.add_finding(make_finding(severity=SeverityEnum.HIGH))
    summary.add_finding(make_finding(severity=SeverityEnum.LOW))

    breakdown = summary.severity_breakdown
    assert breakdown[SeverityEnum.CRITICAL] == 2
    assert breakdown[SeverityEnum.HIGH] == 1
    assert breakdown[SeverityEnum.MEDIUM] == 0
    assert breakdown[SeverityEnum.LOW] == 1


def test_scan_summary_has_critical_findings_true():
    summary = ScanSummary(root_path=Path("."))
    summary.add_finding(make_finding(severity=SeverityEnum.CRITICAL))
    assert summary.has_critical_findings() is True


def test_scan_summary_has_critical_findings_false_when_none_critical():
    summary = ScanSummary(root_path=Path("."))
    summary.add_finding(make_finding(severity=SeverityEnum.MEDIUM))
    summary.add_finding(make_finding(severity=SeverityEnum.LOW))
    assert summary.has_critical_findings() is False


def test_scan_summary_mark_complete_sets_duration():
    summary = ScanSummary(root_path=Path("."))
    assert summary.duration_seconds is None
    summary.mark_complete()
    assert summary.finished_at is not None
    assert summary.duration_seconds is not None
    assert summary.duration_seconds >= 0.0