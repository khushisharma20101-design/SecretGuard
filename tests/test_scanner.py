"""
tests/test_scanner.py

Integration-style tests for src/scanner.py — file discovery, binary/
extension filtering, ignored directories, and end-to-end scanning.

Uses pytest's built-in `tmp_path` fixture to build a throwaway fake
project directory per test, so nothing here touches real files or
depends on the sample_repo/ fixture directory.
"""

from __future__ import annotations

from pathlib import Path

from src.models import DetectionMethod, SeverityEnum
from src.scanner import iter_source_files, scan_directory, scan_file


def _write(path: Path, content: str) -> Path:
    """Helper: write `content` to `path`, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# iter_source_files: discovery, filtering, ignored dirs
# ---------------------------------------------------------------------------


def test_iter_source_files_finds_eligible_files(tmp_path):
    _write(tmp_path / "app.py", "x = 1\n")
    _write(tmp_path / "readme.md", "# hello\n")

    found = list(iter_source_files(tmp_path))
    names = {p.name for p in found}
    assert names == {"app.py", "readme.md"}


def test_iter_source_files_skips_disallowed_extensions(tmp_path):
    _write(tmp_path / "image.png", "not really an image but wrong ext")
    _write(tmp_path / "app.py", "x = 1\n")

    found = list(iter_source_files(tmp_path))
    names = {p.name for p in found}
    assert "image.png" not in names
    assert "app.py" in names


def test_iter_source_files_skips_ignored_directories(tmp_path):
    _write(tmp_path / "node_modules" / "lib.js", "var secret='AKIAABCDEFGHIJKLMNOP';")
    _write(tmp_path / ".git" / "config", "not scanned")
    _write(tmp_path / "src" / "app.py", "x = 1\n")

    found = list(iter_source_files(tmp_path))
    relative_paths = {p.relative_to(tmp_path) for p in found}

    assert not any("node_modules" in p.parts for p in relative_paths)
    assert not any(".git" in p.parts for p in relative_paths)
    assert Path("src/app.py") in relative_paths


def test_iter_source_files_skips_binary_files(tmp_path):
    binary_path = tmp_path / "blob.py"
    binary_path.write_bytes(b"\x00\x01\x02binarydata")
    _write(tmp_path / "app.py", "x = 1\n")

    found = list(iter_source_files(tmp_path))
    names = {p.name for p in found}
    assert "blob.py" not in names
    assert "app.py" in names


def test_iter_source_files_skips_oversized_files(tmp_path, monkeypatch):
    import src.scanner as scanner_module

    monkeypatch.setattr(scanner_module, "MAX_FILE_SIZE_BYTES", 10)
    _write(tmp_path / "big.py", "x = 'this line is definitely more than ten bytes long'\n")

    found = list(iter_source_files(tmp_path))
    assert found == []


# ---------------------------------------------------------------------------
# scan_file: regex + entropy fusion on a single file
# ---------------------------------------------------------------------------


def test_scan_file_detects_regex_match(tmp_path):
    file_path = _write(tmp_path / "config.py", 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')

    findings = scan_file(file_path)

    assert len(findings) == 1
    assert findings[0].detection_method == DetectionMethod.REGEX
    assert findings[0].severity == SeverityEnum.CRITICAL
    assert findings[0].line_number == 1


def test_scan_file_falls_back_to_entropy_when_no_regex_match(tmp_path):
    # Deliberately avoids any variable name containing "key"/"secret"/
    # "token" (which would also trip the Generic API Key regex rule) so
    # this line can only be caught by the entropy detector.
    file_path = _write(
        tmp_path / "config.py",
        'random_value = "kJ9sP2mQxT7vL4wR8nY1zC6bA3fD5eH0"\n',
    )

    findings = scan_file(file_path)

    assert len(findings) == 1
    assert findings[0].detection_method == DetectionMethod.ENTROPY


def test_scan_file_does_not_run_entropy_when_regex_already_matched(tmp_path):
    # This line matches "AWS Access Key ID" via regex. It should NOT
    # additionally produce an entropy finding for the same line, since
    # scanner.py skips the entropy pass once regex has already flagged it.
    file_path = _write(tmp_path / "config.py", 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')

    findings = scan_file(file_path)

    assert all(f.detection_method == DetectionMethod.REGEX for f in findings)


def test_scan_file_returns_empty_for_clean_file(tmp_path):
    file_path = _write(tmp_path / "clean.py", "def add(a, b):\n    return a + b\n")
    findings = scan_file(file_path)
    assert findings == []


def test_scan_file_reports_correct_line_numbers(tmp_path):
    content = "x = 1\ny = 2\nAWS_KEY = \"AKIAABCDEFGHIJKLMNOP\"\nz = 3\n"
    file_path = _write(tmp_path / "config.py", content)

    findings = scan_file(file_path)

    assert len(findings) == 1
    assert findings[0].line_number == 3


# ---------------------------------------------------------------------------
# scan_directory: end-to-end
# ---------------------------------------------------------------------------


def test_scan_directory_aggregates_findings_across_files(tmp_path):
    _write(tmp_path / "config.py", 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
    _write(tmp_path / "utils.py", 'TOKEN = "mytoken_1234567890abcdef"\n')
    _write(tmp_path / "readme.md", "Nothing sensitive here.\n")

    summary = scan_directory(tmp_path)

    assert summary.files_scanned == 3
    assert summary.total_findings >= 2
    assert summary.finished_at is not None


def test_scan_directory_marks_complete(tmp_path):
    _write(tmp_path / "app.py", "x = 1\n")
    summary = scan_directory(tmp_path)
    assert summary.finished_at is not None
    assert summary.duration_seconds is not None


def test_scan_directory_excludes_ignored_dirs_from_results(tmp_path):
    _write(tmp_path / "node_modules" / "lib.js", 'var k = "AKIAABCDEFGHIJKLMNOP";')
    _write(tmp_path / "app.py", "x = 1\n")

    summary = scan_directory(tmp_path)

    assert summary.total_findings == 0
    assert summary.files_scanned == 1  # only app.py, node_modules skipped


def test_scan_directory_on_empty_directory(tmp_path):
    summary = scan_directory(tmp_path)
    assert summary.files_scanned == 0
    assert summary.total_findings == 0
    assert summary.severity_breakdown[SeverityEnum.CRITICAL] == 0

   # ---------------------------------------------------------------------------
# Context Analysis: confidence refinement
# ---------------------------------------------------------------------------


def test_context_increases_confidence_for_secret_like_name(tmp_path):
    file_path = _write(
        tmp_path / "config.py",
        'api_secret = "kJ9sP2mQxT7vL4wR8nY1zC6bA3fD5eH0"\n',
    )

    findings = scan_file(file_path)

    assert len(findings) == 1
    assert findings[0].detection_method == DetectionMethod.REGEX
    assert findings[0].confidence_score > 0.55


def test_context_does_not_boost_normal_variable_name(tmp_path):
    file_path = _write(
        tmp_path / "config.py",
        'random_value = "kJ9sP2mQxT7vL4wR8nY1zC6bA3fD5eH0"\n',
    )

    findings = scan_file(file_path)

    assert len(findings) == 1
    assert findings[0].detection_method == DetectionMethod.ENTROPY


def test_context_reduces_confidence_for_placeholder(tmp_path):
    file_path = _write(
        tmp_path / "config.py",
        'api_key = "YOUR_API_KEY_12345678901234567890"\n',
    )

    findings = scan_file(file_path)

    assert len(findings) == 1
    assert findings[0].detection_method == DetectionMethod.REGEX
    assert findings[0].confidence_score < 0.55

def test_secret_context_has_higher_confidence_than_neutral_context(tmp_path):
    secret_file = tmp_path / "secret.py"
    secret_file.write_text(
        'api_key = "kJ9sP2mQxT7vL4wR8nY1zC6bA3fD5eH0"\n',
        encoding="utf-8",
    )

    neutral_file = tmp_path / "neutral.py"
    neutral_file.write_text(
        'random_value = "kJ9sP2mQxT7vL4wR8nY1zC6bA3fD5eH0"\n',
        encoding="utf-8",
    )

    secret_findings = scan_file(secret_file)
    neutral_findings = scan_file(neutral_file)

    assert len(secret_findings) == 1
    assert len(neutral_findings) == 1

    assert (
        secret_findings[0].confidence_score
        > neutral_findings[0].confidence_score
    )


def test_neutral_context_does_not_create_extra_findings(tmp_path):
    file_path = tmp_path / "normal.py"
    file_path.write_text(
        'random_value = "kJ9sP2mQxT7vL4wR8nY1zC6bA3fD5eH0"\n',
        encoding="utf-8",
    )

    findings = scan_file(file_path)

    assert len(findings) == 1
    assert findings[0].detection_method == DetectionMethod.ENTROPY