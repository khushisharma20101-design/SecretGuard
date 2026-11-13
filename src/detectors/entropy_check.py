"""
Entropy-based secret detection for SecretGuard.

Entropy detection is used as a secondary check for random-looking
strings that are not recognized by the normal regex rules.
"""

from __future__ import annotations

import math
import re
import string
from pathlib import Path

from src.models import DetectionMethod, Finding, SeverityEnum


# Minimum length for an entropy candidate.
MIN_CANDIDATE_LENGTH = 20

# Entropy thresholds.
HEX_ENTROPY_THRESHOLD = 3.0
BASE64_ENTROPY_THRESHOLD = 4.5
GENERIC_ENTROPY_THRESHOLD = 3.5

_HEX_CHARS = set(string.hexdigits.lower())
_BASE64_CHARS = set(
    string.ascii_letters + string.digits + "+/="
)


# Only inspect quoted values assigned to a variable/key.
_ASSIGNMENT_STRING_PATTERN = re.compile(
    r"""[:=]\s*['"]([^'"]{%d,})['"]""" % MIN_CANDIDATE_LENGTH
)


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy in bits per character."""

    if not value:
        return 0.0

    length = len(value)
    frequency: dict[str, int] = {}

    for char in value:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0.0

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _classify_charset(value: str) -> tuple[str, float]:
    """Identify the character set and return its entropy threshold."""

    chars = set(value.lower())

    if chars <= _HEX_CHARS:
        return "hex", HEX_ENTROPY_THRESHOLD

    if chars <= {c.lower() for c in _BASE64_CHARS}:
        return "base64-like", BASE64_ENTROPY_THRESHOLD

    return "generic", GENERIC_ENTROPY_THRESHOLD


def _confidence_from_entropy(
    entropy: float,
    threshold: float,
) -> float:
    """Convert entropy into a confidence score."""

    if entropy <= threshold:
        return 0.0

    excess = entropy - threshold

    return min(
        0.5 + excess * 0.2,
        0.9,
    )


def _severity_from_confidence(
    confidence: float,
) -> SeverityEnum:
    """Convert entropy confidence into a severity level."""

    if confidence >= 0.8:
        return SeverityEnum.HIGH

    if confidence >= 0.6:
        return SeverityEnum.MEDIUM

    return SeverityEnum.LOW


def _redact(
    value: str,
    keep_prefix: int = 4,
    keep_suffix: int = 2,
) -> str:
    """Hide most of the detected value."""

    if len(value) <= keep_prefix + keep_suffix:
        return "*" * len(value)

    masked_length = len(value) - keep_prefix - keep_suffix

    return (
        f"{value[:keep_prefix]}"
        f"{'*' * masked_length}"
        f"{value[-keep_suffix:]}"
    )


def extract_candidates(line: str) -> list[str]:
    """
    Extract quoted strings assigned to variables or configuration keys.
    """

    return _ASSIGNMENT_STRING_PATTERN.findall(line)


def scan_line(
    line: str,
    line_number: int,
    file_path: Path,
    min_length: int = MIN_CANDIDATE_LENGTH,
) -> list[Finding]:
    """
    Scan one line for high-entropy secret-like values.
    """

    findings: list[Finding] = []

    for candidate in extract_candidates(line):

        if len(candidate) < min_length:
            continue

        # Important false-positive protection:
        # normal sentences/prose containing spaces should not be
        # treated as random secret values.
        if any(char.isspace() for char in candidate):
            continue

        entropy = shannon_entropy(candidate)

        charset_label, threshold = _classify_charset(candidate)

        confidence = _confidence_from_entropy(
            entropy,
            threshold,
        )

        if confidence <= 0.0:
            continue

        findings.append(
            Finding(
                file_path=file_path,
                line_number=line_number,
                secret_type=f"High-Entropy String ({charset_label})",
                redacted_value=_redact(candidate),
                detection_method=DetectionMethod.ENTROPY,
                entropy_score=round(entropy, 3),
                severity=_severity_from_confidence(confidence),
                confidence_score=round(confidence, 3),
                recommendation=(
                    "This value has unusually high randomness for "
                    "hardcoded source text, which can indicate a "
                    "secret. Verify it manually and, if it is a real "
                    "credential, move it to an environment variable "
                    "or secrets manager."
                ),
            )
        )

    return findings