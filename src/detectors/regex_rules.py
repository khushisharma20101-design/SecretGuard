"""
Regex-based secret detection for SecretGuard.

This module contains a small catalogue of common secret patterns
suitable for a BCA minor project.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from src.models import DetectionMethod, Finding, SeverityEnum


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """Represents one regex rule."""

    name: str
    pattern: re.Pattern[str]
    severity: SeverityEnum
    base_confidence: float
    recommendation: str


def _compile(expr: str) -> re.Pattern[str]:
    """Compile a regex expression."""
    return re.compile(expr)


# ------------------------------------------------------------
# Secret detection rules
# ------------------------------------------------------------

REGEX_RULES: list[SecretPattern] = [

    # 1. AWS Access Key ID
    SecretPattern(
        name="AWS Access Key ID",
        pattern=_compile(
            r"\b(AKIA[0-9A-Z]{16})\b"
        ),
        severity=SeverityEnum.CRITICAL,
        base_confidence=0.95,
        recommendation=(
            "Remove the AWS access key from source code and rotate "
            "it if it is real. Store credentials using environment "
            "variables or a secrets manager."
        ),
    ),

    # 2. AWS Secret Access Key
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=_compile(
            r"(?i)AWS[_-]?SECRET[_-]?ACCESS[_-]?KEY\s*[=:]\s*"
            r"['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        severity=SeverityEnum.CRITICAL,
        base_confidence=0.95,
        recommendation=(
            "Remove the AWS secret access key from source code and "
            "rotate it if it is real. Store credentials using "
            "environment variables or a secrets manager."
        ),
    ),

    # 3. Generic API key / secret / token / password
    SecretPattern(
        name="Generic API Key Assignment",
        pattern=_compile(
            r"(?i)(?:api[_-]?key|api[_-]?secret|"
            r"secret(?:[_-]?key)?|token|password|passwd)"
            r"\s*[=:]\s*"
            r"['\"]([^'\"\s]{16,64})['\"]"
        ),
        severity=SeverityEnum.MEDIUM,
        base_confidence=0.55,
        recommendation=(
            "Move this value out of source code and store it in "
            "an environment variable or secrets manager. Verify "
            "whether the value is a real secret."
        ),
    ),

    # 4. Private key block
    SecretPattern(
        name="Private Key Block",
        pattern=_compile(
            r"(-----BEGIN(?: RSA| EC| DSA| OPENSSH)? PRIVATE KEY-----)"
        ),
        severity=SeverityEnum.CRITICAL,
        base_confidence=0.98,
        recommendation=(
            "Remove the private key from source code, rotate the "
            "associated key pair if necessary, and store private "
            "keys outside the repository."
        ),
    ),

    # 5. Database connection string
    SecretPattern(
        name="Database Connection String",
        pattern=_compile(
            r"\b((?:postgres|postgresql|mysql|"
            r"mongodb(?:\+srv)?)://"
            r"[^:\s]+:[^@\s]+@[^\s'\"]+)\b"
        ),
        severity=SeverityEnum.HIGH,
        base_confidence=0.85,
        recommendation=(
            "Do not store database credentials directly in source "
            "code. Use environment variables or a secure "
            "credentials store."
        ),
    ),
]


def _redact(
    value: str,
    keep_prefix: int = 4,
    keep_suffix: int = 2,
) -> str:
    """Mask most of a detected secret."""

    if len(value) <= keep_prefix + keep_suffix:
        return "*" * len(value)

    masked_length = len(value) - keep_prefix - keep_suffix

    return (
        f"{value[:keep_prefix]}"
        f"{'*' * masked_length}"
        f"{value[-keep_suffix:]}"
    )


def scan_line(
    line: str,
    line_number: int,
    file_path: Path,
    rules: list[SecretPattern] | None = None,
) -> list[Finding]:
    """Run all regex rules against one line."""

    active_rules = rules if rules is not None else REGEX_RULES

    findings: list[Finding] = []

    for rule in active_rules:

        for match in rule.pattern.finditer(line):

            if match.groups():
                raw_value = match.group(1)
            else:
                raw_value = match.group(0)

            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=line_number,
                    secret_type=rule.name,
                    redacted_value=_redact(raw_value),
                    detection_method=DetectionMethod.REGEX,
                    severity=rule.severity,
                    confidence_score=rule.base_confidence,
                    recommendation=rule.recommendation,
                )
            )

    return findings