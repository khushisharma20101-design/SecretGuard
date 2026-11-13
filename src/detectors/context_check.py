"""
Context analysis helpers for SecretGuard.

These functions examine variable/key names and values to determine
whether a piece of code has secret-related context or looks like
a placeholder/example.
"""

from __future__ import annotations

import re


# Words that commonly indicate sensitive information.
SECRET_CONTEXT_WORDS = {
    "api_key",
    "apikey",
    "api_secret",
    "secret",
    "secret_key",
    "password",
    "passwd",
    "token",
    "auth_token",
    "access_token",
    "credential",
    "credentials",
    "private_key",
}


# Values that are commonly used as examples/placeholders.
PLACEHOLDER_MARKERS = {
    "your_api_key",
    "your_api_secret",
    "your_token",
    "your_password",
    "change_me",
    "replace_me",
    "placeholder",
    "example",
    "dummy",
    "test_key",
    "test_token",
}


def normalize_name(name: str) -> str:
    """
    Convert a variable/key name into a simple comparable form.

    Example:
        "API-Key" -> "api_key"
        "apiKey"  -> "apikey"
    """
    name = name.strip().lower()
    name = re.sub(r"[-\s]+", "_", name)
    return name


def extract_assignment_name(line: str) -> str | None:
    """
    Extract the variable/key name from a simple assignment.

    Examples:
        api_key = "abc"       -> "api_key"
        password = "abc"      -> "password"
        "token": "abc"        -> "token"
    """

    # Python-style assignment:
    # api_key = "value"
    match = re.search(
        r"^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=",
        line,
    )

    if match:
        return normalize_name(match.group(1))

    # JSON/dictionary-style assignment:
    # "api_key": "value"
    match = re.search(
        r"""["']([A-Za-z_][A-Za-z0-9_-]*)["']\s*:""",
        line,
    )

    if match:
        return normalize_name(match.group(1))

    return None


def has_secret_context(name: str | None) -> bool:
    """
    Return True if a variable/key name strongly suggests
    that it stores sensitive information.
    """
    if not name:
        return False

    normalized = normalize_name(name)

    # Exact sensitive names.
    if normalized in SECRET_CONTEXT_WORDS:
        return True

    # Check for compound secret-related names.
    parts = re.split(r"[_\-\s]+", normalized)

    # Handle multi-word secret terms such as:
    # user_api_key
    # database_api_key
    # my_secret_key
    for i in range(len(parts) - 1):
        combined = f"{parts[i]}_{parts[i + 1]}"
        if combined in SECRET_CONTEXT_WORDS:
            return True

    # Handle single sensitive words such as:
    # database_password
    # github_token
    # user_credential
    return any(part in SECRET_CONTEXT_WORDS for part in parts)


def is_placeholder(value: str) -> bool:
    """
    Return True when a value looks like an example or placeholder
    rather than an actual secret.
    """

    normalized = value.strip().lower()

    for marker in PLACEHOLDER_MARKERS:
        if marker in normalized:
            return True

    return False
