from src.detectors.context_check import (
    normalize_name,
    extract_assignment_name,
    has_secret_context,
    is_placeholder,
)


def test_normalize_name():
    assert normalize_name("API-Key") == "api_key"
    assert normalize_name(" password ") == "password"


def test_extract_python_assignment_name():
    assert extract_assignment_name('api_key = "abc123"') == "api_key"
    assert extract_assignment_name('password = "hello"') == "password"


def test_extract_json_assignment_name():
    assert extract_assignment_name('"api_key": "abc123"') == "api_key"


def test_extract_assignment_name_returns_none():
    assert extract_assignment_name("print('hello')") is None


def test_has_secret_context():
    assert has_secret_context("api_key") is True
    assert has_secret_context("database_password") is True
    assert has_secret_context("github_token") is True


def test_has_secret_context_for_normal_name():
    assert has_secret_context("random_value") is False
    assert has_secret_context("username") is False


def test_placeholder_detection():
    assert is_placeholder("YOUR_API_KEY") is True
    assert is_placeholder("CHANGE_ME") is True
    assert is_placeholder("PLACEHOLDER") is True


def test_realistic_value_is_not_placeholder():
    assert is_placeholder("sk-demo123456789abcdef") is False

def test_strong_secret_context():
    assert has_secret_context("api_key")
    assert has_secret_context("api_secret")
    assert has_secret_context("password")
    assert has_secret_context("auth_token")


def test_combined_secret_context():
    assert has_secret_context("database_password")
    assert has_secret_context("github_token")
    assert has_secret_context("user_api_key")


def test_neutral_context():
    assert not has_secret_context("random_id")
    assert not has_secret_context("session_id")
    assert not has_secret_context("username")
    assert not has_secret_context("description")


def test_normalize_context_names():
    assert normalize_name("API-Key") == "api_key"
    assert normalize_name("API Secret") == "api_secret"
    assert normalize_name("Password") == "password"