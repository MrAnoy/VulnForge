"""
Security Tests: Secret Sanitizer & Path Traversal Prevention
"""
import pytest
from packages.security.sanitizer import sanitize_text, sanitize_headers, sanitize_path


def test_secret_scrubbing():
    # Bearer token
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuv"
    scrubbed = sanitize_text(text)
    assert "[REDACTED_TOKEN]" in scrubbed
    assert "eyJzdWI" not in scrubbed

    # API key
    text = "api_key: abcdef1234567890abcdef"
    scrubbed = sanitize_text(text)
    assert "[REDACTED_KEY]" in scrubbed

    # Password
    text = "DB_PASSWORD=SuperSecretAdminPassword123!"
    scrubbed = sanitize_text(text)
    assert "[REDACTED_PASSWORD]" in scrubbed
    assert "SuperSecretAdmin" not in scrubbed


def test_header_sanitization():
    headers = {
        "Authorization": "Bearer secret_token_value_12345",
        "Set-Cookie": "session_id=abcdef12345; Secure; HttpOnly",
        "Content-Type": "application/json",
        "X-Custom-Info": "harmless_value"
    }
    sanitized = sanitize_headers(headers)
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["Set-Cookie"] == "[REDACTED]"
    assert sanitized["Content-Type"] == "application/json"
    assert sanitized["X-Custom-Info"] == "harmless_value"


def test_path_traversal_sanitization():
    assert sanitize_path("../../../etc/passwd") == "etc/passwd"
    assert sanitize_path("..\\..\\windows\\win.ini") == "windows\\win.ini"
    assert sanitize_path("/reports/report123.pdf") == "reports/report123.pdf"
