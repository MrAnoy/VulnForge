"""
VulnForge Sanitizer & Secret Scrubbing Engine
"""
import re
from typing import Dict, Any, Union


SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{20,}'), r'\1[REDACTED_TOKEN]'),
    (re.compile(r'(?i)(api[_-]?key\s*[:=]\s*["\']?)[a-zA-Z0-9_\-\.]{16,}(["\']?)'), r'\1[REDACTED_KEY]\2'),
    (re.compile(r'(?i)(password\s*[:=]\s*["\']?)[^"\'\s&]{4,}(["\']?)'), r'\1[REDACTED_PASSWORD]\2'),
    (re.compile(r'(?i)(authorization\s*:\s*Basic\s+)[a-zA-Z0-9+/=]+'), r'\1[REDACTED_BASIC_AUTH]'),
    (re.compile(r'(?i)(secret\s*[:=]\s*["\']?)[a-zA-Z0-9_\-\.]{12,}(["\']?)'), r'\1[REDACTED_SECRET]\2'),
    (re.compile(r'(?i)(set-cookie\s*:\s*)([^;\r\n]+)'), r'\1[REDACTED_COOKIE]'),
    (re.compile(r'(?i)(aws_access_key_id\s*[:=]\s*["\']?)(AKIA[0-9A-Z]{16})(["\']?)'), r'\1[REDACTED_AWS_KEY]\3'),
    (re.compile(r'(?i)(aws_secret_access_key\s*[:=]\s*["\']?)[0-9a-zA-Z/+]{40}(["\']?)'), r'\1[REDACTED_AWS_SECRET]\2'),
]

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "api-key",
    "secret",
}


def sanitize_text(text: str) -> str:
    """Scrub sensitive credentials, tokens, and secrets from logs or evidence."""
    if not text:
        return text
    scrubbed = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        scrubbed = pattern.sub(replacement, scrubbed)
    return scrubbed


def sanitize_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize sensitive HTTP headers before storage or reporting."""
    sanitized = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = sanitize_text(str(v))
    return sanitized


def sanitize_path(path: str) -> str:
    """Prevent path traversal attacks by resolving and sanitizing relative sequences."""
    cleaned = re.sub(r'\.\.+[/\\]', '', path)
    return cleaned.strip('/\\')
