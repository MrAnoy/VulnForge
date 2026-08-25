"""
Unit Tests: Scope Engine & SSRF Guard
"""
import pytest
from packages.security.ssrf_guard import SSRFGuard, TargetValidationError


def test_target_normalization():
    # URL normalization
    host, port, proto = SSRFGuard.normalize_target("https://example.com:8443/v1/api")
    assert host == "example.com"
    assert port == 8443
    assert proto == "https"

    # Domain only
    host, port, proto = SSRFGuard.normalize_target("api.example.com")
    assert host == "api.example.com"
    assert port is None
    assert proto == "http"

    # IP with port
    host, port, proto = SSRFGuard.normalize_target("192.0.2.1:8080")
    assert host == "192.0.2.1"
    assert port == 8080


def test_private_ip_detection():
    assert SSRFGuard.is_private_ip("127.0.0.1") is True
    assert SSRFGuard.is_private_ip("10.0.0.1") is True
    assert SSRFGuard.is_private_ip("172.16.0.5") is True
    assert SSRFGuard.is_private_ip("192.168.1.100") is True
    assert SSRFGuard.is_private_ip("169.254.169.254") is True  # Cloud metadata
    assert SSRFGuard.is_private_ip("::1") is True
    assert SSRFGuard.is_private_ip("93.184.216.34") is False  # Public IP


def test_scope_allowlist_matching():
    allowed = ["example.com", "*.api.company.com", "192.0.2.0/24"]
    excluded = ["test.api.company.com"]

    # Direct match
    in_scope, msg = SSRFGuard.is_target_in_scope("example.com", allowed, excluded)
    assert in_scope is True

    # Wildcard match
    in_scope, msg = SSRFGuard.is_target_in_scope("auth.api.company.com", allowed, excluded)
    assert in_scope is True

    # Excluded match
    in_scope, msg = SSRFGuard.is_target_in_scope("test.api.company.com", allowed, excluded)
    assert in_scope is False
    assert "matches excluded scope rule" in msg

    # Out of scope
    in_scope, msg = SSRFGuard.is_target_in_scope("unauthorized.org", allowed, excluded)
    assert in_scope is False
