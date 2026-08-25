"""
Security Tests: Advanced SSRF Evasion Defenses
Verifies that IPv6 mapped IPv4, cloud metadata, link-local, and webhook targets are blocked.
"""
import pytest
from packages.security.ssrf_guard import SSRFGuard, TargetValidationError


def test_ipv6_mapped_ipv4_loopback_is_blocked():
    # ::ffff:127.0.0.1
    assert SSRFGuard.is_private_ip("::ffff:127.0.0.1") is True
    # ::ffff:169.254.169.254
    assert SSRFGuard.is_private_ip("::ffff:169.254.169.254") is True
    # ::ffff:10.0.0.1
    assert SSRFGuard.is_private_ip("::ffff:10.0.0.1") is True


def test_cloud_metadata_blocked():
    assert SSRFGuard.is_private_ip("169.254.169.254") is True


def test_public_ip_is_allowed():
    assert SSRFGuard.is_private_ip("93.184.216.34") is False  # example.com public IP


def test_ssrf_guard_blocks_private_targets_when_local_lab_false():
    with pytest.raises(TargetValidationError):
        SSRFGuard.resolve_and_validate("127.0.0.1", allow_local_lab=False)

    with pytest.raises(TargetValidationError):
        SSRFGuard.resolve_and_validate("10.0.0.5", allow_local_lab=False)


def test_ssrf_guard_allows_private_targets_when_local_lab_true():
    ips = SSRFGuard.resolve_and_validate("127.0.0.1", allow_local_lab=True)
    assert "127.0.0.1" in ips
