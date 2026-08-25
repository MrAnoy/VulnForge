"""
Unit Tests: Transparent Risk Scoring Engine
"""
import pytest
from packages.schemas.models import FindingBase
from apps.api.services.risk_service import RiskEngine
from packages.shared.constants import (
    Severity,
    AssetCriticality,
    EnvironmentType,
    Confidence,
)


def test_critical_finding_risk_score():
    score = RiskEngine.calculate_finding_risk_score(
        severity=Severity.CRITICAL,
        cvss_score=9.1,
        criticality=AssetCriticality.CRITICAL,
        environment=EnvironmentType.PRODUCTION,
        confidence=Confidence.CONFIRMED
    )
    # Base 85 + (9.1/10)*15 = ~98.65 * 1.25 * 1.2 * 1.0 = capped at 100.0
    assert score == 100.0


def test_low_finding_risk_score():
    score = RiskEngine.calculate_finding_risk_score(
        severity=Severity.LOW,
        cvss_score=3.1,
        criticality=AssetCriticality.LOW,
        environment=EnvironmentType.DEVELOPMENT,
        confidence=Confidence.HIGH
    )
    # Low severity in dev environment should have low risk score
    assert score < 30.0


def test_overall_security_score_calculation():
    f_crit = FindingBase(
        title="Critical RCE",
        description="test",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        category="RCE",
        asset_target="example.com",
        impact="Full compromise",
        remediation="Patch",
        scanner="TestScanner"
    )
    f_high = FindingBase(
        title="High SQLi",
        description="test",
        severity=Severity.HIGH,
        cvss_score=8.5,
        category="SQLi",
        asset_target="example.com",
        impact="Data leak",
        remediation="Parameterized queries",
        scanner="TestScanner"
    )

    # Clean posture
    assert RiskEngine.calculate_security_score([]) == 100.0

    # With Critical & High
    score = RiskEngine.calculate_security_score([f_crit, f_high])
    # 100 - 20 - 10 = 70
    assert score == 70.0
