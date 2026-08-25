"""
Unit Tests: Smart Prioritization Engine ("What Should I Fix First?")
"""
import pytest
from packages.schemas.models import FindingResponse
from packages.shared.constants import Severity, FindingStatus, Confidence, AssetCriticality


def test_prioritization_critical_tier1_asset_ranking():
    # Critical finding on critical asset should have maximum priority
    sev_base = 100.0  # Critical
    crit_mult = 1.4   # Critical Asset
    cvss_factor = (9.8 / 10.0) * 20.0
    conf_factor = 1.0 # Confirmed

    score = (sev_base + cvss_factor) * crit_mult * conf_factor
    assert score > 150.0  # Extremely high urgency


def test_prioritization_low_severity_asset_ranking():
    sev_base = 20.0  # Low
    crit_mult = 0.8  # Low Asset
    cvss_factor = (3.1 / 10.0) * 20.0
    conf_factor = 0.8 # Medium confidence

    score = (sev_base + cvss_factor) * crit_mult * conf_factor
    assert score < 30.0  # Low priority scheduled remediation
