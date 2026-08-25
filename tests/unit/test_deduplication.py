"""
Unit Tests: Finding Deduplication & Correlation Engine
"""
import pytest
from packages.schemas.models import FindingBase, EvidenceItem
from apps.api.services.finding_service import FindingService
from packages.shared.constants import Severity, Confidence


def test_deduplication_and_correlation():
    f1 = FindingBase(
        title="Missing Content Security Policy (CSP)",
        description="CSP header is missing.",
        severity=Severity.LOW,
        cvss_score=4.0,
        cwe="CWE-1021",
        category="Web Security Configuration",
        asset_target="https://example.com",
        endpoint="/",
        impact="XSS risk",
        remediation="Add CSP header",
        scanner="Custom Web Security Engine",
        evidence=EvidenceItem(output_snippet="CSP missing on GET /"),
        confidence=Confidence.MEDIUM
    )

    f2 = FindingBase(
        title="Content Security Policy Not Implemented [csp-missing]",
        description="Nuclei found CSP absent.",
        severity=Severity.MEDIUM,
        cvss_score=6.1,
        cwe="CWE-1021",
        category="Web Security Configuration",
        asset_target="https://example.com",
        endpoint="/",
        impact="XSS risk",
        remediation="Add CSP header",
        scanner="Nuclei Template Scanner",
        evidence=EvidenceItem(output_snippet="Nuclei matched http-missing-csp"),
        confidence=Confidence.CONFIRMED
    )

    # Different finding
    f3 = FindingBase(
        title="Exposed .git Directory",
        description="Git exposed",
        severity=Severity.HIGH,
        cvss_score=7.5,
        cwe="CWE-538",
        category="Information Disclosure",
        asset_target="https://example.com",
        endpoint="/.git/HEAD",
        impact="Source code leakage",
        remediation="Block .git",
        scanner="Custom Web Security Engine"
    )

    results = FindingService.deduplicate_and_correlate([f1, f2, f3])

    # Should merge f1 and f2 into 1 correlated finding, leaving 2 unique findings total
    assert len(results) == 2

    # Find the merged CSP finding
    csp_finding = next(f for f in results if "Content Security Policy" in f.title)
    # Severity should be elevated to MEDIUM (from f2)
    assert csp_finding.severity == Severity.MEDIUM
    assert csp_finding.cvss_score == 6.1
    # Scanner should indicate correlation
    assert "Correlated" in csp_finding.scanner
    assert "Nuclei Template Scanner" in csp_finding.scanner
    assert "Custom Web Security Engine" in csp_finding.scanner
