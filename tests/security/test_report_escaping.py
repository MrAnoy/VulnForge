"""
Security Tests: Report Generation HTML Escaping / Stored XSS Prevention
"""
import os
from packages.schemas.models import ReportGenerateRequest
from packages.shared.constants import ReportType, ReportFormat
from apps.api.services.report_service import ReportEngine, REPORTS_DIR


def test_html_report_escapes_xss_in_finding_data():
    malicious_finding = {
        "id": "find_xss_test",
        "title": "<script>alert('XSS_TITLE')</script>",
        "description": "<img src=x onerror=alert('XSS_DESC')>",
        "severity": "Critical",
        "cvss_score": 9.8,
        "platform_risk_score": 95.0,
        "cwe": "CWE-79",
        "category": "Injection",
        "asset_target": "https://example.com",
        "endpoint": "/<svg onload=alert(1)>",
        "impact": "<script>evil()</script>",
        "remediation": "<iframe src='javascript:alert(1)'></iframe>",
        "evidence": {
            "output_snippet": "<script>document.cookie</script>"
        },
        "scanner": "Web Scanner",
        "status": "OPEN"
    }

    assessment_data = {
        "id": "assess_xss_test",
        "name": "<script>alert('ASSESS')</script>",
        "profile": "STANDARD_VAPT",
        "status": "COMPLETED",
        "targets": ["https://example.com"],
        "completed_at": "2026-08-25 12:00 UTC"
    }

    req = ReportGenerateRequest(
        assessment_id="assess_xss_test",
        report_type=ReportType.TECHNICAL,
        report_format=ReportFormat.HTML,
        include_evidence=True
    )

    report_res = ReportEngine.generate_report(
        assessment_data=assessment_data,
        findings_data=[malicious_finding],
        request=req,
        security_score=45.0
    )

    file_path = report_res["file_path"]
    assert file_path is not None and os.path.exists(file_path)

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Raw executable tags must NOT be present unescaped
    assert "<script>alert('XSS_TITLE')</script>" not in content
    assert "<script>evil()</script>" not in content
    assert "<img src=x onerror=alert('XSS_DESC')>" not in content
    assert "<iframe src='javascript:alert(1)'></iframe>" not in content
    assert "<script>document.cookie</script>" not in content

    # Verified that tags are properly HTML entity escaped
    assert "&lt;script&gt;" in content
    assert "&lt;img" in content
    assert "&lt;iframe" in content
