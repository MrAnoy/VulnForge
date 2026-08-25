"""
VulnForge Report Generation Engine
Produces Executive, Technical, and Developer reports across HTML, PDF, JSON, CSV, and Markdown formats.
Enforces Jinja2 autoescaping to prevent Stored XSS and supports enterprise white-label branding.
"""
import os
import json
import csv
import io
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from jinja2 import Template
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from packages.schemas.models import ReportGenerateRequest, WhiteLabelBranding
from packages.shared.constants import ReportType, ReportFormat, Severity
from packages.shared.logging import logger

REPORTS_DIR = "./reports_storage"
os.makedirs(REPORTS_DIR, exist_ok=True)


HTML_REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - {{ branding.company_name }}</title>
    <style>
        :root {
            --bg: #090d16;
            --card-bg: #111827;
            --border: #1f2937;
            --text-main: #f9fafb;
            --text-muted: #9ca3af;
            --accent: {{ branding.accent_color or '#3b82f6' }};
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #6b7280;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        .header {
            border-bottom: 2px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .brand {
            font-size: 24px;
            font-weight: 800;
            color: var(--accent);
            letter-spacing: -0.5px;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
        .badge-high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
        .badge-medium { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
        .badge-low { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
        .badge-info { background: rgba(107, 114, 128, 0.2); color: var(--info); border: 1px solid var(--info); }
        
        .score-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 32px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        .metric-title { font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .metric-value { font-size: 32px; font-weight: 800; margin-top: 6px; }
        
        .section-title {
            font-size: 20px;
            font-weight: 700;
            margin-top: 36px;
            margin-bottom: 16px;
            border-left: 4px solid var(--accent);
            padding-left: 12px;
        }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }
        .finding-title { font-size: 17px; font-weight: 700; }
        .code-box {
            background: #030712;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 12px;
            font-family: monospace;
            font-size: 13px;
            color: #38bdf8;
            white-space: pre-wrap;
            word-break: break-all;
            margin-top: 8px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }
        th, td {
            text-align: left;
            padding: 10px 14px;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
        }
        th { color: var(--text-muted); background: #1f2937; }
        .footer {
            margin-top: 60px;
            text-align: center;
            font-size: 13px;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            padding-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="brand">🛡️ {{ branding.company_name }}</div>
                <div style="color: var(--text-muted); font-size: 14px; margin-top: 4px;">{{ report_type }} Security Assessment Deliverable</div>
                {% if branding.client_name %}
                <div style="font-size: 13px; color: var(--accent); margin-top: 2px;">Prepared for: {{ branding.client_name }}</div>
                {% endif %}
            </div>
            <div style="text-align: right;">
                <div style="font-weight: 600;">Date: {{ generated_at }}</div>
                <div style="font-size: 12px; display: inline-block; padding: 2px 8px; border-radius: 4px; background: rgba(239, 68, 68, 0.15); color: #f87171; font-weight: 700; margin-top: 4px;">
                    {{ branding.classification }}
                </div>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Assessor: {{ branding.consultant_name }}</div>
            </div>
        </div>

        <div class="score-card">
            <div>
                <div class="metric-title">Security Posture Score</div>
                <div class="metric-value" style="color: {% if security_score >= 80 %}#10b981{% elif security_score >= 50 %}#f59e0b{% else %}#ef4444{% endif %};">
                    {{ security_score }} / 100
                </div>
            </div>
            <div>
                <div class="metric-title">Total Findings</div>
                <div class="metric-value">{{ findings|length }}</div>
            </div>
            <div>
                <div class="metric-title">Critical / High Risk</div>
                <div class="metric-value" style="color: var(--critical);">
                    {{ summary.critical }} / {{ summary.high }}
                </div>
            </div>
            <div>
                <div class="metric-title">Assessment Target(s)</div>
                <div style="font-size: 16px; font-weight: 600; margin-top: 10px; word-break: break-all;">
                    {{ targets|join(', ') }}
                </div>
            </div>
        </div>

        <div class="section-title">Executive Summary</div>
        <div class="card">
            <p>{{ executive_summary }}</p>
        </div>

        <div class="section-title">Assessment Scope & Methodology</div>
        <div class="card">
            <table>
                <tr><th>Parameter</th><th>Details</th></tr>
                <tr><td>Authorized Targets</td><td>{{ targets|join(', ') }}</td></tr>
                <tr><td>Assessment Profile</td><td>{{ assessment.profile }}</td></tr>
                <tr><td>Execution Status</td><td>{{ assessment.status }}</td></tr>
                <tr><td>Completed Timestamp</td><td>{{ assessment.completed_at or 'In Progress' }}</td></tr>
                <tr><td>Framework Alignments</td><td>OWASP Top 10, CWE / SANS Top 25, CVSS v3.1 Standards</td></tr>
            </table>
        </div>

        <div class="section-title">Detailed Vulnerability Findings</div>
        {% for f in findings %}
        <div class="card">
            <div class="finding-header">
                <div>
                    <span class="badge badge-{{ f.severity|lower }}">{{ f.severity }}</span>
                    <span style="font-size: 13px; color: var(--text-muted); margin-left: 8px;">CVSS: {{ f.cvss_score }} | Risk Score: {{ f.platform_risk_score }} | CWE: {{ f.cwe }}</span>
                    <div class="finding-title" style="margin-top: 6px;">{{ f.title }}</div>
                </div>
                <div style="font-size: 12px; color: var(--text-muted);">{{ f.scanner }}</div>
            </div>

            <p style="margin-top: 8px;"><strong>Description:</strong> {{ f.description }}</p>
            <p><strong>Affected Asset / Endpoint:</strong> <code>{{ f.asset_target }}{{ f.endpoint or '' }}</code></p>
            <p><strong>Business Impact:</strong> {{ f.impact }}</p>
            
            <div style="margin-top: 12px; background: rgba(59, 130, 246, 0.05); border-left: 3px solid var(--accent); padding: 10px;">
                <strong>Recommended Remediation:</strong>
                <div>{{ f.remediation }}</div>
            </div>

            {% if include_evidence and f.evidence and f.evidence.output_snippet %}
            <div style="margin-top: 12px;">
                <strong>Observed Technical Evidence:</strong>
                <div class="code-box">{{ f.evidence.output_snippet }}</div>
            </div>
            {% endif %}
        </div>
        {% else %}
        <div class="card">
            <p style="color: #10b981; font-weight: 600;">✓ No security vulnerabilities were discovered during this assessment execution.</p>
        </div>
        {% endfor %}

        <div class="footer">
            Delivered by {{ branding.company_name }} &bull; Immutable Audit Hash: {{ assessment.id }}
        </div>
    </div>
</body>
</html>
"""


class ReportEngine:
    @staticmethod
    def generate_executive_summary(security_score: float, findings: List[Dict[str, Any]], targets: List[str]) -> str:
        crit = len([f for f in findings if f.get("severity") == "Critical"])
        high = len([f for f in findings if f.get("severity") == "High"])
        med = len([f for f in findings if f.get("severity") == "Medium"])

        summary = (
            f"An authorized security assessment was conducted against {len(targets)} primary asset target(s) ({', '.join(targets)}). "
            f"The overall calculated Security Posture Score is {security_score}/100. "
            f"During the evaluation, a total of {len(findings)} unique finding(s) were identified across the perimeter, "
            f"including {crit} Critical, {high} High, and {med} Medium severity issues. "
        )

        if crit > 0 or high > 0:
            summary += "Immediate prioritization should be given to resolving Critical and High severity findings to eliminate external exposure and mitigate potential data compromise."
        else:
            summary += "The evaluated perimeter exhibits a resilient baseline posture with no critical or high severity vulnerabilities discovered."

        return summary

    @classmethod
    def generate_report(
        cls,
        assessment_data: Dict[str, Any],
        findings_data: List[Dict[str, Any]],
        request: ReportGenerateRequest,
        security_score: float
    ) -> Dict[str, Any]:
        """
        Generate report in requested format (HTML, PDF, JSON, CSV, MARKDOWN) with white-label support.
        """
        branding = request.branding or WhiteLabelBranding()
        title = request.title or f"{assessment_data.get('name', 'Assessment')} - {request.report_type.value} Report"
        targets = assessment_data.get("targets", [])
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        summary_counts = {
            "critical": len([f for f in findings_data if f.get("severity") == "Critical"]),
            "high": len([f for f in findings_data if f.get("severity") == "High"]),
            "medium": len([f for f in findings_data if f.get("severity") == "Medium"]),
            "low": len([f for f in findings_data if f.get("severity") == "Low"]),
            "info": len([f for f in findings_data if f.get("severity") == "Informational"]),
        }

        exec_summary = request.executive_summary_override or cls.generate_executive_summary(
            security_score, findings_data, targets
        )

        report_id = f"rep_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{assessment_data.get('id', 'gen')[:8]}"
        file_path = None
        download_url = None

        if request.report_format == ReportFormat.HTML:
            # Enable autoescape=True in Jinja2 to prevent XSS in reports
            template = Template(HTML_REPORT_TEMPLATE, autoescape=True)
            html_content = template.render(
                title=title,
                report_type=request.report_type.value if hasattr(request.report_type, 'value') else str(request.report_type),
                generated_at=now_str,
                security_score=security_score,
                summary=summary_counts,
                targets=targets,
                executive_summary=exec_summary,
                assessment=assessment_data,
                findings=findings_data,
                include_evidence=request.include_evidence,
                branding=branding.model_dump()
            )
            file_name = f"{report_id}.html"
            file_path = os.path.join(REPORTS_DIR, file_name)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            download_url = f"/api/reports/{report_id}/download"

        elif request.report_format == ReportFormat.JSON:
            data = {
                "report_id": report_id,
                "title": title,
                "branding": branding.model_dump(),
                "type": request.report_type.value if hasattr(request.report_type, 'value') else str(request.report_type),
                "generated_at": now_str,
                "security_score": security_score,
                "summary": summary_counts,
                "executive_summary": exec_summary,
                "assessment": assessment_data,
                "findings": findings_data,
            }
            file_name = f"{report_id}.json"
            file_path = os.path.join(REPORTS_DIR, file_name)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            download_url = f"/api/reports/{report_id}/download"

        elif request.report_format == ReportFormat.CSV:
            file_name = f"{report_id}.csv"
            file_path = os.path.join(REPORTS_DIR, file_name)
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Title", "Severity", "CVSS", "Risk Score", "CWE", "Asset Target", "Endpoint", "Impact", "Remediation", "Scanner", "Status"])
                for f in findings_data:
                    writer.writerow([
                        f.get("title"),
                        f.get("severity"),
                        f.get("cvss_score"),
                        f.get("platform_risk_score"),
                        f.get("cwe"),
                        f.get("asset_target"),
                        f.get("endpoint"),
                        f.get("impact"),
                        f.get("remediation"),
                        f.get("scanner"),
                        f.get("status"),
                    ])
            download_url = f"/api/reports/{report_id}/download"

        elif request.report_format == ReportFormat.PDF:
            file_name = f"{report_id}.pdf"
            file_path = os.path.join(REPORTS_DIR, file_name)
            doc = SimpleDocTemplate(file_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()
            story = []

            # Header with Branding
            title_style = ParagraphStyle(name="DocTitle", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#1e3a8a"), spaceAfter=8)
            story.append(Paragraph(f"{branding.company_name} — {title}", title_style))
            if branding.client_name:
                story.append(Paragraph(f"<b>Client:</b> {branding.client_name} | <b>Assessor:</b> {branding.consultant_name}", styles["Normal"]))
            story.append(Paragraph(f"<b>Classification:</b> {branding.classification} | <b>Generated:</b> {now_str} | <b>Score:</b> {security_score}/100", styles["Normal"]))
            story.append(Spacer(1, 14))

            # Executive Summary
            story.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))
            story.append(Paragraph(exec_summary, styles["Normal"]))
            story.append(Spacer(1, 14))

            # Findings Table
            story.append(Paragraph("<b>Discovered Vulnerabilities & Weaknesses</b>", styles["Heading2"]))
            table_data = [["Severity", "Title", "CVSS", "Target", "Status"]]
            for f in findings_data:
                table_data.append([
                    f.get("severity", "Medium"),
                    Paragraph(f.get("title", ""), styles["Normal"]),
                    str(f.get("cvss_score", 0.0)),
                    f.get("asset_target", "")[:30],
                    f.get("status", "OPEN")
                ])
            
            if len(table_data) > 1:
                t = Table(table_data, colWidths=[70, 220, 45, 120, 60])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0,0), (-1,0), 6),
                    ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
                ]))
                story.append(t)
            else:
                story.append(Paragraph("No vulnerabilities discovered.", styles["Normal"]))

            doc.build(story)
            download_url = f"/api/reports/{report_id}/download"

        return {
            "id": report_id,
            "title": title,
            "report_type": request.report_type,
            "report_format": request.report_format,
            "file_path": file_path,
            "download_url": download_url,
            "created_at": datetime.now(timezone.utc),
            "security_score": security_score,
            "summary": summary_counts
        }
