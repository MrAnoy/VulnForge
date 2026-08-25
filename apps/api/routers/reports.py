"""
VulnForge Reports Management & Export Router
Enforces Multi-Tenant Isolation, Authentication on Downloads, and Safe Canonical Path Resolution.
"""
import os
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from apps.api.core.database import get_db
from apps.api.core.models import User, Report, Assessment, Finding, Project
from apps.api.core.security import (
    get_current_user,
    verify_project_access,
    verify_assessment_access,
    verify_report_access,
)
from packages.schemas.models import ReportGenerateRequest, ReportResponse
from apps.api.services.report_service import ReportEngine, REPORTS_DIR
from packages.shared.constants import Role

router = APIRouter(prefix="/api", tags=["Reports"])


@router.post("/reports/generate", response_model=ReportResponse)
async def generate_report(
    req: ReportGenerateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    assessment, project, _ = await verify_assessment_access(
        req.assessment_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )

    f_res = await db.execute(select(Finding).where(Finding.assessment_id == req.assessment_id))
    findings = f_res.scalars().all()

    assessment_dict = {
        "id": assessment.id,
        "name": assessment.name,
        "profile": assessment.profile.value if hasattr(assessment.profile, 'value') else str(assessment.profile),
        "status": assessment.status.value if hasattr(assessment.status, 'value') else str(assessment.status),
        "targets": assessment.targets or [],
        "completed_at": assessment.completed_at.strftime("%Y-%m-%d %H:%M UTC") if assessment.completed_at else None,
    }

    findings_list = [
        {
            "id": f.id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "cvss_score": f.cvss_score,
            "platform_risk_score": f.platform_risk_score,
            "cwe": f.cwe,
            "category": f.category,
            "asset_target": f.asset_target,
            "endpoint": f.endpoint,
            "impact": f.impact,
            "remediation": f.remediation,
            "evidence": f.evidence,
            "scanner": f.scanner,
            "status": f.status.value if hasattr(f.status, 'value') else str(f.status)
        }
        for f in findings
    ]

    report_result = ReportEngine.generate_report(
        assessment_data=assessment_dict,
        findings_data=findings_list,
        request=req,
        security_score=assessment.risk_score or 100.0
    )

    # Save report record in DB
    report_db = Report(
        id=report_result["id"],
        assessment_id=assessment.id,
        project_id=assessment.project_id,
        title=report_result["title"],
        report_type=report_result["report_type"],
        report_format=report_result["report_format"],
        file_path=report_result["file_path"],
        download_url=report_result["download_url"],
        security_score=report_result["security_score"],
        summary=report_result["summary"]
    )
    db.add(report_db)
    await db.commit()

    return ReportResponse(
        id=report_db.id,
        assessment_id=report_db.assessment_id,
        project_id=report_db.project_id,
        title=report_db.title,
        report_type=report_db.report_type,
        report_format=report_db.report_format,
        file_path=report_db.file_path,
        download_url=report_db.download_url,
        created_at=report_db.created_at,
        security_score=report_db.security_score,
        summary=report_db.summary
    )


@router.get("/projects/{project_id}/reports", response_model=List[ReportResponse])
async def list_project_reports(
    project_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_project_access(project_id, user, db)
    res = await db.execute(
        select(Report)
        .where(Report.project_id == project_id)
        .order_by(desc(Report.created_at))
    )
    return [ReportResponse.model_validate(r) for r in res.scalars().all()]


@router.get("/reports/{report_id}/download")
async def download_report_file(
    report_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    report, _, _ = await verify_report_access(report_id, user, db)

    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found")

    # Enforce safe canonical path boundary validation
    canonical_reports_dir = os.path.realpath(REPORTS_DIR)
    canonical_file_path = os.path.realpath(report.file_path)
    if not canonical_file_path.startswith(canonical_reports_dir):
        raise HTTPException(status_code=403, detail="Access Denied: Path traversal detected")

    media_types = {
        "HTML": "text/html",
        "PDF": "application/pdf",
        "JSON": "application/json",
        "CSV": "text/csv"
    }
    media_type = media_types.get(
        report.report_format.value if hasattr(report.report_format, 'value') else str(report.report_format),
        "application/octet-stream"
    )
    filename = os.path.basename(report.file_path)

    return FileResponse(path=canonical_file_path, filename=filename, media_type=media_type)
