"""
VulnForge Findings Management & Status Workflow Router
Enforces Multi-Tenant Isolation, RBAC, and Audit Trail Logging.
"""
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from apps.api.core.database import get_db
from apps.api.core.models import User, Finding, Project, AuditLog
from apps.api.core.security import (
    get_current_user,
    verify_project_access,
    verify_finding_access,
)
from packages.schemas.models import FindingResponse, FindingStatusUpdate
from packages.shared.constants import Severity, FindingStatus, Role

router = APIRouter(prefix="/api", tags=["Findings"])


@router.get("/projects/{project_id}/findings", response_model=List[FindingResponse])
async def list_findings(
    project_id: str,
    severity: Optional[List[Severity]] = Query(None),
    finding_status: Optional[List[FindingStatus]] = Query(None, alias="status"),
    scanner: Optional[str] = None,
    cwe: Optional[str] = None,
    search: Optional[str] = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_project_access(project_id, user, db)

    query = select(Finding).where(Finding.project_id == project_id)

    if severity:
        query = query.where(Finding.severity.in_(severity))
    if finding_status:
        query = query.where(Finding.status.in_(finding_status))
    if scanner:
        query = query.where(Finding.scanner.ilike(f"%{scanner}%"))
    if cwe:
        query = query.where(Finding.cwe.ilike(f"%{cwe}%"))
    if search:
        query = query.where(
            Finding.title.ilike(f"%{search}%") | 
            Finding.description.ilike(f"%{search}%") | 
            Finding.asset_target.ilike(f"%{search}%")
        )

    query = query.order_by(desc(Finding.platform_risk_score), desc(Finding.first_seen))
    result = await db.execute(query)
    findings = result.scalars().all()
    return [FindingResponse.model_validate(f) for f in findings]


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    finding, _, _ = await verify_finding_access(finding_id, user, db)
    return FindingResponse.model_validate(finding)


@router.patch("/findings/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: str,
    update_in: FindingStatusUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    finding, project, _ = await verify_finding_access(
        finding_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )

    old_status = finding.status
    finding.status = update_in.status
    if update_in.remediation_notes:
        finding.remediation_notes = update_in.remediation_notes

    # Append to status history
    history = list(finding.status_history or [])
    history.append({
        "from_status": old_status.value if hasattr(old_status, 'value') else str(old_status),
        "to_status": update_in.status.value if hasattr(update_in.status, 'value') else str(update_in.status),
        "reason": update_in.reason,
        "changed_by": user.email,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    finding.status_history = history

    # Audit log
    audit = AuditLog(
        organization_id=project.organization_id,
        user_id=user.id,
        user_email=user.email,
        action="UPDATE_FINDING_STATUS",
        target_resource=finding.id,
        details={
            "finding_title": finding.title,
            "old_status": str(old_status),
            "new_status": str(update_in.status),
            "reason": update_in.reason
        }
    )
    db.add(audit)

    await db.commit()
    await db.refresh(finding)
    return FindingResponse.model_validate(finding)
