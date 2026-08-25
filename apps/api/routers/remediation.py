"""
VulnForge Remediation Tasks & Verification Tracking Router
Enforces Multi-Tenant Isolation and Role-Based Remediation Workflows.
"""
from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from apps.api.core.database import get_db
from apps.api.core.models import User, RemediationTask, Finding
from apps.api.core.security import (
    get_current_user,
    verify_project_access,
    verify_finding_access,
    verify_task_access,
)
from packages.schemas.models import RemediationTaskCreate, RemediationTaskResponse
from packages.shared.constants import FindingStatus, Role

router = APIRouter(prefix="/api", tags=["Remediation"])


@router.get("/projects/{project_id}/remediation", response_model=List[RemediationTaskResponse])
async def list_remediation_tasks(
    project_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_project_access(project_id, user, db)

    query = (
        select(RemediationTask)
        .join(Finding, Finding.id == RemediationTask.finding_id)
        .where(Finding.project_id == project_id)
    )
    result = await db.execute(query)
    tasks = result.scalars().all()
    return [RemediationTaskResponse.model_validate(t) for t in tasks]


@router.post("/remediation", response_model=RemediationTaskResponse)
async def create_remediation_task(
    task_in: RemediationTaskCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    finding, project, _ = await verify_finding_access(
        task_in.finding_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )

    task = RemediationTask(
        finding_id=task_in.finding_id,
        title=task_in.title,
        description=task_in.description,
        assignee_id=task_in.assignee_id,
        status=FindingStatus.OPEN,
        priority=task_in.priority,
        due_date=task_in.due_date,
        notes=[]
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)
    return RemediationTaskResponse.model_validate(task)


@router.patch("/remediation/{task_id}", response_model=RemediationTaskResponse)
async def update_remediation_status(
    task_id: str,
    status_update: FindingStatus,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    task, finding, project, _ = await verify_task_access(
        task_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )

    task.status = status_update
    task.updated_at = datetime.now(timezone.utc)
    
    # Also update associated finding status if marked resolved
    if status_update in [FindingStatus.RESOLVED, FindingStatus.VERIFIED, FindingStatus.IN_PROGRESS]:
        finding.status = status_update

    await db.commit()
    await db.refresh(task)
    return RemediationTaskResponse.model_validate(task)
