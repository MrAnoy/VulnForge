"""
VulnForge Scheduled Assessments Router
Enforces Authorization Re-check on Schedule Creation and Management.
"""
from typing import List
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from apps.api.core.database import get_db
from apps.api.core.models import User, Schedule, Project
from apps.api.core.security import get_current_user, verify_project_access, verify_org_access
from packages.schemas.models import ScheduleCreate, ScheduleResponse
from packages.shared.constants import Role

router = APIRouter(prefix="/api", tags=["Schedules"])


def compute_next_run(freq: str) -> datetime:
    now = datetime.now(timezone.utc)
    if freq == "DAILY":
        return now + timedelta(days=1)
    elif freq == "MONTHLY":
        return now + timedelta(days=30)
    else:  # WEEKLY default
        return now + timedelta(days=7)


@router.get("/projects/{project_id}/schedules", response_model=List[ScheduleResponse])
async def list_schedules(
    project_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_project_access(project_id, user, db)
    result = await db.execute(select(Schedule).where(Schedule.project_id == project_id))
    return [ScheduleResponse.model_validate(s) for s in result.scalars().all()]


@router.post("/projects/{project_id}/schedules", response_model=ScheduleResponse)
async def create_schedule(
    project_id: str,
    schedule_in: ScheduleCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    project, _ = await verify_project_access(
        project_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )

    next_run = compute_next_run(schedule_in.frequency.upper())

    schedule = Schedule(
        project_id=project_id,
        name=schedule_in.name,
        profile=schedule_in.profile,
        frequency=schedule_in.frequency.upper(),
        targets=schedule_in.targets,
        is_active=schedule_in.is_active,
        next_run_at=next_run
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return ScheduleResponse.model_validate(schedule)


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    res = await db.execute(select(Schedule).where(Schedule.id == schedule_id))
    schedule = res.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    await verify_project_access(
        schedule.project_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )
    await db.delete(schedule)
    await db.commit()
    return {"success": True, "message": "Schedule deleted"}
