"""
VulnForge Assessments Lifecycle & Live Event Streaming Router
Enforces Tenant Isolation, Scope Authorization, and Real-time SSE Execution.
"""
import asyncio
import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from apps.api.core.database import get_db
from apps.api.core.models import User, Assessment, AssessmentLog, Project, Asset, Finding
from apps.api.core.security import (
    get_current_user,
    verify_project_access,
    verify_assessment_access,
)
from packages.schemas.models import (
    AssessmentCreate,
    AssessmentResponse,
    LiveLogEvent,
    AssessmentComparisonResponse,
    FindingComparisonItem,
)
from apps.api.services.orchestrator import ScanOrchestrator
from packages.shared.constants import AssessmentStatus, AssessmentPhase, Role

router = APIRouter(prefix="/api", tags=["Assessments"])


@router.get("/projects/{project_id}/assessments", response_model=List[AssessmentResponse])
async def list_assessments(
    project_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_project_access(project_id, user, db)
    result = await db.execute(
        select(Assessment)
        .where(Assessment.project_id == project_id)
        .order_by(desc(Assessment.created_at))
    )
    return [AssessmentResponse.model_validate(a) for a in result.scalars().all()]


@router.get("/projects/{project_id}/assessments/compare", response_model=AssessmentComparisonResponse)
async def compare_assessments(
    project_id: str,
    base_id: str = Query(..., description="Earlier baseline assessment ID"),
    target_id: str = Query(..., description="Later assessment ID to compare against"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_project_access(project_id, user, db)

    base_res = await db.execute(select(Assessment).where(Assessment.id == base_id, Assessment.project_id == project_id))
    base = base_res.scalar_one_or_none()
    if not base:
        raise HTTPException(status_code=404, detail="Base assessment not found in project")

    target_res = await db.execute(select(Assessment).where(Assessment.id == target_id, Assessment.project_id == project_id))
    target = target_res.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target assessment not found in project")

    # Fetch findings for both
    base_findings_res = await db.execute(select(Finding).where(Finding.assessment_id == base_id))
    base_findings = base_findings_res.scalars().all()
    base_dict = {f"{f.title}:{f.asset_target}:{f.endpoint or ''}": f for f in base_findings}

    target_findings_res = await db.execute(select(Finding).where(Finding.assessment_id == target_id))
    target_findings = target_findings_res.scalars().all()
    target_dict = {f"{f.title}:{f.asset_target}:{f.endpoint or ''}": f for f in target_findings}

    new_items = []
    resolved_items = []
    persistent_items = []

    for key, f in target_dict.items():
        item = FindingComparisonItem(
            id=f.id,
            title=f.title,
            severity=f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            asset_target=f.asset_target,
            platform_risk_score=f.platform_risk_score,
            status=f.status.value if hasattr(f.status, 'value') else str(f.status)
        )
        if key not in base_dict:
            new_items.append(item)
        else:
            persistent_items.append(item)

    for key, f in base_dict.items():
        if key not in target_dict:
            resolved_items.append(FindingComparisonItem(
                id=f.id,
                title=f.title,
                severity=f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                asset_target=f.asset_target,
                platform_risk_score=f.platform_risk_score,
                status="RESOLVED"
            ))

    score_delta = round((target.risk_score or 100.0) - (base.risk_score or 100.0), 1)
    crit_delta = (target.critical_count or 0) - (base.critical_count or 0)
    high_delta = (target.high_count or 0) - (base.high_count or 0)
    med_delta = (target.medium_count or 0) - (base.medium_count or 0)
    low_delta = (target.low_count or 0) - (base.low_count or 0)

    if score_delta > 0:
        verdict = f"Security Posture Improved by +{score_delta} points ({len(resolved_items)} vulnerabilities resolved)."
    elif score_delta < 0:
        verdict = f"Security Posture Decreased by {score_delta} points ({len(new_items)} new findings introduced)."
    else:
        verdict = "Security Posture remained identical between both assessment checkpoints."

    return AssessmentComparisonResponse(
        base_assessment=AssessmentResponse.model_validate(base),
        target_assessment=AssessmentResponse.model_validate(target),
        score_delta=score_delta,
        critical_delta=crit_delta,
        high_delta=high_delta,
        medium_delta=med_delta,
        low_delta=low_delta,
        new_findings=new_items,
        resolved_findings=resolved_items,
        persistent_findings=persistent_items,
        summary_verdict=verdict
    )


@router.post("/assessments", response_model=AssessmentResponse)
async def create_and_start_assessment(
    assessment_in: AssessmentCreate,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    project, _ = await verify_project_access(
        assessment_in.project_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )

    if not assessment_in.authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Authorization confirmation is required before launching an assessment."
        )

    # Determine targets
    targets = list(assessment_in.target_assets)
    if not targets:
        # Pull all assets in project
        a_res = await db.execute(select(Asset).where(Asset.project_id == project.id))
        assets = a_res.scalars().all()
        targets = [a.target for a in assets]

    if not targets:
        raise HTTPException(
            status_code=400,
            detail="No target assets specified or registered in this project."
        )

    assessment = Assessment(
        project_id=project.id,
        name=assessment_in.name,
        profile=assessment_in.profile,
        status=AssessmentStatus.QUEUED,
        current_phase=AssessmentPhase.INITIALIZING,
        progress_percent=0,
        targets=targets,
        custom_modules=assessment_in.custom_modules
    )
    db.add(assessment)
    await db.commit()
    await db.refresh(assessment)

    # Dispatch asynchronous background task execution
    background_tasks.add_task(ScanOrchestrator.run_assessment_lifecycle, assessment.id)

    return AssessmentResponse.model_validate(assessment)


@router.get("/assessments/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(
    assessment_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    assessment, _, _ = await verify_assessment_access(assessment_id, user, db)
    return AssessmentResponse.model_validate(assessment)


@router.post("/assessments/{assessment_id}/cancel")
async def cancel_assessment(
    assessment_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    assessment, _, _ = await verify_assessment_access(
        assessment_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )

    assessment.status = AssessmentStatus.CANCELLED
    assessment.current_phase = AssessmentPhase.COMPLETED
    await db.commit()
    return {"success": True, "message": f"Assessment {assessment_id} cancelled."}


@router.get("/assessments/{assessment_id}/logs")
async def get_assessment_logs(
    assessment_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_assessment_access(assessment_id, user, db)
    res = await db.execute(
        select(AssessmentLog)
        .where(AssessmentLog.assessment_id == assessment_id)
        .order_by(AssessmentLog.timestamp.asc())
    )
    logs = res.scalars().all()
    return [
        {
            "id": l.id,
            "phase": l.phase,
            "level": l.level,
            "message": l.message,
            "progress": l.progress,
            "is_technical": l.is_technical,
            "timestamp": l.timestamp.isoformat()
        }
        for l in logs
    ]


@router.get("/assessments/{assessment_id}/stream")
async def stream_assessment_logs(
    assessment_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Server-Sent Events (SSE) stream for live scan progress."""
    await verify_assessment_access(assessment_id, user, db)

    queue = asyncio.Queue()
    ScanOrchestrator.register_listener(assessment_id, queue)

    async def event_generator():
        try:
            # First send existing logs
            res = await db.execute(
                select(AssessmentLog)
                .where(AssessmentLog.assessment_id == assessment_id)
                .order_by(AssessmentLog.timestamp.asc())
            )
            existing = res.scalars().all()
            for l in existing:
                payload = {
                    "assessment_id": assessment_id,
                    "phase": l.phase.value if hasattr(l.phase, 'value') else str(l.phase),
                    "level": l.level,
                    "message": l.message,
                    "progress": l.progress,
                    "is_technical": l.is_technical,
                    "timestamp": l.timestamp.isoformat()
                }
                yield f"data: {json.dumps(payload)}\n\n"

            # Then stream real-time events
            while True:
                data = await queue.get()
                yield f"data: {json.dumps(data)}\n\n"
                if data.get("phase") in ["COMPLETED", "FAILED"]:
                    break
        except asyncio.CancelledError:
            pass
        finally:
            ScanOrchestrator.unregister_listener(assessment_id, queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
