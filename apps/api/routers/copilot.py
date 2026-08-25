"""
VulnForge AI Security Copilot Router
Enforces Multi-Tenant Isolation on AI Operations.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from apps.api.core.database import get_db
from apps.api.core.models import User, Finding, Project, Assessment
from apps.api.core.security import (
    get_current_user,
    verify_project_access,
    verify_finding_access,
)
from packages.schemas.models import (
    AICopilotChatRequest,
    AICopilotChatResponse,
    AIFindingExplanationRequest,
    AIFindingExplanationResponse,
)
from apps.api.services.ai_service import get_ai_provider

router = APIRouter(prefix="/api/copilot", tags=["Security Copilot"])


@router.post("/chat", response_model=AICopilotChatResponse)
async def copilot_chat(
    req: AICopilotChatRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    project, _ = await verify_project_access(req.project_id, user, db)

    # Fetch findings context
    f_query = select(Finding).where(Finding.project_id == req.project_id)
    if req.assessment_id:
        f_query = f_query.where(Finding.assessment_id == req.assessment_id)
    f_res = await db.execute(f_query)
    findings = f_res.scalars().all()

    findings_context = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "cvss_score": f.cvss_score,
            "platform_risk_score": f.platform_risk_score,
            "asset_target": f.asset_target,
            "endpoint": f.endpoint,
            "description": f.description,
            "impact": f.impact,
            "remediation": f.remediation,
            "status": f.status.value if hasattr(f.status, 'value') else str(f.status)
        }
        for f in findings
    ]

    context = {
        "project_name": project.name,
        "environment": project.environment.value if hasattr(project.environment, 'value') else str(project.environment),
        "findings": findings_context
    }

    ai = get_ai_provider()
    return await ai.chat(
        message=req.message,
        context=context,
        chat_history=req.chat_history
    )


@router.post("/explain-finding", response_model=AIFindingExplanationResponse)
async def explain_finding(
    req: AIFindingExplanationRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    finding, _, _ = await verify_finding_access(req.finding_id, user, db)

    finding_data = {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
        "cvss_score": finding.cvss_score,
        "impact": finding.impact,
        "remediation": finding.remediation,
    }

    ai = get_ai_provider()
    return await ai.explain_finding(finding_data)
