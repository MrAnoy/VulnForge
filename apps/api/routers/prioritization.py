"""
VulnForge Smart Prioritization Engine ("What Should I Fix First?")
Calculates algorithmic risk prioritization with human-readable rationales and actionable developer advice.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from apps.api.core.database import get_db
from apps.api.core.models import User, Finding, Project, Asset
from apps.api.core.security import get_current_user, verify_project_access
from packages.schemas.models import (
    FindingResponse,
    PrioritizedFindingItem,
    PrioritizationResponse,
)
from packages.shared.constants import Severity, FindingStatus, AssetCriticality

router = APIRouter(prefix="/api", tags=["Prioritization"])


@router.get("/projects/{project_id}/findings/prioritized", response_model=PrioritizationResponse)
async def get_prioritized_findings(
    project_id: str,
    limit: int = Query(5, ge=1, le=20),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    project, _ = await verify_project_access(project_id, user, db)

    # Fetch open/in_progress findings
    f_res = await db.execute(
        select(Finding).where(
            Finding.project_id == project_id,
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS])
        )
    )
    findings = f_res.scalars().all()

    # Also load asset criticality cache
    ast_res = await db.execute(select(Asset).where(Asset.project_id == project_id))
    assets = {a.target: a for a in ast_res.scalars().all()}

    scored_items = []
    for f in findings:
        asset = assets.get(f.asset_target)
        asset_crit = asset.criticality if asset else AssetCriticality.HIGH

        # Severity Base
        sev_base = {
            Severity.CRITICAL: 100.0,
            Severity.HIGH: 75.0,
            Severity.MEDIUM: 45.0,
            Severity.LOW: 20.0,
            Severity.INFORMATIONAL: 5.0,
        }.get(f.severity, 30.0)

        # Asset Multiplier
        crit_multiplier = {
            AssetCriticality.CRITICAL: 1.4,
            AssetCriticality.HIGH: 1.2,
            AssetCriticality.MEDIUM: 1.0,
            AssetCriticality.LOW: 0.8,
        }.get(asset_crit, 1.0)

        # CVSS Factor
        cvss_factor = (f.cvss_score / 10.0) * 20.0

        # Confidence Multiplier
        conf_factor = 1.0 if f.confidence.value == "Confirmed" else 0.95 if f.confidence.value == "High" else 0.8

        total_weight = (sev_base + cvss_factor) * crit_multiplier * conf_factor

        # Determine Urgency Label
        if total_weight >= 120 or f.severity == Severity.CRITICAL:
            urgency = "IMMEDIATE_ACTION"
        elif total_weight >= 85 or f.severity == Severity.HIGH:
            urgency = "HIGH_PRIORITY"
        elif total_weight >= 50:
            urgency = "SCHEDULED_REMEDIATION"
        else:
            urgency = "LOW_RISK_BASELINE"

        # Generate Human-Readable Rationale
        rationale_parts = []
        if f.severity in [Severity.CRITICAL, Severity.HIGH]:
            rationale_parts.append(f"{f.severity.value} technical vulnerability")
        if asset_crit in [AssetCriticality.CRITICAL, AssetCriticality.HIGH]:
            rationale_parts.append(f"affects Tier-1 asset ({f.asset_target})")
        if f.cvss_score >= 7.0:
            rationale_parts.append(f"high industry exploitability (CVSS {f.cvss_score})")
        if f.endpoint:
            rationale_parts.append(f"directly reachable at `{f.endpoint}`")

        rationale = f"Priority calculated because this {' and '.join(rationale_parts)}." if rationale_parts else "Standard remediation item based on perimeter exposure."

        rec_action = f"Apply developer fix: {f.remediation[:120]}..." if len(f.remediation) > 120 else f.remediation

        scored_items.append({
            "finding": FindingResponse.model_validate(f),
            "weight": total_weight,
            "urgency": urgency,
            "rationale": rationale,
            "rec_action": rec_action,
        })

    # Sort descending by priority weight
    scored_items.sort(key=lambda x: x["weight"], reverse=True)

    top_items = [
        PrioritizedFindingItem(
            finding=item["finding"],
            priority_rank=idx + 1,
            urgency_level=item["urgency"],
            priority_rationale=item["rationale"],
            recommended_action=item["rec_action"]
        )
        for idx, item in enumerate(scored_items[:limit])
    ]

    crit_count = len([f for f in findings if f.severity == Severity.CRITICAL])
    high_count = len([f for f in findings if f.severity == Severity.HIGH])

    if crit_count > 0:
        advice = f"Focus engineering triage entirely on the {crit_count} Critical vulnerabilities first. Resolving these will immediately mitigate ~60% of total perimeter risk."
    elif high_count > 0:
        advice = f"Perimeter has {high_count} High-priority issues. Assign developer remediation tasks and verify with automated re-scans."
    else:
        advice = "No Critical or High vulnerabilities recorded. Perimeter baseline is solid. Proceed with scheduled weekly hygiene audits."

    return PrioritizationResponse(
        project_id=project_id,
        total_findings=len(findings),
        top_priority_items=top_items,
        executive_advice=advice
    )
