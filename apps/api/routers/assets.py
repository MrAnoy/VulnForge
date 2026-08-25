"""
VulnForge Asset Management Router
Enforces Multi-Tenant Isolation and SSRF Pre-flight Validation.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from apps.api.core.database import get_db
from apps.api.core.models import User, Asset, Project, ScopeRule
from apps.api.core.security import (
    get_current_user,
    verify_project_access,
    verify_asset_access,
)
from packages.schemas.models import AssetCreate, AssetResponse
from packages.security.ssrf_guard import SSRFGuard
from packages.shared.constants import ScopeStatus, Role

router = APIRouter(prefix="/api", tags=["Assets"])


@router.get("/projects/{project_id}/assets", response_model=List[AssetResponse])
async def list_assets(
    project_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_project_access(project_id, user, db)
    result = await db.execute(select(Asset).where(Asset.project_id == project_id))
    return [AssetResponse.model_validate(a) for a in result.scalars().all()]


@router.post("/projects/{project_id}/assets", response_model=AssetResponse)
async def create_asset(
    project_id: str,
    asset_in: AssetCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    project, _ = await verify_project_access(
        project_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )

    host, port, proto = SSRFGuard.normalize_target(asset_in.target)

    asset = Asset(
        project_id=project_id,
        target=asset_in.target,
        asset_type=asset_in.asset_type,
        criticality=asset_in.criticality,
        environment=asset_in.environment,
        description=asset_in.description,
        tags=asset_in.tags,
        hostname=host,
        port=port,
        protocol=proto.upper(),
        scope_status=ScopeStatus.IN_SCOPE,
        risk_score=0.0
    )
    db.add(asset)
    
    # Also update project ScopeRule allowed_targets if not present
    scope_res = await db.execute(select(ScopeRule).where(ScopeRule.project_id == project_id))
    scope_rule = scope_res.scalar_one_or_none()
    if scope_rule:
        allowed = list(scope_rule.allowed_targets or [])
        if asset_in.target not in allowed:
            allowed.append(asset_in.target)
            scope_rule.allowed_targets = allowed

    await db.commit()
    await db.refresh(asset)
    return AssetResponse.model_validate(asset)


@router.delete("/assets/{asset_id}")
async def delete_asset(
    asset_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    asset, _, _ = await verify_asset_access(
        asset_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )
    await db.delete(asset)
    await db.commit()
    return {"success": True, "message": "Asset deleted successfully"}
