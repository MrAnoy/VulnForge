"""
VulnForge Scope & Target Authorization Router
Enforces Scope Allowlist Validation and Tenant Authorization Gates.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from apps.api.core.database import get_db
from apps.api.core.models import User, ScopeRule, Project, AuditLog
from apps.api.core.security import (
    get_current_user,
    verify_project_access,
)
from packages.schemas.models import (
    ScopeRule as ScopeRuleSchema,
    ScopeValidationRequest,
    ScopeValidationResult,
    AuthorizationConfirmation,
)
from apps.api.services.scope_service import ScopeService
from packages.shared.constants import Role

router = APIRouter(prefix="/api", tags=["Scope & Authorization"])


@router.get("/projects/{project_id}/scope", response_model=ScopeRuleSchema)
async def get_project_scope(
    project_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_project_access(project_id, user, db)

    res = await db.execute(select(ScopeRule).where(ScopeRule.project_id == project_id))
    rule = res.scalar_one_or_none()
    if not rule:
        return ScopeRuleSchema(
            allowed_targets=[],
            excluded_targets=[],
            allow_local_lab=True
        )
    return ScopeRuleSchema(
        allowed_targets=rule.allowed_targets or [],
        excluded_targets=rule.excluded_targets or [],
        allowed_ports=rule.allowed_ports or [],
        excluded_ports=rule.excluded_ports or [],
        allowed_paths=rule.allowed_paths or [],
        excluded_paths=rule.excluded_paths or [],
        rate_limit_rps=rule.rate_limit_rps or 20,
        max_concurrency=rule.max_concurrency or 5,
        scan_window_hours=rule.scan_window_hours or 4,
        allow_local_lab=rule.allow_local_lab
    )


@router.put("/projects/{project_id}/scope", response_model=ScopeRuleSchema)
async def update_project_scope(
    project_id: str,
    scope_in: ScopeRuleSchema,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_project_access(
        project_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )

    res = await db.execute(select(ScopeRule).where(ScopeRule.project_id == project_id))
    rule = res.scalar_one_or_none()
    if not rule:
        rule = ScopeRule(project_id=project_id)
        db.add(rule)

    rule.allowed_targets = scope_in.allowed_targets
    rule.excluded_targets = scope_in.excluded_targets
    rule.allowed_ports = scope_in.allowed_ports
    rule.excluded_ports = scope_in.excluded_ports
    rule.allowed_paths = scope_in.allowed_paths
    rule.excluded_paths = scope_in.excluded_paths
    rule.rate_limit_rps = scope_in.rate_limit_rps
    rule.max_concurrency = scope_in.max_concurrency
    rule.scan_window_hours = scope_in.scan_window_hours
    rule.allow_local_lab = scope_in.allow_local_lab

    await db.commit()
    return scope_in


@router.post("/scope/validate", response_model=List[ScopeValidationResult])
async def validate_scope(
    request: ScopeValidationRequest,
    user: User = Depends(get_current_user)
):
    results = []
    for t in request.targets:
        res = ScopeService.validate_target_scope(
            target=t,
            allowed_targets=request.allowed_targets,
            excluded_targets=request.excluded_targets,
            allow_local_lab=request.allow_local_lab
        )
        results.append(res)
    return results


@router.post("/scope/confirm-authorization")
async def confirm_authorization(
    confirmation: AuthorizationConfirmation,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not confirmation.confirmed:
        raise HTTPException(
            status_code=400,
            detail="Explicit authorization confirmation is required before proceeding."
        )

    # Fetch and verify project access
    proj, _ = await verify_project_access(
        confirmation.project_id, user, db,
        allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST]
    )

    # Record immutable audit log
    audit = AuditLog(
        organization_id=proj.organization_id,
        user_id=user.id,
        user_email=user.email,
        action="CONFIRM_TARGET_AUTHORIZATION",
        target_resource=confirmation.project_id,
        details={
            "authorized_by": confirmation.authorized_by,
            "statement": confirmation.authorization_statement,
            "targets": confirmation.target_scope,
            "timestamp": str(confirmation.confirmation_timestamp),
        }
    )
    db.add(audit)
    await db.commit()

    return {"success": True, "message": "Target authorization recorded and verified in immutable audit ledger."}
