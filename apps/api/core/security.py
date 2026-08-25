"""
VulnForge Authentication & Authorization Dependencies
Enforces RBAC, Tenant Isolation, and IDOR Defense across all resources.
"""
import os
from typing import Optional, List, Tuple
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from apps.api.core.database import get_db
from apps.api.core.models import (
    User,
    Organization,
    OrganizationMember,
    Project,
    Asset,
    Assessment,
    Finding,
    Report,
    RemediationTask,
    ApiKey,
    Webhook,
)
from packages.security.crypto import decode_token, hash_api_key
from packages.shared.constants import Role

security_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Extract and validate the authenticated User via JWT Bearer or API Key."""
    if credentials:
        token = credentials.credentials
        payload = decode_token(token)
        if not payload or "sub" not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, malformed, or expired authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_id = payload["sub"]
        result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or account deactivated",
            )
        return user

    elif x_api_key:
        hashed = hash_api_key(x_api_key)
        result = await db.execute(select(ApiKey).where(ApiKey.hashed_key == hashed))
        api_key_obj = result.scalar_one_or_none()
        if not api_key_obj:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key provided",
            )
        # Find organization owner to act as user context
        org_res = await db.execute(select(Organization).where(Organization.id == api_key_obj.organization_id))
        org = org_res.scalar_one_or_none()
        if not org:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Organization not found")
        
        user_res = await db.execute(select(User).where(User.id == org.owner_id))
        user = user_res.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API Key owner not found")
        return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Please provide a Bearer token or X-API-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_user_org_membership(
    organization_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> OrganizationMember:
    """Verify that the current user belongs to the specified organization."""
    result = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == organization_id,
            OrganizationMember.user_id == user.id
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: You are not a member of this organization."
        )
    return membership


def require_roles(allowed_roles: List[Role]):
    """Enforce role-based access control (RBAC)."""
    async def role_checker(membership: OrganizationMember = Depends(get_user_org_membership)) -> OrganizationMember:
        if membership.role not in allowed_roles and membership.role != Role.OWNER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Action requires one of the following roles: {[r.value for r in allowed_roles]}"
            )
        return membership
    return role_checker


# ==================== Centralized IDOR & Multi-Tenancy Helpers ====================

async def verify_org_access(
    organization_id: str,
    user: User,
    db: AsyncSession,
    allowed_roles: Optional[List[Role]] = None
) -> Tuple[Organization, OrganizationMember]:
    """Verify organization exists and user is a member with required role."""
    org_res = await db.execute(select(Organization).where(Organization.id == organization_id))
    org = org_res.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    mem_res = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == organization_id,
            OrganizationMember.user_id == user.id
        )
    )
    membership = mem_res.scalar_one_or_none()
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: You are not a member of this organization."
        )

    if allowed_roles and membership.role not in allowed_roles and membership.role != Role.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Action requires one of the following roles: {[r.value for r in allowed_roles]}"
        )

    return org, membership


async def verify_project_access(
    project_id: str,
    user: User,
    db: AsyncSession,
    allowed_roles: Optional[List[Role]] = None
) -> Tuple[Project, OrganizationMember]:
    """Verify project exists and user belongs to the owning organization."""
    p_res = await db.execute(select(Project).where(Project.id == project_id))
    project = p_res.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    _, membership = await verify_org_access(project.organization_id, user, db, allowed_roles)
    return project, membership


async def verify_assessment_access(
    assessment_id: str,
    user: User,
    db: AsyncSession,
    allowed_roles: Optional[List[Role]] = None
) -> Tuple[Assessment, Project, OrganizationMember]:
    """Verify assessment exists and user has access to its project & organization."""
    a_res = await db.execute(select(Assessment).where(Assessment.id == assessment_id))
    assessment = a_res.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    project, membership = await verify_project_access(assessment.project_id, user, db, allowed_roles)
    return assessment, project, membership


async def verify_finding_access(
    finding_id: str,
    user: User,
    db: AsyncSession,
    allowed_roles: Optional[List[Role]] = None
) -> Tuple[Finding, Project, OrganizationMember]:
    """Verify finding exists and user has access to its project & organization."""
    f_res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = f_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    project, membership = await verify_project_access(finding.project_id, user, db, allowed_roles)
    return finding, project, membership


async def verify_report_access(
    report_id: str,
    user: User,
    db: AsyncSession,
    allowed_roles: Optional[List[Role]] = None
) -> Tuple[Report, Project, OrganizationMember]:
    """Verify report exists and user has access to its project & organization."""
    r_res = await db.execute(select(Report).where(Report.id == report_id))
    report = r_res.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    project, membership = await verify_project_access(report.project_id, user, db, allowed_roles)
    return report, project, membership


async def verify_asset_access(
    asset_id: str,
    user: User,
    db: AsyncSession,
    allowed_roles: Optional[List[Role]] = None
) -> Tuple[Asset, Project, OrganizationMember]:
    """Verify asset exists and user has access to its project & organization."""
    ast_res = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = ast_res.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    project, membership = await verify_project_access(asset.project_id, user, db, allowed_roles)
    return asset, project, membership


async def verify_task_access(
    task_id: str,
    user: User,
    db: AsyncSession,
    allowed_roles: Optional[List[Role]] = None
) -> Tuple[RemediationTask, Finding, Project, OrganizationMember]:
    """Verify remediation task exists and user has access to its finding and project."""
    t_res = await db.execute(select(RemediationTask).where(RemediationTask.id == task_id))
    task = t_res.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation task not found")

    finding, project, membership = await verify_finding_access(task.finding_id, user, db, allowed_roles)
    return task, finding, project, membership
