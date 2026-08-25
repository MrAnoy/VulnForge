"""
VulnForge Projects Management Router
Enforces Organization Tenant Boundaries and RBAC.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from apps.api.core.database import get_db
from apps.api.core.models import User, Project, Asset, Finding, ScopeRule
from apps.api.core.security import get_current_user, verify_org_access, verify_project_access
from packages.schemas.models import ProjectCreate, ProjectResponse
from packages.shared.constants import Role

router = APIRouter(prefix="/api", tags=["Projects"])


@router.get("/organizations/{org_id}/projects", response_model=List[ProjectResponse])
async def list_projects(
    org_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_org_access(org_id, user, db)
    result = await db.execute(select(Project).where(Project.organization_id == org_id))
    projects = result.scalars().all()

    resp = []
    for p in projects:
        asset_count = await db.scalar(
            select(func.count()).select_from(Asset).where(Asset.project_id == p.id)
        )
        finding_count = await db.scalar(
            select(func.count()).select_from(Finding).where(Finding.project_id == p.id)
        )
        resp.append(ProjectResponse(
            id=p.id,
            organization_id=p.organization_id,
            owner_id=p.owner_id,
            name=p.name,
            description=p.description,
            client_name=p.client_name,
            environment=p.environment,
            tags=p.tags or [],
            risk_score=p.risk_score or 0.0,
            asset_count=asset_count or 0,
            finding_count=finding_count or 0,
            created_at=p.created_at,
            updated_at=p.updated_at
        ))
    return resp


@router.post("/organizations/{org_id}/projects", response_model=ProjectResponse)
async def create_project(
    org_id: str,
    proj_in: ProjectCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_org_access(org_id, user, db, allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST])

    project = Project(
        organization_id=org_id,
        owner_id=user.id,
        name=proj_in.name,
        description=proj_in.description,
        client_name=proj_in.client_name,
        environment=proj_in.environment,
        tags=proj_in.tags,
        risk_score=0.0
    )
    db.add(project)
    await db.flush()

    # Initialize default scope rule for this project
    default_scope = ScopeRule(
        project_id=project.id,
        allowed_targets=[],
        excluded_targets=[],
        allow_local_lab=True
    )
    db.add(default_scope)
    await db.commit()

    return ProjectResponse(
        id=project.id,
        organization_id=project.organization_id,
        owner_id=project.owner_id,
        name=project.name,
        description=project.description,
        client_name=project.client_name,
        environment=project.environment,
        tags=project.tags or [],
        risk_score=0.0,
        asset_count=0,
        finding_count=0,
        created_at=project.created_at
    )


@router.get("/projects/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    p, _ = await verify_project_access(project_id, user, db)

    asset_count = await db.scalar(
        select(func.count()).select_from(Asset).where(Asset.project_id == p.id)
    )
    finding_count = await db.scalar(
        select(func.count()).select_from(Finding).where(Finding.project_id == p.id)
    )

    return ProjectResponse(
        id=p.id,
        organization_id=p.organization_id,
        owner_id=p.owner_id,
        name=p.name,
        description=p.description,
        client_name=p.client_name,
        environment=p.environment,
        tags=p.tags or [],
        risk_score=p.risk_score or 0.0,
        asset_count=asset_count or 0,
        finding_count=finding_count or 0,
        created_at=p.created_at,
        updated_at=p.updated_at
    )


@router.delete("/projects/{project_id}")
async def delete_project(
    project_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    p, _ = await verify_project_access(project_id, user, db, allowed_roles=[Role.OWNER, Role.ADMIN])
    await db.delete(p)
    await db.commit()
    return {"success": True, "message": "Project deleted successfully"}
