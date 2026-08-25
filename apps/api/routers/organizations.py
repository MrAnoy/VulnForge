"""
VulnForge Organizations & Tenancy Router
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from apps.api.core.database import get_db
from apps.api.core.models import User, Organization, OrganizationMember, Project
from apps.api.core.security import get_current_user
from packages.schemas.models import (
    OrganizationCreate,
    OrganizationResponse,
    MemberInvite,
    MemberResponse,
)
from packages.shared.constants import Role

router = APIRouter(prefix="/api/organizations", tags=["Organizations"])


@router.get("", response_model=List[OrganizationResponse])
async def list_user_organizations(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    query = (
        select(Organization)
        .join(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where(OrganizationMember.user_id == user.id)
    )
    result = await db.execute(query)
    orgs = result.scalars().all()

    resp = []
    for org in orgs:
        # Count members and projects
        mem_count = await db.scalar(
            select(func.count()).select_from(OrganizationMember).where(OrganizationMember.organization_id == org.id)
        )
        proj_count = await db.scalar(
            select(func.count()).select_from(Project).where(Project.organization_id == org.id)
        )
        resp.append(OrganizationResponse(
            id=org.id,
            name=org.name,
            slug=org.slug,
            description=org.description,
            owner_id=org.owner_id,
            created_at=org.created_at,
            member_count=mem_count or 1,
            project_count=proj_count or 0
        ))
    return resp


@router.post("", response_model=OrganizationResponse)
async def create_organization(
    org_in: OrganizationCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Ensure unique slug
    res = await db.execute(select(Organization).where(Organization.slug == org_in.slug))
    if res.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Organization slug is already in use.")

    org = Organization(
        name=org_in.name,
        slug=org_in.slug,
        description=org_in.description,
        owner_id=user.id
    )
    db.add(org)
    await db.flush()

    member = OrganizationMember(
        organization_id=org.id,
        user_id=user.id,
        role=Role.OWNER
    )
    db.add(member)
    await db.commit()

    return OrganizationResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        description=org.description,
        owner_id=org.owner_id,
        created_at=org.created_at,
        member_count=1,
        project_count=0
    )


@router.get("/{org_id}/members", response_model=List[MemberResponse])
async def list_members(
    org_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    query = (
        select(OrganizationMember, User)
        .join(User, User.id == OrganizationMember.user_id)
        .where(OrganizationMember.organization_id == org_id)
    )
    result = await db.execute(query)
    rows = result.all()

    return [
        MemberResponse(
            id=m.id,
            organization_id=m.organization_id,
            user_id=u.id,
            user_email=u.email,
            user_name=u.full_name,
            role=m.role,
            joined_at=m.joined_at
        )
        for m, u in rows
    ]
