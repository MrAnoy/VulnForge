"""
VulnForge API Keys Management Router
Enforces Tenant Access Control and Role-Based Delegation.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from apps.api.core.database import get_db
from apps.api.core.models import User, ApiKey
from apps.api.core.security import get_current_user, verify_org_access
from packages.schemas.models import ApiKeyCreate, ApiKeyResponse
from packages.security.crypto import generate_api_key, hash_api_key
from packages.shared.constants import Role

router = APIRouter(prefix="/api", tags=["API Keys"])


@router.get("/organizations/{org_id}/api-keys", response_model=List[ApiKeyResponse])
async def list_api_keys(
    org_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_org_access(org_id, user, db, allowed_roles=[Role.OWNER, Role.ADMIN])
    result = await db.execute(select(ApiKey).where(ApiKey.organization_id == org_id))
    return [
        ApiKeyResponse(
            id=k.id,
            name=k.name,
            key_preview=k.key_preview,
            role=k.role,
            created_at=k.created_at,
            last_used=k.last_used
        )
        for k in result.scalars().all()
    ]


@router.post("/organizations/{org_id}/api-keys", response_model=ApiKeyResponse)
async def create_api_key(
    org_id: str,
    key_in: ApiKeyCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_org_access(org_id, user, db, allowed_roles=[Role.OWNER, Role.ADMIN])

    raw_key = generate_api_key()
    hashed = hash_api_key(raw_key)
    preview = f"{raw_key[:7]}...{raw_key[-4:]}"

    api_key = ApiKey(
        organization_id=org_id,
        name=key_in.name,
        hashed_key=hashed,
        key_preview=preview,
        role=key_in.role
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return ApiKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key_preview=preview,
        role=api_key.role,
        created_at=api_key.created_at,
        raw_key=raw_key  # Returned only once on initial creation
    )


@router.delete("/api-keys/{key_id}")
async def delete_api_key(
    key_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    res = await db.execute(select(ApiKey).where(ApiKey.id == key_id))
    k = res.scalar_one_or_none()
    if not k:
        raise HTTPException(status_code=404, detail="API key not found")

    await verify_org_access(k.organization_id, user, db, allowed_roles=[Role.OWNER, Role.ADMIN])
    await db.delete(k)
    await db.commit()
    return {"success": True, "message": "API key revoked"}
