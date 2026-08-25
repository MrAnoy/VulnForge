"""
VulnForge Immutable Audit Logs Router
Enforces Multi-Tenant Access Control.
"""
from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from apps.api.core.database import get_db
from apps.api.core.models import User, AuditLog
from apps.api.core.security import get_current_user, verify_org_access
from packages.shared.constants import Role

router = APIRouter(prefix="/api", tags=["Audit Logs"])


@router.get("/organizations/{org_id}/audit-logs")
async def list_audit_logs(
    org_id: str,
    limit: int = 100,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_org_access(org_id, user, db, allowed_roles=[Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST, Role.VIEWER])
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.organization_id == org_id)
        .order_by(desc(AuditLog.timestamp))
        .limit(limit)
    )
    logs = result.scalars().all()
    return [
        {
            "id": l.id,
            "user_id": l.user_id,
            "user_email": l.user_email,
            "action": l.action,
            "target_resource": l.target_resource,
            "details": l.details,
            "ip_address": l.ip_address,
            "timestamp": l.timestamp.isoformat()
        }
        for l in logs
    ]
