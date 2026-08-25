"""
VulnForge Immutable Audit Logger Service
"""
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from apps.api.core.models import AuditLog, User
from packages.shared.logging import logger


class AuditLogger:
    @staticmethod
    async def log_event(
        db: AsyncSession,
        organization_id: str,
        action: str,
        user: Optional[User] = None,
        target_resource: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None
    ) -> AuditLog:
        """Create an append-only immutable audit log record."""
        audit_entry = AuditLog(
            organization_id=organization_id,
            user_id=user.id if user else None,
            user_email=user.email if user else "SYSTEM",
            action=action,
            target_resource=target_resource,
            details=details or {},
            ip_address=ip_address
        )
        db.add(audit_entry)
        await db.commit()
        logger.info(f"Audit log recorded: org={organization_id} action={action} user={user.email if user else 'SYSTEM'}")
        return audit_entry
