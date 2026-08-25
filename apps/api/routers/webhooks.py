"""
VulnForge Webhooks & Event Integrations Router
Enforces SSRF Validation on Webhook Targets and Multi-Tenant Access Control.
"""
from typing import List
import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from apps.api.core.database import get_db
from apps.api.core.models import User, Webhook
from apps.api.core.security import get_current_user, verify_org_access
from packages.schemas.models import WebhookCreate, WebhookResponse
from packages.security.ssrf_guard import SSRFGuard, TargetValidationError
from packages.shared.constants import Role

router = APIRouter(prefix="/api", tags=["Webhooks"])


@router.get("/organizations/{org_id}/webhooks", response_model=List[WebhookResponse])
async def list_webhooks(
    org_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_org_access(org_id, user, db)
    result = await db.execute(select(Webhook).where(Webhook.organization_id == org_id))
    return [WebhookResponse.model_validate(w) for w in result.scalars().all()]


@router.post("/organizations/{org_id}/webhooks", response_model=WebhookResponse)
async def create_webhook(
    org_id: str,
    webhook_in: WebhookCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await verify_org_access(org_id, user, db, allowed_roles=[Role.OWNER, Role.ADMIN])

    # Validate webhook target URL against SSRF
    try:
        SSRFGuard.resolve_and_validate(webhook_in.url, allow_local_lab=False)
    except TargetValidationError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid webhook URL: {str(e)}"
        )

    webhook = Webhook(
        organization_id=org_id,
        url=webhook_in.url,
        events=webhook_in.events,
        secret=webhook_in.secret,
        is_active=True
    )
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)
    return WebhookResponse.model_validate(webhook)


@router.post("/webhooks/{webhook_id}/test")
async def test_webhook(
    webhook_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    res = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    webhook = res.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    await verify_org_access(webhook.organization_id, user, db, allowed_roles=[Role.OWNER, Role.ADMIN])

    # Re-validate target URL against SSRF before dispatch
    try:
        SSRFGuard.resolve_and_validate(webhook.url, allow_local_lab=False)
    except TargetValidationError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Webhook target failed SSRF security validation: {str(e)}"
        )

    payload = {
        "event": "assessment.completed",
        "organization_id": webhook.organization_id,
        "test": True,
        "message": "VulnForge test webhook delivery ping"
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(webhook.url, json=payload)
            return {
                "success": resp.status_code < 400,
                "status_code": resp.status_code,
                "message": f"Webhook returned status {resp.status_code}"
            }
    except Exception as e:
        return {
            "success": False,
            "status_code": 0,
            "error": str(e)
        }
