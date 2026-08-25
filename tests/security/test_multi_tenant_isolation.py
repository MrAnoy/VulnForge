"""
Security Tests: Multi-Tenant Isolation & IDOR Prevention
Verifies that User A in Org A cannot read, modify, or delete resources in Org B.
"""
import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from apps.api.main import app
from apps.api.core.database import init_db


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    await init_db()


@pytest.mark.asyncio
async def test_cross_tenant_isolation_idor():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register User A (Org A)
        email_a = f"user_a_{uuid.uuid4().hex[:6]}@vulnforge.io"
        reg_a = await client.post(
            "/api/auth/register",
            json={"email": email_a, "password": "Password123!", "full_name": "User A"}
        )
        assert reg_a.status_code == 200
        token_a = reg_a.json()["access_token"]
        headers_a = {"Authorization": f"Bearer {token_a}"}

        # 2. Register User B (Org B)
        email_b = f"user_b_{uuid.uuid4().hex[:6]}@vulnforge.io"
        reg_b = await client.post(
            "/api/auth/register",
            json={"email": email_b, "password": "Password123!", "full_name": "User B"}
        )
        assert reg_b.status_code == 200
        token_b = reg_b.json()["access_token"]
        headers_b = {"Authorization": f"Bearer {token_b}"}

        # Get Org A and Org B
        orgs_a = (await client.get("/api/organizations", headers=headers_a)).json()
        orgs_b = (await client.get("/api/organizations", headers=headers_b)).json()
        org_id_a = orgs_a[0]["id"]
        org_id_b = orgs_b[0]["id"]

        # Create Project in Org A
        proj_a = (await client.post(
            f"/api/organizations/{org_id_a}/projects",
            headers=headers_a,
            json={"name": "Org A Secret Project", "environment": "Production"}
        )).json()
        proj_id_a = proj_a["id"]

        # Create Asset in Org A
        asset_a = (await client.post(
            f"/api/projects/{proj_id_a}/assets",
            headers=headers_a,
            json={"target": "https://orga.example.com", "asset_type": "URL", "criticality": "High"}
        )).json()
        asset_id_a = asset_a["id"]

        # 3. ATTEMPT IDOR BY USER B ON ORG A'S RESOURCES:

        # Test A: User B lists Org A projects -> MUST FAIL (403)
        idor_proj_list = await client.get(f"/api/organizations/{org_id_a}/projects", headers=headers_b)
        assert idor_proj_list.status_code in [403, 404]

        # Test B: User B gets Org A project directly -> MUST FAIL (403)
        idor_proj_get = await client.get(f"/api/projects/{proj_id_a}", headers=headers_b)
        assert idor_proj_get.status_code in [403, 404]

        # Test C: User B deletes Org A project -> MUST FAIL (403)
        idor_proj_del = await client.delete(f"/api/projects/{proj_id_a}", headers=headers_b)
        assert idor_proj_del.status_code in [403, 404]

        # Test D: User B lists Org A assets -> MUST FAIL (403)
        idor_asset_list = await client.get(f"/api/projects/{proj_id_a}/assets", headers=headers_b)
        assert idor_asset_list.status_code in [403, 404]

        # Test E: User B deletes Org A asset -> MUST FAIL (403)
        idor_asset_del = await client.delete(f"/api/assets/{asset_id_a}", headers=headers_b)
        assert idor_asset_del.status_code in [403, 404]

        # Test F: User B lists Org A audit logs -> MUST FAIL (403)
        idor_audit = await client.get(f"/api/organizations/{org_id_a}/audit-logs", headers=headers_b)
        assert idor_audit.status_code in [403, 404]
