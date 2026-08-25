"""
Integration Tests: Full End-to-End VAPT Platform Lifecycle
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
async def test_full_vapt_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        unique_email = f"tester_{uuid.uuid4().hex[:8]}@vulnforge.io"
        
        # 1. Register User
        reg_resp = await client.post(
            "/api/auth/register",
            json={
                "email": unique_email,
                "password": "SecurePassword123!",
                "full_name": "Integration Tester"
            }
        )
        assert reg_resp.status_code == 200, reg_resp.text
        auth_data = reg_resp.json()
        token = auth_data["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Get Organizations
        org_resp = await client.get("/api/organizations", headers=headers)
        assert org_resp.status_code == 200
        orgs = org_resp.json()
        assert len(orgs) > 0
        org_id = orgs[0]["id"]

        # 3. Create Project
        proj_resp = await client.post(
            f"/api/organizations/{org_id}/projects",
            headers=headers,
            json={
                "name": "Integration Test Banking App",
                "description": "Authorized integration test project",
                "environment": "Production",
                "tags": ["Integration", "Test"]
            }
        )
        assert proj_resp.status_code == 200
        project = proj_resp.json()
        project_id = project["id"]

        # 4. Add Asset
        asset_resp = await client.post(
            f"/api/projects/{project_id}/assets",
            headers=headers,
            json={
                "target": "http://127.0.0.1:8000/api/health",
                "asset_type": "API_ENDPOINT",
                "criticality": "High",
                "environment": "Production",
                "description": "Health check endpoint"
            }
        )
        assert asset_resp.status_code == 200
        asset = asset_resp.json()
        assert asset["hostname"] == "127.0.0.1"

        # 5. Confirm Authorization Gate
        auth_confirm_resp = await client.post(
            "/api/scope/confirm-authorization",
            headers=headers,
            json={
                "project_id": project_id,
                "authorized_by": "Integration Tester Lead",
                "authorization_statement": "Authorized internal assessment of test target.",
                "target_scope": ["http://127.0.0.1:8000/api/health"],
                "confirmed": True
            }
        )
        assert auth_confirm_resp.status_code == 200

        # 6. Launch Assessment
        assess_resp = await client.post(
            "/api/assessments",
            headers=headers,
            json={
                "project_id": project_id,
                "name": "Automated Quick VAPT",
                "profile": "QUICK_SCAN",
                "target_assets": ["http://127.0.0.1:8000/api/health"],
                "authorization_confirmed": True
            }
        )
        assert assess_resp.status_code == 200
        assessment = assess_resp.json()
        assessment_id = assessment["id"]

        # 7. Query Assessment Logs
        logs_resp = await client.get(f"/api/assessments/{assessment_id}/logs", headers=headers)
        assert logs_resp.status_code == 200

        # 8. Query Copilot Chat
        copilot_resp = await client.post(
            "/api/copilot/chat",
            headers=headers,
            json={
                "project_id": project_id,
                "message": "What are the top security issues for this project?"
            }
        )
        assert copilot_resp.status_code == 200
        copilot_data = copilot_resp.json()
        assert "answer" in copilot_data

        # 9. Generate Report
        rep_resp = await client.post(
            "/api/reports/generate",
            headers=headers,
            json={
                "assessment_id": assessment_id,
                "report_type": "EXECUTIVE",
                "report_format": "HTML",
                "title": "Integration Test Executive Deliverable"
            }
        )
        assert rep_resp.status_code == 200
        report = rep_resp.json()
        assert report["download_url"] is not None

        # 10. Audit Logs
        audit_resp = await client.get(f"/api/organizations/{org_id}/audit-logs", headers=headers)
        assert audit_resp.status_code == 200
        logs = audit_resp.json()
        assert len(logs) >= 1
