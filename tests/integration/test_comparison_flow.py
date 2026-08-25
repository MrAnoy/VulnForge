"""
Integration Tests: Assessment Comparison & Schedules Lifecycle
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
async def test_assessment_comparison_and_schedules():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register User
        email = f"lead_auditor_{uuid.uuid4().hex[:6]}@vulnforge.io"
        reg = await client.post(
            "/api/auth/register",
            json={"email": email, "password": "Password123!", "full_name": "Lead Auditor"}
        )
        assert reg.status_code == 200
        token = reg.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Get Org & Create Project
        orgs = (await client.get("/api/organizations", headers=headers)).json()
        org_id = orgs[0]["id"]

        proj = (await client.post(
            f"/api/organizations/{org_id}/projects",
            headers=headers,
            json={"name": "Comparison Test Project", "environment": "Staging"}
        )).json()
        proj_id = proj["id"]

        # 3. Add Asset
        asset = (await client.post(
            f"/api/projects/{proj_id}/assets",
            headers=headers,
            json={"target": "http://127.0.0.1:3001", "asset_type": "URL", "criticality": "Critical"}
        )).json()

        # 4. Launch Baseline Assessment (Assessment 1)
        assess1 = (await client.post(
            "/api/assessments",
            headers=headers,
            json={
                "project_id": proj_id,
                "name": "Sprint 1 Assessment",
                "profile": "STANDARD_VAPT",
                "target_assets": ["http://127.0.0.1:3001"],
                "authorization_confirmed": True
            }
        )).json()
        assess1_id = assess1["id"]

        # 5. Launch Target Assessment (Assessment 2)
        assess2 = (await client.post(
            "/api/assessments",
            headers=headers,
            json={
                "project_id": proj_id,
                "name": "Sprint 2 Verification Assessment",
                "profile": "STANDARD_VAPT",
                "target_assets": ["http://127.0.0.1:3001"],
                "authorization_confirmed": True
            }
        )).json()
        assess2_id = assess2["id"]

        # 6. Compare Assessments
        compare_res = await client.get(
            f"/api/projects/{proj_id}/assessments/compare?base_id={assess1_id}&target_id={assess2_id}",
            headers=headers
        )
        assert compare_res.status_code == 200
        comp_data = compare_res.json()
        assert "score_delta" in comp_data
        assert "summary_verdict" in comp_data

        # 7. Create Scheduled Assessment
        sched_res = await client.post(
            f"/api/projects/{proj_id}/schedules",
            headers=headers,
            json={
                "project_id": proj_id,
                "name": "Weekly Continuous Audit",
                "frequency": "WEEKLY",
                "profile": "STANDARD_VAPT",
                "targets": ["http://127.0.0.1:3001"],
                "is_active": True
            }
        )
        assert sched_res.status_code == 200
        sched_data = sched_res.json()
        assert sched_data["frequency"] == "WEEKLY"
        sched_id = sched_data["id"]

        # 8. List & Delete Schedule
        scheds = (await client.get(f"/api/projects/{proj_id}/schedules", headers=headers)).json()
        assert len(scheds) >= 1

        del_res = await client.delete(f"/api/schedules/{sched_id}", headers=headers)
        assert del_res.status_code == 200

        # 9. Test Smart Prioritization
        prio_res = await client.get(f"/api/projects/{proj_id}/findings/prioritized", headers=headers)
        assert prio_res.status_code == 200
        prio_data = prio_res.json()
        assert "top_priority_items" in prio_data
        assert "executive_advice" in prio_data
