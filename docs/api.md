# VulnForge REST API Reference

The interactive Swagger/OpenAPI documentation is available at `http://localhost:8000/docs`.

## Key Endpoints

### Authentication
- `POST /api/auth/register`: Register user and create default workspace.
- `POST /api/auth/login`: Authenticate and receive JWT token.
- `GET /api/auth/me`: Get current user context.

### Projects & Assets
- `GET /api/organizations/{org_id}/projects`: List organization projects.
- `POST /api/organizations/{org_id}/projects`: Create security project.
- `GET /api/projects/{id}/assets`: List assets in project.
- `POST /api/projects/{id}/assets`: Register target asset in scope.

### Scope & Authorization
- `GET /api/projects/{id}/scope`: Get scope rules.
- `PUT /api/projects/{id}/scope`: Update scope rules.
- `POST /api/scope/validate`: Pre-flight scope check.
- `POST /api/scope/confirm-authorization`: Record authorized assessment consent.

### Assessments & Scans
- `GET /api/projects/{id}/assessments`: List scan history.
- `POST /api/assessments`: Launch new assessment.
- `GET /api/assessments/{id}`: Get assessment details.
- `POST /api/assessments/{id}/cancel`: Trigger emergency kill switch.
- `GET /api/assessments/{id}/stream`: Server-Sent Events (SSE) live log stream.

### Findings & Remediation
- `GET /api/projects/{id}/findings`: List findings with filters (`severity`, `status`, `scanner`, `search`).
- `GET /api/findings/{id}`: Get finding details.
- `PATCH /api/findings/{id}/status`: Update triage status with audit reason.
- `GET /api/projects/{id}/remediation`: List remediation tasks.
- `POST /api/remediation`: Create remediation task.

### Reports & Deliverables
- `POST /api/reports/generate`: Generate Executive, Technical, or Developer report in PDF/HTML/JSON/CSV.
- `GET /api/reports/{id}/download`: Download generated report file.

### AI Copilot & System Diagnostics
- `POST /api/copilot/chat`: Contextual security assistant chat.
- `POST /api/copilot/explain-finding`: Generate vulnerability fix guide.
- `GET /api/system/scanners`: Scanner subsystem health.
