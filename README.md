# 🛡️ VulnForge

**Production-Grade Automated VAPT & Security Assessment Platform**

VulnForge is an authorized security assessment and vulnerability automation platform designed for security engineering teams, MSSPs, consultants, and enterprise DevSecOps. It unifies target reconnaissance, scoped vulnerability assessment, cross-scanner finding correlation, transparent risk scoring, AI-assisted triage, remediation tracking, and boardroom-ready deliverable reporting.

---

## 🌟 Key Capabilities

1. **Four Adaptive Experience View Modes**
   - **Beginner Mode**: Guided, jargon-free workflows with plain-English vulnerability summaries and step-by-step fix recommendations.
   - **Professional Mode**: Deep scanner telemetry, raw HTTP Request/Response evidence snippets, CVSS v3.1 vectors, CWE/OWASP taxonomy, and custom rate limits.
   - **Executive Mode**: Board-level security posture scores, top 5 risk drivers, and compliance SLA tracking.
   - **Developer Mode**: Actionable code fixes, affected endpoints, and instant local verification triggers.

2. **Smart Prioritization Engine ("What Should I Fix First?")**
   - Algorithmic ranking incorporating Severity, Asset Criticality, Internet Exposure, CVSS, and Scanner Confidence with human-understandable rationales.

3. **Assessment Comparison & Delta Engine**
   - Interactive checkpoint comparison (`/assessments/compare`) showing Posture Score progression, Resolved Vulnerabilities, and New Findings.

4. **Continuous Scheduled Audits**
   - Automated recurring scans (`Daily`, `Weekly`, `Monthly`) with pre-flight scope & authorization re-verification.

5. **Enterprise White-Label Deliverables**
   - Customizable branding (Company Name, Assessor, Client Organization, Classification Badges, Custom Accent Colors) across HTML, PDF, JSON, and CSV exports.

6. **Pluggable Scanner Subsystems & Observability**
   - **Reconnaissance Engine**: DNS records, TLS certificate validity & SANs, HTTP headers, robots.txt, security.txt.
   - **Custom Web Security Engine**: Native async checks for HSTS, CSP, X-Frame-Options, Cookie flags, CORS reflection, sensitive exposures (`/.git/HEAD`, `/.env`, `/web.config`), and HTTP TRACE.
   - **Nmap Adapter**: Safe pre-defined port & service detection.
   - **Nuclei Adapter**: Controlled template execution with tag filtering.
   - **OWASP ZAP Adapter**: Web application spidering and passive alerts.

7. **Strict Scope & SSRF Boundary Engine**
   - Mandatory authorization confirmation gate with immutable audit logging.
   - Comprehensive SSRF guard blocking RFC 1918 private IPs, loopback, and cloud metadata targets by default.
   - CIDR, wildcard (`*.domain.com`), and path allowlists/denylists.

---

## 🚀 Quickstart

### 1. Setup Backend
```bash
# Create and activate Python virtual environment
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Seed realistic demo data
python scripts/seed_demo.py

# Start FastAPI API Gateway
uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Setup Frontend
```bash
cd apps/web
npm install
npm run dev
```

Visit **[http://localhost:3000](http://localhost:3000)** (or **[http://localhost:3000/landing](http://localhost:3000/landing)** for the public product landing page).

### 3. Demo Credentials
- **Owner / Admin**: `admin@vulnforge.sec` / `VulnForgeDemo2026!`
- **Security Analyst**: `analyst@vulnforge.sec` / `VulnForgeDemo2026!`
- **Viewer / Auditor**: `viewer@vulnforge.sec` / `VulnForgeDemo2026!`

---

## 🐳 Docker Deployment

```bash
# Start full platform stack (PostgreSQL, Redis, API, Next.js Web, Nginx)
docker-compose up -d --build

# Start authorized local testing lab (OWASP Juice Shop & DVWA)
docker-compose -f docker-compose.lab.yml up -d
```

---

## 🧪 Testing

```bash
# Run Unit, Security, and Integration test suite (24 tests)
pytest tests/ -v --tb=short

# Run Frontend production typecheck & build (17 routes)
cd apps/web && npm run build
```

---

## 📄 License
This project is licensed under the MIT License — see the [LICENSE](file:///d:/github/VAPT/VAPT/LICENSE) file for details.
