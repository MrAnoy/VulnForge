# VulnForge Installation & Local Setup Guide

## Prerequisites

- **Python 3.11+**
- **Node.js 18+** & **npm**
- **Docker & Docker Compose** (Optional for containerized deployment & lab targets)
- Optional external tools: `nmap`, `nuclei` (auto-detected if present in PATH)

---

## 1. Local Development Setup (Quickstart)

### Step 1: Clone Repository & Create Python Virtual Environment
```bash
# Using uv or python venv:
uv venv .venv --python python3.12
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### Step 2: Seed Demo Database
```bash
python scripts/seed_demo.py
```
This initializes the database schemas and creates realistic demo organizations, projects, scoped assets, findings, and audit logs.

### Step 3: Install Frontend Dependencies
```bash
cd apps/web
npm install
cd ../..
```

### Step 4: Launch Applications

**Terminal 1 - FastAPI Backend:**
```bash
uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 - Next.js Frontend:**
```bash
cd apps/web
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 2. Default Demo Credentials

| Role | Email | Password | Access Level |
|---|---|---|---|
| **Owner / Admin** | `admin@vulnforge.sec` | `VulnForgeDemo2026!` | Full platform & user management |
| **Security Analyst** | `analyst@vulnforge.sec` | `VulnForgeDemo2026!` | Launch scans, triage findings, generate reports |
| **Viewer** | `viewer@vulnforge.sec` | `VulnForgeDemo2026!` | Read-only compliance & posture view |

---

## 3. Docker Compose Deployment

To run the full stack with PostgreSQL, Redis, API, Next.js Web, and Nginx:

```bash
docker-compose up -d --build
```

Access the platform at [http://localhost](http://localhost).

---

## 4. Local Authorized Testing Lab

To start intentionally vulnerable test targets (OWASP Juice Shop & DVWA) in Docker:

```bash
docker-compose -f docker-compose.lab.yml up -d
```

- **OWASP Juice Shop**: `http://localhost:3001`
- **DVWA**: `http://localhost:3002`

Add these targets to your project scope for safe, isolated testing!
