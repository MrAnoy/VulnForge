# VulnForge Platform Architecture & System Design

**Document Version:** 2.0.0 (Production Architecture Reference)  
**Classification:** Technical Architecture Specification  

---

## 1. High-Level Architectural Topology

VulnForge follows a modern, decoupled monorepo architecture separating the **Next.js 14 Web Presentation Layer**, the **FastAPI Asynchronous Gateway**, the **Background Scanner Orchestration Engine**, and pluggable **Security Adapters**.

```
                           +---------------------------------+
                           |      Next.js 14 Frontend        |
                           | (4 View Modes: Beg/Pro/Exec/Dev)|
                           +----------------+----------------+
                                            |
                                  HTTP REST / SSE Stream
                                            |
                                            v
                           +----------------+----------------+
                           |     FastAPI Backend Gateway     |
                           |  (JWT Auth, RBAC, IDOR Guards)  |
                           +-------+----------------+--------+
                                   |                |
                +------------------+                +------------------+
                |                                                      |
                v                                                      v
  +-------------+-------------+                          +-------------+-------------+
  |    Database & Storage     |                          |   Task Queue & Engine     |
  |  - SQLite / PostgreSQL    |                          |  - Scan Orchestrator      |
  |  - Append-Only Audit Log  |                          |  - Redis Event Broker     |
  +---------------------------+                          +-------------+-------------+
                                                                       |
                                         +-----------------------------+-----------------------------+
                                         |                             |                             |
                                         v                             v                             v
                           +-------------+-------------+ +-------------+-------------+ +-------------+-------------+
                           |    Recon & OSINT Adapter  | |  Custom Web Engine        | | External Tool Adapters    |
                           |  - DNS, TLS SANs, Headers | |  - HSTS, CSP, CORS, Files | | - Nmap, Nuclei, ZAP       |
                           +---------------------------+ +---------------------------+ +---------------------------+
                                         |                             |                             |
                                         +-----------------------------+-----------------------------+
                                                                       |
                                                                       v
                                                         +-------------+-------------+
                                                         |  Normalization & Correlate|
                                                         |  - Severity Merging       |
                                                         |  - Secret Sanitizer       |
                                                         +-------------+-------------+
                                                                       |
                                                                       v
                                                         +-------------+-------------+
                                                         |  Risk Engine & AI Copilot |
                                                         |  - Contextual Math        |
                                                         |  - Delimiter Prompt Guard |
                                                         +-------------+-------------+
                                                                       |
                                                                       v
                                                         +-------------+-------------+
                                                         |  Report & Deliverables    |
                                                         |  - White-Label Engine     |
                                                         |  - HTML, PDF, JSON, CSV   |
                                                         +---------------------------+
```

---

## 2. Core Subsystems

### A. Presentation Layer (`apps/web`)
- **Next.js 14 App Router**: 17 compiled static and dynamic routes.
- **View Mode Context (`ViewModeProvider`)**: Tailors information density across `Beginner`, `Professional`, `Executive`, and `Developer` perspectives.
- **Real-Time Terminal Streaming**: Server-Sent Events (`EventSource`) consume live assessment phase progress, technical logs, and discovered assets.
- **Command Palette (`Ctrl+K`)**: Rapid navigation and action execution.

### B. Core API Gateway (`apps/api`)
- **FastAPI (Python 3.12)**: Asynchronous non-blocking endpoints.
- **Centralized Security Layer (`apps/api/core/security.py`)**: Strict tenant boundary validation (`verify_project_access`, `verify_assessment_access`, `verify_finding_access`, `verify_report_access`, `verify_asset_access`, `verify_task_access`).
- **Audit Logging Subsystem**: Immutable event trail recording actor, action, timestamp, IP, and payload metadata.

### C. Scope & Safety Engine (`packages/security` & `apps/api/services/scope_engine.py`)
- **SSRF Guard**: Pre-flight target DNS resolution with automated blocking of loopback (`127.0.0.0/8`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and AWS/GCP/Azure cloud metadata (`169.254.169.254`).
- **Authorization Gate**: Mandatory digital sign-off verified prior to scan initiation.
- **Command Safety**: Zero shell execution (`shell=False`); strict argument vectors with path resolution.

### D. Pluggable Scanner Subsystems (`packages/scanner`)
1. **`ReconAdapter`**: DNS resolution (A, AAAA, MX, TXT, NS, CNAME), TLS certificate expiry & SAN inspection, HTTP headers, robots.txt, security.txt.
2. **`CustomWebAdapter`**: Native asynchronous security tests for HSTS, CSP, X-Frame-Options, Cookie security flags, CORS origin reflection, and sensitive exposures (`/.git/HEAD`, `/.env`, `/web.config`, `/.DS_Store`, `/actuator/env`).
3. **`NmapAdapter`**: TCP port discovery and service versioning (`-sT -sV`) with strict XML parsing.
4. **`NucleiAdapter`**: Controlled template vulnerability scanning with tag filtering and rate limiting.
5. **`ZapAdapter`**: Web application spidering and passive alerts.

### E. Finding Deduplication & Correlation (`apps/api/services/finding_correlation.py`)
- Correlates findings across multiple scanners matching target, endpoint, and vulnerability classification.
- Retains highest severity, CVSS score, combined references, and sanitized technical evidence.

### F. Dual-Track Risk Engine (`apps/api/services/risk_engine.py`)
- **CVSS v3.1 Score (0.0 - 10.0)**: Industry standard exploitability and impact metric.
- **Platform Risk Score (0 - 100)**: Dynamic contextual score:
  $$\text{Risk} = (\text{Base Severity} + \text{CVSS Factor}) \times \text{Asset Criticality} \times \text{Exposure Multiplier} \times \text{Confidence}$$

### G. AI Security Copilot & Prompt Injection Isolation (`apps/api/services/ai_service.py`)
- Grounded strictly in project telemetry with zero hallucination.
- Untrusted scan outputs are isolated within `<UNTRUSTED_SECURITY_DATA>` delimiter blocks.

### H. Consulting Deliverable & White-Label Generator (`apps/api/services/report_service.py`)
- Produces **HTML** (with Jinja2 autoescaping), **PDF** (ReportLab), **JSON**, and **CSV** reports.
- Supports custom company name, assessor name, client name, classification labels, and accent colors.
