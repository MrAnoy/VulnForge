# VulnForge Platform Architecture

## 1. System Overview

VulnForge is designed with a decoupled, asynchronous, multi-tenant architecture designed to scale across enterprise security workflows.

```
+-----------------------------------------------------------------------------------+
|                              VULNFORGE FRONTEND                                   |
|   Next.js 14 (App Router) + Tailwind CSS + Lucide + Recharts + Dark-first UI      |
|   - Dashboard (Security Score, Risk Trends, Exposure Matrix)                      |
|   - Scope & Authorization Wizard                                                  |
|   - Live Scan Monitor (SSE streaming logs)                                        |
|   - Finding Detail & Evidence Viewer                                              |
|   - AI Security Copilot (Drawer & Chat)                                           |
|   - Remediation Kanban / Table                                                    |
|   - Executive & Technical Report Generator                                        |
+------------------------------------------+----------------------------------------+
                                           | HTTPS / JSON API / SSE
+------------------------------------------v----------------------------------------+
|                               FASTAPI BACKEND (apps/api)                          |
|   - Auth & RBAC (Owner, Admin, Security Analyst, Viewer) + JWT + API Keys         |
|   - Organization Multi-Tenancy Isolation                                          |
|   - Project & Asset Management                                                    |
|   - Scope Engine (SSRF Guard, CIDR, Allowlist/Denylist, Authorization Gate)       |
|   - Audit Logging & Rate Limiting                                                 |
|   - AI Provider Abstraction (Gemini, OpenAI, Local, Mock)                         |
+------------------------------------------+----------------------------------------+
                                           | Task Dispatcher
+------------------------------------------v----------------------------------------+
|                    WORKER & SCANNER ORCHESTRATOR (workers/)                       |
|   - Recon Worker (DNS, TLS/Certificates, Headers, Tech Stack, Robots)             |
|   - Network Scanner Worker (Nmap Adapter with safe pre-defined profiles)          |
|   - Web Scanner Worker (Nuclei, ZAP Adapters & Custom Python Web Checks)          |
|   - Finding Processor (Normalization, CWE/CVSS mapping, Evidence sanitizer)      |
|   - Correlation & Deduplication Engine (Cross-scanner fingerprint matching)       |
|   - Risk Engine (Severity + CVSS + Criticality + Exposure + Confidence)           |
|   - Reporter Worker (HTML, Markdown, PDF, CSV, JSON deliverables)                 |
+-----------------------------------------------------------------------------------+
```

## 2. Core Modules

### `packages/security`
- **SSRF Guard**: Resolves DNS, checks RFC 1918 / Loopback / Cloud metadata IP ranges, and blocks non-authorized targets.
- **Command Safety**: Enforces strictly argument-array based subprocess execution (`shell=False`) to make command injection impossible.
- **Sanitizer**: Scrubs API keys, passwords, bearer tokens, and sensitive HTTP headers before database persistence and report generation.
- **Crypto**: Passwords hashed with bcrypt; signed HS256 JWT tokens for session auth; SHA-256 for API keys.

### `packages/scanner`
- **Abstract Adapter Interface**: Standard lifecycle (`validate`, `prepare`, `execute`, `parse`, `normalize`, `cleanup`).
- **Recon Adapter**: DNS records (A, AAAA, MX, TXT, NS, CNAME), TLS certificate dates/SANs, HTTP headers, robots.txt, security.txt.
- **Custom Web Adapter**: Native Python async security checks (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Cookies, CORS reflection, sensitive files `/.git/HEAD`, `/.env`, HTTP TRACE).
- **Nmap Adapter**: Safe pre-defined profile executor parsing XML results.
- **Nuclei Adapter**: Controlled template executor with approved tags and rate limits.
- **ZAP Adapter**: OWASP ZAP API integration.

### `apps/api/services`
- **Scope Service**: Target normalization, allowlist/denylist scope verification.
- **Finding Service**: Semantic topic extraction, cross-scanner deduplication, and evidence merging.
- **Risk Engine**: Transparent Platform Risk Score (0-100) and Project Security Posture Score (0-100).
- **AI Service**: Multi-provider Copilot (Mock, OpenAI, Gemini) grounded in evidence.
- **Report Service**: Deliverable rendering (HTML, PDF, JSON, CSV, Markdown).
- **Scan Orchestrator**: 8-phase state machine manager with real-time SSE log broadcasting.
