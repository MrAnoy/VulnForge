# VulnForge Security Model & Hardening Guide

## 1. Zero Shell Execution & Subprocess Isolation

VulnForge enforces process isolation by never invoking shell interpreters (`shell=False`). All external scanner binaries (e.g. `nmap`, `nuclei`) are executed using structured argument arrays via `packages/security/command_safety.py`.

```python
# Safe invocation pattern:
process = await asyncio.create_subprocess_exec(
    *args,  # List of validated string arguments
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE
)
```

No user-supplied strings are ever interpolated into shell strings.

---

## 2. Server-Side Request Forgery (SSRF) Protection

The `SSRFGuard` module (`packages/security/ssrf_guard.py`) validates all candidate targets prior to scanning:
- Resolves domain hostnames to IP addresses.
- Evaluates resolved IPs against standard RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and AWS/cloud metadata endpoints (`169.254.169.254`).
- Blocks unauthorized scanning of internal infrastructure unless explicit authorized local lab mode is enabled on the project.

---

## 3. Scope Boundary Enforcement

Before any scan starts, target inputs pass through an authorization and scope pipeline:
1. **Target Normalization**: Extracts hostname, port, and protocol.
2. **Exclusion Check**: Tests against project denylist rules.
3. **Allowlist Match**: Verifies exact domain, wildcard subdomains (`*.example.com`), or CIDR subnets.
4. **Mandatory Authorization Gate**: Requires explicit acknowledgement of scanning authority recorded into the append-only audit ledger.

---

## 4. Secret Scrubbing & Data Hygiene

The `packages/security/sanitizer.py` engine strips sensitive credentials before database persistence or report output:
- Bearer tokens
- API keys
- Password strings
- Authorization & Cookie headers
- AWS Access & Secret keys

---

## 5. Role-Based Access Control (RBAC) & Multi-Tenancy

Every API endpoint enforces organization tenant boundaries. A user belonging to Organization A cannot access projects, assets, scans, or findings belonging to Organization B.

| Role | Permissions |
|---|---|
| **OWNER** | Full tenant admin, billing, user invite, API keys, scanner controls |
| **ADMIN** | Manage projects, assets, assessments, reports, team members |
| **SECURITY_ANALYST** | Configure and run assessments, triage findings, generate reports |
| **VIEWER** | Read-only access to dashboards, reports, and finding statuses |
