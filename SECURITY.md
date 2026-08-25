# VulnForge Security Policy

## Security Principles

VulnForge is designed and maintained according to core security principles:
1. **Zero Trust & Least Privilege**: All API routes enforce organization membership and role verification.
2. **Deterministic Process Isolation**: External scanner execution uses strictly immutable argument vectors (`shell=False`).
3. **Comprehensive SSRF Defense**: Candidate scan targets and webhook URLs are normalized and resolved against blocked IP ranges (RFC 1918, loopbacks, link-local, and cloud metadata).
4. **Data Hygiene & Secret Scrubbing**: Scanner outputs and evidence snippets are scrubbed for sensitive credentials, session tokens, and passwords.
5. **Jinja2 Autoescaping**: Deliverable HTML reports enforce entity escaping to prevent Stored XSS from external server banners or reflected parameters.
6. **AI Prompt Injection Isolation**: Untrusted vulnerability data is quarantined within `<UNTRUSTED_SECURITY_DATA>` delimiter blocks.

---

## Reporting a Vulnerability

If you discover a security vulnerability within VulnForge, please report it privately:
- **Email:** `security@vulnforge.sec`
- Please provide detailed reproduction steps, target environment, and potential impact.
- We will acknowledge receipt within 24 hours and provide regular status updates through remediation.

---

## Automated Security Testing

VulnForge maintains an extensive automated security test suite under `tests/security/`:
- `test_command_injection.py`: Verifies non-executable commands, string command rejection, and shell character isolation.
- `test_multi_tenant_isolation.py`: Verifies cross-tenant IDOR defense across projects, assets, scans, and audit logs.
- `test_ssrf_advanced.py`: Verifies IPv6 mapped IPv4, cloud metadata, and webhook validation.
- `test_report_escaping.py`: Verifies Jinja2 HTML deliverable entity encoding.
- `test_sanitizer.py`: Verifies secret scrubbing and header sanitization.
