# VulnForge Quality Assurance & Automated Testing Guide

**Document Version:** 2.0.0  
**Test Coverage:** Backend (Pytest Unit + Security + Integration) & Frontend (Next.js Typecheck & Production Build)  

---

## 1. Automated Test Suite Overview

VulnForge incorporates a defense-in-depth automated test suite spanning unit tests, security regression tests, and end-to-end integration workflows.

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1
collected 24 items

tests/integration/test_api_flow.py::test_full_vapt_lifecycle PASSED      [  4%]
tests/integration/test_comparison_flow.py::test_assessment_comparison_and_schedules PASSED [  8%]
tests/security/test_command_injection.py::test_command_safety_rejects_string_commands PASSED [ 12%]
tests/security/test_command_injection.py::test_command_safety_non_executable_binary PASSED [ 16%]
tests/security/test_command_injection.py::test_malicious_shell_characters_are_not_evaluated PASSED [ 20%]
tests/security/test_multi_tenant_isolation.py::test_cross_tenant_isolation_idor PASSED [ 25%]
tests/security/test_report_escaping.py::test_html_report_escapes_xss_in_finding_data PASSED [ 29%]
tests/security/test_sanitizer.py::test_secret_scrubbing PASSED           [ 33%]
tests/security/test_sanitizer.py::test_header_sanitization PASSED        [ 37%]
tests/security/test_sanitizer.py::test_path_traversal_sanitization PASSED [ 41%]
tests/security/test_ssrf_advanced.py::test_ipv6_mapped_ipv4_loopback_is_blocked PASSED [ 45%]
tests/security/test_ssrf_advanced.py::test_cloud_metadata_blocked PASSED [ 50%]
tests/security/test_public_ip_is_allowed PASSED                          [ 54%]
tests/security/test_ssrf_guard_blocks_private_targets_when_local_lab_false PASSED [ 58%]
tests/security/test_ssrf_guard_allows_private_targets_when_local_lab_true PASSED [ 62%]
tests/unit/test_deduplication.py::test_deduplication_and_correlation PASSED [ 66%]
tests/unit/test_prioritization.py::test_prioritization_critical_tier1_asset_ranking PASSED [ 70%]
tests/unit/test_prioritization.py::test_prioritization_low_severity_asset_ranking PASSED [ 75%]
tests/unit/test_risk_engine.py::test_critical_finding_risk_score PASSED  [ 79%]
tests/unit/test_risk_engine.py::test_low_finding_risk_score PASSED       [ 83%]
tests/unit/test_risk_engine.py::test_overall_security_score_calculation PASSED [ 87%]
tests/unit/test_scope_engine.py::test_target_normalization PASSED        [ 91%]
tests/unit/test_scope_engine.py::test_private_ip_detection PASSED        [ 95%]
tests/unit/test_scope_engine.py::test_scope_allowlist_matching PASSED    [100%]

============================= 24 passed in 7.64s (100% PASS) ==============================
```

---

## 2. Test Suites Breakdown

### A. Security Testing (`tests/security/`)
- **`test_command_injection.py`**: Verifies that shell command strings are rejected and malicious metacharacters (`; && | $(whoami)`) are treated as literal arguments.
- **`test_multi_tenant_isolation.py`**: Verifies that users in Organization A cannot access or mutate projects, assets, scans, findings, or reports belonging to Organization B (IDOR prevention).
- **`test_report_escaping.py`**: Verifies that Jinja2 HTML deliverable templates escape malicious XSS payloads in vulnerability titles and descriptions.
- **`test_sanitizer.py`**: Verifies that Bearer tokens, passwords, Authorization headers, and AWS keys are scrubbed before persistence or report rendering.
- **`test_ssrf_advanced.py`**: Verifies that IPv6-mapped IPv4 addresses (`::ffff:127.0.0.1`), link-local IPs, cloud metadata endpoints (`169.254.169.254`), and private subnets are blocked.

### B. Unit Testing (`tests/unit/`)
- **`test_scope_engine.py`**: Target normalization, IPv4/IPv6 private IP detection, and CIDR/wildcard matching.
- **`test_risk_engine.py`**: CVSS score vs Platform Risk Score mathematics, severity baseline weights, and asset criticality multiplier calculations.
- **`test_deduplication.py`**: Cross-scanner finding correlation and deduplication algorithm.
- **`test_prioritization.py`**: Multi-dimensional ranking verification for top priority remediation items.

### C. Integration Testing (`tests/integration/`)
- **`test_api_flow.py`**: End-to-end user registration, project creation, scope validation, scan initiation, finding generation, and report export.
- **`test_comparison_flow.py`**: Multi-assessment delta calculation, resolved findings detection, new findings identification, and recurring schedule management.

---

## 3. How to Run Tests Locally

### Run Backend Pytest Suite:
```bash
.venv\Scripts\activate
python -m pytest tests/ -v
```

### Run Frontend Production Build & Typecheck:
```bash
cd apps/web
npm run build
```
