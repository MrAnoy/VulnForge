# VulnForge Changelog

## [2.0.0] - 2026-08-25 (World-Class Transformation Release)

### 🌟 Experience & Product Transformations
- **Four Adaptive View Modes**: Added seamless toggle between `Beginner`, `Professional`, `Executive`, and `Developer` modes across the entire UI with persistent preferences.
- **Smart Prioritization Engine ("What Should I Fix First?")**: Implemented multi-dimensional algorithmic ranking factoring in Severity, Asset Criticality, Internet Exposure, CVSS, and Scanner Confidence with human-understandable rationales.
- **Assessment Comparison & Delta Engine**: Added `/assessments/compare` to calculate Posture Score progression, Resolved Vulnerabilities, and New Findings between any two scans.
- **Scheduled Continuous Assessments**: Built automated recurring scan subsystem supporting `Daily`, `Weekly`, and `Monthly` configurations with pre-flight authorization validation.
- **White-Label Deliverable Customization**: Added enterprise branding controls (Company Name, Assessor, Client Organization, Classification Badges, Custom Accent Colors) across HTML, PDF, JSON, and CSV exports.
- **Platform Observability & Health Matrix**: Live status dashboard reporting health, latency, and capabilities across API Gateway, Database, Worker Queue, Scanner Adapters, AI Copilot, and Report Engine.
- **Enterprise Landing Experience**: Created high-impact landing page (`/landing`) communicating trust, precision, and evidence-driven security without hyperbole.

### 🛡️ Security Hardening & Defenses
- **Multi-Tenant Isolation & IDOR Defense**: Enforced centralized organization membership and resource verification across all 15 API routers.
- **Webhook SSRF Protection**: Strict outbound validation against private IP subnets, loopbacks, and cloud metadata (`169.254.169.254`).
- **HTML Report Stored XSS Prevention**: Enabled Jinja2 `autoescape=True` across deliverable report templates.
- **AI Prompt Injection Boundary Defense**: Encapsulated scanner telemetry in `<UNTRUSTED_SECURITY_DATA>` delimiter blocks.
- **Subprocess Security**: Zero `shell=True` execution; immutable argument arrays with strict command validation.
- **Sanitization Engine**: Multi-pattern secret scrubber removing tokens, headers, and API keys from raw scanner evidence.

### 🧪 Test Automation
- Expanded automated test suite to 24 tests covering Unit, Security (SSRF, Command Injection, Tenant IDOR, Report XSS, Sanitizer), Prioritization, and Integration flows (100% PASS).
- Verified Next.js 14 production build with 17/17 static & dynamic routes compiling with 0 errors.
