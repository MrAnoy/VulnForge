"""
VulnForge Demo Data Seeder
Seeds realistic enterprise security assessment data, assets, scopes, findings, evidence, and audit logs.
"""
import sys
import os
from datetime import datetime, timedelta, timezone

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy.orm import Session
from apps.api.core.database import sync_engine, Base
from apps.api.core.models import (
    User,
    Organization,
    OrganizationMember,
    Project,
    Asset,
    ScopeRule,
    Assessment,
    AssessmentLog,
    Finding,
    RemediationTask,
    AuditLog,
    Report,
)
from packages.security.crypto import hash_password
from packages.shared.constants import (
    Role,
    EnvironmentType,
    AssetType,
    AssetCriticality,
    ScopeStatus,
    AssessmentProfileType,
    AssessmentStatus,
    AssessmentPhase,
    Severity,
    Confidence,
    FindingStatus,
    ReportFormat,
    ReportType,
)


def seed_database():
    print("[*] Initializing tables on sync engine...")
    Base.metadata.create_all(bind=sync_engine)

    session = Session(bind=sync_engine)
    try:
        # Check if already seeded
        existing_user = session.query(User).filter(User.email == "admin@vulnforge.sec").first()
        if existing_user:
            print("[+] Database already contains seed data. Refreshing...")
            # Clean old records
            session.query(AuditLog).delete()
            session.query(RemediationTask).delete()
            session.query(Finding).delete()
            session.query(AssessmentLog).delete()
            session.query(Report).delete()
            session.query(Assessment).delete()
            session.query(Asset).delete()
            session.query(ScopeRule).delete()
            session.query(Project).delete()
            session.query(OrganizationMember).delete()
            session.query(Organization).delete()
            session.query(User).delete()
            session.commit()

        print("[*] Creating users...")
        pw_hash = hash_password("VulnForgeDemo2026!")

        admin_user = User(
            email="admin@vulnforge.sec",
            hashed_password=pw_hash,
            full_name="Alex Mercer (Security Lead)",
            is_active=True
        )
        analyst_user = User(
            email="analyst@vulnforge.sec",
            hashed_password=pw_hash,
            full_name="Sarah Chen (Senior AppSec)",
            is_active=True
        )
        viewer_user = User(
            email="viewer@vulnforge.sec",
            hashed_password=pw_hash,
            full_name="David Ross (Compliance Officer)",
            is_active=True
        )
        session.add_all([admin_user, analyst_user, viewer_user])
        session.flush()

        print("[*] Creating demo organization...")
        org = Organization(
            name="Acme Cyber Defense Corp",
            slug="acme-cyber-defense",
            description="Enterprise financial technology & secure payment processing division",
            owner_id=admin_user.id
        )
        session.add(org)
        session.flush()

        session.add_all([
            OrganizationMember(organization_id=org.id, user_id=admin_user.id, role=Role.OWNER),
            OrganizationMember(organization_id=org.id, user_id=analyst_user.id, role=Role.SECURITY_ANALYST),
            OrganizationMember(organization_id=org.id, user_id=viewer_user.id, role=Role.VIEWER),
        ])
        session.flush()

        print("[*] Creating projects...")
        p_prod = Project(
            organization_id=org.id,
            owner_id=admin_user.id,
            name="Core Banking API & Payment Gateway",
            description="PCI-DSS In-Scope Production Core Banking REST APIs and Checkout Frontend",
            client_name="Acme Payments Division",
            environment=EnvironmentType.PRODUCTION,
            tags=["PCI-DSS", "Tier-1", "Payment-Gateway", "Production"],
            risk_score=74.5
        )
        p_staging = Project(
            organization_id=org.id,
            owner_id=analyst_user.id,
            name="Customer Portal NextGen (Staging)",
            description="Microservices-based customer facing banking portal staging environment",
            client_name="Acme Digital Banking",
            environment=EnvironmentType.STAGING,
            tags=["Staging", "Frontend", "OAuth2"],
            risk_score=88.0
        )
        session.add_all([p_prod, p_staging])
        session.flush()

        # Scope for p_prod
        scope_prod = ScopeRule(
            project_id=p_prod.id,
            allowed_targets=["https://api.corebanking.acme-demo.internal", "https://checkout.acme-demo.internal", "198.51.100.25"],
            excluded_targets=["https://api.corebanking.acme-demo.internal/admin/wipe-db"],
            allowed_ports=[80, 443, 8443],
            rate_limit_rps=25,
            max_concurrency=4,
            scan_window_hours=6,
            allow_local_lab=True
        )
        session.add(scope_prod)

        print("[*] Registering assets...")
        a1 = Asset(
            project_id=p_prod.id,
            target="https://api.corebanking.acme-demo.internal",
            asset_type=AssetType.API_ENDPOINT,
            criticality=AssetCriticality.CRITICAL,
            environment=EnvironmentType.PRODUCTION,
            description="Core financial ledger & transaction submission API endpoint",
            tags=["API", "FastAPI", "Critical"],
            hostname="api.corebanking.acme-demo.internal",
            port=443,
            protocol="HTTPS",
            service="nginx/1.18.0 + uvicorn",
            technologies=["Python", "FastAPI", "Nginx", "PostgreSQL", "OpenSSL 1.1.1"],
            scope_status=ScopeStatus.IN_SCOPE,
            risk_score=82.0
        )
        a2 = Asset(
            project_id=p_prod.id,
            target="https://checkout.acme-demo.internal",
            asset_type=AssetType.URL,
            criticality=AssetCriticality.HIGH,
            environment=EnvironmentType.PRODUCTION,
            description="Customer checkout and payment tokenization web UI",
            tags=["Web", "NextJS", "Checkout"],
            hostname="checkout.acme-demo.internal",
            port=443,
            protocol="HTTPS",
            service="Cloudflare + Node.js",
            technologies=["Next.js", "React", "TailwindCSS"],
            scope_status=ScopeStatus.IN_SCOPE,
            risk_score=65.0
        )
        session.add_all([a1, a2])
        session.flush()

        print("[*] Creating assessment and logs...")
        assessment = Assessment(
            project_id=p_prod.id,
            name="Q3 Comprehensive Automated VAPT Assessment",
            profile=AssessmentProfileType.STANDARD_VAPT,
            status=AssessmentStatus.COMPLETED,
            current_phase=AssessmentPhase.COMPLETED,
            progress_percent=100,
            targets=[a1.target, a2.target],
            assets_discovered_count=2,
            findings_count=6,
            critical_count=1,
            high_count=2,
            medium_count=2,
            low_count=1,
            info_count=0,
            risk_score=74.5,
            started_at=datetime.now(timezone.utc) - timedelta(hours=2),
            completed_at=datetime.now(timezone.utc) - timedelta(hours=1, minutes=45)
        )
        session.add(assessment)
        session.flush()

        logs = [
            AssessmentLog(assessment_id=assessment.id, phase=AssessmentPhase.INITIALIZING, level="INFO", message="Assessment initialized. Profile: Standard VAPT.", progress=5),
            AssessmentLog(assessment_id=assessment.id, phase=AssessmentPhase.SCOPE_VALIDATION, level="INFO", message="Validated 2 targets against allowlist policy. SSRF guard passed.", progress=15),
            AssessmentLog(assessment_id=assessment.id, phase=AssessmentPhase.RECON, level="INFO", message="Gathering OSINT, DNS records, TLS certificates, and HTTP headers...", progress=30),
            AssessmentLog(assessment_id=assessment.id, phase=AssessmentPhase.DISCOVERY, level="INFO", message="Network service discovery completed on ports 80, 443, 8443.", progress=50),
            AssessmentLog(assessment_id=assessment.id, phase=AssessmentPhase.ASSESSMENT, level="INFO", message="Executing Web security engines (Headers, Cookies, CORS, Methods, Sensitive endpoints)...", progress=75),
            AssessmentLog(assessment_id=assessment.id, phase=AssessmentPhase.CORRELATION, level="INFO", message="Correlating and deduplicating cross-scanner findings. 8 raw -> 6 unique issues.", progress=85),
            AssessmentLog(assessment_id=assessment.id, phase=AssessmentPhase.RISK_ANALYSIS, level="INFO", message="Computing Platform Risk Scores. Overall Security Posture Score: 74.5/100.", progress=95),
            AssessmentLog(assessment_id=assessment.id, phase=AssessmentPhase.COMPLETED, level="INFO", message="Assessment finished successfully.", progress=100),
        ]
        session.add_all(logs)

        print("[*] Creating realistic findings & evidence...")
        f1 = Finding(
            project_id=p_prod.id,
            assessment_id=assessment.id,
            asset_id=a1.id,
            title="Exposed Environment Configuration File (/.env)",
            description="The web server exposes a raw environment configuration file at `/.env`. Inspection revealed sensitive production secrets including database credentials and JWT signing keys.",
            severity=Severity.CRITICAL,
            cvss_score=9.1,
            cwe="CWE-526",
            category="Sensitive Information Disclosure",
            asset_target=a1.target,
            endpoint="/.env",
            port=443,
            protocol="HTTPS",
            evidence={
                "url": "https://api.corebanking.acme-demo.internal/.env",
                "output_snippet": "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nDB_USER=banking_prod\nDB_PASSWORD=[REDACTED_PASSWORD]\nJWT_SECRET=[REDACTED_KEY]\nAWS_SECRET=[REDACTED_AWS_SECRET]"
            },
            impact="Direct full compromise of application database, unauthorized token forging, and lateral infrastructure movement.",
            remediation="Immediately restrict public web access to all dotfiles (`.*`) in Nginx configuration: `location ~ /\\. { deny all; }`. Rotate all exposed database and JWT credentials.",
            references=["https://cwe.mitre.org/data/definitions/526.html", "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
            scanner="Correlated (Custom Web Security Engine, Nuclei Template Scanner)",
            detected_by_scanners=["Custom Web Security Engine", "Nuclei Template Scanner"],
            confidence=Confidence.CONFIRMED,
            status=FindingStatus.OPEN,
            platform_risk_score=95.0,
            status_history=[]
        )

        f2 = Finding(
            project_id=p_prod.id,
            assessment_id=assessment.id,
            asset_id=a1.id,
            title="Insecure CORS Policy: Arbitrary Origin Reflection with Credentials",
            description="The API dynamically reflects arbitrary `Origin` headers and returns `Access-Control-Allow-Credentials: true`. This allows malicious websites to execute cross-origin authenticated queries against customer accounts.",
            severity=Severity.HIGH,
            cvss_score=7.5,
            cwe="CWE-942",
            category="Access Control Misconfiguration",
            asset_target=a1.target,
            endpoint="/v1/accounts/me",
            port=443,
            protocol="HTTPS",
            evidence={
                "url": "https://api.corebanking.acme-demo.internal/v1/accounts/me",
                "output_snippet": "Request: Origin: https://evil-attacker.example.com\nResponse:\nAccess-Control-Allow-Origin: https://evil-attacker.example.com\nAccess-Control-Allow-Credentials: true"
            },
            impact="Unauthorized extraction of customer account balances and personal identifiable information (PII) via malicious third-party websites.",
            remediation="Implement a strict static allowlist of authorized consumer domains. Never dynamically reflect untrusted request Origin headers alongside credential allowance.",
            references=["https://portswigger.net/web-security/cors", "https://cwe.mitre.org/data/definitions/942.html"],
            scanner="Custom Web Security Engine",
            detected_by_scanners=["Custom Web Security Engine"],
            confidence=Confidence.CONFIRMED,
            status=FindingStatus.OPEN,
            platform_risk_score=82.5,
            status_history=[]
        )

        f3 = Finding(
            project_id=p_prod.id,
            assessment_id=assessment.id,
            asset_id=a2.id,
            title="Exposed Git Repository Metadata (/.git/HEAD)",
            description="The web server permits access to `/.git/HEAD` and repository objects. Adversaries can dump the entire application source code repository and history.",
            severity=Severity.HIGH,
            cvss_score=7.5,
            cwe="CWE-538",
            category="Information Disclosure",
            asset_target=a2.target,
            endpoint="/.git/HEAD",
            port=443,
            protocol="HTTPS",
            evidence={
                "url": "https://checkout.acme-demo.internal/.git/HEAD",
                "output_snippet": "HTTP/1.1 200 OK\n\nref: refs/heads/main"
            },
            impact="Source code leakage, intellectual property theft, and identification of hardcoded internal endpoints.",
            remediation="Configure the web server or reverse proxy to return HTTP 403/404 for all requests under `/.git/`.",
            references=["https://cwe.mitre.org/data/definitions/538.html"],
            scanner="Custom Web Security Engine",
            detected_by_scanners=["Custom Web Security Engine"],
            confidence=Confidence.CONFIRMED,
            status=FindingStatus.IN_PROGRESS,
            platform_risk_score=76.0,
            status_history=[{
                "from_status": "OPEN",
                "to_status": "IN_PROGRESS",
                "reason": "Assigned to DevOps engineering team for Nginx block rule deployment.",
                "changed_by": "alex.mercer@vulnforge.sec",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }]
        )

        f4 = Finding(
            project_id=p_prod.id,
            assessment_id=assessment.id,
            asset_id=a1.id,
            title="Missing Content Security Policy (CSP)",
            description="The web application does not return a `Content-Security-Policy` header. CSP is a critical defense-in-depth mitigation against Cross-Site Scripting (XSS) and data exfiltration.",
            severity=Severity.MEDIUM,
            cvss_score=6.1,
            cwe="CWE-1021",
            category="Web Security Configuration",
            asset_target=a1.target,
            endpoint="/",
            port=443,
            protocol="HTTPS",
            evidence={
                "output_snippet": "Header 'Content-Security-Policy' was absent across all sampled API endpoints."
            },
            impact="Heightened susceptibility to Cross-Site Scripting (XSS) exploitation if input sanitization fails.",
            remediation="Deploy a robust Content-Security-Policy header such as `default-src 'self'; script-src 'self'; object-src 'none';`.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
            scanner="Custom Web Security Engine",
            detected_by_scanners=["Custom Web Security Engine"],
            confidence=Confidence.HIGH,
            status=FindingStatus.OPEN,
            platform_risk_score=52.0,
            status_history=[]
        )

        f5 = Finding(
            project_id=p_prod.id,
            assessment_id=assessment.id,
            asset_id=a1.id,
            title="Missing HTTP Strict Transport Security (HSTS) Header",
            description="The HTTPS endpoint does not provide a `Strict-Transport-Security` header, allowing potential SSL stripping attacks against initial unencrypted connections.",
            severity=Severity.MEDIUM,
            cvss_score=5.9,
            cwe="CWE-319",
            category="Cryptographic Configuration",
            asset_target=a1.target,
            endpoint="/",
            port=443,
            protocol="HTTPS",
            evidence={
                "output_snippet": "Strict-Transport-Security header was not observed in HTTPS response headers."
            },
            impact="Users could be downgraded to plaintext HTTP via active adversary-in-the-middle attacks.",
            remediation="Add header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
            scanner="Custom Web Security Engine",
            detected_by_scanners=["Custom Web Security Engine"],
            confidence=Confidence.CONFIRMED,
            status=FindingStatus.RESOLVED,
            platform_risk_score=48.0,
            status_history=[{
                "from_status": "OPEN",
                "to_status": "RESOLVED",
                "reason": "HSTS header configured on CDN Edge distribution.",
                "changed_by": "sarah.chen@vulnforge.sec",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }]
        )

        f6 = Finding(
            project_id=p_prod.id,
            assessment_id=assessment.id,
            asset_id=a2.id,
            title="Missing Anti-Clickjacking Header (X-Frame-Options)",
            description="The page lacks an `X-Frame-Options` or `frame-ancestors` directive, permitting it to be loaded inside an `<iframe>` on third-party sites.",
            severity=Severity.LOW,
            cvss_score=4.3,
            cwe="CWE-1021",
            category="Web Security Configuration",
            asset_target=a2.target,
            endpoint="/",
            port=443,
            protocol="HTTPS",
            evidence={
                "output_snippet": "Neither X-Frame-Options nor frame-ancestors directive found."
            },
            impact="Users can be tricked into clicking hidden actions on framed sensitive pages (Clickjacking).",
            remediation="Send `X-Frame-Options: SAMEORIGIN` or `X-Frame-Options: DENY` on all HTML responses.",
            references=["https://owasp.org/www-community/attacks/Clickjacking"],
            scanner="Custom Web Security Engine",
            detected_by_scanners=["Custom Web Security Engine"],
            confidence=Confidence.CONFIRMED,
            status=FindingStatus.OPEN,
            platform_risk_score=28.0,
            status_history=[]
        )

        session.add_all([f1, f2, f3, f4, f5, f6])
        session.flush()

        print("[*] Creating remediation tasks...")
        session.add_all([
            RemediationTask(
                finding_id=f1.id,
                title="Immediate Rotation of Production Secrets & Nginx Dotfile Deny Rule",
                description="1. Rotate DB password and JWT keys. 2. Push Nginx deny rule for `/.env`.",
                assignee_id=admin_user.id,
                status=FindingStatus.OPEN,
                priority=Severity.CRITICAL,
                due_date=datetime.now(timezone.utc) + timedelta(days=1)
            ),
            RemediationTask(
                finding_id=f3.id,
                title="Block Public Access to /.git Directory on Checkout Service",
                description="Add web server configuration rule to block `.git` folder.",
                assignee_id=analyst_user.id,
                status=FindingStatus.IN_PROGRESS,
                priority=Severity.HIGH,
                due_date=datetime.now(timezone.utc) + timedelta(days=3)
            )
        ])

        print("[*] Creating audit logs...")
        session.add_all([
            AuditLog(organization_id=org.id, user_id=admin_user.id, user_email=admin_user.email, action="CREATE_PROJECT", target_resource=p_prod.id, details={"name": p_prod.name}),
            AuditLog(organization_id=org.id, user_id=admin_user.id, user_email=admin_user.email, action="CONFIRM_TARGET_AUTHORIZATION", target_resource=p_prod.id, details={"targets": [a1.target, a2.target], "authorized_by": "Alex Mercer"}),
            AuditLog(organization_id=org.id, user_id=admin_user.id, user_email=admin_user.email, action="START_ASSESSMENT", target_resource=assessment.id, details={"profile": "STANDARD_VAPT"}),
            AuditLog(organization_id=org.id, user_id=analyst_user.id, user_email=analyst_user.email, action="UPDATE_FINDING_STATUS", target_resource=f3.id, details={"to_status": "IN_PROGRESS"}),
            AuditLog(organization_id=org.id, user_id=analyst_user.id, user_email=analyst_user.email, action="UPDATE_FINDING_STATUS", target_resource=f5.id, details={"to_status": "RESOLVED"}),
        ])

        session.commit()
        print("[+] Demo data successfully seeded!")
        print("-----------------------------------------------------")
        print("Admin Login:     admin@vulnforge.sec   / VulnForgeDemo2026!")
        print("Analyst Login:   analyst@vulnforge.sec / VulnForgeDemo2026!")
        print("Viewer Login:    viewer@vulnforge.sec  / VulnForgeDemo2026!")
        print("-----------------------------------------------------")

    except Exception as e:
        session.rollback()
        print(f"[-] Error during seed: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    seed_database()
