"""
VulnForge Custom Web Security Scanner Engine
Executes comprehensive native async Python web vulnerability and configuration checks.
"""
import urllib.parse
from typing import List, Dict, Any, Optional
import httpx
from packages.scanner.base import BaseScannerAdapter
from packages.schemas.models import FindingBase, EvidenceItem
from packages.security.ssrf_guard import SSRFGuard
from packages.security.sanitizer import sanitize_headers, sanitize_text
from packages.shared.constants import (
    ScannerType,
    Severity,
    Confidence,
    FindingStatus,
)
from packages.shared.logging import logger


class CustomWebAdapter(BaseScannerAdapter):
    scanner_type = ScannerType.CUSTOM_WEB
    name = "Custom Web Security Engine"

    SENSITIVE_PATHS = [
        ("/.git/HEAD", "ref: refs/", "Exposed Git Repository Metadata", Severity.HIGH, "CWE-538", 7.5),
        ("/.env", "DB_PASSWORD=", "Exposed Environment Configuration File", Severity.CRITICAL, "CWE-526", 9.1),
        ("/.env.bak", "APP_KEY=", "Exposed Backup Environment File", Severity.CRITICAL, "CWE-526", 9.1),
        ("/web.config", "<configuration>", "Exposed IIS Web Configuration", Severity.HIGH, "CWE-538", 7.5),
        ("/.DS_Store", "\x00\x00\x00\x01Bud1", "Exposed macOS Metadata File", Severity.LOW, "CWE-538", 3.1),
        ("/actuator/env", "propertySources", "Exposed Spring Boot Actuator Env Endpoint", Severity.HIGH, "CWE-200", 7.5),
        ("/phpinfo.php", "phpinfo()", "Exposed PHPInfo Diagnostic Page", Severity.MEDIUM, "CWE-200", 5.3),
    ]

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        return "1.0.0 (Native Python Async)"

    async def validate(self, target: str, options: Dict[str, Any]) -> bool:
        host, _, _ = SSRFGuard.normalize_target(target)
        return bool(host)

    async def prepare(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        host, port, proto = SSRFGuard.normalize_target(target)
        base_url = target if target.startswith(("http://", "https://")) else f"http://{host}{f':{port}' if port else ''}"
        return {
            "base_url": base_url.rstrip("/"),
            "host": host,
            "timeout": options.get("timeout", 10),
            "rate_limit_rps": options.get("rate_limit_rps", 20),
        }

    async def execute(self, target: str, options: Dict[str, Any]) -> List[Dict[str, Any]]:
        context = await self.prepare(target, options)
        base_url = context["base_url"]
        timeout = context["timeout"]
        findings = []

        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
            # 1. Base URL Probe
            try:
                resp = await client.get(base_url)
                headers = {k.lower(): v for k, v in resp.headers.items()}

                # Check Security Headers
                # A. HSTS
                if base_url.startswith("https://") and "strict-transport-security" not in headers:
                    findings.append({
                        "title": "Missing HTTP Strict Transport Security (HSTS) Header",
                        "description": "The web application does not enforce HSTS, allowing man-in-the-middle attackers to downgrade HTTPS connections to HTTP.",
                        "severity": Severity.MEDIUM,
                        "cvss": 5.9,
                        "cwe": "CWE-319",
                        "category": "Cryptographic Configuration",
                        "endpoint": "/",
                        "impact": "Vulnerability to SSL stripping and insecure HTTP downgrade attacks.",
                        "remediation": "Add the header `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
                        "evidence": f"Response headers inspected: {list(headers.keys())}",
                    })

                # B. CSP
                if "content-security-policy" not in headers:
                    findings.append({
                        "title": "Missing Content Security Policy (CSP)",
                        "description": "The application lacks a Content-Security-Policy header. CSP restricts the origins of scripts, images, and other resources to defend against Cross-Site Scripting (XSS).",
                        "severity": Severity.MEDIUM,
                        "cvss": 6.1,
                        "cwe": "CWE-1021",
                        "category": "Web Security Configuration",
                        "endpoint": "/",
                        "impact": "Increased risk of successful Cross-Site Scripting (XSS) and data exfiltration.",
                        "remediation": "Implement a restrictive Content-Security-Policy header (e.g. `default-src 'self'; script-src 'self'`).",
                        "evidence": "Header 'Content-Security-Policy' was absent.",
                    })

                # C. X-Frame-Options / Clickjacking
                if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
                    findings.append({
                        "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
                        "description": "The page does not specify X-Frame-Options or CSP frame-ancestors, enabling malicious sites to embed it inside an iframe to perform clickjacking attacks.",
                        "severity": Severity.LOW,
                        "cvss": 4.3,
                        "cwe": "CWE-1021",
                        "category": "Web Security Configuration",
                        "endpoint": "/",
                        "impact": "Users can be tricked into clicking hidden UI elements on the framed target.",
                        "remediation": "Send `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` in all HTTP responses.",
                        "evidence": "Neither X-Frame-Options nor frame-ancestors directive found.",
                    })

                # D. X-Content-Type-Options
                if headers.get("x-content-type-options", "").lower() != "nosniff":
                    findings.append({
                        "title": "Missing X-Content-Type-Options: nosniff Header",
                        "description": "Browsers may MIME-sniff responses away from the declared Content-Type, potentially executing non-executable files as scripts.",
                        "severity": Severity.LOW,
                        "cvss": 3.4,
                        "cwe": "CWE-116",
                        "category": "Web Security Configuration",
                        "endpoint": "/",
                        "impact": "Potential MIME-confusion attacks and script execution.",
                        "remediation": "Set `X-Content-Type-Options: nosniff` on all HTTP responses.",
                        "evidence": f"X-Content-Type-Options header was '{headers.get('x-content-type-options', 'None')}'",
                    })

                # E. Insecure Cookies
                cookies = resp.cookies
                for cookie in cookies.jar:
                    cookie_name = cookie.name
                    if not cookie.secure and base_url.startswith("https"):
                        findings.append({
                            "title": f"Insecure Cookie Flag: Missing Secure on '{cookie_name}'",
                            "description": f"The cookie '{cookie_name}' is set without the 'Secure' flag and may be transmitted over unencrypted HTTP.",
                            "severity": Severity.LOW,
                            "cvss": 3.7,
                            "cwe": "CWE-614",
                            "category": "Session Management",
                            "endpoint": "/",
                            "impact": "Session cookies or tokens may be intercepted over unencrypted channels.",
                            "remediation": "Append `; Secure` to all Set-Cookie directives.",
                            "evidence": f"Cookie {cookie_name} missing Secure flag.",
                        })
                    if not cookie.has_nonstandard_attr("HttpOnly") and not cookie.has_nonstandard_attr("httponly"):
                        findings.append({
                            "title": f"Insecure Cookie Flag: Missing HttpOnly on '{cookie_name}'",
                            "description": f"The cookie '{cookie_name}' does not specify the 'HttpOnly' flag, making it readable by client-side JavaScript.",
                            "severity": Severity.LOW,
                            "cvss": 3.7,
                            "cwe": "CWE-1004",
                            "category": "Session Management",
                            "endpoint": "/",
                            "impact": "If an XSS vulnerability exists, attackers can steal this cookie directly via document.cookie.",
                            "remediation": "Append `; HttpOnly` to sensitive session and auth cookies.",
                            "evidence": f"Cookie {cookie_name} missing HttpOnly flag.",
                        })

            except Exception as e:
                logger.warning(f"Error during base URL probe for {base_url}: {e}")

            # 2. CORS Misconfiguration Check
            try:
                cors_headers = {"Origin": "https://evil-attacker.example.com"}
                cors_resp = await client.get(base_url, headers=cors_headers)
                acao = cors_resp.headers.get("access-control-allow-origin")
                acac = cors_resp.headers.get("access-control-allow-credentials")

                if acao == "https://evil-attacker.example.com":
                    findings.append({
                        "title": "Insecure CORS Policy: Arbitrary Origin Reflection",
                        "description": "The web server dynamically reflects arbitrary untrusted Origin headers in Access-Control-Allow-Origin.",
                        "severity": Severity.HIGH if acac == "true" else Severity.MEDIUM,
                        "cvss": 7.5 if acac == "true" else 5.3,
                        "cwe": "CWE-942",
                        "category": "Access Control",
                        "endpoint": "/",
                        "impact": "Attacker websites can make authenticated cross-origin requests and read private user data.",
                        "remediation": "Maintain a strict allowlist of trusted origins rather than reflecting arbitrary input origins.",
                        "evidence": f"Request Origin: https://evil-attacker.example.com -> Response ACAO: {acao}, ACAC: {acac}",
                    })
            except Exception:
                pass

            # 3. Sensitive File & Directory Probing
            for path, signature, title, severity, cwe, cvss in self.SENSITIVE_PATHS:
                try:
                    probe_url = f"{base_url}{path}"
                    probe_resp = await client.get(probe_url)
                    if probe_resp.status_code == 200 and signature in probe_resp.text:
                        findings.append({
                            "title": title,
                            "description": f"The sensitive file '{path}' is publicly accessible on the web server.",
                            "severity": severity,
                            "cvss": cvss,
                            "cwe": cwe,
                            "category": "Information Disclosure & Exposure",
                            "endpoint": path,
                            "impact": "Exposes internal configurations, source code references, or application secrets to unauthorized users.",
                            "remediation": f"Block public web server access to '{path}' in reverse proxy or web server configuration.",
                            "evidence": f"GET {path} returned HTTP 200 with signature '{signature}'. Snippet: {sanitize_text(probe_resp.text[:300])}",
                        })
                except Exception:
                    pass

            # 4. Dangerous HTTP Methods Check
            try:
                options_resp = await client.options(base_url)
                allowed_methods = options_resp.headers.get("allow", "").upper()
                risky_found = [m for m in ["TRACE", "PUT", "DELETE"] if m in allowed_methods]
                if "TRACE" in risky_found:
                    findings.append({
                        "title": "HTTP TRACE Method Enabled (Cross-Site Tracing / XST)",
                        "description": "The web server enables the HTTP TRACE method, which echoes back client requests and headers.",
                        "severity": Severity.MEDIUM,
                        "cvss": 5.3,
                        "cwe": "CWE-693",
                        "category": "Web Server Configuration",
                        "endpoint": "/",
                        "impact": "Can be leveraged in Cross-Site Tracing attacks to bypass HttpOnly cookie protections.",
                        "remediation": "Disable TRACE method in web server configuration (e.g. `TraceEnable off` in Apache).",
                        "evidence": f"OPTIONS Allow header: {allowed_methods}",
                    })
            except Exception:
                pass

        return findings

    async def parse(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return raw_results

    async def normalize(self, parsed_items: List[Dict[str, Any]], target: str) -> List[FindingBase]:
        findings = []
        for item in parsed_items:
            findings.append(FindingBase(
                title=item["title"],
                description=item["description"],
                severity=item["severity"],
                cvss_score=item.get("cvss", 0.0),
                cwe=item.get("cwe", "CWE-693"),
                category=item.get("category", "Web Application Security"),
                asset_target=target,
                endpoint=item.get("endpoint", "/"),
                protocol="HTTP/HTTPS",
                evidence=EvidenceItem(
                    output_snippet=item.get("evidence"),
                ),
                impact=item["impact"],
                remediation=item["remediation"],
                references=["https://owasp.org/www-project-top-ten/"],
                scanner=self.name,
                confidence=Confidence.CONFIRMED,
                status=FindingStatus.OPEN,
            ))
        return findings
