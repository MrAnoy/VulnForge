"""
VulnForge Reconnaissance & OSINT Scanner Adapter
Performs DNS record analysis, TLS certificate validation, HTTP technology fingerprinting,
and security policy discovery (/robots.txt, /.well-known/security.txt).
"""
import ssl
import socket
import datetime
from typing import List, Dict, Any, Optional
import httpx
import dns.resolver
from packages.scanner.base import BaseScannerAdapter
from packages.schemas.models import FindingBase, EvidenceItem
from packages.security.ssrf_guard import SSRFGuard
from packages.security.sanitizer import sanitize_headers
from packages.shared.constants import (
    ScannerType,
    Severity,
    Confidence,
    FindingStatus,
)
from packages.shared.logging import logger


class ReconAdapter(BaseScannerAdapter):
    scanner_type = ScannerType.RECON
    name = "Reconnaissance Engine"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        return "1.0.0 (Native Async)"

    async def validate(self, target: str, options: Dict[str, Any]) -> bool:
        host, _, _ = SSRFGuard.normalize_target(target)
        return bool(host)

    async def prepare(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        host, port, proto = SSRFGuard.normalize_target(target)
        return {
            "host": host,
            "port": port or (443 if proto == "https" else 80),
            "protocol": proto,
            "timeout": options.get("timeout", 10),
        }

    async def execute(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        context = await self.prepare(target, options)
        host = context["host"]
        timeout = context["timeout"]

        results = {
            "target": target,
            "host": host,
            "dns": {},
            "tls": {},
            "http": {},
            "security_txt": None,
            "robots_txt": None,
        }

        # 1. DNS Records Enumeration
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0
            
            for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
                try:
                    answers = resolver.resolve(host, rtype)
                    results["dns"][rtype] = [str(rdata) for rdata in answers]
                except Exception:
                    results["dns"][rtype] = []
        except Exception as e:
            logger.warning(f"DNS resolution error for {host}: {e}")

        # 2. TLS Certificate Inspection
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        # Extract expiration
                        not_after_str = cert.get("notAfter")
                        expire_date = None
                        days_left = None
                        if not_after_str:
                            expire_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expire_date - datetime.datetime.utcnow()).days
                        
                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        sans = [x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"]

                        results["tls"] = {
                            "has_tls": True,
                            "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                            "subject": subject.get("commonName", "Unknown"),
                            "expires_at": str(expire_date),
                            "days_until_expiry": days_left,
                            "sans": sans,
                            "version": ssock.version(),
                        }
        except Exception as e:
            results["tls"] = {
                "has_tls": False,
                "error": str(e)
            }

        # 3. HTTP Header & Banner Probing
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}"
            try:
                async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
                    resp = await client.get(url)
                    results["http"][scheme] = {
                        "status_code": resp.status_code,
                        "headers": sanitize_headers(dict(resp.headers)),
                        "server": resp.headers.get("server"),
                        "x_powered_by": resp.headers.get("x-powered-by"),
                        "title": None,
                    }
                    
                    # Extract <title> if present
                    if "text/html" in resp.headers.get("content-type", ""):
                        import re
                        m = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
                        if m:
                            results["http"][scheme]["title"] = m.group(1).strip()
                    break  # Success
            except Exception:
                continue

        # 4. Security.txt & Robots.txt Probing
        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
                for base in [f"https://{host}", f"http://{host}"]:
                    try:
                        r = await client.get(f"{base}/.well-known/security.txt")
                        if r.status_code == 200 and "contact" in r.text.lower():
                            results["security_txt"] = r.text[:1000]
                            break
                    except Exception:
                        pass

                for base in [f"https://{host}", f"http://{host}"]:
                    try:
                        r = await client.get(f"{base}/robots.txt")
                        if r.status_code == 200 and ("user-agent" in r.text.lower() or "disallow" in r.text.lower()):
                            results["robots_txt"] = r.text[:1000]
                            break
                    except Exception:
                        pass
        except Exception:
            pass

        return results

    async def parse(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        host = raw_results.get("host", "")
        dns_data = raw_results.get("dns", {})
        tls_data = raw_results.get("tls", {})
        http_data = raw_results.get("http", {})

        # Check DMARC & SPF
        txt_records = dns_data.get("TXT", [])
        has_spf = any("v=spf1" in txt.lower() for txt in txt_records)
        if not has_spf and txt_records:
            findings.append({
                "title": "Missing DNS SPF (Sender Policy Framework) Record",
                "description": f"Domain {host} does not have a configured SPF TXT record. Attackers may spoof emails purporting to originate from this domain.",
                "severity": Severity.LOW,
                "cvss": 3.1,
                "cwe": "CWE-290",
                "category": "DNS & Email Security",
                "impact": "Increased susceptibility to email spoofing and domain reputation damage.",
                "remediation": "Publish a valid SPF record in DNS (e.g. `v=spf1 include:_spf.example.com ~all`).",
                "evidence": f"Queried TXT records: {txt_records}",
            })

        # Check TLS Expiration
        if tls_data.get("has_tls"):
            days = tls_data.get("days_until_expiry")
            if days is not None and days <= 14:
                findings.append({
                    "title": "SSL/TLS Certificate Expiring Soon",
                    "description": f"The SSL/TLS certificate for {host} will expire in {days} days on {tls_data.get('expires_at')}.",
                    "severity": Severity.MEDIUM if days > 3 else Severity.HIGH,
                    "cvss": 5.3,
                    "cwe": "CWE-295",
                    "category": "Cryptographic Weakness",
                    "impact": "Service disruption and browser security warnings upon certificate expiration.",
                    "remediation": "Renew and deploy the TLS certificate before the expiration date.",
                    "evidence": f"Issuer: {tls_data.get('issuer')}, Days Left: {days}",
                })

        # Check Server Banner / X-Powered-By Exposure
        for scheme, hinfo in http_data.items():
            server_banner = hinfo.get("server")
            x_powered = hinfo.get("x_powered_by")
            if server_banner and any(char.isdigit() for char in server_banner):
                findings.append({
                    "title": "Detailed Web Server Version Disclosure",
                    "description": f"The server banner exposes specific version information: '{server_banner}'. This aids attackers in tailoring exploits to known CVEs.",
                    "severity": Severity.LOW,
                    "cvss": 2.6,
                    "cwe": "CWE-200",
                    "category": "Information Disclosure",
                    "impact": "Assists adversaries in reconnaissance and automated vulnerability scanning.",
                    "remediation": "Configure the web server to suppress detailed version numbers (e.g. `ServerTokens Prod` in Apache, `server_tokens off;` in Nginx).",
                    "evidence": f"Server header returned: {server_banner}",
                })

            if x_powered:
                findings.append({
                    "title": "Technology Stack Disclosure via X-Powered-By Header",
                    "description": f"The HTTP response contains an `X-Powered-By: {x_powered}` header revealing underlying application runtime.",
                    "severity": Severity.LOW,
                    "cvss": 2.6,
                    "cwe": "CWE-200",
                    "category": "Information Disclosure",
                    "impact": "Reveals framework details to potential adversaries.",
                    "remediation": "Disable the X-Powered-By header in your application framework configuration.",
                    "evidence": f"X-Powered-By header: {x_powered}",
                })

        return findings

    async def normalize(self, parsed_items: List[Dict[str, Any]], target: str) -> List[FindingBase]:
        findings = []
        for item in parsed_items:
            findings.append(FindingBase(
                title=item["title"],
                description=item["description"],
                severity=item["severity"],
                cvss_score=item.get("cvss", 0.0),
                cwe=item.get("cwe", "CWE-200"),
                category=item.get("category", "Reconnaissance"),
                asset_target=target,
                endpoint="/",
                protocol="TCP/DNS/TLS",
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
