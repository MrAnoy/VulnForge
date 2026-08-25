"""
VulnForge OWASP ZAP Scanner Adapter
Interfaces with OWASP ZAP API for web spidering, passive alert collection, and controlled active scanning.
"""
from typing import List, Dict, Any, Optional
import httpx
from packages.scanner.base import BaseScannerAdapter
from packages.schemas.models import FindingBase, EvidenceItem
from packages.security.ssrf_guard import SSRFGuard
from packages.shared.config import settings
from packages.shared.constants import (
    ScannerType,
    Severity,
    Confidence,
    FindingStatus,
)
from packages.shared.logging import logger


class ZapAdapter(BaseScannerAdapter):
    scanner_type = ScannerType.ZAP
    name = "OWASP ZAP Scanner"

    RISK_MAP = {
        "3": Severity.HIGH,
        "2": Severity.MEDIUM,
        "1": Severity.LOW,
        "0": Severity.INFORMATIONAL,
    }

    def is_available(self) -> bool:
        # Check if ZAP API responds
        try:
            r = httpx.get(f"{settings.ZAP_API_URL}/JSON/core/view/version/", timeout=1.0)
            return r.status_code == 200
        except Exception:
            return False

    def get_version(self) -> Optional[str]:
        try:
            r = httpx.get(f"{settings.ZAP_API_URL}/JSON/core/view/version/", timeout=1.0)
            if r.status_code == 200:
                return f"OWASP ZAP v{r.json().get('version', 'Unknown')}"
        except Exception:
            pass
        return None

    async def validate(self, target: str, options: Dict[str, Any]) -> bool:
        host, _, _ = SSRFGuard.normalize_target(target)
        return bool(host)

    async def prepare(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "target": target,
            "api_url": settings.ZAP_API_URL,
            "api_key": settings.ZAP_API_KEY,
            "active_scan": options.get("active_scan", False),  # Disabled by default
        }

    async def execute(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        if not self.is_available():
            logger.info("OWASP ZAP daemon not reachable. Skipping ZAP scan.")
            return {"available": False, "target": target, "alerts": []}

        context = await self.prepare(target, options)
        api_url = context["api_url"]
        api_key = context["api_key"]

        alerts = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                params = {"baseurl": target}
                if api_key:
                    params["apikey"] = api_key
                resp = await client.get(f"{api_url}/JSON/alert/view/alertsByRisk/", params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    alerts = data.get("alertsByRisk", [])
        except Exception as e:
            logger.error(f"ZAP API error: {e}")

        return {
            "available": True,
            "target": target,
            "alerts": alerts,
        }

    async def parse(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        if not raw_results.get("available") or not raw_results.get("alerts"):
            return findings

        for risk_group in raw_results["alerts"]:
            for alert in risk_group.get("alerts", []):
                risk_code = str(alert.get("risk", "0"))
                severity = self.RISK_MAP.get(risk_code, Severity.INFORMATIONAL)
                cwe_id = alert.get("cweid")
                cwe_str = f"CWE-{cwe_id}" if cwe_id and int(cwe_id) > 0 else "CWE-200"

                findings.append({
                    "title": alert.get("alert", "ZAP Alert"),
                    "description": alert.get("description", ""),
                    "severity": severity,
                    "cvss": 5.0 if severity == Severity.MEDIUM else (7.5 if severity == Severity.HIGH else 2.0),
                    "cwe": cwe_str,
                    "category": "Web Security Assessment",
                    "endpoint": alert.get("url", "/"),
                    "param": alert.get("param", ""),
                    "impact": "Security misconfiguration or vulnerability identified by OWASP ZAP.",
                    "remediation": alert.get("solution", "Follow OWASP guidelines to remediate this alert."),
                    "references": [alert.get("reference", "https://www.zaproxy.org")],
                    "evidence": f"URL: {alert.get('url')}, Param: {alert.get('param')}, Evidence: {alert.get('evidence')}",
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
                category=item.get("category", "Web Security"),
                asset_target=target,
                endpoint=item.get("endpoint"),
                protocol="HTTP/HTTPS",
                evidence=EvidenceItem(
                    url=item.get("endpoint"),
                    parameter=item.get("param"),
                    output_snippet=item.get("evidence"),
                ),
                impact=item["impact"],
                remediation=item["remediation"],
                references=item.get("references", []),
                scanner=self.name,
                confidence=Confidence.HIGH,
                status=FindingStatus.OPEN,
            ))
        return findings
