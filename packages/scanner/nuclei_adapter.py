"""
VulnForge Nuclei Template Scanner Adapter
Controlled Nuclei execution with approved categories, rate limits, and JSON output parsing.
"""
import shutil
import json
from typing import List, Dict, Any, Optional
from packages.scanner.base import BaseScannerAdapter
from packages.schemas.models import FindingBase, EvidenceItem
from packages.security.command_safety import CommandSafety
from packages.security.ssrf_guard import SSRFGuard
from packages.shared.config import settings
from packages.shared.constants import (
    ScannerType,
    Severity,
    Confidence,
    FindingStatus,
)
from packages.shared.logging import logger


class NucleiAdapter(BaseScannerAdapter):
    scanner_type = ScannerType.NUCLEI
    name = "Nuclei Template Scanner"

    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFORMATIONAL,
    }

    def is_available(self) -> bool:
        return shutil.which(settings.NUCLEI_PATH or "nuclei") is not None

    def get_version(self) -> Optional[str]:
        if not self.is_available():
            return None
        return "Nuclei Fast Vulnerability Scanner"

    async def validate(self, target: str, options: Dict[str, Any]) -> bool:
        host, _, _ = SSRFGuard.normalize_target(target)
        return bool(host)

    async def prepare(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        tags = options.get("tags", "cve,misconfiguration,exposure,tech")
        rate_limit = options.get("rate_limit_rps", 20)
        return {
            "target": target,
            "tags": tags,
            "rate_limit": rate_limit,
            "timeout": options.get("timeout", 300),
        }

    async def execute(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        if not self.is_available():
            logger.info("Nuclei binary not found. Skipping Nuclei execution.")
            return {"available": False, "target": target, "results": []}

        context = await self.prepare(target, options)
        timeout = context["timeout"]

        args = [
            settings.NUCLEI_PATH or "nuclei",
            "-target", target,
            "-tags", context["tags"],
            "-rate-limit", str(context["rate_limit"]),
            "-jsonl",
            "-silent",
            "-duc"  # Disable update check
        ]

        try:
            return_code, stdout, stderr = await CommandSafety.run_safe_command(args, timeout=timeout)
            json_lines = [json.loads(line) for line in stdout.splitlines() if line.strip()]
            return {
                "available": True,
                "target": target,
                "json_results": json_lines,
                "stderr": stderr
            }
        except Exception as e:
            logger.error(f"Nuclei execution error: {str(e)}")
            return {"available": True, "target": target, "error": str(e), "json_results": []}

    async def parse(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        if not raw_results.get("available") or not raw_results.get("json_results"):
            return findings

        for item in raw_results["json_results"]:
            info = item.get("info", {})
            template_id = item.get("template-id", "nuclei-template")
            name = info.get("name", template_id)
            sev_str = str(info.get("severity", "info")).lower()
            severity = self.SEVERITY_MAP.get(sev_str, Severity.LOW)

            # Extract classification
            classif = info.get("classification", {})
            cve_id = classif.get("cve-id")
            cwe_id = classif.get("cwe-id", ["CWE-200"])
            cwe_str = cwe_id[0] if isinstance(cwe_id, list) and cwe_id else str(cwe_id)
            cvss_score = float(classif.get("cvss-score", 0.0) or 0.0)

            matched_at = item.get("matched-at", "")
            extracted = item.get("extracted-results", [])

            findings.append({
                "title": f"{name} [{template_id}]",
                "description": info.get("description", f"Nuclei identified matching signature {template_id} at {matched_at}."),
                "severity": severity,
                "cvss": cvss_score,
                "cwe": cwe_str,
                "category": "Vulnerability Assessment",
                "endpoint": matched_at,
                "impact": "Potential security compromise based on signature definition.",
                "remediation": info.get("remediation", "Apply vendor patch or remove exposed resources."),
                "references": info.get("reference", []),
                "evidence": f"Matched at: {matched_at}. Extracted: {extracted}",
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
                category=item.get("category", "Vulnerability Assessment"),
                asset_target=target,
                endpoint=item.get("endpoint"),
                protocol="HTTP/HTTPS",
                evidence=EvidenceItem(
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
