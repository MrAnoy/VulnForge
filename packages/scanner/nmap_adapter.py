"""
VulnForge Nmap Network Scanner Adapter
Safe, controlled Nmap network & service detection with zero shell execution and strict argument arrays.
"""
import shutil
import xml.etree.ElementTree as ET
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


class NmapAdapter(BaseScannerAdapter):
    scanner_type = ScannerType.NMAP
    name = "Nmap Network Scanner"

    RISKY_SERVICES = {
        21: ("FTP Service Exposed", "Unencrypted FTP service running. Credentials may be intercepted.", Severity.MEDIUM, "CWE-319", 5.3),
        23: ("Telnet Service Exposed", "Insecure legacy Telnet protocol in cleartext.", Severity.HIGH, "CWE-319", 7.5),
        3389: ("RDP Remote Desktop Port Exposed", "RDP exposed to the internet increases brute-force risks.", Severity.MEDIUM, "CWE-284", 5.0),
        6379: ("Redis Database Port Exposed", "Redis instance exposed. If unauthenticated, allows arbitrary data access and RCE.", Severity.HIGH, "CWE-306", 8.2),
        27017: ("MongoDB Database Port Exposed", "MongoDB database port accessible directly.", Severity.HIGH, "CWE-306", 8.2),
        9200: ("Elasticsearch Cluster Exposed", "Elasticsearch REST interface exposed directly.", Severity.HIGH, "CWE-306", 8.2),
    }

    def is_available(self) -> bool:
        return shutil.which(settings.NMAP_PATH or "nmap") is not None

    def get_version(self) -> Optional[str]:
        if not self.is_available():
            return None
        return "Nmap Network Engine"

    async def validate(self, target: str, options: Dict[str, Any]) -> bool:
        host, _, _ = SSRFGuard.normalize_target(target)
        return bool(host)

    async def prepare(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        host, _, _ = SSRFGuard.normalize_target(target)
        ports = options.get("ports", "21,22,23,25,80,443,3306,3389,5432,6379,8000,8080,8443,27017")
        return {
            "host": host,
            "ports": ports,
            "timeout": options.get("timeout", 180),
        }

    async def execute(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        if not self.is_available():
            logger.info("Nmap binary not found. Skipping Nmap execution.")
            return {"available": False, "target": target, "services": []}

        context = await self.prepare(target, options)
        host = context["host"]
        ports = context["ports"]
        timeout = context["timeout"]

        # Safe argument vector (zero shell expansion)
        args = [
            settings.NMAP_PATH or "nmap",
            "-sT",                   # Safe TCP Connect Scan (no root raw socket needed)
            "-sV",                   # Service Version Detection
            "--version-intensity", "2",
            "-Pn",                   # Treat host as online
            "-p", ports,             # Scoped ports
            "-oX", "-",              # Output XML to stdout
            "--open",                # Only show open ports
            host
        ]

        try:
            return_code, stdout, stderr = await CommandSafety.run_safe_command(args, timeout=timeout)
            return {
                "available": True,
                "target": target,
                "host": host,
                "xml_output": stdout,
                "stderr": stderr
            }
        except Exception as e:
            logger.error(f"Nmap execution error for {target}: {str(e)}")
            return {"available": True, "target": target, "host": host, "error": str(e), "services": []}

    async def parse(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        if not raw_results.get("available") or not raw_results.get("xml_output"):
            return findings

        xml_data = raw_results["xml_output"]
        host = raw_results.get("host", "")

        try:
            root = ET.fromstring(xml_data)
            for host_el in root.findall("host"):
                ports_el = host_el.find("ports")
                if ports_el is None:
                    continue

                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue

                    port_id = int(port_el.get("portid", 0))
                    proto = port_el.get("protocol", "tcp").upper()
                    service_el = port_el.find("service")
                    
                    service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                    product = service_el.get("product", "") if service_el is not None else ""
                    version = service_el.get("version", "") if service_el is not None else ""
                    extra_info = service_el.get("extrainfo", "") if service_el is not None else ""

                    banner = f"{product} {version} {extra_info}".strip() or service_name

                    # 1. Generic open port informational finding
                    findings.append({
                        "title": f"Exposed Service Detected on Port {port_id}/{proto} ({service_name})",
                        "description": f"Port {port_id}/{proto} is open on {host}. Detected service: {banner}.",
                        "severity": Severity.INFORMATIONAL,
                        "cvss": 0.0,
                        "cwe": "CWE-200",
                        "category": "Network Service Enumeration",
                        "port": port_id,
                        "protocol": proto,
                        "impact": "Expands the network attack surface.",
                        "remediation": "Restrict port access using network firewall rules if public exposure is unnecessary.",
                        "evidence": f"Port {port_id}/{proto} open. Service banner: {banner}",
                    })

                    # 2. Risky services checks
                    if port_id in self.RISKY_SERVICES:
                        rtitle, rdesc, rsev, rcwe, rcvss = self.RISKY_SERVICES[port_id]
                        findings.append({
                            "title": rtitle,
                            "description": f"{rdesc} Host: {host}:{port_id}.",
                            "severity": rsev,
                            "cvss": rcvss,
                            "cwe": rcwe,
                            "category": "Insecure Network Service",
                            "port": port_id,
                            "protocol": proto,
                            "impact": "Potential credential interception or unauthorized administrative access.",
                            "remediation": f"Disable or restrict port {port_id} behind a VPN or firewall allowlist.",
                            "evidence": f"Service identified on port {port_id}: {banner}",
                        })
        except Exception as e:
            logger.error(f"Error parsing Nmap XML output: {e}")

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
                category=item.get("category", "Network Security"),
                asset_target=target,
                port=item.get("port"),
                protocol=item.get("protocol", "TCP"),
                evidence=EvidenceItem(
                    output_snippet=item.get("evidence"),
                ),
                impact=item["impact"],
                remediation=item["remediation"],
                references=["https://nmap.org/book/man.html"],
                scanner=self.name,
                confidence=Confidence.CONFIRMED,
                status=FindingStatus.OPEN,
            ))
        return findings
