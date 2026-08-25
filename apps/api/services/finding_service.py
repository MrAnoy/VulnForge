"""
VulnForge Finding Deduplication & Correlation Engine
Correlates findings across multiple scanners to prevent duplicates and present a unified security view.
"""
import re
import hashlib
from typing import List, Dict
from packages.schemas.models import FindingBase, EvidenceItem
from packages.shared.constants import Severity, Confidence
from packages.shared.logging import logger


class FindingService:
    KNOWN_TOPICS = [
        ("content security policy", "csp"),
        ("strict transport security", "hsts"),
        ("clickjacking", "clickjacking"),
        ("x-frame-options", "clickjacking"),
        ("x-content-type-options", "nosniff"),
        ("cors", "cors"),
        ("cross-origin", "cors"),
        (".git", "git-exposure"),
        (".env", "env-exposure"),
        ("cookie", "insecure-cookie"),
        ("trace", "http-trace"),
    ]

    @classmethod
    def extract_semantic_topic(cls, title: str, cwe: str) -> str:
        t_low = title.lower()
        for phrase, topic in cls.KNOWN_TOPICS:
            if phrase in t_low:
                return topic
        if cwe and cwe.upper() != "CWE-200":
            return cwe.upper()
        # Fallback to normalized alphanumeric title
        cleaned = re.sub(r'\[.*?\]', '', title).strip().lower()
        return re.sub(r'[^a-z0-9]', '', cleaned)

    @classmethod
    def generate_fingerprint(cls, finding: FindingBase) -> str:
        """
        Generate a unique correlation fingerprint for a finding.
        Normalizes titles, CWEs, endpoints, and targets.
        """
        norm_target = finding.asset_target.lower().strip()
        norm_endpoint = (finding.endpoint or "/").lower().strip()
        topic = cls.extract_semantic_topic(finding.title, finding.cwe or "")

        key = f"{norm_target}:{norm_endpoint}:{topic}"
        return hashlib.sha256(key.encode()).hexdigest()

    @classmethod
    def deduplicate_and_correlate(cls, findings: List[FindingBase]) -> List[FindingBase]:
        """
        Correlate and merge duplicate findings discovered by different scanner modules.
        """
        if not findings:
            return []

        severity_rank = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFORMATIONAL: 1
        }

        confidence_rank = {
            Confidence.CONFIRMED: 5,
            Confidence.HIGH: 4,
            Confidence.MEDIUM: 3,
            Confidence.LOW: 2,
            Confidence.POTENTIAL: 1
        }

        merged_map: Dict[str, FindingBase] = {}
        scanner_tracker: Dict[str, List[str]] = {}

        for f in findings:
            fp = cls.generate_fingerprint(f)
            
            if fp not in merged_map:
                merged_map[fp] = f
                scanner_tracker[fp] = [f.scanner]
            else:
                existing = merged_map[fp]
                
                # Track discovering scanner
                if f.scanner not in scanner_tracker[fp]:
                    scanner_tracker[fp].append(f.scanner)
                
                # Select highest severity
                if severity_rank.get(f.severity, 0) > severity_rank.get(existing.severity, 0):
                    existing.severity = f.severity
                    existing.cvss_score = max(existing.cvss_score, f.cvss_score)

                # Select highest confidence
                if confidence_rank.get(f.confidence, 0) > confidence_rank.get(existing.confidence, 0):
                    existing.confidence = f.confidence

                # Merge references
                for ref in f.references:
                    if ref not in existing.references:
                        existing.references.append(ref)

                # Merge evidence
                if f.evidence and f.evidence.output_snippet:
                    if existing.evidence and existing.evidence.output_snippet:
                        if f.evidence.output_snippet not in existing.evidence.output_snippet:
                            existing.evidence.output_snippet += f"\n---\n[{f.scanner}]: {f.evidence.output_snippet}"
                    else:
                        existing.evidence = f.evidence

        # Finalize merged results
        result = []
        for fp, finding in merged_map.items():
            scanners = scanner_tracker[fp]
            if len(scanners) > 1:
                finding.scanner = f"Correlated ({', '.join(scanners)})"
            result.append(finding)

        logger.info(f"Deduplicated findings: {len(findings)} incoming -> {len(result)} unique correlated issues.")
        return result
