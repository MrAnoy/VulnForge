"""
VulnForge Scan Orchestrator & Execution Pipeline
Executes multi-phase security assessments with live logging, scope enforcement,
finding correlation, and transparent risk scoring.
"""
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any, Callable
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from apps.api.core.database import AsyncSessionLocal
from apps.api.core.models import Assessment, AssessmentLog, Finding, Project, Asset, ScopeRule
from packages.scanner.recon_adapter import ReconAdapter
from packages.scanner.custom_web_adapter import CustomWebAdapter
from packages.scanner.nmap_adapter import NmapAdapter
from packages.scanner.nuclei_adapter import NucleiAdapter
from packages.scanner.zap_adapter import ZapAdapter
from apps.api.services.scope_service import ScopeService
from apps.api.services.finding_service import FindingService
from apps.api.services.risk_service import RiskEngine
from packages.schemas.models import FindingBase
from packages.shared.constants import (
    AssessmentStatus,
    AssessmentPhase,
    AssessmentProfileType,
    Severity,
    FindingStatus,
)
from packages.shared.logging import logger

# Active SSE listeners mapping: assessment_id -> list of asyncio.Queue
active_log_listeners: Dict[str, List[asyncio.Queue]] = {}


class ScanOrchestrator:
    @staticmethod
    def register_listener(assessment_id: str, queue: asyncio.Queue):
        if assessment_id not in active_log_listeners:
            active_log_listeners[assessment_id] = []
        active_log_listeners[assessment_id].append(queue)

    @staticmethod
    def unregister_listener(assessment_id: str, queue: asyncio.Queue):
        if assessment_id in active_log_listeners:
            active_log_listeners[assessment_id] = [q for q in active_log_listeners[assessment_id] if q != queue]
            if not active_log_listeners[assessment_id]:
                del active_log_listeners[assessment_id]

    @classmethod
    async def broadcast_log(
        cls,
        db: AsyncSession,
        assessment_id: str,
        phase: AssessmentPhase,
        level: str,
        message: str,
        progress: int,
        is_technical: bool = False
    ):
        """Save log entry in database and broadcast to live subscribers."""
        log_entry = AssessmentLog(
            assessment_id=assessment_id,
            phase=phase,
            level=level,
            message=message,
            progress=progress,
            is_technical=is_technical,
            timestamp=datetime.now(timezone.utc)
        )
        db.add(log_entry)
        await db.commit()

        event_payload = {
            "assessment_id": assessment_id,
            "phase": phase.value,
            "level": level,
            "message": message,
            "progress": progress,
            "is_technical": is_technical,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Broadcast to active SSE queues
        if assessment_id in active_log_listeners:
            for q in active_log_listeners[assessment_id]:
                await q.put(event_payload)

    @classmethod
    async def run_assessment_lifecycle(cls, assessment_id: str):
        """
        Main end-to-end execution flow for an authorized security assessment.
        """
        async with AsyncSessionLocal() as db:
            # 1. Fetch assessment and related project
            res = await db.execute(select(Assessment).where(Assessment.id == assessment_id))
            assessment = res.scalar_one_or_none()
            if not assessment:
                logger.error(f"Assessment {assessment_id} not found.")
                return

            proj_res = await db.execute(select(Project).where(Project.id == assessment.project_id))
            project = proj_res.scalar_one()

            scope_res = await db.execute(select(ScopeRule).where(ScopeRule.project_id == project.id))
            scope_rule = scope_res.scalar_one_or_none()

            # Initialize
            assessment.status = AssessmentStatus.RUNNING
            assessment.current_phase = AssessmentPhase.INITIALIZING
            assessment.started_at = datetime.now(timezone.utc)
            assessment.progress_percent = 5
            await db.commit()

            await cls.broadcast_log(
                db, assessment_id, AssessmentPhase.INITIALIZING, "INFO",
                f"Starting assessment '{assessment.name}' with profile '{assessment.profile.value}'",
                progress=5
            )

            targets = assessment.targets or []
            if not targets:
                # Use project assets as fallback
                asset_res = await db.execute(select(Asset).where(Asset.project_id == project.id))
                assets = asset_res.scalars().all()
                targets = [a.target for a in assets]
                assessment.targets = targets
                await db.commit()

            if not targets:
                assessment.status = AssessmentStatus.FAILED
                assessment.error_message = "No target assets specified for assessment."
                await db.commit()
                await cls.broadcast_log(db, assessment_id, AssessmentPhase.FAILED, "ERROR", "No target assets defined in scope.", 100)
                return

            # ================= PHASE 1: SCOPE VALIDATION =================
            assessment.current_phase = AssessmentPhase.SCOPE_VALIDATION
            assessment.progress_percent = 15
            await db.commit()

            await cls.broadcast_log(
                db, assessment_id, AssessmentPhase.SCOPE_VALIDATION, "INFO",
                f"Validating {len(targets)} target(s) against scope policy and SSRF restrictions...",
                progress=15
            )

            allowed = scope_rule.allowed_targets if scope_rule and scope_rule.allowed_targets else targets
            excluded = scope_rule.excluded_targets if scope_rule else []
            allow_local = scope_rule.allow_local_lab if scope_rule else True

            validated_targets = []
            for t in targets:
                val_res = ScopeService.validate_target_scope(
                    target=t,
                    allowed_targets=allowed,
                    excluded_targets=excluded,
                    allow_local_lab=allow_local
                )
                if not val_res.in_scope:
                    await cls.broadcast_log(
                        db, assessment_id, AssessmentPhase.SCOPE_VALIDATION, "WARNING",
                        f"Target '{t}' excluded from scan: {val_res.message}",
                        progress=18
                    )
                else:
                    validated_targets.append(t)
                    await cls.broadcast_log(
                        db, assessment_id, AssessmentPhase.SCOPE_VALIDATION, "INFO",
                        f"Authorized target confirmed: '{t}' (Resolved: {', '.join(val_res.resolved_ips)})",
                        progress=20
                    )

            if not validated_targets:
                assessment.status = AssessmentStatus.FAILED
                assessment.error_message = "All targets failed scope validation or authorization policies."
                await db.commit()
                await cls.broadcast_log(db, assessment_id, AssessmentPhase.FAILED, "ERROR", "All targets rejected by scope engine.", 100)
                return

            raw_findings: List[FindingBase] = []

            # ================= PHASE 2: RECONNAISSANCE =================
            assessment.current_phase = AssessmentPhase.RECON
            assessment.progress_percent = 30
            await db.commit()

            recon = ReconAdapter()
            for t in validated_targets:
                await cls.broadcast_log(
                    db, assessment_id, AssessmentPhase.RECON, "INFO",
                    f"Gathering OSINT, DNS records, TLS certificates, and HTTP headers for {t}...",
                    progress=30
                )
                try:
                    recon_raw = await recon.execute(t, {"timeout": 10})
                    recon_parsed = await recon.parse(recon_raw)
                    recon_norm = await recon.normalize(recon_parsed, t)
                    raw_findings.extend(recon_norm)
                    await cls.broadcast_log(
                        db, assessment_id, AssessmentPhase.RECON, "INFO",
                        f"Recon complete for {t}. Identified {len(recon_norm)} preliminary issue(s).",
                        progress=40
                    )
                except Exception as e:
                    logger.error(f"Recon failed for {t}: {e}")
                    await cls.broadcast_log(db, assessment_id, AssessmentPhase.RECON, "WARNING", f"Recon warning for {t}: {str(e)}", 40)

            # ================= PHASE 3: DISCOVERY & NETWORK =================
            assessment.current_phase = AssessmentPhase.DISCOVERY
            assessment.progress_percent = 50
            await db.commit()

            if assessment.profile in [AssessmentProfileType.STANDARD_VAPT, AssessmentProfileType.NETWORK_ASSESSMENT, AssessmentProfileType.DEEP_ASSESSMENT]:
                nmap = NmapAdapter()
                for t in validated_targets:
                    await cls.broadcast_log(
                        db, assessment_id, AssessmentPhase.DISCOVERY, "INFO",
                        f"Performing network service and port discovery on {t}...",
                        progress=50
                    )
                    try:
                        nmap_raw = await nmap.execute(t, {"timeout": 60})
                        if nmap_raw.get("available"):
                            nmap_parsed = await nmap.parse(nmap_raw)
                            nmap_norm = await nmap.normalize(nmap_parsed, t)
                            raw_findings.extend(nmap_norm)
                            await cls.broadcast_log(
                                db, assessment_id, AssessmentPhase.DISCOVERY, "INFO",
                                f"Service discovery completed for {t}. Found {len(nmap_norm)} network service item(s).",
                                progress=60
                            )
                        else:
                            await cls.broadcast_log(
                                db, assessment_id, AssessmentPhase.DISCOVERY, "INFO",
                                "Nmap binary not installed on host. Proceeding with application layer checks.",
                                progress=60
                            )
                    except Exception as e:
                        logger.error(f"Network discovery error for {t}: {e}")

            # ================= PHASE 4: SECURITY ASSESSMENT =================
            assessment.current_phase = AssessmentPhase.ASSESSMENT
            assessment.progress_percent = 70
            await db.commit()

            # Custom Web Checks
            custom_web = CustomWebAdapter()
            for t in validated_targets:
                await cls.broadcast_log(
                    db, assessment_id, AssessmentPhase.ASSESSMENT, "INFO",
                    f"Executing web vulnerability checks (Headers, Cookies, CORS, Methods, Sensitive endpoints) on {t}...",
                    progress=70
                )
                try:
                    cw_raw = await custom_web.execute(t, {"timeout": 15})
                    cw_parsed = await custom_web.parse(cw_raw)
                    cw_norm = await custom_web.normalize(cw_parsed, t)
                    raw_findings.extend(cw_norm)
                    await cls.broadcast_log(
                        db, assessment_id, AssessmentPhase.ASSESSMENT, "INFO",
                        f"Custom Web checks complete for {t}. Identified {len(cw_norm)} finding(s).",
                        progress=75
                    )
                except Exception as e:
                    logger.error(f"Web check error for {t}: {e}")

            # Nuclei Checks (if available)
            nuclei = NucleiAdapter()
            if nuclei.is_available():
                for t in validated_targets:
                    await cls.broadcast_log(
                        db, assessment_id, AssessmentPhase.ASSESSMENT, "INFO",
                        f"Executing Nuclei template vulnerability scans on {t}...",
                        progress=80
                    )
                    try:
                        nuc_raw = await nuclei.execute(t, {"timeout": 120})
                        nuc_parsed = await nuclei.parse(nuc_raw)
                        nuc_norm = await nuclei.normalize(nuc_parsed, t)
                        raw_findings.extend(nuc_norm)
                    except Exception as e:
                        logger.error(f"Nuclei error: {e}")

            # ================= PHASE 5: CORRELATION & DEDUPLICATION =================
            assessment.current_phase = AssessmentPhase.CORRELATION
            assessment.progress_percent = 85
            await db.commit()

            await cls.broadcast_log(
                db, assessment_id, AssessmentPhase.CORRELATION, "INFO",
                f"Normalizing, cross-correlating, and deduplicating {len(raw_findings)} raw scanner finding(s)...",
                progress=85
            )

            unique_findings = FindingService.deduplicate_and_correlate(raw_findings)

            # ================= PHASE 6: RISK ANALYSIS =================
            assessment.current_phase = AssessmentPhase.RISK_ANALYSIS
            assessment.progress_percent = 92
            await db.commit()

            await cls.broadcast_log(
                db, assessment_id, AssessmentPhase.RISK_ANALYSIS, "INFO",
                "Computing contextual Platform Risk Scores and evaluating overall Security Posture...",
                progress=92
            )

            # Save findings into database
            crit_c = 0
            high_c = 0
            med_c = 0
            low_c = 0
            info_c = 0

            for f in unique_findings:
                risk_val = RiskEngine.calculate_finding_risk_score(
                    severity=f.severity,
                    cvss_score=f.cvss_score,
                    environment=project.environment,
                    confidence=f.confidence
                )
                
                db_finding = Finding(
                    project_id=project.id,
                    assessment_id=assessment.id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    cvss_score=f.cvss_score,
                    cwe=f.cwe,
                    category=f.category,
                    asset_target=f.asset_target,
                    endpoint=f.endpoint,
                    port=f.port,
                    protocol=f.protocol,
                    evidence=f.evidence.dict() if f.evidence else {},
                    impact=f.impact,
                    remediation=f.remediation,
                    references=f.references,
                    scanner=f.scanner,
                    detected_by_scanners=[f.scanner],
                    confidence=f.confidence,
                    status=FindingStatus.OPEN,
                    platform_risk_score=risk_val,
                )
                db.add(db_finding)

                if f.severity == Severity.CRITICAL:
                    crit_c += 1
                elif f.severity == Severity.HIGH:
                    high_c += 1
                elif f.severity == Severity.MEDIUM:
                    med_c += 1
                elif f.severity == Severity.LOW:
                    low_c += 1
                else:
                    info_c += 1

            # Update project & assessment overall scores
            security_score = RiskEngine.calculate_security_score(unique_findings)
            assessment.risk_score = security_score
            project.risk_score = security_score
            
            assessment.findings_count = len(unique_findings)
            assessment.critical_count = crit_c
            assessment.high_count = high_c
            assessment.medium_count = med_c
            assessment.low_count = low_c
            assessment.info_count = info_c

            # ================= PHASE 7: REPORT PREPARATION & COMPLETION =================
            assessment.current_phase = AssessmentPhase.COMPLETED
            assessment.status = AssessmentStatus.COMPLETED
            assessment.progress_percent = 100
            assessment.completed_at = datetime.now(timezone.utc)
            await db.commit()

            await cls.broadcast_log(
                db, assessment_id, AssessmentPhase.COMPLETED, "INFO",
                f"Assessment successfully completed. Discovered {len(unique_findings)} unique finding(s). Security Posture Score: {security_score}/100.",
                progress=100
            )
