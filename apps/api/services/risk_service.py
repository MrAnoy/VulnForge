"""
VulnForge Transparent Risk Scoring Engine
Calculates Platform Risk Scores (0-100) and Overall Project Security Scores (0-100).
Clearly separates industry CVSS scores from contextualized Platform Risk Scores.
"""
from typing import List
from packages.schemas.models import FindingBase
from packages.shared.constants import (
    Severity,
    AssetCriticality,
    EnvironmentType,
    Confidence,
)


class RiskEngine:
    SEVERITY_BASE_WEIGHTS = {
        Severity.CRITICAL: 85.0,
        Severity.HIGH: 65.0,
        Severity.MEDIUM: 40.0,
        Severity.LOW: 15.0,
        Severity.INFORMATIONAL: 0.0,
    }

    CRITICALITY_MULTIPLIERS = {
        AssetCriticality.CRITICAL: 1.25,
        AssetCriticality.HIGH: 1.10,
        AssetCriticality.MEDIUM: 1.00,
        AssetCriticality.LOW: 0.80,
    }

    ENVIRONMENT_MULTIPLIERS = {
        EnvironmentType.PRODUCTION: 1.20,
        EnvironmentType.EXTERNAL: 1.20,
        EnvironmentType.STAGING: 0.95,
        EnvironmentType.DEVELOPMENT: 0.80,
        EnvironmentType.INTERNAL: 0.85,
    }

    CONFIDENCE_FACTORS = {
        Confidence.CONFIRMED: 1.00,
        Confidence.HIGH: 0.95,
        Confidence.MEDIUM: 0.80,
        Confidence.LOW: 0.60,
        Confidence.POTENTIAL: 0.40,
    }

    @classmethod
    def calculate_finding_risk_score(
        cls,
        severity: Severity,
        cvss_score: float,
        criticality: AssetCriticality = AssetCriticality.HIGH,
        environment: EnvironmentType = EnvironmentType.PRODUCTION,
        confidence: Confidence = Confidence.HIGH
    ) -> float:
        """
        Calculate contextual Platform Risk Score (0 - 100).
        Formula incorporates:
        - Base Severity (0 - 85)
        - CVSS Boost (up to +15 pts based on CVSS / 10)
        - Asset Criticality Multiplier
        - Environment Exposure Multiplier
        - Confidence Weighting
        """
        base = cls.SEVERITY_BASE_WEIGHTS.get(severity, 20.0)
        cvss_boost = (cvss_score / 10.0) * 15.0 if cvss_score > 0 else 0.0
        raw_score = base + cvss_boost

        # Apply modifiers
        crit_mult = cls.CRITICALITY_MULTIPLIERS.get(criticality, 1.0)
        env_mult = cls.ENVIRONMENT_MULTIPLIERS.get(environment, 1.0)
        conf_factor = cls.CONFIDENCE_FACTORS.get(confidence, 1.0)

        final_score = raw_score * crit_mult * env_mult * conf_factor

        # Bound score between 0.0 and 100.0
        return round(min(100.0, max(0.0, final_score)), 1)

    @classmethod
    def calculate_security_score(cls, findings: List[FindingBase]) -> float:
        """
        Calculate the overall Security Posture Score (0 - 100) where 100 = Perfect posture.
        Deducts points based on open finding severity and count.
        """
        if not findings:
            return 100.0

        total_penalty = 0.0
        for f in findings:
            if f.severity == Severity.CRITICAL:
                total_penalty += 20.0
            elif f.severity == Severity.HIGH:
                total_penalty += 10.0
            elif f.severity == Severity.MEDIUM:
                total_penalty += 4.0
            elif f.severity == Severity.LOW:
                total_penalty += 1.0

        security_score = max(0.0, 100.0 - total_penalty)
        return round(security_score, 1)
