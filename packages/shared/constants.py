"""
VulnForge Shared Constants and Enums
"""
from enum import Enum


class Role(str, Enum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    VIEWER = "VIEWER"


class EnvironmentType(str, Enum):
    DEVELOPMENT = "Development"
    STAGING = "Staging"
    PRODUCTION = "Production"
    INTERNAL = "Internal"
    EXTERNAL = "External"


class AssetType(str, Enum):
    DOMAIN = "DOMAIN"
    URL = "URL"
    IP = "IP"
    CIDR = "CIDR"
    API_ENDPOINT = "API_ENDPOINT"


class AssetCriticality(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class ScopeStatus(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    EXCLUDED = "EXCLUDED"
    PENDING_VALIDATION = "PENDING_VALIDATION"


class AssessmentProfileType(str, Enum):
    QUICK_SCAN = "QUICK_SCAN"
    STANDARD_VAPT = "STANDARD_VAPT"
    WEB_APPLICATION = "WEB_APPLICATION"
    API_ASSESSMENT = "API_ASSESSMENT"
    NETWORK_ASSESSMENT = "NETWORK_ASSESSMENT"
    DEEP_ASSESSMENT = "DEEP_ASSESSMENT"
    CUSTOM = "CUSTOM"


class AssessmentStatus(str, Enum):
    DRAFT = "DRAFT"
    AUTHORIZED = "AUTHORIZED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class AssessmentPhase(str, Enum):
    INITIALIZING = "INITIALIZING"
    SCOPE_VALIDATION = "SCOPE_VALIDATION"
    RECON = "RECON"
    DISCOVERY = "DISCOVERY"
    ASSESSMENT = "ASSESSMENT"
    CORRELATION = "CORRELATION"
    RISK_ANALYSIS = "RISK_ANALYSIS"
    REPORT_PREPARATION = "REPORT_PREPARATION"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Confidence(str, Enum):
    CONFIRMED = "Confirmed"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    POTENTIAL = "Potential"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    SUPPRESSED = "SUPPRESSED"


class ScannerType(str, Enum):
    RECON = "Recon Engine"
    CUSTOM_WEB = "Custom Web Security Checks"
    NMAP = "Nmap Network Scanner"
    NUCLEI = "Nuclei Template Scanner"
    ZAP = "OWASP ZAP Scanner"


class ReportFormat(str, Enum):
    PDF = "PDF"
    HTML = "HTML"
    JSON = "JSON"
    CSV = "CSV"
    MARKDOWN = "MARKDOWN"


class ReportType(str, Enum):
    EXECUTIVE = "EXECUTIVE"
    TECHNICAL = "TECHNICAL"
    DEVELOPER = "DEVELOPER"
