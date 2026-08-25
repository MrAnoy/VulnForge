"""
VulnForge Pydantic Models and Request/Response Schemas
"""
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, EmailStr, Field, ConfigDict
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


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ==================== Auth & Users ====================
class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    is_active: bool = True


class UserCreate(UserBase):
    password: str = Field(min_length=8)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "UserResponse"


class UserResponse(UserBase):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: datetime
    updated_at: Optional[datetime] = None


# ==================== Organization & Members ====================
class OrganizationBase(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None


class OrganizationCreate(OrganizationBase):
    pass


class OrganizationResponse(OrganizationBase):
    model_config = ConfigDict(from_attributes=True)
    id: str
    owner_id: str
    created_at: datetime
    member_count: int = 1
    project_count: int = 0


class MemberInvite(BaseModel):
    email: EmailStr
    role: Role = Role.SECURITY_ANALYST


class MemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    organization_id: str
    user_id: str
    user_email: str
    user_name: str
    role: Role
    joined_at: datetime


# ==================== Projects ====================
class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None
    client_name: Optional[str] = None
    environment: EnvironmentType = EnvironmentType.PRODUCTION
    tags: List[str] = []


class ProjectCreate(ProjectBase):
    pass


class ProjectResponse(ProjectBase):
    model_config = ConfigDict(from_attributes=True)
    id: str
    organization_id: str
    owner_id: str
    risk_score: float = 0.0
    asset_count: int = 0
    finding_count: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None


# ==================== Assets ====================
class AssetBase(BaseModel):
    target: str
    asset_type: AssetType
    criticality: AssetCriticality = AssetCriticality.HIGH
    environment: EnvironmentType = EnvironmentType.PRODUCTION
    description: Optional[str] = None
    tags: List[str] = []


class AssetCreate(AssetBase):
    pass


class AssetResponse(AssetBase):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    technologies: List[str] = []
    scope_status: ScopeStatus = ScopeStatus.IN_SCOPE
    risk_score: float = 0.0
    first_discovered: datetime
    last_seen: datetime


# ==================== Scope & Authorization ====================
class ScopeRule(BaseModel):
    allowed_targets: List[str]
    excluded_targets: List[str] = []
    allowed_ports: List[int] = []
    excluded_ports: List[int] = []
    allowed_paths: List[str] = []
    excluded_paths: List[str] = []
    rate_limit_rps: int = 20
    max_concurrency: int = 5
    scan_window_hours: int = 4
    allow_local_lab: bool = False


class AuthorizationConfirmation(BaseModel):
    project_id: str
    authorized_by: str
    authorization_statement: str
    target_scope: List[str]
    confirmation_timestamp: datetime = Field(default_factory=get_utc_now)
    confirmed: bool


class ScopeValidationRequest(BaseModel):
    targets: List[str]
    allowed_targets: List[str]
    excluded_targets: List[str] = []
    allow_local_lab: bool = False


class ScopeValidationResult(BaseModel):
    target: str
    in_scope: bool
    resolved_ips: List[str]
    message: str


# ==================== Assessments ====================
class AssessmentCreate(BaseModel):
    project_id: str
    name: str
    profile: AssessmentProfileType = AssessmentProfileType.STANDARD_VAPT
    target_assets: List[str]
    authorization_confirmed: bool = True
    custom_modules: List[str] = []


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: str
    name: str
    profile: AssessmentProfileType
    status: AssessmentStatus
    current_phase: AssessmentPhase
    progress_percent: int = 0
    targets: List[str]
    assets_discovered_count: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    risk_score: float = 0.0
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class LiveLogEvent(BaseModel):
    assessment_id: str
    phase: AssessmentPhase
    level: str
    message: str
    timestamp: str
    progress: int
    is_technical: bool = False


# ==================== Assessment Comparison ====================
class FindingComparisonItem(BaseModel):
    id: str
    title: str
    severity: str
    asset_target: str
    platform_risk_score: float
    status: str


class AssessmentComparisonResponse(BaseModel):
    base_assessment: AssessmentResponse
    target_assessment: AssessmentResponse
    score_delta: float
    critical_delta: int
    high_delta: int
    medium_delta: int
    low_delta: int
    new_findings: List[FindingComparisonItem]
    resolved_findings: List[FindingComparisonItem]
    persistent_findings: List[FindingComparisonItem]
    summary_verdict: str


# ==================== Findings & Prioritization ====================
class EvidenceItem(BaseModel):
    request: Optional[str] = None
    response: Optional[str] = None
    url: Optional[str] = None
    parameter: Optional[str] = None
    headers: Dict[str, Any] = {}
    output_snippet: Optional[str] = None


class FindingBase(BaseModel):
    title: str
    description: str
    severity: Severity
    cvss_score: float = 0.0
    cwe: Optional[str] = None
    category: str
    asset_target: str
    endpoint: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = "HTTP"
    evidence: Optional[EvidenceItem] = None
    impact: str
    remediation: str
    references: List[str] = []
    scanner: str
    confidence: Confidence = Confidence.HIGH
    status: FindingStatus = FindingStatus.OPEN


class FindingCreate(FindingBase):
    assessment_id: str
    project_id: str
    asset_id: Optional[str] = None


class FindingResponse(FindingBase):
    model_config = ConfigDict(from_attributes=True)
    id: str
    assessment_id: str
    project_id: str
    asset_id: Optional[str] = None
    platform_risk_score: float = 0.0
    detected_by_scanners: List[str] = []
    first_seen: datetime
    last_seen: datetime
    remediation_notes: Optional[str] = None
    status_history: List[Dict[str, Any]] = []


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    reason: str
    remediation_notes: Optional[str] = None


class FindingFilter(BaseModel):
    severity: Optional[List[Severity]] = None
    status: Optional[List[FindingStatus]] = None
    asset_id: Optional[str] = None
    scanner: Optional[str] = None
    cwe: Optional[str] = None
    search: Optional[str] = None


class PrioritizedFindingItem(BaseModel):
    finding: FindingResponse
    priority_rank: int
    urgency_level: str
    priority_rationale: str
    recommended_action: str


class PrioritizationResponse(BaseModel):
    project_id: str
    total_findings: int
    top_priority_items: List[PrioritizedFindingItem]
    executive_advice: str


# ==================== Remediation ====================
class RemediationTaskCreate(BaseModel):
    finding_id: str
    title: str
    description: Optional[str] = None
    assignee_id: Optional[str] = None
    due_date: Optional[datetime] = None
    priority: Severity = Severity.MEDIUM


class RemediationTaskResponse(RemediationTaskCreate):
    model_config = ConfigDict(from_attributes=True)
    id: str
    status: FindingStatus = FindingStatus.OPEN
    created_at: datetime
    updated_at: Optional[datetime] = None
    notes: List[Dict[str, Any]] = []


# ==================== Reports & White-Labeling ====================
class WhiteLabelBranding(BaseModel):
    company_name: Optional[str] = "VulnForge Security Services"
    consultant_name: Optional[str] = "Senior Security Architect"
    client_name: Optional[str] = None
    classification: Optional[str] = "CONFIDENTIAL"
    logo_url: Optional[str] = None
    accent_color: Optional[str] = "#3b82f6"


class ReportGenerateRequest(BaseModel):
    assessment_id: str
    report_type: ReportType = ReportType.EXECUTIVE
    report_format: ReportFormat = ReportFormat.HTML
    title: Optional[str] = None
    include_evidence: bool = True
    executive_summary_override: Optional[str] = None
    branding: Optional[WhiteLabelBranding] = None


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    assessment_id: str
    project_id: str
    title: str
    report_type: ReportType
    report_format: ReportFormat
    file_path: Optional[str] = None
    download_url: Optional[str] = None
    created_at: datetime
    security_score: float
    summary: Dict[str, Any]


# ==================== Schedules ====================
class ScheduleCreate(BaseModel):
    project_id: str
    name: str
    profile: AssessmentProfileType = AssessmentProfileType.STANDARD_VAPT
    frequency: str = "WEEKLY"  # "DAILY", "WEEKLY", "MONTHLY"
    targets: List[str] = []
    is_active: bool = True


class ScheduleResponse(ScheduleCreate):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: datetime
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None


# ==================== AI Copilot ====================
class AICopilotChatRequest(BaseModel):
    project_id: str
    assessment_id: Optional[str] = None
    finding_id: Optional[str] = None
    message: str
    chat_history: List[Dict[str, str]] = []


class AICopilotChatResponse(BaseModel):
    answer: str
    suggested_actions: List[str] = []
    referenced_findings: List[str] = []


class AIFindingExplanationRequest(BaseModel):
    finding_id: str


class AIFindingExplanationResponse(BaseModel):
    finding_id: str
    plain_english_summary: str
    business_impact: str
    developer_fix_guide: str
    code_examples: Optional[str] = None


# ==================== System Observability & Health ====================
class ScannerHealth(BaseModel):
    name: str
    available: bool
    version: Optional[str] = None
    details: str
    capabilities: List[str] = []


class SubsystemDiagnostic(BaseModel):
    name: str
    status: str  # "HEALTHY", "DEGRADED", "STANDBY", "UNAVAILABLE"
    latency_ms: Optional[float] = 0.0
    details: str
    version: Optional[str] = None


class SystemHealthResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime
    subsystems: List[SubsystemDiagnostic]


# ==================== API Keys & Webhooks ====================
class ApiKeyCreate(BaseModel):
    name: str
    role: Role = Role.SECURITY_ANALYST


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_preview: str
    role: Role
    created_at: datetime
    last_used: Optional[datetime] = None
    raw_key: Optional[str] = None


class WebhookCreate(BaseModel):
    url: str
    events: List[str]
    secret: Optional[str] = None


class WebhookResponse(BaseModel):
    id: str
    organization_id: str
    url: str
    events: List[str]
    is_active: bool
    created_at: datetime
