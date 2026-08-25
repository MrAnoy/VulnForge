"""
VulnForge SQLAlchemy ORM Models
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Float,
    Text,
    Enum as SQLEnum,
    JSON,
)
from sqlalchemy.orm import relationship
from apps.api.core.database import Base
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


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    memberships = relationship("OrganizationMember", back_populates="user", cascade="all, delete-orphan")


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
    projects = relationship("Project", back_populates="organization", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="organization", cascade="all, delete-orphan")
    webhooks = relationship("Webhook", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")


class OrganizationMember(Base):
    __tablename__ = "organization_members"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    role = Column(SQLEnum(Role), default=Role.SECURITY_ANALYST, nullable=False)
    joined_at = Column(DateTime(timezone=True), default=utc_now)

    organization = relationship("Organization", back_populates="members")
    user = relationship("User", back_populates="memberships")


class Project(Base):
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    client_name = Column(String(255), nullable=True)
    environment = Column(SQLEnum(EnvironmentType), default=EnvironmentType.PRODUCTION, nullable=False)
    tags = Column(JSON, default=list)
    risk_score = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization = relationship("Organization", back_populates="projects")
    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan")
    assessments = relationship("Assessment", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    scope_rules = relationship("ScopeRule", back_populates="project", cascade="all, delete-orphan")
    schedules = relationship("Schedule", back_populates="project", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    target = Column(String(512), nullable=False, index=True)
    asset_type = Column(SQLEnum(AssetType), nullable=False)
    criticality = Column(SQLEnum(AssetCriticality), default=AssetCriticality.HIGH, nullable=False)
    environment = Column(SQLEnum(EnvironmentType), default=EnvironmentType.PRODUCTION, nullable=False)
    description = Column(Text, nullable=True)
    tags = Column(JSON, default=list)
    
    # Discovery fields
    hostname = Column(String(255), nullable=True)
    ip_address = Column(String(128), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(32), nullable=True)
    service = Column(String(128), nullable=True)
    technologies = Column(JSON, default=list)
    scope_status = Column(SQLEnum(ScopeStatus), default=ScopeStatus.IN_SCOPE, nullable=False)
    risk_score = Column(Float, default=0.0)
    first_discovered = Column(DateTime(timezone=True), default=utc_now)
    last_seen = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    project = relationship("Project", back_populates="assets")


class ScopeRule(Base):
    __tablename__ = "scope_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    allowed_targets = Column(JSON, default=list)
    excluded_targets = Column(JSON, default=list)
    allowed_ports = Column(JSON, default=list)
    excluded_ports = Column(JSON, default=list)
    allowed_paths = Column(JSON, default=list)
    excluded_paths = Column(JSON, default=list)
    rate_limit_rps = Column(Integer, default=20)
    max_concurrency = Column(Integer, default=5)
    scan_window_hours = Column(Integer, default=4)
    allow_local_lab = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    project = relationship("Project", back_populates="scope_rules")


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    profile = Column(SQLEnum(AssessmentProfileType), default=AssessmentProfileType.STANDARD_VAPT, nullable=False)
    status = Column(SQLEnum(AssessmentStatus), default=AssessmentStatus.DRAFT, nullable=False)
    current_phase = Column(SQLEnum(AssessmentPhase), default=AssessmentPhase.INITIALIZING, nullable=False)
    progress_percent = Column(Integer, default=0)
    targets = Column(JSON, default=list)
    custom_modules = Column(JSON, default=list)
    
    # Counts and metrics
    assets_discovered_count = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    
    created_at = Column(DateTime(timezone=True), default=utc_now)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    project = relationship("Project", back_populates="assessments")
    findings = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")
    logs = relationship("AssessmentLog", back_populates="assessment", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="assessment", cascade="all, delete-orphan")


class AssessmentLog(Base):
    __tablename__ = "assessment_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id"), nullable=False)
    phase = Column(SQLEnum(AssessmentPhase), nullable=False)
    level = Column(String(32), default="INFO")
    message = Column(Text, nullable=False)
    progress = Column(Integer, default=0)
    is_technical = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), default=utc_now)

    assessment = relationship("Assessment", back_populates="logs")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    assessment_id = Column(String(36), ForeignKey("assessments.id"), nullable=False)
    asset_id = Column(String(36), ForeignKey("assets.id"), nullable=True)
    
    title = Column(String(512), nullable=False, index=True)
    description = Column(Text, nullable=False)
    severity = Column(SQLEnum(Severity), nullable=False)
    cvss_score = Column(Float, default=0.0)
    cwe = Column(String(64), nullable=True)
    category = Column(String(128), nullable=False)
    asset_target = Column(String(512), nullable=False)
    endpoint = Column(String(512), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(32), default="HTTP")
    
    evidence = Column(JSON, default=dict)
    impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    references = Column(JSON, default=list)
    scanner = Column(String(128), nullable=False)
    detected_by_scanners = Column(JSON, default=list)
    confidence = Column(SQLEnum(Confidence), default=Confidence.HIGH, nullable=False)
    status = Column(SQLEnum(FindingStatus), default=FindingStatus.OPEN, nullable=False)
    platform_risk_score = Column(Float, default=0.0)
    
    first_seen = Column(DateTime(timezone=True), default=utc_now)
    last_seen = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    remediation_notes = Column(Text, nullable=True)
    status_history = Column(JSON, default=list)

    project = relationship("Project", back_populates="findings")
    assessment = relationship("Assessment", back_populates="findings")
    remediation_tasks = relationship("RemediationTask", back_populates="finding", cascade="all, delete-orphan")


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    assignee_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    status = Column(SQLEnum(FindingStatus), default=FindingStatus.OPEN, nullable=False)
    priority = Column(SQLEnum(Severity), default=Severity.MEDIUM, nullable=False)
    due_date = Column(DateTime(timezone=True), nullable=True)
    notes = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    finding = relationship("Finding", back_populates="remediation_tasks")


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id"), nullable=False)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    title = Column(String(255), nullable=False)
    report_type = Column(SQLEnum(ReportType), default=ReportType.EXECUTIVE, nullable=False)
    report_format = Column(SQLEnum(ReportFormat), default=ReportFormat.HTML, nullable=False)
    file_path = Column(String(512), nullable=True)
    download_url = Column(String(512), nullable=True)
    security_score = Column(Float, default=0.0)
    summary = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    assessment = relationship("Assessment", back_populates="reports")


class Schedule(Base):
    __tablename__ = "schedules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    profile = Column(SQLEnum(AssessmentProfileType), default=AssessmentProfileType.STANDARD_VAPT, nullable=False)
    frequency = Column(String(32), default="WEEKLY", nullable=False)  # DAILY, WEEKLY, MONTHLY
    targets = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)

    project = relationship("Project", back_populates="schedules")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    hashed_key = Column(String(255), nullable=False, unique=True, index=True)
    key_preview = Column(String(16), nullable=False)
    role = Column(SQLEnum(Role), default=Role.SECURITY_ANALYST, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    last_used = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="api_keys")


class Webhook(Base):
    __tablename__ = "webhooks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    url = Column(String(512), nullable=False)
    events = Column(JSON, default=list)
    secret = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    organization = relationship("Organization", back_populates="webhooks")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    user_email = Column(String(255), nullable=True)
    action = Column(String(128), nullable=False, index=True)
    target_resource = Column(String(255), nullable=True)
    details = Column(JSON, default=dict)
    ip_address = Column(String(64), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now)

    organization = relationship("Organization", back_populates="audit_logs")
