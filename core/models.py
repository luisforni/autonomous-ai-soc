"""Modelos de dominio del AI-SOC."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def _missing_(cls, value: object) -> "Severity":
        if isinstance(value, str):
            normalized = value.lower().strip()
            for member in cls:
                if member.value == normalized:
                    return member
        return cls.INFO


class ThreatCategory(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    APT = "apt"
    INSIDER_THREAT = "insider_threat"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    BRUTE_FORCE = "brute_force"
    DDOS = "ddos"
    INJECTION = "injection"
    ZERO_DAY = "zero_day"
    SUPPLY_CHAIN = "supply_chain"
    SOCIAL_ENGINEERING = "social_engineering"
    C2 = "c2"
    CRYPTOMINING = "cryptomining"
    ROOTKIT = "rootkit"
    ANOMALY = "anomaly"
    COMPLIANCE = "compliance"
    VULNERABILITY = "vulnerability"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> "ThreatCategory":
        if isinstance(value, str):
            normalized = value.lower().strip().replace(" ", "_").replace("-", "_")
            for member in cls:
                if member.value == normalized:
                    return member
        return cls.UNKNOWN


class IncidentStatus(str, Enum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class MITRETactic(str, Enum):
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    EMAIL = "email"
    FILENAME = "filename"
    REGISTRY_KEY = "registry_key"
    CVE = "cve"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"


class IOC(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: IOCType
    value: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)

    @field_validator("confidence", mode="before")
    @classmethod
    def _normalize_confidence(cls, v: Any) -> float:
        try:
            f = float(v)
            return f / 100.0 if f > 1.0 else f
        except (TypeError, ValueError):
            return 0.5
    severity: Severity = Severity.MEDIUM
    source: str = "ai-soc"
    tags: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    enrichment: dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: Severity
    category: ThreatCategory = ThreatCategory.UNKNOWN
    source_agent: str
    source_system: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    iocs: list[IOC] = Field(default_factory=list)
    mitre_tactics: list[MITRETactic] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    false_positive_score: float = Field(ge=0.0, le=1.0, default=0.0)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    recommendations: list[Any] = Field(default_factory=list)
    incident_id: str | None = None

    @field_validator("recommendations", mode="before")
    @classmethod
    def _coerce_recs(cls, v: Any) -> list:
        if v is None:
            return []
        if isinstance(v, list):
            return v
        if isinstance(v, dict):
            return list(v.values())
        return [v] if v else []

    @field_validator("confidence", "false_positive_score", mode="before")
    @classmethod
    def _normalize_confidence(cls, v: Any) -> float:
        try:
            f = float(v)
            return f / 100.0 if f > 1.0 else f
        except (TypeError, ValueError):
            return 0.5


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.NEW
    category: ThreatCategory = ThreatCategory.UNKNOWN
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    closed_at: datetime | None = None
    alerts: list[str] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    mitre_tactics: list[MITRETactic] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    assigned_to: str = "ai-soc"
    response_actions: list[dict[str, Any]] = Field(default_factory=list)
    containment_actions: list[str] = Field(default_factory=list)
    root_cause: str = ""
    lessons_learned: str = ""
    customer_id: str = ""
    sla_breach: bool = False
    ticket_id: str = ""


class Event(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str
    event_type: str
    severity: Severity = Severity.INFO
    data: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    agent_id: str = ""
    processed: bool = False
    alert_generated: bool = False


class AgentAnalysis(BaseModel):
    agent_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    input_data: dict[str, Any]
    findings: list[Any] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=10.0, default=0.0)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    recommendations: list[Any] = Field(default_factory=list)
    raw_ai_response: str = ""
    execution_time_ms: int = 0

    @field_validator("findings", "recommendations", mode="before")
    @classmethod
    def _coerce_to_list(cls, v: Any) -> list:
        if v is None:
            return []
        if isinstance(v, list):
            return v
        if isinstance(v, dict):
            return list(v.values())
        return [v] if v else []


class ThreatIntelReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    summary: str
    threat_actor: str = ""
    campaign: str = ""
    iocs: list[IOC] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list)
    affected_sectors: list[str] = Field(default_factory=list)
    affected_countries: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    published_at: datetime = Field(default_factory=datetime.utcnow)
    source: str = ""
    references: list[str] = Field(default_factory=list)


class ComplianceFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str
    control_id: str
    control_name: str
    status: str
    severity: Severity
    description: str
    evidence: list[str] = Field(default_factory=list)
    remediation: str = ""
    due_date: datetime | None = None
    asset: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
