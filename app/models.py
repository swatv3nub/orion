from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Classification(StrEnum):
    benign = "benign"
    needs_investigation = "needs_investigation"
    suspicious = "suspicious"


class HypothesisStatus(StrEnum):
    supported = "supported"
    plausible = "plausible"
    unresolved = "unresolved"
    unsupported = "unsupported"


class Asset(BaseModel):
    model_config = ConfigDict(extra="allow")

    hostname: str | None = None
    ip: str | None = None
    url: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str
    title: str
    severity: Severity
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.lower().replace("informational", "informational")
        return value


class AlertContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    historical_alerts: list[dict[str, Any]] = Field(default_factory=list)
    related_findings: list[dict[str, Any]] = Field(default_factory=list)
    asset_inventory: dict[str, Any] | None = None


class ThreatLensAlert(BaseModel):
    model_config = ConfigDict(extra="allow")

    alert_id: str
    source: str
    timestamp: datetime | None = None
    asset: Asset | None = None
    finding: Finding
    context: AlertContext = Field(default_factory=AlertContext)
    mitre_attack: list[str] = Field(default_factory=list)


class InvestigationRequest(ThreatLensAlert):
    pass


class Evidence(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    source: str
    type: str
    finding: str
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp: datetime | None = None
    raw_reference: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class InvestigationContext(BaseModel):
    investigation_id: str
    primary_alert: ThreatLensAlert
    asset: Asset | None = None
    historical_alerts: list[dict[str, Any]] = Field(default_factory=list)
    related_findings: list[dict[str, Any]] = Field(default_factory=list)
    asset_inventory: dict[str, Any] | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class Hypothesis(BaseModel):
    id: str
    title: str
    description: str
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    status: HypothesisStatus


class Evaluation(BaseModel):
    classification: Classification
    confidence: float = Field(ge=0.0, le=1.0)
    missing_evidence: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    needs_investigation: bool = True


class AnalystReport(BaseModel):
    investigation_id: str
    alert_id: str
    classification: Classification
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    hypotheses: list[Hypothesis]
    evidence: list[Evidence]
    missing_evidence: list[str]
    investigation_steps: list[str]
    mitre_attack: list[str]
    recommended_actions: list[str]
    uncertainties: list[str]
    human_review_required: bool
    automated_action: str = "none"


class InvestigationResponse(BaseModel):
    investigation_id: str
    status: str = "completed"
    classification: Classification
