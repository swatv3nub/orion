from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

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


class AssessmentClassification(StrEnum):
    benign = "benign"
    needs_investigation = "needs_investigation"
    suspicious = "suspicious"
    confirmed = "confirmed"


class AssessmentSource(StrEnum):
    deterministic = "deterministic"
    llm = "llm"
    reconciled = "reconciled"


class AssessmentConsistencyStatus(StrEnum):
    consistent = "consistent"
    reconciled = "reconciled"
    invalid = "invalid"


class HypothesisStatus(StrEnum):
    supported = "supported"
    plausible = "plausible"
    unresolved = "unresolved"
    unsupported = "unsupported"


class ToolName(StrEnum):
    threatlens_query = "threatlens.query"
    reconix_results = "reconix.results"
    mitre_lookup = "mitre.lookup"


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
    canonical_evidence_id: str | None = None
    provenance: list[dict[str, str]] = Field(default_factory=list)


RelationshipType = Literal[
    "same_asset",
    "same_scan",
    "same_finding",
    "same_source",
    "related_service",
    "related_dns",
    "related_tls",
    "related_http",
    "related_cloud",
    "corroborates",
    "contradicts",
    "contextualizes",
]


class EvidenceRelation(BaseModel):
    source_evidence_id: str
    target_evidence_id: str
    relationship_type: RelationshipType
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str


class CorrelationResult(BaseModel):
    relationships: list[EvidenceRelation] = Field(default_factory=list)
    unique_evidence_ids: list[str] = Field(default_factory=list)
    duplicate_evidence_ids: list[str] = Field(default_factory=list)
    duplicate_of: dict[str, str] = Field(default_factory=dict)
    raw_evidence_count: int = 0
    canonical_evidence_count: int = 0
    semantic_relationship_count: int = 0
    provenance_relationship_count: int = 0

    @property
    def correlated_evidence_count(self) -> int:
        return self.canonical_evidence_count


class InvestigationContext(BaseModel):
    investigation_id: str
    primary_alert: ThreatLensAlert
    asset: Asset | None = None
    historical_alerts: list[dict[str, Any]] = Field(default_factory=list)
    related_findings: list[dict[str, Any]] = Field(default_factory=list)
    asset_inventory: dict[str, Any] | None = None
    scan_id: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class MissingEvidence(BaseModel):
    id: str
    description: str
    importance: str
    possible_sources: list[str] = Field(default_factory=list)
    status: str = "missing"


class InvestigationStep(BaseModel):
    step_id: str
    tool: ToolName
    purpose: str
    reason: str
    priority: int = Field(ge=1)
    requires_human_approval: bool = False
    arguments: dict[str, str] = Field(default_factory=dict)


class InvestigationPlan(BaseModel):
    investigation_id: str
    steps: list[InvestigationStep] = Field(default_factory=list)


class ToolResult(BaseModel):
    tool: str
    status: str
    data: dict[str, Any] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolActivity(BaseModel):
    step_id: str
    tool: str
    status: str
    duration_ms: int = Field(ge=0)
    evidence_added: int = Field(ge=0)


class InvestigationState(BaseModel):
    investigation_id: str
    status: str = "pending"
    current_step: str | None = None
    completed_steps: int = 0
    tool_calls: int = 0
    evidence_count: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    error: str | None = None
    timeout: bool = False
    policy_denials: list[str] = Field(default_factory=list)
    stop_reason: str | None = None


class Hypothesis(BaseModel):
    id: str
    title: str
    description: str
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    contextual_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    status: HypothesisStatus


class Evaluation(BaseModel):
    classification: Classification
    confidence: float = Field(ge=0.0, le=1.0)
    missing_evidence: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    needs_investigation: bool = True


class FinalAssessment(BaseModel):
    classification: AssessmentClassification
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    source: AssessmentSource


class AssessmentConsistency(BaseModel):
    status: AssessmentConsistencyStatus
    reason: str


class AnalystReport(BaseModel):
    investigation_id: str
    alert_id: str
    classification: Classification = Field(description="Legacy deterministic classification. The authoritative outcome is final_assessment.")
    severity: Severity = Field(description="Legacy deterministic finding severity. The authoritative outcome is final_assessment.")
    confidence: float = Field(ge=0.0, le=1.0, description="Legacy deterministic confidence. The authoritative outcome is final_assessment.")
    summary: str = Field(description="Deterministically constructed summary grounded in the reconciled final assessment and deterministic hypotheses.")
    hypotheses: list[Hypothesis] = Field(description="Deterministic hypotheses generated from the investigation evidence; not LLM hypotheses.")
    evidence: list[Evidence] = Field(description="Verified investigation evidence available for reference by a validated LLM assessment.")
    evidence_relationships: list[EvidenceRelation] = Field(default_factory=list)
    raw_evidence_count: int = Field(default=0, ge=0)
    canonical_evidence_count: int = Field(default=0, ge=0)
    correlated_evidence_count: int = Field(default=0, ge=0)
    semantic_relationship_count: int = Field(default=0, ge=0)
    provenance_relationship_count: int = Field(default=0, ge=0)
    llm_assessment: dict[str, Any] | None = Field(default=None, description="Validated LLM assessment, including its evidence-backed factual_claims, hypotheses, unresolved_questions, and recommended_next_steps. It is not authoritative.")
    deterministic_assessment: FinalAssessment = Field(description="Assessment derived solely from deterministic investigation evaluation.")
    final_assessment: FinalAssessment = Field(description="Authoritative final assessment after deterministic reconciliation of any validated LLM assessment.")
    assessment_consistency: AssessmentConsistency = Field(description="Whether the LLM and deterministic assessments were consistent, reconciled, or invalid.")
    llm_status: str | None = Field(default=None, description="LLM execution status: success, failed, or not_configured.")
    llm_model: str | None = Field(default=None, description="Model that produced the LLM assessment or most recently failed.")
    llm_failure_reason: str | None = Field(default=None, description="Controlled LLM failure reason when no validated assessment is available.")
    llm_provider: str | None = Field(default=None, description="Provider that produced the LLM assessment or most recently failed.")
    llm_fallback_used: bool = Field(default=False, description="Whether the configured LLM fallback chain produced the result.")
    llm_primary_failure_reason: str | None = Field(default=None, description="Controlled primary-provider failure reason when a fallback was used.")
    missing_evidence: list[str] = Field(description="Evidence required to resolve the deterministic assessment.")
    investigation_steps: list[str] = Field(description="Deterministic actions generated from missing evidence.")
    tool_activity: list[ToolActivity] = Field(default_factory=list, description="Executed investigation tool activity.")
    stop_reason: str | None = None
    state: InvestigationState | None = None
    mitre_attack: list[str]
    recommended_actions: list[str] = Field(description="Deterministic analyst actions. LLM recommended_next_steps, if any, remain in llm_assessment.")
    uncertainties: list[str] = Field(description="Deterministic investigation uncertainties.")
    human_review_required: bool = Field(description="Required when deterministic evaluation or missing evidence requires human security-context review.")
    automated_action: str = Field(default="none", description="Always none; ORION does not automate remediation.")


class InvestigationResponse(BaseModel):
    investigation_id: str
    alert_id: str | None = None
    status: str = "completed"
    classification: Classification
