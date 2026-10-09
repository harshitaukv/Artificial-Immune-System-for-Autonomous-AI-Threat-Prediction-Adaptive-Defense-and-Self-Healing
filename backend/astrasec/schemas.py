"""Pydantic contracts shared by the engines, the pipeline and the REST API."""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------
class ThreatClass(str, Enum):
    BENIGN = "benign"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    ADVERSARIAL_OBFUSCATION = "adversarial_obfuscation"
    DATA_EXFILTRATION = "data_exfiltration"
    MODEL_EXTRACTION = "model_extraction"


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DefenseAction(str, Enum):
    ALLOW = "allow"
    MONITOR = "monitor"
    SANITIZE = "sanitize"
    MASK = "mask"
    RATE_LIMIT = "rate_limit"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class HealthBand(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    HEALTHY = "healthy"
    OPTIMAL = "optimal"


# --------------------------------------------------------------------------
# Inbound request
# --------------------------------------------------------------------------
class AppContext(BaseModel):
    """Deployment context of the protected AI application.

    Drives the *configuration* and *dependency* risk surfaces of Module 2.
    """

    app_id: str = "default-app"
    app_name: str = "Protected AI Application"
    model_name: str = "gpt-oss-20b"
    system_prompt_protected: bool = True
    output_filtering_enabled: bool = True
    tool_calling_enabled: bool = False
    retrieval_enabled: bool = False
    pii_redaction_enabled: bool = True
    authentication_required: bool = True
    logging_enabled: bool = True
    rate_limiting_enabled: bool = True
    sandbox_enabled: bool = True
    dependencies: List[str] = Field(default_factory=list)
    known_vulnerable_dependencies: List[str] = Field(default_factory=list)
    last_security_review_days: int = 14


class InspectRequest(BaseModel):
    """A single prompt/API interaction submitted for immune inspection."""

    prompt: str = Field(..., min_length=0, max_length=20_000)
    tenant_id: str = "anonymous"
    session_id: Optional[str] = None
    app: AppContext = Field(default_factory=AppContext)
    channel: str = "chat"                       # chat | api | tool | rag
    user_role: str = "end_user"                 # end_user | staff | admin
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # If supplied, the engine also screens the model's *response*.
    model_response: Optional[str] = None
    # Set False to evaluate without mutating memory/state (used by the UI
    # playground and by the evaluation harness).
    persist: bool = True


# --------------------------------------------------------------------------
# Per-module outputs
# --------------------------------------------------------------------------
class BehaviorReport(BaseModel):
    """Module 1 — Behavior Learning Engine."""

    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    is_anomalous: bool
    raw_iforest_score: float
    baseline_source: str                # global | tenant | cold_start
    observations_seen: int
    deviating_features: List[Dict[str, Any]] = Field(default_factory=list)
    feature_vector: Dict[str, float] = Field(default_factory=dict)
    novelty: float = Field(0.0, ge=0.0, le=1.0)
    explanation: str = ""


class RiskFinding(BaseModel):
    surface: str                        # prompt | behaviour | configuration | dependency
    code: str
    title: str
    severity: Severity
    score: float = Field(..., ge=0.0, le=1.0)
    weight: float = 0.0
    evidence: str = ""
    remediation: str = ""
    # Audit category: code | dependency | api | ai | configuration | secrets
    category: str = ""


class HealthReport(BaseModel):
    """Module 2 — AI Health & Risk Analyzer."""

    health_score: float = Field(..., ge=0.0, le=100.0)
    band: HealthBand
    risk_level: Severity
    surface_scores: Dict[str, float] = Field(default_factory=dict)
    weighted_risk: float = 0.0
    findings: List[RiskFinding] = Field(default_factory=list)
    top_priority: Optional[RiskFinding] = None
    rolling_health_score: float = 100.0
    explanation: str = ""


class ThreatPrediction(BaseModel):
    """Module 3 — Threat Prediction Engine."""

    threat_class: ThreatClass
    confidence: float = Field(..., ge=0.0, le=1.0)
    probabilities: Dict[str, float] = Field(default_factory=dict)
    severity: Severity
    model_votes: Dict[str, str] = Field(default_factory=dict)
    top_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    signature_hits: List[str] = Field(default_factory=list)
    signature_detail: List[Dict[str, Any]] = Field(default_factory=list)
    signature_risk: float = 0.0
    ml_confidence: float = 0.0
    memory_assisted: bool = False
    explanation: str = ""


class SanitizationStep(BaseModel):
    rule_id: str
    description: str
    span: Optional[str] = None
    replacement: str = ""


class DefenseDecision(BaseModel):
    """Module 4 — Adaptive Defense Engine."""

    action: DefenseAction
    actions_applied: List[DefenseAction] = Field(default_factory=list)
    allowed: bool
    sanitized_prompt: Optional[str] = None
    sanitization_steps: List[SanitizationStep] = Field(default_factory=list)
    response_filtered: Optional[str] = None
    response_filter_steps: List[SanitizationStep] = Field(default_factory=list)
    policy_ids: List[str] = Field(default_factory=list)
    rationale: str = ""
    residual_risk: float = Field(0.0, ge=0.0, le=1.0)
    revalidated_clean: bool = True
    rate_limit_remaining: Optional[int] = None
    quarantined_until: Optional[float] = None


class MemoryCell(BaseModel):
    """A single antibody / memory B-cell in the Artificial Immune Memory."""

    cell_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    antigen_signature: str
    threat_class: ThreatClass
    exemplar_prompt: str
    defense_used: DefenseAction
    defense_successful: bool = True
    affinity_vector: List[float] = Field(default_factory=list)
    encounters: int = 1
    successes: int = 1
    generation: int = 0
    parent_id: Optional[str] = None
    created_at: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    utility: float = 1.0

    @property
    def success_rate(self) -> float:
        return self.successes / max(1, self.encounters)


class SynthesizedRule(BaseModel):
    """A self-healing policy rule created by Module 5."""

    rule_id: str = Field(default_factory=lambda: "SH-" + uuid.uuid4().hex[:8])
    pattern: str
    threat_class: ThreatClass
    action: DefenseAction
    confidence: float = 0.0
    support: int = 0
    active: bool = False
    origin: str = "self_healing"
    created_at: float = Field(default_factory=time.time)
    description: str = ""
    # Owner-controlled promotion: the last validation run and who approved it.
    validation: Optional[Dict[str, Any]] = None
    approved_at: Optional[float] = None


class Recommendation(BaseModel):
    recommendation_id: str = Field(default_factory=lambda: "REC-" + uuid.uuid4().hex[:8])
    title: str
    detail: str
    priority: Severity
    category: str
    source: str = "offline_engine"      # offline_engine | llm
    references: List[str] = Field(default_factory=list)


class MemoryReport(BaseModel):
    """Module 5 — Self-Healing & Security Intelligence Engine."""

    matched_cell_id: Optional[str] = None
    matched_affinity: float = 0.0
    recall_hit: bool = False
    primary_response: bool = True       # True = first exposure, False = memory recall
    cells_total: int = 0
    clones_created: int = 0
    cells_pruned: int = 0
    rules_synthesized: List[SynthesizedRule] = Field(default_factory=list)
    rules_promoted: List[str] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)
    immunity_strength: float = Field(0.0, ge=0.0, le=1.0)
    explanation: str = ""


# --------------------------------------------------------------------------
# Aggregate pipeline output
# --------------------------------------------------------------------------
class InspectionResult(BaseModel):
    incident_id: str = Field(default_factory=lambda: "INC-" + uuid.uuid4().hex[:10])
    timestamp: float = Field(default_factory=time.time)
    tenant_id: str
    app_id: str
    prompt: str
    prompt_preview: str = ""
    behavior: BehaviorReport
    health: HealthReport
    prediction: ThreatPrediction
    defense: DefenseDecision
    memory: MemoryReport
    verdict: str                        # allowed | sanitized | blocked | quarantined
    latency_ms: Dict[str, float] = Field(default_factory=dict)
    total_latency_ms: float = 0.0
    narrative: str = ""


# --------------------------------------------------------------------------
# Dashboard / analytics payloads
# --------------------------------------------------------------------------
class ThreatTimelinePoint(BaseModel):
    bucket: str
    total: int
    blocked: int
    sanitized: int
    allowed: int


class DashboardSummary(BaseModel):
    generated_at: float = Field(default_factory=time.time)
    total_requests: int
    threats_detected: int
    threats_blocked: int
    threats_sanitized: int
    block_rate: float
    detection_rate: float
    current_health_score: float
    health_band: HealthBand
    mean_latency_ms: float
    p95_latency_ms: float
    threat_distribution: Dict[str, int] = Field(default_factory=dict)
    severity_distribution: Dict[str, int] = Field(default_factory=dict)
    action_distribution: Dict[str, int] = Field(default_factory=dict)
    timeline: List[ThreatTimelinePoint] = Field(default_factory=list)
    health_history: List[Dict[str, float]] = Field(default_factory=list)
    immune_memory_cells: int = 0
    immune_memory_recall_rate: float = 0.0
    active_rules: int = 0
    quarantined_tenants: List[str] = Field(default_factory=list)
    top_tenants: List[Dict[str, Any]] = Field(default_factory=list)
    recent_recommendations: List[Recommendation] = Field(default_factory=list)


class TrainingReport(BaseModel):
    trained_at: float
    dataset_size: int
    class_distribution: Dict[str, int]
    accuracy: float
    macro_f1: float
    weighted_f1: float
    per_class: Dict[str, Dict[str, float]]
    confusion_matrix: List[List[int]]
    labels: List[str]
    cv_scores: List[float] = Field(default_factory=list)
    behavior_auc: Optional[float] = None
    duration_seconds: float = 0.0


class HealthCheck(BaseModel):
    status: str
    version: str
    models_loaded: bool
    llm_provider: str
    llm_available: bool
    uptime_seconds: float
    memory_cells: int
