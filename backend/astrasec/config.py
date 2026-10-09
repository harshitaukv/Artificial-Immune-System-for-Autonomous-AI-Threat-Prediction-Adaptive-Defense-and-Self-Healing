"""Central configuration for AstraSec.

All tunables live here so the whole immune system can be re-parameterised
from one place (or from environment variables prefixed ``ASTRASEC_``).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# --------------------------------------------------------------------------
# Filesystem layout
# --------------------------------------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parent.parent          # backend/
PROJECT_ROOT = BACKEND_DIR.parent                             # astrasec/
ARTIFACT_DIR = Path(os.environ.get("ASTRASEC_ARTIFACTS", PROJECT_ROOT / "artifacts"))
MODEL_DIR = ARTIFACT_DIR / "models"
REPORT_DIR = ARTIFACT_DIR / "reports"
FIGURE_DIR = ARTIFACT_DIR / "figures"
DATA_DIR = ARTIFACT_DIR / "datasets"
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"

# Bumped whenever the training corpus or model format changes, so the start
# scripts know that models trained by an older version must be rebuilt.
MODEL_VERSION = "2026.09-assistant"
MODEL_VERSION_FILE = MODEL_DIR / "model_version.txt"

for _d in (ARTIFACT_DIR, MODEL_DIR, REPORT_DIR, FIGURE_DIR, DATA_DIR):
    _d.mkdir(parents=True, exist_ok=True)


class Settings(BaseSettings):
    """Runtime settings. Override with env vars, e.g. ``ASTRASEC_LLM_PROVIDER=ollama``."""

    model_config = SettingsConfigDict(
        env_prefix="ASTRASEC_", env_file=".env", extra="ignore"
    )

    # ---- general ---------------------------------------------------------
    app_name: str = "AstraSec"
    environment: str = "development"
    database_url: str = Field(default_factory=lambda: str(ARTIFACT_DIR / "astrasec.db"))
    random_seed: int = 42

    # ---- Module 1 : Behavior Learning Engine -----------------------------
    # Isolation Forest hyper-parameters.
    # 150 trees rather than 300: measured on the held-out set, 300 -> 150 costs
    # 0.003 ROC-AUC (0.8976 -> 0.8947) and saves ~11 ms on every single-row
    # score, which is the shape of traffic this engine actually serves.
    iforest_n_estimators: int = 150
    iforest_contamination: float = 0.08
    iforest_max_samples: int = 512
    # A tenant needs this many observations before its *personal* baseline
    # supersedes the globally-trained baseline.
    baseline_min_observations: int = 40
    # Exponential moving-average factor for online behavioural drift.
    behaviour_ema_alpha: float = 0.02
    # Window (seconds) used for rate/burst behavioural features.
    behaviour_window_seconds: int = 60

    # ---- Module 2 : AI Health & Risk Analyzer ----------------------------
    # Weights for the four risk surfaces. Must sum to 1.0 (validated at load).
    health_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "prompt_risk": 0.40,
            "behaviour_risk": 0.25,
            "configuration_risk": 0.20,
            "dependency_risk": 0.15,
        }
    )
    # Severity band cut-points on the 0-100 Health Score.
    health_bands: Dict[str, float] = Field(
        default_factory=lambda: {
            "critical": 40.0,
            "high": 60.0,
            "moderate": 78.0,
            "healthy": 90.0,
        }
    )
    # How strongly a single incident depresses the rolling health score.
    health_decay_halflife: int = 25  # in requests

    # ---- Module 3 : Threat Prediction Engine -----------------------------
    tfidf_word_ngrams: tuple = (1, 2)
    tfidf_char_ngrams: tuple = (3, 5)
    tfidf_word_max_features: int = 60_000
    tfidf_char_max_features: int = 80_000
    rf_n_estimators: int = 400
    rf_max_depth: int | None = None
    # min_samples_leaf=2 stops the forest growing pure single-sample leaves —
    # mild regularisation on a corpus with many near-duplicate phrasings.
    # Measured effect on held-out accuracy: 0.9816 -> 0.9810, i.e. noise.
    # (It was also tried as a model-size reduction and did not deliver one:
    # the serialised artifact is dominated by the SVD component matrix,
    # not by the forest. See docs/RESULTS.md.)
    rf_min_samples_leaf: int = 2
    rf_class_weight: str = "balanced_subsample"
    # Ensemble blend: RandomForest vs calibrated LogisticRegression.
    ensemble_weights: Dict[str, float] = Field(
        default_factory=lambda: {"random_forest": 0.55, "logistic_regression": 0.45}
    )
    # Minimum probability before a non-benign class is asserted.
    prediction_threshold: float = 0.45
    # ...unless the *malicious mass as a whole* is at least this large. An
    # attack the ensemble cannot place in one class (0.40 exfiltration + 0.35
    # injection) is still clearly an attack; judged class by class it fell
    # under the threshold and was waved through as benign.
    malicious_mass_threshold: float = 0.60
    # "Obfuscated" is a claim about the text: that it is encoded, spaced out,
    # leetspoken or otherwise disguised. With this on, the class is only
    # accepted when the text shows a trace of that — the evasion normaliser
    # changes it, a decoder recovers a payload, or a signature fires. Without
    # it, fragments the model never saw in training (a name, a table label, a
    # heading) are guessed to be obfuscation, which real documents are full of.
    obfuscation_requires_evidence: bool = True
    # Exfiltration and model extraction are both *requests* — for data, or for
    # the model's internals. With this on, those classes are only accepted when
    # the text asks for something. A heading such as "Internal memo" or a
    # statement such as "Customer cannot reset their password" contains the
    # vocabulary of exfiltration but asks for nothing.
    extraction_requires_request: bool = True

    # ---- Module 4 : Adaptive Defense Engine ------------------------------
    # Severity thresholds that gate the escalation ladder.
    defense_block_threshold: float = 0.80
    defense_sanitize_threshold: float = 0.45
    defense_monitor_threshold: float = 0.25
    # Token-bucket rate limiting per tenant.
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    # Consecutive high-severity incidents before a tenant is quarantined.
    quarantine_strike_count: int = 5
    quarantine_seconds: int = 300

    # ---- Module 5 : Self-Healing & Immune Memory -------------------------
    # Cosine affinity above which an incoming antigen matches a memory cell.
    memory_affinity_threshold: float = 0.72
    # Memory cells below this affinity-weighted utility are pruned (apoptosis).
    memory_apoptosis_utility: float = 0.15
    memory_max_cells: int = 5_000
    # Clonal selection: how many mutated clones per successful memory match.
    clonal_expansion_factor: int = 3
    # A synthesised rule is promoted to an active policy at this confidence.
    rule_promotion_confidence: float = 0.85
    rule_promotion_min_support: int = 4
    # Hard ceiling on self-written policy. The false-positive gate already
    # makes each individual rule safe; this bounds how much of the enforcement
    # surface the system is allowed to author for itself without review.
    max_promoted_rules: int = 200
    # Controlled self-healing: when False (the default), a rule that passes
    # every automatic check is held as a *suggestion* for the owner to test and
    # approve in the Security Center, instead of going live on its own.
    rule_auto_promote: bool = False

    # ---- LLM advisor (pluggable) ----------------------------------------
    llm_provider: str = "offline"       # offline | ollama | openai_compatible
    llm_model: str = "llama3.1"
    llm_base_url: str = "http://localhost:11434"
    llm_api_key: str = ""
    llm_timeout_seconds: float = 30.0
    llm_max_tokens: int = 512

    # ---- API -------------------------------------------------------------
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:8000",
        ]
    )
    live_feed_buffer: int = 300


settings = Settings()

# Fail fast on a mis-weighted health model — a silent 0.9-sum would quietly
# bias every Health Score in the system.
_w = sum(settings.health_weights.values())
if abs(_w - 1.0) > 1e-6:  # pragma: no cover - configuration guard
    raise ValueError(f"health_weights must sum to 1.0, got {_w:.4f}")


__all__ = [
    "settings",
    "Settings",
    "PROJECT_ROOT",
    "BACKEND_DIR",
    "ARTIFACT_DIR",
    "MODEL_DIR",
    "REPORT_DIR",
    "FIGURE_DIR",
    "DATA_DIR",
    "FRONTEND_DIST",
    "MODEL_VERSION",
    "MODEL_VERSION_FILE",
]
