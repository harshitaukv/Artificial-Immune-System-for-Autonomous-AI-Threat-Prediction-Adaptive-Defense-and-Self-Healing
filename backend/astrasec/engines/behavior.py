"""Module 1 — Behavior Learning Engine.

Biological analogue: *self / non-self discrimination*. The engine is trained
exclusively on benign traffic, so it learns what "self" looks like for an AI
application and flags deviation without ever being shown a labelled attack.
That is the defining property demanded by the project objective ("continuously
learn the normal behaviour of AI applications") and the reason an Isolation
Forest — an unsupervised novelty detector — is the right primitive here.

Three layers of behavioural memory operate together:

1. **Global baseline**  an Isolation Forest fitted on the benign corpus,
   available immediately at cold start.
2. **Tenant baseline**  per-tenant running statistics (Welford mean/variance,
   EMA centroid) that gradually supersede the global baseline once the tenant
   has produced ``baseline_min_observations`` requests. This is what makes the
   system *continuously* learning rather than statically trained.
3. **Session dynamics**  rate, burstiness, novelty and escalation slope over a
   sliding window — the features that expose slow, low-and-slow probing that
   no single prompt would reveal.
"""
from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional, Sequence, Tuple

import joblib

from ..utils import atomic_dump
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ..config import MODEL_DIR, settings
from ..features import (
    ALL_FEATURES,
    PROMPT_FEATURES,
    SESSION_FEATURES,
    empty_session_features,
    extract_prompt_features,
    full_vector,
)
from ..schemas import BehaviorReport

# Features whose raw scale is heavy-tailed; log1p keeps one 8000-character
# paste from dominating the Euclidean geometry of the forest.
_LOG_FEATURES = {
    "length", "word_count", "max_word_len", "newline_count", "question_marks",
    "exclamations", "longest_repeat_run", "role_marker_count",
    "delimiter_count", "url_count", "code_block_count", "zero_width_count",
    "requests_in_window", "inter_arrival_seconds", "session_depth",
}
_LOG_IDX = np.array([i for i, f in enumerate(ALL_FEATURES) if f in _LOG_FEATURES])


def _transform(X: np.ndarray) -> np.ndarray:
    X = np.asarray(X, dtype=np.float64).copy()
    if X.ndim == 1:
        X = X.reshape(1, -1)
    if _LOG_IDX.size:
        X[:, _LOG_IDX] = np.log1p(np.clip(X[:, _LOG_IDX], 0, None))
    return np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)


@dataclass
class TenantProfile:
    """Online behavioural baseline for one tenant / application."""

    tenant_id: str
    count: int = 0
    # Welford accumulators for scalar statistics
    _len_mean: float = 0.0
    _len_m2: float = 0.0
    _ent_mean: float = 0.0
    _ent_m2: float = 0.0
    # EMA centroid over the standardised prompt-feature space
    centroid: Optional[np.ndarray] = None
    timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=500))
    prompt_hashes: Deque[int] = field(default_factory=lambda: deque(maxlen=200))
    recent_risk: Deque[float] = field(default_factory=lambda: deque(maxlen=20))
    threat_streak: int = 0
    total_threats: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # ---- running statistics -------------------------------------------
    @property
    def length_std(self) -> float:
        return math.sqrt(self._len_m2 / self.count) if self.count > 1 else 0.0

    @property
    def entropy_std(self) -> float:
        return math.sqrt(self._ent_m2 / self.count) if self.count > 1 else 0.0

    def _welford(self, mean: float, m2: float, x: float, n: int) -> Tuple[float, float]:
        delta = x - mean
        mean += delta / n
        m2 += delta * (x - mean)
        return mean, m2

    def update(self, prompt_feats: Dict[str, float], vec_std: np.ndarray,
               prompt_hash: int, ts: float) -> None:
        self.count += 1
        self._len_mean, self._len_m2 = self._welford(
            self._len_mean, self._len_m2, prompt_feats["length"], self.count
        )
        self._ent_mean, self._ent_m2 = self._welford(
            self._ent_mean, self._ent_m2, prompt_feats["char_entropy"], self.count
        )
        a = settings.behaviour_ema_alpha
        # Early on, weight new observations heavily so the profile converges
        # quickly; later, settle to the configured slow drift rate.
        alpha = max(a, 1.0 / max(1, min(self.count, 50)))
        if self.centroid is None:
            self.centroid = vec_std.copy()
        else:
            self.centroid = (1 - alpha) * self.centroid + alpha * vec_std
        self.timestamps.append(ts)
        self.prompt_hashes.append(prompt_hash)
        self.last_seen = ts

    def record_outcome(self, is_threat: bool, risk: float) -> None:
        self.recent_risk.append(float(risk))
        if is_threat:
            self.threat_streak += 1
            self.total_threats += 1
        else:
            self.threat_streak = 0

    # ---- derived session features ---------------------------------------
    def session_features(self, prompt_feats: Dict[str, float],
                         vec_std: np.ndarray, now: float) -> Dict[str, float]:
        f = empty_session_features()
        w = settings.behaviour_window_seconds

        recent = [t for t in self.timestamps if now - t <= w]
        f["requests_in_window"] = float(len(recent))
        f["inter_arrival_seconds"] = (
            float(min(now - self.timestamps[-1], 3600.0)) if self.timestamps else 0.0
        )

        # Burstiness B = (sigma - mu) / (sigma + mu)  in [-1, 1]; +1 = bursty,
        # -1 = perfectly periodic (Goh & Barabasi, 2008).
        if len(recent) >= 3:
            gaps = np.diff(np.array(recent))
            mu, sd = float(gaps.mean()), float(gaps.std())
            f["burstiness"] = (sd - mu) / (sd + mu) if (sd + mu) > 1e-9 else 0.0
        f["length_zscore"] = (
            (prompt_feats["length"] - self._len_mean) / self.length_std
            if self.length_std > 1e-6 else 0.0
        )
        f["entropy_zscore"] = (
            (prompt_feats["char_entropy"] - self._ent_mean) / self.entropy_std
            if self.entropy_std > 1e-6 else 0.0
        )
        if self.centroid is not None and self.count >= 3:
            a, b = vec_std, self.centroid
            denom = (np.linalg.norm(a) * np.linalg.norm(b))
            cos = float(np.dot(a, b) / denom) if denom > 1e-9 else 0.0
            f["novelty_distance"] = float(np.clip(1.0 - cos, 0.0, 2.0))
        f["threat_streak"] = float(self.threat_streak)
        f["session_depth"] = float(self.count)
        if self.prompt_hashes:
            f["distinct_template_ratio"] = len(set(self.prompt_hashes)) / len(self.prompt_hashes)
        if len(self.recent_risk) >= 4:
            y = np.array(self.recent_risk, dtype=float)
            x = np.arange(len(y), dtype=float)
            f["escalation_slope"] = float(np.polyfit(x, y, 1)[0])
        # Clip to keep a single pathological value from destabilising the
        # forest at inference time.
        for k in ("length_zscore", "entropy_zscore", "escalation_slope"):
            f[k] = float(np.clip(f[k], -10.0, 10.0))
        return f


class BehaviorLearningEngine:
    """Unsupervised behavioural baseline + anomaly scorer."""

    MODEL_FILE = "behavior_engine.joblib"

    def __init__(self) -> None:
        self.scaler: Optional[StandardScaler] = None
        self.forest: Optional[IsolationForest] = None
        self.profiles: Dict[str, TenantProfile] = {}
        self._threshold: float = 0.0
        self._scale: float = 1.0
        self._feature_names: Sequence[str] = ALL_FEATURES
        self._global_mean: Optional[np.ndarray] = None
        self._global_std: Optional[np.ndarray] = None
        self.trained_at: Optional[float] = None
        self.training_size: int = 0

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def fit(self, benign_prompts: Sequence[str], verbose: bool = True) -> Dict[str, float]:
        """Fit the global baseline on benign traffic only (novelty detection)."""
        t0 = time.perf_counter()
        feats = [extract_prompt_features(p) for p in benign_prompts]
        neutral = empty_session_features()
        X = np.vstack([full_vector(f, neutral) for f in feats])
        Xt = _transform(X)

        self.scaler = StandardScaler().fit(Xt)
        Xs = self.scaler.transform(Xt)

        self.forest = IsolationForest(
            n_estimators=settings.iforest_n_estimators,
            contamination=settings.iforest_contamination,
            max_samples=min(settings.iforest_max_samples, len(Xs)),
            random_state=settings.random_seed,
            n_jobs=-1,
            bootstrap=False,
        ).fit(Xs)

        raw = self.forest.decision_function(Xs)
        # Calibrate raw scores -> [0,1] anomaly probability with a logistic
        # centred on the contamination quantile of *benign* traffic, so a
        # typical benign prompt scores well below 0.5.
        self._threshold = float(np.quantile(raw, settings.iforest_contamination))
        p50 = float(np.quantile(raw, 0.50))
        self._scale = max(1e-3, (p50 - self._threshold) / 2.0)

        self._global_mean = Xs.mean(axis=0)
        self._global_std = Xs.std(axis=0) + 1e-9
        self.trained_at = time.time()
        self.training_size = len(benign_prompts)

        scores = self._calibrate(raw)
        stats = {
            "training_size": float(len(benign_prompts)),
            "threshold_raw": self._threshold,
            "scale": self._scale,
            "benign_mean_anomaly": float(scores.mean()),
            "benign_p95_anomaly": float(np.quantile(scores, 0.95)),
            "flag_rate_on_benign": float((scores > 0.5).mean()),
            "fit_seconds": time.perf_counter() - t0,
        }
        if verbose:
            print(
                f"[Module 1] Isolation Forest fitted on {len(benign_prompts):,} benign prompts "
                f"in {stats['fit_seconds']:.1f}s | benign flag-rate "
                f"{stats['flag_rate_on_benign']:.2%}"
            )
        return stats

    def _calibrate(self, raw: np.ndarray | float) -> np.ndarray:
        z = (self._threshold - np.asarray(raw, dtype=float)) / self._scale
        return 1.0 / (1.0 + np.exp(-z))

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    def _standardise(self, vec: np.ndarray) -> np.ndarray:
        return self.scaler.transform(_transform(vec))[0]

    def get_profile(self, tenant_id: str) -> TenantProfile:
        if tenant_id not in self.profiles:
            self.profiles[tenant_id] = TenantProfile(tenant_id=tenant_id)
        return self.profiles[tenant_id]

    def analyse(self, prompt: str, tenant_id: str = "anonymous",
                now: Optional[float] = None, update: bool = True) -> BehaviorReport:
        if self.forest is None or self.scaler is None:
            raise RuntimeError("BehaviorLearningEngine.fit() must be called before analyse()")

        now = time.time() if now is None else now
        profile = self.get_profile(tenant_id)

        prompt_feats = extract_prompt_features(prompt)
        # Standardise with neutral session features first so the centroid /
        # novelty comparison happens in a stable space.
        vec_prompt_only = full_vector(prompt_feats, empty_session_features())
        vec_std_prompt = self._standardise(vec_prompt_only)

        session_feats = profile.session_features(prompt_feats, vec_std_prompt, now)
        vec = full_vector(prompt_feats, session_feats)
        vec_std = self._standardise(vec)

        # n_jobs is forced to 1 for single-row scoring: joblib's parallel
        # dispatch costs an order of magnitude more than the tree traversal
        # itself. score_batch() raises it again for real batches.
        if self.forest.n_jobs != 1:
            self.forest.n_jobs = 1
        raw = float(self.forest.decision_function(vec_std.reshape(1, -1))[0])
        anomaly = float(self._calibrate(raw))

        # Blend the global verdict with the tenant's own baseline once that
        # baseline is statistically meaningful.
        if profile.count >= settings.baseline_min_observations:
            baseline_source = "tenant"
            personal = self._tenant_deviation(vec_std, profile)
            anomaly = float(np.clip(0.55 * anomaly + 0.45 * personal, 0.0, 1.0))
        elif profile.count == 0:
            baseline_source = "cold_start"
        else:
            baseline_source = "global"

        deviating = self._top_deviations(vec_std, profile, k=5)
        novelty = float(np.clip(session_feats["novelty_distance"] / 1.2, 0.0, 1.0))

        if update:
            profile.update(prompt_feats, vec_std_prompt, hash(prompt.strip().lower()), now)

        report = BehaviorReport(
            anomaly_score=round(anomaly, 4),
            is_anomalous=anomaly >= 0.5,
            raw_iforest_score=round(raw, 5),
            baseline_source=baseline_source,
            observations_seen=profile.count,
            deviating_features=deviating,
            feature_vector={k: round(v, 4) for k, v in
                            {**prompt_feats, **session_feats}.items()},
            novelty=round(novelty, 4),
            explanation=self._explain(anomaly, deviating, baseline_source, profile),
        )
        return report

    def _tenant_deviation(self, vec_std: np.ndarray, profile: TenantProfile) -> float:
        """Mahalanobis-lite deviation from this tenant's own centroid."""
        if profile.centroid is None:
            return 0.0
        d = np.abs(vec_std - profile.centroid)
        # Robust aggregation: the 90th percentile of per-feature deviation,
        # so one noisy dimension cannot alone declare an anomaly.
        dev = float(np.quantile(d, 0.90))
        return float(np.clip(dev / 4.0, 0.0, 1.0))

    def _top_deviations(self, vec_std: np.ndarray, profile: TenantProfile,
                        k: int = 5) -> List[Dict[str, object]]:
        ref = profile.centroid if (profile.centroid is not None and profile.count >= 5) \
            else self._global_mean
        if ref is None:
            return []
        diff = vec_std - ref
        idx = np.argsort(-np.abs(diff))[:k]
        out = []
        for i in idx:
            if abs(diff[i]) < 0.75:      # below ~0.75 sigma is not worth reporting
                continue
            out.append({
                "feature": ALL_FEATURES[i],
                "deviation_sigma": round(float(diff[i]), 2),
                "direction": "above" if diff[i] > 0 else "below",
            })
        return out

    @staticmethod
    def _explain(anomaly: float, deviating: List[Dict[str, object]],
                 source: str, profile: TenantProfile) -> str:
        if source == "cold_start":
            base = ("No behavioural history for this tenant yet; scored against the "
                    "global benign baseline.")
        elif source == "tenant":
            base = (f"Scored against this tenant's own learned baseline "
                    f"({profile.count} observations).")
        else:
            base = (f"Scored against the global benign baseline "
                    f"({profile.count}/{settings.baseline_min_observations} observations "
                    f"collected toward a tenant-specific baseline).")
        if anomaly >= 0.5 and deviating:
            drivers = ", ".join(
                f"{d['feature']} {d['direction']} baseline by {abs(d['deviation_sigma'])}σ"
                for d in deviating[:3]
            )
            return f"{base} Behaviour deviates from normal: {drivers}."
        if anomaly >= 0.5:
            return f"{base} Overall behavioural pattern is atypical."
        return f"{base} Behaviour is consistent with the learned normal pattern."

    # ------------------------------------------------------------------
    # Feedback + persistence
    # ------------------------------------------------------------------
    def record_outcome(self, tenant_id: str, is_threat: bool, risk: float) -> None:
        self.get_profile(tenant_id).record_outcome(is_threat, risk)

    def score_batch(self, prompts: Sequence[str]) -> np.ndarray:
        """Anomaly scores with no session context — used by the evaluator."""
        neutral = empty_session_features()
        X = np.vstack([full_vector(extract_prompt_features(p), neutral) for p in prompts])
        Xs = self.scaler.transform(_transform(X))
        self.forest.n_jobs = -1 if len(prompts) >= 32 else 1
        return self._calibrate(self.forest.decision_function(Xs))

    def save(self, path: Optional[Path] = None) -> Path:
        path = path or (MODEL_DIR / self.MODEL_FILE)
        atomic_dump({
            "scaler": self.scaler,
            "forest": self.forest,
            "threshold": self._threshold,
            "scale": self._scale,
            "global_mean": self._global_mean,
            "global_std": self._global_std,
            "trained_at": self.trained_at,
            "training_size": self.training_size,
            "feature_names": list(ALL_FEATURES),
        }, path, compress=3)
        return path

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "BehaviorLearningEngine":
        path = path or (MODEL_DIR / cls.MODEL_FILE)
        blob = joblib.load(path)
        eng = cls()
        eng.scaler = blob["scaler"]
        eng.forest = blob["forest"]
        eng._threshold = blob["threshold"]
        eng._scale = blob["scale"]
        eng._global_mean = blob["global_mean"]
        eng._global_std = blob["global_std"]
        eng.trained_at = blob.get("trained_at")
        eng.training_size = blob.get("training_size", 0)
        saved = blob.get("feature_names")
        if saved and list(saved) != list(ALL_FEATURES):
            raise ValueError(
                "Feature schema changed since this model was trained "
                f"({len(saved)} -> {len(ALL_FEATURES)} features). Retrain with scripts/train.py."
            )
        return eng

    @property
    def is_trained(self) -> bool:
        return self.forest is not None


__all__ = ["BehaviorLearningEngine", "TenantProfile"]
