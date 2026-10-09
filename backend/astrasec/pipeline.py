"""The AstraSec immune response pipeline.

This is the orchestrator that turns five independent engines into one
organism. A single request flows through the full immune cascade:

    ┌─ Module 1 ─┐   ┌─ Module 3 ─┐   ┌─ Module 2 ─┐   ┌─ Module 4 ─┐   ┌─ Module 5 ─┐
    │ Behaviour  │──▶│  Threat    │──▶│  Health &  │──▶│  Adaptive  │──▶│ Immune     │
    │ Learning   │   │ Prediction │   │   Risk     │   │  Defense   │   │ Memory     │
    └────────────┘   └────────────┘   └────────────┘   └────────────┘   └────────────┘
          ▲                 ▲                                                  │
          │                 └──────────── memory hint (secondary response) ────┤
          └──────────────── outcome feedback (streak, escalation slope) ───────┘

Note the two feedback edges — they are what make the system *adaptive* rather
than a fixed chain:

1. Module 5 recalls a matching antigen **before** Module 3 classifies, so a
   previously-seen attack gets a sharpened posterior (a secondary immune
   response is faster and more certain than a primary one).
2. The final verdict is fed back into Module 1's tenant profile, so an
   escalating campaign raises the behavioural anomaly score of the *next*
   request from that tenant.

Self-healing closes the third loop: rules synthesised by Module 5 are
installed into Module 4 as soon as they are promoted, so the defence policy
set grows without any model being retrained.
"""
from __future__ import annotations

import statistics
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from .config import MODEL_DIR, settings
from .engines import (
    AdaptiveDefenseEngine,
    BehaviorLearningEngine,
    HealthRiskAnalyzer,
    ImmuneMemoryEngine,
    LLMAdvisor,
    ThreatPredictionEngine,
)
from .schemas import (
    AppContext,
    BehaviorReport,
    DashboardSummary,
    DefenseAction,
    DefenseDecision,
    HealthBand,
    HealthReport,
    InspectionResult,
    InspectRequest,
    MemoryReport,
    Recommendation,
    Severity,
    ThreatClass,
    ThreatPrediction,
    ThreatTimelinePoint,
)


class ImmuneSystem:
    """End-to-end AstraSec artificial immune system."""

    def __init__(
        self,
        behavior: Optional[BehaviorLearningEngine] = None,
        prediction: Optional[ThreatPredictionEngine] = None,
        health: Optional[HealthRiskAnalyzer] = None,
        defense: Optional[AdaptiveDefenseEngine] = None,
        memory: Optional[ImmuneMemoryEngine] = None,
        advisor: Optional[LLMAdvisor] = None,
    ) -> None:
        self.advisor = advisor or LLMAdvisor()
        self.behavior = behavior or BehaviorLearningEngine()
        self.prediction = prediction or ThreatPredictionEngine()
        self.health = health or HealthRiskAnalyzer()
        self.defense = defense or AdaptiveDefenseEngine()
        self.memory = memory or ImmuneMemoryEngine(advisor=self.advisor)

        self.started_at = time.time()
        self.incidents: Deque[InspectionResult] = deque(maxlen=5_000)
        self.live_feed: Deque[Dict[str, Any]] = deque(maxlen=settings.live_feed_buffer)
        self._latencies: Deque[float] = deque(maxlen=2_000)
        self._counters: Counter = Counter()
        self._on_incident = []          # observer callbacks (used by WebSocket)

    # ------------------------------------------------------------------
    # Loading / readiness
    # ------------------------------------------------------------------
    @classmethod
    def load(cls, model_dir: Optional[Path] = None,
             advisor: Optional[LLMAdvisor] = None) -> "ImmuneSystem":
        """Restore a trained system from disk."""
        model_dir = model_dir or MODEL_DIR
        advisor = advisor or LLMAdvisor()
        behavior = BehaviorLearningEngine.load(model_dir / BehaviorLearningEngine.MODEL_FILE)
        prediction = ThreatPredictionEngine.load(model_dir / ThreatPredictionEngine.MODEL_FILE)

        mem_path = model_dir / ImmuneMemoryEngine.MODEL_FILE
        memory = (ImmuneMemoryEngine.load(mem_path, advisor=advisor)
                  if mem_path.exists() else ImmuneMemoryEngine(advisor=advisor))

        system = cls(behavior=behavior, prediction=prediction,
                     memory=memory, advisor=advisor)
        # Re-install any rules the memory engine had already promoted.
        for rule in memory.promoted_rules.values():
            system.defense.install_rule(rule)
        return system

    @property
    def is_ready(self) -> bool:
        return self.behavior.is_trained and self.prediction.is_trained

    def save(self, model_dir: Optional[Path] = None) -> Dict[str, str]:
        model_dir = model_dir or MODEL_DIR
        return {
            "behavior": str(self.behavior.save(model_dir / BehaviorLearningEngine.MODEL_FILE)),
            "prediction": str(self.prediction.save(model_dir / ThreatPredictionEngine.MODEL_FILE)),
            "memory": str(self.memory.save(model_dir / ImmuneMemoryEngine.MODEL_FILE)),
        }

    def subscribe(self, callback) -> None:
        self._on_incident.append(callback)

    # ------------------------------------------------------------------
    # The immune cascade
    # ------------------------------------------------------------------
    def inspect(self, request: InspectRequest, now: Optional[float] = None) -> InspectionResult:
        if not self.is_ready:
            raise RuntimeError(
                "AstraSec models are not trained. Run `python -m astrasec.train` first."
            )
        now = time.time() if now is None else now
        t_start = time.perf_counter()
        timings: Dict[str, float] = {}
        commit = request.persist

        # ---- Module 1: Behavior Learning ------------------------------
        t0 = time.perf_counter()
        behavior: BehaviorReport = self.behavior.analyse(
            request.prompt, tenant_id=request.tenant_id, now=now, update=commit
        )
        timings["module1_behavior_ms"] = (time.perf_counter() - t0) * 1000

        # ---- Module 5 (recall leg): does memory already know this? ----
        t0 = time.perf_counter()
        hint = self.memory.hint(request.prompt)
        timings["module5_recall_ms"] = (time.perf_counter() - t0) * 1000

        # ---- Module 3: Threat Prediction ------------------------------
        t0 = time.perf_counter()
        raw_pred = self.prediction.predict(request.prompt, memory_hint=hint)
        prediction = ThreatPrediction(**{
            k: v for k, v in raw_pred.items()
            if k in ThreatPrediction.model_fields
        })
        timings["module3_prediction_ms"] = (time.perf_counter() - t0) * 1000

        # ---- Module 2: AI Health & Risk -------------------------------
        t0 = time.perf_counter()
        health: HealthReport = self.health.analyse(
            prediction, behavior, request.app, update_rolling=commit, now=now
        )
        timings["module2_health_ms"] = (time.perf_counter() - t0) * 1000

        # ---- Module 4: Adaptive Defense -------------------------------
        t0 = time.perf_counter()
        defense: DefenseDecision = self.defense.decide(
            prompt=request.prompt,
            prediction=prediction,
            behavior=behavior,
            health=health,
            app=request.app,
            tenant_id=request.tenant_id,
            model_response=request.model_response,
            now=now,
            commit=commit,
        )
        timings["module4_defense_ms"] = (time.perf_counter() - t0) * 1000

        # ---- Module 5 (learn leg): commit to immune memory ------------
        t0 = time.perf_counter()
        if commit:
            memory = self.memory.learn(
                prompt=request.prompt,
                threat_class=prediction.threat_class,
                defense=defense.action,
                successful=not defense.allowed or defense.action in (
                    DefenseAction.SANITIZE, DefenseAction.MASK
                ),
                now=now,
            )
            # Install any newly promoted self-healing rules immediately.
            for rule in memory.rules_synthesized:
                if rule.active:
                    self.defense.install_rule(rule)
        else:
            cell, aff = self.memory.recall(request.prompt)
            memory = MemoryReport(
                matched_cell_id=cell.cell_id if cell else None,
                matched_affinity=round(aff, 4),
                recall_hit=bool(cell and aff >= settings.memory_affinity_threshold),
                cells_total=len(self.memory.cells),
                immunity_strength=self.memory.immunity_strength(),
                explanation="Dry-run inspection: immune memory was read but not updated.",
            )

        # Recommendations are generated for anything that is not clean traffic.
        if prediction.threat_class != ThreatClass.BENIGN or health.health_score < 75:
            memory.recommendations = self.memory.recommend(
                self._incident_summary(request, behavior, prediction, health, defense, memory),
                use_llm=self.advisor.provider != "offline",
            )
        timings["module5_memory_ms"] = (time.perf_counter() - t0) * 1000

        # ---- Feedback into Module 1 -----------------------------------
        if commit:
            self.behavior.record_outcome(
                request.tenant_id,
                is_threat=prediction.threat_class != ThreatClass.BENIGN,
                risk=health.weighted_risk,
            )

        verdict = self._verdict(defense)
        total_ms = (time.perf_counter() - t_start) * 1000

        result = InspectionResult(
            timestamp=now,
            tenant_id=request.tenant_id,
            app_id=request.app.app_id,
            prompt=request.prompt,
            prompt_preview=(request.prompt[:160] + "…") if len(request.prompt) > 160
            else request.prompt,
            behavior=behavior,
            health=health,
            prediction=prediction,
            defense=defense,
            memory=memory,
            verdict=verdict,
            latency_ms={k: round(v, 3) for k, v in timings.items()},
            total_latency_ms=round(total_ms, 3),
            narrative=self._narrative(behavior, prediction, health, defense, memory),
        )

        if commit:
            self._record(result)
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def _verdict(defense: DefenseDecision) -> str:
        if defense.action == DefenseAction.QUARANTINE:
            return "quarantined"
        if defense.action in (DefenseAction.BLOCK, DefenseAction.RATE_LIMIT):
            return "blocked"
        if defense.action in (DefenseAction.SANITIZE, DefenseAction.MASK):
            return "sanitized"
        return "allowed"

    def _record(self, result: InspectionResult) -> None:
        self.incidents.append(result)
        self._latencies.append(result.total_latency_ms)
        self._counters["total"] += 1
        self._counters[f"verdict:{result.verdict}"] += 1
        self._counters[f"class:{result.prediction.threat_class.value}"] += 1
        self._counters[f"severity:{result.prediction.severity.value}"] += 1
        self._counters[f"action:{result.defense.action.value}"] += 1
        if result.prediction.threat_class != ThreatClass.BENIGN:
            self._counters["threats"] += 1

        event = {
            "incident_id": result.incident_id,
            "timestamp": result.timestamp,
            "tenant_id": result.tenant_id,
            "app_id": result.app_id,
            "prompt_preview": result.prompt_preview,
            "threat_class": result.prediction.threat_class.value,
            "severity": result.prediction.severity.value,
            "confidence": result.prediction.confidence,
            "action": result.defense.action.value,
            "verdict": result.verdict,
            "health_score": result.health.health_score,
            "anomaly_score": result.behavior.anomaly_score,
            "recall_hit": result.memory.recall_hit,
            "latency_ms": result.total_latency_ms,
        }
        self.live_feed.append(event)
        for cb in self._on_incident:
            try:
                cb(event)
            except Exception:
                pass        # a broken subscriber must never break inspection

    # ------------------------------------------------------------------
    @staticmethod
    def _incident_summary(request, behavior, prediction, health, defense, memory
                          ) -> Dict[str, Any]:
        return {
            "threat_class": prediction.threat_class.value,
            "severity": prediction.severity.value,
            "confidence": prediction.confidence,
            "signature_hits": prediction.signature_hits,
            "health_score": health.health_score,
            "health_band": health.band.value,
            "surface_scores": health.surface_scores,
            "findings": [f.model_dump() for f in health.findings[:5]],
            "anomaly_score": behavior.anomaly_score,
            "threat_streak": behavior.feature_vector.get("threat_streak", 0),
            "defense_action": defense.action.value,
            "recall_hit": memory.recall_hit,
            "application": {
                "tool_calling_enabled": request.app.tool_calling_enabled,
                "retrieval_enabled": request.app.retrieval_enabled,
                "output_filtering_enabled": request.app.output_filtering_enabled,
                "system_prompt_protected": request.app.system_prompt_protected,
            },
            # The prompt itself is deliberately excluded from anything sent to
            # an external model: the advisor reasons over structured evidence,
            # not over attacker-controlled text.
        }

    @staticmethod
    def _narrative(behavior, prediction, health, defense, memory) -> str:
        """Human-readable five-step account of the immune response."""
        steps = [
            f"1. Behaviour Learning — {behavior.explanation} "
            f"(anomaly {behavior.anomaly_score:.2f})",
            f"2. Health & Risk — {health.explanation}",
            f"3. Threat Prediction — {prediction.explanation}",
            f"4. Adaptive Defense — {defense.rationale}",
            f"5. Immune Memory — {memory.explanation}",
        ]
        return "\n".join(steps)

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------
    def summary(self, app_id: Optional[str] = None) -> DashboardSummary:
        records = [r for r in self.incidents
                   if app_id is None or r.app_id == app_id]
        total = len(records)
        threats = sum(1 for r in records if r.prediction.threat_class != ThreatClass.BENIGN)
        blocked = sum(1 for r in records if r.verdict in ("blocked", "quarantined"))
        sanitized = sum(1 for r in records if r.verdict == "sanitized")

        lat = [r.total_latency_ms for r in records] or [0.0]
        lat_sorted = sorted(lat)
        p95 = lat_sorted[min(len(lat_sorted) - 1, int(0.95 * len(lat_sorted)))]

        current_app = app_id or (records[-1].app_id if records else "default-app")
        current_health = (self.health.current(current_app) if records
                          else 100.0)

        tenant_counter: Counter = Counter()
        tenant_threats: Counter = Counter()
        for r in records:
            tenant_counter[r.tenant_id] += 1
            if r.prediction.threat_class != ThreatClass.BENIGN:
                tenant_threats[r.tenant_id] += 1

        return DashboardSummary(
            total_requests=total,
            threats_detected=threats,
            threats_blocked=blocked,
            threats_sanitized=sanitized,
            block_rate=round(blocked / total, 4) if total else 0.0,
            detection_rate=round(threats / total, 4) if total else 0.0,
            current_health_score=round(current_health, 2),
            health_band=self.health._band(current_health),
            mean_latency_ms=round(statistics.fmean(lat), 3),
            p95_latency_ms=round(p95, 3),
            threat_distribution=dict(Counter(
                r.prediction.threat_class.value for r in records)),
            severity_distribution=dict(Counter(
                r.prediction.severity.value for r in records)),
            action_distribution=dict(Counter(
                r.defense.action.value for r in records)),
            timeline=self._timeline(records),
            health_history=self.health.get_history(current_app, limit=200),
            immune_memory_cells=len(self.memory.cells),
            immune_memory_recall_rate=round(self.memory.recall_rate(), 4),
            active_rules=len(self.defense.active_rules),
            quarantined_tenants=self.defense.quarantined_tenants(),
            top_tenants=[
                {"tenant_id": t, "requests": c, "threats": tenant_threats.get(t, 0),
                 "threat_rate": round(tenant_threats.get(t, 0) / c, 3)}
                for t, c in tenant_counter.most_common(8)
            ],
            recent_recommendations=self.memory.recent_recommendations(6),
        )

    @staticmethod
    def _timeline(records: List[InspectionResult], buckets: int = 24
                  ) -> List[ThreatTimelinePoint]:
        if not records:
            return []
        # Take the true extent rather than first/last: the traffic simulator
        # spreads synthetic timestamps forward in time, so a request inspected
        # later in real time can carry an earlier timestamp than one already
        # in the buffer. Assuming arrival order here collapsed the whole
        # timeline into a single bucket at one end of the axis.
        stamps = [r.timestamp for r in records]
        t0, t1 = min(stamps), max(stamps)
        span = max(1e-6, t1 - t0)
        width = span / buckets
        agg: Dict[int, Dict[str, int]] = {
            i: {"total": 0, "blocked": 0, "sanitized": 0, "allowed": 0}
            for i in range(buckets)
        }
        for r in records:
            i = max(0, min(buckets - 1, int((r.timestamp - t0) / width)))
            agg[i]["total"] += 1
            if r.verdict in ("blocked", "quarantined"):
                agg[i]["blocked"] += 1
            elif r.verdict == "sanitized":
                agg[i]["sanitized"] += 1
            else:
                agg[i]["allowed"] += 1
        out = []
        for i in range(buckets):
            ts = t0 + i * width
            out.append(ThreatTimelinePoint(
                bucket=time.strftime("%H:%M:%S", time.localtime(ts)),
                **agg[i],
            ))
        return out

    def reset(self) -> None:
        """Clear runtime state (keeps trained models)."""
        self.incidents.clear()
        self.live_feed.clear()
        self._latencies.clear()
        self._counters.clear()
        self.health.reset()
        self.behavior.profiles.clear()
        self.defense.tenants.clear()

    def stats(self) -> Dict[str, Any]:
        return {
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "counters": dict(self._counters),
            "memory": self.memory.stats(),
            "defense": self.defense.stats(),
            "llm": self.advisor.info(),
            "behavior": {
                "tenants_profiled": len(self.behavior.profiles),
                "training_size": self.behavior.training_size,
            },
            "prediction": {
                "classes": self.prediction.classes_,
                "training_size": self.prediction.training_size,
            },
        }


__all__ = ["ImmuneSystem"]
