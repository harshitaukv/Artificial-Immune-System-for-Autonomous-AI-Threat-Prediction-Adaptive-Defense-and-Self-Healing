"""Module 2 — AI Health & Risk Analyzer.

Biological analogue: *homeostasis monitoring*. An immune system does not only
react to pathogens; it continuously reports on the health of the organism. This
engine produces the **AI Health Score** — a single 0–100 number that fuses four
independent risk surfaces — plus a severity-ranked list of findings with
concrete remediation.

    Health Score = 100 x (1 - Σ wᵢ · rᵢ)

where the four surfaces rᵢ ∈ [0,1] and their weights wᵢ come from
:attr:`astrasec.config.Settings.health_weights`:

  ``prompt_risk``         what this specific request is trying to do
  ``behaviour_risk``      how far the tenant has drifted from its own baseline
  ``configuration_risk``  the deployment posture of the protected application
  ``dependency_risk``     known-vulnerable components in the AI supply chain

The first two are *instantaneous*; the last two are *structural* and change
only when the application's configuration changes. A rolling score with an
exponential half-life is also maintained, so one malicious request dents the
score but a sustained campaign collapses it.
"""
from __future__ import annotations

import math
import time
from typing import Dict, List, Optional, Tuple

from ..config import settings
from ..schemas import (
    AppContext,
    BehaviorReport,
    HealthBand,
    HealthReport,
    RiskFinding,
    Severity,
    ThreatPrediction,
)
from ..signatures import SEVERITY_SCORE

# --------------------------------------------------------------------------
# Configuration posture checks
# --------------------------------------------------------------------------
# (attribute, expected_value, weight, code, title, remediation)
CONFIG_CHECKS: List[Tuple[str, bool, float, str, str, str]] = [
    ("system_prompt_protected", True, 0.20, "CFG-001",
     "System prompt is not protected against extraction",
     "Enable system-prompt isolation and refuse verbatim disclosure of instructions."),
    ("output_filtering_enabled", True, 0.18, "CFG-002",
     "Model output is not filtered before reaching the user",
     "Enable response filtering so credentials, PII and leaked instructions are masked."),
    ("pii_redaction_enabled", True, 0.16, "CFG-003",
     "PII redaction is disabled",
     "Turn on PII redaction on both the inbound prompt and the outbound response."),
    ("authentication_required", True, 0.14, "CFG-004",
     "Endpoint accepts unauthenticated requests",
     "Require authenticated, per-tenant identity so abuse can be attributed and rate-limited."),
    ("rate_limiting_enabled", True, 0.10, "CFG-005",
     "No rate limiting configured",
     "Apply per-tenant token-bucket limits to blunt extraction and brute-force probing."),
    ("sandbox_enabled", True, 0.12, "CFG-006",
     "Model runs without an execution sandbox",
     "Sandbox tool execution so a successful injection cannot reach the host."),
    ("logging_enabled", True, 0.10, "CFG-007",
     "Security logging is disabled",
     "Enable immutable audit logging of prompts, verdicts and defence actions."),
]

# Capabilities that *widen the blast radius* of a successful injection.
SURFACE_CHECKS: List[Tuple[str, float, str, str, str]] = [
    ("tool_calling_enabled", 0.22, "CFG-101",
     "Tool/function calling is enabled",
     "A successful prompt injection can invoke tools. Enforce per-tool allow-lists, "
     "human confirmation for state-changing calls, and sandboxing."),
    ("retrieval_enabled", 0.16, "CFG-102",
     "Retrieval-augmented generation is enabled",
     "Untrusted retrieved documents can carry indirect prompt injection. "
     "Sanitise retrieved content and mark it as data, never as instructions."),
]

# A small offline advisory table for the AI supply chain. In a production
# deployment this would be backed by OSV/NVD; keeping it local means the
# analyser works with no network, which is a deployment requirement here.
DEPENDENCY_ADVISORIES: Dict[str, Tuple[Severity, str, str]] = {
    "langchain<0.1.0": (Severity.HIGH, "DEP-001",
                        "Server-side request forgery and unsafe deserialization in early LangChain chains."),
    "pickle": (Severity.CRITICAL, "DEP-002",
               "Loading models via pickle allows arbitrary code execution on deserialization."),
    "torch<2.0": (Severity.MEDIUM, "DEP-003",
                  "Older torch releases lack `weights_only` loading, enabling malicious checkpoints."),
    "transformers<4.36": (Severity.MEDIUM, "DEP-004",
                          "`trust_remote_code` paths permit arbitrary code from model repositories."),
    "gradio<4.0": (Severity.HIGH, "DEP-005",
                   "Path traversal and unauthenticated file read in older Gradio servers."),
    "pyyaml<5.4": (Severity.HIGH, "DEP-006",
                   "`yaml.load` without SafeLoader permits arbitrary object construction."),
    "requests<2.31": (Severity.MEDIUM, "DEP-007",
                      "Proxy-Authorization header leak on cross-origin redirect."),
    "flask<2.3.2": (Severity.MEDIUM, "DEP-008",
                    "Session cookie handling issue when running behind a caching proxy."),
}


class HealthRiskAnalyzer:
    """Weighted multi-surface risk scoring producing the AI Health Score."""

    def __init__(self) -> None:
        self.weights = dict(settings.health_weights)
        self.bands = dict(settings.health_bands)
        # Rolling health per application, decayed toward 100 over time.
        self._rolling: Dict[str, float] = {}
        self._last_update: Dict[str, float] = {}
        self.history: Dict[str, List[Dict[str, float]]] = {}

    # ------------------------------------------------------------------
    # Surface scorers
    # ------------------------------------------------------------------
    @staticmethod
    def _prompt_risk(prediction: ThreatPrediction) -> Tuple[float, List[RiskFinding]]:
        findings: List[RiskFinding] = []
        if prediction.threat_class.value == "benign":
            return 0.0, findings

        sev_weight = SEVERITY_SCORE[prediction.severity]
        risk = float(min(1.0, sev_weight * (0.6 + 0.4 * prediction.confidence)))

        findings.append(RiskFinding(
            surface="prompt",
            code=f"PRM-{prediction.threat_class.value.upper()[:6]}",
            title=f"{prediction.threat_class.value.replace('_', ' ').title()} detected in request",
            severity=prediction.severity,
            score=risk,
            evidence=(f"Classifier confidence {prediction.confidence:.0%}"
                      + (f"; signatures {', '.join(prediction.signature_hits[:3])}"
                         if prediction.signature_hits else "")),
            remediation=_PROMPT_REMEDIATION.get(
                prediction.threat_class.value,
                "Apply the recommended defence action and review the incident.",
            ),
        ))
        return risk, findings

    @staticmethod
    def _behaviour_risk(behavior: BehaviorReport) -> Tuple[float, List[RiskFinding]]:
        findings: List[RiskFinding] = []
        fv = behavior.feature_vector
        risk = behavior.anomaly_score

        streak = fv.get("threat_streak", 0.0)
        slope = fv.get("escalation_slope", 0.0)
        rate = fv.get("requests_in_window", 0.0)
        repeat = fv.get("distinct_template_ratio", 1.0)

        # Campaign indicators compound the instantaneous anomaly.
        if streak >= 3:
            risk = min(1.0, risk + 0.10 * min(streak, 6) / 6 * 2)
            findings.append(RiskFinding(
                surface="behaviour", code="BHV-001",
                title="Consecutive malicious requests from the same tenant",
                severity=Severity.HIGH if streak >= 5 else Severity.MEDIUM,
                score=min(1.0, streak / 8.0),
                evidence=f"{int(streak)} consecutive flagged requests",
                remediation="Quarantine the tenant and require re-authentication.",
            ))
        if slope > 0.05:
            risk = min(1.0, risk + 0.12)
            findings.append(RiskFinding(
                surface="behaviour", code="BHV-002",
                title="Escalating risk trajectory",
                severity=Severity.MEDIUM,
                score=float(min(1.0, slope * 4)),
                evidence=f"Risk slope +{slope:.3f} per request over the recent window",
                remediation="Probing campaign in progress; lower the block threshold for this tenant.",
            ))
        if rate > settings.rate_limit_requests * 0.8:
            findings.append(RiskFinding(
                surface="behaviour", code="BHV-003",
                title="Request rate approaching the configured limit",
                severity=Severity.MEDIUM,
                score=float(min(1.0, rate / max(1, settings.rate_limit_requests))),
                evidence=f"{int(rate)} requests in the last {settings.behaviour_window_seconds}s",
                remediation="Possible automated extraction; enforce stricter rate limiting.",
            ))
        if repeat < 0.35 and fv.get("session_depth", 0) > 10:
            findings.append(RiskFinding(
                surface="behaviour", code="BHV-004",
                title="Highly repetitive querying pattern",
                severity=Severity.MEDIUM,
                score=float(1.0 - repeat),
                evidence=f"Only {repeat:.0%} of recent prompts are distinct",
                remediation="Consistent with systematic model extraction; throttle and audit.",
            ))
        if behavior.is_anomalous and not findings:
            findings.append(RiskFinding(
                surface="behaviour", code="BHV-000",
                title="Request deviates from the learned behavioural baseline",
                severity=Severity.MEDIUM if behavior.anomaly_score < 0.75 else Severity.HIGH,
                score=behavior.anomaly_score,
                evidence=behavior.explanation,
                remediation="Monitor the tenant; confirm whether this is a legitimate new use case.",
            ))
        return float(min(1.0, risk)), findings

    @staticmethod
    def _configuration_risk(app: AppContext) -> Tuple[float, List[RiskFinding]]:
        findings: List[RiskFinding] = []
        penalty = 0.0
        total_weight = sum(w for _, _, w, _, _, _ in CONFIG_CHECKS)

        for attr, expected, weight, code, title, fix in CONFIG_CHECKS:
            if getattr(app, attr, expected) != expected:
                penalty += weight
                sev = (Severity.CRITICAL if weight >= 0.18 else
                       Severity.HIGH if weight >= 0.13 else Severity.MEDIUM)
                findings.append(RiskFinding(
                    surface="configuration", code=code, title=title, severity=sev,
                    score=weight / total_weight * 2, weight=weight,
                    evidence=f"{attr} = {getattr(app, attr, None)}", remediation=fix,
                ))

        # Capability surface only counts as risk when protections are missing.
        for attr, weight, code, title, fix in SURFACE_CHECKS:
            if getattr(app, attr, False):
                unguarded = not app.sandbox_enabled if attr == "tool_calling_enabled" \
                    else not app.output_filtering_enabled
                effective = weight if unguarded else weight * 0.35
                penalty += effective
                findings.append(RiskFinding(
                    surface="configuration", code=code, title=title,
                    severity=Severity.HIGH if unguarded else Severity.LOW,
                    score=effective, weight=effective,
                    evidence=f"{attr} = True"
                             + ("; no compensating control" if unguarded else "; compensating control active"),
                    remediation=fix,
                ))

        if app.last_security_review_days > 90:
            penalty += 0.12
            findings.append(RiskFinding(
                surface="configuration", code="CFG-008",
                title="Security review is overdue",
                severity=Severity.MEDIUM, score=0.12,
                evidence=f"Last reviewed {app.last_security_review_days} days ago",
                remediation="Re-run the AI security review; posture drifts as the app evolves.",
            ))

        return float(min(1.0, penalty)), findings

    @staticmethod
    def _dependency_risk(app: AppContext) -> Tuple[float, List[RiskFinding]]:
        findings: List[RiskFinding] = []
        declared = {d.lower().strip() for d in app.dependencies}
        flagged = {d.lower().strip() for d in app.known_vulnerable_dependencies}

        risk = 0.0
        for advisory, (sev, code, detail) in DEPENDENCY_ADVISORIES.items():
            name = advisory.split("<")[0].split(">")[0].split("=")[0]
            if advisory.lower() in flagged or name in flagged or (
                name in declared and advisory.lower() in flagged
            ):
                contribution = SEVERITY_SCORE[sev] * 0.35
                risk += contribution
                findings.append(RiskFinding(
                    surface="dependency", code=code,
                    title=f"Vulnerable dependency: {advisory}",
                    severity=sev, score=SEVERITY_SCORE[sev],
                    evidence=detail,
                    remediation=f"Upgrade {name} to a patched release and re-run the SBOM scan.",
                ))
        # Anything the operator explicitly flagged but we have no advisory for
        # still counts — unknown is not the same as safe.
        known_names = {a.split("<")[0].split(">")[0].split("=")[0] for a in DEPENDENCY_ADVISORIES}
        for dep in flagged:
            base = dep.split("<")[0].split(">")[0].split("=")[0]
            if base not in known_names and dep not in DEPENDENCY_ADVISORIES:
                risk += 0.18
                findings.append(RiskFinding(
                    surface="dependency", code="DEP-999",
                    title=f"Dependency flagged as vulnerable: {dep}",
                    severity=Severity.MEDIUM, score=0.5,
                    evidence="Marked vulnerable by the operator; no local advisory detail.",
                    remediation=f"Review and upgrade {dep}.",
                ))
        if not app.dependencies:
            risk += 0.08
            findings.append(RiskFinding(
                surface="dependency", code="DEP-000",
                title="No software bill of materials declared",
                severity=Severity.LOW, score=0.25,
                evidence="dependencies list is empty",
                remediation="Declare the AI stack's dependencies so supply-chain risk can be assessed.",
            ))
        return float(min(1.0, risk)), findings

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def analyse(self, prediction: ThreatPrediction, behavior: BehaviorReport,
                app: AppContext, update_rolling: bool = True,
                now: Optional[float] = None) -> HealthReport:
        now = time.time() if now is None else now

        r_prompt, f_prompt = self._prompt_risk(prediction)
        r_behav, f_behav = self._behaviour_risk(behavior)
        r_config, f_config = self._configuration_risk(app)
        r_dep, f_dep = self._dependency_risk(app)

        surfaces = {
            "prompt_risk": r_prompt,
            "behaviour_risk": r_behav,
            "configuration_risk": r_config,
            "dependency_risk": r_dep,
        }
        weighted = sum(self.weights[k] * v for k, v in surfaces.items())
        score = max(0.0, min(100.0, 100.0 * (1.0 - weighted)))

        findings = f_prompt + f_behav + f_config + f_dep
        for f in findings:
            f.weight = self.weights.get(f"{f.surface}_risk", f.weight)
        findings.sort(key=lambda f: (-SEVERITY_SCORE[f.severity], -f.score))
        top = findings[0] if findings else None

        rolling = self._update_rolling(app.app_id, score, now, update_rolling)
        band = self._band(score)

        report = HealthReport(
            health_score=round(score, 2),
            band=band,
            risk_level=self._risk_level(weighted),
            surface_scores={k: round(v, 4) for k, v in surfaces.items()},
            weighted_risk=round(weighted, 4),
            findings=findings,
            top_priority=top,
            rolling_health_score=round(rolling, 2),
            explanation=self._explain(score, band, surfaces, top),
        )
        if update_rolling:
            self.history.setdefault(app.app_id, []).append(
                {"t": now, "score": round(score, 2), "rolling": round(rolling, 2)}
            )
            self.history[app.app_id] = self.history[app.app_id][-500:]
        return report

    # ------------------------------------------------------------------
    def _update_rolling(self, app_id: str, score: float, now: float,
                        commit: bool) -> float:
        prev = self._rolling.get(app_id, 100.0)
        last = self._last_update.get(app_id, now)

        # Recover toward 100 with the configured half-life (measured in
        # requests; elapsed time is used as a secondary recovery term).
        alpha = 1.0 - math.pow(0.5, 1.0 / max(1, settings.health_decay_halflife))
        new = prev + alpha * (score - prev)

        elapsed_minutes = max(0.0, (now - last) / 60.0)
        if elapsed_minutes > 1.0:
            recovery = 1.0 - math.pow(0.5, elapsed_minutes / 30.0)
            new = new + recovery * (100.0 - new) * 0.5

        new = float(max(0.0, min(100.0, new)))
        if commit:
            self._rolling[app_id] = new
            self._last_update[app_id] = now
        return new

    def _band(self, score: float) -> HealthBand:
        if score < self.bands["critical"]:
            return HealthBand.CRITICAL
        if score < self.bands["high"]:
            return HealthBand.HIGH
        if score < self.bands["moderate"]:
            return HealthBand.MODERATE
        if score < self.bands["healthy"]:
            return HealthBand.HEALTHY
        return HealthBand.OPTIMAL

    @staticmethod
    def _risk_level(weighted: float) -> Severity:
        if weighted >= 0.60:
            return Severity.CRITICAL
        if weighted >= 0.40:
            return Severity.HIGH
        if weighted >= 0.22:
            return Severity.MEDIUM
        if weighted >= 0.08:
            return Severity.LOW
        return Severity.NONE

    @staticmethod
    def _explain(score: float, band: HealthBand, surfaces: Dict[str, float],
                 top: Optional[RiskFinding]) -> str:
        driver = max(surfaces, key=surfaces.get)
        pretty = driver.replace("_risk", "").replace("_", " ")
        msg = (f"AI Health Score {score:.0f}/100 ({band.value}); "
               f"largest contributor is {pretty} risk at {surfaces[driver]:.0%}.")
        if top:
            msg += f" Highest-priority finding: {top.title} ({top.severity.value})."
        return msg

    def current(self, app_id: str) -> float:
        return self._rolling.get(app_id, 100.0)

    def get_history(self, app_id: str, limit: int = 200) -> List[Dict[str, float]]:
        return self.history.get(app_id, [])[-limit:]

    def reset(self, app_id: Optional[str] = None) -> None:
        if app_id:
            self._rolling.pop(app_id, None)
            self.history.pop(app_id, None)
        else:
            self._rolling.clear()
            self.history.clear()


_PROMPT_REMEDIATION = {
    "prompt_injection": "Isolate the system prompt, treat all user and retrieved text as data, "
                        "and never let inbound content redefine the agent's instructions.",
    "jailbreak": "Enforce a persona lock and refusal policy that survives role-play framing; "
                 "re-assert the system prompt on every turn.",
    "adversarial_obfuscation": "Normalise Unicode, strip zero-width characters and decode "
                               "embedded payloads before the prompt reaches the model.",
    "data_exfiltration": "Enable output-side DLP: mask credentials, PII and any verbatim "
                         "reproduction of the system prompt.",
    "model_extraction": "Apply per-tenant quotas, suppress logits/log-probs, and watermark "
                        "responses to deter distillation.",
}

__all__ = ["HealthRiskAnalyzer", "CONFIG_CHECKS", "SURFACE_CHECKS", "DEPENDENCY_ADVISORIES"]
