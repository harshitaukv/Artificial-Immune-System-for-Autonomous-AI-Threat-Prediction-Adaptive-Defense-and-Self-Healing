"""Module 4 — Adaptive Defense Engine.

Biological analogue: the *effector response*. Once an antigen is recognised,
the immune system does not apply one blunt reaction — it selects a
proportionate one: neutralise, opsonise, isolate, or destroy. This engine does
the same through a deterministic escalation ladder:

    ALLOW  →  MONITOR  →  SANITIZE / MASK  →  RATE_LIMIT  →  BLOCK  →  QUARANTINE

Selection is rule-based and fully auditable (the project specifies a
Rule-Based Decision Engine here, deliberately: a security control that cannot
explain itself cannot be operated). The rules read the outputs of Modules 1-3
plus the tenant's standing and the application's own configuration, so the
*same* prompt can be sanitised for a hardened application and blocked for an
unprotected one.

Two properties make this more than a lookup table:

* **Sanitise-then-revalidate.** A sanitised prompt is re-scanned from scratch.
  If the attack survives cleaning, the request is blocked rather than passed
  through — cleaning is never assumed to have worked.
* **Self-healing rules.** Policies synthesised by Module 5 are injected here
  at runtime, so defences the system invented for itself are enforced by the
  same ladder as the built-in ones.
"""
from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

from ..config import settings
from ..features import ZERO_WIDTH, normalise_evasion
from ..schemas import (
    AppContext,
    BehaviorReport,
    DefenseAction,
    DefenseDecision,
    HealthReport,
    SanitizationStep,
    Severity,
    SynthesizedRule,
    ThreatPrediction,
)
from ..signatures import (
    RESPONSE_SIGNATURES,
    SEVERITY_SCORE,
    SIGNATURES,
    Hit,
    Signature,
    scan,
    signature_risk,
)

# Ordering of the escalation ladder — index is used for "take the strongest".
ACTION_RANK: Dict[DefenseAction, int] = {
    DefenseAction.ALLOW: 0,
    DefenseAction.MONITOR: 1,
    DefenseAction.SANITIZE: 2,
    DefenseAction.MASK: 3,
    DefenseAction.RATE_LIMIT: 4,
    DefenseAction.BLOCK: 5,
    DefenseAction.QUARANTINE: 6,
}

# Structural sanitisation applied to every request that reaches the SANITIZE
# rung, independent of which signature fired.
STRUCTURAL_RULES: List[Tuple[str, re.Pattern, str, str]] = [
    ("SAN-001", re.compile(f"[{ZERO_WIDTH}]+"), "",
     "Strip zero-width characters used to smuggle hidden instructions"),
    ("SAN-002", re.compile(r"<\|[^|>]{0,40}\|>"), "",
     "Remove chat-template control tokens"),
    ("SAN-003", re.compile(r"(?im)^\s*(###\s*system\s*###|<<<?SYS>>>?|\[/?INST\]|<system>|</system>)\s*$"), "",
     "Delete forged system-role delimiter lines"),
    ("SAN-004", re.compile(r"<!--.*?-->", re.DOTALL), "",
     "Remove HTML comments (indirect-injection carrier)"),
    ("SAN-005", re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"), "",
     "Remove control characters"),
    ("SAN-006", re.compile(
        r"(?i)\b(ignore|disregard|forget|override|discard|bypass)\b[^.?!\n]{0,40}\b"
        r"(all\s+)?(previous|prior|earlier|above|preceding|initial)\b[^.?!\n]{0,30}\b"
        r"(instruction|instructions|prompt|prompts|message|messages|rule|rules|context)\b"),
     "[INSTRUCTION-OVERRIDE-REMOVED]",
     "Neutralise instruction-override chains"),
    ("SAN-007", re.compile(r"(?i)\b(you\s+are\s+now|from\s+now\s+on)\b[^.?!\n]{0,60}\b"
                           r"(no\s+(rules|restrictions|limits|filters)|unrestricted|unfiltered)\b"),
     "[PERSONA-OVERRIDE-REMOVED]",
     "Neutralise persistent persona re-programming"),
]


@dataclass
class TenantDefenseState:
    """Per-tenant enforcement state: rate budget, strikes, quarantine."""

    tenant_id: str
    bucket: Deque[float] = field(default_factory=deque)
    strikes: int = 0
    quarantined_until: float = 0.0
    total_blocked: int = 0
    total_sanitized: int = 0
    total_allowed: int = 0

    def consume(self, now: float) -> Tuple[bool, int]:
        """Token bucket. Returns (within_limit, remaining)."""
        window = settings.rate_limit_window_seconds
        while self.bucket and now - self.bucket[0] > window:
            self.bucket.popleft()
        limit = settings.rate_limit_requests
        if len(self.bucket) >= limit:
            return False, 0
        self.bucket.append(now)
        return True, limit - len(self.bucket)

    def is_quarantined(self, now: float) -> bool:
        return now < self.quarantined_until

    def quarantine(self, now: float) -> None:
        self.quarantined_until = now + settings.quarantine_seconds
        self.strikes = 0


class AdaptiveDefenseEngine:
    """Rule-based, proportionate response selection and enforcement."""

    def __init__(self) -> None:
        self.tenants: Dict[str, TenantDefenseState] = {}
        # Rules synthesised by Module 5 and promoted to active enforcement.
        self.active_rules: Dict[str, SynthesizedRule] = {}
        self._compiled: Dict[str, re.Pattern] = {}

    # ------------------------------------------------------------------
    def state(self, tenant_id: str) -> TenantDefenseState:
        if tenant_id not in self.tenants:
            self.tenants[tenant_id] = TenantDefenseState(tenant_id=tenant_id)
        return self.tenants[tenant_id]

    def install_rule(self, rule: SynthesizedRule) -> bool:
        """Activate a self-healing rule produced by Module 5."""
        try:
            self._compiled[rule.rule_id] = re.compile(rule.pattern, re.IGNORECASE)
        except re.error:
            return False
        rule.active = True
        self.active_rules[rule.rule_id] = rule
        return True

    def remove_rule(self, rule_id: str) -> bool:
        self._compiled.pop(rule_id, None)
        return self.active_rules.pop(rule_id, None) is not None

    def _match_synth_rules(self, text: str) -> List[SynthesizedRule]:
        out = []
        norm = normalise_evasion(text)
        for rid, rule in self.active_rules.items():
            pat = self._compiled.get(rid)
            if pat and (pat.search(text) or pat.search(norm)):
                out.append(rule)
        return out

    # ------------------------------------------------------------------
    # Decision
    # ------------------------------------------------------------------
    def decide(
        self,
        prompt: str,
        prediction: ThreatPrediction,
        behavior: BehaviorReport,
        health: HealthReport,
        app: AppContext,
        tenant_id: str = "anonymous",
        model_response: Optional[str] = None,
        now: Optional[float] = None,
        commit: bool = True,
    ) -> DefenseDecision:
        now = time.time() if now is None else now
        st = self.state(tenant_id)
        policies: List[str] = []
        actions: List[DefenseAction] = []
        reasons: List[str] = []

        # ---- Rung 0: standing quarantine ------------------------------
        if st.is_quarantined(now):
            return DefenseDecision(
                action=DefenseAction.QUARANTINE,
                actions_applied=[DefenseAction.QUARANTINE],
                allowed=False,
                policy_ids=["POL-QUARANTINE"],
                rationale=(f"Tenant is quarantined until "
                           f"{time.strftime('%H:%M:%S', time.localtime(st.quarantined_until))} "
                           f"after repeated high-severity incidents."),
                residual_risk=0.0,
                quarantined_until=st.quarantined_until,
            )

        # ---- Rung 1: rate limiting ------------------------------------
        within, remaining = st.consume(now) if commit else (True, settings.rate_limit_requests)
        if not within:
            if commit:
                st.total_blocked += 1
            return DefenseDecision(
                action=DefenseAction.RATE_LIMIT,
                actions_applied=[DefenseAction.RATE_LIMIT],
                allowed=False,
                policy_ids=["POL-RATE-001"],
                rationale=(f"Rate limit exceeded: more than {settings.rate_limit_requests} "
                           f"requests in {settings.rate_limit_window_seconds}s."),
                residual_risk=0.0,
                rate_limit_remaining=0,
            )

        # ---- Compute the threat pressure driving the ladder -----------
        threat = prediction.threat_class.value
        severity_weight = SEVERITY_SCORE[prediction.severity]
        pressure = self._pressure(prediction, behavior, health, app)

        hits = scan(prompt)
        synth_matches = self._match_synth_rules(prompt)

        # Strongest action demanded by any individual signature.
        sig_action = DefenseAction.ALLOW
        for hit in hits:
            sig = hit.signature
            if ACTION_RANK[sig.action] > ACTION_RANK[sig_action]:
                sig_action = sig.action
                policies.append(sig.id)
        for rule in synth_matches:
            if ACTION_RANK[rule.action] > ACTION_RANK[sig_action]:
                sig_action = rule.action
            policies.append(rule.rule_id)
            reasons.append(f"self-healing rule {rule.rule_id} matched")

        # Threshold ladder from the aggregate pressure.
        if pressure >= settings.defense_block_threshold:
            ladder_action = DefenseAction.BLOCK
            policies.append("POL-THRESH-BLOCK")
        elif pressure >= settings.defense_sanitize_threshold:
            ladder_action = DefenseAction.SANITIZE
            policies.append("POL-THRESH-SANITIZE")
        elif pressure >= settings.defense_monitor_threshold:
            ladder_action = DefenseAction.MONITOR
            policies.append("POL-THRESH-MONITOR")
        else:
            ladder_action = DefenseAction.ALLOW

        action = ladder_action if ACTION_RANK[ladder_action] >= ACTION_RANK[sig_action] else sig_action

        # ---- Contextual adjustments -----------------------------------
        # An application that cannot filter its own output must not be handed
        # a data-exfiltration attempt at all.
        if threat == "data_exfiltration" and not app.output_filtering_enabled:
            if ACTION_RANK[action] < ACTION_RANK[DefenseAction.BLOCK]:
                action = DefenseAction.BLOCK
                policies.append("POL-CTX-001")
                reasons.append("output filtering disabled on this application")
        # Tool-calling agents have a far larger blast radius for injection.
        if threat == "prompt_injection" and app.tool_calling_enabled and not app.sandbox_enabled:
            if ACTION_RANK[action] < ACTION_RANK[DefenseAction.BLOCK]:
                action = DefenseAction.BLOCK
                policies.append("POL-CTX-002")
                reasons.append("unsandboxed tool calling enabled")
        # A tenant already in an escalating campaign gets no benefit of doubt.
        if behavior.feature_vector.get("threat_streak", 0) >= 3 and threat != "benign":
            if ACTION_RANK[action] < ACTION_RANK[DefenseAction.BLOCK]:
                action = DefenseAction.BLOCK
                policies.append("POL-CTX-003")
                reasons.append("tenant is in an active attack streak")
        # Privileged internal callers get one rung of leniency, but never
        # below SANITIZE and never for critical classes.
        if app.authentication_required and prediction.severity in (Severity.LOW, Severity.MEDIUM):
            if action == DefenseAction.BLOCK and threat in ("model_extraction",):
                action = DefenseAction.RATE_LIMIT
                policies.append("POL-CTX-004")
                reasons.append("authenticated tenant, non-critical class: throttled instead of blocked")

        # ---- Execute the chosen action --------------------------------
        sanitized: Optional[str] = None
        steps: List[SanitizationStep] = []
        revalidated_clean = True
        residual = 0.0
        allowed = action in (DefenseAction.ALLOW, DefenseAction.MONITOR,
                             DefenseAction.SANITIZE, DefenseAction.MASK)

        if action in (DefenseAction.SANITIZE, DefenseAction.MASK):
            sanitized, steps = self.sanitize(prompt, hits)
            # Sanitise-then-revalidate: never trust that cleaning worked.
            residual = signature_risk(scan(sanitized))
            revalidated_clean = residual < 0.35
            if not revalidated_clean:
                action = DefenseAction.BLOCK
                allowed = False
                policies.append("POL-REVALIDATE-001")
                reasons.append(
                    f"attack survived sanitisation (residual signature risk {residual:.0%})"
                )

        if action in (DefenseAction.BLOCK, DefenseAction.QUARANTINE):
            allowed = False

        # ---- Strikes and quarantine promotion -------------------------
        if commit:
            if action in (DefenseAction.BLOCK, DefenseAction.QUARANTINE) and threat != "benign":
                st.strikes += 1
                st.total_blocked += 1
                if (st.strikes >= settings.quarantine_strike_count
                        and severity_weight >= SEVERITY_SCORE[Severity.HIGH]):
                    st.quarantine(now)
                    action = DefenseAction.QUARANTINE
                    policies.append("POL-QUARANTINE")
                    reasons.append(
                        f"{settings.quarantine_strike_count} high-severity strikes reached"
                    )
            elif action in (DefenseAction.SANITIZE, DefenseAction.MASK):
                st.total_sanitized += 1
            else:
                st.total_allowed += 1
                st.strikes = max(0, st.strikes - 1)   # good behaviour decays strikes

        actions = [action]
        if action != ladder_action and ladder_action != DefenseAction.ALLOW:
            actions.append(ladder_action)

        # ---- Response-side filtering ----------------------------------
        filtered_response: Optional[str] = None
        response_steps: List[SanitizationStep] = []
        if model_response is not None:
            filtered_response, response_steps, blocked_out = self.filter_response(
                model_response, app
            )
            if blocked_out:
                allowed = False
                action = DefenseAction.BLOCK
                policies.append("POL-OUTPUT-001")
                reasons.append("model response attempted to disclose protected content")

        return DefenseDecision(
            action=action,
            actions_applied=list(dict.fromkeys(actions)),
            allowed=allowed,
            sanitized_prompt=sanitized,
            sanitization_steps=steps,
            response_filtered=filtered_response,
            response_filter_steps=response_steps,
            policy_ids=list(dict.fromkeys(policies)),
            rationale=self._rationale(action, threat, pressure, reasons),
            residual_risk=round(float(residual), 4),
            revalidated_clean=revalidated_clean,
            rate_limit_remaining=remaining,
            quarantined_until=st.quarantined_until if st.quarantined_until > now else None,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _pressure(prediction: ThreatPrediction, behavior: BehaviorReport,
                  health: HealthReport, app: AppContext) -> float:
        """Aggregate 0-1 'how hard should we push back' signal.

        Deliberately a transparent weighted sum rather than a learned policy:
        an operator must be able to read why a request was blocked and tune
        the trade-off without retraining anything.
        """
        threat_term = SEVERITY_SCORE[prediction.severity] * prediction.confidence
        if prediction.threat_class.value == "benign":
            threat_term = 0.0
        behaviour_term = behavior.anomaly_score
        posture_term = health.surface_scores.get("configuration_risk", 0.0)

        pressure = 0.62 * threat_term + 0.23 * behaviour_term + 0.15 * posture_term
        # A fired signature is high-precision evidence; floor the pressure so
        # a confident innate detection is never argued away by a calm model.
        return float(min(1.0, pressure))

    @staticmethod
    def _rationale(action: DefenseAction, threat: str, pressure: float,
                   reasons: List[str]) -> str:
        head = {
            DefenseAction.ALLOW: "Request allowed; no material threat indicators.",
            DefenseAction.MONITOR: "Request allowed but flagged for monitoring.",
            DefenseAction.SANITIZE: "Malicious instructions removed; cleaned prompt forwarded.",
            DefenseAction.MASK: "Sensitive references masked before forwarding.",
            DefenseAction.RATE_LIMIT: "Request throttled to blunt automated abuse.",
            DefenseAction.BLOCK: "Request rejected before reaching the AI model.",
            DefenseAction.QUARANTINE: "Tenant quarantined after repeated high-severity incidents.",
        }[action]
        detail = f" Threat pressure {pressure:.2f}"
        if threat != "benign":
            detail += f" for {threat.replace('_', ' ')}"
        detail += "."
        if reasons:
            detail += " Contributing factors: " + "; ".join(reasons) + "."
        return head + detail

    # ------------------------------------------------------------------
    # Sanitisation
    # ------------------------------------------------------------------
    def sanitize(self, prompt: str,
                 hits: Optional[List[Hit]] = None
                 ) -> Tuple[str, List[SanitizationStep]]:
        """Remove or neutralise malicious spans, preserving legitimate intent."""
        text = prompt
        steps: List[SanitizationStep] = []

        # 1. Signature-directed replacement (precise, span-level).
        hits = hits if hits is not None else scan(prompt)
        for sig, match, _via in hits:
            if sig.action in (DefenseAction.SANITIZE, DefenseAction.MASK):
                if match and match in text:
                    text = text.replace(match, sig.replacement)
                    steps.append(SanitizationStep(
                        rule_id=sig.id, description=sig.description,
                        span=match[:120], replacement=sig.replacement,
                    ))

        # 2. Structural cleaning (always applied at this rung).
        for rule_id, pattern, replacement, description in STRUCTURAL_RULES:
            new_text, n = pattern.subn(replacement, text)
            if n:
                steps.append(SanitizationStep(
                    rule_id=rule_id, description=description,
                    span=f"{n} occurrence(s)", replacement=replacement or "(removed)",
                ))
                text = new_text

        # 3. Self-healing rules that ask for sanitisation.
        for rule in self._match_synth_rules(text):
            if rule.action == DefenseAction.SANITIZE:
                pat = self._compiled.get(rule.rule_id)
                if pat:
                    new_text, n = pat.subn("[SELF-HEALED-RULE-REMOVED]", text)
                    if n:
                        steps.append(SanitizationStep(
                            rule_id=rule.rule_id,
                            description=rule.description or "Self-healing policy",
                            span=f"{n} occurrence(s)",
                            replacement="[SELF-HEALED-RULE-REMOVED]",
                        ))
                        text = new_text

        text = re.sub(r"\s{3,}", " ", text).strip()
        if not text:
            text = "[EMPTY-AFTER-SANITISATION]"
        return text, steps

    # ------------------------------------------------------------------
    # Response filtering
    # ------------------------------------------------------------------
    def filter_response(self, response: str, app: AppContext
                        ) -> Tuple[str, List[SanitizationStep], bool]:
        """Output-side DLP. Returns (filtered_text, steps, should_block)."""
        text = response
        steps: List[SanitizationStep] = []
        should_block = False

        for sig in RESPONSE_SIGNATURES:
            if sig.id == "SIG-RS-002" and not app.pii_redaction_enabled:
                continue
            matches = list(sig.pattern.finditer(text))
            if not matches:
                continue
            if sig.action == DefenseAction.BLOCK:
                should_block = True
                steps.append(SanitizationStep(
                    rule_id=sig.id, description=sig.description,
                    span=matches[0].group(0)[:120], replacement="(response blocked)",
                ))
                continue
            text = sig.pattern.sub(sig.replacement, text)
            steps.append(SanitizationStep(
                rule_id=sig.id, description=sig.description,
                span=f"{len(matches)} occurrence(s)", replacement=sig.replacement,
            ))
        return text, steps, should_block

    # ------------------------------------------------------------------
    def quarantined_tenants(self, now: Optional[float] = None) -> List[str]:
        now = time.time() if now is None else now
        return [t for t, st in self.tenants.items() if st.is_quarantined(now)]

    def release(self, tenant_id: str) -> bool:
        st = self.tenants.get(tenant_id)
        if st:
            st.quarantined_until = 0.0
            st.strikes = 0
            return True
        return False

    def stats(self) -> Dict[str, int]:
        return {
            "tenants_tracked": len(self.tenants),
            "active_self_healing_rules": len(self.active_rules),
            "quarantined": len(self.quarantined_tenants()),
            "total_blocked": sum(s.total_blocked for s in self.tenants.values()),
            "total_sanitized": sum(s.total_sanitized for s in self.tenants.values()),
            "total_allowed": sum(s.total_allowed for s in self.tenants.values()),
        }


__all__ = ["AdaptiveDefenseEngine", "TenantDefenseState", "ACTION_RANK", "STRUCTURAL_RULES"]
