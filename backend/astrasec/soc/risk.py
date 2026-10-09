"""Risk Analyzer — turns the five modules' evidence into one explained score.

A single "malicious: yes" is useless to an operator. The analyzer reports each
layer's evidence on a 0-100 scale, combines them in a way that can be read
back, and maps the result onto the owner's risk bands.

Layers
------
``threat``       Module 3's ML ensemble: probability the text is not benign.
``signature``    Module 3's innate layer: known-attack patterns that fired.
``similarity``   Module 5: affinity to an attack already held in immune memory.
``behavior``     Module 1: how far this client's behaviour departs from normal.
``application``  Module 2: configuration risk of the application being protected.

Combination
-----------
The two *detection* layers (threat, signature) are primary evidence: either
one alone can justify action. The other three are *corroborating* evidence:
they cannot make a harmless message dangerous on their own, but they raise
confidence in one that already looks hostile.

    primary  P = 0.88 · max(T, S) + 0.04 · min(T, S)
    corroboration C = 1 − (1 − ws·sim)(1 − wb·beh)(1 − wa·app)
    overall  = P + (100 − P) · C · g        g = gain · min(1, P/50)^1.5

So a first-time, clear-cut attack lands around 90 (BLOCK), the same attack
repeated by a client whose behaviour is already anomalous and whose phrasing
matches immune memory crosses 96 (QUARANTINE), and an ordinary question stays
under 20 (ALLOW) even when the client is a little unusual.

The score is a *risk index*, not a probability: 91 does not mean "91% likely
to be an attack". It means "the evidence sits in the band the owner chose to
treat as critical".
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional

from .policy import SecurityPolicy

SEVERITY_BANDS = ((20, "none"), (40, "low"), (60, "medium"), (80, "high"), (101, "critical"))


def severity_for(risk: float) -> str:
    for limit, name in SEVERITY_BANDS:
        if risk <= limit:
            return name
    return "critical"


@dataclass
class RiskBreakdown:
    threat: float
    signature: float
    similarity: float
    behavior: float
    application: float
    primary: float
    corroboration: float
    overall: float
    severity: str
    band_action: str
    threat_class: str
    ml_confidence: float
    matched_memory: Optional[Dict[str, Any]] = None
    signatures: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in ("threat", "signature", "similarity", "behavior", "application",
                  "primary", "overall"):
            d[k] = round(float(d[k]), 1)
        d["corroboration"] = round(float(d["corroboration"]), 3)
        d["ml_confidence"] = round(float(d["ml_confidence"]), 4)
        return d


class RiskAnalyzer:
    def __init__(self, policy: SecurityPolicy) -> None:
        self.policy = policy

    def score(self, *, threat_class: str, probabilities: Dict[str, float],
              ml_confidence: float, signature_risk: float, signatures: List[str],
              similarity: float, similarity_meta: Optional[Dict[str, Any]],
              behavior: float, application: float,
              use_behavior: bool = True) -> RiskBreakdown:
        p = self.policy
        p_benign = float(probabilities.get("benign", 1.0 - ml_confidence))
        p_mal = max(0.0, min(1.0, 1.0 - p_benign))
        notes: List[str] = []

        # Threat layer. When the ensemble's final call is "benign", the residual
        # malicious mass is shown but discounted: the model looked and decided.
        T = p_mal * 100.0
        if threat_class == "benign":
            T *= 0.6
        S = max(0.0, min(1.0, signature_risk)) * 100.0

        # Similarity only corroborates when it is a real match. A 0.4 cosine to
        # some attack in memory is what any sentence with "system" in it gets.
        sim = max(0.0, min(1.0, similarity))
        sim_eff = sim if sim >= 0.6 else sim * 0.3
        beh = max(0.0, min(1.0, behavior)) if use_behavior else 0.0
        app = max(0.0, min(1.0, application))

        primary = 0.88 * max(T, S) + 0.04 * min(T, S)
        corroboration = 1.0 - ((1 - p.weight_similarity * sim_eff)
                               * (1 - p.weight_behavior * beh)
                               * (1 - p.weight_application * app))
        # Corroboration scales with the primary evidence it corroborates. Module 1
        # alone flags plenty of ordinary short messages as unusual; letting that
        # push a harmless question into a sanitising band would punish users
        # for being brief.
        gain = p.corroboration_gain * min(1.0, primary / 50.0) ** 1.5
        overall = primary + (100.0 - primary) * corroboration * gain
        overall = max(0.0, min(100.0, overall))

        if S >= 60:
            notes.append("known attack pattern matched")
        if sim >= 0.72 and similarity_meta:
            notes.append(f"matches an attack seen {similarity_meta.get('encounters', 1)} "
                         f"time(s) before")
        if beh >= 0.6:
            notes.append("client behaviour is anomalous")

        return RiskBreakdown(
            threat=T, signature=S, similarity=sim * 100.0, behavior=beh * 100.0,
            application=app * 100.0, primary=primary, corroboration=corroboration,
            overall=overall, severity=severity_for(overall),
            band_action=p.bands.action_for(overall), threat_class=threat_class,
            ml_confidence=ml_confidence, matched_memory=similarity_meta,
            signatures=list(signatures), notes=notes,
        )

    def from_inspection(self, result, similarity: float,
                        similarity_meta: Optional[Dict[str, Any]],
                        use_behavior: bool = True) -> RiskBreakdown:
        pred = result.prediction
        return self.score(
            threat_class=pred.threat_class.value,
            probabilities=pred.probabilities or {},
            ml_confidence=pred.confidence,
            signature_risk=pred.signature_risk,
            signatures=pred.signature_hits,
            similarity=similarity,
            similarity_meta=similarity_meta,
            behavior=result.behavior.anomaly_score,
            application=result.health.surface_scores.get("configuration_risk", 0.0),
            use_behavior=use_behavior,
        )


__all__ = ["RiskAnalyzer", "RiskBreakdown", "severity_for"]
