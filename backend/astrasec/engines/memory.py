"""Module 5 — Self-Healing & Security Intelligence Engine.

Biological analogue: *adaptive immunity*. After an infection, the body keeps
memory B-cells whose receptors already fit that antigen. A second exposure
therefore produces a response that is faster, stronger and more specific than
the first. AstraSec implements the same four mechanisms literally:

``affinity matching``      cosine similarity between an incoming antigen's
                           character-n-gram vector and every stored receptor.
``clonal selection``       a memory cell that successfully defended is cloned
                           into mutated variants, pre-covering near-neighbour
                           phrasings of the same attack.
``affinity maturation``    on re-encounter, the matched receptor moves toward
                           the new antigen, so the cell's coverage sharpens
                           with every exposure (somatic hypermutation).
``apoptosis``              cells whose utility decays below threshold are
                           pruned, bounding memory and preventing the
                           accumulation of stale receptors.

On top of memory sits the *self-healing* loop: recurring antigens are mined
for a shared discriminative pattern, that pattern is compiled into a candidate
policy rule, validated against a benign hold-out to bound false positives, and
— only if it passes — promoted into the Adaptive Defense Engine as an active
rule. The system therefore writes new defences for itself without retraining
any model.
"""
from __future__ import annotations

import math
import re
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import joblib

from ..utils import atomic_dump
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer

from ..config import MODEL_DIR, settings
from ..features import WORD_RE, normalise_evasion
from ..schemas import (
    DefenseAction,
    MemoryCell,
    MemoryReport,
    Recommendation,
    Severity,
    SynthesizedRule,
    ThreatClass,
)
from .llm import LLMAdvisor

# Hashing (not fitted) so memory works from the very first request without a
# vocabulary, and stays stable across restarts.
_VECTOR_DIM = 2 ** 12
_vectoriser = HashingVectorizer(
    analyzer="char_wb", ngram_range=(3, 5), n_features=_VECTOR_DIM,
    norm="l2", alternate_sign=False, lowercase=True,
)

# Tokens too generic to anchor a synthesised rule on.
_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "for", "with", "in", "on", "at",
    "is", "are", "was", "were", "be", "been", "this", "that", "it", "you",
    "your", "me", "my", "we", "our", "please", "can", "could", "will", "would",
    "do", "does", "did", "have", "has", "had", "so", "if", "as", "by", "from",
    "i", "am", "but", "not", "what", "how", "why", "all", "any", "one", "now",
}


def _embed(text: str) -> np.ndarray:
    return np.asarray(_vectoriser.transform([text]).todense()).ravel().astype(np.float32)


class ImmuneMemoryEngine:
    """Artificial Immune Memory with clonal selection and self-healing rules."""

    MODEL_FILE = "immune_memory.joblib"

    def __init__(self, advisor: Optional[LLMAdvisor] = None) -> None:
        self.cells: Dict[str, MemoryCell] = {}
        self._matrix: Optional[np.ndarray] = None       # (n_cells, dim)
        self._index: List[str] = []                     # row -> cell_id
        self._dirty = True

        self.candidate_rules: Dict[str, SynthesizedRule] = {}
        self.promoted_rules: Dict[str, SynthesizedRule] = {}
        self.advisor = advisor or LLMAdvisor()

        # Benign hold-out used to validate a rule before promotion. Populated
        # at training time; a rule that fires on any of these is rejected.
        self.benign_holdout: List[str] = []

        self.total_encounters = 0
        self.recall_hits = 0
        self.clones_created = 0
        self.cells_pruned = 0
        self._recent_recommendations: List[Recommendation] = []

    # ------------------------------------------------------------------
    # Index management
    # ------------------------------------------------------------------
    def _rebuild(self) -> None:
        if not self.cells:
            self._matrix, self._index = None, []
            self._dirty = False
            return
        self._index = list(self.cells.keys())
        self._matrix = np.vstack([
            np.asarray(self.cells[cid].affinity_vector, dtype=np.float32)
            for cid in self._index
        ])
        self._dirty = False

    def _ensure_index(self) -> None:
        if self._dirty:
            self._rebuild()

    # ------------------------------------------------------------------
    # Recall
    # ------------------------------------------------------------------
    def recall(self, prompt: str) -> Tuple[Optional[MemoryCell], float]:
        """Find the highest-affinity memory cell for this antigen."""
        self._ensure_index()
        if self._matrix is None or self._matrix.size == 0:
            return None, 0.0
        v = _embed(normalise_evasion(prompt))
        nv = np.linalg.norm(v)
        if nv < 1e-9:
            return None, 0.0
        sims = self._matrix @ v / nv        # rows are already L2-normalised
        i = int(np.argmax(sims))
        return self.cells[self._index[i]], float(sims[i])

    def hint(self, prompt: str) -> Optional[Tuple[str, float]]:
        """``(threat_class, affinity)`` for Module 3's posterior sharpening."""
        cell, aff = self.recall(prompt)
        if cell and aff >= settings.memory_affinity_threshold:
            return cell.threat_class.value, aff
        return None

    # ------------------------------------------------------------------
    # Learning from an incident
    # ------------------------------------------------------------------
    def learn(self, prompt: str, threat_class: ThreatClass, defense: DefenseAction,
              successful: bool = True, now: Optional[float] = None) -> MemoryReport:
        """Record an encounter; grow, mature or prune memory accordingly."""
        now = time.time() if now is None else now
        self.total_encounters += 1

        cell, affinity = self.recall(prompt)
        report = MemoryReport(cells_total=len(self.cells))
        clones = 0

        if threat_class == ThreatClass.BENIGN:
            # Benign traffic is never committed to memory, but it *is* useful
            # as hold-out material for validating future synthesised rules.
            if len(self.benign_holdout) < 4000 and len(prompt) > 10:
                self.benign_holdout.append(prompt)
            report.recall_hit = bool(cell and affinity >= settings.memory_affinity_threshold)
            report.matched_cell_id = cell.cell_id if cell else None
            report.matched_affinity = round(affinity, 4)
            report.primary_response = True
            report.immunity_strength = self.immunity_strength()
            report.explanation = "Benign interaction; no antigen committed to immune memory."
            return report

        if cell is not None and affinity >= settings.memory_affinity_threshold \
                and cell.threat_class == threat_class:
            # ---- Secondary response: mature the existing receptor ---------
            self.recall_hits += 1
            cell.encounters += 1
            if successful:
                cell.successes += 1
            cell.last_seen = now
            cell.defense_used = defense
            cell.defense_successful = successful

            # Somatic hypermutation: shift the receptor toward this antigen.
            v_new = _embed(normalise_evasion(prompt))
            old = np.asarray(cell.affinity_vector, dtype=np.float32)
            rate = 0.25 / math.sqrt(cell.encounters)
            matured = (1 - rate) * old + rate * v_new
            n = np.linalg.norm(matured)
            cell.affinity_vector = (matured / n if n > 1e-9 else matured).tolist()
            cell.utility = self._utility(cell, now)
            self._dirty = True

            report.recall_hit = True
            report.primary_response = False
            report.matched_cell_id = cell.cell_id
            report.matched_affinity = round(affinity, 4)
            report.explanation = (
                f"Secondary immune response: antigen matched memory cell "
                f"{cell.cell_id} at {affinity:.0%} affinity "
                f"(encounter #{cell.encounters}). Receptor matured."
            )
        else:
            # ---- Primary response: create a new memory cell ---------------
            new_cell = self._create_cell(prompt, threat_class, defense, successful, now)
            report.primary_response = True
            report.matched_cell_id = new_cell.cell_id
            report.matched_affinity = round(affinity, 4)
            report.explanation = (
                f"Primary immune response: new antigen. Memory cell "
                f"{new_cell.cell_id} created for {threat_class.value}."
            )
            if successful:
                clones = self._clonal_expansion(new_cell, prompt, now)
                report.clones_created = clones

        # ---- Housekeeping and self-healing -------------------------------
        pruned = self._apoptosis(now)
        report.cells_pruned = pruned
        report.cells_total = len(self.cells)
        report.immunity_strength = self.immunity_strength()

        synthesized = self._synthesize_rules(threat_class)
        report.rules_synthesized = synthesized
        report.rules_promoted = [r.rule_id for r in synthesized if r.active]

        return report

    # ------------------------------------------------------------------
    def _create_cell(self, prompt: str, threat_class: ThreatClass,
                     defense: DefenseAction, successful: bool,
                     now: float, parent_id: Optional[str] = None,
                     generation: int = 0,
                     vector: Optional[np.ndarray] = None) -> MemoryCell:
        norm = normalise_evasion(prompt)
        vec = vector if vector is not None else _embed(norm)
        cell = MemoryCell(
            antigen_signature=self._signature(norm, threat_class),
            threat_class=threat_class,
            exemplar_prompt=prompt[:500],
            defense_used=defense,
            defense_successful=successful,
            affinity_vector=np.asarray(vec, dtype=np.float32).tolist(),
            created_at=now,
            last_seen=now,
            parent_id=parent_id,
            generation=generation,
        )
        self.cells[cell.cell_id] = cell
        self._dirty = True
        return cell

    @staticmethod
    def _signature(normalised: str, threat_class: ThreatClass) -> str:
        tokens = [w for w in WORD_RE.findall(normalised.lower())
                  if w not in _STOPWORDS and len(w) > 2]
        core = "-".join(tokens[:6]) or "opaque"
        return f"{threat_class.value}:{core}"[:120]

    def _clonal_expansion(self, parent: MemoryCell, prompt: str, now: float) -> int:
        """Pre-cover near-neighbour variants of a newly defeated antigen.

        Each clone's receptor is the parent's vector perturbed along a random
        direction and re-normalised — the artificial analogue of somatic
        hypermutation producing a diverse daughter population. This is what
        lets the system recognise a *rewording* of an attack it has seen once.
        """
        k = settings.clonal_expansion_factor
        if k <= 0 or len(self.cells) >= settings.memory_max_cells:
            return 0
        rng = np.random.default_rng(abs(hash(parent.antigen_signature)) % (2 ** 32))
        base = np.asarray(parent.affinity_vector, dtype=np.float32)
        created = 0
        for i in range(k):
            noise = rng.normal(0.0, 0.06, size=base.shape).astype(np.float32)
            mutated = np.clip(base + noise, 0.0, None)
            n = np.linalg.norm(mutated)
            if n < 1e-9:
                continue
            mutated /= n
            clone = self._create_cell(
                prompt, parent.threat_class, parent.defense_used, True, now,
                parent_id=parent.cell_id, generation=parent.generation + 1,
                vector=mutated,
            )
            clone.utility = 0.55           # clones start with modest utility
            clone.encounters = 0
            clone.successes = 0
            created += 1
        self.clones_created += created
        return created

    @staticmethod
    def _utility(cell: MemoryCell, now: float) -> float:
        """Utility = efficacy x recency x experience."""
        efficacy = cell.successes / max(1, cell.encounters) if cell.encounters else 0.5
        age_days = max(0.0, (now - cell.last_seen) / 86_400.0)
        recency = math.exp(-age_days / 30.0)          # 30-day half-life-ish
        experience = math.log1p(cell.encounters) / math.log(10)
        return float(np.clip(0.5 * efficacy + 0.3 * recency + 0.2 * experience, 0.0, 1.0))

    def _apoptosis(self, now: float) -> int:
        """Prune low-utility cells, bounding memory size."""
        if len(self.cells) <= settings.memory_max_cells * 0.9:
            # Only recompute utilities periodically; pruning is cheap otherwise.
            if self.total_encounters % 50 != 0:
                return 0
        pruned = 0
        for cid, cell in list(self.cells.items()):
            cell.utility = self._utility(cell, now)
            # Never prune an experienced parent cell.
            if cell.encounters >= 3:
                continue
            if cell.utility < settings.memory_apoptosis_utility:
                del self.cells[cid]
                pruned += 1
        # Hard cap: drop the least useful cells if still over budget.
        if len(self.cells) > settings.memory_max_cells:
            ordered = sorted(self.cells.values(), key=lambda c: c.utility)
            for cell in ordered[: len(self.cells) - settings.memory_max_cells]:
                del self.cells[cell.cell_id]
                pruned += 1
        if pruned:
            self._dirty = True
            self.cells_pruned += pruned
        return pruned

    # ------------------------------------------------------------------
    # Self-healing rule synthesis
    # ------------------------------------------------------------------
    def _ngrams(self, text: str, sizes: Sequence[int] = (3, 2)) -> List[str]:
        """Consecutive word n-grams usable as a literal pattern.

        N-grams are taken from the *unfiltered* token stream so the resulting
        regex matches real prompt text. Stopwords are used only to reject
        n-grams that carry no discriminative content ("of the", "to my"), not
        to reshape the phrase — removing them first would synthesise patterns
        like ``reset\\s+password`` that never match "reset my password".
        """
        toks = WORD_RE.findall(normalise_evasion(text).lower())
        out: List[str] = []
        for n in sizes:
            for i in range(len(toks) - n + 1):
                gram = toks[i:i + n]
                if all(w in _STOPWORDS for w in gram):
                    continue
                if not any(len(w) > 3 for w in gram):
                    continue
                out.append(" ".join(gram))
        return out

    def _synthesize_rules(self, threat_class: ThreatClass) -> List[SynthesizedRule]:
        """Mine recurring antigens for a discriminative, promotable pattern.

        Support is measured in **encounters, not distinct cells**. That
        distinction is the whole point: affinity matching deliberately
        collapses rewordings of one attack onto a single maturing receptor, so
        counting cells would mean a campaign that hits a thousand times still
        looks like "support = 1" and no rule could ever be promoted. Counting
        encounters makes recurrence — which is exactly the signal self-healing
        should act on — the thing that drives promotion.
        """
        family = [c for c in self.cells.values()
                  if c.threat_class == threat_class and c.generation == 0]
        if not family:
            return []
        family_encounters = sum(max(1, c.encounters) for c in family)
        if family_encounters < settings.rule_promotion_min_support:
            return []

        # gram -> (cells covering it, encounters covering it)
        gram_cells: Dict[str, set] = defaultdict(set)
        gram_encounters: Counter = Counter()
        for c in family:
            weight = max(1, c.encounters)
            for gram in set(self._ngrams(c.exemplar_prompt)):
                gram_cells[gram].add(c.cell_id)
                gram_encounters[gram] += weight

        enforcing = {r.pattern for r in self.promoted_rules.values()}
        by_pattern = {r.pattern: r for r in self.candidate_rules.values()}

        # Prefer high support, then longer (more specific) phrases.
        ranked = sorted(
            gram_encounters.items(),
            key=lambda kv: (-kv[1], -len(kv[0].split()), kv[0]),
        )

        results: List[SynthesizedRule] = []
        for gram, support in ranked:
            if support < settings.rule_promotion_min_support:
                break
            pattern = r"\b" + r"\s+".join(re.escape(w) for w in gram.split()) + r"\b"
            if pattern in enforcing:
                continue

            confidence, fp_rate = self._validate_rule(pattern, support)

            # A candidate seen before is RE-SCORED against its grown support,
            # not skipped. Skipping was a real defect: a phrase that was too
            # weakly evidenced at four encounters would keep that stale
            # confidence for ever, so a campaign could repeat indefinitely and
            # the rule it justified would never be promoted. Recurrence is the
            # entire signal self-healing runs on, so it has to be re-read.
            existing = by_pattern.get(pattern)
            if existing is not None:
                existing.support = support
                existing.confidence = round(confidence, 4)
                if (confidence >= settings.rule_promotion_confidence
                        and fp_rate == 0.0
                        and len(self.promoted_rules) < settings.max_promoted_rules
                        and settings.rule_auto_promote):
                    existing.active = True
                    self.promoted_rules[existing.rule_id] = existing
                    self.candidate_rules.pop(existing.rule_id, None)
                    results.append(existing)
                    if len(results) >= 2:
                        break
                continue
            rule = SynthesizedRule(
                pattern=pattern,
                threat_class=threat_class,
                action=(DefenseAction.BLOCK if threat_class in (
                    ThreatClass.PROMPT_INJECTION, ThreatClass.DATA_EXFILTRATION,
                    ThreatClass.JAILBREAK)
                    else DefenseAction.SANITIZE),
                confidence=round(confidence, 4),
                support=support,
                description=(
                    f"Auto-synthesised from {support} encounters across "
                    f"{len(gram_cells[gram])} {threat_class.value} antigen(s) sharing the "
                    f"phrase '{gram}' (benign false-positive rate {fp_rate:.2%})."
                ),
            )
            self.candidate_rules[rule.rule_id] = rule
            results.append(rule)

            if (confidence >= settings.rule_promotion_confidence
                    and support >= settings.rule_promotion_min_support
                    and fp_rate == 0.0
                    and len(self.promoted_rules) < settings.max_promoted_rules
                    and settings.rule_auto_promote):
                rule.active = True
                self.promoted_rules[rule.rule_id] = rule
                self.candidate_rules.pop(rule.rule_id, None)
            if len(results) >= 2:        # at most two new candidates per incident
                break
        return results

    def _validate_rule(self, pattern: str, support: int) -> Tuple[float, float]:
        """Score a candidate rule against the benign hold-out.

        Confidence answers two questions, and deliberately *not* a third:

        * **Is it harmless?** Any firing on held-out benign traffic
          disqualifies promotion outright. An automatically-generated policy
          must never be able to take down legitimate traffic, so this gate is
          absolute rather than a threshold.
        * **Is it recurring?** Evidence saturates at twice the minimum
          support: a phrase seen eight times is established, and seeing it
          eighty times does not make it more true.

        The question it does *not* ask is "does this pattern cover most of its
        threat class?". An earlier version used exactly that as the
        denominator, and the result was that no rule could ever be promoted
        under realistic traffic: prompt injection arrives in dozens of
        unrelated phrasings, so any one campaign's signature covers only a
        sliver of the class and scored far below threshold. But a rule that
        reliably catches *one recurring campaign* is precisely what
        self-healing is for. Breadth is the wrong bar; specificity and
        recurrence are the right ones.
        """
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return 0.0, 1.0
        if not self.benign_holdout:
            # Without a hold-out we cannot bound false positives, so we refuse
            # to express confidence rather than guessing.
            return 0.0, 1.0
        fp = sum(1 for b in self.benign_holdout if rx.search(b))
        fp_rate = fp / len(self.benign_holdout)
        evidence = min(1.0, support / (2.0 * max(1, settings.rule_promotion_min_support)))
        confidence = float(np.clip(evidence * (1.0 - fp_rate) ** 3, 0.0, 1.0))
        return confidence, fp_rate

    def seed_holdout(self, benign_prompts: Sequence[str]) -> None:
        self.benign_holdout = list(benign_prompts)[:4000]

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------
    def recommend(self, incident: Dict[str, object], use_llm: bool = True
                  ) -> List[Recommendation]:
        """Security recommendations — LLM-generated when available, else offline."""
        recs: List[Recommendation] = []
        if use_llm:
            llm_out = self.advisor.generate(incident)
            if llm_out:
                for item in llm_out:
                    recs.append(Recommendation(
                        title=item["title"], detail=item["detail"],
                        priority=Severity(item["priority"]),
                        category=item["category"], source="llm",
                    ))
        if not recs:
            recs = self._offline_recommendations(incident)

        self._recent_recommendations = (recs + self._recent_recommendations)[:40]
        return recs

    def _offline_recommendations(self, incident: Dict[str, object]) -> List[Recommendation]:
        """Deterministic retrieval + template engine (no model required)."""
        threat = str(incident.get("threat_class", "benign"))
        severity = str(incident.get("severity", "low"))
        health = float(incident.get("health_score", 100.0) or 100.0)
        findings = incident.get("findings") or []
        streak = float(incident.get("threat_streak", 0) or 0)
        recall = bool(incident.get("recall_hit", False))

        recs: List[Recommendation] = []
        playbook = _PLAYBOOK.get(threat)
        if playbook:
            for title, detail, prio, cat in playbook:
                recs.append(Recommendation(
                    title=title, detail=detail, priority=Severity(prio), category=cat,
                    references=_REFERENCES.get(threat, []),
                ))

        # Configuration findings become their own recommendations, since they
        # are the cheapest durable fix available to the operator.
        for f in list(findings)[:3]:
            code = f.get("code", "") if isinstance(f, dict) else ""
            if code.startswith("CFG") or code.startswith("DEP"):
                recs.append(Recommendation(
                    title=f.get("title", "Harden configuration"),
                    detail=f.get("remediation", ""),
                    priority=Severity(f.get("severity", "medium")),
                    category="configuration" if code.startswith("CFG") else "supply_chain",
                ))

        if streak >= 3:
            recs.append(Recommendation(
                title="Contain the active attack campaign",
                detail=(f"This tenant has produced {int(streak)} consecutive malicious "
                        "requests. Quarantine the identity, invalidate its session tokens "
                        "and require re-authentication before restoring access."),
                priority=Severity.CRITICAL, category="incident_response",
            ))
        if health < 60:
            recs.append(Recommendation(
                title="AI Health Score below safe operating threshold",
                detail=(f"The health score is {health:.0f}/100. Address the highest-severity "
                        "configuration findings first — they are structural and reduce risk "
                        "for every future request, not just this one."),
                priority=Severity.HIGH, category="posture",
            ))
        if recall:
            recs.append(Recommendation(
                title="Promote this antigen family to a static policy",
                detail=("Immune memory recalled this attack, meaning it is recurring. "
                        "Promoting the synthesised rule to a permanently enforced policy "
                        "moves detection from the probabilistic layer to the deterministic "
                        "one, cutting both latency and false negatives."),
                priority=Severity.MEDIUM, category="self_healing",
            ))
        if not recs:
            recs.append(Recommendation(
                title="Maintain current posture",
                detail="No material risk indicators in this interaction. Continue monitoring.",
                priority=Severity.LOW, category="posture",
            ))
        # De-duplicate by title, keep highest priority first.
        seen, unique = set(), []
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
        for r in sorted(recs, key=lambda x: order.get(x.priority.value, 5)):
            if r.title in seen:
                continue
            seen.add(r.title)
            unique.append(r)
        return unique[:5]

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def immunity_strength(self) -> float:
        """Fraction of encounters resolved by memory recall (0-1)."""
        if self.total_encounters == 0:
            return 0.0
        coverage = self.recall_hits / self.total_encounters
        diversity = min(1.0, len(self.cells) / 200.0)
        return float(np.clip(0.7 * coverage + 0.3 * diversity, 0.0, 1.0))

    def recall_rate(self) -> float:
        return self.recall_hits / self.total_encounters if self.total_encounters else 0.0

    def stats(self) -> Dict[str, object]:
        by_class = Counter(c.threat_class.value for c in self.cells.values())
        return {
            "cells": len(self.cells),
            "primary_cells": sum(1 for c in self.cells.values() if c.generation == 0),
            "clones": sum(1 for c in self.cells.values() if c.generation > 0),
            "by_class": dict(by_class),
            "total_encounters": self.total_encounters,
            "recall_hits": self.recall_hits,
            "recall_rate": round(self.recall_rate(), 4),
            "immunity_strength": round(self.immunity_strength(), 4),
            "clones_created": self.clones_created,
            "cells_pruned": self.cells_pruned,
            "candidate_rules": len(self.candidate_rules),
            "promoted_rules": len(self.promoted_rules),
            "benign_holdout": len(self.benign_holdout),
        }

    def top_cells(self, limit: int = 20) -> List[MemoryCell]:
        return sorted(self.cells.values(),
                      key=lambda c: (-c.encounters, -c.utility))[:limit]

    def recent_recommendations(self, limit: int = 10) -> List[Recommendation]:
        return self._recent_recommendations[:limit]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save(self, path: Optional[Path] = None) -> Path:
        path = path or (MODEL_DIR / self.MODEL_FILE)
        atomic_dump({
            "cells": {k: v.model_dump() for k, v in self.cells.items()},
            "candidate_rules": {k: v.model_dump() for k, v in self.candidate_rules.items()},
            "promoted_rules": {k: v.model_dump() for k, v in self.promoted_rules.items()},
            "benign_holdout": self.benign_holdout[:2000],
            "counters": {
                "total_encounters": self.total_encounters,
                "recall_hits": self.recall_hits,
                "clones_created": self.clones_created,
                "cells_pruned": self.cells_pruned,
            },
        }, path, compress=3)
        return path

    @classmethod
    def load(cls, path: Optional[Path] = None,
             advisor: Optional[LLMAdvisor] = None) -> "ImmuneMemoryEngine":
        path = path or (MODEL_DIR / cls.MODEL_FILE)
        blob = joblib.load(path)
        eng = cls(advisor=advisor)
        eng.cells = {k: MemoryCell(**v) for k, v in blob.get("cells", {}).items()}
        eng.candidate_rules = {k: SynthesizedRule(**v)
                               for k, v in blob.get("candidate_rules", {}).items()}
        eng.promoted_rules = {k: SynthesizedRule(**v)
                              for k, v in blob.get("promoted_rules", {}).items()}
        eng.benign_holdout = blob.get("benign_holdout", [])
        c = blob.get("counters", {})
        eng.total_encounters = c.get("total_encounters", 0)
        eng.recall_hits = c.get("recall_hits", 0)
        eng.clones_created = c.get("clones_created", 0)
        eng.cells_pruned = c.get("cells_pruned", 0)
        eng._dirty = True
        return eng


# --------------------------------------------------------------------------
# Offline knowledge base
# --------------------------------------------------------------------------
_PLAYBOOK: Dict[str, List[Tuple[str, str, str, str]]] = {
    "prompt_injection": [
        ("Isolate the system prompt from user content",
         "Place system instructions in a dedicated, non-overridable channel and never "
         "concatenate untrusted text into it. Re-assert the system prompt after every "
         "user turn so a mid-conversation override cannot persist.",
         "critical", "architecture"),
        ("Treat all retrieved and pasted content as data, never as instructions",
         "Wrap retrieved documents, emails and file contents in an explicit data fence and "
         "instruct the model that text inside the fence is never to be executed. This is "
         "the primary control against indirect prompt injection.",
         "high", "architecture"),
        ("Apply least privilege to downstream tools",
         "Assume injection will eventually succeed. Give the agent the narrowest tool "
         "scopes possible and require human confirmation for any state-changing action.",
         "high", "authorisation"),
    ],
    "jailbreak": [
        ("Enforce a persona lock that survives role-play",
         "Add an invariant instruction that the assistant's safety policy applies to every "
         "persona, character or hypothetical it is asked to adopt, and validate output "
         "against that policy independently of the requested framing.",
         "high", "policy"),
        ("Add an independent output-side safety classifier",
         "Jailbreaks target the generation step. A separate classifier on the response — "
         "which never sees the manipulative framing — catches what input filtering misses.",
         "high", "defence_in_depth"),
        ("Rate-limit and log persona-switch attempts per identity",
         "Repeated jailbreak framings from one identity are a strong campaign signal; "
         "escalate to quarantine rather than refusing each attempt in isolation.",
         "medium", "monitoring"),
    ],
    "adversarial_obfuscation": [
        ("Normalise input before every security decision",
         "Apply Unicode NFKC normalisation, strip zero-width and control characters, fold "
         "homoglyphs and leetspeak, and re-segment character-spaced text — then run "
         "detection on the normalised form as well as the original.",
         "high", "preprocessing"),
        ("Decode embedded payloads before classification",
         "Detect and decode base64, hex, ROT13, reversed and Morse payloads, and classify "
         "each decoded reading. An instruction the model will eventually read must be a "
         "reading the filter also considered.",
         "high", "preprocessing"),
        ("Reject inputs whose decoded form contradicts their surface form",
         "A prompt that looks benign but decodes to an override instruction is "
         "unambiguously adversarial and should be blocked, not sanitised.",
         "medium", "policy"),
    ],
    "data_exfiltration": [
        ("Enable output-side DLP on every response",
         "Mask credentials, API keys, private keys, payment cards and national identifiers "
         "in the response stream. Input filtering alone cannot stop a leak the model "
         "produces spontaneously.",
         "critical", "data_protection"),
        ("Block verbatim reproduction of system instructions",
         "Detect and refuse responses that echo the system prompt, including summarised, "
         "translated or encoded forms — all three are common bypasses.",
         "critical", "data_protection"),
        ("Strip outbound markdown images and links from model output",
         "Attacker-controlled URLs in generated markdown are a silent exfiltration channel; "
         "render-time fetches leak whatever was embedded in the query string.",
         "high", "data_protection"),
        ("Scope context to the current tenant only",
         "Ensure no cross-tenant history or shared cache can enter the context window; "
         "this removes the target rather than defending it.",
         "high", "isolation"),
    ],
    "model_extraction": [
        ("Enforce per-identity query budgets",
         "Extraction requires volume. Daily and burst quotas per authenticated identity "
         "raise the cost of distillation far more effectively than content filtering.",
         "high", "rate_control"),
        ("Never expose logits, log-probabilities or token alternatives",
         "These turn every response into many labelled training signals and make "
         "distillation orders of magnitude cheaper.",
         "high", "api_design"),
        ("Watermark and fingerprint responses",
         "Statistical watermarking lets you later prove that a competing model was "
         "distilled from your outputs, converting a technical problem into a legal one.",
         "medium", "deterrence"),
        ("Detect systematic coverage patterns, not just individual prompts",
         "Extraction shows up as low prompt diversity at high volume — exactly the "
         "distinct_template_ratio and burstiness signals the behaviour engine tracks.",
         "medium", "monitoring"),
    ],
}

_REFERENCES: Dict[str, List[str]] = {
    "prompt_injection": ["OWASP LLM01: Prompt Injection",
                         "Greshake et al., 2023 — Indirect Prompt Injection"],
    "jailbreak": ["OWASP LLM01: Prompt Injection",
                  "Shen et al., 2024 — 'Do Anything Now'"],
    "adversarial_obfuscation": ["Zou et al., 2023 — Universal Adversarial Attacks on LLMs",
                                "OWASP LLM01"],
    "data_exfiltration": ["OWASP LLM06: Sensitive Information Disclosure",
                          "OWASP LLM02: Insecure Output Handling"],
    "model_extraction": ["OWASP LLM10: Model Theft",
                         "Tramèr et al., 2016 — Stealing ML Models via Prediction APIs"],
}

__all__ = ["ImmuneMemoryEngine"]
