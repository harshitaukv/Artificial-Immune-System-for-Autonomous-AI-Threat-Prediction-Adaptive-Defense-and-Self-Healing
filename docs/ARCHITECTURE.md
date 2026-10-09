# AstraSec — Architecture

> Artificial Immune System for Autonomous AI Threat Prediction, Adaptive
> Defense and Self-Healing

This document explains *why* AstraSec is built the way it is. Implementation
detail lives in the module docstrings; this is the design rationale.

---

## 1. The problem

An AI application is attacked through the one channel it cannot refuse: its
input. A prompt is simultaneously data and instruction, and the model has no
reliable way to tell which is which. The consequences are catalogued in the
OWASP Top-10 for LLM Applications — prompt injection (LLM01), sensitive
information disclosure (LLM06), model theft (LLM10).

The prevailing defence is a single classifier in front of the model: text in,
label out. That design has three structural weaknesses:

1. **It is stateless.** Each request is judged alone, so a hundred slow probes
   from one identity look exactly like a hundred unrelated questions.
2. **It cannot explain itself.** A probability is not an audit trail, and a
   security control that cannot justify a block cannot be operated.
3. **It never improves.** Being attacked teaches it nothing until someone
   collects data and retrains.

## 2. The biological argument

A vertebrate immune system solves the same problem — distinguishing self from
a hostile, adapting, previously-unseen non-self — and it does *not* do so with
one mechanism. It uses three:

| Immune mechanism | Property | AstraSec counterpart |
|---|---|---|
| Innate immunity | Fast, fixed, high-precision, no learning required | Signature bank (`signatures.py`) |
| Adaptive immunity | Slow to prime, generalises to novel antigens | ML ensemble (Module 3) |
| Immune memory | Second exposure is faster and stronger than the first | Immune memory (Module 5) |

This is not a decorative metaphor; it is the reason the architecture has the
shape it does. The innate arm gives precision and explainability the learned
arm cannot; the adaptive arm gives coverage the rules cannot; memory converts
*having been attacked* into *being harder to attack*, which is the only
mechanism in the system that improves without human intervention.

## 3. System architecture

```
                         ┌──────────────────────────────────────┐
   client request ──────▶│           FastAPI gateway            │
                         │      /api/inspect  /api/gateway      │
                         └───────────────────┬──────────────────┘
                                             ▼
        ┌──────────────────────── ImmuneSystem.inspect() ────────────────────────┐
        │                                                                        │
        │   ① Behaviour Learning ──┐                                             │
        │      Isolation Forest    │                                             │
        │      tenant baselines    │                                             │
        │                          ▼                                             │
        │   ⑤ Memory recall ──▶ ③ Threat Prediction ──▶ ② Health & Risk          │
        │      affinity match      TF-IDF + RF/LogReg     weighted 4 surfaces    │
        │      (memory hint)       + innate signatures    AI Health Score        │
        │                                                        │               │
        │                                                        ▼               │
        │                                             ④ Adaptive Defence         │
        │                                                escalation ladder       │
        │                                                sanitise → revalidate   │
        │                                                        │               │
        │                                                        ▼               │
        │                                             ⑤ Memory learn             │
        │                                                clonal selection        │
        │                                                rule synthesis          │
        └────────────────────────────┬───────────────────────────────────────────┘
                                     │
          ┌──────────────────────────┼───────────────────────────┐
          ▼                          ▼                           ▼
   SQLite audit log         WebSocket live feed          protected AI model
                                                         (only if allowed)
```

### 3.1 The two feedback edges

A strict left-to-right chain would not be an immune system, it would be a
pipeline. Two edges close the loops:

**Memory → Prediction (before classification).** Module 5 is queried *before*
Module 3 runs. If an incoming antigen matches a stored receptor above the
affinity threshold, that class prior is used to sharpen the posterior. This is
the secondary immune response: a re-encountered pathogen is identified faster
and with more confidence than a novel one.

**Verdict → Behaviour (after the decision).** The final verdict is written back
into the tenant's behavioural profile. A malicious verdict increments a threat
streak and shifts the escalation slope, which raises the anomaly score of that
tenant's *next* request. A campaign therefore becomes progressively easier to
detect as it proceeds — the opposite of a stateless filter, which is equally
blind on attempt one and attempt fifty.

**Memory → Defence (continuous).** Rules synthesised by Module 5 are installed
into Module 4 the moment they are promoted. The policy set grows at runtime
with no model retraining and no human in the loop — bounded, critically, by a
false-positive gate described in §4.5.

### 3.2 Why this order

Behaviour runs first because it is cheap and its output (session features,
anomaly score) is an input to both Health and Defence. Memory recall runs
before Prediction because its hint changes the posterior. Health runs after
Prediction because prompt risk is one of its four surfaces. Defence runs last
among the deciders because it consumes all three. Memory commit runs after the
verdict because what it stores is *(antigen, defence used, whether it worked)*.

---

## 4. Module design decisions

### 4.1 Module 1 — why Isolation Forest, and why benign-only

The objective is to *learn normal behaviour*, which forbids training on
labelled attacks. That makes this a novelty-detection problem, not a
classification one. Isolation Forest suits it because it isolates outliers in
`O(n log n)` without assuming a distributional form, handles the mixed-scale
feature space after log-transforming the heavy-tailed columns, and needs no
negative examples.

**Score calibration.** Raw `decision_function` output is unitless and its
midpoint is meaningless. AstraSec maps it through a logistic centred on the
contamination quantile *of benign traffic*, so a typical benign prompt lands
well below 0.5 rather than at it. Without this, roughly half of all clean
traffic reads as "borderline".

**Three baselines, not one.** A single global baseline cannot serve a customer
support bot and an internal engineering copilot — their normal is different.
Per-tenant profiles (Welford statistics, EMA centroid) supersede the global
model once a tenant has enough observations. The EMA rate decays from
fast-converging to slow-drifting, so a new tenant stabilises quickly while an
established one is not knocked off baseline by a single unusual day.

**Session features are where campaigns show up.** Rate, burstiness
(Goh & Barabási), novelty distance from the tenant centroid, distinct-prompt
ratio and escalation slope. Systematic model extraction is invisible
prompt-by-prompt and obvious in `distinct_template_ratio` at volume.

### 4.2 Module 2 — why a transparent weighted sum

An operator has to be able to read why the score moved and tune the trade-off
without retraining. A learned risk model would be both harder to justify and
harder to change. The four surfaces are deliberately of two kinds:

* **instantaneous** — prompt risk, behaviour risk: what *this* request is doing;
* **structural** — configuration risk, dependency risk: what the deployment
  would cost you if any request succeeded.

Separating them means the score answers two different questions at once: "is
this request dangerous?" and "how much would it matter?". It is also why the
same prompt yields a different Health Score against a hardened app and an
unhardened one.

The weights are validated to sum to 1.0 at import. A silently mis-weighted
model is the kind of bug that never raises an exception and quietly biases
every number in the system.

### 4.3 Module 3 — why three views and two learners

**Word TF-IDF** captures intent. **Character n-grams (3–5, `char_wb`)** survive
leetspeak, homoglyphs and typos — `1gn0r3` shares character n-grams with
`ignore` even though it shares no word tokens. **Engineered dense features**
encode signals that neither view expresses: Shannon entropy, base64/hex blob
ratios, zero-width counts, and a co-occurrence bigram that distinguishes
*"please ignore the typo"* from *"ignore all previous instructions"*.

Two learners because they fail differently. `LogisticRegression` on the full
sparse space is well-calibrated and its coefficients give free per-token
explanations. `RandomForest` on `[SVD(TF-IDF) ‖ dense]` captures interactions a
linear model cannot — "high entropy AND high encoding density AND short" is a
conjunction, not a sum.

**Signature fusion is noisy-OR, not override.** The innate layer can only
*raise* the posterior of the class it evidences and drain mass from `benign`
proportionally; it can never invent an unrelated class. `predict_ml_only()`
bypasses fusion entirely so the evaluation harness can report honest,
ML-attributable numbers alongside the deployed ones.

**Obfuscated delivery is its own class.** When the substantive payload is only
legible after decoding, the incident is attributed to
`adversarial_obfuscation` rather than to the payload's class. This separates
*what was asked* from *how it was smuggled*. Obfuscation-class signatures are
excluded from that test, because they describe the wrapper: "Decode and execute
this base64…" announces the encoding in plain text, yet the instruction it
carries is still hidden.

### 4.4 Module 4 — why rule-based

This is the one place where a learned policy would be actively worse. A
security control must be auditable: an operator needs to read the exact reason
a request was blocked, and change that reason without retraining. The ladder is
therefore a transparent weighted pressure plus explicit contextual rules, and
every decision returns its `policy_ids` and a prose rationale.

Two properties matter more than the ladder itself:

**Sanitise-then-revalidate.** A cleaned prompt is re-scanned from scratch, and
if the attack survives the cleaning it is blocked rather than forwarded.
Sanitisation that is assumed to have worked is worse than no sanitisation,
because it converts a detected attack into an undetected one.

**Posture-sensitive enforcement.** Identical prompts get different treatment
depending on the protected app's blast radius. An exfiltration attempt against
an app with no output filtering is blocked outright; a tool-calling agent
without a sandbox gets no benefit of the doubt on injection.

### 4.5 Module 5 — memory, and the gate on self-healing

Receptors are L2-normalised character-n-gram vectors from a *hashing*
vectoriser, so memory works from the very first request with no vocabulary to
fit and stays stable across restarts.

* **Clonal selection** — a successful defence spawns mutated daughter
  receptors, pre-covering the neighbourhood of the antigen. This is why a
  *rewording* of an attack seen once is recognised.
* **Affinity maturation** — a re-encountered receptor moves toward the new
  antigen at a rate decaying as `1/√encounters`, sharpening without thrashing.
* **Apoptosis** — utility (efficacy × recency × experience) below threshold
  prunes the cell, bounding memory and preventing stale receptors accumulating.

**Rule synthesis and its gate.** Recurring antigens are mined for a shared
discriminative phrase, compiled to a regex, and then — the important part —
**validated against a held-out benign corpus**. A candidate that fires on even
one benign prompt is refused promotion. An automatically-generated policy that
can block legitimate traffic is a self-inflicted outage, so the gate is
absolute rather than a threshold.

Three details decide whether this loop actually runs, and each was wrong in an
earlier version in a way that left the feature looking implemented but inert:

1. **Support is counted in encounters, not distinct cells.** Affinity matching
   deliberately collapses rewordings of one attack onto a single maturing
   receptor, so counting cells would mean a campaign that hits a thousand
   times still registers as "support = 1", and no rule could ever be promoted.
2. **Confidence measures specificity and recurrence, not breadth.** Using
   coverage of the whole threat class as the denominator meant nothing was
   ever promoted under realistic traffic: prompt injection arrives in dozens
   of unrelated phrasings, so one campaign's signature covers only a sliver of
   the class. But a rule that reliably catches *one recurring campaign* is
   precisely what self-healing is for. Confidence is therefore
   `(1 − fp_rate)³ × min(1, support / 2·min_support)` — harmless, and seen
   often enough to be real.
3. **Candidates are re-scored, not skipped.** A phrase first seen four times
   would otherwise keep that initial confidence for ever, so the campaign
   could repeat indefinitely and the rule it justified would never cross the
   threshold. Recurrence is the entire signal, so it has to be re-read on
   every encounter.

A hard ceiling (`max_promoted_rules`) bounds how much of the enforcement
surface the system may author for itself without review. The false-positive
gate makes each individual rule safe; the ceiling bounds the aggregate.

### 4.6 The LLM is optional by construction

The project specifies Llama 3.1 for recommendation generation. A security
control must not depend on an optional component, so the advisor is strictly
additive: a deterministic template-and-retrieval engine always produces
recommendations, and every LLM timeout, connection error or malformed response
falls back to it silently.

Model output is treated as untrusted input like any other: parsed, shape
checked, and every field clamped before a single value reaches the dashboard.
The advisor is also given *structured evidence only* — never the attacker's
prompt text — so a prompt injection cannot reach the recommender.

---

## 5. Data flow

### 5.1 Level-0 context

```
   ┌────────────┐   prompt    ┌───────────┐  sanitised prompt  ┌────────────┐
   │   Client   │────────────▶│  AstraSec │───────────────────▶│  AI model  │
   │ application│◀────────────│           │◀───────────────────│            │
   └────────────┘  filtered   └─────┬─────┘   raw response     └────────────┘
                   response         │
                                    ▼
                        ┌────────────────────────┐
                        │  Dashboard / audit log │
                        └────────────────────────┘
```

### 5.2 Level-1 decomposition

```
 prompt ──▶ [1.0 Feature extraction] ──▶ feature vector
                    │
                    ├──▶ [2.0 Behaviour scoring] ──▶ anomaly score, session features
                    │              │
                    │              ▼
                    │      (tenant profile store)
                    │
                    ├──▶ [3.0 Signature scan] ──▶ innate hits + decoded variants
                    │
                    └──▶ [4.0 Threat classification] ──▶ class, confidence, probabilities
                                   │
                                   ▼
                        [5.0 Health scoring] ──▶ AI Health Score, findings
                                   │
                                   ▼
                        [6.0 Defence decision] ──▶ action, sanitised prompt
                                   │
                                   ├──▶ [7.0 Response filtering] ──▶ filtered response
                                   │
                                   ▼
                        [8.0 Memory commit] ──▶ receptors, rules, recommendations
                                   │
                                   ▼
                        [9.0 Persistence] ──▶ SQLite, live feed
```

---

## 6. Non-functional design

**Latency.** Every module reports its own timing, and the aggregate is returned
with each verdict. Vectorisation dominates per-request cost, which is why the
evaluation harness uses `predict_batch()` — batching turns an O(n) sequence of
full transforms into one.

**Persistence.** SQLite in WAL mode, written *after* the verdict is returned so
audit-log latency never sits in the request path. Trained models and immune
memory are joblib artifacts; the feature schema is stored alongside them and
verified on load, so a model trained against an older feature set fails loudly
instead of silently mis-scoring.

**Failure modes.** A broken WebSocket subscriber cannot break inspection; an
unreachable LLM cannot break recommendations; an unparseable synthesised rule
is rejected rather than installed; explainability failures are caught so they
can never take down a verdict.

**Security of the security tool.** The grouping column in the store's
aggregation query is allow-listed rather than interpolated; report names are
sanitised against path traversal; the config endpoint exposes no secrets; the
receptor vectors (4096 floats each) are stripped from API responses.

---

## 7. What would come next

* **Semantic receptors.** Character n-grams are cheap and language-agnostic but
  blind to paraphrase. Sentence embeddings would let memory recognise an attack
  restated entirely in different words.
* **Real traffic.** The corpus is synthesised from published attack families,
  which makes it reproducible but not a sample of production. Validating
  against real logs is the single highest-value next step.
* **Shared memory across replicas.** Immune memory is currently per-process.
* **Adaptive thresholds.** The ladder's cut-points are fixed; learning them
  per-application from operator feedback would let the system tune its own
  precision/recall trade-off.
