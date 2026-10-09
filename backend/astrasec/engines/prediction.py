"""Module 3 — Threat Prediction Engine.

Biological analogue: *antigen recognition*. Where Module 1 only knows
"this is not self", this engine names the pathogen — prompt injection,
jailbreak, adversarial obfuscation, data exfiltration or model extraction —
and attaches a confidence to that call.

Architecture
------------
Three complementary views of the same prompt are fused:

``word TF-IDF (1-2 grams)``   lexical intent  — "ignore previous instructions"
``char TF-IDF (3-5 grams)``   robustness to obfuscation, typos and leetspeak;
                              character n-grams survive "1gn0r3 4ll"
``dense behavioural features`` the 40 engineered signals from
                              :mod:`astrasec.features` (entropy, densities,
                              co-occurrence bigram, encoding ratios)

Two learners consume them:

``LogisticRegression``  on the full sparse TF-IDF — a strong, well-calibrated
                        text baseline whose coefficients give per-token
                        explanations for free.
``RandomForest``        on [TruncatedSVD(TF-IDF) ‖ dense features] — captures
                        non-linear interactions the linear model cannot, e.g.
                        "high entropy AND high encoding density AND short".

Their probabilities are blended by the weights in
:attr:`astrasec.config.Settings.ensemble_weights`, then optionally fused with
the innate signature bank. ``predict_ml_only`` bypasses the signature fusion so
the evaluation harness can report honest, ML-attributable metrics.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import joblib

from ..utils import atomic_dump
import numpy as np
import scipy.sparse as sp
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import MaxAbsScaler

from ..config import MODEL_DIR, settings
from ..features import PROMPT_FEATURES, extract_prompt_features, prompt_feature_matrix
from ..schemas import Severity, ThreatClass
from ..features import decode_variants, normalise_evasion
from ..signatures import SEVERITY_SCORE, dominant_threat, scan, signature_risk

# Baseline severity of each threat family, used when converting a class
# prediction into an actionable severity.
CLASS_SEVERITY: Dict[str, Severity] = {
    "benign": Severity.NONE,
    "prompt_injection": Severity.CRITICAL,
    "jailbreak": Severity.HIGH,
    "adversarial_obfuscation": Severity.HIGH,
    "data_exfiltration": Severity.CRITICAL,
    "model_extraction": Severity.MEDIUM,
}


# Structural disguise: formatting built to break a model out of its context
# rather than to hide characters. Each alternative is a technique from the
# training corpus's adversarial templates.
_STRUCTURAL = re.compile(
    r"([=#*~_\-<>|\\/])\1{3,}"                          # fake delimiters: ==== #### ~~~~
    r"|[\]\})]\s*[\]\})]\s*[\]\})]"                     # stacked closers: ] } ]]
    r"|[\[\{(]\s*[\[\{(]\s*[\[\{(]"                     # stacked openers
    r"|'\s*\*?\s*;|;\s*--|\bDROP\s+[A-Z]|\bUNION\s+SELECT\b"  # injection syntax
    r"|\b(?:[A-Za-z][*.\-_|/+]){2,}[A-Za-z]\b"             # interleaved: r*a*w, i.g.n.o.r.e
    r"|(?:^|[\s\]})>])(?:system|assistant|developer)\s*[:=]"  # forged role markers
    r"|\bnew[_ ](?:instruction|directive)s?\b",
    re.IGNORECASE | re.MULTILINE,
)


def obfuscation_evidence(text: str, hits: Sequence) -> bool:
    """Does the text show any trace of actually being disguised?

    Four independent traces, any one sufficient:

    * a signature fired;
    * a decoder recovered a hidden payload (base64, hex, ROT13, Morse ...);
    * evasion normalisation changed the words (leetspeak, homoglyphs,
      zero-width characters, s p a c e d letters);
    * structural disguise — fake delimiters, stacked brackets, injection
      syntax, letters interleaved with symbols, forged role markers.

    Plain text — a person's name, a table label, a heading, an ordinary
    sentence — shows none of these, and so cannot be "obfuscated".
    """
    if hits:
        return True
    if decode_variants(text):
        return True
    if _STRUCTURAL.search(text) and re.search(r"[A-Za-z]{3,}", text):
        return True
    return normalise_evasion(text).casefold().split() != text.casefold().split()


def gate_obfuscation(probs: Dict[str, float], text: str, hits: Sequence) -> Dict[str, float]:
    """Withdraw an obfuscation verdict that has no evidence behind it.

    The mass is removed and the rest renormalised, so the next most likely
    class is judged on its own merits against the usual threshold — usually
    that is benign.
    """
    if not settings.obfuscation_requires_evidence:
        return probs
    if max(probs, key=probs.get) != "adversarial_obfuscation":
        return probs
    if obfuscation_evidence(text, hits):
        return probs
    out = dict(probs)
    out["adversarial_obfuscation"] = 0.0
    s = sum(out.values()) or 1.0
    return {k: v / s for k, v in out.items()}


# A request: a question, an imperative, or a politely framed ask.
_REQUEST = re.compile(
    r"\?|\b(?:tell|show|print|reveal|give|list|send|output|share|repeat|dump|export|"
    r"provide|leak|display|disclose|return|write|echo|expose|forward|e-?mail|upload|"
    r"paste|copy|spell|translate|summari[sz]e|recite|describe|enumerate|extract|fetch|"
    r"retrieve|read|include|attach|append|post|state|confirm|explain|decode|encode|"
    r"convert|generate|what|which|who|where|how|can you|could you|would you|will you|"
    r"please|i need|i want|we need)\b",
    re.IGNORECASE,
)
_REQUEST_CLASSES = ("data_exfiltration", "model_extraction")


def gate_intent(probs: Dict[str, float], text: str, hits: Sequence) -> Dict[str, float]:
    """Withdraw an exfiltration or extraction verdict on text that asks for nothing.

    Both classes are requests by definition. Across the whole held-out test
    set every example of either contains a request form, so this costs no
    recall — while "Internal memo" and "Customer cannot reset their password"
    stop being reported as data theft.
    """
    if not settings.extraction_requires_request:
        return probs
    top = max(probs, key=probs.get)
    if top not in _REQUEST_CLASSES or hits or _REQUEST.search(text):
        return probs
    out = dict(probs)
    out[top] = 0.0
    s = sum(out.values()) or 1.0
    return {k: v / s for k, v in out.items()}


def apply_evidence_gates(probs: Dict[str, float], text: str,
                         hits: Sequence) -> Dict[str, float]:
    """Run every evidence gate until the verdict stops changing.

    The gates are not independent. Withdrawing one class promotes the next,
    and the next may be one an earlier gate would have rejected: "Customer
    cannot reset their password." is first read as exfiltration; the intent
    gate withdraws that (nothing is being asked for), which promotes
    obfuscation — after the obfuscation gate has already run. Applied once,
    in a fixed order, that sentence came out as "obfuscation". Iterating to a
    fixed point makes the result independent of gate order. Each pass either
    withdraws a class or stops, so it ends within one pass per class.
    """
    for _ in range(len(probs) + 1):
        before = max(probs, key=probs.get)
        probs = gate_intent(gate_obfuscation(probs, text, hits), text, hits)
        if max(probs, key=probs.get) == before:
            break
    return probs


class ThreatPredictionEngine:
    """Multi-class AI-threat classifier with signature fusion."""

    MODEL_FILE = "threat_prediction.joblib"

    def __init__(self) -> None:
        self.word_vec: Optional[TfidfVectorizer] = None
        self.char_vec: Optional[TfidfVectorizer] = None
        self.dense_scaler: Optional[MaxAbsScaler] = None
        self.svd: Optional[TruncatedSVD] = None
        self.logreg: Optional[LogisticRegression] = None
        self.forest: Optional[RandomForestClassifier] = None
        self.classes_: List[str] = []
        self.trained_at: Optional[float] = None
        self.training_size: int = 0
        self._feature_names_word: Optional[np.ndarray] = None

    # ------------------------------------------------------------------
    # Feature assembly
    # ------------------------------------------------------------------
    def _vectorise(self, texts: Sequence[str], fit: bool = False):
        if fit:
            self.word_vec = TfidfVectorizer(
                analyzer="word",
                ngram_range=tuple(settings.tfidf_word_ngrams),
                max_features=settings.tfidf_word_max_features,
                sublinear_tf=True,
                min_df=2,
                lowercase=True,
                strip_accents="unicode",
                token_pattern=r"(?u)\b\w[\w'-]*\b",
            )
            self.char_vec = TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=tuple(settings.tfidf_char_ngrams),
                max_features=settings.tfidf_char_max_features,
                sublinear_tf=True,
                min_df=3,
                lowercase=True,
            )
            Xw = self.word_vec.fit_transform(texts)
            Xc = self.char_vec.fit_transform(texts)
            self._feature_names_word = self.word_vec.get_feature_names_out()
        else:
            Xw = self.word_vec.transform(texts)
            Xc = self.char_vec.transform(texts)

        D = prompt_feature_matrix(texts)
        if fit:
            self.dense_scaler = MaxAbsScaler().fit(D)
        Ds = sp.csr_matrix(self.dense_scaler.transform(D))
        return Xw, Xc, Ds

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def fit(self, texts: Sequence[str], labels: Sequence[str],
            verbose: bool = True) -> Dict[str, float]:
        t0 = time.perf_counter()
        texts = list(texts)
        labels = list(labels)

        Xw, Xc, Ds = self._vectorise(texts, fit=True)
        X_sparse = sp.hstack([Xw, Xc, Ds], format="csr")

        if verbose:
            print(f"[Module 3] TF-IDF matrix: {X_sparse.shape[0]:,} x {X_sparse.shape[1]:,}")

        # --- Linear learner on the full sparse space ---------------------
        self.logreg = LogisticRegression(
            max_iter=3000,
            C=2.0,
            tol=1e-3,
            class_weight="balanced",
            solver="saga",
            random_state=settings.random_seed,
        )
        self.logreg.fit(X_sparse, labels)
        self.classes_ = list(self.logreg.classes_)

        # --- Non-linear learner on a compressed + dense view -------------
        n_comp = min(300, X_sparse.shape[1] - 1, max(2, X_sparse.shape[0] - 1))
        self.svd = TruncatedSVD(
            n_components=n_comp, random_state=settings.random_seed, algorithm="randomized"
        )
        X_lex = sp.hstack([Xw, Xc], format="csr")
        self.svd.fit(X_lex)

        # The component matrix is by far the largest thing in the serialised
        # model (300 x ~43,000 float64 ≈ 103 MB, more than twice the forest).
        # Storing it as float32 halves that. Measured on the held-out set:
        # zero label changes across 5,316 rows and identical accuracy/macro-F1
        # — a random forest's output is piecewise constant, so a ~1e-7
        # perturbation of the projection almost never moves a leaf.
        #
        # The cast happens BEFORE the forest is fitted, so the forest trains on
        # exactly the values it will be served. Casting only at save time would
        # leave the in-memory and reloaded models subtly different.
        self.svd.components_ = self.svd.components_.astype(np.float32)
        Z = self._svd_transform(X_lex)
        Z_full = np.hstack([Z, Ds.toarray()])

        self.forest = RandomForestClassifier(
            n_estimators=settings.rf_n_estimators,
            max_depth=settings.rf_max_depth,
            min_samples_leaf=settings.rf_min_samples_leaf,
            class_weight=settings.rf_class_weight,
            random_state=settings.random_seed,
            n_jobs=-1,
        )
        self.forest.fit(Z_full, labels)
        # Guarantee both learners agree on class ordering before blending.
        if list(self.forest.classes_) != self.classes_:
            raise RuntimeError("class ordering mismatch between ensemble members")

        self.trained_at = time.time()
        self.training_size = len(texts)
        stats = {
            "training_size": float(len(texts)),
            "n_features": float(X_sparse.shape[1]),
            "svd_components": float(n_comp),
            "svd_explained_variance": float(self.svd.explained_variance_ratio_.sum()),
            "fit_seconds": time.perf_counter() - t0,
        }
        if verbose:
            print(
                f"[Module 3] Ensemble trained in {stats['fit_seconds']:.1f}s "
                f"| SVD retains {stats['svd_explained_variance']:.1%} variance"
            )
        return stats

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Inference-path performance
    # ------------------------------------------------------------------
    # Serving one prompt at a time is the common case, and two scikit-learn
    # defaults are actively harmful there:
    #
    #   * `n_jobs=-1` makes joblib dispatch a parallel job per call. For a
    #     single row the thread coordination costs far more than the work —
    #     profiling showed ~86 ms per RandomForest call, almost all of it
    #     joblib polling. Parallelism only pays on a real batch.
    #   * `TruncatedSVD.transform` computes `X @ components_.T`. The `.T` is
    #     an F-contiguous view, so SciPy copies the whole 300x43,015 matrix
    #     (~103 MB) on every call. For a one-row input that is pure waste.
    #
    # Both are fixed below without touching the fitted parameters, so results
    # are identical to `svd.transform` / `forest.predict_proba`.
    _BATCH_PARALLEL_THRESHOLD = 32

    def _svd_transform(self, X: sp.spmatrix) -> np.ndarray:
        """Project onto the SVD basis, reading only the non-zero columns.

        A prompt touches a few hundred of ~43,000 TF-IDF columns, so gathering
        `components_[:, nonzero]` reads ~1 MB instead of the full matrix.
        Falls back to the BLAS path once a batch is large enough for it to win.
        """
        X = X.tocsr()
        if X.shape[0] >= self._BATCH_PARALLEL_THRESHOLD:
            return self.svd.transform(X)
        C = self.svd.components_                      # (k, d)
        out = np.zeros((X.shape[0], C.shape[0]), dtype=np.float64)
        for i in range(X.shape[0]):
            lo, hi = X.indptr[i], X.indptr[i + 1]
            if hi > lo:
                out[i] = C[:, X.indices[lo:hi]] @ X.data[lo:hi]
        return out

    def _tune_parallelism(self, n_rows: int) -> None:
        n_jobs = -1 if n_rows >= self._BATCH_PARALLEL_THRESHOLD else 1
        if self.forest is not None and self.forest.n_jobs != n_jobs:
            self.forest.n_jobs = n_jobs

    def _proba_matrix(self, texts: Sequence[str]) -> np.ndarray:
        self._tune_parallelism(len(texts))
        Xw, Xc, Ds = self._vectorise(texts, fit=False)
        X_sparse = sp.hstack([Xw, Xc, Ds], format="csr")
        p_lr = self.logreg.predict_proba(X_sparse)

        Z = self._svd_transform(sp.hstack([Xw, Xc], format="csr"))
        Z_full = np.hstack([Z, Ds.toarray()])
        p_rf = self.forest.predict_proba(Z_full)

        w_rf = settings.ensemble_weights["random_forest"]
        w_lr = settings.ensemble_weights["logistic_regression"]
        total = w_rf + w_lr
        return (w_rf * p_rf + w_lr * p_lr) / total

    def predict_proba(self, texts: Sequence[str]) -> np.ndarray:
        if self.logreg is None:
            raise RuntimeError("ThreatPredictionEngine.fit() must be called first")
        return self._proba_matrix(texts)

    def predict_ml_only(self, texts: Sequence[str]) -> List[str]:
        """Pure-ML predictions — no signature fusion. Used for honest metrics."""
        P = self.predict_proba(texts)
        return [self.classes_[i] for i in P.argmax(axis=1)]

    def predict_batch(self, texts: Sequence[str],
                      fuse_signatures: bool = True) -> List[str]:
        """Vectorised equivalent of :meth:`predict` for evaluation.

        Vectorisation dominates single-prompt cost, so batching it turns an
        O(n) sequence of full transforms into one — the difference between a
        4-minute and a 10-second evaluation pass over the test set.
        """
        P = self.predict_proba(texts)
        out: List[str] = []
        for row, text in zip(P, texts):
            probs = {c: float(p) for c, p in zip(self.classes_, row)}
            hits = scan(text) if fuse_signatures else []
            if fuse_signatures:
                if hits:
                    sig_class = dominant_threat(hits)
                    if sig_class is not None:
                        boost = signature_risk(hits)
                        key = sig_class.value
                        probs[key] = probs.get(key, 0.0) + (1.0 - probs.get(key, 0.0)) * boost
                        probs["benign"] = max(0.0, probs.get("benign", 0.0)
                                              - probs.get("benign", 0.0) * boost)
                        s = sum(probs.values()) or 1.0
                        probs = {k: v / s for k, v in probs.items()}
            probs = apply_evidence_gates(probs, text, hits)
            best = max(probs, key=probs.get)
            if (best != "benign" and probs[best] < settings.prediction_threshold
                    and not hits
                    and 1.0 - probs.get("benign", 0.0) < settings.malicious_mass_threshold):
                best = "benign"
            out.append(best)
        return out

    def predict(self, prompt: str, memory_hint: Optional[Tuple[str, float]] = None,
                fuse_signatures: bool = True) -> Dict[str, object]:
        """Full prediction for a single prompt.

        Parameters
        ----------
        memory_hint
            ``(threat_class, affinity)`` recalled by Module 5 for a
            near-identical antigen seen before. A confident recall nudges the
            posterior — this is the immune-memory feedback loop that makes the
            secondary response faster and more certain than the primary one.
        """
        P = self.predict_proba([prompt])[0]
        probs: Dict[str, float] = {c: float(p) for c, p in zip(self.classes_, P)}

        hits = scan(prompt) if fuse_signatures else []
        sig_risk = signature_risk(hits)
        sig_class = dominant_threat(hits)

        ml_class = max(probs, key=probs.get)
        ml_conf = probs[ml_class]

        if fuse_signatures and hits and sig_class is not None:
            # Noisy-OR fusion: the innate layer can only *raise* the posterior
            # of the class it evidences, never invent an unrelated one. It also
            # drains probability mass from `benign` proportionally.
            key = sig_class.value
            boost = sig_risk
            probs[key] = probs.get(key, 0.0) + (1.0 - probs.get(key, 0.0)) * boost
            drain = probs.get("benign", 0.0) * boost
            probs["benign"] = max(0.0, probs.get("benign", 0.0) - drain)
            s = sum(probs.values()) or 1.0
            probs = {k: v / s for k, v in probs.items()}

        memory_assisted = False
        if memory_hint:
            mem_class, affinity = memory_hint
            if affinity >= settings.memory_affinity_threshold and mem_class in probs:
                # Secondary immune response: prior exposure sharpens the call.
                lift = 0.5 * (affinity - settings.memory_affinity_threshold) / max(
                    1e-6, 1.0 - settings.memory_affinity_threshold
                )
                probs[mem_class] = probs[mem_class] + (1.0 - probs[mem_class]) * lift
                s = sum(probs.values()) or 1.0
                probs = {k: v / s for k, v in probs.items()}
                memory_assisted = True

        # Evidence gates: a class that makes a claim about the text — that it
        # is disguised, or that it asks for data — must be able to point at
        # something in the text that supports the claim.
        probs = apply_evidence_gates(probs, prompt, hits)
        final_class = max(probs, key=probs.get)
        confidence = probs[final_class]

        # Guard against a low-confidence non-benign call: if nothing crosses
        # the decision threshold and no signature fired, stay benign.
        if (final_class != "benign" and confidence < settings.prediction_threshold and not hits
                and 1.0 - probs.get("benign", 0.0) < settings.malicious_mass_threshold):
            final_class = "benign"
            confidence = probs.get("benign", 1.0 - confidence)

        severity = self._severity(final_class, confidence, sig_risk)

        return {
            "threat_class": ThreatClass(final_class),
            "confidence": round(float(confidence), 4),
            "probabilities": {k: round(float(v), 4) for k, v in
                              sorted(probs.items(), key=lambda kv: -kv[1])},
            "severity": severity,
            "model_votes": {
                "ensemble_ml": ml_class,
                "signature_bank": sig_class.value if sig_class else "none",
                "memory": memory_hint[0] if memory_hint else "none",
            },
            "top_indicators": self.explain(prompt, final_class),
            "signature_hits": [h.signature.id for h in hits],
            "signature_detail": [
                {"id": h.signature.id, "description": h.signature.description,
                 "owasp": h.signature.owasp, "severity": h.signature.severity.value,
                 "match": h.match[:120], "via": h.via}
                for h in hits
            ],
            "memory_assisted": memory_assisted,
            "ml_confidence": round(float(ml_conf), 4),
            "signature_risk": round(float(sig_risk), 4),
            "explanation": self._explain_text(final_class, confidence, hits, memory_assisted),
        }

    @staticmethod
    def _severity(threat_class: str, confidence: float, sig_risk: float) -> Severity:
        if threat_class == "benign":
            return Severity.NONE
        base = CLASS_SEVERITY.get(threat_class, Severity.MEDIUM)
        score = SEVERITY_SCORE[base] * (0.55 + 0.45 * confidence)
        score = max(score, sig_risk * SEVERITY_SCORE[base])
        if score >= 0.85:
            return Severity.CRITICAL
        if score >= 0.62:
            return Severity.HIGH
        if score >= 0.38:
            return Severity.MEDIUM
        return Severity.LOW

    # ------------------------------------------------------------------
    # Explainability
    # ------------------------------------------------------------------
    def explain(self, prompt: str, threat_class: str, k: int = 6) -> List[Dict[str, object]]:
        """Top word-level contributions to the predicted class.

        Contribution = tf-idf weight x logistic-regression coefficient, which
        is the exact additive term that moved the logit. This makes every
        verdict auditable — a hard requirement for a security control.
        """
        if self.logreg is None or threat_class not in self.classes_:
            return []
        try:
            ci = self.classes_.index(threat_class)
            xw = self.word_vec.transform([prompt])
            n_word = xw.shape[1]
            coefs = self.logreg.coef_[ci][:n_word]
            xw = xw.tocoo()
            contribs = [
                (self._feature_names_word[j], float(v * coefs[j]))
                for j, v in zip(xw.col, xw.data)
            ]
            contribs.sort(key=lambda t: -abs(t[1]))
            out = []
            for term, c in contribs[:k]:
                if abs(c) < 1e-6:
                    continue
                out.append({
                    "term": term,
                    "contribution": round(c, 4),
                    "direction": "supports" if c > 0 else "opposes",
                })
            return out
        except Exception:       # explainability must never break inference
            return []

    @staticmethod
    def _explain_text(threat_class: str, confidence: float, hits, memory_assisted: bool) -> str:
        if threat_class == "benign":
            base = f"Classified as benign traffic with {confidence:.0%} confidence."
        else:
            pretty = threat_class.replace("_", " ")
            base = f"Predicted {pretty} with {confidence:.0%} confidence."
        if hits:
            ids = ", ".join(h.signature.id for h in hits[:4])
            base += f" Innate signature layer corroborates ({ids})."
        if memory_assisted:
            # Deliberately not "secondary response": a recall above the
            # affinity threshold sharpens the posterior, but whether this
            # is genuinely a re-encounter depends on the *final* class
            # agreeing with the matched cell's — a question only Module 5
            # can settle, after this prediction is made. Claiming it here
            # produced traces where Module 3 announced a secondary response
            # and Module 5 then reported a primary one.
            base += (" Immune memory matched a stored antigen above the affinity "
                     "threshold, sharpening the posterior.")
        return base

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save(self, path: Optional[Path] = None) -> Path:
        path = path or (MODEL_DIR / self.MODEL_FILE)
        atomic_dump({
            "word_vec": self.word_vec,
            "char_vec": self.char_vec,
            "dense_scaler": self.dense_scaler,
            "svd": self.svd,
            "logreg": self.logreg,
            "forest": self.forest,
            "classes": self.classes_,
            "trained_at": self.trained_at,
            "training_size": self.training_size,
            "dense_features": list(PROMPT_FEATURES),
        }, path, compress=3)
        return path

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "ThreatPredictionEngine":
        path = path or (MODEL_DIR / cls.MODEL_FILE)
        blob = joblib.load(path)
        eng = cls()
        eng.word_vec = blob["word_vec"]
        eng.char_vec = blob["char_vec"]
        eng.dense_scaler = blob["dense_scaler"]
        eng.svd = blob["svd"]
        eng.logreg = blob["logreg"]
        eng.forest = blob["forest"]
        eng.classes_ = blob["classes"]
        eng.trained_at = blob.get("trained_at")
        eng.training_size = blob.get("training_size", 0)
        eng._feature_names_word = eng.word_vec.get_feature_names_out()
        # Defensive: models trained before the float32 change still load, and
        # are normalised to the serving representation on the way in.
        if eng.svd is not None and eng.svd.components_.dtype != np.float32:
            eng.svd.components_ = eng.svd.components_.astype(np.float32)
        if eng.forest is not None:
            eng.forest.n_jobs = 1
        saved = blob.get("dense_features")
        if saved and list(saved) != list(PROMPT_FEATURES):
            raise ValueError(
                "Dense feature schema changed since training. Retrain with scripts/train.py."
            )
        return eng

    @property
    def is_trained(self) -> bool:
        return self.logreg is not None and self.forest is not None


__all__ = ["ThreatPredictionEngine", "CLASS_SEVERITY"]
