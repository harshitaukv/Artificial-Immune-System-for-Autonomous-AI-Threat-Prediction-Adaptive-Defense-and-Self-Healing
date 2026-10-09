"""Reproducible corpus synthesis for the AstraSec Threat Prediction Engine.

`build_dataset()` expands every template in :mod:`astrasec.data.lexicon` with
randomised slot fills, obfuscation transforms and realistic text noise,
producing a labelled multi-class corpus together with the ``template_id`` of
each row. The template id is what makes a *template-disjoint* evaluation split
possible, so reported accuracy reflects generalisation to unseen phrasings
rather than memorisation.
"""
from __future__ import annotations

import hashlib
import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

from ..config import DATA_DIR, settings
from .lexicon import (
    BENIGN_TEMPLATES,
    HARD_NEGATIVE_IDS,
    LEXICON,
    OBFUSCATION_CORES,
    TEMPLATES,
    casing_noise,
    inject_typos,
    normalise_ws,
    to_acrostic,
    to_base64,
    to_hex,
    to_homoglyph,
    to_leet,
    to_reversed,
    to_rot13,
    to_spaced,
    to_zerowidth,
)

# Target proportion of each class in the generated corpus. Benign dominates,
# mirroring real production traffic where attacks are a minority class.
DEFAULT_CLASS_MIX: Dict[str, float] = {
    "benign": 0.40,
    "prompt_injection": 0.15,
    "jailbreak": 0.15,
    "adversarial_obfuscation": 0.12,
    "data_exfiltration": 0.11,
    "model_extraction": 0.07,
}


@dataclass
class DatasetStats:
    total: int
    per_class: Dict[str, int]
    per_template: Dict[str, int]
    hard_negatives: int
    obfuscated: int
    mean_length: float
    build_seconds: float
    seed: int
    checksum: str
    extras: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "total": self.total,
            "per_class": self.per_class,
            "per_template": self.per_template,
            "hard_negatives": self.hard_negatives,
            "obfuscated": self.obfuscated,
            "mean_length": round(self.mean_length, 2),
            "build_seconds": round(self.build_seconds, 3),
            "seed": self.seed,
            "checksum": self.checksum,
            **self.extras,
        }


class DatasetGenerator:
    """Deterministic generator: same seed -> byte-identical corpus."""

    def __init__(self, seed: int = None, class_mix: Optional[Dict[str, float]] = None):
        self.seed = settings.random_seed if seed is None else seed
        self.rng = random.Random(self.seed)
        self.class_mix = dict(class_mix or DEFAULT_CLASS_MIX)
        total = sum(self.class_mix.values())
        self.class_mix = {k: v / total for k, v in self.class_mix.items()}

        self._by_label: Dict[str, List[Tuple[str, str, str]]] = {}
        for tid, label, tpl in TEMPLATES + BENIGN_TEMPLATES:
            self._by_label.setdefault(label, []).append((tid, label, tpl))

    # ------------------------------------------------------------------
    # Slot filling
    # ------------------------------------------------------------------
    def _payload_slots(self) -> Dict[str, str]:
        """Materialise the obfuscation-specific template slots."""
        core = self.rng.choice(OBFUSCATION_CORES)
        third = max(1, len(core) // 3)
        return {
            "b64_payload": to_base64(core),
            "rot13_payload": to_rot13(core),
            "hex_payload": to_hex(core),
            "leet_payload": to_leet(core, self.rng),
            "spaced_payload": to_spaced(core, self.rng),
            "homoglyph_payload": to_homoglyph(core, self.rng),
            "zerowidth_payload": to_zerowidth(core, self.rng),
            "acrostic_payload": to_acrostic(core, self.rng),
            "reversed_payload": to_reversed(core),
            "split_a": core[:third],
            "split_b": core[third: 2 * third],
            "split_c": core[2 * third:],
            "ticket": str(self.rng.randint(10_000, 99_999)),
        }

    def _fill(self, template: str) -> str:
        slots = {k: self.rng.choice(v) for k, v in LEXICON.items()}
        slots.update(self._payload_slots())
        try:
            text = template.format(**slots)
        except KeyError as exc:  # pragma: no cover - template authoring guard
            raise KeyError(f"template references unknown slot {exc} in: {template!r}")
        return text.replace("\\n", "\n")

    def _decorate(self, text: str, label: str) -> Tuple[str, bool]:
        """Apply realistic surface noise; returns (text, was_obfuscated).

        Intent-hiding obfuscation (leetspeak, homoglyphs, zero-width padding,
        character spacing) is applied ONLY to the adversarial_obfuscation
        class. This is a deliberate labelling decision, not a convenience:
        AstraSec's taxonomy defines obfuscated *delivery* as its own class, so
        a leetspeak exfiltration attempt is an adversarial-obfuscation
        incident at runtime. Decorating other classes with intent-hiding noise
        while keeping their original label would put the corpus in direct
        conflict with the deployed decision rule, and would show up as
        "errors" that are actually correct behaviour.

        Class-neutral noise — typos, casing, conversational padding — is
        applied everywhere, since it carries no label signal.
        """
        obfuscated = False
        r = self.rng.random()

        # Extra evasion diversity for the class whose defining feature it is.
        if label == "adversarial_obfuscation" and r < 0.35:
            fn = self.rng.choice(["leet", "homoglyph", "zerowidth", "spaced"])
            if fn == "leet":
                text = to_leet(text, self.rng, rate=0.35)
            elif fn == "homoglyph":
                text = to_homoglyph(text, self.rng, rate=0.25)
            elif fn == "zerowidth":
                text = to_zerowidth(text, self.rng)
            else:
                words = text.split()
                idx = self.rng.randrange(len(words)) if words else 0
                if words:
                    words[idx] = to_spaced(words[idx], self.rng)
                text = " ".join(words)
            obfuscated = True

        # Typos / casing affect both classes so they carry no label signal.
        if self.rng.random() < 0.22:
            text = inject_typos(text, self.rng)
        text = casing_noise(text, self.rng)

        # Conversational padding, again class-neutral.
        if self.rng.random() < 0.18:
            pad = self.rng.choice([
                " Thanks!", " Please respond quickly.", " (sent from mobile)",
                " Let me know if you need more detail.", " -- Regards, Priya",
                " Appreciate the help.", " Cheers.",
            ])
            text = text + pad
        if self.rng.random() < 0.10:
            pre = self.rng.choice([
                "Hi again. ", "Following up: ", "One more thing — ", "FYI: ",
            ])
            text = pre + text

        return normalise_ws(text), obfuscated

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate(self, n_samples: int = 24_000) -> pd.DataFrame:
        t0 = time.perf_counter()
        rows: List[Dict[str, object]] = []
        seen: set[str] = set()

        targets = {lbl: int(round(frac * n_samples)) for lbl, frac in self.class_mix.items()}

        for label, target in targets.items():
            pool = self._by_label.get(label, [])
            if not pool:  # pragma: no cover
                raise ValueError(f"no templates for label {label!r}")
            produced = 0
            attempts = 0
            max_attempts = target * 40
            while produced < target and attempts < max_attempts:
                attempts += 1
                tid, lbl, tpl = pool[produced % len(pool)] if attempts <= target else self.rng.choice(pool)
                raw = self._fill(tpl)
                text, obf = self._decorate(raw, lbl)
                if len(text) < 3:
                    continue
                key = hashlib.md5(text.lower().encode()).hexdigest()
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "text": text,
                    "label": lbl,
                    "template_id": tid,
                    "obfuscated": obf,
                    "hard_negative": tid in HARD_NEGATIVE_IDS,
                    "length": len(text),
                })
                produced += 1

        # A small tail of "clean-but-unusual" benign traffic (very long
        # pastes, code blocks, non-English) so the behaviour engine sees
        # legitimate outliers and the classifier learns they are benign.
        rows.extend(self._long_tail_benign(max(200, n_samples // 40)))

        df = pd.DataFrame(rows)
        df = df.sample(frac=1.0, random_state=self.seed).reset_index(drop=True)

        checksum = hashlib.sha256(
            "".join(df["text"].astype(str).tolist()).encode()
        ).hexdigest()[:16]

        self.stats = DatasetStats(
            total=len(df),
            per_class=df["label"].value_counts().to_dict(),
            per_template=df["template_id"].value_counts().to_dict(),
            hard_negatives=int(df["hard_negative"].sum()),
            obfuscated=int(df["obfuscated"].sum()),
            mean_length=float(df["length"].mean()),
            build_seconds=time.perf_counter() - t0,
            seed=self.seed,
            checksum=checksum,
            extras={"n_templates": len(TEMPLATES) + len(BENIGN_TEMPLATES)},
        )
        return df

    def _long_tail_benign(self, n: int) -> List[Dict[str, object]]:
        code_snippets = [
            "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a",
            "SELECT u.id, COUNT(o.id) FROM users u LEFT JOIN orders o ON o.user_id = u.id GROUP BY u.id;",
            "const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };",
            "FROM python:3.11-slim\nWORKDIR /app\nCOPY requirements.txt .\nRUN pip install -r requirements.txt",
        ]
        multilingual = [
            "வணக்கம், எனது கணக்கை எப்படி புதுப்பிப்பது?",
            "नमस्ते, मुझे अपना पासवर्ड रीसेट करना है।",
            "Bonjour, comment puis-je exporter mes factures ?",
            "¿Cómo cambio mi plan de suscripción?",
            "こんにちは、請求書のダウンロード方法を教えてください。",
        ]
        rows = []
        for i in range(n):
            kind = self.rng.random()
            if kind < 0.4:
                body = self.rng.choice(code_snippets)
                text = f"Please review this code and suggest improvements:\n{body}"
                tid = "BN-LT-CODE"
            elif kind < 0.7:
                text = self.rng.choice(multilingual)
                tid = "BN-LT-I18N"
            else:
                para = " ".join(
                    self.rng.choice(LEXICON["benign_technical"]) for _ in range(self.rng.randint(4, 9))
                )
                text = f"I have several questions in one message. {para}"
                tid = "BN-LT-LONG"
            rows.append({
                "text": normalise_ws(text) if tid != "BN-LT-CODE" else text,
                "label": "benign",
                "template_id": tid,
                "obfuscated": False,
                "hard_negative": True,
                "length": len(text),
            })
        return rows


# --------------------------------------------------------------------------
# Splitting
# --------------------------------------------------------------------------
def template_disjoint_split(
    df: pd.DataFrame, test_size: float = 0.2, seed: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Hold out whole templates per class.

    This is the strict protocol: the test set contains *phrasings the model has
    never seen*. Accuracy under this split is the number that should be
    reported for generalisation claims.
    """
    rng = random.Random(seed)
    test_templates: set[str] = set()
    for label, grp in df.groupby("label", observed=True):
        tids = sorted(grp["template_id"].unique())
        if len(tids) < 3:
            continue
        k = max(1, int(round(len(tids) * test_size)))
        test_templates.update(rng.sample(tids, k))
    test_mask = df["template_id"].isin(test_templates)
    return df[~test_mask].reset_index(drop=True), df[test_mask].reset_index(drop=True)


def random_split(
    df: pd.DataFrame, test_size: float = 0.2, seed: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Conventional stratified random split (optimistic upper bound)."""
    from sklearn.model_selection import train_test_split

    train, test = train_test_split(
        df, test_size=test_size, random_state=seed, stratify=df["label"]
    )
    return train.reset_index(drop=True), test.reset_index(drop=True)


# --------------------------------------------------------------------------
# Convenience helpers
# --------------------------------------------------------------------------
def build_dataset(
    n_samples: int = 24_000,
    seed: int | None = None,
    save: bool = True,
    path: Optional[Path] = None,
) -> Tuple[pd.DataFrame, DatasetStats]:
    gen = DatasetGenerator(seed=seed)
    df = gen.generate(n_samples)
    if save:
        path = path or (DATA_DIR / "astrasec_corpus.parquet")
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            df.to_parquet(path, index=False)
        except Exception:  # pyarrow missing -> csv fallback
            path = path.with_suffix(".csv")
            df.to_csv(path, index=False)
        (DATA_DIR / "corpus_stats.json").write_text(
            json.dumps(gen.stats.to_dict(), indent=2)
        )
    return df, gen.stats


def load_or_build(
    n_samples: int = 24_000, seed: int | None = None
) -> Tuple[pd.DataFrame, Optional[DatasetStats]]:
    for ext in (".parquet", ".csv"):
        p = DATA_DIR / f"astrasec_corpus{ext}"
        if p.exists():
            df = pd.read_parquet(p) if ext == ".parquet" else pd.read_csv(p)
            stats_p = DATA_DIR / "corpus_stats.json"
            stats = json.loads(stats_p.read_text()) if stats_p.exists() else None
            # A corpus cached by an older version has fewer phrasing templates
            # than the generator now knows; training on it would silently
            # reproduce the old models. Rebuild instead.
            current = len(TEMPLATES) + len(BENIGN_TEMPLATES)
            cached = (stats or {}).get("n_templates") or ((stats or {}).get("extras") or {}).get("n_templates")
            if cached != current:
                break
            return df, stats
    return build_dataset(n_samples=n_samples, seed=seed)


__all__ = [
    "DatasetGenerator",
    "DatasetStats",
    "build_dataset",
    "load_or_build",
    "template_disjoint_split",
    "random_split",
    "DEFAULT_CLASS_MIX",
]
