"""Training entry point for AstraSec.

    python -m astrasec.train                     # full run, default settings
    python -m astrasec.train --samples 40000     # larger corpus
    python -m astrasec.train --split random      # optimistic split
    python -m astrasec.train --quick             # fast smoke run

Two evaluation protocols are reported, deliberately:

``template-disjoint`` (default)
    Whole phrasing templates are held out, so the test set contains attack
    formulations the model has never seen. This is the number that should be
    quoted for generalisation.

``random``
    Conventional stratified split. Because the corpus is template-generated,
    near-duplicates leak across the split and accuracy is inflated. It is
    reported only as an upper bound, and labelled as such.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold

from .config import MODEL_DIR, REPORT_DIR, settings
from .data.generator import (
    build_dataset,
    load_or_build,
    random_split,
    template_disjoint_split,
)
from .engines.behavior import BehaviorLearningEngine
from .engines.memory import ImmuneMemoryEngine
from .engines.prediction import ThreatPredictionEngine


def _metrics(y_true, y_pred, labels) -> Dict[str, object]:
    rep = classification_report(y_true, y_pred, labels=labels,
                                output_dict=True, zero_division=0)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "per_class": {
            k: {m: float(v) for m, v in d.items()}
            for k, d in rep.items() if isinstance(d, dict)
        },
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "labels": list(labels),
    }


def train(
    n_samples: int = 24_000,
    split: str = "disjoint",
    rebuild: bool = False,
    cv_folds: int = 3,
    quick: bool = False,
    verbose: bool = True,
) -> Dict[str, object]:
    t_start = time.perf_counter()

    if quick:
        n_samples = min(n_samples, 6_000)
        cv_folds = 0

    # ---------------------------------------------------------------- data
    if rebuild:
        df, stats = build_dataset(n_samples=n_samples, save=True)
        stats = stats.to_dict()
    else:
        df, stats = load_or_build(n_samples=n_samples)
        if hasattr(stats, "to_dict"):
            stats = stats.to_dict()
    if quick and len(df) > n_samples:
        df = df.sample(n_samples, random_state=settings.random_seed).reset_index(drop=True)

    if verbose:
        print(f"\n{'=' * 78}\nAstraSec — training run\n{'=' * 78}")
        print(f"Corpus: {len(df):,} prompts across {df['label'].nunique()} classes")
        for lbl, n in df["label"].value_counts().items():
            print(f"   {lbl:26s} {n:6,d}  ({n / len(df):5.1%})")

    splitter = template_disjoint_split if split == "disjoint" else random_split
    train_df, test_df = splitter(df, test_size=0.2, seed=settings.random_seed)
    if verbose:
        print(f"\nSplit protocol: {split}"
              f"  |  train {len(train_df):,}  test {len(test_df):,}")
        if split == "disjoint":
            n_held = test_df["template_id"].nunique()
            print(f"   {n_held} phrasing templates held out entirely from training")

    labels = sorted(df["label"].unique())

    # ------------------------------------------------- Module 1: behaviour
    print(f"\n{'-' * 78}\nModule 1 — Behavior Learning Engine (Isolation Forest)\n{'-' * 78}")
    benign_train = train_df[train_df.label == "benign"].text.tolist()
    behavior = BehaviorLearningEngine()
    b_stats = behavior.fit(benign_train, verbose=verbose)

    # Behaviour AUC: can an unsupervised model trained only on benign traffic
    # separate attacks it has never been shown?
    test_scores = behavior.score_batch(test_df.text.tolist())
    y_binary = (test_df.label != "benign").astype(int).values
    behavior_auc = float(roc_auc_score(y_binary, test_scores))
    b_stats["test_auc"] = behavior_auc
    if verbose:
        print(f"[Module 1] Novelty-detection ROC-AUC on unseen attacks: {behavior_auc:.4f}")

    # ------------------------------------------------ Module 3: prediction
    print(f"\n{'-' * 78}\nModule 3 — Threat Prediction Engine (TF-IDF + RF/LogReg ensemble)\n{'-' * 78}")
    prediction = ThreatPredictionEngine()
    p_stats = prediction.fit(train_df.text.tolist(), train_df.label.tolist(), verbose=verbose)

    # --- ML-only metrics (no signature fusion) — the honest number --------
    y_pred_ml = prediction.predict_ml_only(test_df.text.tolist())
    ml_metrics = _metrics(test_df.label.tolist(), y_pred_ml, labels)

    # --- Fused metrics (ML + innate signature bank) ----------------------
    fused = prediction.predict_batch(test_df.text.tolist(), fuse_signatures=True)
    fused_metrics = _metrics(test_df.label.tolist(), fused, labels)

    if verbose:
        print(f"\n[Module 3] ML-only    accuracy {ml_metrics['accuracy']:.4f}  "
              f"macro-F1 {ml_metrics['macro_f1']:.4f}")
        print(f"[Module 3] ML+innate  accuracy {fused_metrics['accuracy']:.4f}  "
              f"macro-F1 {fused_metrics['macro_f1']:.4f}")

    # ------------------------------------------------- Module 5: memory
    print(f"\n{'-' * 78}\nModule 5 — Immune Memory (benign hold-out for rule validation)\n{'-' * 78}")
    memory = ImmuneMemoryEngine()
    holdout = train_df[train_df.label == "benign"].text.tolist()
    memory.seed_holdout(holdout)
    print(f"[Module 5] Seeded {len(memory.benign_holdout):,} benign prompts as the "
          f"false-positive guard for synthesised rules")

    # ---------------------------------------------------------- persistence
    # Models are written BEFORE cross-validation deliberately. CV trains an
    # extra ensemble per fold and is by far the longest phase; if it is
    # interrupted (OOM, timeout, a killed session) the expensive work above
    # must not be lost. CV is a reporting extra, not a prerequisite.
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    paths = {
        "behavior": str(behavior.save()),
        "prediction": str(prediction.save()),
        "memory": str(memory.save()),
    }
    print(f"\n[persist] Models saved to {MODEL_DIR}")
    from .config import MODEL_VERSION, MODEL_VERSION_FILE
    MODEL_VERSION_FILE.write_text(MODEL_VERSION + "\n", encoding="utf-8")

    # --- Cross-validation -------------------------------------------------
    # NOTE ON INTERPRETATION: these folds are *random* within the training
    # split, so phrasing templates appear on both sides of each fold. The
    # resulting score measures in-distribution fit, NOT generalisation to new
    # attack phrasings — it will be far higher than the template-disjoint
    # number above, and only the latter should be quoted as the headline
    # result. CV is reported here because it shows the ensemble is stable
    # across resamples, which is what cross-validation is actually for.
    cv_scores = []
    if cv_folds and cv_folds > 1:
        if verbose:
            print(f"\n[Module 3] {cv_folds}-fold stratified CV (in-distribution — "
                  f"templates leak across folds, so this is an optimistic bound) …")
        skf = StratifiedKFold(n_splits=cv_folds, shuffle=True,
                              random_state=settings.random_seed)
        X = train_df.text.values
        y = train_df.label.values
        for i, (tr, te) in enumerate(skf.split(X, y), 1):
            fold = ThreatPredictionEngine()
            fold.fit(X[tr].tolist(), y[tr].tolist(), verbose=False)
            f1 = f1_score(y[te], fold.predict_ml_only(X[te].tolist()),
                          average="macro", zero_division=0)
            cv_scores.append(float(f1))
            if verbose:
                print(f"   fold {i}/{cv_folds}: macro-F1 {f1:.4f}")
        if verbose:
            print(f"   mean {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}")

    duration = time.perf_counter() - t_start
    report = {
        "trained_at": time.time(),
        "duration_seconds": round(duration, 2),
        "split_protocol": split,
        "dataset": stats if isinstance(stats, dict) else {},
        "dataset_size": len(df),
        "train_size": len(train_df),
        "test_size": len(test_df),
        "class_distribution": df["label"].value_counts().to_dict(),
        "module1_behavior": b_stats,
        "module3_ml_only": ml_metrics,
        "module3_fused": fused_metrics,
        "module3_training": p_stats,
        "cv_macro_f1": cv_scores,
        "cv_mean": float(np.mean(cv_scores)) if cv_scores else None,
        "cv_std": float(np.std(cv_scores)) if cv_scores else None,
        "model_paths": paths,
        "settings": {
            "iforest_n_estimators": settings.iforest_n_estimators,
            "rf_n_estimators": settings.rf_n_estimators,
            "ensemble_weights": settings.ensemble_weights,
            "prediction_threshold": settings.prediction_threshold,
            "random_seed": settings.random_seed,
        },
    }
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORT_DIR / "training_report.json"
    out.write_text(json.dumps(report, indent=2, default=str))

    if verbose:
        print(f"\n{'=' * 78}")
        print(f"Training complete in {duration:.1f}s")
        print(f"   models  -> {MODEL_DIR}")
        print(f"   report  -> {out}")
        print(f"{'=' * 78}\n")
        _print_table(fused_metrics, labels)
    return report


def _print_table(metrics: Dict[str, object], labels) -> None:
    per = metrics["per_class"]
    print(f"{'class':26s} {'precision':>10s} {'recall':>8s} {'f1':>8s} {'support':>8s}")
    print("-" * 64)
    for lbl in labels:
        d = per.get(lbl, {})
        print(f"{lbl:26s} {d.get('precision', 0):10.4f} {d.get('recall', 0):8.4f} "
              f"{d.get('f1-score', 0):8.4f} {int(d.get('support', 0)):8d}")
    print("-" * 64)
    print(f"{'accuracy':26s} {'':10s} {'':8s} {metrics['accuracy']:8.4f}")
    print(f"{'macro avg':26s} {'':10s} {'':8s} {metrics['macro_f1']:8.4f}\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the AstraSec immune system")
    ap.add_argument("--samples", type=int, default=24_000, help="corpus size")
    ap.add_argument("--split", choices=["disjoint", "random"], default="disjoint")
    ap.add_argument("--rebuild", action="store_true", help="regenerate the corpus")
    ap.add_argument("--cv", type=int, default=3, help="cross-validation folds (0 to skip)")
    ap.add_argument("--quick", action="store_true", help="fast smoke run")
    args = ap.parse_args()
    train(n_samples=args.samples, split=args.split, rebuild=args.rebuild,
          cv_folds=args.cv, quick=args.quick)


if __name__ == "__main__":
    main()
