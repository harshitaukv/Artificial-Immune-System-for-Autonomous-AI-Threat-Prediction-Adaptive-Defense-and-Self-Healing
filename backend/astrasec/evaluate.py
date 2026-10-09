"""Evaluation harness — produces every figure and table in the project report.

    python -m astrasec.evaluate

Outputs to ``artifacts/reports/evaluation_report.json`` and
``artifacts/figures/*.png``:

  * confusion matrices (ML-only and ML + innate signatures)
  * ROC and precision-recall curves for the behaviour engine
  * per-class precision / recall / F1 bars
  * an ablation study isolating each component's contribution
  * latency benchmarks, broken down per module
  * the red-team battery, including evasive-variant recall
  * a false-positive audit over hard negatives

Every number quoted in the report comes from this file, so the report and the
code cannot drift apart.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Sequence

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt          # noqa: E402
import numpy as np                        # noqa: E402
import pandas as pd                       # noqa: E402
from sklearn.metrics import (              # noqa: E402
    ConfusionMatrixDisplay, accuracy_score, auc, classification_report,
    confusion_matrix, f1_score, precision_recall_curve, roc_curve,
)

from .config import FIGURE_DIR, REPORT_DIR, settings   # noqa: E402
from .data.generator import load_or_build, template_disjoint_split, random_split  # noqa: E402
from .engines.behavior import BehaviorLearningEngine   # noqa: E402
from .engines.prediction import ThreatPredictionEngine  # noqa: E402
from .pipeline import ImmuneSystem                      # noqa: E402
from .schemas import InspectRequest                     # noqa: E402
from .simulate import APPS, BENIGN_CONTROL, run_red_team, simulate_traffic  # noqa: E402

# Figure styling matched to the dashboard's validated palette.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#898781"]
INK = "#0b0b0b"
MUTED = "#898781"
GRID = "#e1e0d9"
SURFACE = "#fcfcfb"

plt.rcParams.update({
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "axes.edgecolor": "#c3c2b7",
    "axes.labelcolor": INK,
    "text.color": INK,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "grid.color": GRID,
    "font.family": "sans-serif",
    "font.size": 9,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.dpi": 150,
})

PRETTY = {
    "benign": "Benign",
    "prompt_injection": "Prompt injection",
    "jailbreak": "Jailbreak",
    "adversarial_obfuscation": "Adversarial /\nobfuscation",
    "data_exfiltration": "Data exfiltration",
    "model_extraction": "Model extraction",
}


def _save(fig, name: str) -> str:
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    path = FIGURE_DIR / f"{name}.png"
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"   figure -> {path.name}")
    return str(path)


# --------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------
def plot_confusion(y_true, y_pred, labels, title: str, name: str) -> str:
    cm = confusion_matrix(y_true, y_pred, labels=labels, normalize="true")
    fig, ax = plt.subplots(figsize=(6.4, 5.4))
    disp = ConfusionMatrixDisplay(cm, display_labels=[PRETTY.get(l, l) for l in labels])
    disp.plot(ax=ax, cmap="Blues", colorbar=False, values_format=".2f")
    ax.set_title(title, fontsize=11, pad=12)
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("True class")
    plt.setp(ax.get_xticklabels(), rotation=38, ha="right", fontsize=8)
    plt.setp(ax.get_yticklabels(), fontsize=8)
    for txt in disp.text_.ravel():
        txt.set_fontsize(8)
    return _save(fig, name)


def plot_behavior_curves(scores: np.ndarray, y: np.ndarray) -> Dict[str, object]:
    fpr, tpr, _ = roc_curve(y, scores)
    roc_auc = auc(fpr, tpr)
    prec, rec, _ = precision_recall_curve(y, scores)
    pr_auc = auc(rec, prec)

    fig, axes = plt.subplots(1, 2, figsize=(10.2, 4.2))
    axes[0].plot(fpr, tpr, color=SERIES[0], lw=2, label=f"ROC (AUC = {roc_auc:.3f})")
    axes[0].plot([0, 1], [0, 1], color=MUTED, lw=1, ls="--", label="Chance")
    axes[0].set_xlabel("False positive rate")
    axes[0].set_ylabel("True positive rate")
    axes[0].set_title("Module 1 — novelty detection ROC", fontsize=10)
    axes[0].legend(frameon=False, fontsize=8)
    axes[0].grid(True, lw=0.5, alpha=0.6)

    baseline = float(y.mean())
    axes[1].plot(rec, prec, color=SERIES[2], lw=2, label=f"PR (AUC = {pr_auc:.3f})")
    axes[1].axhline(baseline, color=MUTED, lw=1, ls="--",
                    label=f"Prevalence ({baseline:.2f})")
    axes[1].set_xlabel("Recall")
    axes[1].set_ylabel("Precision")
    axes[1].set_title("Module 1 — precision / recall", fontsize=10)
    axes[1].legend(frameon=False, fontsize=8)
    axes[1].grid(True, lw=0.5, alpha=0.6)

    path = _save(fig, "module1_behavior_curves")
    return {"roc_auc": float(roc_auc), "pr_auc": float(pr_auc), "figure": path}


def plot_per_class(report: Dict[str, Dict[str, float]], labels: Sequence[str]) -> str:
    metrics = ["precision", "recall", "f1-score"]
    x = np.arange(len(labels))
    width = 0.26
    fig, ax = plt.subplots(figsize=(9.4, 4.2))
    for i, m in enumerate(metrics):
        vals = [report.get(l, {}).get(m, 0.0) for l in labels]
        bars = ax.bar(x + (i - 1) * width, vals, width * 0.9,
                      label=m.replace("-score", ""), color=SERIES[i])
        ax.bar_label(bars, fmt="%.2f", fontsize=7, padding=2, color=MUTED)
    ax.set_xticks(x)
    ax.set_xticklabels([PRETTY.get(l, l) for l in labels], fontsize=8)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score")
    ax.set_title("Module 3 — per-class performance (template-disjoint split)", fontsize=11)
    ax.legend(frameon=False, ncol=3, fontsize=9)
    ax.grid(True, axis="y", lw=0.5, alpha=0.6)
    return _save(fig, "module3_per_class")


def plot_ablation(rows: List[Dict[str, object]]) -> str:
    names = [r["configuration"] for r in rows]
    f1 = [r["macro_f1"] for r in rows]
    acc = [r["accuracy"] for r in rows]
    y = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(8.6, 0.62 * len(names) + 1.8))
    b1 = ax.barh(y - 0.19, acc, 0.36, label="Accuracy", color=SERIES[0])
    b2 = ax.barh(y + 0.19, f1, 0.36, label="Macro F1", color=SERIES[1])
    ax.bar_label(b1, fmt="%.3f", fontsize=7.5, padding=3, color=MUTED)
    ax.bar_label(b2, fmt="%.3f", fontsize=7.5, padding=3, color=MUTED)
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=8.5)
    ax.set_xlim(0, 1.12)
    ax.invert_yaxis()
    ax.set_title("Ablation study — contribution of each component", fontsize=11)
    ax.legend(frameon=False, ncol=2, fontsize=9)
    ax.grid(True, axis="x", lw=0.5, alpha=0.6)
    return _save(fig, "ablation_study")


def plot_latency(per_module: Dict[str, List[float]], totals: List[float]) -> str:
    names = ["Module 1\nBehaviour", "Module 2\nHealth", "Module 3\nPrediction",
             "Module 4\nDefence", "Module 5\nMemory"]
    keys = ["module1_behavior_ms", "module2_health_ms", "module3_prediction_ms",
            "module4_defense_ms", "module5_memory_ms"]
    means = [float(np.mean(per_module[k])) for k in keys]
    p95 = [float(np.percentile(per_module[k], 95)) for k in keys]

    fig, axes = plt.subplots(1, 2, figsize=(10.6, 4.0))
    x = np.arange(len(names))
    b1 = axes[0].bar(x - 0.2, means, 0.38, label="Mean", color=SERIES[0])
    b2 = axes[0].bar(x + 0.2, p95, 0.38, label="p95", color=SERIES[3])
    axes[0].bar_label(b1, fmt="%.1f", fontsize=7, padding=2, color=MUTED)
    axes[0].bar_label(b2, fmt="%.1f", fontsize=7, padding=2, color=MUTED)
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(names, fontsize=8)
    axes[0].set_ylabel("Latency (ms)")
    axes[0].set_title("Per-module latency", fontsize=10)
    axes[0].legend(frameon=False, fontsize=9)
    axes[0].grid(True, axis="y", lw=0.5, alpha=0.6)

    axes[1].hist(totals, bins=36, color=SERIES[0], alpha=0.85, edgecolor=SURFACE)
    axes[1].axvline(float(np.mean(totals)), color=SERIES[1], lw=2,
                    label=f"mean {np.mean(totals):.1f} ms")
    axes[1].axvline(float(np.percentile(totals, 95)), color=SERIES[3], lw=2, ls="--",
                    label=f"p95 {np.percentile(totals, 95):.1f} ms")
    axes[1].set_xlabel("End-to-end latency (ms)")
    axes[1].set_ylabel("Requests")
    axes[1].set_title("End-to-end inspection latency", fontsize=10)
    axes[1].legend(frameon=False, fontsize=9)
    axes[1].grid(True, axis="y", lw=0.5, alpha=0.6)
    return _save(fig, "latency_benchmark")


def plot_threat_mix(summary) -> str:
    dist = {k: v for k, v in summary.threat_distribution.items() if v}
    if not dist:
        return ""
    order = ["prompt_injection", "jailbreak", "adversarial_obfuscation",
             "data_exfiltration", "model_extraction", "benign"]
    keys = [k for k in order if k in dist]
    vals = [dist[k] for k in keys]
    colors = {k: SERIES[i] for i, k in enumerate(order)}
    fig, ax = plt.subplots(figsize=(6.4, 4.4))
    wedges, _ = ax.pie(vals, startangle=90, counterclock=False,
                       colors=[colors[k] for k in keys],
                       wedgeprops={"width": 0.38, "edgecolor": SURFACE, "linewidth": 2})
    total = sum(vals)
    ax.legend(wedges, [f"{PRETTY.get(k, k).replace(chr(10), ' ')} — {v} ({v/total:.0%})"
                       for k, v in zip(keys, vals)],
              loc="center left", bbox_to_anchor=(1.0, 0.5), frameon=False, fontsize=8.5)
    ax.set_title("Simulated traffic composition", fontsize=11)
    return _save(fig, "traffic_composition")


# --------------------------------------------------------------------------
# Ablation
# --------------------------------------------------------------------------
def ablation_study(train_df: pd.DataFrame, test_df: pd.DataFrame,
                   labels: Sequence[str]) -> List[Dict[str, object]]:
    """Isolate the contribution of each architectural choice.

    Each row removes exactly one component, so the delta is attributable.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import make_pipeline
    from astrasec.features import prompt_feature_matrix
    from astrasec.signatures import dominant_threat, scan

    Xtr, ytr = train_df.text.tolist(), train_df.label.tolist()
    Xte, yte = test_df.text.tolist(), test_df.label.tolist()
    rows: List[Dict[str, object]] = []

    def record(name: str, pred: Sequence[str], note: str = "") -> None:
        rows.append({
            "configuration": name,
            "accuracy": float(accuracy_score(yte, pred)),
            "macro_f1": float(f1_score(yte, pred, average="macro", zero_division=0)),
            "note": note,
        })
        print(f"   {name:46s} acc {rows[-1]['accuracy']:.4f}  F1 {rows[-1]['macro_f1']:.4f}")

    # 1. Signatures alone (no learning at all).
    sig_only = []
    for t in Xte:
        hits = scan(t)
        cls = dominant_threat(hits)
        sig_only.append(cls.value if cls else "benign")
    record("Innate signatures only (no ML)", sig_only,
           "Deterministic rules; the baseline the ML must beat.")

    # 2. Word TF-IDF + LogisticRegression.
    lr_word = make_pipeline(
        TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2, max_features=60_000),
        LogisticRegression(max_iter=1500, C=2.0, tol=1e-3, class_weight="balanced"),
    ).fit(Xtr, ytr)
    record("Word TF-IDF + LogisticRegression", lr_word.predict(Xte),
           "Classic text baseline.")

    # 3. Char TF-IDF + LogisticRegression (obfuscation robustness).
    lr_char = make_pipeline(
        TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True,
                        min_df=3, max_features=80_000),
        LogisticRegression(max_iter=1500, C=2.0, tol=1e-3, class_weight="balanced"),
    ).fit(Xtr, ytr)
    record("Char TF-IDF + LogisticRegression", lr_char.predict(Xte),
           "Character n-grams survive leetspeak and typos.")

    # 4. Dense engineered features alone + RandomForest.
    rf_dense = RandomForestClassifier(
        n_estimators=300, class_weight="balanced_subsample",
        random_state=settings.random_seed, n_jobs=-1,
    ).fit(prompt_feature_matrix(Xtr), ytr)
    record("Engineered features only + RandomForest", rf_dense.predict(prompt_feature_matrix(Xte)),
           "No lexical view at all — tests the hand-built signals.")

    # 5. The full ensemble, ML only.
    full = ThreatPredictionEngine()
    full.fit(Xtr, ytr, verbose=False)
    ml_pred = full.predict_ml_only(Xte)
    record("Full ensemble (word + char + dense)", ml_pred,
           "All three views, no signature fusion.")

    # 6. Full ensemble + innate signature fusion — the deployed configuration.
    record("Full ensemble + innate fusion (deployed)",
           full.predict_batch(Xte, fuse_signatures=True),
           "The configuration AstraSec actually runs.")

    return rows


# --------------------------------------------------------------------------
# False-positive audit
# --------------------------------------------------------------------------
def false_positive_audit(system: ImmuneSystem) -> Dict[str, object]:
    """Hard negatives only — prompts engineered to look malicious."""
    results = []
    blocked = 0
    for case_id, prompt in BENIGN_CONTROL:
        r = system.inspect(InspectRequest(
            prompt=prompt, tenant_id=f"fp-{case_id}", app=APPS[0], persist=False))
        fp = r.verdict in ("blocked", "quarantined")
        blocked += int(fp)
        results.append({
            "case_id": case_id,
            "prompt": prompt,
            "predicted": r.prediction.threat_class.value,
            "verdict": r.verdict,
            "confidence": r.prediction.confidence,
            "anomaly_score": r.behavior.anomaly_score,
            "health_score": r.health.health_score,
            "false_positive": fp,
        })
    return {
        "total": len(BENIGN_CONTROL),
        "blocked": blocked,
        "false_positive_rate": round(blocked / len(BENIGN_CONTROL), 4),
        "cases": results,
    }


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def evaluate(n_traffic: int = 400, run_ablation: bool = True) -> Dict[str, object]:
    t0 = time.perf_counter()
    print(f"\n{'=' * 78}\nAstraSec — evaluation suite\n{'=' * 78}")

    df, _ = load_or_build()
    train_df, test_df = template_disjoint_split(df, 0.2, settings.random_seed)
    labels = sorted(df.label.unique())
    print(f"Corpus {len(df):,} | train {len(train_df):,} | test {len(test_df):,} "
          f"(template-disjoint)")

    behavior = BehaviorLearningEngine.load()
    prediction = ThreatPredictionEngine.load()
    system = ImmuneSystem.load()

    report: Dict[str, object] = {
        "generated_at": time.time(),
        "protocol": "template-disjoint (held-out phrasings)",
        "corpus_size": len(df),
        "test_size": len(test_df),
        "labels": labels,
        "figures": {},
    }

    # ---- Module 3 ----------------------------------------------------
    print(f"\n{'-' * 78}\nModule 3 — classification\n{'-' * 78}")
    y_true = test_df.label.tolist()
    ml_pred = prediction.predict_ml_only(test_df.text.tolist())
    fused_pred = prediction.predict_batch(test_df.text.tolist(), fuse_signatures=True)

    for tag, pred in (("ml_only", ml_pred), ("fused", fused_pred)):
        rep = classification_report(y_true, pred, labels=labels,
                                    output_dict=True, zero_division=0)
        report[f"module3_{tag}"] = {
            "accuracy": float(accuracy_score(y_true, pred)),
            "macro_f1": float(f1_score(y_true, pred, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_true, pred, average="weighted", zero_division=0)),
            "per_class": {k: v for k, v in rep.items() if isinstance(v, dict)},
            "confusion_matrix": confusion_matrix(y_true, pred, labels=labels).tolist(),
        }
        print(f"   {tag:9s} accuracy {report[f'module3_{tag}']['accuracy']:.4f}  "
              f"macro-F1 {report[f'module3_{tag}']['macro_f1']:.4f}")

    report["figures"]["confusion_ml_only"] = plot_confusion(
        y_true, ml_pred, labels, "Confusion matrix — ML ensemble only", "confusion_ml_only")
    report["figures"]["confusion_fused"] = plot_confusion(
        y_true, fused_pred, labels,
        "Confusion matrix — ML + innate signatures (deployed)", "confusion_fused")
    report["figures"]["per_class"] = plot_per_class(
        report["module3_fused"]["per_class"], labels)

    # ---- Module 1 ----------------------------------------------------
    print(f"\n{'-' * 78}\nModule 1 — unsupervised novelty detection\n{'-' * 78}")
    scores = behavior.score_batch(test_df.text.tolist())
    y_bin = (test_df.label != "benign").astype(int).values
    curves = plot_behavior_curves(scores, y_bin)
    report["module1_behavior"] = {
        "roc_auc": curves["roc_auc"],
        "pr_auc": curves["pr_auc"],
        "mean_benign_score": float(scores[y_bin == 0].mean()),
        "mean_attack_score": float(scores[y_bin == 1].mean()),
        "flag_rate_benign": float((scores[y_bin == 0] > 0.5).mean()),
        "flag_rate_attack": float((scores[y_bin == 1] > 0.5).mean()),
    }
    report["figures"]["behavior_curves"] = curves["figure"]
    print(f"   ROC-AUC {curves['roc_auc']:.4f}  PR-AUC {curves['pr_auc']:.4f}")
    print(f"   mean anomaly — benign {report['module1_behavior']['mean_benign_score']:.3f}, "
          f"attack {report['module1_behavior']['mean_attack_score']:.3f}")

    # ---- Ablation ----------------------------------------------------
    if run_ablation:
        print(f"\n{'-' * 78}\nAblation study\n{'-' * 78}")
        rows = ablation_study(train_df, test_df, labels)
        report["ablation"] = rows
        report["figures"]["ablation"] = plot_ablation(rows)

    # ---- End-to-end simulation, latency, red team --------------------
    print(f"\n{'-' * 78}\nEnd-to-end pipeline\n{'-' * 78}")
    system.reset()
    sim = simulate_traffic(system, n=n_traffic, seed=21)
    report["simulation"] = sim.__dict__
    print(f"   {sim.requests} requests | {sim.threats} threats | "
          f"{sim.blocked} blocked | {sim.sanitized} sanitised | "
          f"mean {sim.mean_latency_ms:.1f} ms")

    per_module: Dict[str, List[float]] = {}
    totals: List[float] = []
    for inc in system.incidents:
        totals.append(inc.total_latency_ms)
        for k, v in inc.latency_ms.items():
            per_module.setdefault(k, []).append(v)
    if totals:
        report["latency"] = {
            "mean_ms": float(np.mean(totals)),
            "median_ms": float(np.median(totals)),
            "p95_ms": float(np.percentile(totals, 95)),
            "p99_ms": float(np.percentile(totals, 99)),
            "max_ms": float(np.max(totals)),
            "per_module_mean_ms": {k: float(np.mean(v)) for k, v in per_module.items()},
            "per_module_p95_ms": {k: float(np.percentile(v, 95)) for k, v in per_module.items()},
            "throughput_rps": float(1000.0 / np.mean(totals)),
        }
        report["figures"]["latency"] = plot_latency(per_module, totals)
        print(f"   latency mean {report['latency']['mean_ms']:.1f} ms | "
              f"p95 {report['latency']['p95_ms']:.1f} ms | "
              f"~{report['latency']['throughput_rps']:.0f} req/s single-threaded")

    summary = system.summary()
    fig = plot_threat_mix(summary)
    if fig:
        report["figures"]["traffic_composition"] = fig

    print(f"\n{'-' * 78}\nRed-team battery\n{'-' * 78}")
    rt = run_red_team(system)
    report["red_team"] = rt
    print(f"   attacks detected {rt['attacks_detected']}/{rt['attacks_total']} "
          f"({rt['detection_rate']:.1%}) | exact class {rt['exact_class_rate']:.1%}")
    print(f"   false positives  {rt['false_positives']}/{rt['benign_total']} "
          f"({rt['false_positive_rate']:.1%})")
    if rt.get("evasive"):
        e = rt["evasive"]
        print(f"   evasive variants {e['detected']}/{e['total']} detected | "
              f"memory recall {e['memory_recall_rate']:.0%}")

    print(f"\n{'-' * 78}\nFalse-positive audit (hard negatives)\n{'-' * 78}")
    fp = false_positive_audit(system)
    report["false_positive_audit"] = fp
    print(f"   {fp['blocked']}/{fp['total']} hard negatives blocked "
          f"({fp['false_positive_rate']:.1%})")
    for c in fp["cases"]:
        if c["false_positive"]:
            print(f"     FP: {c['case_id']} -> {c['predicted']} :: {c['prompt'][:60]}")

    # ---- Immune memory -----------------------------------------------
    report["immune_memory"] = system.memory.stats()
    report["defense"] = system.defense.stats()
    report["duration_seconds"] = round(time.perf_counter() - t0, 2)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORT_DIR / "evaluation_report.json"
    out.write_text(json.dumps(report, indent=2, default=str))
    print(f"\n{'=' * 78}")
    print(f"Evaluation complete in {report['duration_seconds']:.1f}s")
    print(f"   report  -> {out}")
    print(f"   figures -> {FIGURE_DIR}")
    print(f"{'=' * 78}\n")
    return report


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="Evaluate the AstraSec immune system")
    ap.add_argument("--traffic", type=int, default=400, help="simulated requests")
    ap.add_argument("--no-ablation", action="store_true")
    args = ap.parse_args()
    evaluate(n_traffic=args.traffic, run_ablation=not args.no_ablation)


if __name__ == "__main__":
    main()
