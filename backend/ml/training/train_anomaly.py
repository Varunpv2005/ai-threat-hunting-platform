"""
Model Training Script — AI Threat Hunting & Incident Response Platform

Orchestrates the full training pipeline:
  1. Generate labelled log data via LogSimulator
  2. Extract features via FeaturePipeline
  3. Train IsolationForest on normal-only data
  4. Evaluate detection quality on a held-out test set
  5. Save the fitted model to data/models/

Usage
-----
    python -m backend.ml.training.train_anomaly
    python -m backend.ml.training.train_anomaly --n-train 20000 --n-test 5000
    python -m backend.ml.training.train_anomaly --contamination 0.08 --model-path data/models/detector_v2.pkl
"""

import argparse
import json
import logging
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)

# ── project imports ──────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from backend.log_simulator.simulator import LogSimulator
from backend.ml.classifier.feature_engineering import FeaturePipeline
from backend.ml.anomaly.isolation_forest import AnomalyDetector

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [TRAIN] %(message)s")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train the IsolationForest anomaly detector")
    p.add_argument("--n-train",      type=int,   default=15_000,  help="Training set size")
    p.add_argument("--n-test",       type=int,   default=4_000,   help="Test set size")
    p.add_argument("--contamination",type=float, default=0.05,    help="Expected anomaly fraction")
    p.add_argument("--n-estimators", type=int,   default=150,     help="Isolation trees")
    p.add_argument("--window",       type=int,   default=5,       help="Feature window (minutes)")
    p.add_argument("--attack-prob",  type=float, default=0.04,    help="Simulator attack probability")
    p.add_argument("--model-path",   default="data/models/anomaly_detector.pkl")
    p.add_argument("--no-save",      action="store_true")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Data generation helpers
# ---------------------------------------------------------------------------

def generate_dataset(
    n: int,
    attack_prob: float,
    label: str = "dataset",
) -> list[dict]:
    logger.info("Generating %d events for %s (attack_prob=%.3f)…", n, label, attack_prob)
    sim = LogSimulator(output="stdout", attack_probability=attack_prob)
    events = sim.generate_batch(n=n, include_attacks=True)
    n_attacks = sum(1 for e in events if e.get("label") == 1)
    logger.info(
        "%s: %d normal  +  %d attack  (%.1f%%)",
        label, n - n_attacks, n_attacks, 100 * n_attacks / max(n, 1),
    )
    return events


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------

def evaluate(
    detector: AnomalyDetector,
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_names: list[str],
) -> dict:
    """
    Compute a suite of binary classification metrics.
    IsolationForest predicts -1 (anomaly) or 1 (normal);
    we map that to 1 (anomaly) or 0 (normal) for sklearn metrics.
    """
    results = detector.predict(X_test)

    y_pred    = np.array([1 if r.is_anomaly  else 0 for r in results])
    y_scores  = np.array([r.anomaly_score / 100.0   for r in results])

    # ── Classification report ─────────────────────────────────────────
    print("\n" + "="*55)
    print("  Classification Report")
    print("="*55)
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"], digits=3))

    # ── Confusion matrix ──────────────────────────────────────────────
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"  Confusion matrix:")
    print(f"    True  Negatives (correctly normal): {tn:>6}")
    print(f"    False Positives (false alarms):     {fp:>6}")
    print(f"    False Negatives (missed attacks):   {fn:>6}")
    print(f"    True  Positives (caught attacks):   {tp:>6}")

    # ── Curve-based metrics ───────────────────────────────────────────
    roc_auc = roc_auc_score(y_test, y_scores)
    avg_prec = average_precision_score(y_test, y_scores)
    print(f"\n  ROC-AUC  : {roc_auc:.4f}")
    print(f"  Avg Prec : {avg_prec:.4f}")
    print("="*55 + "\n")

    # ── Threat level distribution ─────────────────────────────────────
    report = detector.report(results)
    print(report.summary())

    return {
        "roc_auc":    roc_auc,
        "avg_prec":   avg_prec,
        "precision":  tp / max(tp + fp, 1),
        "recall":     tp / max(tp + fn, 1),
        "f1":         2*tp / max(2*tp + fp + fn, 1),
        "fp_rate":    fp / max(fp + tn, 1),
        "fn_rate":    fn / max(fn + tp, 1),
    }


# ---------------------------------------------------------------------------
# Main training pipeline
# ---------------------------------------------------------------------------

def train(args: argparse.Namespace) -> tuple[AnomalyDetector, FeaturePipeline, dict]:
    t0 = time.perf_counter()

    # ── 1. Generate data ──────────────────────────────────────────────
    train_events = generate_dataset(args.n_train, args.attack_prob, label="train")
    test_events  = generate_dataset(args.n_test,  args.attack_prob, label="test")

    # ── 2. Feature extraction ─────────────────────────────────────────
    logger.info("Extracting features…")
    pipeline = FeaturePipeline(window_minutes=args.window, scale=False)

    X_train, y_train, feature_names = pipeline.fit_transform(train_events)
    X_test,  y_test,  _             = pipeline.fit_transform(test_events)

    logger.info(
        "Feature matrix: train=%s  test=%s  features=%d",
        X_train.shape, X_test.shape, len(feature_names),
    )

    # ── 3. Train detector ─────────────────────────────────────────────
    logger.info("Training IsolationForest…")
    detector = AnomalyDetector(
        contamination=args.contamination,
        n_estimators=args.n_estimators,
    )
    detector.fit(X_train, feature_names, normal_only=True, y=y_train)

    # ── 4. Evaluate ───────────────────────────────────────────────────
    logger.info("Evaluating on test set…")
    metrics = evaluate(detector, X_test, y_test, feature_names)

    elapsed = time.perf_counter() - t0
    logger.info("Training complete in %.1f s", elapsed)

    # ── 5. Save ───────────────────────────────────────────────────────
    if not args.no_save:
        Path(args.model_path).parent.mkdir(parents=True, exist_ok=True)
        detector.save(args.model_path)

    return detector, pipeline, metrics


# ---------------------------------------------------------------------------
# Example predictions demo
# ---------------------------------------------------------------------------

def demo_predictions(detector: AnomalyDetector, pipeline: FeaturePipeline) -> None:
    """
    Generate a handful of labelled example events, run them through
    the detector, and pretty-print the results for illustration.
    """
    from backend.log_simulator.generators.attack_scenarios import (
        BruteForceScenario,
        PrivilegeEscalationScenario,
        DataExfiltrationScenario,
    )
    from backend.log_simulator.generators.auth_logs import generate_login_success
    from backend.log_simulator.generators.system_logs import generate_file_access

    scenarios = {
        "normal_login":         [generate_login_success() for _ in range(5)],
        "normal_file_access":   [generate_file_access()   for _ in range(5)],
        "brute_force":          BruteForceScenario().generate()[:10],
        "privilege_escalation": PrivilegeEscalationScenario().generate()[:10],
        "data_exfiltration":    DataExfiltrationScenario().generate()[:10],
    }

    print("\n" + "="*65)
    print("  Example Predictions")
    print("="*65)

    for scenario_name, events in scenarios.items():
        try:
            X = pipeline.transform(events)
            results = detector.predict(X)

            scores = [r.anomaly_score for r in results]
            levels = [r.threat_level  for r in results]
            attacks = list({at for r in results for at in r.attack_types})

            print(f"\n  Scenario : {scenario_name}")
            print(f"  Events   : {len(events)}")
            print(f"  Avg risk : {np.mean(scores):.1f}  |  Max: {max(scores):.1f}")
            print(f"  Levels   : {', '.join(sorted(set(levels)))}")
            if attacks:
                print(f"  Detected : {', '.join(attacks)}")

            # Show top features for the most suspicious event
            worst = max(results, key=lambda r: r.anomaly_score)
            if worst.is_anomaly:
                print(f"  Top features driving worst event (score={worst.anomaly_score:.1f}):")
                for feat, dev in worst.top_features:
                    print(f"    {feat:<38} deviation={dev:.2f}σ")
        except Exception as e:
            print(f"  [{scenario_name}] skipped — {e}")

    print("\n" + "="*65)


if __name__ == "__main__":
    args = parse_args()
    detector, pipeline, metrics = train(args)
    demo_predictions(detector, pipeline)
