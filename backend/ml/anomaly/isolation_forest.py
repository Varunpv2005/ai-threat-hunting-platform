"""
Anomaly Detector — AI Threat Hunting & Incident Response Platform

Wraps scikit-learn's IsolationForest with:
  - Per-feature contamination-aware scoring
  - Calibrated risk scores in [0, 100]
  - Threat classification into named attack categories
  - Explainability: top contributing features per prediction
  - Persistence: save / load trained models

Design rationale
----------------
IsolationForest is trained exclusively on NORMAL behaviour logs.
It learns the "shape" of normal by randomly partitioning the feature
space and measuring how many splits are needed to isolate each point.
Normal points cluster together → hard to isolate → many splits → low score.
Anomalous points sit alone → isolated quickly → few splits → high score.

No labelled attack data is needed for training. This is the key advantage
for a SOC: zero-day attacks and novel techniques get caught because they
are *different from normal*, regardless of whether they match a known signature.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [DETECTOR] %(message)s")


# ---------------------------------------------------------------------------
# Threat category thresholds (risk score → label)
# ---------------------------------------------------------------------------

THREAT_LEVELS = [
    (85, "CRITICAL",  "Immediate automated response required"),
    (65, "HIGH",      "Analyst review within 15 minutes"),
    (45, "MEDIUM",    "Review within 1 hour"),
    (25, "LOW",       "Log and monitor"),
    (0,  "NORMAL",    "Within expected behaviour baseline"),
]

# Named attack patterns and the features that primarily drive them
ATTACK_SIGNATURES: dict[str, list[str]] = {
    "brute_force": [
        "user_login_failed_count", "ip_failed_login_count",
        "user_failure_rate", "ip_brute_force_flag",
        "ip_rapid_fire", "user_rapid_fire",
    ],
    "password_spray": [
        "ip_unique_user_count", "ip_spray_flag",
        "ip_event_count", "is_external_ip",
    ],
    "privilege_escalation": [
        "user_admin_access_count", "user_admin_spike",
        "is_admin_access", "is_high_risk_process", "mfa_absent",
    ],
    "data_exfiltration": [
        "user_total_bytes_read", "ip_total_bytes_read",
        "is_sensitive_file", "user_sensitive_file_count",
        "log_bytes_read", "log_file_size_kb",
    ],
    "off_hours_intrusion": [
        "is_after_hours", "is_weekend",
        "is_external_ip", "is_suspicious_country",
    ],
    "automated_scanner": [
        "ip_rapid_fire", "user_rapid_fire",
        "log_ip_time_delta", "log_user_time_delta",
        "ip_event_count",
    ],
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """Prediction output for a single event."""
    event_index:    int
    raw_score:      float          # IsolationForest score_samples output  (higher = more normal)
    anomaly_score:  float          # Inverted, normalised to [0, 100]       (higher = more suspicious)
    is_anomaly:     bool
    threat_level:   str            # NORMAL / LOW / MEDIUM / HIGH / CRITICAL
    threat_message: str
    attack_types:   list[str]      # Matched attack pattern names
    top_features:   list[tuple[str, float]]   # (feature_name, deviation_from_mean)
    raw_if_label:   int            # sklearn raw: -1 = anomaly, 1 = normal


@dataclass
class DetectionReport:
    """Aggregate report over a batch of predictions."""
    total_events:    int
    anomaly_count:   int
    critical_count:  int
    high_count:      int
    medium_count:    int
    low_count:       int
    normal_count:    int
    anomaly_rate:    float
    attack_type_counts: dict[str, int] = field(default_factory=dict)
    results:         list[DetectionResult] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"{'='*55}",
            f"  Detection Report  —  {self.total_events:,} events analysed",
            f"{'='*55}",
            f"  CRITICAL : {self.critical_count:>6}",
            f"  HIGH     : {self.high_count:>6}",
            f"  MEDIUM   : {self.medium_count:>6}",
            f"  LOW      : {self.low_count:>6}",
            f"  NORMAL   : {self.normal_count:>6}",
            f"  Anomaly rate : {self.anomaly_rate*100:.1f}%",
            f"{'─'*55}",
        ]
        if self.attack_type_counts:
            lines.append("  Attack type breakdown:")
            for atype, cnt in sorted(self.attack_type_counts.items(), key=lambda x: -x[1]):
                lines.append(f"    {atype:<30} {cnt:>5}")
        lines.append("="*55)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main detector class
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    IsolationForest-based anomaly detector for cybersecurity logs.

    Parameters
    ----------
    contamination : float
        Expected fraction of anomalies in the training data.
        Set this to the approximate attack rate in your log stream.
        IsolationForest uses this to calibrate its decision threshold.
    n_estimators : int
        Number of isolation trees. More trees = more stable scores,
        diminishing returns above 200.
    max_samples : int | "auto"
        Samples drawn per tree. "auto" uses min(256, n_samples).
        Smaller values speed up training; larger values improve accuracy.
    random_state : int
        Reproducibility seed.
    n_top_features : int
        Number of top anomalous features to include in each result.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators:  int   = 150,
        max_samples = "auto",
        random_state:  int   = 42,
        n_top_features: int  = 5,
    ):
        self.contamination  = contamination
        self.n_estimators   = n_estimators
        self.max_samples    = max_samples
        self.random_state   = random_state
        self.n_top_features = n_top_features

        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._feature_names: list[str] = []
        self._train_mean: Optional[np.ndarray] = None
        self._train_std:  Optional[np.ndarray] = None
        self._score_min:  float = -0.5
        self._score_max:  float = 0.5
        self._fitted = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(
        self,
        X: np.ndarray,
        feature_names: list[str],
        normal_only: bool = True,
        y: Optional[np.ndarray] = None,
    ) -> "AnomalyDetector":
        """
        Train the IsolationForest on (ideally) normal-behaviour data.

        Parameters
        ----------
        X : np.ndarray, shape (n_samples, n_features)
            Feature matrix from FeaturePipeline.
        feature_names : list[str]
            Column names matching X's columns.
        normal_only : bool
            If True and y is provided, train only on rows where y == 0.
            This gives the model the cleanest possible baseline.
        y : np.ndarray, optional
            Ground-truth labels. Used only when normal_only=True.
        """
        self._feature_names = list(feature_names)

        # Optionally restrict training to normal events only
        X_train = X
        if normal_only and y is not None:
            normal_mask = (y == 0)
            X_train = X[normal_mask]
            logger.info(
                "Training on %d normal events (%.1f%% of %d total)",
                X_train.shape[0], 100 * normal_mask.mean(), len(X),
            )

        # Scale features
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X_train)

        # Memorise per-feature statistics for explainability
        self._train_mean = X_scaled.mean(axis=0)
        self._train_std  = X_scaled.std(axis=0) + 1e-8

        # Fit Isolation Forest
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)

        # Calibrate score range from the training distribution
        train_scores = self._model.score_samples(X_scaled)
        self._score_min = float(train_scores.min())
        self._score_max = float(train_scores.max())

        self._fitted = True
        logger.info(
            "IsolationForest fitted — %d trees, %d features, contamination=%.3f",
            self.n_estimators, X_train.shape[1], self.contamination,
        )
        return self

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, X: np.ndarray) -> list[DetectionResult]:
        """
        Score a feature matrix and return one DetectionResult per row.

        The conversion from raw IF score → risk score [0,100]:
          1. raw_score: score_samples output (higher = more normal in sklearn)
          2. inverted:  multiply by -1 so higher = more anomalous
          3. normalised: min-max scale using training-set min/max → [0, 1]
          4. risk_score: multiply by 100 and clip to [0, 100]
        """
        self._assert_fitted()
        X_scaled = self._scaler.transform(X)

        raw_scores  = self._model.score_samples(X_scaled)     # higher = more normal
        if_labels   = self._model.predict(X_scaled)            # -1 anomaly, 1 normal

        results = []
        for i, (raw, label) in enumerate(zip(raw_scores, if_labels)):
            risk = self._calibrate_score(float(raw))
            threat_level, threat_msg = self._classify_threat(risk)
            attack_types = self._identify_attack_types(X_scaled[i])
            top_features = self._top_anomalous_features(X_scaled[i])

            results.append(DetectionResult(
                event_index=i,
                raw_score=float(raw),
                anomaly_score=risk,
                is_anomaly=(label == -1),
                threat_level=threat_level,
                threat_message=threat_msg,
                attack_types=attack_types,
                top_features=top_features,
                raw_if_label=int(label),
            ))

        return results

    def predict_single(self, x: np.ndarray) -> DetectionResult:
        """Convenience wrapper for a single feature vector (1-D array)."""
        return self.predict(x.reshape(1, -1))[0]

    def predict_dataframe(self, X: np.ndarray) -> pd.DataFrame:
        """Return predictions as a tidy pandas DataFrame."""
        results = self.predict(X)
        return pd.DataFrame([
            {
                "event_index":  r.event_index,
                "anomaly_score": r.anomaly_score,
                "is_anomaly":   r.is_anomaly,
                "threat_level": r.threat_level,
                "attack_types": ", ".join(r.attack_types) if r.attack_types else "—",
                "top_features": "; ".join(f"{n}={v:.2f}" for n, v in r.top_features),
            }
            for r in results
        ])

    def score_stream(
        self,
        events: list[dict],
        feature_pipeline,
        threshold: float = 45.0,
    ) -> list[DetectionResult]:
        """
        End-to-end convenience: accepts raw event dicts, runs feature
        extraction, and returns only results above the threat threshold.

        Parameters
        ----------
        events : list[dict]
            Raw log event dicts (same format as LogSimulator output).
        feature_pipeline : FeaturePipeline
            Already-fitted pipeline from feature_engineering.py.
        threshold : float
            Minimum anomaly_score to include in the returned list.
        """
        X = feature_pipeline.transform(events)
        all_results = self.predict(X)
        return [r for r in all_results if r.anomaly_score >= threshold]

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def report(self, results: list[DetectionResult]) -> DetectionReport:
        """Aggregate a list of results into a summary DetectionReport."""
        level_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NORMAL": 0}
        attack_type_counts: dict[str, int] = {}

        for r in results:
            level_counts[r.threat_level] = level_counts.get(r.threat_level, 0) + 1
            for atype in r.attack_types:
                attack_type_counts[atype] = attack_type_counts.get(atype, 0) + 1

        n_anomalies = sum(1 for r in results if r.is_anomaly)

        return DetectionReport(
            total_events=len(results),
            anomaly_count=n_anomalies,
            critical_count=level_counts["CRITICAL"],
            high_count=level_counts["HIGH"],
            medium_count=level_counts["MEDIUM"],
            low_count=level_counts["LOW"],
            normal_count=level_counts["NORMAL"],
            anomaly_rate=n_anomalies / max(len(results), 1),
            attack_type_counts=attack_type_counts,
            results=results,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Serialise the fitted model and scaler to disk."""
        self._assert_fitted()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "model":         self._model,
            "scaler":        self._scaler,
            "feature_names": self._feature_names,
            "train_mean":    self._train_mean,
            "train_std":     self._train_std,
            "score_min":     self._score_min,
            "score_max":     self._score_max,
            "contamination": self.contamination,
            "n_estimators":  self.n_estimators,
        }
        joblib.dump(payload, path)
        logger.info("Model saved → %s", path)

    @classmethod
    def load(cls, path: str | Path) -> "AnomalyDetector":
        """Load a previously saved detector from disk."""
        payload = joblib.load(path)
        detector = cls(
            contamination=payload["contamination"],
            n_estimators=payload["n_estimators"],
        )
        detector._model         = payload["model"]
        detector._scaler        = payload["scaler"]
        detector._feature_names = payload["feature_names"]
        detector._train_mean    = payload["train_mean"]
        detector._train_std     = payload["train_std"]
        detector._score_min     = payload["score_min"]
        detector._score_max     = payload["score_max"]
        detector._fitted        = True
        logger.info("Model loaded ← %s  (%d features)", path, len(detector._feature_names))
        return detector

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _calibrate_score(self, raw: float) -> float:
        """
        Convert sklearn's score_samples output to a 0–100 risk score.
        sklearn returns higher values for normal points, lower for anomalies.
        We invert and normalise so that 100 = maximally anomalous.
        """
        span = self._score_max - self._score_min
        if span < 1e-9:
            return 0.0
        normalised = (raw - self._score_min) / span          # 0=most anomalous, 1=most normal
        risk = (1.0 - normalised) * 100.0                     # invert → 100=most anomalous
        return float(np.clip(risk, 0.0, 100.0))

    def _classify_threat(self, risk: float) -> tuple[str, str]:
        for threshold, level, message in THREAT_LEVELS:
            if risk >= threshold:
                return level, message
        return "NORMAL", "Within expected behaviour baseline"

    def _identify_attack_types(self, x_scaled: np.ndarray) -> list[str]:
        """
        Match the event's feature deviations against known attack signatures.
        A signature fires when at least 2 of its key features deviate
        more than 2 standard deviations from the training mean.
        """
        matched = []
        feature_index = {name: i for i, name in enumerate(self._feature_names)}

        for attack_type, sig_features in ATTACK_SIGNATURES.items():
            hits = 0
            for feat in sig_features:
                idx = feature_index.get(feat)
                if idx is None:
                    continue
                deviation = abs(x_scaled[idx] - self._train_mean[idx]) / self._train_std[idx]
                if deviation > 2.0:
                    hits += 1
            if hits >= 2:
                matched.append(attack_type)

        return matched

    def _top_anomalous_features(self, x_scaled: np.ndarray) -> list[tuple[str, float]]:
        """
        Return the N features with the highest standardised deviation from
        the training mean. These are the "reasons" the model flagged the event.
        """
        deviations = np.abs(x_scaled - self._train_mean) / self._train_std
        top_indices = np.argsort(deviations)[::-1][: self.n_top_features]
        return [
            (self._feature_names[i], float(deviations[i]))
            for i in top_indices
            if i < len(self._feature_names)
        ]

    def _assert_fitted(self) -> None:
        if not self._fitted:
            raise RuntimeError(
                "Detector not fitted. Call fit() before predict()."
            )
