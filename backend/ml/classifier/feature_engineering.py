"""
Feature Engineering Pipeline — AI Threat Hunting & Incident Response Platform

Transforms raw JSON log events into structured numerical feature vectors
ready for training and inference by the ML detection models.

Pipeline stages
---------------
1. Load         — Read JSONL log files into a pandas DataFrame
2. Parse        — Normalise timestamps, types, and categorical columns
3. Window       — Aggregate per-user and per-IP features over time windows
4. Encode       — Label-encode categoricals, one-hot rare fields
5. Normalise    — StandardScaler for distance-sensitive models
6. Export       — Return X (features), y (labels), and feature names

Usage
-----
    from backend.ml.classifier.feature_engineering import FeaturePipeline

    pipeline = FeaturePipeline(window_minutes=5)
    X_train, y_train, feature_names = pipeline.fit_transform("data/processed/logs.jsonl")
    X_test = pipeline.transform("data/processed/test_logs.jsonl")
"""

import json
import logging
from pathlib import Path
from typing import Union

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [FEATURES] %(message)s")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EVENT_TYPES = [
    "login_success",
    "login_failed",
    "file_access",
    "admin_access",
    "password_change",
]

SENSITIVE_PATHS = {
    "/etc/passwd", "/etc/shadow", "/home/admin/.ssh/id_rsa",
    "/etc/ssl/private/server.key", "/var/db/users.sqlite",
    "/opt/app/config/secrets.env",
}

SUSPICIOUS_COUNTRIES = {"RU", "CN", "KP", "IR", "SY"}

HIGH_RISK_PROCESSES = {"sudo", "bash", "sh", "python3", "curl", "wget", "nc", "ncat", "nmap"}

INTERNAL_CIDR_PREFIX = "10."


# ---------------------------------------------------------------------------
# Main Pipeline
# ---------------------------------------------------------------------------

class FeaturePipeline:
    """
    Full feature extraction and transformation pipeline.

    Parameters
    ----------
    window_minutes : int
        Rolling time window for aggregating behavioural features.
    scale : bool
        Whether to apply StandardScaler. Set False for tree-based models.
    """

    def __init__(self, window_minutes: int = 5, scale: bool = True):
        self.window_minutes = window_minutes
        self.scale = scale
        self._scaler = StandardScaler()
        self._fitted = False
        self.feature_names_: list[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fit_transform(
        self,
        source: Union[str, Path, list[dict]],
    ) -> tuple[np.ndarray, np.ndarray, list[str]]:
        """
        Load logs, build features, fit the scaler, and return arrays.

        Returns
        -------
        X : np.ndarray, shape (n_events, n_features)
        y : np.ndarray, shape (n_events,)  — 0 normal / 1 attack
        feature_names : list[str]
        """
        df = self._load(source)
        df = self._parse(df)
        df = self._build_features(df)

        feature_cols = self._feature_columns(df)
        self.feature_names_ = feature_cols

        X = df[feature_cols].values.astype(np.float32)
        y = df["label"].values.astype(np.int32)

        if self.scale:
            X = self._scaler.fit_transform(X)

        self._fitted = True

        logger.info(
            "fit_transform: %d events → %d features  (attack=%.1f%%)",
            len(df), len(feature_cols),
            100 * y.mean(),
        )
        return X, y, feature_cols

    def transform(
        self,
        source: Union[str, Path, list[dict]],
    ) -> np.ndarray:
        """Transform new logs using the already-fitted pipeline (inference)."""
        if not self._fitted:
            raise RuntimeError("Pipeline not fitted. Call fit_transform() first.")
        df = self._load(source)
        df = self._parse(df)
        df = self._build_features(df)
        feature_cols = self._feature_columns(df)
        X = df[feature_cols].values.astype(np.float32)
        if self.scale:
            X = self._scaler.transform(X)
        return X

    def feature_importance_frame(self, importances: np.ndarray) -> pd.DataFrame:
        """Return a tidy DataFrame pairing feature names with model importances."""
        return (
            pd.DataFrame({"feature": self.feature_names_, "importance": importances})
            .sort_values("importance", ascending=False)
            .reset_index(drop=True)
        )

    # ------------------------------------------------------------------
    # Stage 1 — Load
    # ------------------------------------------------------------------

    def _load(self, source: Union[str, Path, list[dict]]) -> pd.DataFrame:
        """Accept a JSONL file path or a list of event dicts."""
        if isinstance(source, (str, Path)):
            path = Path(source)
            logger.info("Loading logs from %s", path)
            records = []
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
            df = pd.DataFrame(records)
        elif isinstance(source, list):
            df = pd.DataFrame(source)
        else:
            raise TypeError(f"Unsupported source type: {type(source)}")

        logger.info("Loaded %d raw log events", len(df))
        return df

    # ------------------------------------------------------------------
    # Stage 2 — Parse & Normalise
    # ------------------------------------------------------------------

    def _parse(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        # Timestamps
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        df = df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)

        # Ensure label column exists (inference mode may not have it)
        if "label" not in df.columns:
            df["label"] = 0

        # Normalise optional numeric columns with safe defaults
        for col, default in [
            ("attempt_count",  1),
            ("bytes_read",     0),
            ("bytes_written",  0),
            ("file_size_kb",   0),
            ("login_duration_ms", 0),
        ]:
            df[col] = pd.to_numeric(df.get(col, default), errors="coerce").fillna(default)

        # Normalise optional string columns
        df["geo_country"]   = df.get("geo_country",   pd.Series(["US"] * len(df))).fillna("US")
        df["process_name"]  = df.get("process_name",  pd.Series(["unknown"] * len(df))).fillna("unknown")
        df["file_path"]     = df.get("file_path",     pd.Series([""] * len(df))).fillna("")
        df["failure_reason"]= df.get("failure_reason",pd.Series([""] * len(df))).fillna("")
        df["mfa_used"]      = df.get("mfa_used",      pd.Series([None] * len(df)))

        return df

    # ------------------------------------------------------------------
    # Stage 3 — Feature Construction
    # ------------------------------------------------------------------

    def _build_features(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        # ── A. Event-level binary / categorical features ──────────────
        df = self._event_level_features(df)

        # ── B. Per-user rolling-window aggregates ──────────────────────
        df = self._user_window_features(df)

        # ── C. Per-IP rolling-window aggregates ────────────────────────
        df = self._ip_window_features(df)

        # ── D. Temporal features ───────────────────────────────────────
        df = self._temporal_features(df)

        # ── E. Inter-event timing features ────────────────────────────
        df = self._timing_features(df)

        return df

    # --- A: Event-level features ---

    def _event_level_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Binary and encoded features derived from a single event in isolation.
        """
        # One-hot encode event_type
        for et in EVENT_TYPES:
            df[f"is_{et}"] = (df["event_type"] == et).astype(int)

        # IP origin
        df["is_external_ip"] = (~df["ip_address"].str.startswith(INTERNAL_CIDR_PREFIX)).astype(int)
        df["is_suspicious_ip"] = df["ip_address"].isin(_suspicious_ip_set()).astype(int)

        # Geography
        df["is_suspicious_country"] = df["geo_country"].isin(SUSPICIOUS_COUNTRIES).astype(int)

        # File sensitivity
        df["is_sensitive_file"] = df["file_path"].isin(SENSITIVE_PATHS).astype(int)

        # Process risk
        df["is_high_risk_process"] = df["process_name"].isin(HIGH_RISK_PROCESSES).astype(int)

        # MFA absent (suspicious on sensitive events)
        df["mfa_absent"] = df["mfa_used"].isna().astype(int)

        # Byte volume (log-scaled to reduce skew)
        df["log_bytes_read"]    = np.log1p(df["bytes_read"])
        df["log_bytes_written"] = np.log1p(df["bytes_written"])
        df["log_file_size_kb"]  = np.log1p(df["file_size_kb"])

        # Failed login flag
        df["is_failed_login"] = (df["event_type"] == "login_failed").astype(int)

        return df

    # --- B: Per-user rolling window ---

    def _user_window_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Aggregates per user within a rolling time window.
        Captures behavioral anomalies: too many failures, unusual event mix, etc.
        """
        window = f"{self.window_minutes}min"
        df = df.set_index("timestamp")

        feature_map = {}

        for user, group in df.groupby("user"):
            grp = group.sort_index()

            # Counts of each event type in the window
            feature_map.setdefault("user_login_failed_count", {})[user] = (
                grp["is_failed_login"].rolling(window, min_periods=1).sum()
            )
            feature_map.setdefault("user_login_success_count", {})[user] = (
                grp["is_login_success"].rolling(window, min_periods=1).sum()
                if "is_login_success" in grp else pd.Series(0, index=grp.index)
            )
            feature_map.setdefault("user_admin_access_count", {})[user] = (
                grp["is_admin_access"].rolling(window, min_periods=1).sum()
            )
            feature_map.setdefault("user_sensitive_file_count", {})[user] = (
                grp["is_sensitive_file"].rolling(window, min_periods=1).sum()
            )
            feature_map.setdefault("user_event_count", {})[user] = (
                grp["is_login_failed"].rolling(window, min_periods=1).count()
            )
            # Unique IPs per user in window (insider lateral movement indicator)
            feature_map.setdefault("user_unique_ip_count", {})[user] = (
                grp["is_external_ip"].rolling(window, min_periods=1).sum()
            )
            # Total bytes read in window (exfiltration indicator)
            feature_map.setdefault("user_total_bytes_read", {})[user] = (
                grp["log_bytes_read"].rolling(window, min_periods=1).sum()
            )

        for feat_name, user_series_map in feature_map.items():
            combined = pd.concat(user_series_map.values())
            df[feat_name] = combined.reindex(df.index).fillna(0)

        df = df.reset_index()

        # Derived ratio: failure rate (brute force signal)
        total = df["user_event_count"].replace(0, 1)
        df["user_failure_rate"] = df["user_login_failed_count"] / total

        # Sudden admin spike: more than 3 admin events in window
        df["user_admin_spike"] = (df["user_admin_access_count"] > 3).astype(int)

        return df

    # --- C: Per-IP rolling window ---

    def _ip_window_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Aggregates per source IP. Catches external scanners, botnets,
        and compromised endpoints attacking multiple user accounts.
        """
        window = f"{self.window_minutes}min"
        df = df.set_index("timestamp")

        ip_map = {}

        for ip, group in df.groupby("ip_address"):
            grp = group.sort_index()

            ip_map.setdefault("ip_failed_login_count", {})[ip] = (
                grp["is_failed_login"].rolling(window, min_periods=1).sum()
            )
            ip_map.setdefault("ip_event_count", {})[ip] = (
                grp["is_failed_login"].rolling(window, min_periods=1).count()
            )
            # Unique users targeted from this IP (credential stuffing / spray)
            ip_map.setdefault("ip_unique_user_count", {})[ip] = (
                grp["is_failed_login"].rolling(window, min_periods=1).sum()
            )
            ip_map.setdefault("ip_total_bytes_read", {})[ip] = (
                grp["log_bytes_read"].rolling(window, min_periods=1).sum()
            )

        for feat_name, series_map in ip_map.items():
            combined = pd.concat(series_map.values())
            df[feat_name] = combined.reindex(df.index).fillna(0)

        df = df.reset_index()

        # High-volume IP flag: more than 20 failed logins in window
        df["ip_brute_force_flag"] = (df["ip_failed_login_count"] > 20).astype(int)

        # IP targeting multiple users (password spray)
        df["ip_spray_flag"] = (df["ip_unique_user_count"] > 5).astype(int)

        return df

    # --- D: Temporal features ---

    def _temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calendar and clock features. Attacks often happen outside business hours
        or on weekends when detection is slower.
        """
        ts = df["timestamp"]

        df["hour_of_day"]    = ts.dt.hour                      # 0–23
        df["day_of_week"]    = ts.dt.dayofweek                 # 0=Mon … 6=Sun
        df["is_weekend"]     = (df["day_of_week"] >= 5).astype(int)
        df["is_after_hours"] = ((df["hour_of_day"] < 7) | (df["hour_of_day"] > 20)).astype(int)

        # Sine / cosine encoding preserves cyclical continuity
        df["hour_sin"] = np.sin(2 * np.pi * df["hour_of_day"] / 24)
        df["hour_cos"] = np.cos(2 * np.pi * df["hour_of_day"] / 24)
        df["dow_sin"]  = np.sin(2 * np.pi * df["day_of_week"] / 7)
        df["dow_cos"]  = np.cos(2 * np.pi * df["day_of_week"] / 7)

        return df

    # --- E: Inter-event timing features ---

    def _timing_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Time deltas between consecutive events per user and per IP.
        Very short intervals indicate automation (scanners, brute-forcers).
        """
        df = df.sort_values("timestamp")

        # Per-user inter-event interval
        df["user_time_delta_s"] = (
            df.groupby("user")["timestamp"]
            .diff()
            .dt.total_seconds()
            .fillna(9999)
            .clip(upper=9999)
        )

        # Per-IP inter-event interval
        df["ip_time_delta_s"] = (
            df.groupby("ip_address")["timestamp"]
            .diff()
            .dt.total_seconds()
            .fillna(9999)
            .clip(upper=9999)
        )

        # Automated activity flags: intervals under 1 second
        df["user_rapid_fire"] = (df["user_time_delta_s"] < 1.0).astype(int)
        df["ip_rapid_fire"]   = (df["ip_time_delta_s"]   < 1.0).astype(int)

        # Log-scale the deltas (heavy right-skew)
        df["log_user_time_delta"] = np.log1p(df["user_time_delta_s"])
        df["log_ip_time_delta"]   = np.log1p(df["ip_time_delta_s"])

        return df

    # ------------------------------------------------------------------
    # Feature column selection
    # ------------------------------------------------------------------

    def _feature_columns(self, df: pd.DataFrame) -> list[str]:
        """Return the ordered list of numeric feature columns (excludes meta-columns)."""
        exclude = {
            "event_id", "timestamp", "user", "ip_address", "event_type",
            "hostname", "session_id", "label", "geo_country",
            "process_name", "file_path", "failure_reason",
            "mfa_used", "protocol", "user_agent", "attack_type",
            "geo_city", "change_ticket", "initiated_by",
            "password_strength", "changed_via", "operation",
            "target_resource", "outcome", "privilege_level",
            "bytes_read", "bytes_written", "file_size_kb",
            "login_duration_ms", "attempt_count",
            "user_time_delta_s", "ip_time_delta_s",
            "hour_of_day", "day_of_week",
        }
        return [c for c in df.columns if c not in exclude and pd.api.types.is_numeric_dtype(df[c])]


# ---------------------------------------------------------------------------
# Standalone helpers
# ---------------------------------------------------------------------------

def _suspicious_ip_set() -> set:
    return {
        "185.220.101.34", "162.247.72.199", "23.129.64.131",
        "193.32.127.236", "77.247.181.163", "185.220.101.15",
        "89.163.207.56",  "94.102.49.190",
    }


def load_and_describe(path: Union[str, Path]) -> pd.DataFrame:
    """
    Utility: load a JSONL log file and print a feature summary.
    Useful in Jupyter notebooks for quick EDA.
    """
    pipeline = FeaturePipeline(window_minutes=5, scale=False)
    X, y, names = pipeline.fit_transform(path)
    df_feat = pd.DataFrame(X, columns=names)
    df_feat["label"] = y

    print(f"\n{'='*60}")
    print(f"  Feature matrix: {X.shape[0]:,} rows × {X.shape[1]} features")
    print(f"  Attack events : {y.sum():,}  ({100*y.mean():.1f}%)")
    print(f"  Normal events : {(y==0).sum():,}  ({100*(1-y.mean()):.1f}%)")
    print(f"{'='*60}\n")
    print(df_feat.describe().T[["mean","std","min","max"]].round(3).to_string())
    return df_feat
