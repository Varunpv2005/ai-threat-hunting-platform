"""
Data Store — AI Threat Hunting & Incident Response Platform

In-memory store that:
  • Holds log events, threat records, and alerts
  • Owns the trained IsolationForest + FeaturePipeline + ThreatClassifier
  • Exposes query helpers used by all API route handlers
  • Bootstraps itself with synthetic baseline data on first import

In production this becomes a thin adapter over Elasticsearch + Redis.
The interface (get_logs, get_threats, get_alerts, ingest_events) stays
identical — only the storage layer changes.
"""

import logging
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.ml.classifier.attack_classifier import ThreatClassifier
from backend.ml.classifier.threat_taxonomy   import ThreatCategory, Severity
from backend.incident_response.rule_engine    import RuleEngine
from backend.incident_response.actions        import ActionType
from backend.api.schemas import (
    LogEvent, ThreatRecord, Alert,
    SimulateAttackRequest, SimulateAttackResponse,
    StatsResponse,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Feature column list (must match what the pipeline produces)
# ─────────────────────────────────────────────────────────────────────────────

FEATURE_COLS = [
    "is_login_failed", "is_login_success", "is_admin_access",
    "is_file_access", "is_password_change",
    "is_external_ip", "is_suspicious_country", "is_suspicious_ip",
    "is_sensitive_file", "is_high_risk_process", "mfa_absent",
    "log_bytes_read", "log_file_size_kb", "attempt_count",
    "user_login_failed_count", "user_login_success_count",
    "user_admin_access_count", "user_sensitive_file_count",
    "user_event_count", "user_unique_ip_count", "user_total_bytes_read",
    "user_failure_rate", "user_admin_spike",
    "ip_failed_login_count", "ip_event_count", "ip_unique_user_count",
    "ip_total_bytes_read", "ip_brute_force_flag", "ip_spray_flag",
    "is_weekend", "is_after_hours", "hour_sin", "hour_cos",
    "log_user_time_delta", "log_ip_time_delta",
    "user_rapid_fire", "ip_rapid_fire",
]

SUSP_IPS  = {"185.220.101.34", "162.247.72.199", "23.129.64.131"}
INT_IPS   = [f"10.0.{r}.{h}" for r in range(0, 5) for h in range(10, 60)]
EXT_IPS   = ["203.0.113.42", "198.51.100.7", "185.220.101.15", "89.163.207.56"]
USERS     = ["alice", "bob", "carol", "david", "eve", "frank", "grace", "henry"]
HOSTNAMES = [f"server-{i:02d}" for i in range(1, 8)] + \
            [f"ws-{u}" for u in USERS]

rng = random.Random(42)


# ─────────────────────────────────────────────────────────────────────────────
# Tiny event generators (self-contained, no external sim import needed)
# ─────────────────────────────────────────────────────────────────────────────

def _ts(offset_s: float = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_s)).isoformat()

def _normal_event(offset_s: float = 0) -> dict:
    etype = rng.choices(
        ["login_success", "login_failed", "file_access", "admin_access", "password_change"],
        weights=[0.40, 0.15, 0.30, 0.05, 0.10]
    )[0]
    return {
        "event_id": str(uuid.uuid4()), "timestamp": _ts(offset_s),
        "user": rng.choice(USERS), "ip_address": rng.choice(INT_IPS),
        "event_type": etype, "geo_country": "US",
        "hostname": rng.choice(HOSTNAMES),
        "attempt_count": 1, "bytes_read": rng.randint(0, 50_000),
        "bytes_written": 0, "file_size_kb": rng.randint(1, 200),
        "is_sensitive": 0, "mfa_used": rng.choice(["totp", "push"]),
        "is_high_risk_proc": 0, "label": 0,
    }

def _attack_events(attack_type: str, source_ip: str, username: str,
                   geo: str, intensity: str) -> list[dict]:
    n_map   = {"low": 10, "medium": 25, "high": 50}
    n       = n_map.get(intensity, 25)
    ext     = source_ip not in set(INT_IPS)
    susp    = geo in {"RU", "CN", "KP", "IR"}

    if attack_type == "brute_force":
        events = [
            {"event_id": str(uuid.uuid4()), "timestamp": _ts(-n*0.4 + i*0.4),
             "user": username, "ip_address": source_ip,
             "event_type": "login_failed", "geo_country": geo,
             "hostname": rng.choice(HOSTNAMES),
             "attempt_count": i+1, "bytes_read": 0, "bytes_written": 0,
             "file_size_kb": 0, "is_sensitive": 0, "mfa_used": None,
             "is_high_risk_proc": 0, "label": 1}
            for i in range(n)
        ]
        events.append({**events[-1], "event_id": str(uuid.uuid4()),
                        "event_type": "login_success", "timestamp": _ts(1)})
        return events

    if attack_type == "privilege_escalation":
        base = {"user": username, "ip_address": source_ip,
                "geo_country": geo, "hostname": rng.choice(HOSTNAMES),
                "mfa_used": None, "label": 1}
        events = [
            {**base, "event_id": str(uuid.uuid4()), "timestamp": _ts(-60),
             "event_type": "login_success", "attempt_count": 1,
             "bytes_read": 100, "bytes_written": 0, "file_size_kb": 1,
             "is_sensitive": 0, "is_high_risk_proc": 0},
        ]
        for i in range(n // 3):
            events.append({**base, "event_id": str(uuid.uuid4()),
                            "timestamp": _ts(-50 + i*3),
                            "event_type": "admin_access", "attempt_count": 1,
                            "bytes_read": 500, "bytes_written": 0, "file_size_kb": 5,
                            "is_sensitive": 0, "is_high_risk_proc": 1})
        for i, path in enumerate(["/etc/shadow", "/.ssh/id_rsa", "/etc/ssl/private"]):
            events.append({**base, "event_id": str(uuid.uuid4()),
                            "timestamp": _ts(-20 + i*5),
                            "event_type": "file_access", "attempt_count": 1,
                            "bytes_read": rng.randint(1000, 50_000), "bytes_written": 0,
                            "file_size_kb": rng.randint(1, 50),
                            "is_sensitive": 1, "is_high_risk_proc": 1})
        return events

    if attack_type == "data_exfiltration":
        return [
            {"event_id": str(uuid.uuid4()), "timestamp": _ts(-n*2 + i*2),
             "user": username, "ip_address": source_ip,
             "event_type": "file_access", "geo_country": geo,
             "hostname": rng.choice(HOSTNAMES),
             "attempt_count": 1,
             "bytes_read": rng.randint(5_000_000, 50_000_000),
             "bytes_written": 0,
             "file_size_kb": rng.randint(5000, 50_000),
             "is_sensitive": 1, "mfa_used": None, "is_high_risk_proc": 1, "label": 1}
            for i in range(n)
        ]

    if attack_type == "password_spray":
        return [
            {"event_id": str(uuid.uuid4()), "timestamp": _ts(-n*3 + i*3),
             "user": USERS[i % len(USERS)], "ip_address": source_ip,
             "event_type": "login_failed", "geo_country": geo,
             "hostname": rng.choice(HOSTNAMES),
             "attempt_count": 1, "bytes_read": 0, "bytes_written": 0,
             "file_size_kb": 0, "is_sensitive": 0, "mfa_used": None,
             "is_high_risk_proc": 0, "label": 1}
            for i in range(n * 2)
        ]

    if attack_type == "suspicious_login":
        return [
            {"event_id": str(uuid.uuid4()), "timestamp": _ts(-i*60),
             "user": username, "ip_address": source_ip,
             "event_type": "login_success", "geo_country": geo,
             "hostname": rng.choice(HOSTNAMES),
             "attempt_count": 1, "bytes_read": 0, "bytes_written": 0,
             "file_size_kb": 0, "is_sensitive": 0, "mfa_used": None,
             "is_high_risk_proc": 0, "label": 1}
            for i in range(5)
        ]

    if attack_type == "automated_scanner":
        return [
            {"event_id": str(uuid.uuid4()), "timestamp": _ts(-n*0.1 + i*0.1),
             "user": "unknown", "ip_address": source_ip,
             "event_type": "login_failed", "geo_country": geo,
             "hostname": rng.choice(HOSTNAMES),
             "attempt_count": i+1, "bytes_read": 0, "bytes_written": 0,
             "file_size_kb": 0, "is_sensitive": 0, "mfa_used": None,
             "is_high_risk_proc": 0, "label": 1}
            for i in range(n)
        ]

    raise ValueError(f"Unknown attack_type: {attack_type!r}")


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(events: list[dict]) -> np.ndarray:
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("timestamp").reset_index(drop=True)

    df["is_login_failed"]      = (df["event_type"] == "login_failed").astype(float)
    df["is_login_success"]     = (df["event_type"] == "login_success").astype(float)
    df["is_admin_access"]      = (df["event_type"] == "admin_access").astype(float)
    df["is_file_access"]       = (df["event_type"] == "file_access").astype(float)
    df["is_password_change"]   = (df["event_type"] == "password_change").astype(float)
    df["is_external_ip"]       = (~df["ip_address"].str.startswith("10.")).astype(float)
    df["is_suspicious_country"]= df["geo_country"].isin({"RU","CN","KP","IR"}).astype(float)
    df["is_suspicious_ip"]     = df["ip_address"].isin(SUSP_IPS).astype(float)
    df["is_sensitive_file"]    = df.get("is_sensitive", pd.Series(0, index=df.index)).fillna(0).astype(float)
    df["is_high_risk_process"] = df.get("is_high_risk_proc", pd.Series(0, index=df.index)).fillna(0).astype(float)
    df["mfa_absent"]           = df["mfa_used"].isna().astype(float)
    df["log_bytes_read"]       = np.log1p(df["bytes_read"].fillna(0))
    df["log_file_size_kb"]     = np.log1p(df["file_size_kb"].fillna(0))
    df["attempt_count"]        = df["attempt_count"].fillna(1).astype(float)

    df["user_login_failed_count"]  = df.groupby("user")["is_login_failed"].transform("sum")
    df["user_login_success_count"] = df.groupby("user")["is_login_success"].transform("sum")
    df["user_admin_access_count"]  = df.groupby("user")["is_admin_access"].transform("sum")
    df["user_sensitive_file_count"]= df.groupby("user")["is_sensitive_file"].transform("sum")
    df["user_event_count"]         = df.groupby("user")["is_login_failed"].transform("count").astype(float)
    df["user_unique_ip_count"]     = df.groupby("user")["ip_address"].transform("nunique").astype(float)
    df["user_total_bytes_read"]    = df.groupby("user")["log_bytes_read"].transform("sum")
    df["user_failure_rate"]        = df["user_login_failed_count"] / df["user_event_count"].replace(0,1)
    df["user_admin_spike"]         = (df["user_admin_access_count"] > 3).astype(float)

    df["ip_failed_login_count"] = df.groupby("ip_address")["is_login_failed"].transform("sum")
    df["ip_event_count"]        = df.groupby("ip_address")["is_login_failed"].transform("count").astype(float)
    df["ip_unique_user_count"]  = df.groupby("ip_address")["user"].transform("nunique").astype(float)
    df["ip_total_bytes_read"]   = df.groupby("ip_address")["log_bytes_read"].transform("sum")
    df["ip_brute_force_flag"]   = (df["ip_failed_login_count"] > 20).astype(float)
    df["ip_spray_flag"]         = (df["ip_unique_user_count"] > 5).astype(float)

    ts = df["timestamp"]
    df["hour_of_day"]   = ts.dt.hour.astype(float)
    df["is_weekend"]    = (ts.dt.dayofweek >= 5).astype(float)
    df["is_after_hours"]= ((ts.dt.hour < 7) | (ts.dt.hour > 20)).astype(float)
    df["hour_sin"]      = np.sin(2 * np.pi * df["hour_of_day"] / 24)
    df["hour_cos"]      = np.cos(2 * np.pi * df["hour_of_day"] / 24)

    df["user_time_delta_s"] = df.groupby("user")["timestamp"].diff().dt.total_seconds().fillna(999).clip(upper=999)
    df["ip_time_delta_s"]   = df.groupby("ip_address")["timestamp"].diff().dt.total_seconds().fillna(999).clip(upper=999)
    df["log_user_time_delta"] = np.log1p(df["user_time_delta_s"])
    df["log_ip_time_delta"]   = np.log1p(df["ip_time_delta_s"])
    df["user_rapid_fire"]     = (df["user_time_delta_s"] < 1.0).astype(float)
    df["ip_rapid_fire"]       = (df["ip_time_delta_s"]   < 1.0).astype(float)

    return df[FEATURE_COLS].fillna(0).values.astype(np.float32)


# ─────────────────────────────────────────────────────────────────────────────
# DataStore
# ─────────────────────────────────────────────────────────────────────────────

class DataStore:
    """
    Central in-memory store for the API.  Single instance shared across
    all route handlers via dependency injection.
    """

    def __init__(self):
        self._logs:    list[dict] = []
        self._threats: list[dict] = []
        self._alerts:  list[dict] = []

        # ML components
        self._if_model:   Optional[IsolationForest] = None
        self._scaler:     Optional[StandardScaler]  = None
        self._score_min:  float = -0.5
        self._score_max:  float =  0.5
        self._classifier: ThreatClassifier = ThreatClassifier(
            anomaly_threshold=30.0, min_rule_confidence=0.25
        )
        self._rule_engine: RuleEngine = RuleEngine(simulate=True)

        self._bootstrapped = False

    # ------------------------------------------------------------------
    # Bootstrap
    # ------------------------------------------------------------------

    def bootstrap(self, n_train: int = 5000) -> None:
        """Generate baseline data and train the IsolationForest."""
        if self._bootstrapped:
            return

        logger.info("Bootstrapping data store with %d training events…", n_train)
        t0 = time.perf_counter()

        # Generate normal training data
        train_events = [_normal_event(offset_s=-rng.uniform(0, 86400))
                        for _ in range(n_train)]
        X_train = extract_features(train_events)

        # Train IsolationForest on normal-only data
        self._scaler = StandardScaler().fit(X_train)
        X_scaled = self._scaler.transform(X_train)
        self._if_model = IsolationForest(
            n_estimators=150, contamination=0.05, random_state=42, n_jobs=-1
        )
        self._if_model.fit(X_scaled)
        tr_scores = self._if_model.score_samples(X_scaled)
        self._score_min = float(tr_scores.min())
        self._score_max = float(tr_scores.max())

        # Seed the store with some realistic baseline logs
        seed_events = [_normal_event(offset_s=-rng.uniform(0, 3600))
                       for _ in range(200)]
        for ev in seed_events:
            self._logs.append(self._enrich_log(ev))

        elapsed = time.perf_counter() - t0
        logger.info("Bootstrap complete in %.1fs  (%d logs seeded)", elapsed, len(seed_events))
        self._bootstrapped = True

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def _anomaly_score(self, X: np.ndarray) -> np.ndarray:
        if self._if_model is None:
            return np.zeros(len(X))
        Xs   = self._scaler.transform(X)
        raw  = self._if_model.score_samples(Xs)
        span = max(self._score_max - self._score_min, 1e-9)
        return np.clip((1 - (raw - self._score_min) / span) * 100, 0, 100)

    # ------------------------------------------------------------------
    # Log operations
    # ------------------------------------------------------------------

    def _enrich_log(self, ev: dict) -> dict:
        return {
            "event_id":   ev.get("event_id", str(uuid.uuid4())),
            "timestamp":  ev.get("timestamp", _ts()),
            "user":       ev.get("user", "unknown"),
            "source_ip":  ev.get("ip_address", "0.0.0.0"),
            "event_type": ev.get("event_type", "unknown"),
            "geo_country":ev.get("geo_country", "US"),
            "hostname":   ev.get("hostname", "unknown"),
            "label":      int(ev.get("label", 0)),
            "bytes_read": int(ev.get("bytes_read", 0)),
            "is_sensitive":int(ev.get("is_sensitive", 0)),
            "mfa_used":   ev.get("mfa_used"),
            "metadata":   {},
        }

    def ingest_events(self, events: list[dict]) -> list[dict]:
        """Ingest raw events, score them, create threats/alerts as needed."""
        enriched = [self._enrich_log(e) for e in events]
        self._logs.extend(enriched)

        if not events:
            return enriched

        # Feature extraction + scoring
        X      = extract_features(events)
        scores = self._anomaly_score(X)

        # Classify + respond
        for i, (ev, score) in enumerate(zip(events, scores)):
            feat_dict = dict(zip(FEATURE_COLS, X[i].tolist()))
            clf_result = self._classifier.classify(float(score), feat_dict)

            if clf_result.is_threat:
                threat = self._make_threat(ev, clf_result)
                self._threats.append(threat)

                # Build rule-engine context
                ctx = {**feat_dict,
                       "event_id":        ev.get("event_id"),
                       "username":        ev.get("user", "unknown"),
                       "source_ip":       ev.get("ip_address", "0.0.0.0"),
                       "hostname":        ev.get("hostname", "unknown"),
                       "geo_country":     ev.get("geo_country", "US"),
                       "threat_category": clf_result.primary_category.value,
                       "anomaly_score":   float(score),
                       "severity":        clf_result.final_severity.value,
                       "category":        clf_result.primary_category.value,
                       "mitre_techniques":clf_result.mitre_techniques}
                self._rule_engine.clear_cooldowns()
                outcome = self._rule_engine.evaluate(ctx)

                alert = self._make_alert(threat, outcome)
                self._alerts.append(alert)

        return enriched

    def _make_threat(self, ev: dict, clf) -> dict:
        return ThreatRecord(
            threat_id=str(uuid.uuid4()),
            timestamp=_ts(),
            event_id=ev.get("event_id", ""),
            source_ip=ev.get("ip_address", "0.0.0.0"),
            username=ev.get("user", "unknown"),
            anomaly_score=clf.anomaly_score,
            threat_category=clf.primary_category.value,
            primary_confidence=clf.primary_confidence,
            severity=clf.final_severity.value,
            mitre_techniques=clf.mitre_techniques,
            rule_matches=[
                {"rule": m.rule_name, "confidence": round(m.confidence, 3),
                 "conditions_met": m.conditions_met}
                for m in clf.all_matches[:3]
            ],
        ).to_dict()

    def _make_alert(self, threat: dict, outcome) -> dict:
        sev = threat["severity"]
        cat = threat["threat_category"]
        titles = {
            "brute_force":          "Brute Force Attack Detected",
            "privilege_escalation": "Privilege Escalation Attempt",
            "data_exfiltration":    "Data Exfiltration Activity",
            "suspicious_login":     "Suspicious Login Activity",
            "password_spray":       "Password Spray Attack",
            "automated_scanner":    "Automated Scanner Detected",
            "unknown":              "Anomalous Activity Detected",
        }
        return Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=_ts(),
            threat_id=threat["threat_id"],
            severity=sev,
            title=titles.get(cat, "Security Alert"),
            description=(
                f"{cat.replace('_',' ').title()} detected from "
                f"{threat['source_ip']} targeting {threat['username']}. "
                f"Anomaly score: {threat['anomaly_score']:.1f}. "
                f"Confidence: {threat['primary_confidence']:.0%}."
            ),
            source_ip=threat["source_ip"],
            username=threat["username"],
            category=cat,
            actions_taken=outcome.actions_taken,
            action_results=[r.to_dict() for r in outcome.action_results[:5]],
            status="open",
        ).to_dict()

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_logs(
        self,
        page:       int  = 1,
        limit:      int  = 50,
        event_type: Optional[str] = None,
        username:   Optional[str] = None,
        source_ip:  Optional[str] = None,
        label:      Optional[int] = None,
        since:      Optional[str] = None,
    ) -> tuple[list[dict], int]:
        rows = self._logs
        if event_type: rows = [r for r in rows if r["event_type"] == event_type]
        if username:   rows = [r for r in rows if r["user"] == username]
        if source_ip:  rows = [r for r in rows if r["source_ip"] == source_ip]
        if label is not None: rows = [r for r in rows if r["label"] == label]
        if since:      rows = [r for r in rows if r["timestamp"] >= since]
        rows = sorted(rows, key=lambda r: r["timestamp"], reverse=True)
        total = len(rows)
        start = (page - 1) * limit
        return rows[start: start + limit], total

    def get_threats(
        self,
        page:     int  = 1,
        limit:    int  = 50,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        since:    Optional[str] = None,
    ) -> tuple[list[dict], int]:
        rows = self._threats
        if severity: rows = [r for r in rows if r["severity"] == severity.upper()]
        if category: rows = [r for r in rows if r["threat_category"] == category]
        if since:    rows = [r for r in rows if r["timestamp"] >= since]
        rows = sorted(rows, key=lambda r: r["anomaly_score"], reverse=True)
        total = len(rows)
        start = (page - 1) * limit
        return rows[start: start + limit], total

    def get_alerts(
        self,
        page:     int  = 1,
        limit:    int  = 50,
        severity: Optional[str] = None,
        status:   Optional[str] = None,
        category: Optional[str] = None,
    ) -> tuple[list[dict], int]:
        rows = self._alerts
        if severity: rows = [r for r in rows if r["severity"] == severity.upper()]
        if status:   rows = [r for r in rows if r["status"] == status]
        if category: rows = [r for r in rows if r["category"] == category]
        rows = sorted(rows, key=lambda r: r["timestamp"], reverse=True)
        total = len(rows)
        start = (page - 1) * limit
        return rows[start: start + limit], total

    def acknowledge_alert(self, alert_id: str, by: str = "analyst") -> Optional[dict]:
        for a in self._alerts:
            if a["alert_id"] == alert_id:
                a["status"] = "acknowledged"
                a["acknowledged_by"] = by
                return a
        return None

    def resolve_alert(self, alert_id: str) -> Optional[dict]:
        for a in self._alerts:
            if a["alert_id"] == alert_id:
                a["status"] = "resolved"
                a["resolved_at"] = _ts()
                return a
        return None

    def stats(self) -> dict:
        from collections import Counter
        sev_counts = Counter(t["severity"] for t in self._threats)
        cat_counts = Counter(t["threat_category"] for t in self._threats)
        alert_sev  = Counter(a["severity"] for a in self._alerts)
        alert_stat = Counter(a["status"] for a in self._alerts)
        ip_counts  = Counter(t["source_ip"] for t in self._threats)
        usr_counts = Counter(t["username"] for t in self._threats)

        total_logs = len(self._logs)
        return StatsResponse(
            total_logs=total_logs,
            total_threats=len(self._threats),
            total_alerts=len(self._alerts),
            open_alerts=alert_stat.get("open", 0),
            critical_count=sev_counts.get("CRITICAL", 0),
            high_count=sev_counts.get("HIGH", 0),
            threats_by_category=dict(cat_counts),
            alerts_by_severity=dict(alert_sev),
            top_source_ips=[{"ip": ip, "count": c}
                            for ip, c in ip_counts.most_common(5)],
            top_targeted_users=[{"user": u, "count": c}
                                 for u, c in usr_counts.most_common(5)],
            detection_rate=len(self._threats) / max(total_logs, 1),
            timestamp=_ts(),
        ).to_dict()

    # ------------------------------------------------------------------
    # Simulate attack (POST /simulate_attack)
    # ------------------------------------------------------------------

    def simulate_attack(self, req: SimulateAttackRequest) -> SimulateAttackResponse:
        sim_id = str(uuid.uuid4())[:8].upper()

        # Resolve defaults
        geo_map = {
            "brute_force": "RU", "password_spray": "CN",
            "suspicious_login": "KP", "privilege_escalation": "US",
            "data_exfiltration": "US", "automated_scanner": "US",
        }
        source_ip  = req.source_ip  or rng.choice(EXT_IPS)
        username   = req.username   or rng.choice(USERS)
        geo        = req.geo_country or geo_map.get(req.attack_type, "US")

        # Generate attack events
        events = _attack_events(req.attack_type, source_ip, username, geo, req.intensity)

        # Score with IsolationForest
        X      = extract_features(events)
        scores = self._anomaly_score(X)
        max_score = float(scores.max())
        worst_idx = int(scores.argmax())

        # Aggregate features across ALL attack events (column-wise max) so the
        # classifier sees the full behavioural picture, not just one event.
        feat_agg   = np.max(X, axis=0)
        feat_dict  = dict(zip(FEATURE_COLS, feat_agg.tolist()))
        clf_result = self._classifier.classify(max_score, feat_dict)

        # Run rule engine (skip real actions on dry_run)
        ctx = {**feat_dict,
               "event_id":        events[worst_idx].get("event_id"),
               "username":        username,
               "source_ip":       source_ip,
               "hostname":        events[worst_idx].get("hostname", "server-01"),
               "geo_country":     geo,
               "threat_category": clf_result.primary_category.value,
               "anomaly_score":   max_score,
               "severity":        clf_result.final_severity.value,
               "category":        clf_result.primary_category.value,
               "mitre_techniques":clf_result.mitre_techniques}

        engine = RuleEngine(simulate=True)   # always simulate for /simulate_attack
        engine.clear_cooldowns()
        outcome = engine.evaluate(ctx)

        # Persist unless dry_run
        if not req.dry_run:
            self.ingest_events(events)

        rules_fired = [e.rule_name for e in outcome.evaluations if e.fired]

        return SimulateAttackResponse(
            simulation_id=sim_id,
            attack_type=req.attack_type,
            events_generated=len(events),
            anomaly_score=round(max_score, 2),
            threat_detected=clf_result.is_threat,
            threat_category=clf_result.primary_category.value,
            severity=clf_result.final_severity.value,
            confidence=round(clf_result.primary_confidence, 3),
            mitre_techniques=clf_result.mitre_techniques,
            actions_triggered=outcome.actions_taken,
            action_results=[r.to_dict() for r in outcome.action_results[:6]],
            rules_fired=rules_fired,
            events_sample=[self._enrich_log(e) for e in events[:3]],
            timestamp=_ts(),
        )


# Global singleton — imported by routes
store = DataStore()
