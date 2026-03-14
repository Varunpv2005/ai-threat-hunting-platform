"""
Unit tests for the AnomalyDetector (IsolationForest wrapper).

Run with:  pytest backend/tests/test_anomaly_detector.py -v

These tests are self-contained — they generate their own synthetic data
using the same lightweight helpers from demo_detector.py so they work
without the full project import chain.
"""

import random, uuid
import numpy as np
import pandas as pd
import pytest
from datetime import datetime, timezone, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ─────────────────────────────────────────────────────────────────────────────
# Minimal inline simulator & feature extractor (mirrors demo_detector.py)
# ─────────────────────────────────────────────────────────────────────────────

rng = random.Random(99)
INT_IPS  = [f"10.0.1.{i}" for i in range(10, 60)]
EXT_IPS  = ["203.0.113.42", "185.220.101.15", "89.163.207.56"]
USERS    = ["alice", "bob", "carol", "david"]

def _ts(offset=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=offset)).isoformat()

def _normal():
    etype = rng.choice(["login_success","login_failed","file_access"])
    return {
        "timestamp": _ts(rng.uniform(-3600, 0)),
        "user": rng.choice(USERS),
        "ip_address": rng.choice(INT_IPS),
        "event_type": etype,
        "geo_country": "US",
        "attempt_count": 1,
        "bytes_read": rng.randint(0, 5000),
        "bytes_written": 0,
        "file_size_kb": rng.randint(1, 100),
        "is_sensitive": 0,
        "mfa_used": "totp",
        "label": 0,
    }

def _brute(n=25):
    ip = rng.choice(EXT_IPS)
    u  = rng.choice(USERS)
    evts = []
    for i in range(n):
        evts.append({
            "timestamp": _ts(i * 0.3), "user": u, "ip_address": ip,
            "event_type": "login_failed", "geo_country": "RU",
            "attempt_count": i+1, "bytes_read": 0, "bytes_written": 0,
            "file_size_kb": 0, "is_sensitive": 0, "mfa_used": None, "label": 1,
        })
    return evts

def _exfil(n=12):
    return [{
        "timestamp": _ts(i*2), "user": rng.choice(USERS),
        "ip_address": rng.choice(INT_IPS), "event_type": "file_access",
        "geo_country": "US", "attempt_count": 1,
        "bytes_read": rng.randint(5_000_000, 50_000_000),
        "bytes_written": 0, "file_size_kb": rng.randint(5000, 50000),
        "is_sensitive": 1, "mfa_used": None, "label": 1,
    } for i in range(n)]


def simple_features(events):
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["is_login_failed"]      = (df["event_type"] == "login_failed").astype(int)
    df["is_admin_access"]      = (df["event_type"] == "admin_access").astype(int)
    df["is_file_access"]       = (df["event_type"] == "file_access").astype(int)
    df["is_external_ip"]       = (~df["ip_address"].str.startswith("10.")).astype(int)
    df["is_suspicious_country"]= df["geo_country"].isin({"RU","CN","KP"}).astype(int)
    df["is_sensitive_file"]    = df["is_sensitive"].fillna(0).astype(int)
    df["mfa_absent"]           = df["mfa_used"].isna().astype(int)
    df["log_bytes_read"]       = np.log1p(df["bytes_read"].fillna(0))
    df["log_file_size_kb"]     = np.log1p(df["file_size_kb"].fillna(0))
    df["attempt_count"]        = df["attempt_count"].fillna(1)
    df["is_after_hours"]       = (df["timestamp"].dt.hour < 7).astype(int)
    df["is_weekend"]           = (df["timestamp"].dt.dayofweek >= 5).astype(int)
    df["hour_sin"]             = np.sin(2 * np.pi * df["timestamp"].dt.hour / 24)
    df["hour_cos"]             = np.cos(2 * np.pi * df["timestamp"].dt.hour / 24)
    df["user_time_delta"]      = df.groupby("user")["timestamp"].diff().dt.total_seconds().fillna(999).clip(upper=999)
    df["ip_time_delta"]        = df.groupby("ip_address")["timestamp"].diff().dt.total_seconds().fillna(999).clip(upper=999)
    df["log_user_delta"]       = np.log1p(df["user_time_delta"])
    df["log_ip_delta"]         = np.log1p(df["ip_time_delta"])
    df["user_rapid_fire"]      = (df["user_time_delta"] < 1.0).astype(int)
    df["ip_rapid_fire"]        = (df["ip_time_delta"]   < 1.0).astype(int)

    # Simple per-user/IP aggregates without rolling (for test simplicity)
    df["user_failed_count"]    = df.groupby("user")["is_login_failed"].transform("sum")
    df["ip_failed_count"]      = df.groupby("ip_address")["is_login_failed"].transform("sum")
    df["ip_brute_flag"]        = (df["ip_failed_count"] > 20).astype(int)
    df["user_admin_count"]     = df.groupby("user")["is_admin_access"].transform("sum")
    df["user_sensitive_count"] = df.groupby("user")["is_sensitive_file"].transform("sum")
    df["user_bytes_read"]      = df.groupby("user")["log_bytes_read"].transform("sum")
    df["user_failure_rate"]    = df["user_failed_count"] / df.groupby("user")["is_login_failed"].transform("count").replace(0,1)

    FEAT_COLS = [
        "is_login_failed","is_admin_access","is_file_access","is_external_ip",
        "is_suspicious_country","is_sensitive_file","mfa_absent","log_bytes_read",
        "log_file_size_kb","attempt_count","is_after_hours","is_weekend",
        "hour_sin","hour_cos","log_user_delta","log_ip_delta","user_rapid_fire",
        "ip_rapid_fire","user_failed_count","ip_failed_count","ip_brute_flag",
        "user_admin_count","user_sensitive_count","user_bytes_read","user_failure_rate",
    ]
    X = df[FEAT_COLS].fillna(0).values.astype(np.float32)
    y = df["label"].fillna(0).values.astype(np.int32)
    return X, y, FEAT_COLS


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def trained_model():
    events = [_normal() for _ in range(1500)] + _brute(25) + _exfil(12)
    rng.shuffle(events)
    X, y, feat = simple_features(events)
    X_normal = X[y == 0]
    scaler = StandardScaler().fit(X_normal)
    X_scaled = scaler.transform(X_normal)
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42).fit(X_scaled)
    tr_scores = model.score_samples(X_scaled)
    return model, scaler, feat, float(tr_scores.min()), float(tr_scores.max())


@pytest.fixture(scope="module")
def test_data():
    normal  = [_normal() for _ in range(200)]
    attacks = _brute(25) + _exfil(12)
    return normal, attacks


# ─────────────────────────────────────────────────────────────────────────────
# Tests — model basics
# ─────────────────────────────────────────────────────────────────────────────

def test_model_is_fitted(trained_model):
    model, _, _, _, _ = trained_model
    assert hasattr(model, "estimators_"), "Model not fitted"
    assert len(model.estimators_) == 100


def test_predict_returns_correct_shape(trained_model):
    model, scaler, feat, _, _ = trained_model
    X, _, _ = simple_features([_normal() for _ in range(50)])
    X_s = scaler.transform(X)
    preds = model.predict(X_s)
    assert preds.shape == (50,)
    assert set(preds).issubset({-1, 1})


def test_score_samples_returns_floats(trained_model):
    model, scaler, feat, _, _ = trained_model
    X, _, _ = simple_features([_normal() for _ in range(30)])
    X_s = scaler.transform(X)
    scores = model.score_samples(X_s)
    assert scores.dtype in (np.float32, np.float64)
    assert scores.shape == (30,)


# ─────────────────────────────────────────────────────────────────────────────
# Tests — risk score calibration
# ─────────────────────────────────────────────────────────────────────────────

def to_risk(raw, smin, smax):
    span = max(smax - smin, 1e-9)
    return float(np.clip((1 - (raw - smin) / span) * 100, 0, 100))


def test_risk_scores_bounded(trained_model):
    model, scaler, feat, smin, smax = trained_model
    X, _, _ = simple_features([_normal() for _ in range(100)])
    X_s = scaler.transform(X)
    risks = np.array([to_risk(r, smin, smax) for r in model.score_samples(X_s)])
    assert (risks >= 0).all() and (risks <= 100).all()


def test_attacks_score_higher_than_normal(trained_model):
    model, scaler, _, smin, smax = trained_model

    X_norm, _, _ = simple_features([_normal() for _ in range(200)])
    X_att,  _, _ = simple_features(_brute(25))

    X_norm_s = scaler.transform(X_norm)
    X_att_s  = scaler.transform(X_att)

    risk_normal = np.array([to_risk(r, smin, smax) for r in model.score_samples(X_norm_s)])
    risk_attack = np.array([to_risk(r, smin, smax) for r in model.score_samples(X_att_s)])

    assert risk_attack.mean() > risk_normal.mean(), (
        f"Attack mean ({risk_attack.mean():.1f}) should exceed normal mean ({risk_normal.mean():.1f})"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tests — attack detection
# ─────────────────────────────────────────────────────────────────────────────

def test_brute_force_flagged_anomalous(trained_model):
    model, scaler, _, smin, smax = trained_model
    X, _, _ = simple_features(_brute(30))
    X_s     = scaler.transform(X)
    labels  = model.predict(X_s)
    # Majority of brute-force events should be flagged
    anomaly_rate = (labels == -1).mean()
    assert anomaly_rate > 0.5, f"Only {anomaly_rate:.0%} of brute-force flagged"


def test_exfil_flagged_anomalous(trained_model):
    model, scaler, _, smin, smax = trained_model
    X, _, _ = simple_features(_exfil(15))
    X_s     = scaler.transform(X)
    labels  = model.predict(X_s)
    anomaly_rate = (labels == -1).mean()
    assert anomaly_rate > 0.4, f"Only {anomaly_rate:.0%} of exfil events flagged"


def test_normal_events_mostly_pass(trained_model):
    model, scaler, _, smin, smax = trained_model
    X, _, _ = simple_features([_normal() for _ in range(500)])
    X_s     = scaler.transform(X)
    labels  = model.predict(X_s)
    false_alarm_rate = (labels == -1).mean()
    # With contamination=0.05 we expect at most ~10% false alarms
    assert false_alarm_rate < 0.15, f"False alarm rate too high: {false_alarm_rate:.1%}"


# ─────────────────────────────────────────────────────────────────────────────
# Tests — feature sanity
# ─────────────────────────────────────────────────────────────────────────────

def test_brute_force_features_high(trained_model):
    _, _, feat, _, _ = trained_model
    X, _, _ = simple_features(_brute(30))
    df = pd.DataFrame(X, columns=feat)
    assert df["ip_failed_count"].mean() > 5, "Brute force: ip_failed_count should be elevated"
    assert df["user_rapid_fire"].mean() > 0.5, "Brute force: rapid fire should be common"


def test_exfil_bytes_feature_elevated(trained_model):
    _, _, feat, _, _ = trained_model
    X, _, _ = simple_features(_exfil(15))
    Xn, _, _ = simple_features([_normal() for _ in range(15)])
    df_att  = pd.DataFrame(X,  columns=feat)
    df_norm = pd.DataFrame(Xn, columns=feat)
    assert df_att["log_bytes_read"].mean() > df_norm["log_bytes_read"].mean()


def test_no_nan_in_feature_matrix():
    X, _, _ = simple_features([_normal() for _ in range(100)])
    assert not np.isnan(X).any()
    assert not np.isinf(X).any()
