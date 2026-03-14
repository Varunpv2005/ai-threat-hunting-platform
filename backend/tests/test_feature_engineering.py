"""
Unit tests for the feature engineering pipeline.

Run with:  pytest backend/tests/test_feature_engineering.py -v
"""

import pytest
import numpy as np
import pandas as pd
from backend.ml.classifier.feature_engineering import FeaturePipeline
from backend.log_simulator import LogSimulator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sample_events() -> list[dict]:
    """Generate a labeled batch via the simulator."""
    sim = LogSimulator(output="stdout", attack_probability=0.3)
    return sim.generate_batch(n=500, include_attacks=True)


@pytest.fixture(scope="module")
def pipeline_output(sample_events):
    pipeline = FeaturePipeline(window_minutes=5, scale=False)
    X, y, names = pipeline.fit_transform(sample_events)
    return X, y, names, pipeline


# ---------------------------------------------------------------------------
# Shape and type checks
# ---------------------------------------------------------------------------

def test_output_shapes(pipeline_output):
    X, y, names, _ = pipeline_output
    assert X.ndim == 2
    assert y.ndim == 1
    assert X.shape[0] == y.shape[0]
    assert X.shape[1] == len(names)


def test_labels_are_binary(pipeline_output):
    _, y, _, _ = pipeline_output
    assert set(np.unique(y)).issubset({0, 1})


def test_no_nan_in_features(pipeline_output):
    X, _, _, _ = pipeline_output
    assert not np.isnan(X).any(), "Feature matrix contains NaN values"


def test_no_inf_in_features(pipeline_output):
    X, _, _, _ = pipeline_output
    assert not np.isinf(X).any(), "Feature matrix contains Inf values"


# ---------------------------------------------------------------------------
# Feature presence checks
# ---------------------------------------------------------------------------

REQUIRED_FEATURES = [
    "is_login_failed",
    "is_external_ip",
    "is_sensitive_file",
    "user_login_failed_count",
    "user_failure_rate",
    "ip_failed_login_count",
    "ip_brute_force_flag",
    "ip_spray_flag",
    "is_after_hours",
    "is_weekend",
    "log_user_time_delta",
    "log_ip_time_delta",
    "user_rapid_fire",
    "ip_rapid_fire",
    "hour_sin",
    "hour_cos",
]

def test_required_features_present(pipeline_output):
    _, _, names, _ = pipeline_output
    for feat in REQUIRED_FEATURES:
        assert feat in names, f"Missing required feature: {feat}"


# ---------------------------------------------------------------------------
# Value sanity checks
# ---------------------------------------------------------------------------

def test_binary_features_are_0_or_1(pipeline_output):
    X, _, names, _ = pipeline_output
    df = pd.DataFrame(X, columns=names)
    binary_cols = [
        "is_login_failed", "is_external_ip", "is_sensitive_file",
        "is_after_hours", "is_weekend", "ip_brute_force_flag",
        "ip_spray_flag", "user_admin_spike", "user_rapid_fire", "ip_rapid_fire",
    ]
    for col in binary_cols:
        if col in names:
            vals = df[col].unique()
            assert set(vals).issubset({0.0, 1.0}), f"{col} has non-binary values: {vals}"


def test_failure_rate_bounded(pipeline_output):
    X, _, names, _ = pipeline_output
    df = pd.DataFrame(X, columns=names)
    assert df["user_failure_rate"].between(0, 1).all(), "user_failure_rate out of [0, 1]"


def test_log_deltas_non_negative(pipeline_output):
    X, _, names, _ = pipeline_output
    df = pd.DataFrame(X, columns=names)
    for col in ["log_user_time_delta", "log_ip_time_delta"]:
        assert (df[col] >= 0).all(), f"{col} contains negative values"


def test_hour_encoding_range(pipeline_output):
    X, _, names, _ = pipeline_output
    df = pd.DataFrame(X, columns=names)
    for col in ["hour_sin", "hour_cos", "dow_sin", "dow_cos"]:
        assert df[col].between(-1, 1).all(), f"{col} outside [-1, 1]"


# ---------------------------------------------------------------------------
# Attack vs normal separation
# ---------------------------------------------------------------------------

def test_attack_events_have_higher_failure_count(pipeline_output):
    X, y, names, _ = pipeline_output
    df = pd.DataFrame(X, columns=names)
    df["label"] = y
    normal_mean  = df[df.label == 0]["user_login_failed_count"].mean()
    attack_mean  = df[df.label == 1]["user_login_failed_count"].mean()
    assert attack_mean >= normal_mean, (
        f"Expected attack mean ({attack_mean:.2f}) >= normal mean ({normal_mean:.2f})"
    )


def test_attack_events_have_higher_ip_failure_count(pipeline_output):
    X, y, names, _ = pipeline_output
    df = pd.DataFrame(X, columns=names)
    df["label"] = y
    normal_mean = df[df.label == 0]["ip_failed_login_count"].mean()
    attack_mean = df[df.label == 1]["ip_failed_login_count"].mean()
    assert attack_mean >= normal_mean


# ---------------------------------------------------------------------------
# Fit / transform consistency
# ---------------------------------------------------------------------------

def test_transform_same_columns(pipeline_output, sample_events):
    _, _, names_fit, pipeline = pipeline_output
    X_new = pipeline.transform(sample_events[:50])
    assert X_new.shape[1] == len(names_fit)


def test_transform_before_fit_raises():
    p = FeaturePipeline()
    with pytest.raises(RuntimeError):
        p.transform([])
