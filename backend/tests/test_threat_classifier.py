"""
Unit tests — Threat Classifier
AI Threat Hunting & Incident Response Platform

Tests cover:
  - Rule primitive evaluation (FeatureRule)
  - ThreatRule match scoring and min_conditions gating
  - ThreatClassifier normal gate (below threshold)
  - Correct primary category for each attack scenario
  - Confidence and severity contracts
  - Multi-match ordering
  - Report aggregation
"""

import sys
sys.path.insert(0, ".")

from backend.ml.classifier.threat_taxonomy import (
    FeatureRule, ThreatRule, ThreatCategory, Severity,
    RuleOperator, severity_from_score, THREAT_RULES,
)
from backend.ml.classifier.attack_classifier import (
    ThreatClassifier, ClassificationResult,
)

GT  = RuleOperator.GT
GTE = RuleOperator.GTE
LT  = RuleOperator.LT
EQ  = RuleOperator.EQ


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _clf() -> ThreatClassifier:
    return ThreatClassifier(anomaly_threshold=25.0, min_rule_confidence=0.20)

def _brute_features(n_failed=30, rapid=1, external=1, susp_country=1) -> dict:
    return {
        "ip_failed_login_count":   float(n_failed),
        "user_login_failed_count": float(n_failed * 0.8),
        "user_failure_rate":       0.90,
        "ip_rapid_fire":           float(rapid),
        "user_rapid_fire":         float(rapid),
        "is_external_ip":          float(external),
        "is_suspicious_country":   float(susp_country),
        "mfa_absent":              1.0,
        "ip_spray_flag":           0.0,
        "ip_unique_user_count":    1.0,
        "user_admin_access_count": 0.0,
        "user_admin_spike":        0.0,
        "is_sensitive_file":       0.0,
        "user_sensitive_file_count": 0.0,
        "user_total_bytes_read":   0.0,
        "log_bytes_read":          0.0,
        "is_high_risk_process":    0.0,
        "is_login_success":        0.0,
        "is_after_hours":          0.0,
        "is_weekend":              0.0,
    }

def _priv_esc_features() -> dict:
    return {
        "user_admin_access_count": 7.0,
        "user_admin_spike":        1.0,
        "is_high_risk_process":    1.0,
        "mfa_absent":              1.0,
        "is_sensitive_file":       1.0,
        "user_sensitive_file_count": 3.0,
        "is_external_ip":          0.0,
        "is_suspicious_country":   0.0,
        "ip_failed_login_count":   0.0,
        "user_failure_rate":       0.0,
        "user_total_bytes_read":   0.0,
        "log_bytes_read":          0.0,
        "ip_spray_flag":           0.0,
        "user_rapid_fire":         0.0,
        "ip_rapid_fire":           0.0,
    }

def _exfil_features() -> dict:
    return {
        "user_total_bytes_read":    15.0,   # log-scaled: very large
        "log_bytes_read":           15.0,
        "is_sensitive_file":        1.0,
        "user_sensitive_file_count": 5.0,
        "log_file_size_kb":         10.0,
        "is_high_risk_process":     1.0,
        "user_admin_access_count":  0.0,
        "user_admin_spike":         0.0,
        "is_external_ip":           0.0,
        "mfa_absent":               1.0,
        "ip_failed_login_count":    0.0,
        "user_failure_rate":        0.0,
        "ip_spray_flag":            0.0,
    }

def _suspicious_login_features() -> dict:
    return {
        "is_suspicious_country":  1.0,
        "is_external_ip":         1.0,
        "mfa_absent":             1.0,
        "is_login_success":       1.0,
        "is_after_hours":         1.0,
        "is_weekend":             0.0,
        "user_login_success_count": 1.0,
        "ip_failed_login_count":  0.0,
        "user_failure_rate":      0.0,
        "ip_spray_flag":          0.0,
        "user_admin_spike":       0.0,
        "is_sensitive_file":      0.0,
        "user_total_bytes_read":  0.0,
    }

def _normal_features() -> dict:
    return {k: 0.0 for k in [
        "ip_failed_login_count","user_login_failed_count","user_failure_rate",
        "ip_rapid_fire","user_rapid_fire","is_external_ip","is_suspicious_country",
        "mfa_absent","ip_spray_flag","ip_unique_user_count","user_admin_access_count",
        "user_admin_spike","is_sensitive_file","user_sensitive_file_count",
        "user_total_bytes_read","log_bytes_read","is_high_risk_process",
        "is_login_success","is_after_hours","is_weekend","log_file_size_kb",
    ]}


# ─────────────────────────────────────────────────────────────────────────────
# FeatureRule tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureRule:
    def test_gt_passes(self):
        assert FeatureRule("x", GT, 10.0).evaluate(11.0)

    def test_gt_fails(self):
        assert not FeatureRule("x", GT, 10.0).evaluate(10.0)

    def test_gte_on_boundary(self):
        assert FeatureRule("x", GTE, 1.0).evaluate(1.0)

    def test_lt_passes(self):
        assert FeatureRule("x", LT, 5.0).evaluate(4.9)

    def test_eq_passes(self):
        assert FeatureRule("x", EQ, 0.0).evaluate(0.0)

    def test_eq_fails(self):
        assert not FeatureRule("x", EQ, 0.0).evaluate(1.0)


# ─────────────────────────────────────────────────────────────────────────────
# ThreatRule tests
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatRule:
    def _rule(self, min_cond=2):
        return ThreatRule(
            name="test_rule",
            category=ThreatCategory.BRUTE_FORCE,
            min_conditions=min_cond,
            conditions=[
                FeatureRule("a", GT,  5.0, weight=1.0),
                FeatureRule("b", GTE, 1.0, weight=1.0),
                FeatureRule("c", GT,  0.5, weight=2.0),
            ],
        )

    def test_zero_when_min_not_reached(self):
        rule = self._rule(min_cond=3)
        score = rule.match_score({"a": 10.0, "b": 1.0, "c": 0.0})
        assert score == 0.0, "Should return 0 when min_conditions not met"

    def test_partial_match_above_min(self):
        rule = self._rule(min_cond=2)
        score = rule.match_score({"a": 10.0, "b": 1.0, "c": 0.0})
        assert 0 < score < 1.0

    def test_full_match_returns_positive(self):
        rule = self._rule(min_cond=2)
        score = rule.match_score({"a": 10.0, "b": 2.0, "c": 1.0})
        assert score > 0.9

    def test_missing_feature_treated_as_zero(self):
        rule = self._rule(min_cond=1)
        score = rule.match_score({"a": 10.0})  # b, c missing → 0
        # Only 'a' fires, that's ≥ min_conditions=1 → score > 0
        assert score > 0.0

    def test_weighted_score_reflects_weights(self):
        rule = self._rule(min_cond=2)
        # Only c fires (weight=2 of total=4) → 0.5
        score = rule.match_score({"a": 0.0, "b": 0.0, "c": 1.0})
        # c alone doesn't meet min_conditions=2 → 0
        assert score == 0.0
        # a + c meet min=2, weight = 1+2=3 of 4 total → 0.75
        score2 = rule.match_score({"a": 10.0, "b": 0.0, "c": 1.0})
        assert abs(score2 - 0.75) < 0.01


# ─────────────────────────────────────────────────────────────────────────────
# ThreatClassifier tests
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatClassifier:

    # ── Normal gate ──────────────────────────────────────────────────────────

    def test_below_threshold_is_normal(self):
        clf = _clf()
        result = clf.classify(anomaly_score=10.0, features=_normal_features())
        assert not result.is_threat
        assert result.final_severity == Severity.INFO
        assert result.primary_category == ThreatCategory.UNKNOWN

    def test_exactly_at_threshold_is_classified(self):
        clf = _clf()
        result = clf.classify(anomaly_score=25.0, features=_brute_features())
        # At threshold, should attempt classification
        assert result.anomaly_score == 25.0

    # ── Brute force ──────────────────────────────────────────────────────────

    def test_brute_force_classified_correctly(self):
        clf = _clf()
        result = clf.classify(anomaly_score=90.0, features=_brute_features())
        assert result.is_threat
        assert result.primary_category == ThreatCategory.BRUTE_FORCE

    def test_brute_force_is_high_or_critical(self):
        clf = _clf()
        result = clf.classify(anomaly_score=90.0, features=_brute_features())
        assert result.final_severity in (Severity.HIGH, Severity.CRITICAL)

    def test_brute_force_confidence_above_half(self):
        clf = _clf()
        result = clf.classify(anomaly_score=92.0, features=_brute_features())
        assert result.primary_confidence > 0.5

    def test_brute_force_includes_mitre(self):
        clf = _clf()
        result = clf.classify(anomaly_score=90.0, features=_brute_features())
        assert len(result.mitre_techniques) > 0
        # T1110.x should appear
        assert any("T1110" in t for t in result.mitre_techniques)

    def test_brute_force_includes_block_action(self):
        clf = _clf()
        result = clf.classify(anomaly_score=90.0, features=_brute_features())
        assert "block_source_ip" in result.recommended_actions

    # ── Privilege escalation ─────────────────────────────────────────────────

    def test_privilege_escalation_classified(self):
        clf = _clf()
        result = clf.classify(anomaly_score=88.0, features=_priv_esc_features())
        assert result.is_threat
        assert result.primary_category == ThreatCategory.PRIVILEGE_ESCALATION

    def test_privilege_escalation_is_critical(self):
        clf = _clf()
        result = clf.classify(anomaly_score=88.0, features=_priv_esc_features())
        assert result.final_severity == Severity.CRITICAL

    def test_privilege_escalation_disable_user_action(self):
        clf = _clf()
        result = clf.classify(anomaly_score=88.0, features=_priv_esc_features())
        assert "disable_user_account" in result.recommended_actions

    # ── Data exfiltration ─────────────────────────────────────────────────────

    def test_data_exfil_classified(self):
        clf = _clf()
        result = clf.classify(anomaly_score=85.0, features=_exfil_features())
        assert result.is_threat
        assert result.primary_category == ThreatCategory.DATA_EXFILTRATION

    def test_data_exfil_includes_block_action(self):
        clf = _clf()
        result = clf.classify(anomaly_score=85.0, features=_exfil_features())
        assert "block_outbound_transfer" in result.recommended_actions

    # ── Suspicious login ─────────────────────────────────────────────────────

    def test_suspicious_login_classified(self):
        clf = _clf()
        result = clf.classify(anomaly_score=70.0, features=_suspicious_login_features())
        assert result.is_threat
        assert result.primary_category == ThreatCategory.SUSPICIOUS_LOGIN

    def test_suspicious_login_enforce_mfa_action(self):
        clf = _clf()
        result = clf.classify(anomaly_score=70.0, features=_suspicious_login_features())
        assert "enforce_mfa" in result.recommended_actions

    # ── Unknown anomaly ───────────────────────────────────────────────────────

    def test_anomalous_but_no_rule_match_is_unknown(self):
        clf = ThreatClassifier(anomaly_threshold=25.0, min_rule_confidence=0.99)
        result = clf.classify(anomaly_score=60.0, features=_normal_features())
        # All rules suppressed by high confidence threshold → UNKNOWN
        assert result.primary_category == ThreatCategory.UNKNOWN
        assert result.is_threat  # still flagged as anomalous

    # ── Result contracts ─────────────────────────────────────────────────────

    def test_confidence_bounded_0_1(self):
        clf = _clf()
        for score in [30, 60, 90]:
            result = clf.classify(float(score), _brute_features())
            assert 0.0 <= result.primary_confidence <= 1.0

    def test_matches_sorted_by_confidence_desc(self):
        clf = _clf()
        result = clf.classify(90.0, _brute_features())
        confs = [m.confidence for m in result.all_matches]
        assert confs == sorted(confs, reverse=True)

    def test_max_categories_respected(self):
        clf = ThreatClassifier(max_categories=2, anomaly_threshold=10.0)
        result = clf.classify(80.0, _brute_features())
        assert len(result.all_matches) <= 2

    def test_mitre_deduplication(self):
        clf = _clf()
        result = clf.classify(90.0, _brute_features())
        assert len(result.mitre_techniques) == len(set(result.mitre_techniques))

    def test_actions_deduplication(self):
        clf = _clf()
        result = clf.classify(90.0, _brute_features())
        assert len(result.recommended_actions) == len(set(result.recommended_actions))

    # ── Batch classification ─────────────────────────────────────────────────

    def test_batch_length_matches_input(self):
        import numpy as np
        clf = _clf()
        n = 50
        scores = np.random.uniform(0, 100, n)
        feats  = list(_normal_features().values())
        names  = list(_normal_features().keys())
        matrix = np.tile(feats, (n, 1)).astype(np.float32)
        results = clf.classify_batch(scores, matrix, names)
        assert len(results) == n

    def test_batch_indices_sequential(self):
        import numpy as np
        clf = _clf()
        n = 10
        scores = np.full(n, 80.0)
        feats  = list(_brute_features().values())
        names  = list(_brute_features().keys())
        matrix = np.tile(feats, (n, 1)).astype(np.float32)
        results = clf.classify_batch(scores, matrix, names)
        for i, r in enumerate(results):
            assert r.event_index == i

    # ── Report ───────────────────────────────────────────────────────────────

    def test_report_totals_correct(self):
        clf = _clf()
        results = [
            clf.classify(90.0, _brute_features()),
            clf.classify(10.0, _normal_features()),
            clf.classify(88.0, _priv_esc_features()),
        ]
        report = clf.report(results)
        assert report.total == 3
        assert report.threats_detected == 2
        assert report.normal == 1

    def test_report_by_category_sums_to_threats(self):
        clf = _clf()
        results = [clf.classify(90.0, _brute_features()) for _ in range(5)]
        report = clf.report(results)
        assert sum(report.by_category.values()) == report.threats_detected


# ─────────────────────────────────────────────────────────────────────────────
# Taxonomy integrity tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTaxonomyIntegrity:

    def test_all_rules_have_conditions(self):
        for rule in THREAT_RULES:
            assert len(rule.conditions) > 0, f"{rule.name} has no conditions"

    def test_min_conditions_not_greater_than_total(self):
        for rule in THREAT_RULES:
            assert rule.min_conditions <= len(rule.conditions), (
                f"{rule.name}: min_conditions={rule.min_conditions} > "
                f"total={len(rule.conditions)}"
            )

    def test_all_rules_have_mitre(self):
        for rule in THREAT_RULES:
            assert len(rule.mitre_techniques) > 0, f"{rule.name} has no MITRE techniques"

    def test_all_rules_have_recommended_actions(self):
        for rule in THREAT_RULES:
            assert len(rule.recommended_actions) > 0, f"{rule.name} has no recommended actions"

    def test_confidence_boost_bounded(self):
        for rule in THREAT_RULES:
            assert 0.0 <= rule.confidence_boost <= 1.0, (
                f"{rule.name} confidence_boost {rule.confidence_boost} out of [0,1]"
            )

    def test_severity_from_score_covers_all_ranges(self):
        assert severity_from_score(95) == Severity.CRITICAL
        assert severity_from_score(70) == Severity.HIGH
        assert severity_from_score(50) == Severity.MEDIUM
        assert severity_from_score(30) == Severity.LOW
        assert severity_from_score(10) == Severity.INFO


# ─────────────────────────────────────────────────────────────────────────────
# Self-contained test runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    suites = [
        TestFeatureRule(),
        TestThreatRule(),
        TestThreatClassifier(),
        TestTaxonomyIntegrity(),
    ]

    passed = failed = 0
    for suite in suites:
        suite_name = type(suite).__name__
        methods = [m for m in dir(suite) if m.startswith("test_")]
        for method in methods:
            try:
                getattr(suite, method)()
                print(f"  PASS  {suite_name}.{method}")
                passed += 1
            except Exception as e:
                print(f"  FAIL  {suite_name}.{method}")
                traceback.print_exc()
                failed += 1

    print(f"\n{'─'*55}")
    print(f"  {passed + failed} tests  |  {passed} passed  |  {failed} failed")
    sys.exit(0 if failed == 0 else 1)
