"""
Unit tests — Incident Response Rule Engine
AI Threat Hunting & Incident Response Platform

Covers:
  - Condition evaluation (all operators)
  - ResponseRule AND/OR condition logic + min_conditions
  - Cooldown enforcement and bypass
  - RuleEngine: correct rules fire, actions execute, audit log written
  - Per-scenario behavioural contracts
  - Action result status and metadata
  - Custom rule injection
  - Rule enable/disable
"""

import sys, time
sys.path.insert(0, ".")

from backend.incident_response.rule_engine import (
    Condition, ResponseRule, RuleEngine, RESPONSE_RULES,
)
from backend.incident_response.actions import (
    ActionStatus, ActionType,
    BlockIPAction, DisableUserAction, SendAlertAction,
    LogIncidentAction, RateLimitAction, build_action,
)


# ─────────────────────────────────────────────────────────────────────────────
# Context factory helpers
# ─────────────────────────────────────────────────────────────────────────────

def brute_ctx(**overrides):
    base = {
        "event_id": "EVT-TEST-BF", "username": "alice",
        "source_ip": "185.220.101.15", "hostname": "server-01",
        "geo_country": "RU", "threat_category": "brute_force",
        "anomaly_score": 95.0,
        "ip_failed_login_count": 30.0, "user_login_failed_count": 25.0,
        "user_failure_rate": 0.92, "ip_rapid_fire": 1.0,
        "user_rapid_fire": 1.0, "is_external_ip": 1.0,
        "is_suspicious_country": 1.0, "mfa_absent": 1.0,
        "ip_event_count": 40.0, "ip_unique_user_count": 1.0,
        "ip_spray_flag": 0.0, "user_admin_spike": 0.0,
        "user_admin_access_count": 0.0, "user_sensitive_file_count": 0.0,
        "user_total_bytes_read": 0.0, "is_high_risk_process": 0.0,
        "severity": "CRITICAL", "category": "brute_force",
        "mitre_techniques": ["T1110.001"],
    }
    base.update(overrides)
    return base

def priv_esc_ctx(**overrides):
    base = {
        "event_id": "EVT-TEST-PE", "username": "carol",
        "source_ip": "10.0.1.22", "hostname": "workstation-carol",
        "geo_country": "US", "threat_category": "privilege_escalation",
        "anomaly_score": 91.0,
        "ip_failed_login_count": 0.0, "user_login_failed_count": 0.0,
        "user_failure_rate": 0.0, "ip_rapid_fire": 0.0,
        "user_rapid_fire": 0.0, "is_external_ip": 0.0,
        "is_suspicious_country": 0.0, "mfa_absent": 1.0,
        "ip_event_count": 10.0, "ip_unique_user_count": 1.0,
        "ip_spray_flag": 0.0, "user_admin_spike": 1.0,
        "user_admin_access_count": 7.0, "user_sensitive_file_count": 3.0,
        "user_total_bytes_read": 5.0, "is_high_risk_process": 1.0,
        "severity": "CRITICAL", "category": "privilege_escalation",
        "mitre_techniques": ["T1548.003"],
    }
    base.update(overrides)
    return base

def exfil_ctx(internal=False, **overrides):
    base = {
        "event_id": "EVT-TEST-EX", "username": "david",
        "source_ip": "10.0.1.33" if internal else "198.51.100.7",
        "hostname": "server-01", "geo_country": "US",
        "threat_category": "data_exfiltration", "anomaly_score": 88.0,
        "ip_failed_login_count": 0.0, "user_login_failed_count": 0.0,
        "user_failure_rate": 0.0, "ip_rapid_fire": 0.0,
        "user_rapid_fire": 0.0, "is_external_ip": 0.0 if internal else 1.0,
        "is_suspicious_country": 0.0, "mfa_absent": 1.0,
        "ip_event_count": 15.0, "ip_unique_user_count": 1.0,
        "ip_spray_flag": 0.0, "user_admin_spike": 0.0,
        "user_admin_access_count": 0.0, "user_sensitive_file_count": 5.0,
        "user_total_bytes_read": 15.0, "is_high_risk_process": 1.0,
        "severity": "CRITICAL", "category": "data_exfiltration",
        "mitre_techniques": ["T1005"],
    }
    base.update(overrides)
    return base

def susp_login_ctx(**overrides):
    base = {
        "event_id": "EVT-TEST-SL", "username": "alice",
        "source_ip": "162.247.72.199", "hostname": "server-01",
        "geo_country": "KP", "threat_category": "suspicious_login",
        "anomaly_score": 86.0,
        "ip_failed_login_count": 0.0, "user_login_failed_count": 0.0,
        "user_failure_rate": 0.0, "ip_rapid_fire": 0.0,
        "user_rapid_fire": 0.0, "is_external_ip": 1.0,
        "is_suspicious_country": 1.0, "mfa_absent": 1.0,
        "ip_event_count": 3.0, "ip_unique_user_count": 1.0,
        "ip_spray_flag": 0.0, "user_admin_spike": 0.0,
        "user_admin_access_count": 0.0, "user_sensitive_file_count": 0.0,
        "user_total_bytes_read": 0.0, "is_high_risk_process": 0.0,
        "severity": "CRITICAL", "category": "suspicious_login",
        "mitre_techniques": ["T1078"],
    }
    base.update(overrides)
    return base

def normal_ctx():
    return {
        "event_id": "EVT-TEST-NORM", "username": "bob",
        "source_ip": "10.0.1.15", "hostname": "workstation-bob",
        "geo_country": "US", "threat_category": "normal",
        "anomaly_score": 12.0,
        "ip_failed_login_count": 1.0, "user_login_failed_count": 0.0,
        "user_failure_rate": 0.1, "ip_rapid_fire": 0.0,
        "user_rapid_fire": 0.0, "is_external_ip": 0.0,
        "is_suspicious_country": 0.0, "mfa_absent": 0.0,
        "ip_event_count": 3.0, "ip_unique_user_count": 1.0,
        "ip_spray_flag": 0.0, "user_admin_spike": 0.0,
        "user_admin_access_count": 0.0, "user_sensitive_file_count": 0.0,
        "user_total_bytes_read": 0.0, "is_high_risk_process": 0.0,
        "severity": "INFO", "category": "normal", "mitre_techniques": [],
    }

def fresh_engine(**kwargs):
    e = RuleEngine(simulate=True, **kwargs)
    e.clear_cooldowns()
    return e


# ─────────────────────────────────────────────────────────────────────────────
# Condition tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCondition:
    def test_gt_true(self):
        assert Condition("x", ">", 10).evaluate({"x": 11})

    def test_gt_false_on_equal(self):
        assert not Condition("x", ">", 10).evaluate({"x": 10})

    def test_gte_on_boundary(self):
        assert Condition("x", ">=", 20).evaluate({"x": 20})

    def test_lt_true(self):
        assert Condition("x", "<", 5).evaluate({"x": 4.9})

    def test_eq_true(self):
        assert Condition("x", "==", "brute_force").evaluate({"x": "brute_force"})

    def test_neq_true(self):
        assert Condition("x", "!=", 0).evaluate({"x": 1})

    def test_in_operator(self):
        assert Condition("country", "in", ["RU","CN","KP"]).evaluate({"country": "RU"})

    def test_in_operator_false(self):
        assert not Condition("country", "in", ["RU","CN"]).evaluate({"country": "US"})

    def test_missing_field_returns_false(self):
        assert not Condition("nonexistent", ">", 0).evaluate({"other": 5})

    def test_label_shown_in_describe(self):
        c = Condition("x", ">", 5, label="MY LABEL")
        assert c.describe() == "MY LABEL"

    def test_default_describe_format(self):
        c = Condition("ip_failed", ">", 20)
        assert "ip_failed" in c.describe() and "20" in c.describe()


# ─────────────────────────────────────────────────────────────────────────────
# ResponseRule condition logic
# ─────────────────────────────────────────────────────────────────────────────

class TestResponseRule:
    def _rule(self, conditions, any_conditions=None):
        return ResponseRule(
            name="test", description="test",
            conditions=conditions,
            any_conditions=any_conditions or [],
            actions=["log_incident"],
        )

    def test_and_all_pass(self):
        rule = self._rule([Condition("a", ">", 1), Condition("b", ">", 1)])
        fired, _ = rule.matches({"a": 2, "b": 2})
        assert fired

    def test_and_one_fails(self):
        rule = self._rule([Condition("a", ">", 1), Condition("b", ">", 10)])
        fired, _ = rule.matches({"a": 2, "b": 1})
        assert not fired

    def test_or_at_least_one_passes(self):
        rule = self._rule(
            [Condition("a", ">", 1)],
            any_conditions=[Condition("b", ">", 5), Condition("c", ">", 5)],
        )
        # only c passes the OR
        fired, _ = rule.matches({"a": 2, "b": 0, "c": 10})
        assert fired

    def test_or_none_passes_blocks_rule(self):
        rule = self._rule(
            [Condition("a", ">", 1)],
            any_conditions=[Condition("b", ">", 5), Condition("c", ">", 5)],
        )
        fired, _ = rule.matches({"a": 2, "b": 0, "c": 0})
        assert not fired

    def test_disabled_rule_never_fires(self):
        rule = self._rule([Condition("a", ">", 0)])
        rule.enabled = False
        fired, reasons = rule.matches({"a": 999})
        assert not fired
        assert "disabled" in reasons[0]


# ─────────────────────────────────────────────────────────────────────────────
# Action tests
# ─────────────────────────────────────────────────────────────────────────────

class TestActions:
    def test_block_ip_simulated(self):
        action = BlockIPAction(block_duration_hours=24, simulate=True)
        result = action.run("1.2.3.4", {"reason": "test"})
        assert result.status == ActionStatus.SIMULATED
        assert result.action_type == ActionType.BLOCK_IP
        assert "1.2.3.4" in result.message

    def test_disable_user_simulated(self):
        result = DisableUserAction(simulate=True).run("alice", {})
        assert result.status == ActionStatus.SIMULATED
        assert result.action_type == ActionType.DISABLE_USER

    def test_send_alert_critical_channel(self):
        result = SendAlertAction(simulate=True).run("1.2.3.4", {
            "severity": "CRITICAL", "category": "brute_force", "anomaly_score": 95
        })
        assert "#soc-critical" in result.message

    def test_send_alert_medium_channel(self):
        result = SendAlertAction(simulate=True).run("1.2.3.4", {
            "severity": "MEDIUM", "category": "scan", "anomaly_score": 50
        })
        assert "#soc-monitoring" in result.message

    def test_log_incident_metadata(self):
        result = LogIncidentAction(simulate=True).run("1.2.3.4", {"category": "brute_force"})
        assert result.status == ActionStatus.SIMULATED
        assert "incident_id" in result.metadata

    def test_rate_limit_respects_rpm(self):
        result = RateLimitAction(requests_per_minute=3, simulate=True).run("u1", {})
        assert "3" in result.message

    def test_build_action_factory(self):
        action = build_action("block_ip", simulate=True, block_duration_hours=48)
        assert isinstance(action, BlockIPAction)
        assert action.block_duration_hours == 48

    def test_build_action_unknown_raises(self):
        try:
            build_action("nonexistent_action")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_result_to_dict_complete(self):
        result = BlockIPAction(simulate=True).run("1.2.3.4", {})
        d = result.to_dict()
        for key in ["action_id","action_type","status","target","timestamp","message"]:
            assert key in d

    def test_action_result_str_includes_status(self):
        result = BlockIPAction(simulate=True).run("1.2.3.4", {})
        s = str(result)
        assert "SIMULATED" in s or "simulated" in s.lower()


# ─────────────────────────────────────────────────────────────────────────────
# RuleEngine behavioural tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleEngine:

    # ── Normal context — no rules should fire ────────────────────────────────

    def test_normal_context_no_rules_fire(self):
        engine = fresh_engine()
        outcome = engine.evaluate(normal_ctx())
        assert outcome.rules_fired == 0
        assert len(outcome.action_results) == 0

    # ── Brute force ──────────────────────────────────────────────────────────

    def test_brute_force_triggers_block_ip(self):
        engine = fresh_engine()
        outcome = engine.evaluate(brute_ctx())
        action_types = {r.action_type for r in outcome.action_results}
        assert ActionType.BLOCK_IP in action_types

    def test_brute_force_triggers_disable_user(self):
        engine = fresh_engine()
        outcome = engine.evaluate(brute_ctx())
        action_types = {r.action_type for r in outcome.action_results}
        assert ActionType.DISABLE_USER in action_types

    def test_brute_force_triggers_send_alert(self):
        engine = fresh_engine()
        outcome = engine.evaluate(brute_ctx())
        action_types = {r.action_type for r in outcome.action_results}
        assert ActionType.SEND_ALERT in action_types

    def test_brute_force_triggers_log_incident(self):
        engine = fresh_engine()
        outcome = engine.evaluate(brute_ctx())
        action_types = {r.action_type for r in outcome.action_results}
        assert ActionType.LOG_INCIDENT in action_types

    def test_brute_force_below_threshold_no_block(self):
        engine = fresh_engine()
        # Only 10 failed attempts — below the 20 threshold
        ctx = brute_ctx(
            ip_failed_login_count=10.0,
            user_login_failed_count=8.0,
            user_failure_rate=0.5,
            ip_rapid_fire=0.0,
            is_suspicious_country=0.0,
        )
        outcome = engine.evaluate(ctx)
        action_types = {r.action_type for r in outcome.action_results}
        assert ActionType.BLOCK_IP not in action_types

    # ── Privilege escalation ─────────────────────────────────────────────────

    def test_priv_esc_triggers_quarantine(self):
        engine = fresh_engine()
        outcome = engine.evaluate(priv_esc_ctx())
        action_types = {r.action_type for r in outcome.action_results}
        assert ActionType.QUARANTINE_HOST in action_types

    def test_priv_esc_triggers_rotate_credentials(self):
        engine = fresh_engine()
        outcome = engine.evaluate(priv_esc_ctx())
        action_types = {r.action_type for r in outcome.action_results}
        assert ActionType.ROTATE_CREDENTIALS in action_types

    def test_priv_esc_requires_anomaly_score_70(self):
        engine = fresh_engine()
        # Low anomaly score — priv_esc rule needs >= 70
        ctx = priv_esc_ctx(anomaly_score=50.0)
        outcome = engine.evaluate(ctx)
        fired_names = {e.rule_name for e in outcome.evaluations if e.fired}
        assert "privilege_escalation_full_response" not in fired_names

    # ── Data exfiltration ─────────────────────────────────────────────────────

    def test_exfil_external_triggers_block_ip(self):
        engine = fresh_engine()
        outcome = engine.evaluate(exfil_ctx(internal=False))
        action_types = {r.action_type for r in outcome.action_results}
        assert ActionType.BLOCK_IP in action_types

    def test_exfil_internal_triggers_disable_user(self):
        engine = fresh_engine()
        outcome = engine.evaluate(exfil_ctx(internal=True))
        action_types = {r.action_type for r in outcome.action_results}
        assert ActionType.DISABLE_USER in action_types

    def test_exfil_internal_triggers_rotate_creds(self):
        engine = fresh_engine()
        outcome = engine.evaluate(exfil_ctx(internal=True))
        action_types = {r.action_type for r in outcome.action_results}
        assert ActionType.ROTATE_CREDENTIALS in action_types

    # ── Suspicious login ─────────────────────────────────────────────────────

    def test_suspicious_login_enforces_mfa(self):
        engine = fresh_engine()
        outcome = engine.evaluate(susp_login_ctx())
        action_types = {r.action_type for r in outcome.action_results}
        assert ActionType.ENFORCE_MFA in action_types

    def test_suspicious_login_with_mfa_no_mfa_enforcement(self):
        engine = fresh_engine()
        # MFA was used — should not trigger MFA enforcement rule
        ctx = susp_login_ctx(mfa_absent=0.0, anomaly_score=60.0)
        outcome = engine.evaluate(ctx)
        fired_names = {e.rule_name for e in outcome.evaluations if e.fired}
        assert "suspicious_login_enforce_mfa" not in fired_names

    # ── Cooldown ──────────────────────────────────────────────────────────────

    def test_cooldown_prevents_second_fire(self):
        engine = RuleEngine(simulate=True)
        engine.clear_cooldowns()
        ctx = brute_ctx()
        engine.evaluate(ctx)   # first evaluation — fires
        outcome2 = engine.evaluate(ctx)  # second — should be in cooldown
        # The brute_force_block_ip rule should be suppressed
        fired_names = {e.rule_name for e in outcome2.evaluations if e.fired and not e.skipped_cooldown}
        assert "brute_force_block_ip" not in fired_names

    def test_clear_cooldowns_allows_refire(self):
        engine = RuleEngine(simulate=True)
        engine.clear_cooldowns()
        ctx = brute_ctx()
        engine.evaluate(ctx)
        engine.clear_cooldowns()  # reset
        outcome2 = engine.evaluate(ctx)
        fired_names = {e.rule_name for e in outcome2.evaluations if e.fired}
        assert "brute_force_block_ip" in fired_names

    def test_zero_cooldown_always_fires(self):
        rule = ResponseRule(
            name="no_cooldown_rule", description="test",
            cooldown_seconds=0,
            conditions=[Condition("anomaly_score", ">", 0)],
            actions=["log_incident"],
        )
        engine = RuleEngine(rules=[rule], simulate=True)
        ctx = {"anomaly_score": 50.0, "source_ip": "1.2.3.4"}
        engine.evaluate(ctx)
        outcome2 = engine.evaluate(ctx)
        fired = [e for e in outcome2.evaluations if e.fired]
        assert len(fired) > 0

    # ── Rule management ───────────────────────────────────────────────────────

    def test_disable_rule_prevents_firing(self):
        engine = fresh_engine()
        engine.disable_rule("brute_force_block_ip")
        outcome = engine.evaluate(brute_ctx())
        fired_names = {e.rule_name for e in outcome.evaluations if e.fired}
        assert "brute_force_block_ip" not in fired_names

    def test_re_enable_rule_fires_again(self):
        engine = fresh_engine()
        engine.disable_rule("brute_force_block_ip")
        engine.enable_rule("brute_force_block_ip")
        outcome = engine.evaluate(brute_ctx())
        fired_names = {e.rule_name for e in outcome.evaluations if e.fired}
        assert "brute_force_block_ip" in fired_names

    def test_add_custom_rule_fires(self):
        engine = fresh_engine()
        custom = ResponseRule(
            name="custom_test_rule", description="test",
            cooldown_seconds=0,
            conditions=[Condition("ip_failed_login_count", ">", 20,
                                  label="failed_login_attempts > 20")],
            actions=["block_ip", "log_incident"],
        )
        engine.add_rule(custom)
        outcome = engine.evaluate(brute_ctx(ip_failed_login_count=25.0))
        fired_names = {e.rule_name for e in outcome.evaluations if e.fired}
        assert "custom_test_rule" in fired_names

    def test_list_rules_returns_all(self):
        engine = fresh_engine()
        rules = engine.list_rules()
        assert len(rules) == len(RESPONSE_RULES)
        assert all("name" in r for r in rules)

    # ── Audit log ─────────────────────────────────────────────────────────────

    def test_audit_log_records_evaluations(self):
        engine = fresh_engine()
        engine.evaluate(brute_ctx())
        log = engine.audit_log()
        assert len(log) > 0

    def test_audit_log_fired_entries_have_actions(self):
        engine = fresh_engine()
        engine.evaluate(brute_ctx())
        fired = [e for e in engine.audit_log() if e["fired"]]
        assert all(len(e["actions"]) > 0 for e in fired)

    def test_audit_log_not_fired_entries_have_no_actions(self):
        engine = fresh_engine()
        engine.evaluate(normal_ctx())
        not_fired = [e for e in engine.audit_log() if not e["fired"]]
        assert all(len(e["actions"]) == 0 for e in not_fired)

    def test_clear_audit_log(self):
        engine = fresh_engine()
        engine.evaluate(brute_ctx())
        engine.clear_audit_log()
        assert len(engine.audit_log()) == 0

    # ── Outcome contracts ─────────────────────────────────────────────────────

    def test_outcome_context_id_set(self):
        engine = fresh_engine()
        outcome = engine.evaluate(brute_ctx())
        assert outcome.context_id == "EVT-TEST-BF"

    def test_outcome_rules_evaluated_count(self):
        # Create a minimal single-rule engine to get a deterministic count
        from backend.incident_response.rule_engine import Condition, ResponseRule
        rule = ResponseRule(
            name="count_test", description="test", cooldown_seconds=0,
            conditions=[Condition("anomaly_score", ">", 0)],
            actions=["log_incident"],
        )
        engine = RuleEngine(rules=[rule], simulate=True)
        engine.clear_cooldowns()
        ctx = {"anomaly_score": 50.0, "source_ip": "1.2.3.4"}
        outcome = engine.evaluate(ctx)
        assert outcome.rules_evaluated == 1

    def test_action_results_all_simulated(self):
        engine = fresh_engine()
        outcome = engine.evaluate(brute_ctx())
        for r in outcome.action_results:
            assert r.status == ActionStatus.SIMULATED

    def test_batch_evaluate_length(self):
        engine = fresh_engine()
        contexts = [brute_ctx(), normal_ctx(), priv_esc_ctx()]
        outcomes = engine.evaluate_batch(contexts)
        assert len(outcomes) == 3

    def test_max_actions_cap(self):
        engine = RuleEngine(simulate=True, max_actions_per_context=3)
        engine.clear_cooldowns()
        outcome = engine.evaluate(brute_ctx())
        assert len(outcome.action_results) <= 3

    def test_stop_on_first_match(self):
        engine = RuleEngine(simulate=True, stop_on_first_match=True)
        engine.clear_cooldowns()
        outcome = engine.evaluate(brute_ctx())
        # Only one rule should fire
        assert outcome.rules_fired == 1


# ─────────────────────────────────────────────────────────────────────────────
# Self-contained test runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    suites = [
        TestCondition(),
        TestResponseRule(),
        TestActions(),
        TestRuleEngine(),
    ]

    passed = failed = 0
    for suite in suites:
        name = type(suite).__name__
        for method in sorted(m for m in dir(suite) if m.startswith("test_")):
            try:
                getattr(suite, method)()
                print(f"  PASS  {name}.{method}")
                passed += 1
            except Exception as e:
                print(f"  FAIL  {name}.{method}  —  {e}")
                traceback.print_exc()
                failed += 1

    print(f"\n{'─'*60}")
    print(f"  {passed + failed} tests  |  {passed} passed  |  {failed} failed")
    sys.exit(0 if failed == 0 else 1)
