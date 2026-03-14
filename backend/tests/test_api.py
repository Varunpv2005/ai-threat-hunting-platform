"""
API Integration Tests — AI Threat Hunting & Incident Response Platform

Tests every endpoint's business logic through the DataStore layer.
No HTTP server needed — tests call store methods directly,
matching exactly what each route handler calls.

Run with:  python backend/tests/test_api.py
"""

import sys, json, traceback
sys.path.insert(0, ".")

from backend.api.store   import DataStore, _normal_event, _attack_events
from backend.api.schemas import SimulateAttackRequest

# ─────────────────────────────────────────────────────────────────────────────
# Shared fixture: one bootstrapped store for the whole suite
# ─────────────────────────────────────────────────────────────────────────────

print("  Bootstrapping test store…", end=" ", flush=True)
_store = DataStore()
_store.bootstrap(n_train=2000)
print(f"done ({len(_store._logs)} seed logs)")


def fresh() -> DataStore:
    """Return the shared bootstrapped store (re-bootstrap is skipped)."""
    return _store


# ─────────────────────────────────────────────────────────────────────────────
# Test suite
# ─────────────────────────────────────────────────────────────────────────────

class TestGetLogs:
    def test_returns_seed_logs(self):
        s = fresh()
        rows, total = s.get_logs()
        assert total > 0
        assert len(rows) > 0

    def test_pagination_limit(self):
        s = fresh()
        rows, _ = s.get_logs(limit=5)
        assert len(rows) <= 5

    def test_pagination_page2(self):
        s = fresh()
        rows_p1, total = s.get_logs(page=1, limit=10)
        rows_p2, _     = s.get_logs(page=2, limit=10)
        if total > 10:
            assert rows_p1 != rows_p2

    def test_filter_by_event_type(self):
        s = fresh()
        rows, _ = s.get_logs(event_type="login_success")
        assert all(r["event_type"] == "login_success" for r in rows)

    def test_filter_by_label(self):
        s = fresh()
        rows, _ = s.get_logs(label=0)
        assert all(r["label"] == 0 for r in rows)

    def test_sorted_descending_by_timestamp(self):
        s = fresh()
        rows, _ = s.get_logs(limit=20)
        ts = [r["timestamp"] for r in rows]
        assert ts == sorted(ts, reverse=True)

    def test_log_record_has_required_fields(self):
        s = fresh()
        rows, _ = s.get_logs(limit=1)
        required = {"event_id","timestamp","user","source_ip","event_type","label"}
        assert required.issubset(rows[0].keys())


class TestGetThreats:
    def _seed_threat(self, store: DataStore) -> None:
        events = _attack_events("brute_force", "203.0.113.1", "alice", "RU", "medium")
        store.ingest_events(events)

    def test_threats_created_after_attack_ingest(self):
        s = DataStore(); s.bootstrap(n_train=500)
        initial = len(s._threats)
        self._seed_threat(s)
        assert len(s._threats) > initial

    def test_filter_by_severity(self):
        s = DataStore(); s.bootstrap(n_train=500)
        self._seed_threat(s)
        rows, _ = s.get_threats(severity="CRITICAL")
        assert all(r["severity"] == "CRITICAL" for r in rows)

    def test_filter_by_category(self):
        s = DataStore(); s.bootstrap(n_train=500)
        self._seed_threat(s)
        rows, _ = s.get_threats(category="brute_force")
        assert all(r["threat_category"] == "brute_force" for r in rows)

    def test_sorted_by_anomaly_score_desc(self):
        s = DataStore(); s.bootstrap(n_train=500)
        self._seed_threat(s)
        rows, _ = s.get_threats(limit=20)
        scores = [r["anomaly_score"] for r in rows]
        assert scores == sorted(scores, reverse=True)

    def test_threat_record_fields(self):
        s = DataStore(); s.bootstrap(n_train=500)
        self._seed_threat(s)
        rows, _ = s.get_threats(limit=1)
        required = {"threat_id","timestamp","source_ip","username",
                    "anomaly_score","threat_category","severity","mitre_techniques"}
        assert required.issubset(rows[0].keys())

    def test_mitre_techniques_not_empty(self):
        s = DataStore(); s.bootstrap(n_train=500)
        self._seed_threat(s)
        rows, _ = s.get_threats(limit=5)
        threats_with_mitre = [r for r in rows if r["mitre_techniques"]]
        assert len(threats_with_mitre) > 0


class TestGetAlerts:
    def _seed_alert(self, store: DataStore) -> None:
        events = _attack_events("brute_force", "203.0.113.1", "bob", "RU", "high")
        store.ingest_events(events)

    def test_alerts_created_after_attack(self):
        s = DataStore(); s.bootstrap(n_train=500)
        self._seed_alert(s)
        assert len(s._alerts) > 0

    def test_alert_has_required_fields(self):
        s = DataStore(); s.bootstrap(n_train=500)
        self._seed_alert(s)
        rows, _ = s.get_alerts(limit=1)
        required = {"alert_id","timestamp","threat_id","severity",
                    "title","description","status","actions_taken"}
        assert required.issubset(rows[0].keys())

    def test_filter_by_status_open(self):
        s = DataStore(); s.bootstrap(n_train=500)
        self._seed_alert(s)
        rows, _ = s.get_alerts(status="open")
        assert all(r["status"] == "open" for r in rows)

    def test_filter_by_severity(self):
        s = DataStore(); s.bootstrap(n_train=500)
        self._seed_alert(s)
        rows, _ = s.get_alerts(severity="CRITICAL")
        assert all(r["severity"] == "CRITICAL" for r in rows)

    def test_acknowledge_changes_status(self):
        s = DataStore(); s.bootstrap(n_train=500)
        self._seed_alert(s)
        alert_id = s._alerts[0]["alert_id"]
        updated = s.acknowledge_alert(alert_id, by="analyst1")
        assert updated is not None
        assert updated["status"] == "acknowledged"
        assert updated["acknowledged_by"] == "analyst1"

    def test_resolve_changes_status(self):
        s = DataStore(); s.bootstrap(n_train=500)
        self._seed_alert(s)
        alert_id = s._alerts[0]["alert_id"]
        updated = s.resolve_alert(alert_id)
        assert updated is not None
        assert updated["status"] == "resolved"
        assert updated["resolved_at"] is not None

    def test_acknowledge_nonexistent_returns_none(self):
        s = fresh()
        result = s.acknowledge_alert("nonexistent-id-xyz")
        assert result is None

    def test_alert_description_contains_ip(self):
        s = DataStore(); s.bootstrap(n_train=500)
        events = _attack_events("brute_force", "10.10.10.10", "carol", "US", "medium")
        s.ingest_events(events)
        rows, _ = s.get_alerts(limit=5)
        # At least one alert should mention the IP or user
        found = any("10.10.10.10" in a["description"] or
                    "carol" in a["description"] for a in rows)
        assert found


class TestStats:
    def test_stats_returns_required_keys(self):
        s = fresh()
        stats = s.stats()
        required = {"total_logs","total_threats","total_alerts","open_alerts",
                    "critical_count","threats_by_category","detection_rate","timestamp"}
        assert required.issubset(stats.keys())

    def test_total_logs_matches_store(self):
        s = fresh()
        stats = s.stats()
        assert stats["total_logs"] == len(s._logs)

    def test_detection_rate_bounded(self):
        s = fresh()
        rate = s.stats()["detection_rate"]
        assert 0.0 <= rate <= 1.0


class TestSimulateAttack:
    ATTACK_TYPES = [
        "brute_force", "privilege_escalation", "data_exfiltration",
        "suspicious_login", "password_spray", "automated_scanner",
    ]

    def test_all_attack_types_detected(self):
        s = fresh()
        for atk in self.ATTACK_TYPES:
            req = SimulateAttackRequest(attack_type=atk, dry_run=True)
            result = s.simulate_attack(req)
            assert result.threat_detected, f"{atk} not detected"

    def test_anomaly_score_high_for_attacks(self):
        s = fresh()
        for atk in self.ATTACK_TYPES:
            req = SimulateAttackRequest(attack_type=atk, intensity="high", dry_run=True)
            result = s.simulate_attack(req)
            assert result.anomaly_score > 50, \
                f"{atk}: score {result.anomaly_score:.1f} too low"

    def test_response_fields_present(self):
        s = fresh()
        req = SimulateAttackRequest(attack_type="brute_force", dry_run=True)
        result = s.simulate_attack(req)
        d = result.to_dict()
        required = {"simulation_id","attack_type","events_generated",
                    "anomaly_score","threat_detected","threat_category",
                    "severity","confidence","mitre_techniques",
                    "actions_triggered","rules_fired","events_sample","timestamp"}
        assert required.issubset(d.keys())

    def test_mitre_techniques_returned(self):
        s = fresh()
        req = SimulateAttackRequest(attack_type="brute_force", dry_run=True)
        result = s.simulate_attack(req)
        assert len(result.mitre_techniques) > 0

    def test_rules_fired_list(self):
        s = fresh()
        req = SimulateAttackRequest(attack_type="privilege_escalation", dry_run=True)
        result = s.simulate_attack(req)
        assert isinstance(result.rules_fired, list)
        assert len(result.rules_fired) > 0

    def test_events_sample_length(self):
        s = fresh()
        req = SimulateAttackRequest(attack_type="brute_force", dry_run=True)
        result = s.simulate_attack(req)
        assert 1 <= len(result.events_sample) <= 3

    def test_dry_run_does_not_persist(self):
        s = fresh()
        threats_before = len(s._threats)
        req = SimulateAttackRequest(attack_type="brute_force", dry_run=True)
        s.simulate_attack(req)
        assert len(s._threats) == threats_before

    def test_not_dry_run_persists(self):
        s = DataStore(); s.bootstrap(n_train=500)
        threats_before = len(s._threats)
        req = SimulateAttackRequest(attack_type="brute_force", dry_run=False)
        s.simulate_attack(req)
        assert len(s._threats) > threats_before

    def test_custom_ip_and_user(self):
        s = fresh()
        req = SimulateAttackRequest(
            attack_type="brute_force",
            source_ip="99.99.99.99",
            username="custom_user",
            dry_run=True,
        )
        result = s.simulate_attack(req)
        assert result.threat_detected

    def test_intensity_high_generates_more_events(self):
        s = fresh()
        low  = s.simulate_attack(SimulateAttackRequest(attack_type="brute_force", intensity="low",  dry_run=True))
        high = s.simulate_attack(SimulateAttackRequest(attack_type="brute_force", intensity="high", dry_run=True))
        assert high.events_generated > low.events_generated

    def test_brute_force_triggers_block_ip(self):
        s = fresh()
        req = SimulateAttackRequest(attack_type="brute_force", dry_run=True)
        result = s.simulate_attack(req)
        assert "block_ip" in result.actions_triggered

    def test_priv_esc_triggers_quarantine(self):
        s = fresh()
        req = SimulateAttackRequest(attack_type="privilege_escalation", dry_run=True)
        result = s.simulate_attack(req)
        assert "quarantine_host" in result.actions_triggered

    def test_exfil_triggers_block_ip(self):
        s = fresh()
        req = SimulateAttackRequest(attack_type="data_exfiltration", dry_run=True)
        result = s.simulate_attack(req)
        assert "block_ip" in result.actions_triggered


class TestIngest:
    def test_ingest_normal_events(self):
        s = DataStore(); s.bootstrap(n_train=500)
        before = len(s._logs)
        events = [_normal_event() for _ in range(10)]
        enriched = s.ingest_events(events)
        assert len(enriched) == 10
        assert len(s._logs) == before + 10

    def test_ingest_attack_creates_threat(self):
        s = DataStore(); s.bootstrap(n_train=500)
        events = _attack_events("brute_force", "1.2.3.4", "victim", "RU", "high")
        s.ingest_events(events)
        assert any(t["source_ip"] == "1.2.3.4" for t in s._threats)

    def test_ingest_empty_list(self):
        s = fresh()
        result = s.ingest_events([])
        assert result == []


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    suites = [
        TestGetLogs(), TestGetThreats(), TestGetAlerts(),
        TestStats(), TestSimulateAttack(), TestIngest(),
    ]
    passed = failed = 0
    print()
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

    print(f"\n{'─'*62}")
    print(f"  {passed + failed} tests  |  {passed} passed  |  {failed} failed")
    sys.exit(0 if failed == 0 else 1)
