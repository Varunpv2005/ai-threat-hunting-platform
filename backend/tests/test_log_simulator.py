"""
Unit tests for the log_simulator module.

Run with:  pytest backend/tests/test_log_simulator.py -v
"""

import pytest
from backend.log_simulator import LogSimulator
from backend.log_simulator.generators.auth_logs import (
    generate_login_success,
    generate_login_failed,
    generate_password_change,
)
from backend.log_simulator.generators.system_logs import (
    generate_file_access,
    generate_admin_access,
)
from backend.log_simulator.generators.attack_scenarios import (
    BruteForceScenario,
    PrivilegeEscalationScenario,
    DataExfiltrationScenario,
)

REQUIRED_FIELDS = {"event_id", "timestamp", "user", "ip_address", "event_type", "label"}


# ---------------------------------------------------------------------------
# Normal event generators
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fn,expected_type", [
    (generate_login_success,   "login_success"),
    (generate_login_failed,    "login_failed"),
    (generate_password_change, "password_change"),
    (generate_file_access,     "file_access"),
    (generate_admin_access,    "admin_access"),
])
def test_event_has_required_fields(fn, expected_type):
    event = fn()
    assert REQUIRED_FIELDS.issubset(event.keys()), f"Missing fields in {expected_type}"
    assert event["event_type"] == expected_type
    assert event["label"] == 0


def test_login_failed_has_failure_reason():
    event = generate_login_failed()
    assert "failure_reason" in event


def test_file_access_has_path():
    event = generate_file_access()
    assert "file_path" in event
    assert event["file_path"].startswith("/")


def test_admin_access_is_privileged():
    event = generate_admin_access()
    assert event["privilege_level"] == "admin"


# ---------------------------------------------------------------------------
# Attack scenarios
# ---------------------------------------------------------------------------

def test_brute_force_produces_labeled_events():
    events = BruteForceScenario().generate()
    assert len(events) >= 21          # at least 20 fails + 1 success
    labels = [e["label"] for e in events]
    assert all(l == 1 for l in labels)
    event_types = {e["event_type"] for e in events}
    assert "login_failed" in event_types
    assert "login_success" in event_types


def test_privilege_escalation_sequence():
    events = PrivilegeEscalationScenario().generate()
    assert len(events) >= 4
    types = [e["event_type"] for e in events]
    assert types[0] == "login_success"
    assert "admin_access" in types
    assert "file_access" in types


def test_data_exfiltration_has_large_reads():
    events = DataExfiltrationScenario().generate()
    file_events = [e for e in events if e["event_type"] == "file_access"]
    assert len(file_events) >= 8
    # At least some events should have large byte reads
    large = [e for e in file_events if e["bytes_read"] > 100_000]
    assert len(large) > 0


# ---------------------------------------------------------------------------
# Simulator batch mode
# ---------------------------------------------------------------------------

def test_batch_contains_correct_count():
    sim = LogSimulator(output="stdout")
    batch = sim.generate_batch(n=100, include_attacks=False)
    assert len(batch) == 100


def test_batch_all_normal_when_no_attacks():
    sim = LogSimulator(output="stdout")
    batch = sim.generate_batch(n=200, include_attacks=False)
    assert all(e["label"] == 0 for e in batch)


def test_batch_with_attacks_has_some_labeled():
    sim = LogSimulator(output="stdout", attack_probability=0.5)
    batch = sim.generate_batch(n=500, include_attacks=True)
    attack_events = [e for e in batch if e["label"] == 1]
    assert len(attack_events) > 0


def test_each_event_has_unique_event_id():
    sim = LogSimulator(output="stdout")
    batch = sim.generate_batch(n=100)
    ids = [e["event_id"] for e in batch]
    assert len(set(ids)) == 100
