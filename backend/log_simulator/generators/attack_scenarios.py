"""
Attack scenario generators.

Each scenario class produces a burst of labeled events (label=1) that
simulate a realistic multi-step attack chain. These are injected into
the normal event stream by the LogSimulator to create training data
with known ground truth.

Scenarios implemented
---------------------
BruteForceScenario          — High-rate failed logins followed by a success
PrivilegeEscalationScenario — Normal login → admin_access abuse → sensitive file reads
DataExfiltrationScenario    — Bulk sensitive file reads with large byte counts
"""

import random
import uuid
from datetime import datetime, timezone, timedelta
from ._fixtures import (
    NORMAL_USERS, ADMIN_USERS,
    INTERNAL_IPS, EXTERNAL_IPS, SUSPICIOUS_IPS,
    SENSITIVE_PATHS, NORMAL_PATHS,
    HOSTNAMES,
)


def _ts(offset_seconds: float = 0) -> str:
    """Return an ISO-8601 UTC timestamp offset by `offset_seconds` from now."""
    t = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return t.isoformat()


def _attack_event(event_type: str, user: str, ip: str, extra: dict, time_offset: float = 0) -> dict:
    """Build a labeled (label=1) event dict."""
    return {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  _ts(time_offset),
        "user":       user,
        "ip_address": ip,
        "event_type": event_type,
        "hostname":   random.choice(HOSTNAMES),
        "session_id": str(uuid.uuid4())[:8],
        "label":      1,   # ← ground-truth attack label for ML training
        **extra,
    }


# ---------------------------------------------------------------------------
# Scenario 1: Brute Force
# ---------------------------------------------------------------------------

class BruteForceScenario:
    """
    Simulates a brute-force SSH attack:
      1. 20–50 rapid login_failed events from a single external IP
      2. One login_success if the attacker "guesses" correctly
    
    MITRE ATT&CK: T1110 — Brute Force
    """

    def generate(self) -> list[dict]:
        attacker_ip = random.choice(SUSPICIOUS_IPS + EXTERNAL_IPS)
        target_user = random.choice(NORMAL_USERS)
        attempt_count = random.randint(20, 50)
        events = []

        for i in range(attempt_count):
            events.append(_attack_event(
                event_type="login_failed",
                user=target_user,
                ip=attacker_ip,
                time_offset=i * 0.5,          # 1 attempt every 0.5 s
                extra={
                    "protocol":       "ssh",
                    "failure_reason": "invalid_password",
                    "attempt_count":  i + 1,
                    "geo_country":    random.choice(["RU", "CN", "KP", "IR"]),
                    "geo_city":       "Unknown",
                    "user_agent":     "OpenSSH_8.2p1",
                    "attack_type":    "brute_force",
                },
            ))

        # Attacker succeeds on the last attempt
        events.append(_attack_event(
            event_type="login_success",
            user=target_user,
            ip=attacker_ip,
            time_offset=attempt_count * 0.5 + 1,
            extra={
                "protocol":        "ssh",
                "mfa_used":        None,
                "login_duration_ms": random.randint(50, 200),
                "geo_country":     random.choice(["RU", "CN", "KP"]),
                "geo_city":        "Unknown",
                "user_agent":      "OpenSSH_8.2p1",
                "privilege_level": "user",
                "attack_type":     "brute_force",
            },
        ))

        return events


# ---------------------------------------------------------------------------
# Scenario 2: Privilege Escalation
# ---------------------------------------------------------------------------

class PrivilegeEscalationScenario:
    """
    Simulates insider privilege abuse:
      1. Normal user login from internal IP
      2. Repeated admin_access events (sudo abuse)
      3. Reads of sensitive files (/etc/shadow, SSH keys)
    
    MITRE ATT&CK: T1078 — Valid Accounts, T1548 — Abuse Elevation Control
    """

    def generate(self) -> list[dict]:
        compromised_user = random.choice(NORMAL_USERS)
        ip = random.choice(INTERNAL_IPS)
        events = []

        # Step 1: Legitimate-looking login
        events.append(_attack_event(
            event_type="login_success",
            user=compromised_user,
            ip=ip,
            time_offset=0,
            extra={
                "protocol":        "web_portal",
                "mfa_used":        None,         # No MFA — suspicious
                "login_duration_ms": 150,
                "geo_country":     "US",
                "privilege_level": "user",
                "attack_type":     "privilege_escalation",
            },
        ))

        # Step 2: Escalation attempts via sudo
        for i in range(random.randint(3, 8)):
            events.append(_attack_event(
                event_type="admin_access",
                user=compromised_user,
                ip=ip,
                time_offset=10 + i * 5,
                extra={
                    "operation":       "sudo_command",
                    "target_resource": random.choice(["sudo su", "sudo bash", "sudo cat /etc/shadow"]),
                    "process_name":    "sudo",
                    "privilege_level": "escalated",
                    "mfa_verified":    False,
                    "outcome":         random.choice(["success", "success", "failed"]),
                    "attack_type":     "privilege_escalation",
                },
            ))

        # Step 3: Sensitive file reads
        for i, path in enumerate(random.sample([
            "/etc/shadow", "/etc/passwd", "/home/admin/.ssh/id_rsa",
            "/etc/ssl/private/server.key", "/var/db/users.sqlite",
        ], k=random.randint(2, 4))):
            events.append(_attack_event(
                event_type="file_access",
                user=compromised_user,
                ip=ip,
                time_offset=60 + i * 3,
                extra={
                    "file_path":    path,
                    "operation":    "read",
                    "file_size_kb": random.randint(1, 50),
                    "process_name": "cat",
                    "outcome":      "success",
                    "bytes_read":   random.randint(512, 10_000),
                    "bytes_written": 0,
                    "attack_type":  "privilege_escalation",
                },
            ))

        return events


# ---------------------------------------------------------------------------
# Scenario 3: Data Exfiltration
# ---------------------------------------------------------------------------

class DataExfiltrationScenario:
    """
    Simulates bulk data theft:
      1. Repeated file reads of sensitive paths with unusually large byte counts
      2. Reads spread across many files in a short window
      3. Optional password_change to cover tracks
    
    MITRE ATT&CK: T1005 — Data from Local System, T1048 — Exfil Over Alt Protocol
    """

    def generate(self) -> list[dict]:
        user = random.choice(NORMAL_USERS + ADMIN_USERS)
        ip   = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
        events = []

        target_files = random.sample(SENSITIVE_PATHS + NORMAL_PATHS, k=random.randint(8, 20))

        for i, path in enumerate(target_files):
            events.append(_attack_event(
                event_type="file_access",
                user=user,
                ip=ip,
                time_offset=i * 2,
                extra={
                    "file_path":    path,
                    "operation":    random.choice(["read", "copy"]),
                    "file_size_kb": random.randint(500, 50_000),   # abnormally large
                    "process_name": random.choice(["rsync", "scp", "python3", "curl"]),
                    "outcome":      "success",
                    "bytes_read":   random.randint(500_000, 50_000_000),  # high volume
                    "bytes_written": 0,
                    "attack_type":  "data_exfiltration",
                },
            ))

        # Cover tracks: change own password
        events.append(_attack_event(
            event_type="password_change",
            user=user,
            ip=ip,
            time_offset=len(target_files) * 2 + 10,
            extra={
                "initiated_by":    "self",
                "password_strength": "strong",
                "mfa_verified":    False,
                "changed_via":     "cli",
                "attack_type":     "data_exfiltration",
            },
        ))

        return events
