"""
Shared fixtures: realistic pools of users, IPs, hostnames, and file paths
used across all log generators.
"""

import random
import uuid
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# User pools
# ---------------------------------------------------------------------------

NORMAL_USERS = [
    "alice.chen", "bob.martinez", "carol.smith", "david.lee",
    "eve.johnson", "frank.wilson", "grace.taylor", "henry.brown",
    "iris.davis", "jack.anderson", "karen.thomas", "liam.jackson",
]

ADMIN_USERS = [
    "admin", "root", "sysadmin", "devops.lead",
    "sec.engineer", "infra.admin",
]

ALL_USERS = NORMAL_USERS + ADMIN_USERS

# ---------------------------------------------------------------------------
# IP pools
# ---------------------------------------------------------------------------

INTERNAL_IPS = [f"10.0.{random.randint(1,5)}.{i}" for i in range(10, 60)]

EXTERNAL_IPS = [
    "203.0.113.42", "198.51.100.7", "192.0.2.88", "45.33.32.156",
    "185.220.101.15", "89.163.207.56", "104.244.74.22", "94.102.49.190",
    "91.108.4.12", "176.10.99.200", "172.67.175.37", "31.13.64.35",
]

SUSPICIOUS_IPS = [
    "185.220.101.34", "162.247.72.199", "23.129.64.131",
    "193.32.127.236", "77.247.181.163",
]

HOSTNAMES = [
    "ws-alice", "ws-bob", "ws-carol", "ws-david",
    "srv-web01", "srv-db01", "srv-auth01", "srv-ldap01",
]

# ---------------------------------------------------------------------------
# File path pools
# ---------------------------------------------------------------------------

SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/var/log/auth.log",
    "/home/admin/.ssh/id_rsa", "/etc/ssl/private/server.key",
    "/var/db/users.sqlite", "/opt/app/config/secrets.env",
]

NORMAL_PATHS = [
    "/var/log/nginx/access.log", "/home/alice.chen/documents/report.pdf",
    "/opt/app/data/export.csv", "/tmp/cache.tmp",
    "/usr/local/bin/deploy.sh", "/home/bob.martinez/notes.txt",
]

ALL_PATHS = NORMAL_PATHS + SENSITIVE_PATHS


# ---------------------------------------------------------------------------
# Helper factory
# ---------------------------------------------------------------------------

def base_event(event_type: str, user: str = None, ip: str = None) -> dict:
    """
    Construct the common fields shared by every log event.

    Returns
    -------
    dict with keys: event_id, timestamp, user, ip_address, event_type,
    hostname, session_id, label (0 = normal, set to 1 by attack generators).
    """
    return {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "user":       user or random.choice(NORMAL_USERS),
        "ip_address": ip   or random.choice(INTERNAL_IPS),
        "event_type": event_type,
        "hostname":   random.choice(HOSTNAMES),
        "session_id": str(uuid.uuid4())[:8],
        "label":      0,  # 0 = normal, 1 = attack/anomaly
    }
