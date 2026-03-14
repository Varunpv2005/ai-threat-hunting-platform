"""
System log generators.

Produces file_access and admin_access events with realistic metadata
covering file paths, operations, process names, and privilege levels.
"""

import random
from ._fixtures import (
    base_event,
    NORMAL_USERS, ADMIN_USERS,
    INTERNAL_IPS,
    NORMAL_PATHS, SENSITIVE_PATHS, ALL_PATHS,
    HOSTNAMES,
)

FILE_OPERATIONS  = ["read", "write", "delete", "rename", "chmod", "copy"]
ADMIN_OPERATIONS = [
    "user_created", "user_deleted", "group_modified",
    "firewall_rule_changed", "service_restarted",
    "sudo_command", "cron_job_added", "package_installed",
]
PROCESSES = [
    "nginx", "sshd", "bash", "python3", "java",
    "node", "mysqld", "postgres", "rsync", "wget", "curl",
]


def generate_file_access() -> dict:
    """
    Normal file access event.
    Most accesses are to non-sensitive paths; occasionally a normal
    user touches a log file (still benign, but worth modeling).
    """
    user = random.choice(NORMAL_USERS)
    ip   = random.choice(INTERNAL_IPS)

    # 85% normal paths, 15% sensitive (still labeled 0 — one access is baseline)
    path = random.choice(NORMAL_PATHS) if random.random() < 0.85 else random.choice(SENSITIVE_PATHS)

    event = base_event("file_access", user=user, ip=ip)
    event.update({
        "file_path":    path,
        "operation":    random.choice(FILE_OPERATIONS),
        "file_size_kb": random.randint(1, 5120),
        "process_name": random.choice(PROCESSES),
        "outcome":      "success",
        "bytes_read":   random.randint(0, 1_000_000),
        "bytes_written": 0 if random.random() > 0.3 else random.randint(0, 500_000),
    })
    return event


def generate_admin_access() -> dict:
    """
    Administrative action event performed by a privileged user.
    These are normal but infrequent; the ML model should learn
    their baseline rate and flag spikes.
    """
    user = random.choice(ADMIN_USERS)
    ip   = random.choice(INTERNAL_IPS)

    operation = random.choice(ADMIN_OPERATIONS)

    event = base_event("admin_access", user=user, ip=ip)
    event.update({
        "operation":       operation,
        "target_resource": _resource_for_operation(operation),
        "process_name":    random.choice(["sudo", "bash", "ansible", "terraform"]),
        "privilege_level": "admin",
        "mfa_verified":    True,
        "outcome":         "success",
        "change_ticket":   f"CHG-{random.randint(1000, 9999)}",
    })
    return event


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resource_for_operation(operation: str) -> str:
    resource_map = {
        "user_created":          f"user:{random.choice(NORMAL_USERS)}",
        "user_deleted":          f"user:{random.choice(NORMAL_USERS)}",
        "group_modified":        random.choice(["sudo", "docker", "www-data"]),
        "firewall_rule_changed": f"rule:allow-{random.randint(8000,9999)}/tcp",
        "service_restarted":     random.choice(["nginx", "sshd", "postgresql"]),
        "sudo_command":          random.choice(["apt upgrade", "systemctl restart nginx", "tail /var/log/syslog"]),
        "cron_job_added":        f"/etc/cron.d/job_{random.randint(100,999)}",
        "package_installed":     random.choice(["openssl", "htop", "vim", "python3-pip"]),
    }
    return resource_map.get(operation, "unknown_resource")
