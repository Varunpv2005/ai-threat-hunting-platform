"""
Authentication log generators.

Produces realistic login_success, login_failed, and password_change events
with contextually appropriate metadata fields.
"""

import random
from ._fixtures import (
    base_event,
    NORMAL_USERS, ADMIN_USERS,
    INTERNAL_IPS, EXTERNAL_IPS,
)

# Auth protocols in use across the simulated environment
AUTH_PROTOCOLS = ["ssh", "rdp", "vpn", "web_portal", "ldap"]
MFA_METHODS    = ["totp", "sms", "push_notification", "hardware_key", None]
FAIL_REASONS   = [
    "invalid_password",
    "account_locked",
    "expired_credentials",
    "invalid_mfa_token",
    "unknown_user",
]


def generate_login_success() -> dict:
    """Normal successful authentication event."""
    user = random.choice(NORMAL_USERS + ADMIN_USERS)
    ip   = random.choice(INTERNAL_IPS)

    event = base_event("login_success", user=user, ip=ip)
    event.update({
        "protocol":        random.choice(AUTH_PROTOCOLS),
        "mfa_used":        random.choice(MFA_METHODS),
        "login_duration_ms": random.randint(80, 800),
        "geo_country":     "US",
        "geo_city":        random.choice(["New York", "Austin", "Seattle", "Chicago"]),
        "user_agent":      _random_user_agent(),
        "privilege_level": "admin" if user in ADMIN_USERS else "user",
    })
    return event


def generate_login_failed() -> dict:
    """
    Failed authentication event.
    May originate from external IPs to simulate credential stuffing attempts.
    """
    user = random.choice(NORMAL_USERS + ["unknown_user", "administrator", "guest"])
    # 30% chance the failure originates from an external IP
    ip = random.choice(EXTERNAL_IPS) if random.random() < 0.3 else random.choice(INTERNAL_IPS)

    event = base_event("login_failed", user=user, ip=ip)
    event.update({
        "protocol":      random.choice(AUTH_PROTOCOLS),
        "failure_reason": random.choice(FAIL_REASONS),
        "attempt_count": random.randint(1, 3),
        "geo_country":   random.choice(["US", "RU", "CN", "DE", "BR"]),
        "geo_city":      random.choice(["Unknown", "Moscow", "Shanghai", "Frankfurt"]),
        "user_agent":    _random_user_agent(),
    })
    return event


def generate_password_change() -> dict:
    """Password change event — normal administrative action."""
    user = random.choice(NORMAL_USERS)
    ip   = random.choice(INTERNAL_IPS)

    event = base_event("password_change", user=user, ip=ip)
    event.update({
        "initiated_by":    random.choice(["self", "admin_reset"]),
        "password_strength": random.choice(["strong", "medium", "weak"]),
        "mfa_verified":    random.choice([True, False]),
        "changed_via":     random.choice(["web_portal", "cli", "ldap"]),
    })
    return event


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _random_user_agent() -> str:
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "OpenSSH_8.9p1",
        "python-requests/2.31.0",
        "curl/7.88.1",
    ]
    return random.choice(agents)
