"""
Feature Catalogue — AI Threat Hunting & Incident Response Platform

Authoritative reference for every feature produced by FeaturePipeline.
Used by:
  - The ML training scripts (to select feature subsets by category)
  - The SOC dashboard (to display human-readable alert explanations)
  - Model interpretability tooling (SHAP, LIME)

Each entry records:
  name         — exact column name produced by FeaturePipeline
  category     — A (event-level), B (user-window), C (IP-window),
                  D (temporal), E (timing)
  dtype        — binary | count | ratio | continuous | encoded
  attack_signal — which attack pattern this feature primarily detects
  description  — plain-English explanation for SOC analysts
"""

FEATURE_CATALOGUE: list[dict] = [

    # ─────────────────────────────────────────────────────────────────────
    # A. Event-level features
    # ─────────────────────────────────────────────────────────────────────
    {
        "name": "is_login_failed",
        "category": "A",
        "dtype": "binary",
        "attack_signal": "brute_force, credential_stuffing",
        "description": (
            "Set to 1 for login_failed events. A single failure is normal; "
            "the count features built on top of this flag are what trigger alerts."
        ),
    },
    {
        "name": "is_login_success",
        "category": "A",
        "dtype": "binary",
        "attack_signal": "post_brute_force_access",
        "description": "Successful authentication. Meaningful in sequence with prior failures.",
    },
    {
        "name": "is_file_access",
        "category": "A",
        "dtype": "binary",
        "attack_signal": "data_exfiltration",
        "description": "File read/write/delete event.",
    },
    {
        "name": "is_admin_access",
        "category": "A",
        "dtype": "binary",
        "attack_signal": "privilege_escalation",
        "description": "Administrative action. Rare in normal operations; spikes indicate abuse.",
    },
    {
        "name": "is_password_change",
        "category": "A",
        "dtype": "binary",
        "attack_signal": "persistence, cover_tracks",
        "description": "Password changed. Attackers change passwords to maintain access or cover tracks.",
    },
    {
        "name": "is_external_ip",
        "category": "A",
        "dtype": "binary",
        "attack_signal": "external_intrusion",
        "description": (
            "Source IP is outside the 10.x.x.x internal range. "
            "External IPs conducting sensitive operations are high-risk."
        ),
    },
    {
        "name": "is_suspicious_ip",
        "category": "A",
        "dtype": "binary",
        "attack_signal": "known_threat_actor",
        "description": "IP matches the threat-intel feed of known-bad addresses (Tor exits, scanners).",
    },
    {
        "name": "is_suspicious_country",
        "category": "A",
        "dtype": "binary",
        "attack_signal": "geo_anomaly",
        "description": "GeoIP origin is in a high-risk country (RU, CN, KP, IR, SY).",
    },
    {
        "name": "is_sensitive_file",
        "category": "A",
        "dtype": "binary",
        "attack_signal": "credential_access, data_exfiltration",
        "description": (
            "File path is in the sensitive set (/etc/shadow, SSH keys, etc.). "
            "Any access to these paths warrants scrutiny."
        ),
    },
    {
        "name": "is_high_risk_process",
        "category": "A",
        "dtype": "binary",
        "attack_signal": "lateral_movement, command_and_control",
        "description": "Process triggering the event (sudo, bash, curl, nmap) is commonly abused by attackers.",
    },
    {
        "name": "mfa_absent",
        "category": "A",
        "dtype": "binary",
        "attack_signal": "account_takeover",
        "description": "MFA was not used. Combined with an external IP or off-hours flag, this is a strong signal.",
    },
    {
        "name": "log_bytes_read",
        "category": "A",
        "dtype": "continuous",
        "attack_signal": "data_exfiltration",
        "description": (
            "log1p(bytes_read). Log transform reduces the influence of enormous outliers "
            "while preserving the signal that 50 MB reads are more suspicious than 50 KB reads."
        ),
    },
    {
        "name": "log_bytes_written",
        "category": "A",
        "dtype": "continuous",
        "attack_signal": "ransomware, staging",
        "description": "log1p(bytes_written). Large writes may indicate file staging or encryption.",
    },
    {
        "name": "log_file_size_kb",
        "category": "A",
        "dtype": "continuous",
        "attack_signal": "data_exfiltration",
        "description": "log1p(file_size_kb). Unusually large files being accessed correlate with bulk theft.",
    },

    # ─────────────────────────────────────────────────────────────────────
    # B. Per-user rolling window features
    # ─────────────────────────────────────────────────────────────────────
    {
        "name": "user_login_failed_count",
        "category": "B",
        "dtype": "count",
        "attack_signal": "brute_force",
        "description": (
            "Number of login_failed events by this user in the last N minutes. "
            "A single user failing 20+ times in 5 minutes is the canonical brute-force signal."
        ),
    },
    {
        "name": "user_login_success_count",
        "category": "B",
        "dtype": "count",
        "attack_signal": "post_compromise_access",
        "description": "Successful logins in the window. Multiple successes may indicate session hijacking.",
    },
    {
        "name": "user_admin_access_count",
        "category": "B",
        "dtype": "count",
        "attack_signal": "privilege_escalation",
        "description": "Admin operations in the window. Normal admins rarely need >3 admin actions in 5 minutes.",
    },
    {
        "name": "user_sensitive_file_count",
        "category": "B",
        "dtype": "count",
        "attack_signal": "credential_access, data_exfiltration",
        "description": "Reads/writes to sensitive paths in the window. Any non-zero value warrants investigation.",
    },
    {
        "name": "user_event_count",
        "category": "B",
        "dtype": "count",
        "attack_signal": "automated_attack",
        "description": "Total events from this user in the window. Very high counts indicate automated tools.",
    },
    {
        "name": "user_unique_ip_count",
        "category": "B",
        "dtype": "count",
        "attack_signal": "lateral_movement, session_hijacking",
        "description": (
            "Count of external IP events associated with this user in the window. "
            "A single user appearing from many IPs suggests stolen credentials used broadly."
        ),
    },
    {
        "name": "user_total_bytes_read",
        "category": "B",
        "dtype": "continuous",
        "attack_signal": "data_exfiltration",
        "description": "Sum of log_bytes_read for this user in the window. Large values indicate bulk data theft.",
    },
    {
        "name": "user_failure_rate",
        "category": "B",
        "dtype": "ratio",
        "attack_signal": "brute_force, credential_stuffing",
        "description": (
            "user_login_failed_count / user_event_count. "
            "Ratios above 0.8 indicate nearly all activity is failed attempts."
        ),
    },
    {
        "name": "user_admin_spike",
        "category": "B",
        "dtype": "binary",
        "attack_signal": "privilege_escalation",
        "description": "Set to 1 if user_admin_access_count > 3 in the window.",
    },

    # ─────────────────────────────────────────────────────────────────────
    # C. Per-IP rolling window features
    # ─────────────────────────────────────────────────────────────────────
    {
        "name": "ip_failed_login_count",
        "category": "C",
        "dtype": "count",
        "attack_signal": "brute_force, password_spray",
        "description": (
            "Failed logins from this IP in the window. "
            "Distinguishes a user forgetting their password (low count) "
            "from an attacker (high count from a single IP)."
        ),
    },
    {
        "name": "ip_event_count",
        "category": "C",
        "dtype": "count",
        "attack_signal": "scanning, dos",
        "description": "Total events from this IP in the window. Scanners and DoS tools generate very high counts.",
    },
    {
        "name": "ip_unique_user_count",
        "category": "C",
        "dtype": "count",
        "attack_signal": "password_spray",
        "description": (
            "Number of distinct users targeted by this IP in the window. "
            "Password spraying sends one attempt to many users to avoid lockouts. "
            "This feature directly catches that pattern."
        ),
    },
    {
        "name": "ip_total_bytes_read",
        "category": "C",
        "dtype": "continuous",
        "attack_signal": "data_exfiltration",
        "description": "Sum of log_bytes_read attributed to this IP in the window.",
    },
    {
        "name": "ip_brute_force_flag",
        "category": "C",
        "dtype": "binary",
        "attack_signal": "brute_force",
        "description": "Set to 1 if ip_failed_login_count > 20. Deterministic rule baked into the feature space.",
    },
    {
        "name": "ip_spray_flag",
        "category": "C",
        "dtype": "binary",
        "attack_signal": "password_spray",
        "description": "Set to 1 if ip_unique_user_count > 5. Flags classic horizontal password spray.",
    },

    # ─────────────────────────────────────────────────────────────────────
    # D. Temporal features
    # ─────────────────────────────────────────────────────────────────────
    {
        "name": "is_weekend",
        "category": "D",
        "dtype": "binary",
        "attack_signal": "timing_evasion",
        "description": "Event occurred on Saturday or Sunday. Attackers prefer weekends when SOC staffing is lower.",
    },
    {
        "name": "is_after_hours",
        "category": "D",
        "dtype": "binary",
        "attack_signal": "timing_evasion",
        "description": "Event occurred before 07:00 or after 20:00 UTC. Strong signal for external attacker time zones.",
    },
    {
        "name": "hour_sin",
        "category": "D",
        "dtype": "encoded",
        "attack_signal": "temporal_anomaly",
        "description": (
            "Sine encoding of hour_of_day (0–23). "
            "Cyclical encoding ensures the model knows that hour 23 and hour 0 are adjacent, "
            "which a raw integer would not convey."
        ),
    },
    {
        "name": "hour_cos",
        "category": "D",
        "dtype": "encoded",
        "attack_signal": "temporal_anomaly",
        "description": "Cosine encoding of hour_of_day. Used together with hour_sin for full cyclical representation.",
    },
    {
        "name": "dow_sin",
        "category": "D",
        "dtype": "encoded",
        "attack_signal": "temporal_anomaly",
        "description": "Sine encoding of day_of_week (0=Monday … 6=Sunday).",
    },
    {
        "name": "dow_cos",
        "category": "D",
        "dtype": "encoded",
        "attack_signal": "temporal_anomaly",
        "description": "Cosine encoding of day_of_week.",
    },

    # ─────────────────────────────────────────────────────────────────────
    # E. Inter-event timing features
    # ─────────────────────────────────────────────────────────────────────
    {
        "name": "log_user_time_delta",
        "category": "E",
        "dtype": "continuous",
        "attack_signal": "automated_attack, brute_force",
        "description": (
            "log1p(seconds since this user's last event). "
            "A human clicking through a web portal generates deltas of several seconds. "
            "A brute-force script generates deltas of milliseconds."
        ),
    },
    {
        "name": "log_ip_time_delta",
        "category": "E",
        "dtype": "continuous",
        "attack_signal": "scanning, brute_force",
        "description": (
            "log1p(seconds since last event from this IP). "
            "Port scanners and credential stuffers generate extremely small inter-event intervals."
        ),
    },
    {
        "name": "user_rapid_fire",
        "category": "E",
        "dtype": "binary",
        "attack_signal": "automated_attack",
        "description": "Set to 1 if consecutive events from this user are less than 1 second apart.",
    },
    {
        "name": "ip_rapid_fire",
        "category": "E",
        "dtype": "binary",
        "attack_signal": "scanning, brute_force",
        "description": "Set to 1 if consecutive events from this IP are less than 1 second apart.",
    },
]


def get_features_by_category(category: str) -> list[dict]:
    """Return all features in a given category (A–E)."""
    return [f for f in FEATURE_CATALOGUE if f["category"] == category]


def get_features_by_signal(signal: str) -> list[dict]:
    """Return features that flag a given attack signal (partial match)."""
    return [f for f in FEATURE_CATALOGUE if signal.lower() in f["attack_signal"].lower()]


def feature_names_by_category(category: str) -> list[str]:
    return [f["name"] for f in get_features_by_category(category)]


def print_catalogue() -> None:
    """Pretty-print the full catalogue for CLI / notebook inspection."""
    cats = {"A": "Event-level", "B": "User-window", "C": "IP-window", "D": "Temporal", "E": "Timing"}
    for cat, label in cats.items():
        features = get_features_by_category(cat)
        print(f"\n{'─'*60}")
        print(f"  {label} features ({cat})  —  {len(features)} total")
        print(f"{'─'*60}")
        for f in features:
            print(f"  {f['name']:<35} [{f['dtype']:<12}]  {f['attack_signal']}")


if __name__ == "__main__":
    print_catalogue()
