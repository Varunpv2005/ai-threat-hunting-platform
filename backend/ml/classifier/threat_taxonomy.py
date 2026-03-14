"""
Threat Taxonomy — AI Threat Hunting & Incident Response Platform

Single source of truth for:
  - All recognised threat categories and their metadata
  - Rule definitions (conditions that must be satisfied for classification)
  - MITRE ATT&CK technique mappings
  - Severity scoring weights per category
  - Recommended response actions

Every other module imports from here.  No threat logic should be
hard-coded outside this file.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class ThreatCategory(str, Enum):
    BRUTE_FORCE            = "brute_force"
    PRIVILEGE_ESCALATION   = "privilege_escalation"
    DATA_EXFILTRATION      = "data_exfiltration"
    SUSPICIOUS_LOGIN       = "suspicious_login"
    PASSWORD_SPRAY         = "password_spray"
    LATERAL_MOVEMENT       = "lateral_movement"
    INSIDER_THREAT         = "insider_threat"
    AUTOMATED_SCANNER      = "automated_scanner"
    UNKNOWN                = "unknown"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"   # 85–100  Immediate automated response
    HIGH     = "HIGH"       # 65–84   Human review within 15 min
    MEDIUM   = "MEDIUM"     # 45–64   Review within 1 hour
    LOW      = "LOW"        # 25–44   Log and monitor
    INFO     = "INFO"       # 0–24    Informational


class RuleOperator(str, Enum):
    GT  = ">"
    GTE = ">="
    LT  = "<"
    LTE = "<="
    EQ  = "=="
    NEQ = "!="


# ─────────────────────────────────────────────────────────────────────────────
# Rule primitives
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FeatureRule:
    """
    A single threshold condition on one feature.

    Example: FeatureRule("ip_failed_count", RuleOperator.GT, 20)
    reads as: ip_failed_count > 20
    """
    feature:   str
    operator:  RuleOperator
    threshold: float
    weight:    float = 1.0   # contribution to the match score

    def evaluate(self, value: float) -> bool:
        ops = {
            RuleOperator.GT:  lambda v, t: v >  t,
            RuleOperator.GTE: lambda v, t: v >= t,
            RuleOperator.LT:  lambda v, t: v <  t,
            RuleOperator.LTE: lambda v, t: v <= t,
            RuleOperator.EQ:  lambda v, t: v == t,
            RuleOperator.NEQ: lambda v, t: v != t,
        }
        return ops[self.operator](value, self.threshold)


@dataclass
class ThreatRule:
    """
    A named rule that classifies an event into a ThreatCategory.

    A rule fires when at least `min_conditions` of its `conditions` evaluate
    to True for the event's feature vector.  Using min_conditions < len(conditions)
    allows "soft" matching (e.g. 3 of 5 signals present).
    """
    name:            str
    category:        ThreatCategory
    conditions:      list[FeatureRule]
    min_conditions:  int             = 2     # how many must pass
    base_severity:   Severity        = Severity.MEDIUM
    confidence_boost: float          = 0.0   # added to confidence when rule fires
    description:     str             = ""
    mitre_techniques: list[str]      = field(default_factory=list)
    recommended_actions: list[str]   = field(default_factory=list)

    def match_score(self, features: dict[str, float]) -> float:
        """
        Return a weighted match score in [0.0, 1.0].
        0.0 = rule did not fire.  >0 = proportion of weighted conditions met.
        """
        total_weight = sum(c.weight for c in self.conditions)
        if total_weight == 0:
            return 0.0

        matched_weight = 0.0
        matched_count  = 0

        for cond in self.conditions:
            val = features.get(cond.feature, 0.0)
            if cond.evaluate(val):
                matched_weight += cond.weight
                matched_count  += 1

        if matched_count < self.min_conditions:
            return 0.0                         # threshold not reached

        return matched_weight / total_weight   # normalised weighted score


# ─────────────────────────────────────────────────────────────────────────────
# Rule registry
# ─────────────────────────────────────────────────────────────────────────────

GT  = RuleOperator.GT
GTE = RuleOperator.GTE
LT  = RuleOperator.LT
LTE = RuleOperator.LTE
EQ  = RuleOperator.EQ

THREAT_RULES: list[ThreatRule] = [

    # ── 1. Brute Force ────────────────────────────────────────────────────────
    ThreatRule(
        name="brute_force_high_volume",
        category=ThreatCategory.BRUTE_FORCE,
        base_severity=Severity.HIGH,
        min_conditions=2,
        confidence_boost=0.20,
        description=(
            "Detects rapid, high-volume failed authentication attempts from a "
            "single IP, the hallmark signature of an automated brute-force tool."
        ),
        mitre_techniques=["T1110.001", "T1110.003"],
        recommended_actions=[
            "block_source_ip",
            "lock_target_account",
            "alert_analyst",
            "create_incident_ticket",
        ],
        conditions=[
            FeatureRule("ip_failed_login_count",   GT,  20,  weight=2.0),
            FeatureRule("user_login_failed_count",  GT,  10,  weight=1.5),
            FeatureRule("user_failure_rate",        GT,  0.7, weight=1.5),
            FeatureRule("ip_rapid_fire",            GTE, 1,   weight=1.0),
            FeatureRule("user_rapid_fire",          GTE, 1,   weight=1.0),
            FeatureRule("is_external_ip",           GTE, 1,   weight=0.5),
        ],
    ),

    ThreatRule(
        name="brute_force_credential_stuffing",
        category=ThreatCategory.BRUTE_FORCE,
        base_severity=Severity.HIGH,
        min_conditions=2,
        confidence_boost=0.15,
        description=(
            "Credential stuffing: large lists of known username/password combos "
            "are tried. Characterised by external origin and high failure rate."
        ),
        mitre_techniques=["T1110.004"],
        recommended_actions=[
            "block_source_ip",
            "enforce_mfa",
            "alert_analyst",
        ],
        conditions=[
            FeatureRule("is_external_ip",          GTE, 1,   weight=1.5),
            FeatureRule("is_suspicious_country",   GTE, 1,   weight=1.5),
            FeatureRule("user_failure_rate",        GT,  0.8, weight=2.0),
            FeatureRule("mfa_absent",               GTE, 1,   weight=1.0),
            FeatureRule("ip_failed_login_count",   GT,  15,  weight=1.5),
        ],
    ),

    # ── 2. Password Spray ─────────────────────────────────────────────────────
    ThreatRule(
        name="password_spray",
        category=ThreatCategory.PASSWORD_SPRAY,
        base_severity=Severity.HIGH,
        min_conditions=2,
        confidence_boost=0.25,
        description=(
            "Password spray: one password attempt per account across many users. "
            "Keeps per-account failure counts below lockout thresholds. "
            "Key signal: one IP targeting many distinct users."
        ),
        mitre_techniques=["T1110.003"],
        recommended_actions=[
            "block_source_ip",
            "enforce_mfa_all_users",
            "alert_analyst",
            "create_incident_ticket",
        ],
        conditions=[
            FeatureRule("ip_spray_flag",           GTE, 1,   weight=3.0),
            FeatureRule("ip_unique_user_count",    GT,  5,   weight=2.0),
            FeatureRule("is_external_ip",          GTE, 1,   weight=1.0),
            FeatureRule("ip_failed_login_count",   GT,  3,   weight=1.0),
        ],
    ),

    # ── 3. Privilege Escalation ───────────────────────────────────────────────
    ThreatRule(
        name="privilege_escalation_sudo_abuse",
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        base_severity=Severity.CRITICAL,
        min_conditions=2,
        confidence_boost=0.30,
        description=(
            "A non-admin user accumulates admin_access events rapidly, "
            "suggesting sudo abuse or exploitation of a SUID binary."
        ),
        mitre_techniques=["T1548.003", "T1078"],
        recommended_actions=[
            "disable_user_account",
            "isolate_endpoint",
            "alert_analyst",
            "create_incident_ticket",
            "capture_forensic_snapshot",
        ],
        conditions=[
            FeatureRule("user_admin_access_count", GT,  3,   weight=2.0),
            FeatureRule("user_admin_spike",        GTE, 1,   weight=2.5),
            FeatureRule("is_high_risk_process",    GTE, 1,   weight=1.5),
            FeatureRule("mfa_absent",              GTE, 1,   weight=1.0),
            FeatureRule("is_sensitive_file",       GTE, 1,   weight=1.0),
        ],
    ),

    ThreatRule(
        name="privilege_escalation_sensitive_access",
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        base_severity=Severity.CRITICAL,
        min_conditions=2,
        confidence_boost=0.20,
        description=(
            "User reads credential stores or private key files. "
            "Even a single access to /etc/shadow or SSH private keys by a "
            "non-root account is a critical signal."
        ),
        mitre_techniques=["T1003", "T1552"],
        recommended_actions=[
            "alert_analyst",
            "disable_user_account",
            "rotate_credentials",
            "create_incident_ticket",
        ],
        conditions=[
            FeatureRule("is_sensitive_file",        GTE, 1,   weight=3.0),
            FeatureRule("user_sensitive_file_count", GT,  1,   weight=2.0),
            FeatureRule("is_high_risk_process",     GTE, 1,   weight=1.5),
            FeatureRule("mfa_absent",               GTE, 1,   weight=0.5),
        ],
    ),

    # ── 4. Data Exfiltration ──────────────────────────────────────────────────
    ThreatRule(
        name="data_exfiltration_bulk_read",
        category=ThreatCategory.DATA_EXFILTRATION,
        base_severity=Severity.CRITICAL,
        min_conditions=2,
        confidence_boost=0.35,
        description=(
            "Abnormally large total bytes read by a single user in a short window, "
            "combined with access to sensitive file paths."
        ),
        mitre_techniques=["T1005", "T1025"],
        recommended_actions=[
            "rate_limit_user",
            "alert_analyst",
            "block_outbound_transfer",
            "create_incident_ticket",
            "capture_forensic_snapshot",
        ],
        conditions=[
            FeatureRule("user_total_bytes_read",    GT,  10.0, weight=2.0),  # log-scaled
            FeatureRule("log_bytes_read",           GT,  13.0, weight=1.5),  # ~440 KB
            FeatureRule("is_sensitive_file",        GTE, 1,    weight=2.0),
            FeatureRule("user_sensitive_file_count",GT,  2,    weight=1.5),
            FeatureRule("log_file_size_kb",         GT,  8.5,  weight=1.0),  # ~5 MB
        ],
    ),

    ThreatRule(
        name="data_exfiltration_high_process_volume",
        category=ThreatCategory.DATA_EXFILTRATION,
        base_severity=Severity.HIGH,
        min_conditions=2,
        confidence_boost=0.15,
        description=(
            "Bulk file operations via high-risk transfer tools (rsync, scp, curl, wget). "
            "Pattern consistent with staging data for exfiltration."
        ),
        mitre_techniques=["T1048", "T1041"],
        recommended_actions=[
            "alert_analyst",
            "block_outbound_transfer",
            "rate_limit_user",
        ],
        conditions=[
            FeatureRule("is_high_risk_process",     GTE, 1,    weight=2.0),
            FeatureRule("log_bytes_read",           GT,  11.0, weight=1.5),  # ~60 KB
            FeatureRule("user_total_bytes_read",    GT,  8.0,  weight=1.5),
            FeatureRule("is_file_access",           GTE, 1,    weight=0.5),
        ],
    ),

    # ── 5. Suspicious Login Activity ─────────────────────────────────────────
    ThreatRule(
        name="suspicious_login_geo_anomaly",
        category=ThreatCategory.SUSPICIOUS_LOGIN,
        base_severity=Severity.MEDIUM,
        min_conditions=2,
        confidence_boost=0.10,
        description=(
            "Login from a geographically suspicious origin combined with "
            "missing MFA — classic account takeover signal."
        ),
        mitre_techniques=["T1078", "T1133"],
        recommended_actions=[
            "enforce_mfa",
            "alert_user",
            "alert_analyst",
        ],
        conditions=[
            FeatureRule("is_suspicious_country",   GTE, 1,   weight=2.0),
            FeatureRule("is_external_ip",          GTE, 1,   weight=1.5),
            FeatureRule("mfa_absent",              GTE, 1,   weight=1.5),
            FeatureRule("is_login_success",        GTE, 1,   weight=1.0),
            FeatureRule("is_after_hours",          GTE, 1,   weight=0.5),
        ],
    ),

    ThreatRule(
        name="suspicious_login_off_hours",
        category=ThreatCategory.SUSPICIOUS_LOGIN,
        base_severity=Severity.LOW,
        min_conditions=2,
        confidence_boost=0.05,
        description=(
            "Successful authentication outside business hours from an external IP "
            "without MFA. Low severity in isolation; elevated when combined with "
            "other anomalies."
        ),
        mitre_techniques=["T1078"],
        recommended_actions=["alert_analyst", "enforce_mfa"],
        conditions=[
            FeatureRule("is_after_hours",          GTE, 1,   weight=1.5),
            FeatureRule("is_weekend",              GTE, 1,   weight=1.0),
            FeatureRule("is_external_ip",          GTE, 1,   weight=1.5),
            FeatureRule("mfa_absent",              GTE, 1,   weight=1.5),
            FeatureRule("is_login_success",        GTE, 1,   weight=0.5),
        ],
    ),

    # ── 6. Lateral Movement ───────────────────────────────────────────────────
    ThreatRule(
        name="lateral_movement_multi_ip",
        category=ThreatCategory.LATERAL_MOVEMENT,
        base_severity=Severity.HIGH,
        min_conditions=2,
        confidence_boost=0.20,
        description=(
            "Single user account authenticating from multiple IPs in a short window, "
            "suggesting credential sharing or an attacker pivoting between hosts."
        ),
        mitre_techniques=["T1021", "T1550"],
        recommended_actions=[
            "alert_analyst",
            "disable_user_account",
            "isolate_endpoint",
        ],
        conditions=[
            FeatureRule("user_unique_ip_count",    GT,  2,   weight=2.5),
            FeatureRule("is_external_ip",          GTE, 1,   weight=1.5),
            FeatureRule("user_login_success_count",GT,  1,   weight=1.0),
            FeatureRule("user_event_count",        GT,  5,   weight=0.5),
        ],
    ),

    # ── 7. Insider Threat ─────────────────────────────────────────────────────
    ThreatRule(
        name="insider_threat_data_staging",
        category=ThreatCategory.INSIDER_THREAT,
        base_severity=Severity.HIGH,
        min_conditions=3,
        confidence_boost=0.10,
        description=(
            "Internal IP performing bulk reads of sensitive files combined with "
            "elevated admin activity and a password change — pattern consistent "
            "with an insider preparing to leave or covering their tracks."
        ),
        mitre_techniques=["T1005", "T1078", "T1098"],
        recommended_actions=[
            "alert_analyst",
            "alert_hr",
            "rate_limit_user",
            "create_incident_ticket",
        ],
        conditions=[
            FeatureRule("is_external_ip",           EQ,  0,    weight=2.0),  # internal only
            FeatureRule("user_sensitive_file_count", GT,  2,    weight=2.0),
            FeatureRule("user_total_bytes_read",     GT,  8.0,  weight=1.5),
            FeatureRule("user_admin_access_count",   GT,  1,    weight=1.0),
            FeatureRule("is_password_change",        GTE, 1,    weight=1.5),
        ],
    ),

    # ── 8. Automated Scanner ──────────────────────────────────────────────────
    ThreatRule(
        name="automated_scanner",
        category=ThreatCategory.AUTOMATED_SCANNER,
        base_severity=Severity.MEDIUM,
        min_conditions=2,
        confidence_boost=0.15,
        description=(
            "Sub-second inter-event intervals from a single IP targeting multiple "
            "services. Consistent with automated port scanners, vulnerability "
            "scanners, or credential stuffing frameworks."
        ),
        mitre_techniques=["T1595", "T1046"],
        recommended_actions=[
            "block_source_ip",
            "alert_analyst",
            "rate_limit_ip",
        ],
        conditions=[
            FeatureRule("ip_rapid_fire",            GTE, 1,   weight=2.5),
            FeatureRule("log_ip_time_delta",        LT,  1.0, weight=2.0),  # <1 s avg
            FeatureRule("ip_event_count",           GT,  30,  weight=1.5),
            FeatureRule("is_external_ip",           GTE, 1,   weight=1.0),
            FeatureRule("is_suspicious_ip",         GTE, 1,   weight=1.5),
        ],
    ),
]

# Fast lookup by category
RULES_BY_CATEGORY: dict[ThreatCategory, list[ThreatRule]] = {}
for _rule in THREAT_RULES:
    RULES_BY_CATEGORY.setdefault(_rule.category, []).append(_rule)


# ─────────────────────────────────────────────────────────────────────────────
# Severity → score range mapping
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_SCORE_RANGES: dict[Severity, tuple[int, int]] = {
    Severity.CRITICAL: (85, 100),
    Severity.HIGH:     (65, 84),
    Severity.MEDIUM:   (45, 64),
    Severity.LOW:      (25, 44),
    Severity.INFO:     (0,  24),
}

def severity_from_score(score: float) -> Severity:
    for sev, (lo, hi) in SEVERITY_SCORE_RANGES.items():
        if lo <= score <= hi:
            return sev
    return Severity.INFO
