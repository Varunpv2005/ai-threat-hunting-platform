"""
Incident Correlator — AI Threat Hunting & Incident Response Platform
=====================================================================

Takes the stream of individual ThreatRecords (one per anomalous event) and
groups them into unified Incidents when they share:

  • The same source IP   — within `ip_window_minutes`   (default 30 min)
  • The same username    — within `user_window_minutes`  (default 60 min)
  • The same host        — within `host_window_minutes`  (default 20 min)

Severity escalation
───────────────────
An Incident's severity is the *maximum* severity of its constituent threats,
with one escalation rule: if 3+ CRITICAL threats share the same actor,
the incident is elevated to CRITICAL regardless of individual severities.

Attack campaign detection
─────────────────────────
If an actor (IP or user) triggers threats across 3+ distinct categories
within 2 hours, the incident is flagged as a coordinated campaign with
extra urgency metadata.

Output
──────
  Incident
    incident_id          UUID
    created_at           ISO timestamp
    updated_at           ISO timestamp
    actor_ip             source IP (may be None if user-only correlation)
    actor_user           username (may be None if IP-only correlation)
    actor_host           hostname (may be None)
    severity             escalated severity
    status               new | investigating | contained | resolved
    threat_count         number of constituent ThreatRecords
    category_breakdown   {category: count}
    primary_category     most frequent category
    mitre_techniques     deduplicated union across all threats
    anomaly_scores       [score, ...] sorted descending
    peak_score           max anomaly_score
    mean_score           mean anomaly_score
    threat_ids           [threat_id, ...]
    timeline             [{timestamp, category, severity, score}, ...]
    is_campaign          bool — multi-category coordinated attack flag
    campaign_categories  list of distinct categories (if is_campaign)
    escalation_reason    human-readable reason for severity escalation
    recommended_actions  list of suggested SOAR actions given full picture
    duration_seconds     span from first to last threat in window
"""

from __future__ import annotations

import logging
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Severity ordering helper
# ─────────────────────────────────────────────────────────────────────────────

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEV_FROM_RANK = {v: k for k, v in SEV_RANK.items()}

def _max_sev(*sevs: str) -> str:
    return SEV_FROM_RANK[max(SEV_RANK.get(s, 0) for s in sevs)]


# ─────────────────────────────────────────────────────────────────────────────
# Incident dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Incident:
    incident_id:          str
    created_at:           str
    updated_at:           str
    actor_ip:             Optional[str]
    actor_user:           Optional[str]
    actor_host:           Optional[str]
    severity:             str
    status:               str           # new | investigating | contained | resolved
    threat_count:         int
    category_breakdown:   dict          # {category: count}
    primary_category:     str
    mitre_techniques:     list[str]
    anomaly_scores:       list[float]
    peak_score:           float
    mean_score:           float
    threat_ids:           list[str]
    timeline:             list[dict]
    is_campaign:          bool
    campaign_categories:  list[str]
    escalation_reason:    str
    recommended_actions:  list[str]
    duration_seconds:     float

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


# ─────────────────────────────────────────────────────────────────────────────
# Correlation key
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _Window:
    """Active correlation window for a single actor dimension."""
    incident_id: str
    threats:     list[dict]
    first_seen:  datetime
    last_seen:   datetime
    actor_ip:    Optional[str]
    actor_user:  Optional[str]
    actor_host:  Optional[str]


# ─────────────────────────────────────────────────────────────────────────────
# Recommended action matrix
# ─────────────────────────────────────────────────────────────────────────────

_ACTIONS_BY_CATEGORY: dict[str, list[str]] = {
    "brute_force":          ["block_ip", "disable_user", "send_alert", "enforce_mfa"],
    "privilege_escalation": ["disable_user", "quarantine_host", "rotate_credentials", "send_alert"],
    "data_exfiltration":    ["block_ip", "rate_limit_user", "rotate_credentials", "send_alert"],
    "suspicious_login":     ["enforce_mfa", "disable_user", "send_alert"],
    "password_spray":       ["block_ip", "send_alert", "enforce_mfa"],
    "automated_scanner":    ["rate_limit_ip", "block_ip", "send_alert"],
    "unknown":              ["send_alert", "log_incident"],
}

def _recommend_actions(categories: list[str], severity: str, is_campaign: bool) -> list[str]:
    actions: list[str] = []
    seen: set[str] = set()
    # Lead with the primary category's actions
    for cat in categories:
        for a in _ACTIONS_BY_CATEGORY.get(cat, ["send_alert", "log_incident"]):
            if a not in seen:
                actions.append(a)
                seen.add(a)
    # Campaign escalation
    if is_campaign and "quarantine_host" not in seen:
        actions.append("quarantine_host")
    if severity == "CRITICAL" and "notify_user" not in seen:
        actions.append("notify_user")
    return actions


# ─────────────────────────────────────────────────────────────────────────────
# Correlator
# ─────────────────────────────────────────────────────────────────────────────

class IncidentCorrelator:
    """
    Groups individual ThreatRecords into Incidents by shared actor identity
    within sliding time windows.

    Parameters
    ----------
    ip_window_minutes   : int  — how long to keep an IP-based window open
    user_window_minutes : int  — how long to keep a user-based window open
    host_window_minutes : int  — how long to keep a host-based window open
    campaign_window_hours   : int  — look-back for multi-category campaign detection
    campaign_min_categories : int  — minimum distinct categories to flag a campaign
    critical_escalation_count: int — number of CRITICAL threats that auto-escalate
    """

    def __init__(
        self,
        ip_window_minutes:          int = 30,
        user_window_minutes:        int = 60,
        host_window_minutes:        int = 20,
        campaign_window_hours:      int = 2,
        campaign_min_categories:    int = 3,
        critical_escalation_count:  int = 3,
    ):
        self.ip_window   = timedelta(minutes=ip_window_minutes)
        self.user_window = timedelta(minutes=user_window_minutes)
        self.host_window = timedelta(minutes=host_window_minutes)
        self.campaign_window = timedelta(hours=campaign_window_hours)
        self.campaign_min    = campaign_min_categories
        self.critical_count  = critical_escalation_count

        # Active windows: {dimension_key: _Window}
        # dimension_key = ("ip", "1.2.3.4") | ("user", "alice") | ("host", "server-01")
        self._windows: dict[tuple, _Window] = {}

        # Completed incidents indexed by incident_id
        self._incidents: dict[str, Incident]  = {}

        # Map: threat_id → incident_id (for deduplication)
        self._threat_to_incident: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, threat: dict) -> Optional[Incident]:
        """
        Correlate a single ThreatRecord dict (as produced by DataStore._make_threat).

        Returns the Incident this threat was added to (existing or newly created),
        or None if the threat was deduplicated.
        """
        threat_id = threat.get("threat_id", "")
        if threat_id in self._threat_to_incident:
            logger.debug("Threat %s already correlated — skipping", threat_id)
            return None

        ts = self._parse_ts(threat.get("timestamp", ""))
        source_ip = threat.get("source_ip") or None
        username  = threat.get("username")  or None
        hostname  = threat.get("hostname")  or None

        # Expire stale windows before checking
        self._expire_windows(ts)

        # Find or create a window for this threat
        window = self._find_window(source_ip, username, hostname, ts)

        if window is None:
            window = _Window(
                incident_id=str(uuid.uuid4()),
                threats=[],
                first_seen=ts,
                last_seen=ts,
                actor_ip=source_ip,
                actor_user=username,
                actor_host=hostname,
            )
            self._register_window(window, source_ip, username, hostname)

        # Append threat to window
        window.threats.append(threat)
        window.last_seen = ts
        # Extend the window's actor fields if previously unknown
        if source_ip and window.actor_ip is None:
            window.actor_ip = source_ip
        if username and window.actor_user is None:
            window.actor_user = username
        if hostname and window.actor_host is None:
            window.actor_host = hostname

        self._threat_to_incident[threat_id] = window.incident_id

        # Build / update the Incident object
        incident = self._build_incident(window)
        self._incidents[window.incident_id] = incident

        logger.info(
            "Correlated threat %s → incident %s  (%s threats, %s severity)",
            threat_id[:8], window.incident_id[:8],
            incident.threat_count, incident.severity,
        )
        return incident

    def ingest_batch(self, threats: list[dict]) -> list[Incident]:
        """Ingest multiple threats, returning the list of unique incidents touched."""
        seen_ids: set[str] = set()
        results:  list[Incident] = []
        for t in sorted(threats, key=lambda x: x.get("timestamp", "")):
            inc = self.ingest(t)
            if inc and inc.incident_id not in seen_ids:
                results.append(inc)
                seen_ids.add(inc.incident_id)
        return results

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def get_all_incidents(
        self,
        severity:   Optional[str] = None,
        status:     Optional[str] = None,
        is_campaign: Optional[bool] = None,
    ) -> list[Incident]:
        rows = list(self._incidents.values())
        if severity:
            rows = [i for i in rows if i.severity == severity.upper()]
        if status:
            rows = [i for i in rows if i.status == status]
        if is_campaign is not None:
            rows = [i for i in rows if i.is_campaign == is_campaign]
        return sorted(rows, key=lambda i: i.peak_score, reverse=True)

    def update_status(self, incident_id: str, status: str) -> Optional[Incident]:
        if incident_id not in self._incidents:
            return None
        self._incidents[incident_id].status = status
        self._incidents[incident_id].updated_at = _now()
        return self._incidents[incident_id]

    def stats(self) -> dict:
        incidents = list(self._incidents.values())
        sev_c  = Counter(i.severity for i in incidents)
        stat_c = Counter(i.status   for i in incidents)
        return {
            "total_incidents":  len(incidents),
            "campaigns":        sum(1 for i in incidents if i.is_campaign),
            "by_severity":      dict(sev_c),
            "by_status":        dict(stat_c),
            "avg_threats_per_incident": (
                round(sum(i.threat_count for i in incidents) / max(len(incidents), 1), 1)
            ),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ts(ts_str: str) -> datetime:
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return datetime.now(timezone.utc)

    def _expire_windows(self, now: datetime) -> None:
        stale = []
        for key, win in self._windows.items():
            dim = key[0]
            limit = {
                "ip":   self.ip_window,
                "user": self.user_window,
                "host": self.host_window,
            }.get(dim, self.user_window)
            if now - win.last_seen > limit:
                stale.append(key)
        for key in stale:
            del self._windows[key]

    def _find_window(
        self,
        ip: Optional[str],
        user: Optional[str],
        host: Optional[str],
        ts: datetime,
    ) -> Optional[_Window]:
        """Return the first active window that shares any actor dimension."""
        for dim, value in [("ip", ip), ("user", user), ("host", host)]:
            if not value:
                continue
            key = (dim, value)
            if key in self._windows:
                win = self._windows[key]
                # Double-check it's still within the active window
                limit = {
                    "ip": self.ip_window, "user": self.user_window,
                    "host": self.host_window,
                }[dim]
                if ts - win.last_seen <= limit:
                    return win
        return None

    def _register_window(
        self,
        window: _Window,
        ip: Optional[str],
        user: Optional[str],
        host: Optional[str],
    ) -> None:
        if ip:   self._windows[("ip",   ip)]   = window
        if user: self._windows[("user", user)] = window
        if host: self._windows[("host", host)] = window

    def _build_incident(self, window: _Window) -> Incident:
        threats = window.threats
        ts_list = [self._parse_ts(t.get("timestamp", "")) for t in threats]

        # Category breakdown
        categories = [t.get("threat_category", "unknown") for t in threats]
        cat_count  = Counter(categories)
        primary    = cat_count.most_common(1)[0][0]

        # Severity
        severities = [t.get("severity", "LOW") for t in threats]
        base_sev   = _max_sev(*severities)

        # Escalation logic
        escalation_reason = ""
        critical_count = severities.count("CRITICAL")
        if critical_count >= self.critical_count:
            base_sev = "CRITICAL"
            escalation_reason = (
                f"Escalated: {critical_count} CRITICAL threats from same actor"
            )

        # Campaign detection
        distinct_cats = list(set(categories))
        duration_h    = 0.0
        if ts_list:
            span = (max(ts_list) - min(ts_list)).total_seconds()
            duration_h = span / 3600
        is_campaign = (
            len(distinct_cats) >= self.campaign_min
            and duration_h <= self.campaign_window.total_seconds() / 3600
        )
        if is_campaign:
            base_sev = "CRITICAL"
            if not escalation_reason:
                escalation_reason = (
                    f"Campaign: {len(distinct_cats)} attack categories in "
                    f"{duration_h:.1f}h from same actor"
                )

        # MITRE techniques (deduplicated, order-preserving)
        seen_m: set[str] = set()
        mitre: list[str] = []
        for t in threats:
            for tech in t.get("mitre_techniques", []):
                if tech not in seen_m:
                    mitre.append(tech)
                    seen_m.add(tech)

        # Scores
        scores = sorted(
            [t.get("anomaly_score", 0.0) for t in threats], reverse=True
        )

        # Timeline (chronological, last 20 entries)
        timeline = sorted(
            [
                {
                    "timestamp":  t.get("timestamp", ""),
                    "category":   t.get("threat_category", "unknown"),
                    "severity":   t.get("severity", "LOW"),
                    "score":      round(t.get("anomaly_score", 0.0), 1),
                    "source_ip":  t.get("source_ip", ""),
                    "username":   t.get("username", ""),
                }
                for t in threats
            ],
            key=lambda x: x["timestamp"],
        )[-20:]

        # Duration
        duration_s = 0.0
        if len(ts_list) >= 2:
            duration_s = (max(ts_list) - min(ts_list)).total_seconds()

        # Recommended actions — use all distinct categories
        rec_actions = _recommend_actions(
            list(dict.fromkeys(categories)),  # order-preserving dedup
            base_sev,
            is_campaign,
        )

        now = _now()
        existing = self._incidents.get(window.incident_id)

        return Incident(
            incident_id=window.incident_id,
            created_at=existing.created_at if existing else now,
            updated_at=now,
            actor_ip=window.actor_ip,
            actor_user=window.actor_user,
            actor_host=window.actor_host,
            severity=base_sev,
            status=existing.status if existing else "new",
            threat_count=len(threats),
            category_breakdown=dict(cat_count),
            primary_category=primary,
            mitre_techniques=mitre,
            anomaly_scores=scores,
            peak_score=round(max(scores, default=0.0), 2),
            mean_score=round(
                sum(scores) / max(len(scores), 1), 2
            ),
            threat_ids=[t.get("threat_id", "") for t in threats],
            timeline=timeline,
            is_campaign=is_campaign,
            campaign_categories=distinct_cats if is_campaign else [],
            escalation_reason=escalation_reason,
            recommended_actions=rec_actions,
            duration_seconds=round(duration_s, 1),
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
