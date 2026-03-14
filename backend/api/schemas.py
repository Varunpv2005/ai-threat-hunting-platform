"""
API Schemas — AI Threat Hunting & Incident Response Platform

All request and response models for the FastAPI backend.
Uses dataclasses (stdlib) with the same field structure as Pydantic BaseModel
so they drop-in replace when FastAPI is available.

In production with FastAPI installed, swap the top import:
    from pydantic import BaseModel, Field  # ← use this
    # from .schemas import *               # ← instead of dataclass versions
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
import uuid


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _uuid() -> str:
    return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────────────────────
# Shared primitives
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PaginationMeta:
    total:   int
    page:    int
    limit:   int
    pages:   int

    def to_dict(self) -> dict:
        return {"total": self.total, "page": self.page,
                "limit": self.limit, "pages": self.pages}


# ─────────────────────────────────────────────────────────────────────────────
# /logs
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LogEvent:
    event_id:    str
    timestamp:   str
    user:        str
    source_ip:   str
    event_type:  str
    geo_country: str
    hostname:    str
    label:       int       # 0=normal, 1=attack (ground truth from simulator)
    bytes_read:  int       = 0
    is_sensitive: int      = 0
    mfa_used:    Optional[str] = None
    metadata:    dict      = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class LogsResponse:
    data:       list[dict]
    pagination: dict
    filters_applied: dict


# ─────────────────────────────────────────────────────────────────────────────
# /threats
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatRecord:
    threat_id:          str
    timestamp:          str
    event_id:           str
    source_ip:          str
    username:           str
    anomaly_score:      float
    threat_category:    str
    primary_confidence: float
    severity:           str
    mitre_techniques:   list[str]
    rule_matches:       list[dict]
    is_resolved:        bool = False
    resolved_at:        Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class ThreatsResponse:
    data:            list[dict]
    pagination:      dict
    summary:         dict


# ─────────────────────────────────────────────────────────────────────────────
# /alerts
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Alert:
    alert_id:         str
    timestamp:        str
    threat_id:        str
    severity:         str
    title:            str
    description:      str
    source_ip:        str
    username:         str
    category:         str
    actions_taken:    list[str]
    action_results:   list[dict]
    status:           str          # open | acknowledged | resolved
    acknowledged_by:  Optional[str] = None
    resolved_at:      Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class AlertsResponse:
    data:       list[dict]
    pagination: dict
    counts:     dict       # by severity and status


# ─────────────────────────────────────────────────────────────────────────────
# POST /simulate_attack
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SimulateAttackRequest:
    """Request body for POST /simulate_attack"""
    attack_type:  str         # brute_force | privilege_escalation | data_exfiltration
                              # suspicious_login | password_spray | automated_scanner
    source_ip:    Optional[str]  = None   # auto-generated if omitted
    username:     Optional[str]  = None   # auto-generated if omitted
    geo_country:  Optional[str]  = None
    intensity:    str            = "medium"   # low | medium | high
    dry_run:      bool           = False      # skip response actions if True

    @classmethod
    def from_dict(cls, d: dict) -> "SimulateAttackRequest":
        return cls(
            attack_type=d.get("attack_type", "brute_force"),
            source_ip=d.get("source_ip"),
            username=d.get("username"),
            geo_country=d.get("geo_country"),
            intensity=d.get("intensity", "medium"),
            dry_run=d.get("dry_run", False),
        )


@dataclass
class SimulateAttackResponse:
    simulation_id:    str
    attack_type:      str
    events_generated: int
    anomaly_score:    float
    threat_detected:  bool
    threat_category:  str
    severity:         str
    confidence:       float
    mitre_techniques: list[str]
    actions_triggered: list[str]
    action_results:   list[dict]
    rules_fired:      list[str]
    events_sample:    list[dict]   # first 3 generated events
    timestamp:        str

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


# ─────────────────────────────────────────────────────────────────────────────
# GET /stats  (dashboard summary)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class StatsResponse:
    total_logs:       int
    total_threats:    int
    total_alerts:     int
    open_alerts:      int
    critical_count:   int
    high_count:       int
    threats_by_category: dict
    alerts_by_severity:  dict
    top_source_ips:      list[dict]
    top_targeted_users:  list[dict]
    detection_rate:      float
    timestamp:           str

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


# ─────────────────────────────────────────────────────────────────────────────
# Error envelope
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ErrorResponse:
    error:   str
    detail:  str
    status:  int

    def to_dict(self) -> dict:
        return {"error": self.error, "detail": self.detail, "status": self.status}
