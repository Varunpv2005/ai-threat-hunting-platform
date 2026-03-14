"""
Response Actions — AI Threat Hunting & Incident Response Platform

Defines every action the SOAR engine can execute.  Each action is a
self-contained class that:
  1. Validates its inputs
  2. Executes (or simulates) the remediation step
  3. Returns an ActionResult with full audit trail

In production these classes would call real APIs:
  block_ip      → firewall API / WAF rule / cloud security group
  disable_user  → Active Directory / LDAP / Okta / IAM
  send_alert    → PagerDuty / Slack / SIEM webhook
  log_incident  → Elasticsearch / SIEM / ticketing system (Jira/ServiceNow)
  quarantine    → EDR agent (CrowdStrike / Defender for Endpoint)
  rotate_creds  → Vault / AWS IAM / Azure AD

For this implementation the execution layer is simulated with realistic
logging so the control flow, audit trail, and rule engine are fully
functional.  Swap _execute() bodies to connect real APIs.
"""

import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Enums & result types
# ─────────────────────────────────────────────────────────────────────────────

class ActionStatus(str, Enum):
    SUCCESS   = "success"
    FAILED    = "failed"
    SKIPPED   = "skipped"     # dry-run or cooldown
    SIMULATED = "simulated"   # sandbox / test mode


class ActionType(str, Enum):
    BLOCK_IP          = "block_ip"
    DISABLE_USER      = "disable_user"
    SEND_ALERT        = "send_alert"
    LOG_INCIDENT      = "log_incident"
    QUARANTINE_HOST   = "quarantine_host"
    ROTATE_CREDENTIALS= "rotate_credentials"
    RATE_LIMIT_USER   = "rate_limit_user"
    RATE_LIMIT_IP     = "rate_limit_ip"
    ENFORCE_MFA       = "enforce_mfa"
    NOTIFY_USER       = "notify_user"


@dataclass
class ActionResult:
    """Immutable audit record produced by every action execution."""
    action_id:    str
    action_type:  ActionType
    status:       ActionStatus
    target:       str                  # IP address / username / host
    timestamp:    str
    duration_ms:  float
    message:      str
    metadata:     dict[str, Any] = field(default_factory=dict)
    error:        Optional[str]  = None

    def to_dict(self) -> dict:
        return {
            "action_id":   self.action_id,
            "action_type": self.action_type.value,
            "status":      self.status.value,
            "target":      self.target,
            "timestamp":   self.timestamp,
            "duration_ms": self.duration_ms,
            "message":     self.message,
            "metadata":    self.metadata,
            "error":       self.error,
        }

    def __str__(self) -> str:
        icon = {"success":"✅","failed":"❌","skipped":"⏭️","simulated":"🔵"}
        return (f"[{icon.get(self.status.value,'?')} {self.status.value.upper():<9}] "
                f"{self.action_type.value:<22} → {self.target}  ({self.duration_ms:.1f}ms)")


# ─────────────────────────────────────────────────────────────────────────────
# Base action
# ─────────────────────────────────────────────────────────────────────────────

class BaseAction(ABC):
    """
    Abstract base for all response actions.

    Subclasses implement _execute() which is called by run().
    run() handles timing, error catching, audit logging, and
    simulation-mode short-circuiting.
    """

    action_type: ActionType   # must be set by subclass

    def __init__(self, simulate: bool = True):
        self.simulate = simulate

    def run(self, target: str, context: dict[str, Any]) -> ActionResult:
        action_id = str(uuid.uuid4())[:8]
        ts        = datetime.now(timezone.utc).isoformat()
        t0        = time.perf_counter()

        try:
            if self.simulate:
                msg, meta = self._simulate(target, context)
                status    = ActionStatus.SIMULATED
            else:
                msg, meta = self._execute(target, context)
                status    = ActionStatus.SUCCESS

            duration_ms = (time.perf_counter() - t0) * 1000
            result = ActionResult(
                action_id=action_id, action_type=self.action_type,
                status=status, target=target, timestamp=ts,
                duration_ms=duration_ms, message=msg, metadata=meta,
            )

        except Exception as exc:
            duration_ms = (time.perf_counter() - t0) * 1000
            result = ActionResult(
                action_id=action_id, action_type=self.action_type,
                status=ActionStatus.FAILED, target=target, timestamp=ts,
                duration_ms=duration_ms,
                message=f"Action failed: {exc}",
                error=str(exc),
            )
            logger.error("[%s] %s failed for %s: %s",
                         action_id, self.action_type.value, target, exc)

        logger.info("%s", result)
        return result

    @abstractmethod
    def _execute(self, target: str, context: dict) -> tuple[str, dict]:
        """Production execution — return (message, metadata)."""

    def _simulate(self, target: str, context: dict) -> tuple[str, dict]:
        """Default simulation mirrors execute signature without side effects."""
        return (
            f"[SIMULATED] {self.action_type.value} on {target}",
            {"simulated": True, "context_keys": list(context.keys())},
        )


# ─────────────────────────────────────────────────────────────────────────────
# Concrete action implementations
# ─────────────────────────────────────────────────────────────────────────────

class BlockIPAction(BaseAction):
    """
    Block a source IP address at the network perimeter.

    Production: calls firewall API, cloud security group rule,
    or WAF IP deny-list.  Duration can be temporary (TTL-based)
    or permanent.
    """
    action_type = ActionType.BLOCK_IP

    def __init__(self, block_duration_hours: int = 24, simulate: bool = True):
        super().__init__(simulate)
        self.block_duration_hours = block_duration_hours

    def _execute(self, target: str, context: dict) -> tuple[str, dict]:
        # Production: firewall_api.add_deny_rule(ip=target, ttl_hours=self.block_duration_hours)
        reason = context.get("reason", "threat_detected")
        rule_id = f"DENY-{target.replace('.', '-')}-{int(time.time())}"
        return (
            f"IP {target} blocked for {self.block_duration_hours}h (rule {rule_id})",
            {"rule_id": rule_id, "duration_hours": self.block_duration_hours,
             "reason": reason, "ip": target},
        )

    def _simulate(self, target: str, context: dict) -> tuple[str, dict]:
        rule_id = f"DENY-{target.replace('.', '-')}-SIM"
        return (
            f"[SIM] Would block IP {target} for {self.block_duration_hours}h → rule {rule_id}",
            {"rule_id": rule_id, "duration_hours": self.block_duration_hours,
             "ip": target, "simulated": True},
        )


class DisableUserAction(BaseAction):
    """
    Disable a user account and invalidate active sessions.

    Production: LDAP modify, Okta API, or AWS IAM policy deny.
    Optionally forces password reset on re-enable.
    """
    action_type = ActionType.DISABLE_USER

    def __init__(self, force_password_reset: bool = True, simulate: bool = True):
        super().__init__(simulate)
        self.force_password_reset = force_password_reset

    def _execute(self, target: str, context: dict) -> tuple[str, dict]:
        # Production: ldap.modify(user=target, active=False) + session_store.revoke_all(target)
        ticket_id = f"ACCT-DISABLE-{target.upper()}-{int(time.time())}"
        return (
            f"User {target} disabled; all sessions revoked (ticket {ticket_id})",
            {"ticket_id": ticket_id, "username": target,
             "sessions_revoked": True,
             "force_password_reset": self.force_password_reset},
        )

    def _simulate(self, target: str, context: dict) -> tuple[str, dict]:
        return (
            f"[SIM] Would disable user {target} and revoke all sessions",
            {"username": target, "simulated": True,
             "force_password_reset": self.force_password_reset},
        )


class SendAlertAction(BaseAction):
    """
    Dispatch a security alert to the on-call team.

    Production: PagerDuty API, Slack webhook, or SIEM alert channel.
    Severity maps to PagerDuty urgency / Slack channel routing.
    """
    action_type = ActionType.SEND_ALERT

    SEVERITY_CHANNELS = {
        "CRITICAL": "#soc-critical",
        "HIGH":     "#soc-alerts",
        "MEDIUM":   "#soc-monitoring",
        "LOW":      "#soc-log",
    }

    def _execute(self, target: str, context: dict) -> tuple[str, dict]:
        severity  = context.get("severity",  "HIGH")
        category  = context.get("category",  "unknown")
        score     = context.get("anomaly_score", 0)
        channel   = self.SEVERITY_CHANNELS.get(severity, "#soc-alerts")
        alert_id  = f"ALERT-{int(time.time())}"
        return (
            f"Alert {alert_id} dispatched to {channel}: {category} on {target} (score={score:.1f})",
            {"alert_id": alert_id, "channel": channel, "severity": severity,
             "category": category, "anomaly_score": score, "target": target},
        )

    def _simulate(self, target: str, context: dict) -> tuple[str, dict]:
        severity = context.get("severity", "HIGH")
        category = context.get("category", "unknown")
        channel  = self.SEVERITY_CHANNELS.get(severity, "#soc-alerts")
        return (
            f"[SIM] Would send {severity} alert to {channel}: {category} on {target}",
            {"channel": channel, "severity": severity, "simulated": True},
        )


class LogIncidentAction(BaseAction):
    """
    Persist a structured incident record to the SIEM / ticketing system.

    Production: Elasticsearch index write + optional Jira/ServiceNow ticket.
    Every field written here feeds the SOC dashboard.
    """
    action_type = ActionType.LOG_INCIDENT

    def _execute(self, target: str, context: dict) -> tuple[str, dict]:
        incident_id = f"INC-{int(time.time())}-{str(uuid.uuid4())[:4].upper()}"
        record = {
            "incident_id":    incident_id,
            "target":         target,
            "category":       context.get("category",      "unknown"),
            "severity":       context.get("severity",      "MEDIUM"),
            "anomaly_score":  context.get("anomaly_score", 0.0),
            "mitre":          context.get("mitre_techniques", []),
            "actions_taken":  context.get("actions_taken",   []),
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "status":         "open",
        }
        # Production: es_client.index(index="incidents", document=record)
        logger.info("INCIDENT LOGGED: %s", json.dumps(record, indent=2))
        return (
            f"Incident {incident_id} created for {target}",
            record,
        )

    def _simulate(self, target: str, context: dict) -> tuple[str, dict]:
        incident_id = f"INC-SIM-{str(uuid.uuid4())[:6].upper()}"
        return (
            f"[SIM] Would log incident {incident_id} for {target}",
            {"incident_id": incident_id, "target": target, "simulated": True,
             "category": context.get("category","unknown")},
        )


class QuarantineHostAction(BaseAction):
    """
    Isolate an endpoint via EDR agent.

    Production: CrowdStrike RTR / Microsoft Defender isolate endpoint.
    Prevents lateral movement while preserving forensic state.
    """
    action_type = ActionType.QUARANTINE_HOST

    def _execute(self, target: str, context: dict) -> tuple[str, dict]:
        host       = context.get("hostname", target)
        quarantine_id = f"QRN-{host.upper()}-{int(time.time())}"
        return (
            f"Host {host} quarantined (network isolated) — ID {quarantine_id}",
            {"quarantine_id": quarantine_id, "host": host,
             "network_isolated": True, "edr_policy": "isolation_full"},
        )

    def _simulate(self, target: str, context: dict) -> tuple[str, dict]:
        host = context.get("hostname", target)
        return (f"[SIM] Would quarantine host {host}", {"host": host, "simulated": True})


class RateLimitAction(BaseAction):
    """
    Apply request rate limiting to a user or IP.

    Production: nginx / API gateway rate-limit rule, or WAF throttle policy.
    Less disruptive than a full block — appropriate for MEDIUM severity.
    """
    action_type = ActionType.RATE_LIMIT_USER

    def __init__(self, requests_per_minute: int = 5, simulate: bool = True):
        super().__init__(simulate)
        self.rpm = requests_per_minute

    def _execute(self, target: str, context: dict) -> tuple[str, dict]:
        rule_id = f"RL-{target}-{int(time.time())}"
        return (
            f"Rate limit applied: {target} → {self.rpm} req/min (rule {rule_id})",
            {"rule_id": rule_id, "target": target, "requests_per_minute": self.rpm},
        )

    def _simulate(self, target: str, context: dict) -> tuple[str, dict]:
        return (
            f"[SIM] Would rate-limit {target} to {self.rpm} req/min",
            {"target": target, "rpm": self.rpm, "simulated": True},
        )


class EnforceMFAAction(BaseAction):
    """
    Force MFA re-enrollment or step-up authentication for a user.

    Production: Okta policy update, Azure AD Conditional Access policy.
    """
    action_type = ActionType.ENFORCE_MFA

    def _execute(self, target: str, context: dict) -> tuple[str, dict]:
        policy_id = f"MFA-ENFORCE-{target.upper()}"
        return (
            f"MFA enforcement policy applied to {target} (policy {policy_id})",
            {"policy_id": policy_id, "username": target, "mfa_required": True},
        )

    def _simulate(self, target: str, context: dict) -> tuple[str, dict]:
        return (
            f"[SIM] Would enforce MFA for user {target}",
            {"username": target, "simulated": True},
        )


class RotateCredentialsAction(BaseAction):
    """
    Trigger an emergency credential rotation for a compromised account.

    Production: Vault lease revocation, AWS IAM access key rotation,
    Azure AD password reset + app token revocation.
    """
    action_type = ActionType.ROTATE_CREDENTIALS

    def _execute(self, target: str, context: dict) -> tuple[str, dict]:
        rotation_id = f"ROT-{target.upper()}-{int(time.time())}"
        return (
            f"Credentials rotated for {target} (rotation ID {rotation_id})",
            {"rotation_id": rotation_id, "username": target,
             "tokens_revoked": True, "new_password_required": True},
        )

    def _simulate(self, target: str, context: dict) -> tuple[str, dict]:
        return (
            f"[SIM] Would rotate credentials for {target}",
            {"username": target, "simulated": True},
        )


# ─────────────────────────────────────────────────────────────────────────────
# Action registry
# ─────────────────────────────────────────────────────────────────────────────

ACTION_REGISTRY: dict[str, type[BaseAction]] = {
    "block_ip":           BlockIPAction,
    "disable_user":       DisableUserAction,
    "send_alert":         SendAlertAction,
    "log_incident":       LogIncidentAction,
    "quarantine_host":    QuarantineHostAction,
    "rate_limit_user":    RateLimitAction,
    "rate_limit_ip":      RateLimitAction,
    "enforce_mfa":        EnforceMFAAction,
    "rotate_credentials": RotateCredentialsAction,
}


def build_action(name: str, simulate: bool = True, **kwargs) -> BaseAction:
    """Factory: instantiate an action by its string name."""
    cls = ACTION_REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown action: {name!r}. "
                         f"Available: {sorted(ACTION_REGISTRY)}")
    return cls(simulate=simulate, **kwargs)
