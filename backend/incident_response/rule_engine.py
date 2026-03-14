"""
Rule Engine — AI Threat Hunting & Incident Response Platform

Evaluates a declarative rule set against enriched incident context and
fires the appropriate response actions automatically.

Design principles
─────────────────
• Rules are DATA, not code.  Security analysts configure rules without
  touching Python.  Rules live in `RESPONSE_RULES` (or a JSON/YAML file
  in production) and are evaluated uniformly by the engine.

• Conditions are composable.  Each rule has `conditions` (all must pass
  for the rule to fire — logical AND) and optionally `any_conditions`
  (at least one must pass — logical OR).  Both sets can be combined.

• Actions have a priority order.  Within a fired rule, actions are
  executed in sequence so that the most protective action (block/disable)
  runs before the most expensive one (quarantine).

• Cooldowns prevent storms.  Each (rule_name, target) pair is tracked
  with a last-fired timestamp.  Re-firing within the cooldown window is
  suppressed to avoid cascading action storms.

• Dry-run mode.  Every execution can be run with `simulate=True` so that
  the full evaluation logic runs and is logged, but no real API calls are
  made.  This is the default for safety.

• Audit log.  Every rule evaluation — whether it fires or not — is
  appended to an in-memory audit log and can be exported to JSON.

Example rule (plain English → code):
  "IF failed_login_attempts > 20 THEN block IP"

  ResponseRule(
      name="brute_force_block",
      conditions=[Condition("ip_failed_login_count", ">", 20)],
      actions=["block_ip", "send_alert", "log_incident"],
  )
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .actions import (
    ActionResult,
    ActionType,
    BaseAction,
    BlockIPAction,
    DisableUserAction,
    EnforceMFAAction,
    LogIncidentAction,
    QuarantineHostAction,
    RateLimitAction,
    RotateCredentialsAction,
    SendAlertAction,
    build_action,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Condition primitives
# ─────────────────────────────────────────────────────────────────────────────

OPS = {
    ">":  lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<":  lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "in": lambda a, b: a in b,         # b must be a list/set
    "contains": lambda a, b: b in a,   # a must be a string/list
}


@dataclass
class Condition:
    """
    A single threshold condition evaluated against a context value.

    Examples
    --------
    Condition("ip_failed_login_count", ">", 20)
    Condition("threat_category",       "==", "brute_force")
    Condition("anomaly_score",         ">=", 85)
    Condition("geo_country",           "in", ["RU","CN","KP","IR"])
    """
    field:     str
    operator:  str
    value:     Any
    label:     str = ""   # human-readable explanation shown in audit log

    def evaluate(self, context: dict[str, Any]) -> bool:
        op_fn = OPS.get(self.operator)
        if op_fn is None:
            raise ValueError(f"Unknown operator: {self.operator!r}")
        ctx_value = context.get(self.field)
        if ctx_value is None:
            return False
        try:
            return bool(op_fn(ctx_value, self.value))
        except TypeError:
            return False

    def describe(self) -> str:
        if self.label:
            return self.label
        return f"{self.field} {self.operator} {self.value}"


# ─────────────────────────────────────────────────────────────────────────────
# Response rule definition
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ResponseRule:
    """
    A named rule that maps a set of conditions to a list of actions.

    Firing logic
    ────────────
    A rule FIRES when:
      • ALL conditions in `conditions` evaluate True (AND logic)
      • AND at least one condition in `any_conditions` is True,
        if `any_conditions` is non-empty (OR logic)

    Execution
    ─────────
    When fired, every action in `actions` is executed in order.
    `target_field` controls which context value is passed as the
    action target (e.g. "source_ip" → block that IP; "username" → disable that user).

    Cooldown
    ────────
    `cooldown_seconds` prevents re-firing the same rule on the same target
    within the window.  Set to 0 to disable cooldown.
    """
    name:              str
    description:       str
    conditions:        list[Condition]        # ALL must pass
    actions:           list[str]              # action names from ACTION_REGISTRY
    any_conditions:    list[Condition] = field(default_factory=list)  # at least one
    target_field:      str  = "source_ip"     # context key for the action target
    priority:          int  = 50              # 0=highest, 100=lowest
    enabled:           bool = True
    cooldown_seconds:  int  = 300             # 5 min default
    tags:              list[str] = field(default_factory=list)
    action_kwargs:     dict[str, dict] = field(default_factory=dict)  # per-action kwargs

    def matches(self, context: dict[str, Any]) -> tuple[bool, list[str]]:
        """
        Evaluate all conditions.

        Returns
        -------
        (fired: bool, reasons: list[str])
            reasons lists the conditions that passed, for the audit log.
        """
        if not self.enabled:
            return False, ["rule disabled"]

        reasons: list[str] = []

        # AND conditions — all must pass
        for cond in self.conditions:
            if not cond.evaluate(context):
                return False, [f"FAILED: {cond.describe()}"]
            reasons.append(f"PASS: {cond.describe()}")

        # OR conditions — at least one must pass (if any defined)
        if self.any_conditions:
            any_passed = False
            for cond in self.any_conditions:
                if cond.evaluate(context):
                    reasons.append(f"PASS(OR): {cond.describe()}")
                    any_passed = True
            if not any_passed:
                return False, reasons + ["FAILED: no OR conditions passed"]

        return True, reasons


# ─────────────────────────────────────────────────────────────────────────────
# Built-in rule set
# ─────────────────────────────────────────────────────────────────────────────

RESPONSE_RULES: list[ResponseRule] = [

    # ── Priority 10: Critical — block first, ask questions later ─────────────

    ResponseRule(
        name="brute_force_block_ip",
        description=(
            "IF failed_login_attempts > 20 THEN block IP + alert + log incident. "
            "High-volume brute force is automated; block immediately."
        ),
        priority=10,
        cooldown_seconds=600,
        target_field="source_ip",
        tags=["brute_force", "network"],
        conditions=[
            Condition("ip_failed_login_count", ">", 20,
                      label="failed_login_attempts > 20"),
        ],
        any_conditions=[
            Condition("user_failure_rate",    ">",  0.7,  label="failure_rate > 70%"),
            Condition("ip_rapid_fire",        ">=", 1,    label="sub-second login attempts"),
            Condition("is_suspicious_country",">=", 1,    label="origin in high-risk country"),
        ],
        actions=["block_ip", "send_alert", "log_incident"],
        action_kwargs={
            "block_ip": {"block_duration_hours": 24},
        },
    ),

    ResponseRule(
        name="brute_force_disable_account",
        description=(
            "IF a specific user account has > 15 failed logins in the window "
            "THEN disable that account to prevent eventual compromise."
        ),
        priority=10,
        cooldown_seconds=3600,
        target_field="username",
        tags=["brute_force", "account"],
        conditions=[
            Condition("user_login_failed_count", ">", 15,
                      label="user failed_login_count > 15"),
            Condition("user_failure_rate",        ">", 0.8,
                      label="user failure_rate > 80%"),
        ],
        actions=["disable_user", "send_alert", "log_incident"],
        action_kwargs={
            "disable_user": {"force_password_reset": True},
        },
    ),

    # ── Priority 10: Critical — privilege escalation ──────────────────────────

    ResponseRule(
        name="privilege_escalation_full_response",
        description=(
            "IF privilege escalation detected (admin spike + sensitive file access) "
            "THEN disable account, quarantine host, rotate credentials, alert."
        ),
        priority=10,
        cooldown_seconds=3600,
        target_field="username",
        tags=["privilege_escalation", "critical"],
        conditions=[
            Condition("threat_category", "==", "privilege_escalation",
                      label="threat classified as privilege_escalation"),
            Condition("anomaly_score",   ">=", 70,
                      label="anomaly_score >= 70"),
        ],
        any_conditions=[
            Condition("user_admin_spike",         ">=", 1,   label="admin access spike"),
            Condition("user_sensitive_file_count", ">",  1,   label="sensitive files accessed"),
            Condition("is_high_risk_process",      ">=", 1,   label="high-risk process detected"),
        ],
        actions=["disable_user", "quarantine_host", "rotate_credentials",
                 "send_alert", "log_incident"],
    ),

    # ── Priority 20: High — data exfiltration ─────────────────────────────────

    ResponseRule(
        name="data_exfiltration_block_and_alert",
        description=(
            "IF data exfiltration detected (large bytes_read + sensitive files) "
            "THEN rate-limit user, block outbound IP, send CRITICAL alert."
        ),
        priority=20,
        cooldown_seconds=1800,
        target_field="source_ip",
        tags=["data_exfiltration", "network"],
        conditions=[
            Condition("threat_category", "==", "data_exfiltration",
                      label="threat classified as data_exfiltration"),
        ],
        any_conditions=[
            Condition("user_total_bytes_read",     ">",  12.0, label="large bytes_read (log-scale)"),
            Condition("user_sensitive_file_count", ">",  2,    label="> 2 sensitive files"),
        ],
        actions=["block_ip", "rate_limit_user", "send_alert", "log_incident"],
        action_kwargs={
            "block_ip": {"block_duration_hours": 72},
        },
    ),

    ResponseRule(
        name="data_exfiltration_disable_insider",
        description=(
            "IF internal IP exfiltrating data (insider threat pattern) "
            "THEN disable user account + rotate credentials."
        ),
        priority=20,
        cooldown_seconds=3600,
        target_field="username",
        tags=["data_exfiltration", "insider_threat"],
        conditions=[
            Condition("threat_category", "==", "data_exfiltration"),
            Condition("is_external_ip",  "==", 0,
                      label="source is internal IP (insider)"),
            Condition("user_sensitive_file_count", ">", 2),
        ],
        actions=["disable_user", "rotate_credentials", "send_alert", "log_incident"],
    ),

    # ── Priority 30: High — suspicious login ─────────────────────────────────

    ResponseRule(
        name="suspicious_login_enforce_mfa",
        description=(
            "IF suspicious login from high-risk country with no MFA "
            "THEN enforce MFA + alert user."
        ),
        priority=30,
        cooldown_seconds=900,
        target_field="username",
        tags=["suspicious_login", "mfa"],
        conditions=[
            Condition("threat_category",       "==", "suspicious_login"),
            Condition("mfa_absent",            ">=", 1,   label="MFA not used"),
            Condition("is_suspicious_country", ">=", 1,   label="login from high-risk country"),
        ],
        actions=["enforce_mfa", "send_alert", "log_incident"],
    ),

    ResponseRule(
        name="suspicious_login_disable_account",
        description=(
            "IF high-confidence suspicious login (score >= 85) from external IP "
            "THEN disable account immediately."
        ),
        priority=25,
        cooldown_seconds=3600,
        target_field="username",
        tags=["suspicious_login", "account"],
        conditions=[
            Condition("threat_category", "==", "suspicious_login"),
            Condition("anomaly_score",   ">=", 85,
                      label="anomaly_score >= 85 (CRITICAL)"),
            Condition("is_external_ip",  ">=", 1),
        ],
        actions=["disable_user", "send_alert", "log_incident"],
    ),

    # ── Priority 40: Medium — password spray ─────────────────────────────────

    ResponseRule(
        name="password_spray_block_ip",
        description=(
            "IF one IP targets > 5 distinct users (password spray) "
            "THEN block IP + alert."
        ),
        priority=40,
        cooldown_seconds=600,
        target_field="source_ip",
        tags=["password_spray", "network"],
        conditions=[
            Condition("ip_unique_user_count", ">", 5,
                      label="ip targets > 5 distinct users"),
            Condition("ip_spray_flag",        ">=", 1,
                      label="spray flag set by feature pipeline"),
        ],
        actions=["block_ip", "send_alert", "log_incident"],
        action_kwargs={
            "block_ip": {"block_duration_hours": 48},
        },
    ),

    # ── Priority 50: Medium — automated scanner ───────────────────────────────

    ResponseRule(
        name="automated_scanner_rate_limit",
        description=(
            "IF sub-second event rate from external IP (automated scanner) "
            "THEN rate limit IP before escalating to full block."
        ),
        priority=50,
        cooldown_seconds=300,
        target_field="source_ip",
        tags=["automated_scanner", "network"],
        conditions=[
            Condition("ip_rapid_fire",  ">=", 1,  label="sub-second event rate"),
            Condition("ip_event_count", ">",  30, label="high event volume from IP"),
            Condition("is_external_ip", ">=", 1),
        ],
        actions=["rate_limit_ip", "send_alert", "log_incident"],
        action_kwargs={
            "rate_limit_ip": {"requests_per_minute": 2},
        },
    ),

    # ── Priority 70: Low — catch-all anomaly logger ────────────────────────────

    ResponseRule(
        name="generic_anomaly_log",
        description=(
            "IF anomaly_score >= 45 but no specific category matched "
            "THEN log the incident for analyst review."
        ),
        priority=70,
        cooldown_seconds=60,
        target_field="source_ip",
        tags=["generic", "monitoring"],
        conditions=[
            Condition("anomaly_score", ">=", 45,
                      label="anomaly_score >= 45 (MEDIUM threshold)"),
        ],
        actions=["log_incident"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Audit log entry
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RuleEvaluation:
    """Record of a single rule's evaluation against a context."""
    rule_name:    str
    fired:        bool
    reasons:      list[str]
    target:       str
    action_results: list[ActionResult] = field(default_factory=list)
    timestamp:    str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    skipped_cooldown: bool = False

    def to_dict(self) -> dict:
        return {
            "rule_name":        self.rule_name,
            "fired":            self.fired,
            "reasons":          self.reasons,
            "target":           self.target,
            "timestamp":        self.timestamp,
            "skipped_cooldown": self.skipped_cooldown,
            "actions":          [a.to_dict() for a in self.action_results],
        }


@dataclass
class ResponseOutcome:
    """Full outcome of running the rule engine against one incident context."""
    context_id:    str
    rules_evaluated: int
    rules_fired:   int
    actions_taken: list[str]
    action_results: list[ActionResult]
    evaluations:   list[RuleEvaluation]
    timestamp:     str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def summary(self) -> str:
        lines = [
            f"  Context:    {self.context_id}",
            f"  Rules eval: {self.rules_evaluated}  fired: {self.rules_fired}",
            f"  Actions:    {len(self.action_results)} executed",
        ]
        for r in self.action_results:
            lines.append(f"    {r}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Rule Engine
# ─────────────────────────────────────────────────────────────────────────────

class RuleEngine:
    """
    Evaluates all ResponseRules against an incident context and executes
    the appropriate actions.

    Parameters
    ----------
    rules : list[ResponseRule]
        Rule set to evaluate.  Defaults to the built-in RESPONSE_RULES.
    simulate : bool
        If True (default), actions are simulated — full evaluation runs
        but no real API calls are made.  Set False in production.
    stop_on_first_match : bool
        If True, stop evaluating after the first rule fires per priority
        tier.  If False (default), all matching rules fire.
    max_actions_per_context : int
        Safety cap on total actions per context evaluation.
    """

    def __init__(
        self,
        rules:                   list[ResponseRule] | None = None,
        simulate:                bool = True,
        stop_on_first_match:     bool = False,
        max_actions_per_context: int  = 10,
    ):
        self._rules     = sorted(rules or RESPONSE_RULES, key=lambda r: r.priority)
        self.simulate   = simulate
        self.stop_first = stop_on_first_match
        self.max_actions = max_actions_per_context

        # cooldown tracking: (rule_name, target) → last_fired epoch
        self._cooldown_store: dict[tuple[str, str], float] = {}
        # full audit log
        self._audit_log: list[RuleEvaluation] = []

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def evaluate(self, context: dict[str, Any]) -> ResponseOutcome:
        """
        Run all rules against `context` and execute matching actions.

        `context` is an enriched dict that can contain any combination of:
          - Feature pipeline outputs  (ip_failed_login_count, anomaly_score, …)
          - ClassificationResult fields (threat_category, mitre_techniques, …)
          - Raw event fields           (source_ip, username, hostname, …)

        Returns a ResponseOutcome with full audit trail.
        """
        context_id  = context.get("event_id", str(id(context)))
        evaluations: list[RuleEvaluation] = []
        all_results: list[ActionResult]   = []
        total_actions = 0

        for rule in self._rules:
            if not rule.enabled:
                continue
            if total_actions >= self.max_actions:
                logger.warning("Action cap (%d) reached; skipping remaining rules",
                               self.max_actions)
                break

            # Get the action target from context
            target = str(context.get(rule.target_field, context.get("source_ip", "unknown")))

            # Check cooldown
            cooldown_key = (rule.name, target)
            if self._in_cooldown(cooldown_key, rule.cooldown_seconds):
                evaluations.append(RuleEvaluation(
                    rule_name=rule.name, fired=False, reasons=["in cooldown"],
                    target=target, skipped_cooldown=True,
                ))
                continue

            # Evaluate conditions
            fired, reasons = rule.matches(context)

            eval_record = RuleEvaluation(
                rule_name=rule.name, fired=fired,
                reasons=reasons, target=target,
            )

            if fired:
                logger.info("Rule FIRED: %s → target=%s", rule.name, target)
                self._cooldown_store[cooldown_key] = time.time()

                # Execute each action
                action_results = self._execute_actions(rule, target, context)
                eval_record.action_results = action_results
                all_results.extend(action_results)
                total_actions += len(action_results)

                if self.stop_first:
                    evaluations.append(eval_record)
                    self._audit_log.append(eval_record)
                    break
            else:
                logger.debug("Rule skipped: %s  reason: %s", rule.name, reasons[-1])

            evaluations.append(eval_record)
            self._audit_log.append(eval_record)

        fired_count   = sum(1 for e in evaluations if e.fired)
        actions_taken = list({r.action_type.value for r in all_results})

        return ResponseOutcome(
            context_id=context_id,
            rules_evaluated=len(evaluations),
            rules_fired=fired_count,
            actions_taken=actions_taken,
            action_results=all_results,
            evaluations=evaluations,
        )

    def evaluate_batch(self, contexts: list[dict]) -> list[ResponseOutcome]:
        """Evaluate a list of incident contexts."""
        return [self.evaluate(ctx) for ctx in contexts]

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, rule: ResponseRule) -> None:
        self._rules = sorted(self._rules + [rule], key=lambda r: r.priority)
        logger.info("Rule added: %s (priority=%d)", rule.name, rule.priority)

    def disable_rule(self, name: str) -> bool:
        for rule in self._rules:
            if rule.name == name:
                rule.enabled = False
                logger.info("Rule disabled: %s", name)
                return True
        return False

    def enable_rule(self, name: str) -> bool:
        for rule in self._rules:
            if rule.name == name:
                rule.enabled = True
                logger.info("Rule enabled: %s", name)
                return True
        return False

    def list_rules(self) -> list[dict]:
        return [
            {"name": r.name, "priority": r.priority, "enabled": r.enabled,
             "tags": r.tags, "description": r.description}
            for r in self._rules
        ]

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def audit_log(self) -> list[dict]:
        return [e.to_dict() for e in self._audit_log]

    def clear_audit_log(self) -> None:
        self._audit_log.clear()

    def clear_cooldowns(self) -> None:
        self._cooldown_store.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _in_cooldown(self, key: tuple[str, str], seconds: int) -> bool:
        if seconds <= 0:
            return False
        last = self._cooldown_store.get(key)
        if last is None:
            return False
        return (time.time() - last) < seconds

    def _execute_actions(
        self,
        rule:    ResponseRule,
        target:  str,
        context: dict[str, Any],
    ) -> list[ActionResult]:
        results = []
        for action_name in rule.actions:
            kwargs = rule.action_kwargs.get(action_name, {})
            try:
                action = build_action(action_name, simulate=self.simulate, **kwargs)
                result = action.run(target, context)
                results.append(result)
            except Exception as exc:
                logger.error("Failed to build/run action %s: %s", action_name, exc)
        return results
