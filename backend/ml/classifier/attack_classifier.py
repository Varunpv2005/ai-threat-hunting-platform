"""
Threat Classifier — AI Threat Hunting & Incident Response Platform

Takes the output of the AnomalyDetector (anomaly_score + feature vector)
and maps each flagged event to one or more named threat categories with
confidence scores, severity levels, and MITRE ATT&CK technique IDs.

Two-stage pipeline
------------------
Stage 1 — Anomaly gate:
    The IsolationForest in anomaly/isolation_forest.py assigns a raw anomaly
    score [0, 100].  Events below `anomaly_threshold` are passed through as
    NORMAL without classification (fast path).

Stage 2 — Rule-based classification:
    Each anomalous event's feature vector is evaluated against all ThreatRules
    in the taxonomy.  Rules that fire contribute a weighted match score.  The
    final threat category is the one whose rules accumulate the highest total
    weighted score, broken by confidence.

Why this two-stage design?
    - IsolationForest catches *unknown* anomalies but cannot name them.
    - Rule-based classification names what the anomaly *is*, enabling targeted
      automated responses and human-readable alerts.
    - Together they handle both novel zero-day attacks (Stage 1 catches them
      even if no rule matches) and known patterns (Stage 2 explains them).
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from .threat_taxonomy import (
    ThreatCategory,
    ThreatRule,
    Severity,
    THREAT_RULES,
    RULES_BY_CATEGORY,
    severity_from_score,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RuleMatch:
    """A single rule that fired for an event."""
    rule_name:    str
    category:     ThreatCategory
    match_score:  float          # weighted proportion of conditions met [0,1]
    confidence:   float          # final confidence after boost [0,1]
    severity:     Severity
    mitre_techniques: list[str]
    conditions_met:   int
    conditions_total: int
    recommended_actions: list[str]


@dataclass
class ClassificationResult:
    """
    Full classification output for one event.

    primary_category  — highest-confidence matched category, or UNKNOWN
    all_matches       — every rule that fired, sorted by confidence desc
    anomaly_score     — pass-through from Stage 1 detector [0, 100]
    final_severity    — derived from anomaly_score + primary category
    is_threat         — True if any rule fired above min_confidence
    mitre_techniques  — deduplicated union of all matched techniques
    recommended_actions — deduplicated union of all matched actions
    """
    event_index:         int
    anomaly_score:       float
    is_threat:           bool
    primary_category:    ThreatCategory
    primary_confidence:  float
    all_matches:         list[RuleMatch]
    final_severity:      Severity
    mitre_techniques:    list[str]
    recommended_actions: list[str]
    features:            dict[str, float] = field(default_factory=dict)

    def summary(self) -> str:
        if not self.is_threat:
            return f"[{self.event_index:>5}]  NORMAL  (score={self.anomaly_score:.1f})"
        cats = ", ".join(m.category.value for m in self.all_matches[:3])
        return (
            f"[{self.event_index:>5}]  {self.final_severity.value:<8}"
            f"  score={self.anomaly_score:>5.1f}"
            f"  {self.primary_category.value:<25}"
            f"  conf={self.primary_confidence:.2f}"
            f"  [{cats}]"
        )


@dataclass
class ClassificationReport:
    """Aggregate statistics over a batch of ClassificationResults."""
    total:              int
    threats_detected:   int
    normal:             int
    threat_rate:        float
    by_category:        dict[str, int]
    by_severity:        dict[str, int]
    top_mitre:          list[tuple[str, int]]   # (technique, count) top-10
    top_actions:        list[tuple[str, int]]   # (action, count) top-5
    results:            list[ClassificationResult] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "=" * 60,
            f"  Classification Report  —  {self.total:,} events",
            "=" * 60,
            f"  Threats detected : {self.threats_detected:>6}  ({self.threat_rate*100:.1f}%)",
            f"  Normal           : {self.normal:>6}",
            "",
            "  By category:",
        ]
        for cat, cnt in sorted(self.by_category.items(), key=lambda x: -x[1]):
            bar = "█" * min(int(cnt / max(self.threats_detected, 1) * 25), 25)
            lines.append(f"    {cat:<30} {cnt:>5}  {bar}")
        lines += ["", "  By severity:"]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = self.by_severity.get(sev, 0)
            lines.append(f"    {sev:<10} {cnt:>5}")
        if self.top_mitre:
            lines += ["", "  Top MITRE ATT&CK techniques:"]
            for tech, cnt in self.top_mitre[:8]:
                lines.append(f"    {tech:<14} {cnt:>4}")
        lines.append("=" * 60)
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Classifier
# ─────────────────────────────────────────────────────────────────────────────

class ThreatClassifier:
    """
    Maps anomaly scores and feature vectors to named threat categories.

    Parameters
    ----------
    anomaly_threshold : float
        Events with anomaly_score below this value skip classification
        and are returned as NORMAL.  Default 25.0 (LOW boundary).
    min_rule_confidence : float
        Rules with a final confidence below this value are suppressed.
        Prevents very weak partial matches from generating false alerts.
    max_categories : int
        Maximum number of threat categories to report per event.
    """

    def __init__(
        self,
        anomaly_threshold:   float = 25.0,
        min_rule_confidence: float = 0.30,
        max_categories:      int   = 3,
    ):
        self.anomaly_threshold   = anomaly_threshold
        self.min_rule_confidence = min_rule_confidence
        self.max_categories      = max_categories
        self._rules              = THREAT_RULES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify(
        self,
        anomaly_score: float,
        features:      dict[str, float],
        event_index:   int = 0,
    ) -> ClassificationResult:
        """
        Classify a single event.

        Parameters
        ----------
        anomaly_score : float
            Output of AnomalyDetector.predict(), range [0, 100].
        features : dict[str, float]
            Feature vector as a name→value mapping.
        event_index : int
            Row index for traceability.

        Returns
        -------
        ClassificationResult
        """
        # ── Stage 1: anomaly gate ─────────────────────────────────────
        if anomaly_score < self.anomaly_threshold:
            return self._normal_result(event_index, anomaly_score, features)

        # ── Stage 2: rule evaluation ──────────────────────────────────
        matches = self._evaluate_rules(features, anomaly_score)

        if not matches:
            # Anomaly detected but no rule pattern matched → UNKNOWN threat
            return ClassificationResult(
                event_index=event_index,
                anomaly_score=anomaly_score,
                is_threat=True,
                primary_category=ThreatCategory.UNKNOWN,
                primary_confidence=0.0,
                all_matches=[],
                final_severity=severity_from_score(anomaly_score),
                mitre_techniques=[],
                recommended_actions=["alert_analyst", "manual_investigation"],
                features=features,
            )

        # ── Aggregate results ─────────────────────────────────────────
        top = matches[: self.max_categories]
        primary = top[0]

        mitre   = self._deduplicate([t for m in matches for t in m.mitre_techniques])
        actions = self._deduplicate([a for m in matches for a in m.recommended_actions])

        final_severity = self._combined_severity(anomaly_score, primary.severity)

        return ClassificationResult(
            event_index=event_index,
            anomaly_score=anomaly_score,
            is_threat=True,
            primary_category=primary.category,
            primary_confidence=primary.confidence,
            all_matches=top,
            final_severity=final_severity,
            mitre_techniques=mitre,
            recommended_actions=actions,
            features=features,
        )

    def classify_batch(
        self,
        anomaly_scores: list[float] | np.ndarray,
        feature_matrix: np.ndarray,
        feature_names:  list[str],
    ) -> list[ClassificationResult]:
        """
        Classify a batch of events efficiently.

        Parameters
        ----------
        anomaly_scores : array-like, shape (n,)
        feature_matrix : np.ndarray, shape (n, p)
        feature_names  : list[str], length p
        """
        results = []
        for i, (score, row) in enumerate(zip(anomaly_scores, feature_matrix)):
            feat_dict = dict(zip(feature_names, row.tolist()))
            results.append(self.classify(float(score), feat_dict, event_index=i))
        return results

    def report(self, results: list[ClassificationResult]) -> ClassificationReport:
        """Build an aggregate ClassificationReport from a result list."""
        threats  = [r for r in results if r.is_threat]
        by_cat:  dict[str, int] = {}
        by_sev:  dict[str, int] = {}
        mitre_counts: dict[str, int] = {}
        action_counts: dict[str, int] = {}

        for r in threats:
            cat = r.primary_category.value
            by_cat[cat] = by_cat.get(cat, 0) + 1
            sev = r.final_severity.value
            by_sev[sev] = by_sev.get(sev, 0) + 1
            for t in r.mitre_techniques:
                mitre_counts[t] = mitre_counts.get(t, 0) + 1
            for a in r.recommended_actions:
                action_counts[a] = action_counts.get(a, 0) + 1

        top_mitre  = sorted(mitre_counts.items(), key=lambda x: -x[1])[:10]
        top_actions = sorted(action_counts.items(), key=lambda x: -x[1])[:5]

        return ClassificationReport(
            total=len(results),
            threats_detected=len(threats),
            normal=len(results) - len(threats),
            threat_rate=len(threats) / max(len(results), 1),
            by_category=by_cat,
            by_severity=by_sev,
            top_mitre=top_mitre,
            top_actions=top_actions,
            results=results,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate_rules(
        self,
        features:      dict[str, float],
        anomaly_score: float,
    ) -> list[RuleMatch]:
        """
        Evaluate all rules against `features`.
        Returns matched rules sorted by confidence descending.
        """
        matches: list[RuleMatch] = []

        for rule in self._rules:
            raw_score = rule.match_score(features)
            if raw_score == 0.0:
                continue

            # Boost confidence by anomaly score contribution
            # (a high IF score makes us more confident in any rule match)
            anomaly_boost = (anomaly_score / 100.0) * 0.15
            confidence    = min(raw_score + rule.confidence_boost + anomaly_boost, 1.0)

            if confidence < self.min_rule_confidence:
                continue

            conditions_met = sum(
                1 for c in rule.conditions
                if c.evaluate(features.get(c.feature, 0.0))
            )

            matches.append(RuleMatch(
                rule_name=rule.name,
                category=rule.category,
                match_score=raw_score,
                confidence=confidence,
                severity=rule.base_severity,
                mitre_techniques=rule.mitre_techniques,
                conditions_met=conditions_met,
                conditions_total=len(rule.conditions),
                recommended_actions=rule.recommended_actions,
            ))

        return sorted(matches, key=lambda m: (m.confidence, m.match_score, m.conditions_met), reverse=True)

    def _combined_severity(
        self,
        anomaly_score: float,
        rule_severity: Severity,
    ) -> Severity:
        """
        Take the *higher* of the anomaly-score-derived severity and the
        rule's base severity.  A rule firing on a low-scoring event is
        still bounded by the IF score; a high IF score can elevate a
        rule's base severity.
        """
        score_sev = severity_from_score(anomaly_score)
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order[max(order.index(score_sev), order.index(rule_severity))]

    @staticmethod
    def _normal_result(
        event_index:   int,
        anomaly_score: float,
        features:      dict[str, float],
    ) -> ClassificationResult:
        return ClassificationResult(
            event_index=event_index,
            anomaly_score=anomaly_score,
            is_threat=False,
            primary_category=ThreatCategory.UNKNOWN,
            primary_confidence=0.0,
            all_matches=[],
            final_severity=Severity.INFO,
            mitre_techniques=[],
            recommended_actions=[],
            features=features,
        )

    @staticmethod
    def _deduplicate(items: list[str]) -> list[str]:
        seen: set[str] = set()
        out:  list[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out
