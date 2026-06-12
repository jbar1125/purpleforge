"""
blue_agent/rule_registry.py — tracks the health and lifecycle of every detection rule.

WHY THIS EXISTS
---------------
Rules aren't permanent. A real attacker doesn't just evade a detection — they actively
DESTROY it via alert fatigue: flood it with false positives until the defender trusts it
so little they disable it. Once a rule is silent, the attacker owns that detection vector.

This registry gives every rule a health score based on its rolling precision (TP / TP+FP).
States:
  ACTIVE    — rule is trusted and running
  DEGRADED  — precision has dropped below the burn threshold; under observation
  BURNED    — rule has been degraded for too many consecutive rounds and is disabled;
              Red has successfully neutralized this part of Blue's defense

When a rule is BURNED, the detector skips it. The technique it covered can only be
re-detected by Blue generating a NEW rule — which Red will immediately try to burn again.

Cross-session: the registry persists burn state across arena runs so Red's victories
compound over time and Blue can't just restart to recover burned rules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json


class RuleState(str, Enum):
    ACTIVE   = "active"
    DEGRADED = "degraded"
    BURNED   = "burned"


@dataclass
class RuleHealth:
    rule_name: str
    state: RuleState = RuleState.ACTIVE
    precision_history: list[float | None] = field(default_factory=list)
    # consecutive rounds below threshold (resets to 0 if precision recovers)
    consecutive_degraded: int = 0
    # total TP/FP counts across all time (for lifetime precision metric)
    total_tp: int = 0
    total_fp: int = 0
    burned_at_round: int | None = None


class RuleRegistry:
    """
    Tracks rule health. Constructed once per arena run; serialized to/from
    arena_memory.json for cross-session state.

    Args:
        burn_threshold: precision below this → DEGRADED (default 0.40)
        burn_consecutive: rounds at DEGRADED before BURNED (default 2)
        fp_gate_threshold: max false-positive rate allowed for a new rule's FIRST
            precision measurement; if FP rate > this, the rule is immediately burned
            before it can flood the SOC with noise (default 0.05 = 5%)
    """

    def __init__(
        self,
        burn_threshold: float = 0.40,
        burn_consecutive: int = 2,
        fp_gate_threshold: float = 0.05,
    ):
        self.burn_threshold = burn_threshold
        self.burn_consecutive = burn_consecutive
        self.fp_gate_threshold = fp_gate_threshold
        self._rules: dict[str, RuleHealth] = {}

    # ── state accessors ────────────────────────────────────────────────────────

    def is_burned(self, rule_name: str) -> bool:
        h = self._rules.get(rule_name)
        return h is not None and h.state == RuleState.BURNED

    def is_degraded(self, rule_name: str) -> bool:
        h = self._rules.get(rule_name)
        return h is not None and h.state == RuleState.DEGRADED

    def state_of(self, rule_name: str) -> RuleState:
        return self._rules.get(rule_name, RuleHealth(rule_name)).state

    def active_rules(self, all_names: list[str]) -> list[str]:
        """Filter a list of rule names to only those not burned."""
        return [n for n in all_names if not self.is_burned(n)]

    def burned_rules(self) -> list[str]:
        return [n for n, h in self._rules.items() if h.state == RuleState.BURNED]

    # ── update ─────────────────────────────────────────────────────────────────

    def record_rule_precision(
        self,
        rule_name: str,
        precision: float | None,
        tp: int = 0,
        fp: int = 0,
        round_num: int = 0,
    ) -> RuleState:
        """
        Update one rule's health after a round/sweep.
        Returns the rule's new state (callers may want to react to a burn).
        """
        if rule_name not in self._rules:
            self._rules[rule_name] = RuleHealth(rule_name=rule_name)
        h = self._rules[rule_name]
        if h.state == RuleState.BURNED:
            return RuleState.BURNED

        is_first_measurement = len(h.precision_history) == 0
        h.precision_history.append(precision)
        h.total_tp += tp
        h.total_fp += fp

        # Only update DEGRADED/ACTIVE state when precision is classifiable
        if precision is None:
            # No classifiable hits this round — don't penalize, but don't reset degraded streak
            return h.state

        # FP promotion gate: if a brand-new rule's very first measurement shows
        # FP rate > fp_gate_threshold, reject it immediately rather than letting it
        # run for burn_consecutive rounds — a noisy rule on first fire means the LLM
        # over-generalized the pattern. Better to burn it now and let Blue regenerate.
        if is_first_measurement and precision is not None:
            fp_rate = 1.0 - precision  # precision = TP/(TP+FP), so FP rate = 1 - precision
            if fp_rate > self.fp_gate_threshold:
                h.state = RuleState.BURNED
                h.burned_at_round = round_num
                print(
                    f"  [registry] FP gate: '{rule_name}' rejected on first fire — "
                    f"FP rate {fp_rate:.1%} > {self.fp_gate_threshold:.0%} threshold"
                )
                return RuleState.BURNED

        if precision < self.burn_threshold:
            h.consecutive_degraded += 1
            h.state = RuleState.DEGRADED
            if h.consecutive_degraded >= self.burn_consecutive:
                h.state = RuleState.BURNED
                h.burned_at_round = round_num
        else:
            # Precision recovered — reset degraded streak
            h.consecutive_degraded = 0
            h.state = RuleState.ACTIVE

        return h.state

    def record_batch(
        self,
        per_rule: dict[str, dict],  # from score_precision → {rule_name: {tp,fp,precision}}
        round_num: int = 0,
    ) -> list[str]:
        """
        Process one round's full precision report. Returns list of newly-burned rule names.
        """
        newly_burned = []
        for rule_name, stats in per_rule.items():
            old_state = self.state_of(rule_name)
            new_state = self.record_rule_precision(
                rule_name=rule_name,
                precision=stats.get("precision"),
                tp=stats.get("tp", 0),
                fp=stats.get("fp", 0),
                round_num=round_num,
            )
            if new_state == RuleState.BURNED and old_state != RuleState.BURNED:
                newly_burned.append(rule_name)
        return newly_burned

    # ── serialization (cross-session persistence) ──────────────────────────────

    def to_dict(self) -> dict:
        return {
            "burn_threshold": self.burn_threshold,
            "burn_consecutive": self.burn_consecutive,
            "fp_gate_threshold": self.fp_gate_threshold,
            "rules": {
                name: {
                    "state": h.state.value,
                    "consecutive_degraded": h.consecutive_degraded,
                    "total_tp": h.total_tp,
                    "total_fp": h.total_fp,
                    "burned_at_round": h.burned_at_round,
                    "precision_history": h.precision_history,
                }
                for name, h in self._rules.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RuleRegistry":
        reg = cls(
            burn_threshold=data.get("burn_threshold", 0.40),
            burn_consecutive=data.get("burn_consecutive", 2),
            fp_gate_threshold=data.get("fp_gate_threshold", 0.05),
        )
        for name, r in data.get("rules", {}).items():
            h = RuleHealth(rule_name=name)
            h.state = RuleState(r["state"])
            h.consecutive_degraded = r.get("consecutive_degraded", 0)
            h.total_tp = r.get("total_tp", 0)
            h.total_fp = r.get("total_fp", 0)
            h.burned_at_round = r.get("burned_at_round")
            h.precision_history = r.get("precision_history", [])
            reg._rules[name] = h
        return reg

    # ── metrics helpers ────────────────────────────────────────────────────────

    def health_summary(self) -> dict:
        total = len(self._rules)
        burned = sum(1 for h in self._rules.values() if h.state == RuleState.BURNED)
        degraded = sum(1 for h in self._rules.values() if h.state == RuleState.DEGRADED)
        return {
            "total_rules_tracked": total,
            "active": total - burned - degraded,
            "degraded": degraded,
            "burned": burned,
            "burned_names": self.burned_rules(),
            "defense_strength_pct": round((total - burned) / total * 100, 1) if total else 100.0,
        }
