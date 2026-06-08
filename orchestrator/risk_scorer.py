"""
orchestrator/risk_scorer.py — Risk-Based Alerting (RBA) instead of binary alerts.

WHY THIS EXISTS
---------------
The arena (and most naive SIEMs) fire one alert per rule hit. That is precisely the
weakness Red's poison campaign exploits: flood a rule with low-value hits and the
analyst drowns, then mutes the rule. Risk-Based Alerting is the production answer.

Instead of alerting on every signal, each signal ADDS RISK to the entity it concerns
(a user, a host). Many small signals on the SAME entity accumulate; only when an
entity's cumulative risk crosses a threshold within a time window is a SINGLE
"notable" raised — consolidating all contributing signals into one investigation.

Two properties that matter here:
  - Alert-fatigue resistance: a flood of low-severity false positives contributes
    little risk each, so it never crosses the notable threshold. Red's poisoning
    stops working. (Splapping a high risk_score on a noisy rule is the analyst's
    tuning knob.)
  - Kill-chain visibility: a brute-force (low risk) + a new-account (low) + a
    scheduled-task (low) on one host sum into a high-risk notable even though no
    single rule was confident — catching the slow attacker that evades each
    individual threshold.

Time-windowed: risk older than `window_seconds` is dropped, so risk reflects
recent, correlated activity. `now` is injectable for deterministic tests.

`to_spl()` emits the standard Splunk RBA aggregation over a `risk` index.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class RiskEvent:
    ts: float
    score: float
    source: str          # which rule/signal contributed
    message: str
    technique: str = ""


@dataclass
class RiskScorer:
    """
    Accumulates per-entity risk and raises one notable per entity when its windowed
    risk crosses `notable_threshold`.

    Args:
        notable_threshold: cumulative windowed risk that raises a notable (default 80).
        window_seconds: only risk newer than this counts (default 3600 = 1h).
    """
    notable_threshold: float = 80.0
    window_seconds: float = 3600.0
    _events: dict[str, list[RiskEvent]] = field(default_factory=dict)

    def add_risk(self, entity: str, score: float, source: str, message: str = "",
                 technique: str = "", now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._events.setdefault(entity, []).append(
            RiskEvent(ts=now, score=float(score), source=source, message=message, technique=technique)
        )

    def _live(self, entity: str, now: float) -> list[RiskEvent]:
        cutoff = now - self.window_seconds
        live = [e for e in self._events.get(entity, []) if e.ts >= cutoff]
        self._events[entity] = live  # opportunistic prune
        return live

    def total_risk(self, entity: str, now: float | None = None) -> float:
        now = time.time() if now is None else now
        return round(sum(e.score for e in self._live(entity, now)), 2)

    def is_notable(self, entity: str, now: float | None = None) -> bool:
        return self.total_risk(entity, now) >= self.notable_threshold

    def notable_entities(self, now: float | None = None) -> list[str]:
        now = time.time() if now is None else now
        return [e for e in self._events if self.total_risk(e, now) >= self.notable_threshold]

    def to_notable(self, entity: str, now: float | None = None) -> dict | None:
        """Consolidate an entity's contributing signals into ONE notable event."""
        now = time.time() if now is None else now
        live = self._live(entity, now)
        if not live or sum(e.score for e in live) < self.notable_threshold:
            return None
        contributing = sorted(live, key=lambda e: e.score, reverse=True)
        return {
            "risk_object": entity,
            "total_risk": round(sum(e.score for e in live), 2),
            "signal_count": len(live),
            "techniques": sorted({e.technique for e in live if e.technique}),
            "sources": sorted({e.source for e in live}),
            "top_contributors": [
                {"source": e.source, "score": e.score, "message": e.message}
                for e in contributing[:5]
            ],
        }

    def top_entities(self, limit: int = 10, now: float | None = None) -> list[tuple[str, float]]:
        now = time.time() if now is None else now
        scored = [(e, self.total_risk(e, now)) for e in self._events]
        return sorted(scored, key=lambda x: x[1], reverse=True)[:limit]

    def to_spl(self, risk_index: str = "risk") -> str:
        """Standard Splunk RBA notable aggregation."""
        return (
            f"index={risk_index}\n"
            f"| stats sum(risk_score) as total_risk, dc(source) as signal_count, "
            f"values(source) as sources, values(technique) as techniques "
            f"by risk_object\n"
            f"| where total_risk >= {self.notable_threshold}\n"
            f"| eval notable_kind=\"risk_based_alert\""
        )
