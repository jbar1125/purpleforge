from dataclasses import dataclass, field
from enum import Enum
from typing import Literal
from .techniques import TECHNIQUES

DetectionStatus = Literal["uncovered", "detected", "evaded"]

# A technique counts as "covered" only if detected in this many of the last N rounds
COVERAGE_WINDOW = 3       # look at last N rounds
COVERAGE_THRESHOLD = 0.5  # must be detected in >= 50% of those rounds


class TechniqueGameState(str, Enum):
    """
    Lifecycle of a technique in the Red-vs-Blue arms race.
    UNCOVERED   — never had a rule catch it
    EVADING     — has been caught before but currently slipping past all rules
    DETECTED    — caught by at least one rule in the current window
    COMPROMISED — evading AND the covering rule has been burned by Red's poisoning
                  → Red has neutralized this defense vector
    """
    UNCOVERED   = "uncovered"
    EVADING     = "evading"
    DETECTED    = "detected"
    COMPROMISED = "compromised"


@dataclass
class TechniqueRecord:
    technique_id: str
    name: str
    tactic: str
    rounds_injected: int = 0
    rounds_detected: int = 0
    rounds_evaded: int = 0
    rules_generated: int = 0
    last_status: DetectionStatus = "uncovered"
    game_state: TechniqueGameState = TechniqueGameState.UNCOVERED
    # Per-round detection history: True = detected, False = evaded
    history: list[bool] = field(default_factory=list)
    # Timing metrics (wall-clock seconds)
    detect_times: list[float] = field(default_factory=list)   # seconds from inject to detect
    evade_times: list[float] = field(default_factory=list)    # seconds evasion lasted


class CoverageMatrix:
    """
    Tracks per-technique detection history across all rounds.

    Coverage is windowed: a technique counts as "covered" only if it was
    detected in >= COVERAGE_THRESHOLD of the last COVERAGE_WINDOW rounds.
    This prevents the metric from permanently inflating after one detection.
    """

    def __init__(self, technique_ids: list[str]):
        self.records: dict[str, TechniqueRecord] = {}
        for tid in technique_ids:
            meta = TECHNIQUES.get(tid, {"name": tid, "tactic": "Unknown"})
            self.records[tid] = TechniqueRecord(
                technique_id=tid,
                name=meta["name"],
                tactic=meta["tactic"],
            )
        self.round_log: list[dict] = []

    def record_round(
        self,
        round_num: int,
        results: dict[str, bool],
        compromised: set[str] | None = None,
    ) -> None:
        """
        Update coverage after a round.
        results: {technique_id: True (detected) | False (evaded)}
        compromised: set of technique IDs whose covering rule has been burned
        """
        compromised = compromised or set()
        entry = {"round": round_num, "results": {}}
        for tid, detected in results.items():
            if tid not in self.records:
                continue
            rec = self.records[tid]
            rec.rounds_injected += 1
            rec.history.append(detected)
            if detected:
                rec.rounds_detected += 1
                rec.last_status = "detected"
                rec.game_state = TechniqueGameState.DETECTED
            else:
                rec.rounds_evaded += 1
                rec.last_status = "evaded"
                if tid in compromised:
                    rec.game_state = TechniqueGameState.COMPROMISED
                elif rec.game_state != TechniqueGameState.UNCOVERED:
                    rec.game_state = TechniqueGameState.EVADING
                # else stays UNCOVERED
            entry["results"][tid] = rec.game_state.value
        self.round_log.append(entry)

    def record_rule_generated(self, technique_id: str) -> None:
        if technique_id in self.records:
            self.records[technique_id].rules_generated += 1
            # First rule generated means it was at least attempted — move from UNCOVERED
            if self.records[technique_id].game_state == TechniqueGameState.UNCOVERED:
                self.records[technique_id].game_state = TechniqueGameState.EVADING

    def record_timing(self, technique_id: str, detect_seconds: float = None, evade_seconds: float = None) -> None:
        rec = self.records.get(technique_id)
        if not rec:
            return
        if detect_seconds is not None:
            rec.detect_times.append(detect_seconds)
        if evade_seconds is not None:
            rec.evade_times.append(evade_seconds)

    def compromised_techniques(self) -> list[str]:
        return [tid for tid, r in self.records.items()
                if r.game_state == TechniqueGameState.COMPROMISED]

    def game_state_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in TechniqueGameState}
        for r in self.records.values():
            counts[r.game_state.value] += 1
        return counts

    def _is_covered(self, rec: TechniqueRecord) -> bool:
        """
        A technique is 'covered' if detected in >= COVERAGE_THRESHOLD
        of the last COVERAGE_WINDOW rounds. Requires at least 1 round injected.
        """
        if not rec.history:
            return False
        window = rec.history[-COVERAGE_WINDOW:]
        return (sum(window) / len(window)) >= COVERAGE_THRESHOLD

    def coverage_percent(self) -> float:
        """Windowed coverage: % of techniques meeting the detection threshold."""
        if not self.records:
            return 0.0
        covered = sum(1 for r in self.records.values() if self._is_covered(r))
        return round(covered / len(self.records) * 100, 1)

    def weighted_coverage_percent(self) -> float:
        """
        Weighted coverage: same windowed logic, but each technique's contribution
        is proportional to its real-world prevalence_weight from TECHNIQUES.

        A 95%-weight technique like T1003.001 (LSASS) counts far more than a
        55%-weight technique like T1114.003 (Email Forwarding) — so a ruleset that
        covers the high-value techniques shows a higher score even if it misses niche ones.

        Formula: sum(weight_i * is_covered_i) / sum(weight_i)
        Returns 0.0 when no techniques have been injected.
        """
        total_weight = 0.0
        covered_weight = 0.0
        for tid, rec in self.records.items():
            meta = TECHNIQUES.get(tid, {})
            weight = float(meta.get("prevalence_weight", 0.5))  # default 0.5 for unknown techniques
            total_weight += weight
            if self._is_covered(rec):
                covered_weight += weight
        if total_weight == 0.0:
            return 0.0
        return round(covered_weight / total_weight * 100, 1)

    def coverage_percent_ever(self) -> float:
        """Legacy metric: % ever detected at least once. Kept for comparison."""
        if not self.records:
            return 0.0
        covered = sum(1 for r in self.records.values() if r.rounds_detected > 0)
        return round(covered / len(self.records) * 100, 1)

    def summary(self) -> dict:
        def _avg(lst): return round(sum(lst) / len(lst), 2) if lst else None

        return {
            "coverage_percent": self.coverage_percent(),
            "weighted_coverage_percent": self.weighted_coverage_percent(),
            "coverage_percent_ever_detected": self.coverage_percent_ever(),
            "coverage_window_rounds": COVERAGE_WINDOW,
            "coverage_threshold": COVERAGE_THRESHOLD,
            "game_state_counts": self.game_state_counts(),
            "compromised_techniques": self.compromised_techniques(),
            "techniques": {
                tid: {
                    "name": r.name,
                    "tactic": r.tactic,
                    "injected": r.rounds_injected,
                    "detected": r.rounds_detected,
                    "evaded": r.rounds_evaded,
                    "rules_generated": r.rules_generated,
                    "status": r.last_status,
                    "game_state": r.game_state.value,
                    "covered": self._is_covered(r),
                    "detection_rate": round(r.rounds_detected / r.rounds_injected, 2) if r.rounds_injected else 0,
                    "mean_time_to_detect_s": _avg(r.detect_times),
                    "mean_time_to_evade_s": _avg(r.evade_times),
                }
                for tid, r in self.records.items()
            },
            "round_log": self.round_log,
        }
