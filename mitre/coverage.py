from dataclasses import dataclass, field
from typing import Literal
from .techniques import TECHNIQUES

DetectionStatus = Literal["uncovered", "detected", "evaded"]

# A technique counts as "covered" only if detected in this many of the last N rounds
COVERAGE_WINDOW = 3       # look at last N rounds
COVERAGE_THRESHOLD = 0.5  # must be detected in >= 50% of those rounds


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
    # Per-round detection history: True = detected, False = evaded
    history: list[bool] = field(default_factory=list)


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

    def record_round(self, round_num: int, results: dict[str, bool]) -> None:
        """
        Update coverage after a round.
        results: {technique_id: True (detected) | False (evaded)}
        """
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
            else:
                rec.rounds_evaded += 1
                rec.last_status = "evaded"
            entry["results"][tid] = "detected" if detected else "evaded"
        self.round_log.append(entry)

    def record_rule_generated(self, technique_id: str) -> None:
        if technique_id in self.records:
            self.records[technique_id].rules_generated += 1

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

    def coverage_percent_ever(self) -> float:
        """Legacy metric: % ever detected at least once. Kept for comparison."""
        if not self.records:
            return 0.0
        covered = sum(1 for r in self.records.values() if r.rounds_detected > 0)
        return round(covered / len(self.records) * 100, 1)

    def summary(self) -> dict:
        return {
            "coverage_percent": self.coverage_percent(),
            "coverage_percent_ever_detected": self.coverage_percent_ever(),
            "coverage_window_rounds": COVERAGE_WINDOW,
            "coverage_threshold": COVERAGE_THRESHOLD,
            "techniques": {
                tid: {
                    "name": r.name,
                    "tactic": r.tactic,
                    "injected": r.rounds_injected,
                    "detected": r.rounds_detected,
                    "evaded": r.rounds_evaded,
                    "rules_generated": r.rules_generated,
                    "status": r.last_status,
                    "covered": self._is_covered(r),
                    "detection_rate": round(r.rounds_detected / r.rounds_injected, 2) if r.rounds_injected else 0,
                }
                for tid, r in self.records.items()
            },
            "round_log": self.round_log,
        }
