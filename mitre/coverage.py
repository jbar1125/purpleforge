from dataclasses import dataclass, field
from typing import Literal
from .techniques import TECHNIQUES


DetectionStatus = Literal["uncovered", "detected", "evaded"]


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


class CoverageMatrix:
    """
    Tracks per-technique detection history across all rounds.
    The output of this class is the heatmap data for the dashboard.
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

    def coverage_percent(self) -> float:
        """Techniques with at least one detection / total techniques."""
        if not self.records:
            return 0.0
        covered = sum(1 for r in self.records.values() if r.rounds_detected > 0)
        return round(covered / len(self.records) * 100, 1)

    def summary(self) -> dict:
        return {
            "coverage_percent": self.coverage_percent(),
            "techniques": {
                tid: {
                    "name": r.name,
                    "tactic": r.tactic,
                    "injected": r.rounds_injected,
                    "detected": r.rounds_detected,
                    "evaded": r.rounds_evaded,
                    "rules_generated": r.rules_generated,
                    "status": r.last_status,
                }
                for tid, r in self.records.items()
            },
            "round_log": self.round_log,
        }
