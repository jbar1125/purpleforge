"""
blue_agent/mutation_inferencer.py — infer what Red mutated WITHOUT being told.

WHY THIS EXISTS  (this is the moat)
-----------------------------------
In the arena, Red hands Blue its exact field changes via ``red.get_current_overrides()``.
A real attacker never does this. The entire adaptive-defense story collapses if it
depends on the adversary confessing what it changed.

This module closes that gap. Every time Blue successfully detects a technique it
snapshots the field-value "fingerprint" of those events. When the technique later
EVADES, Blue diffs the new (evading) events against the last-caught fingerprint and
INFERS which fields the attacker changed — producing the same ``{field: new_value}``
dict the rule generator already consumes. No LLM, no confession: pure observation.

Three diff signals:
  1. VALUE SWAP    — a field that was one stable value is now a different stable value
                     (Sub_Status 0xC000006A -> 0xC000006D, Logon_Type 3 -> 8).
  2. CARDINALITY   — a field that was one value is now many (IP rotation / spray fan-out),
                     or many -> one (consolidating onto a single host).
  3. VOLUME        — the event count per window dropped or spiked (threshold evasion).

Naturally-variable fields (timestamps, GUIDs, per-event record IDs) are excluded both
by a name denylist AND dynamically: a field that is essentially unique-per-event in the
last-caught snapshot is noise, not an anchor, so a change in it is never reported.

The output of ``infer_mutation()`` is a drop-in replacement for Red's self-reported
overrides — feed it straight into ``Generator.generate_rule(mutation_overrides=...)``.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

# ── fields that vary every event by nature — never a deliberate evasion anchor ──
_VOLATILE_SUBSTRINGS = (
    "guid", "uuid",
    "logon_id", "process_id", "thread_id", "processid", "threadid",
    "record", "session", "correlation", "sequence",
)
_VOLATILE_EXACT = {
    "_time", "_raw", "_indextime", "_cd", "_bkt", "_si", "_serial",
    "time", "timestamp", "_sourcetype", "linecount",
}


def _is_volatile_name(field_name: str) -> bool:
    """True for fields whose value is expected to differ on every single event."""
    f = field_name.lower()
    if field_name.startswith("arena_"):
        return True
    if f in _VOLATILE_EXACT:
        return True
    return any(s in f for s in _VOLATILE_SUBSTRINGS)


# ── per-field statistical profile across a batch of events ──────────────────────
@dataclass
class FieldProfile:
    dominant: str | None   # most common value (as string), or None if field absent
    dominance: float       # fraction of present events holding the dominant value (0..1)
    distinct: int          # number of distinct values observed
    n: int                 # number of events in which the field appeared


def _profile_field(events: list[dict], field_name: str) -> FieldProfile:
    values = [
        str(ev[field_name])
        for ev in events
        if field_name in ev and ev[field_name] is not None and ev[field_name] != ""
    ]
    if not values:
        return FieldProfile(dominant=None, dominance=0.0, distinct=0, n=0)
    counts = Counter(values)
    dominant, dom_count = counts.most_common(1)[0]
    return FieldProfile(
        dominant=dominant,
        dominance=dom_count / len(values),
        distinct=len(counts),
        n=len(values),
    )


@dataclass
class FieldDiff:
    """One inferred change between the last-caught snapshot and the evading events."""
    field: str
    kind: str          # swap | rotation | consolidation | introduced | removed | volume
    old: Any
    new: Any

    def describe(self) -> str:
        if self.kind == "swap":
            return f"{self.field}: {self.old} -> {self.new}"
        if self.kind == "rotation":
            n = len(self.new) if isinstance(self.new, list) else self.new
            return f"{self.field}: rotated {self.old} -> {n} values"
        if self.kind == "consolidation":
            return f"{self.field}: collapsed many -> {self.new}"
        if self.kind == "introduced":
            return f"{self.field}: introduced = {self.new}"
        if self.kind == "removed":
            return f"{self.field}: removed (was {self.old})"
        if self.kind == "volume":
            return f"event volume: {self.old} -> {self.new}"
        return f"{self.field}: {self.old} -> {self.new}"


@dataclass
class Snapshot:
    technique_id: str
    event_count: int
    fields: dict[str, FieldProfile] = field(default_factory=dict)
    generation: int = 0


class MutationInferencer:
    """
    Infers Red's field changes by diffing evading events against the last batch
    of events Blue successfully caught for that technique.

    Args:
        stability_threshold: a field must hold its dominant value in at least this
            fraction of events to count as "fixed" (default 0.6).
        volume_change_ratio: flag a volume mutation if the evading event count is
            <= ratio * baseline OR >= baseline / ratio (default 0.5 => 2x in either
            direction).
        min_cardinality_jump: minimum increase in distinct values to call a field a
            rotation/fan-out (default 3).
    """

    def __init__(
        self,
        stability_threshold: float = 0.6,
        volume_change_ratio: float = 0.5,
        min_cardinality_jump: int = 3,
    ):
        self.stability_threshold = stability_threshold
        self.volume_change_ratio = volume_change_ratio
        self.min_cardinality_jump = min_cardinality_jump
        self._snapshots: dict[str, Snapshot] = {}

    # ── snapshot management ─────────────────────────────────────────────────────
    @staticmethod
    def _candidate_fields(events: list[dict]) -> set[str]:
        """Union of non-volatile field names present across the events."""
        names: set[str] = set()
        for ev in events:
            for k in ev:
                if not _is_volatile_name(k):
                    names.add(k)
        return names

    def record_caught(self, technique_id: str, events: list[dict], generation: int = 0) -> None:
        """
        Snapshot the fingerprint of events Blue just caught. Overwrites any prior
        snapshot — we always diff against the MOST RECENT known-good detection.
        """
        if not events:
            return
        profiles = {f: _profile_field(events, f) for f in self._candidate_fields(events)}
        self._snapshots[technique_id] = Snapshot(
            technique_id=technique_id,
            event_count=len(events),
            fields=profiles,
            generation=generation,
        )

    def has_baseline(self, technique_id: str) -> bool:
        return technique_id in self._snapshots

    # ── inference ───────────────────────────────────────────────────────────────
    def diff(self, technique_id: str, evading_events: list[dict]) -> list[FieldDiff]:
        """Structured diff between the last-caught snapshot and evading events."""
        snap = self._snapshots.get(technique_id)
        if snap is None or not evading_events:
            return []

        diffs: list[FieldDiff] = []
        evad_field_names = self._candidate_fields(evading_events)
        all_fields = set(snap.fields) | evad_field_names

        for fname in sorted(all_fields):
            snap_p = snap.fields.get(fname) or FieldProfile(None, 0.0, 0, 0)
            evad_p = _profile_field(evading_events, fname)

            if snap_p.dominant is None and evad_p.dominant is None:
                continue

            # field newly introduced as a stable anchor
            if snap_p.dominant is None and evad_p.dominant is not None:
                if evad_p.dominance >= self.stability_threshold and evad_p.distinct <= 2:
                    diffs.append(FieldDiff(fname, "introduced", None, self._coerce(evad_p.dominant)))
                continue

            # field that used to be present is now gone (attacker dropped a telltale)
            if snap_p.dominant is not None and evad_p.dominant is None:
                diffs.append(FieldDiff(fname, "removed", self._coerce(snap_p.dominant), None))
                continue

            snap_fixed = snap_p.distinct <= 2 and snap_p.dominance >= self.stability_threshold
            evad_fixed = evad_p.distinct <= 2 and evad_p.dominance >= self.stability_threshold

            if snap_fixed and evad_fixed and snap_p.dominant != evad_p.dominant:
                # SIGNAL 1 — value swap
                diffs.append(FieldDiff(fname, "swap",
                                       self._coerce(snap_p.dominant), self._coerce(evad_p.dominant)))
            elif snap_fixed and (evad_p.distinct - snap_p.distinct) >= self.min_cardinality_jump:
                # SIGNAL 2a — fan-out / rotation (one value -> many)
                new_values = sorted({
                    str(ev[fname]) for ev in evading_events
                    if fname in ev and ev[fname] not in (None, "")
                })
                diffs.append(FieldDiff(fname, "rotation", self._coerce(snap_p.dominant), new_values[:8]))
            elif (snap_p.distinct - evad_p.distinct) >= self.min_cardinality_jump and evad_fixed:
                # SIGNAL 2b — consolidation (many values -> one)
                diffs.append(FieldDiff(fname, "consolidation", snap_p.distinct, self._coerce(evad_p.dominant)))

        # SIGNAL 3 — volume (count threshold evasion)
        if snap.event_count > 0:
            ratio = len(evading_events) / snap.event_count
            if ratio <= self.volume_change_ratio or ratio >= (1.0 / self.volume_change_ratio):
                diffs.append(FieldDiff("count", "volume", snap.event_count, len(evading_events)))

        return diffs

    def infer_mutation(self, technique_id: str, evading_events: list[dict]) -> dict[str, Any]:
        """
        Flatten the structured diff into a ``{field: new_value}`` dict — the exact
        shape ``Generator.generate_rule(mutation_overrides=...)`` consumes. Returns
        ``{}`` when there is no baseline to diff against (matches the generator's
        "first miss / unknown" handling).
        """
        overrides: dict[str, Any] = {}
        for d in self.diff(technique_id, evading_events):
            if d.kind == "removed":
                continue  # the generator anchors on present values, not absent ones
            if d.kind == "volume":
                overrides["count"] = d.new
            else:
                overrides[d.field] = d.new
        return overrides

    def describe(self, technique_id: str, evading_events: list[dict]) -> str:
        """Human-readable one-liner for logs / dashboard, e.g. for the engine's log."""
        diffs = self.diff(technique_id, evading_events)
        if not diffs:
            return "no inferable change (no baseline or identical fingerprint)"
        return "; ".join(d.describe() for d in diffs)

    @staticmethod
    def _coerce(v: Any) -> Any:
        """Turn pure-digit strings back into ints so anchors look natural in the prompt."""
        if isinstance(v, str) and v.isdigit():
            return int(v)
        return v

    # ── cross-session persistence (parallel to RuleRegistry) ────────────────────
    def to_dict(self) -> dict:
        return {
            "stability_threshold": self.stability_threshold,
            "volume_change_ratio": self.volume_change_ratio,
            "min_cardinality_jump": self.min_cardinality_jump,
            "snapshots": {
                tid: {
                    "event_count": s.event_count,
                    "generation": s.generation,
                    "fields": {
                        f: {"dominant": p.dominant, "dominance": p.dominance,
                            "distinct": p.distinct, "n": p.n}
                        for f, p in s.fields.items()
                    },
                }
                for tid, s in self._snapshots.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MutationInferencer":
        inf = cls(
            stability_threshold=data.get("stability_threshold", 0.6),
            volume_change_ratio=data.get("volume_change_ratio", 0.5),
            min_cardinality_jump=data.get("min_cardinality_jump", 3),
        )
        for tid, s in data.get("snapshots", {}).items():
            inf._snapshots[tid] = Snapshot(
                technique_id=tid,
                event_count=s.get("event_count", 0),
                generation=s.get("generation", 0),
                fields={
                    f: FieldProfile(
                        dominant=p.get("dominant"),
                        dominance=p.get("dominance", 0.0),
                        distinct=p.get("distinct", 0),
                        n=p.get("n", 0),
                    )
                    for f, p in s.get("fields", {}).items()
                },
            )
        return inf
