"""
blue_agent/threat_intel.py — skate to where the puck is going: pre-build detections from
published adversary intel BEFORE Red runs the technique.

WHY THIS EXISTS  (Track 5, level 4 — extends the mutation-inference "moat")
--------------------------------------------------------------------------
Everything else in Blue is reactive: Red runs a technique, Blue misses, Blue generates a
rule. That always cedes the first move to the attacker. Threat intelligence is how a real
SOC gets ahead — CISA advisories, vendor reports, and ATT&CK Navigator layers publish the
exact techniques a known actor uses. If an advisory says APTxx uses T1003.001 + T1053.005
+ T1547.001, Blue can build and dry-run those detections NOW, so the first time that actor
touches the environment the rule is already live.

This module parses adversary intel into a prioritized list of ATT&CK techniques, then does
a GAP ANALYSIS against Blue's current coverage:

    already_covered  — intel techniques Blue can already detect
    recommended_new  — intel techniques Blue is missing  → proactive rule-generation targets,
                       ranked by how often they appear across the intel you fed in

Two input formats are supported, because that's how intel actually arrives:
  * free text     — paste an advisory; T-codes are extracted with surrounding context.
  * Navigator JSON — the standard MITRE ATT&CK Navigator "layer" used to share the technique
                     set of a campaign/actor ({"techniques": [{"techniqueID": ...}]}).

Pure/offline by design (the parsing + gap analysis need no network); an optional fetch_text()
helper is provided for the run-book to pull a live advisory.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

# ATT&CK technique IDs: T#### optionally .### sub-technique. Word-bounded so we don't match
# inside longer tokens.
_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _base_technique(tid: str) -> str:
    return tid.split(".")[0].upper()


@dataclass
class TechniqueRef:
    """One technique cited by intel, with how often and where it was seen."""
    technique_id: str
    count: int = 0
    contexts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"technique_id": self.technique_id, "count": self.count,
                "contexts": self.contexts[:5]}   # cap stored context to keep it readable


def extract_techniques_from_text(text: str) -> list[tuple[str, str]]:
    """
    Pull (technique_id, context) pairs out of advisory prose. Context is the trimmed line
    the ID appeared on — enough for an analyst to see WHY it was flagged. Order-preserving.
    """
    if not text:
        return []
    found: list[tuple[str, str]] = []
    for line in text.splitlines():
        for m in _TID.finditer(line):
            found.append((m.group(0).upper(), line.strip()[:200]))
    return found


def techniques_from_navigator_layer(layer: dict) -> list[tuple[str, str]]:
    """
    Extract (technique_id, context) from a MITRE ATT&CK Navigator layer dict. The layer's
    per-technique `comment` (or score) becomes the context. Tolerates missing fields.
    """
    if not isinstance(layer, dict):
        return []
    out: list[tuple[str, str]] = []
    for t in layer.get("techniques", []) or []:
        tid = t.get("techniqueID") or t.get("techniqueId") or t.get("technique_id")
        if not tid:
            continue
        ctx = (t.get("comment") or "").strip()
        if not ctx and t.get("score") is not None:
            ctx = f"navigator score {t.get('score')}"
        out.append((tid.upper(), ctx or "navigator layer"))
    return out


class ThreatIntelParser:
    """
    Accumulate techniques from multiple intel sources, then prioritize and gap-analyze.

    Usage:
        ti = ThreatIntelParser()
        ti.ingest_text(advisory_text, source="CISA AA24-109A")
        ti.ingest_navigator_layer(layer_json, source="APT29 layer")
        gaps = ti.gap_analysis(covered_techniques={"T1110.001", "T1021.001"})
        for rec in gaps["recommended_new"]:
            ...  # feed rec["technique_id"] to the rule generator, proactively
    """

    def __init__(self):
        self._refs: dict[str, TechniqueRef] = {}

    # ── ingestion ───────────────────────────────────────────────────────────────
    def _add(self, tid: str, context: str) -> None:
        ref = self._refs.setdefault(tid, TechniqueRef(technique_id=tid))
        ref.count += 1
        if context:
            ref.contexts.append(context)

    def ingest_text(self, text: str, source: str = "") -> int:
        """Parse an advisory's text. Returns the number of technique citations added."""
        pairs = extract_techniques_from_text(text)
        for tid, ctx in pairs:
            self._add(tid, f"[{source}] {ctx}" if source else ctx)
        return len(pairs)

    def ingest_navigator_layer(self, layer: dict, source: str = "") -> int:
        pairs = techniques_from_navigator_layer(layer)
        for tid, ctx in pairs:
            self._add(tid, f"[{source}] {ctx}" if source else ctx)
        return len(pairs)

    # ── analysis ────────────────────────────────────────────────────────────────
    def prioritized(self) -> list[TechniqueRef]:
        """All cited techniques, most-frequently-cited first (frequency = priority)."""
        return sorted(self._refs.values(), key=lambda r: (-r.count, r.technique_id))

    def gap_analysis(self, covered_techniques, base_match: bool = False) -> dict:
        """
        Split cited techniques into what Blue already covers vs. what it should build next.

        covered_techniques: iterable of technique IDs Blue currently detects (from the
                            coverage matrix / rule set).
        base_match:         if True, a covered parent (T1059) satisfies a cited
                            sub-technique (T1059.001). Default False — sub-techniques are
                            distinct detection-engineering targets, so a missing sub-technique
                            is a real gap worth a dedicated rule.

        Returns {already_covered: [...], recommended_new: [...], coverage_pct: float},
        where recommended_new is a list of TechniqueRef.to_dict() ranked by citation count.
        """
        covered = set(covered_techniques or [])
        covered_bases = {_base_technique(t) for t in covered}

        def is_covered(tid: str) -> bool:
            if tid in covered:
                return True
            if base_match and _base_technique(tid) in covered_bases:
                return True
            return False

        already, missing = [], []
        for ref in self.prioritized():
            (already if is_covered(ref.technique_id) else missing).append(ref)

        total = len(self._refs)
        coverage = round(len(already) / total * 100, 1) if total else 0.0
        return {
            "already_covered": [r.technique_id for r in already],
            "recommended_new": [r.to_dict() for r in missing],
            "coverage_pct": coverage,
        }


def fetch_text(url: str, timeout: float = 30.0) -> str:
    """
    OPTIONAL online helper for the run-book: fetch an advisory page/feed as text so it can
    be passed to ingest_text(). Imported lazily-ish (requests is already a project dep).
    Not used by the offline parsing/gap-analysis core or its tests.
    """
    import requests
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text
