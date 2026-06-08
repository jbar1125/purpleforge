"""
rule_review/queue.py — persistent queue of LLM-generated rules awaiting review.

A rule never goes straight to production. The generator enqueues a PendingRule here
(with its Sigma/SPL, the events that triggered it, a dry-run blast-radius, and a
confidence score); an analyst approves or rejects via the CLI or the Flask UI; only
on approval does the deployer commit it. The queue is JSON-backed so reviews survive
process restarts.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class PendingRule:
    technique: str
    rule_name: str
    spl: str
    sigma: str = ""
    sample_events: list = field(default_factory=list)
    confidence: float = 0.0
    dry_run: dict = field(default_factory=dict)   # {total_hits, fp_estimate, fp_rate, window}
    explanation: str = ""
    status: str = "pending"                       # pending | approved | rejected | deployed
    reviewer: str = ""
    notes: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_ts: float = field(default_factory=lambda: round(time.time(), 3))
    decided_ts: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "PendingRule":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


# Anchors that make a rule specific (good) vs. a bare count threshold (weak/noisy).
# Plumbing fields (index/source/host) and the scorer's eval tags are NOT specific anchors —
# every SPL query starts with `index=...`, so counting that as an anchor would make the
# count-only penalty below unreachable. EventCode IS kept (it's a real security anchor).
_PLUMBING = r'(?:index|source|sourcetype|host|technique|rule_name)'
_FIELD_ANCHOR = re.compile(
    rf'\b(?!{_PLUMBING}\b)(\w+)\s*(=|!=)\s*"?[^\s"|]+|\|\s*(contains|endswith|startswith)',
    re.IGNORECASE,
)
_COUNT_ONLY = re.compile(r'\bcount\b\s*(>=|>)\s*\d+', re.IGNORECASE)


def compute_confidence(spl: str, sigma: str, sample_events: list, dry_run: dict) -> float:
    """
    Heuristic confidence in [0,1] from the signals we already have. Explainable on
    purpose — every term maps to a reason an analyst would cite.
    """
    score = 0.45
    reasons_up = 0
    if sigma.strip():
        score += 0.15            # portable, structured, reviewable detection-as-code
        reasons_up += 1
    # Specific field anchor present (not just a volume threshold)
    if _FIELD_ANCHOR.search(spl):
        score += 0.15
        reasons_up += 1
    if _COUNT_ONLY.search(spl) and not _FIELD_ANCHOR.search(spl):
        score -= 0.15            # count-only rules are brittle and noisy
    # Derived from a reasonable evidence base
    if len(sample_events) >= 3:
        score += 0.05
    # Dry-run blast radius: reward low false-positive rate, punish a noisy rule
    fp_rate = dry_run.get("fp_rate")
    if fp_rate is not None:
        if fp_rate == 0:
            score += 0.20
        elif fp_rate < 0.1:
            score += 0.10
        elif fp_rate > 0.4:
            score -= 0.30        # would manufacture exactly the FPs Red wants
    total_hits = dry_run.get("total_hits")
    if total_hits == 0:
        score -= 0.10            # catches nothing in the window — suspicious
    return round(max(0.0, min(1.0, score)), 3)


class ReviewQueue:
    def __init__(self, path: str = "results/rule_review_queue.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._items: dict[str, PendingRule] = {}
        self._load()

    # ── persistence ─────────────────────────────────────────────────────────────
    def _load(self) -> None:
        if self.path.exists() and self.path.stat().st_size:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            for d in data.get("rules", []):
                r = PendingRule.from_dict(d)
                self._items[r.id] = r

    def _save(self) -> None:
        self.path.write_text(
            json.dumps({"rules": [r.to_dict() for r in self._items.values()]}, indent=2),
            encoding="utf-8",
        )

    # ── operations ──────────────────────────────────────────────────────────────
    def enqueue(self, rule: PendingRule) -> str:
        self._items[rule.id] = rule
        self._save()
        return rule.id

    def get(self, rule_id: str) -> PendingRule | None:
        return self._items.get(rule_id)

    def list(self, status: str | None = None) -> list[PendingRule]:
        items = sorted(self._items.values(), key=lambda r: r.created_ts, reverse=True)
        return [r for r in items if status is None or r.status == status]

    def _decide(self, rule_id: str, status: str, reviewer: str, notes: str) -> PendingRule | None:
        r = self._items.get(rule_id)
        if r is None or r.status not in ("pending",):
            return None
        r.status = status
        r.reviewer = reviewer
        r.notes = notes
        r.decided_ts = round(time.time(), 3)
        self._save()
        return r

    def approve(self, rule_id: str, reviewer: str = "analyst", notes: str = "") -> PendingRule | None:
        return self._decide(rule_id, "approved", reviewer, notes)

    def reject(self, rule_id: str, reviewer: str = "analyst", notes: str = "") -> PendingRule | None:
        return self._decide(rule_id, "rejected", reviewer, notes)

    def mark_deployed(self, rule_id: str) -> PendingRule | None:
        r = self._items.get(rule_id)
        if r is None:
            return None
        r.status = "deployed"
        self._save()
        return r

    def counts(self) -> dict:
        c: dict[str, int] = {}
        for r in self._items.values():
            c[r.status] = c.get(r.status, 0) + 1
        return c
