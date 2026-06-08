"""
orchestrator/memory.py — cross-session arena memory.

Persists to results/arena_memory.json so every run starts smarter:
  - Red remembers its best evasion per technique and which rules it burned
  - Blue remembers rule health (which rules are burned) so it doesn't waste
    resources re-running rules Red already destroyed, and accumulates total stats

The memory is intentionally append-only on the sessions list (audit trail)
and merge-on-write on agent memories (latest wins).
"""
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime

from blue_agent.rule_registry import RuleRegistry

MEMORY_PATH = Path(__file__).parent.parent / "results" / "arena_memory.json"


def _default() -> dict:
    return {
        "sessions": [],
        "red_memory": {},       # {technique_id: {best_overrides, evasion_count, compromised}}
        "blue_memory": {
            "rule_registry": {},
            "total_rules_generated": 0,
            "total_rules_burned": 0,
        },
    }


def load() -> dict:
    MEMORY_PATH.parent.mkdir(exist_ok=True)
    if MEMORY_PATH.exists():
        try:
            return json.loads(MEMORY_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return _default()


def save(mem: dict) -> None:
    MEMORY_PATH.parent.mkdir(exist_ok=True)
    MEMORY_PATH.write_text(json.dumps(mem, indent=2), encoding="utf-8")


def load_registry(mem: dict) -> RuleRegistry:
    """Reconstruct RuleRegistry from persisted memory."""
    registry_data = mem.get("blue_memory", {}).get("rule_registry", {})
    if registry_data:
        return RuleRegistry.from_dict(registry_data)
    return RuleRegistry()


def save_registry(mem: dict, registry: RuleRegistry) -> None:
    """Flush registry state into memory dict (caller must call save() after)."""
    blue = mem.setdefault("blue_memory", {})
    blue["rule_registry"] = registry.to_dict()


def load_red_overrides(mem: dict) -> dict[str, dict]:
    """
    Return {technique_id: best_overrides} from memory so Red starts
    from its furthest-evolved mutation rather than baseline.
    """
    return {
        tid: data.get("best_overrides", {})
        for tid, data in mem.get("red_memory", {}).items()
        if data.get("best_overrides")
    }


def record_red_evasion(mem: dict, technique_id: str, overrides: dict, compromised: bool = False) -> None:
    """Update Red's per-technique memory after a successful evasion or compromise."""
    red = mem.setdefault("red_memory", {})
    entry = red.setdefault(technique_id, {"evasion_count": 0, "compromised": False, "best_overrides": {}})
    entry["evasion_count"] += 1
    entry["best_overrides"] = overrides
    if compromised:
        entry["compromised"] = True


def record_session(
    mem: dict,
    run_id: str,
    coverage_end: float,
    rules_generated: int,
    rules_burned: int,
    compromised_techniques: list[str],
    winner: str,
) -> None:
    """Append a session summary to the audit trail."""
    mem.setdefault("sessions", []).append({
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "coverage_end_pct": coverage_end,
        "rules_generated": rules_generated,
        "rules_burned": rules_burned,
        "compromised_techniques": compromised_techniques,
        "winner": winner,
    })
    blue = mem.setdefault("blue_memory", {})
    blue["total_rules_generated"] = blue.get("total_rules_generated", 0) + rules_generated
    blue["total_rules_burned"]    = blue.get("total_rules_burned", 0) + rules_burned


def cross_session_improvement(mem: dict) -> float | None:
    """Coverage improvement vs. the previous session. None if < 2 sessions."""
    sessions = mem.get("sessions", [])
    if len(sessions) < 2:
        return None
    return round(sessions[-1]["coverage_end_pct"] - sessions[-2]["coverage_end_pct"], 1)
