"""
blue_agent/env_whitelist.py — learn what's normal HERE and suppress it.

WHY THIS EXISTS
---------------
The same behavior is malicious in one environment and routine in another. A host
opening 200 SMB sessions is a vuln scanner you own — or lateral movement. A service
account failing auth on 30 hosts is a misconfigured app — or a spray. Hard-coding
these exceptions doesn't scale; you LEARN them from a known-good baseline window.

This whitelist is fit on benign traffic (the arena's benign_loop, or a quiet
production window) and records frequently-recurring (signal, entity) tuples. At
detection time, an event matching a learned-benign tuple is suppressed, cutting the
false positives that Red's poison campaign tries to manufacture.

Conservative by design:
  - only tuples seen at least `min_count` times in the baseline are trusted;
  - whitelisting is per signal TYPE (sourcetype + EventCode), so trusting a service
    account for network logons does NOT trust it for, say, LSASS access.

`to_spl_filter()` emits a `NOT (...)` clause you can append to any deployed rule, or
the rows for a Splunk lookup-based suppression list.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

# Which event field identifies the "entity" to whitelist, per signal type.
# Falls back to a generic set if the specific field isn't present.
_ENTITY_FIELDS = ("Account_Name", "user", "SourceImage", "Image",
                  "Source_Network_Address", "src_ip", "Computer", "host")


def _signal_key(event: dict) -> str:
    """Coarse signal type: sourcetype + EventCode (what KIND of activity this is)."""
    st = str(event.get("sourcetype", event.get("_sourcetype", "")))
    code = str(event.get("EventCode", event.get("event_id", "")))
    return f"{st}|{code}"


def _entity_of(event: dict) -> str | None:
    for f in _ENTITY_FIELDS:
        if event.get(f) not in (None, ""):
            return f"{f}={event[f]}"
    return None


@dataclass
class EnvironmentWhitelist:
    """
    Args:
        min_count: a (signal, entity) tuple must appear at least this many times in
            the benign baseline to be trusted (default 3).
    """
    min_count: int = 3
    _counts: Counter = field(default_factory=Counter)
    _trusted: set[tuple[str, str]] = field(default_factory=set)

    def learn(self, benign_events: list[dict]) -> "EnvironmentWhitelist":
        for ev in benign_events:
            entity = _entity_of(ev)
            if entity is None:
                continue
            self._counts[(_signal_key(ev), entity)] += 1
        self._trusted = {k for k, c in self._counts.items() if c >= self.min_count}
        return self

    def is_whitelisted(self, event: dict) -> bool:
        entity = _entity_of(event)
        if entity is None:
            return False
        return (_signal_key(event), entity) in self._trusted

    def filter(self, events: list[dict]) -> list[dict]:
        """Drop events that match a learned-benign tuple. Returns the survivors."""
        return [e for e in events if not self.is_whitelisted(e)]

    def trusted_pairs(self) -> list[tuple[str, str]]:
        return sorted(self._trusted)

    def to_spl_filter(self) -> str:
        """
        A NOT(...) suppression clause built from the trusted entity values, grouped
        by the field they came from. Append to any rule's base search.
        """
        by_field: dict[str, set[str]] = {}
        for _signal, entity in self._trusted:
            if "=" not in entity:
                continue
            field_name, value = entity.split("=", 1)
            by_field.setdefault(field_name, set()).add(value)
        if not by_field:
            return ""
        clauses = []
        for field_name, values in sorted(by_field.items()):
            joined = " OR ".join(f'{field_name}="{v}"' for v in sorted(values))
            clauses.append(f"({joined})")
        return "NOT (" + " OR ".join(clauses) + ")"

    def summary(self) -> dict:
        return {"trusted_tuples": len(self._trusted), "observed_tuples": len(self._counts)}
