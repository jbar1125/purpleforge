import json
import os
from pathlib import Path

from splunk_client.hec import HECClient
from llm_client.base import LLMClient
from .injector import Injector
from .mutator import Mutator
from .poisoner import Poisoner

TEMPLATES_DIR = Path(__file__).parent / "templates"


class RedAgent:
    """
    Red team agent. Loads MITRE ATT&CK-mapped attack templates, injects them
    into Splunk, and mutates + poisons based on blue's catching rules.

    v2: Added poisoning (alert-fatigue attacks to burn Blue's rules) and
    cross-session memory (starts from best known mutation, not baseline).
    """

    def __init__(
        self,
        hec: HECClient,
        llm: LLMClient,
        index: str,
        technique_ids: list[str],
        initial_overrides: dict[str, dict] | None = None,
    ):
        self.injector = Injector(hec=hec, index=index)
        self.mutator = Mutator(llm=llm)
        self.poisoner = Poisoner(hec=hec, llm=llm, index=index)
        self.technique_ids = technique_ids
        self.templates = self._load_templates()
        # Load from cross-session memory (or fresh dict if first run)
        self._overrides: dict[str, dict] = {tid: {} for tid in technique_ids}
        if initial_overrides:
            for tid, overrides in initial_overrides.items():
                if tid in self._overrides and overrides:
                    self._overrides[tid] = overrides
                    print(f"  [red] {tid}: resuming from session memory (gen {len(overrides)} field(s) mutated)")
        # Tracks which rule each technique is actively being poisoned against
        self._poisoning_targets: dict[str, str] = {}   # {tid: catching_spl}

    def _load_templates(self) -> dict[str, dict]:
        templates = {}
        for tid in self.technique_ids:
            path = TEMPLATES_DIR / f"{tid}.json"
            if path.exists():
                with open(path) as f:
                    templates[tid] = json.load(f)
            else:
                print(f"  [red] Warning: no template found for {tid} at {path}")
        return templates

    def run_round(self, round_num: int) -> dict[str, list[dict]]:
        """
        Inject all technique templates for this round.
        Returns {technique_id: [injected_events]} for the scorer.
        """
        injected = {}
        for tid in self.technique_ids:
            if tid not in self.templates:
                continue
            overrides = self._overrides.get(tid, {})
            if overrides:
                print(f"  [red] {tid}: injecting with {len(overrides)} mutation(s): {list(overrides.keys())}")
            else:
                print(f"  [red] {tid}: injecting baseline template")
            events = self.injector.inject_technique(
                technique_def=self.templates[tid],
                round_num=round_num,
                overrides=overrides,
            )
            injected[tid] = events
        return injected

    def inject_technique(self, technique_id: str, round_num: int = 0, generation: int = 0) -> list[dict]:
        """
        Inject ONE technique with its current overrides. Used by the real-time
        engine, which drives Red one technique at a time on its own cadence
        (run_round injects the whole set at once for the turn-based mode).
        """
        if technique_id not in self.templates:
            return []
        return self.injector.inject_technique(
            technique_def=self.templates[technique_id],
            round_num=round_num,
            overrides=self._overrides.get(technique_id, {}),
            generation=generation,
        )

    def get_current_overrides(self) -> dict[str, dict]:
        """Return the current mutation overrides so blue knows what red changed."""
        return dict(self._overrides)

    def receive_catching_rule(self, technique_id: str, rule_spl: str) -> None:
        """
        Called when Blue detects an attack.
        Triggers two actions:
          1. LLM mutation — evade the catching rule next round
          2. Start poisoning — flood the rule with FPs to degrade its precision
        """
        if technique_id not in self.templates:
            return
        print(f"  [red] {technique_id}: mutating to evade rule...")
        overrides = self.mutator.mutate(
            technique_def=self.templates[technique_id],
            catching_rule_spl=rule_spl,
        )
        # ACCUMULATE mutations — merge new overrides onto existing ones so that
        # previous successful evasions are never undone by a later empty result.
        # New keys are added; same keys are overwritten with the latest value.
        existing = self._overrides.get(technique_id, {})
        self._overrides[technique_id] = {**existing, **overrides}
        # Register this rule for ongoing poisoning
        self._poisoning_targets[technique_id] = rule_spl

    def run_poison_campaign(self, round_num: int, count_per_rule: int = 15) -> dict[str, int]:
        """
        Inject FP-flooding events for every active poisoning target.
        Call this each round after receiving catching rules.
        Returns {technique_id: events_injected}.
        """
        results = {}
        for tid, spl in list(self._poisoning_targets.items()):
            events = self.poisoner.poison_rule(
                technique_id=tid,
                catching_spl=spl,
                round_num=round_num,
                count=count_per_rule,
            )
            if events:
                results[tid] = len(events)
                print(f"  [red] poisoning: injected {len(events)} FP events for {tid}")
        return results

    def stop_poisoning(self, technique_id: str) -> None:
        """Stop poisoning a technique (e.g. when its rule has been burned)."""
        self._poisoning_targets.pop(technique_id, None)
