import json
import os
from pathlib import Path

from splunk_client.hec import HECClient
from llm_client.base import LLMClient
from .injector import Injector
from .mutator import Mutator

TEMPLATES_DIR = Path(__file__).parent / "templates"


class RedAgent:
    """
    Red team agent. Loads MITRE ATT&CK-mapped attack templates, injects them
    into Splunk, and mutates them based on blue's catching rules.

    v1 scope: 6 techniques, template-based injection, LLM-driven mutation.
    To add a new technique in v2+: drop a JSON file in red_agent/templates/.
    """

    def __init__(self, hec: HECClient, llm: LLMClient, index: str, technique_ids: list[str]):
        self.injector = Injector(hec=hec, index=index)
        self.mutator = Mutator(llm=llm)
        self.technique_ids = technique_ids
        self.templates = self._load_templates()
        # Stores per-technique overrides from LLM mutations, updated each round
        self._overrides: dict[str, dict] = {tid: {} for tid in technique_ids}

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

    def receive_catching_rule(self, technique_id: str, rule_spl: str) -> None:
        """
        Called by the orchestrator when blue detects an attack.
        Triggers LLM mutation so next round's injection attempts to evade the rule.
        """
        if technique_id not in self.templates:
            return
        print(f"  [red] {technique_id}: mutating to evade rule...")
        overrides = self.mutator.mutate(
            technique_def=self.templates[technique_id],
            catching_rule_spl=rule_spl,
        )
        self._overrides[technique_id] = overrides
