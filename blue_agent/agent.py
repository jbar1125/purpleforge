from splunk_client.search import SearchClient
from splunk_client.mcp import MCPClient
from llm_client.base import LLMClient
from mitre.techniques import TECHNIQUES
from .detector import Detector
from .generator import Generator

# Proactive rule generation: double-down after this many consecutive misses
PROACTIVE_MISS_THRESHOLD = 3


class BlueAgent:
    """
    Blue team agent. Runs detection rules, scores hits/misses,
    and auto-generates new rules for missed techniques.

    New in v2:
      - Integrates RuleRegistry so burned rules are excluded from detection.
      - Proactive rule generation: when Red mutates a technique Blue was catching,
        Blue immediately generates a hardening variant even before the next miss.
      - Double-down: after PROACTIVE_MISS_THRESHOLD consecutive misses on a technique,
        Blue generates 2 rules per miss instead of 1.
    """

    def __init__(
        self,
        search: SearchClient,
        llm: LLMClient,
        mcp: MCPClient = None,
        index: str = "arena_attacks",
        registry=None,   # RuleRegistry | None
    ):
        self.registry = registry
        self.detector = Detector(search_client=search, mcp_client=mcp, index=index, registry=registry)
        self.generator = Generator(llm=llm, search_client=search, index=index)
        # {technique_id: rule_name} for the rule that caught it this round
        self._last_catching_rules: dict[str, str] = {}
        # Consecutive miss counter per technique — drives proactive doubling
        self._consecutive_misses: dict[str, int] = {}
        # Track techniques whose rules were just burned (need immediate replacement)
        self._recently_burned_techniques: list[str] = []

    def run_detection(self, earliest: str, latest: str) -> dict[str, list[dict]]:
        """Run all detection rules. Returns {rule_name: [result_rows]}."""
        return self.detector.run_all_rules(earliest=earliest, latest=latest)

    def generate_rules_for_misses(
        self,
        missed_techniques: dict[str, list[dict]],
        round_num: int,
        red_mutations: dict[str, dict] = None,
    ) -> list[str]:
        """
        For each missed technique, generate a new detection rule.
        red_mutations: {technique_id: overrides_dict} from red agent — tells
        blue exactly what changed so the new rule targets the evasion.

        Proactive doubling: if a technique has been missed >= PROACTIVE_MISS_THRESHOLD
        consecutive rounds, generate a second variant rule to increase coverage.
        """
        saved = []
        existing_rules = self.detector.get_all_rules()
        red_mutations = red_mutations or {}

        for tid, events in missed_techniques.items():
            if not events:
                continue
            meta = TECHNIQUES.get(tid, {"name": tid})
            catching_spl = self.get_catching_rule_for(tid)

            # Track consecutive misses for proactive doubling
            self._consecutive_misses[tid] = self._consecutive_misses.get(tid, 0) + 1
            rule_count = 2 if self._consecutive_misses[tid] >= PROACTIVE_MISS_THRESHOLD else 1

            for attempt in range(rule_count):
                path = self.generator.generate_rule(
                    technique_id=tid,
                    technique_name=meta["name"],
                    missed_events=events,
                    existing_rules=existing_rules,
                    round_num=round_num,
                    catching_rule_spl=catching_spl,
                    mutation_overrides=red_mutations.get(tid),
                )
                if path:
                    saved.append(path)
                    # Refresh existing_rules so the second attempt knows about rule 1
                    existing_rules = self.detector.get_all_rules()
        return saved

    def generate_hardening_variant(
        self,
        technique_id: str,
        events: list[dict],
        round_num: int,
        red_mutations: dict[str, dict] = None,
    ) -> str | None:
        """
        Proactively generate an evasion-hardened variant when Red mutates a technique
        Blue was catching — anticipating the next evasion before it happens.
        """
        red_mutations = red_mutations or {}
        meta = TECHNIQUES.get(technique_id, {"name": technique_id})
        catching_spl = self.get_catching_rule_for(technique_id)
        existing_rules = self.detector.get_all_rules()
        return self.generator.generate_rule(
            technique_id=technique_id,
            technique_name=meta["name"],
            missed_events=events,
            existing_rules=existing_rules,
            round_num=round_num,
            catching_rule_spl=catching_spl,
            mutation_overrides=red_mutations.get(technique_id),
        )

    def notify_rule_burned(self, technique_id: str) -> None:
        """Called when a rule covering technique_id is burned — queue a replacement."""
        self._recently_burned_techniques.append(technique_id)

    def pop_burned_replacement_queue(self) -> list[str]:
        """Return and clear the list of techniques needing replacement rules."""
        q = list(self._recently_burned_techniques)
        self._recently_burned_techniques.clear()
        return q

    def get_catching_rule_for(self, technique_id: str) -> str | None:
        """Returns SPL of the rule that caught this technique this round."""
        rule_name = self._last_catching_rules.get(technique_id)
        if not rule_name:
            return None
        return self.detector.get_all_rules().get(rule_name, {}).get("spl")

    def record_catching_rule(self, technique_id: str, rule_name: str) -> None:
        self._last_catching_rules[technique_id] = rule_name

    def reset_round(self) -> None:
        self._last_catching_rules = {}
        # Don't reset _consecutive_misses — it compounds across rounds intentionally
