from splunk_client.search import SearchClient
from splunk_client.mcp import MCPClient
from llm_client.base import LLMClient
from mitre.techniques import TECHNIQUES
from .detector import Detector
from .generator import Generator


class BlueAgent:
    """
    Blue team agent. Runs detection rules, scores hits/misses,
    and auto-generates new rules for missed techniques.

    The generator now receives the catching rule and mutation overrides
    so it can write rules that target the specific evasion pattern,
    not just the baseline attack shape.
    """

    def __init__(self, search: SearchClient, llm: LLMClient, mcp: MCPClient = None):
        self.detector = Detector(search_client=search, mcp_client=mcp)
        self.generator = Generator(llm=llm, search_client=search)
        # {technique_id: rule_name} for the rule that caught it this round
        self._last_catching_rules: dict[str, str] = {}

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
        """
        saved = []
        existing_rules = self.detector.get_all_rules()
        red_mutations = red_mutations or {}

        for tid, events in missed_techniques.items():
            if not events:
                continue
            meta = TECHNIQUES.get(tid, {"name": tid})

            # Get the prior catching rule for this technique (what red is evading)
            catching_spl = self.get_catching_rule_for(tid)

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
        return saved

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
