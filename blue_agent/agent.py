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

    v1 scope: baseline rules + LLM-generated rules per round.
    To add more baseline rules in v2+: drop .spl files in blue_agent/rules/baseline/.
    """

    def __init__(self, search: SearchClient, llm: LLMClient, mcp: MCPClient = None):
        self.detector = Detector(search_client=search, mcp_client=mcp)
        self.generator = Generator(llm=llm, search_client=search)
        # Tracks which rule name caught which technique this round
        self._last_catching_rules: dict[str, str] = {}

    def run_detection(self, earliest: str, latest: str) -> dict[str, list[dict]]:
        """
        Run all detection rules and return raw results.
        Returns {rule_name: [result_rows]}.
        """
        return self.detector.run_all_rules(earliest=earliest, latest=latest)

    def generate_rules_for_misses(
        self,
        missed_techniques: dict[str, list[dict]],
        round_num: int,
    ) -> list[str]:
        """
        For each missed technique, ask the LLM to generate a new detection rule.
        Returns list of saved rule file paths.
        """
        saved = []
        existing_rules = self.detector.get_all_rules()

        for tid, events in missed_techniques.items():
            if not events:
                continue
            meta = TECHNIQUES.get(tid, {"name": tid})
            path = self.generator.generate_rule(
                technique_id=tid,
                technique_name=meta["name"],
                missed_events=events,
                existing_rules=existing_rules,
                round_num=round_num,
            )
            if path:
                saved.append(path)
        return saved

    def get_catching_rule_for(self, technique_id: str) -> str | None:
        """
        Returns the SPL of the rule that caught a technique this round,
        or None if it wasn't caught. Used by red's mutator.
        """
        rule_name = self._last_catching_rules.get(technique_id)
        if not rule_name:
            return None
        all_rules = self.detector.get_all_rules()
        return all_rules.get(rule_name, {}).get("spl")

    def record_catching_rule(self, technique_id: str, rule_name: str) -> None:
        self._last_catching_rules[technique_id] = rule_name

    def reset_round(self) -> None:
        self._last_catching_rules = {}
