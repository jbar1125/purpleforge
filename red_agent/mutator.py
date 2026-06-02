import json
from llm_client.base import LLMClient

SYSTEM_PROMPT = """You are a red team operator. Your job is to mutate attack parameters so that
a given attack still achieves its objective but evades specific Splunk detection rules (SPL queries).

Rules for mutation:
- The attack objective must remain the same (e.g., brute force still tries to guess a password)
- Only change the *parameters* (thresholds, field values, timing, count) — not the attack type
- Return ONLY a valid JSON object with the overridden fields
- Do not add fields that aren't in the original template
- Explain nothing outside the JSON"""

USER_PROMPT_TEMPLATE = """
Detection rule that caught this attack (SPL):
{catching_rule}

Attack template that was caught:
{technique_json}

Mutation hints (fields that can be changed):
{mutation_hints}

Generate modified field values that evade the detection rule above.
Return a JSON object with ONLY the fields you are changing and their new values.
Example output: {{"count": 5, "spread_seconds": 3600, "Logon_Type": 7}}
"""


class Mutator:
    """
    Uses an LLM to mutate attack parameters to evade a catching SPL rule.
    Called by the orchestrator after blue detects an attack.
    """

    def __init__(self, llm: LLMClient, max_retries: int = 3):
        self.llm = llm
        self.max_retries = max_retries

    def mutate(self, technique_def: dict, catching_rule_spl: str) -> dict:
        """
        Returns a dict of field overrides to apply to the template.
        Falls back to empty dict (no mutation) if LLM fails after retries.
        """
        prompt = USER_PROMPT_TEMPLATE.format(
            catching_rule=catching_rule_spl,
            technique_json=json.dumps(technique_def, indent=2),
            mutation_hints=json.dumps(technique_def.get("mutation_hints", {}), indent=2),
        )

        for attempt in range(self.max_retries):
            try:
                raw = self.llm.complete_json(SYSTEM_PROMPT, prompt)
                # Strip markdown fences if the model added them anyway
                raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
                overrides = json.loads(raw)
                if isinstance(overrides, dict):
                    return overrides
            except (json.JSONDecodeError, Exception) as e:
                if attempt == self.max_retries - 1:
                    print(f"  [red mutator] LLM failed after {self.max_retries} attempts: {e}. Using no mutation.")
        return {}
