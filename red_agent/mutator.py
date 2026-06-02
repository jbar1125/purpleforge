import json
from llm_client.base import LLMClient

SYSTEM_PROMPT = """You are a red team operator. Your job is to mutate attack parameters so that
a given attack still achieves its objective but evades a specific Splunk detection rule.

Hard rules:
- The attack TYPE must not change (brute force stays brute force, RDP stays RDP)
- Do NOT change EventCode — this is the core identifier of the event type
- Do NOT change TargetImage for process injection techniques
- Only change: timing (count, spread_seconds), source fields (IP, username variation),
  threshold-adjacent values, or alternative but equivalent field values
- count must be between 1 and 200; spread_seconds must be between 1 and 90
- Every key you return must already exist in the template's evadable_fields list
- Return ONLY a valid JSON object with the changed fields and their new values
- No explanation, no markdown, no extra text"""

USER_PROMPT_TEMPLATE = """
Detection rule catching this attack (SPL):
{catching_rule}

Attack template (for context only — do NOT return top-level keys like "events" or "mutation_hints"):
{technique_json}

Fields you are ALLOWED to change (these are event field names, not template structure keys):
{evadable_fields}

Attack objective (must be preserved):
{objective}

Return a JSON object with ONLY field names from the list above and their new values.
These are event-level fields injected into Splunk — NOT keys from the template structure.
Example: {{"count": 3, "spread_seconds": 60}}
Example: {{"GrantedAccess": "0x1038", "SourceImage": "C:\\\\Windows\\\\explorer.exe"}}
"""

# Fields that define the attack type — mutator must never change these
_PROTECTED_FIELDS = {
    "EventCode", "TargetImage", "sourcetype", "arena_technique", "arena_round"
}


class Mutator:
    """
    Uses an LLM to mutate attack parameters to evade a catching SPL rule.
    Validates mutations to ensure they don't break the attack objective.
    """

    def __init__(self, llm: LLMClient, max_retries: int = 3):
        self.llm = llm
        self.max_retries = max_retries

    def mutate(self, technique_def: dict, catching_rule_spl: str) -> dict:
        """
        Returns a dict of validated field overrides to apply to the template.
        Falls back to empty dict if LLM fails or produces invalid mutations.
        """
        mutation_hints = technique_def.get("mutation_hints", {})
        evadable_fields = mutation_hints.get("evadable_fields", [])
        objective = mutation_hints.get("objective", "Achieve the attack goal")

        if not evadable_fields:
            print("  [red mutator] No evadable_fields defined — skipping mutation")
            return {}

        prompt = USER_PROMPT_TEMPLATE.format(
            catching_rule=catching_rule_spl,
            technique_json=json.dumps(technique_def, indent=2),
            evadable_fields=json.dumps(evadable_fields),
            objective=objective,
        )

        for attempt in range(self.max_retries):
            try:
                raw = self.llm.complete_json(SYSTEM_PROMPT, prompt)
                raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
                overrides = json.loads(raw)

                if not isinstance(overrides, dict):
                    continue

                # Validate: reject any mutation touching protected fields
                invalid = [k for k in overrides if k in _PROTECTED_FIELDS]
                if invalid:
                    print(f"  [red mutator] attempt {attempt+1}: rejected mutation of protected fields: {invalid}")
                    prompt += f"\n\nDo NOT change these fields: {invalid}. They define the attack type."
                    continue

                # Validate: only allow fields from evadable_fields list
                not_allowed = [k for k in overrides if k not in evadable_fields and k not in ("count", "spread_seconds")]
                if not_allowed:
                    print(f"  [red mutator] attempt {attempt+1}: rejected fields not in evadable list: {not_allowed}")
                    prompt += f"\n\nOnly change fields from this list: {evadable_fields}"
                    continue

                print(f"  [red mutator] mutation accepted: {list(overrides.keys())}")
                return overrides

            except (json.JSONDecodeError, Exception) as e:
                print(f"  [red mutator] attempt {attempt+1} error: {e}")

        print(f"  [red mutator] failed after {self.max_retries} attempts — using no mutation")
        return {}
