import json
from pathlib import Path
from llm_client.base import LLMClient
from splunk_client.search import SearchClient

GENERATED_DIR = Path(__file__).parent / "rules" / "generated"

SYSTEM_PROMPT = """You are a Splunk detection engineer. Your job is to write SPL (Splunk Processing Language)
detection rules that catch specific attack patterns.

Rules for your response:
- Return ONLY a JSON object with two keys: "spl" (the SPL query string) and "explanation" (one sentence)
- The SPL must query index=arena_attacks
- The SPL must end with: | eval technique="{technique_id}", rule_name="{rule_name}"
- Do not use markdown, no code fences, no extra text outside the JSON"""

USER_PROMPT_TEMPLATE = """
These attack events were injected into Splunk (index=arena_attacks) but were NOT caught by any existing rule.

Technique: {technique_id} — {technique_name}

Sample missed events (JSON):
{sample_events}

Existing rules that missed this attack:
{existing_rules}

Write a new SPL detection query that would catch this pattern.
The rule_name placeholder in the eval statement should be: "{rule_name}"
Return JSON: {{"spl": "...", "explanation": "..."}}
"""


class Generator:
    """
    Uses an LLM to generate new SPL detection rules for missed attacks.
    Validates generated SPL with a dry-run before saving.
    """

    def __init__(self, llm: LLMClient, search_client: SearchClient, max_retries: int = 3):
        self.llm = llm
        self.search = search_client
        self.max_retries = max_retries

    def generate_rule(
        self,
        technique_id: str,
        technique_name: str,
        missed_events: list[dict],
        existing_rules: dict,
        round_num: int,
    ) -> str | None:
        """
        Generate and save a new detection rule for a missed technique.
        Returns the saved file path, or None on failure.
        """
        rule_name = f"generated_r{round_num}_{technique_id.replace('.', '_')}"

        existing_rules_text = "\n".join(
            f"  [{name}]: {rule['spl'][:200]}"
            for name, rule in list(existing_rules.items())[:5]
        )

        # Send a sample of events (cap at 5 to keep prompt short)
        sample = missed_events[:5] if len(missed_events) > 5 else missed_events
        # Strip internal tracking fields before sending to LLM
        clean_sample = [
            {k: v for k, v in ev.items() if not k.startswith("arena_") and k != "_time"}
            for ev in sample
        ]

        system = SYSTEM_PROMPT.format(technique_id=technique_id, rule_name=rule_name)
        prompt = USER_PROMPT_TEMPLATE.format(
            technique_id=technique_id,
            technique_name=technique_name,
            sample_events=json.dumps(clean_sample, indent=2),
            existing_rules=existing_rules_text,
            rule_name=rule_name,
        )

        for attempt in range(self.max_retries):
            try:
                raw = self.llm.complete_json(system, prompt)
                raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
                result = json.loads(raw)
                spl = result.get("spl", "").strip()

                if not spl:
                    continue

                # Ensure the eval tag is present
                if "rule_name" not in spl:
                    spl += f'\n| eval technique="{technique_id}", rule_name="{rule_name}"'

                # Validate syntax before saving
                if not self._validate_spl(spl):
                    print(f"  [blue generator] attempt {attempt+1}: generated invalid SPL, retrying...")
                    continue

                # Save to generated rules dir
                out_path = GENERATED_DIR / f"{rule_name}.spl"
                out_path.write_text(spl)
                explanation = result.get("explanation", "")
                print(f"  [blue generator] saved new rule: {rule_name}")
                print(f"  [blue generator] explanation: {explanation}")
                return str(out_path)

            except (json.JSONDecodeError, Exception) as e:
                print(f"  [blue generator] attempt {attempt+1} error: {e}")

        print(f"  [blue generator] failed to generate rule for {technique_id} after {self.max_retries} attempts")
        return None

    def _validate_spl(self, spl: str) -> bool:
        """Quick syntax check — tries to run it with a 1-minute window."""
        try:
            self.search.run_search_async(spl, earliest="-1m", latest="now", max_results=1)
            return True
        except Exception:
            return False
