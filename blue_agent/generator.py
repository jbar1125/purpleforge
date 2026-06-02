import json
from pathlib import Path
from llm_client.base import LLMClient
from splunk_client.search import SearchClient

GENERATED_DIR = Path(__file__).parent / "rules" / "generated"

SYSTEM_PROMPT = """You are an expert Splunk detection engineer specializing in MITRE ATT&CK.
Your job is to write SPL (Splunk Processing Language) detection rules that catch specific
attack patterns that have evaded existing rules.

Rules for your response:
- Return ONLY a JSON object: {{"spl": "...", "explanation": "one sentence"}}
- The SPL must search index=arena_attacks
- The SPL must end with: | eval technique="{technique_id}", rule_name="{rule_name}"
- Write the narrowest rule that catches the attack without matching normal activity
- No markdown, no code fences, no text outside the JSON"""

USER_PROMPT_TEMPLATE = """
TECHNIQUE: {technique_id} — {technique_name}

ATTACK EVENTS THAT WERE NOT CAUGHT (sample):
{sample_events}

EXISTING RULES THAT MISSED THIS ATTACK:
{existing_rules_text}

{catching_rule_section}

MUTATION APPLIED BY RED (what changed to evade):
{mutation_context}

Your task: Write a NEW SPL detection rule that catches this specific evasion pattern.
Focus on what makes these events anomalous AFTER the mutation — not just what the
baseline rule already checks.

The rule_name for your eval statement must be exactly: "{rule_name}"
Return JSON: {{"spl": "...", "explanation": "..."}}
"""

CATCHING_RULE_SECTION = """RULE THAT PREVIOUSLY CAUGHT THIS (now being evaded):
{catching_spl}

The red agent mutated its attack specifically to evade the rule above.
Your new rule must catch the mutated variant that the above rule misses.
"""


class Generator:
    """
    Uses an LLM to generate new SPL detection rules for missed attacks.

    Key improvement over v1: the generator now receives:
    - The specific catching rule red is evading (not just all existing rules)
    - The mutation overrides red applied (what fields changed)
    - Only rules relevant to the technique (not truncated alphabetically)

    Validates generated SPL with Splunk's parse endpoint before saving.
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
        catching_rule_spl: str = None,
        mutation_overrides: dict = None,
    ) -> str | None:
        """
        Generate and save a new detection rule for a missed technique.

        Args:
            catching_rule_spl: The SPL of the rule red is now evading (critical context).
            mutation_overrides: The field changes red applied to evade detection.
        Returns the saved file path, or None on failure.
        """
        rule_name = f"generated_r{round_num}_{technique_id.replace('.', '_')}"

        # Only show rules relevant to this technique — not alphabetical truncation
        relevant_rules = {
            name: rule for name, rule in existing_rules.items()
            if technique_id.replace(".", "_") in name or technique_id in rule.get("spl", "")
        }
        # Fall back to all rules if none are technique-specific
        if not relevant_rules:
            relevant_rules = dict(list(existing_rules.items())[:8])

        existing_rules_text = "\n".join(
            f"  [{name}]:\n    {rule['spl'][:300]}"
            for name, rule in relevant_rules.items()
        )

        # The catching rule section — this is what red is now evading
        if catching_rule_spl:
            catching_section = CATCHING_RULE_SECTION.format(catching_spl=catching_rule_spl)
        else:
            catching_section = "(No prior catching rule — first time this technique was missed.)"

        # Mutation context — what red changed
        mutation_context = json.dumps(mutation_overrides, indent=2) if mutation_overrides else "Unknown (first miss)"

        # Clean sample events — remove internal tracking fields before sending to LLM
        sample = missed_events[:8]
        clean_sample = [
            {k: v for k, v in ev.items() if not k.startswith("arena_") and k != "_time"}
            for ev in sample
        ]

        system = SYSTEM_PROMPT.format(technique_id=technique_id, rule_name=rule_name)
        prompt = USER_PROMPT_TEMPLATE.format(
            technique_id=technique_id,
            technique_name=technique_name,
            sample_events=json.dumps(clean_sample, indent=2),
            existing_rules_text=existing_rules_text,
            catching_rule_section=catching_section,
            mutation_context=mutation_context,
            rule_name=rule_name,
        )

        for attempt in range(self.max_retries):
            try:
                raw = self.llm.complete_json(system, prompt)
                raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
                result = json.loads(raw)
                spl = result.get("spl", "").strip()

                if not spl:
                    print(f"  [blue generator] attempt {attempt+1}: empty SPL returned")
                    continue

                # Ensure the eval tag is present and correct
                if f'rule_name="{rule_name}"' not in spl:
                    spl += f'\n| eval technique="{technique_id}", rule_name="{rule_name}"'

                # Validate syntax using Splunk's parse endpoint
                valid, parse_error = self._validate_spl_syntax(spl)
                if not valid:
                    print(f"  [blue generator] attempt {attempt+1}: invalid SPL — {parse_error}")
                    # Feed the error back into the next attempt
                    prompt += f"\n\nYour previous attempt had this SPL error: {parse_error}\nFix it."
                    continue

                # Save the rule
                out_path = GENERATED_DIR / f"{rule_name}.spl"
                out_path.write_text(spl)
                explanation = result.get("explanation", "")
                print(f"  [blue generator] ✓ saved: {rule_name}")
                print(f"  [blue generator]   {explanation}")
                return str(out_path)

            except (json.JSONDecodeError, Exception) as e:
                print(f"  [blue generator] attempt {attempt+1} error: {e}")

        print(f"  [blue generator] ✗ failed after {self.max_retries} attempts for {technique_id}")
        return None

    def _validate_spl_syntax(self, spl: str) -> tuple[bool, str]:
        """
        Validate SPL syntax using Splunk's search parser endpoint.
        Returns (is_valid, error_message).
        """
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()

            # Use the parse endpoint — syntax check only, no data scanned
            resp = requests.get(
                f"{self.search.base}/services/search/parser",
                auth=self.search.auth,
                params={"q": f"search {spl}", "output_mode": "json"},
                verify=self.search.verify,
                timeout=10,
            )
            if resp.status_code == 200:
                return True, ""
            data = resp.json()
            messages = data.get("messages", [])
            errors = [m.get("text", "") for m in messages if m.get("type") == "FATAL"]
            return False, "; ".join(errors) if errors else f"HTTP {resp.status_code}"
        except Exception as e:
            # If parse endpoint fails, fall back to permissive (don't block)
            return True, ""
