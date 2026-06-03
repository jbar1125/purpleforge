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
- No markdown, no code fences, no text outside the JSON

CRITICAL SPL SYNTAX RULES (violations cause parse errors):
- Use `| where count >= N` AFTER a stats command, NOT inside it
- `| stats count by field` — `by` takes field names only, no operators
- Correct: `| stats count by Source_Network_Address | where count >= 5`
- Wrong:   `| stats count >= 5 by Source_Network_Address`
- Use double quotes for string values: EventCode=4625, NOT EventCode="4625"
- Do NOT use single quotes for field values in search filters

EXAMPLES OF VALID RULES:

Example 1 — Brute Force with low threshold:
{{"spl": "index=arena_attacks EventCode=4625 | bucket _time span=10m | stats count by Source_Network_Address, _time | where count >= 5 | eval technique=\\"T1110.001\\", rule_name=\\"generated_r2_T1110_001\\"", "explanation": "Detects 5+ failed logins from same IP in a 10-minute window"}}

Example 2 — LSASS dump by suspicious process:
{{"spl": "index=arena_attacks EventCode=10 TargetImage=\\"*lsass.exe\\" NOT (SourceImage=\\"*svchost.exe\\" OR SourceImage=\\"*MsMpEng.exe\\") | eval technique=\\"T1003.001\\", rule_name=\\"generated_r1_T1003_001\\"", "explanation": "Catches non-system processes opening a handle to lsass.exe"}}

Example 3 — RDP from unexpected source using stats:
{{"spl": "index=arena_attacks EventCode=4624 Logon_Type=10 | stats count by Source_Network_Address | where count >= 1 | eval technique=\\"T1021.001\\", rule_name=\\"generated_r3_T1021_001\\"", "explanation": "Detects any RDP logon from a recorded source address"}}"""

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

{count_hint}

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

        # If red reduced count, threshold rules won't work — tell the LLM to detect on field patterns
        mutated_count = (mutation_overrides or {}).get("count")
        if mutated_count is not None and int(mutated_count) <= 5:
            count_hint = (
                f"IMPORTANT: Red reduced event count to {mutated_count}. "
                "Do NOT use a stats count threshold — instead detect on specific field values or "
                "behavior patterns present in the sample events above."
            )
        else:
            count_hint = ""

        system = SYSTEM_PROMPT.format(technique_id=technique_id, rule_name=rule_name)
        prompt = USER_PROMPT_TEMPLATE.format(
            technique_id=technique_id,
            technique_name=technique_name,
            sample_events=json.dumps(clean_sample, indent=2),
            existing_rules_text=existing_rules_text,
            catching_rule_section=catching_section,
            mutation_context=mutation_context,
            rule_name=rule_name,
            count_hint=count_hint,
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

                # Ensure the eval tag is present (accept both single and double quotes)
                if f'rule_name="{rule_name}"' not in spl and f"rule_name='{rule_name}'" not in spl:
                    spl += f'\n| eval technique="{technique_id}", rule_name="{rule_name}"'

                # Validate syntax using Splunk's parse endpoint
                valid, parse_error = self._validate_spl_syntax(spl)
                if not valid:
                    print(f"  [blue generator] attempt {attempt+1}: invalid SPL — {parse_error}")
                    # Feed the error back into the next attempt
                    prompt += f"\n\nYour previous attempt had this SPL error: {parse_error}\nFix it."
                    continue

                # Save the rule (overwrite if same round/technique; prevents stale rules from prior runs)
                out_path = GENERATED_DIR / f"{rule_name}.spl"
                out_path.write_text(spl, encoding="utf-8")
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
            resp = requests.post(
                f"{self.search.base}/services/search/parser",
                auth=self.search.auth,
                data={"q": f"search {spl}", "output_mode": "json"},
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
