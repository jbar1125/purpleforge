import json
from collections import defaultdict
from llm_client.base import LLMClient

SYSTEM_PROMPT = """You are a senior red team operator and detection engineer. \
Your job is to analyze a Splunk detection rule (SPL), identify exactly which field \
or pattern causes the current attack to be detected, and mutate the minimum set of \
attack parameters to evade the rule while fully preserving the attack objective.

Hard rules — NEVER violate these:
- Do NOT change EventCode — it is the Windows/Sysmon event identifier
- Do NOT change TargetImage for process-access or injection techniques
- Do NOT change arena_technique, arena_round, or arena_generation
- Only change fields listed in the ALLOWED FIELDS section
- count must be between 1 and 200; spread_seconds must be between 1 and 90
- Every returned key must be from the ALLOWED FIELDS list
- Values must be realistic — they must look like actual enterprise log entries
- Prefer minimum change: mutate as FEW fields as needed to break the detection anchor

Output format: a JSON object with two optional keys:
  "_analysis": a one-sentence explanation of WHY the rule catches the attack and what you are changing
  <field>: <new_value> for each mutated field

Example output:
{
  "_analysis": "The rule counts 4625 events by Source_Network_Address and fires when count > 10; reducing count to 7 evades the threshold.",
  "count": 7,
  "spread_seconds": 75
}"""

USER_PROMPT_TEMPLATE = """### Detection rule catching this attack (SPL):
{catching_rule}

### Attack template (context only — do NOT return top-level keys like "events"):
{technique_json}

### Attack objective (must be fully preserved):
{objective}

### CRITICAL — "count" is applied PER event spec, not globally:
When you set "count": N, the injector applies count=N to every event spec simultaneously.
Current injection totals at unmodified counts:
{count_context}
To evade a threshold T on EventCode X (with S specs), you need: count × S < T.
Example: threshold=25, 2 specs for EventCode 4625 → need count ≤ 12 (12×2=24 < 25).

### Known detection anchors for this technique (pre-analyzed threat intel):
{detection_anchors}

### ALLOWED FIELDS (you may only mutate these — they are event-level field names):
{evadable_fields}

### SPL pattern → evasion cheat-sheet (apply the matching strategy):
- stats count by X | where count > N  →  reduce count below N accounting for number of specs (see CRITICAL above)
- stats dc(field) by X | where dc > M  →  reduce distinct values below M
- where Field="exact_value"  →  change that field to a valid alternative that preserves attack semantics
- where CommandLine LIKE "%pattern%"  →  use a variant command that avoids the detected substring
- where Image="path"  →  use an alternative executable that performs the same function
- NOT (SourceImage="*\\whitelist.exe")  →  set SourceImage to a whitelisted value to blend in
- TargetObject LIKE "%RegKey%"  →  use an alternative key path with equivalent effect

### Your task:
1. Identify the specific anchor in the SPL (threshold, field match, or whitelist exclusion).
2. Cross-reference the detection anchors listed above.
3. Select the minimum fields from ALLOWED FIELDS that break the anchor.
4. If count is relevant, calculate carefully using the per-spec totals above.
5. Return a JSON object with "_analysis" (one sentence) and your field mutations.

Return ONLY valid JSON. No markdown, no explanation outside the JSON object."""


# Fields that define the attack identity — mutator must never return these
_PROTECTED_FIELDS = {
    "EventCode", "TargetImage", "sourcetype",
    "arena_technique", "arena_round", "arena_generation",
}

# Strip this from the returned overrides — it is reasoning, not a field override
_ANALYSIS_KEY = "_analysis"


class Mutator:
    """
    Uses an LLM to mutate attack parameters to evade a catching SPL rule.
    Employs chain-of-thought via the _analysis key: the model explains WHY
    the rule catches the event before deciding what to change, which produces
    more precise and realistic evasion than asking it to mutate blindly.
    """

    def __init__(self, llm: LLMClient, max_retries: int = 3):
        self.llm = llm
        self.max_retries = max_retries

    def mutate(self, technique_def: dict, catching_rule_spl: str) -> dict:
        """
        Returns a dict of validated field overrides.
        Falls back to empty dict if LLM fails or produces invalid mutations.
        """
        hints = technique_def.get("mutation_hints", {})
        evadable_fields = hints.get("evadable_fields", [])
        objective = hints.get("objective", "Achieve the attack goal")
        detection_anchors = hints.get("detection_anchors", [])

        if not evadable_fields:
            print("  [red mutator] No evadable_fields defined — skipping mutation")
            return {}

        anchors_text = "\n".join(f"  • {a}" for a in detection_anchors) if detection_anchors else "  (none pre-analyzed — derive from the SPL above)"

        # Compute per-EventCode injection totals so the LLM can do accurate count math.
        # count overrides apply PER spec, so EventCodes with multiple specs multiply.
        ec_specs: dict[str, list[int]] = defaultdict(list)
        for spec in technique_def.get("events", []):
            ec = spec.get("template", {}).get("EventCode")
            if ec is not None:
                ec_specs[str(ec)].append(spec.get("count", 1))
        count_lines = []
        for ec in sorted(ec_specs):
            counts = ec_specs[ec]
            total = sum(counts)
            detail = " + ".join(str(c) for c in counts)
            count_lines.append(
                f"  EventCode {ec}: {len(counts)} spec(s), counts=[{detail}], "
                f"total events currently = {total}"
            )
        count_context = "\n".join(count_lines) or "  (no event specs)"

        prompt = USER_PROMPT_TEMPLATE.format(
            catching_rule=catching_rule_spl,
            technique_json=json.dumps(technique_def, indent=2),
            objective=objective,
            count_context=count_context,
            detection_anchors=anchors_text,
            evadable_fields=json.dumps(evadable_fields),
        )

        for attempt in range(self.max_retries):
            try:
                raw = self.llm.complete_json(SYSTEM_PROMPT, prompt)
                raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
                result = json.loads(raw)

                if not isinstance(result, dict):
                    continue

                # Log the model's reasoning if present
                analysis = result.pop(_ANALYSIS_KEY, None)
                if analysis:
                    print(f"  [red mutator] analysis: {analysis}")

                overrides = result

                # Reject any mutation touching protected fields
                invalid = [k for k in overrides if k in _PROTECTED_FIELDS]
                if invalid:
                    print(f"  [red mutator] attempt {attempt+1}: rejected protected fields: {invalid}")
                    prompt += f"\n\nDo NOT change these fields: {invalid}. They define the attack type."
                    continue

                # Reject fields not in the allowed list (count/spread_seconds are always allowed)
                not_allowed = [k for k in overrides if k not in evadable_fields and k not in ("count", "spread_seconds")]
                if not_allowed:
                    print(f"  [red mutator] attempt {attempt+1}: rejected fields not in allowed list: {not_allowed}")
                    prompt += f"\n\nOnly use fields from this list: {evadable_fields}"
                    continue

                if overrides:
                    print(f"  [red mutator] mutation accepted: {list(overrides.keys())}")
                else:
                    print(f"  [red mutator] no mutations returned (rule may not be evadable via allowed fields)")

                return overrides

            except (json.JSONDecodeError, Exception) as e:
                print(f"  [red mutator] attempt {attempt+1} error: {e}")

        print(f"  [red mutator] failed after {self.max_retries} attempts — using no mutation")
        return {}
