import json
from pathlib import Path

import yaml

from llm_client.base import LLMClient
from splunk_client.search import SearchClient
from splunk_client import sigma_compiler

GENERATED_DIR = Path(__file__).parent / "rules" / "generated"

# ──────────────────────────────────────────────────────────────────────────
# PRIMARY PATH: author portable Sigma YAML, then compile to SPL via pySigma.
# Sigma is the detection-as-code lingua franca — one rule runs on Splunk,
# Elastic, Sentinel, QRadar + 20 SIEMs. Every rule Blue writes is portable.
# ──────────────────────────────────────────────────────────────────────────
SIGMA_SYSTEM_PROMPT = """You are an expert detection engineer who writes Sigma rules.
Sigma is a portable, YAML-based detection format that compiles to any SIEM.

Your job: given attack events that evaded existing detections, write ONE new Sigma
rule (YAML) that catches the evasion pattern.

OUTPUT RULES:
- Output ONLY raw Sigma YAML. No markdown, no code fences, no prose before or after.
- Use the EXACT field names that appear in the attack events (e.g. EventCode, Image,
  CommandLine, TargetImage, SourceImage, GrantedAccess, TargetObject, ScriptBlockText,
  DestinationPort, Source_Network_Address, Account_Name, Logon_Type).
- Reference the event type with the field `EventCode` directly inside each selection.
- Include a tag `attack.{tag}` so the technique is recorded.
- Prefer field modifiers: |contains, |endswith, |startswith, |all for substrings.
- Write the NARROWEST rule that still catches the evaded events — avoid matching
  normal activity.

*** CRITICAL — THE ONLY RULE THAT MATTERS ***
The CATCHING RULE shown in the prompt is ALREADY BYPASSED. Do NOT reconstruct its
anchor. Do NOT use the same field it matched on. Your rule must anchor on a DIFFERENT
field — specifically the field values shown in "WHAT RED MUTATED".

  Step 1: Look at "WHAT RED MUTATED TO EVADE" in the prompt.
  Step 2: Find the specific field values Red changed TO (the new evading values).
  Step 3: Write a rule that matches THOSE new values.

If Red changed Sub_Status from 0xC000006A to 0xC000006D, anchor on 0xC000006D.
If Red changed CommandLine to a new pattern, anchor on that new pattern.
If Red changed SourceImage to a new path, anchor on that new path.
Never write a rule that re-anchors on what the OLD rule already checks — Red has
already proven it can bypass that.

REQUIRED YAML STRUCTURE:
title: <short title>
status: experimental
description: <one sentence: what this catches>
logsource:
  product: windows
detection:
  selection:
    EventCode: <code>
    <Field>|contains: <value>
  condition: selection
level: high
tags:
  - attack.{tag}

EXAMPLE 1 — Red mutated Sub_Status from 0xC000006A to 0xC000006D to evade the
baseline rule. Old rule anchored on 0xC000006A — useless now. Correct response:
anchor on the NEW value 0xC000006D:
title: Brute Force via NTLM General Failure Code
status: experimental
description: Detects password spray using the general NTLM failure code (0xC000006D) after evasion of wrong-password anchor
logsource:
  product: windows
detection:
  selection:
    EventCode: 4625
    Sub_Status: '0xC000006D'
    Logon_Type: 3
  condition: selection
level: high
tags:
  - attack.t1110.001

EXAMPLE 2 — Red changed SourceImage of process-inject from an unwhitelisted path
to C:\\Temp\\loader.exe. Anchor on that new path:
title: Remote Thread From Temp Directory
status: experimental
description: Detects CreateRemoteThread originating from a binary in a temp/staging directory
logsource:
  product: windows
detection:
  selection:
    EventCode: 8
    SourceImage|contains: '\\Temp\\'
  condition: selection
level: high
tags:
  - attack.t1055.001

EXAMPLE 3 — catch LSASS handle opened with an unusual access mask after the
0x1fffff signature was evaded:
title: LSASS Access With Suspicious Mask
status: experimental
description: Detects a non-system process opening lsass.exe with a credential-theft access mask
logsource:
  product: windows
detection:
  selection:
    EventCode: 10
    TargetImage|endswith: \\lsass.exe
    GrantedAccess|startswith: '0x14'
  filter:
    SourceImage|endswith:
      - \\svchost.exe
      - \\MsMpEng.exe
  condition: selection and not filter
level: high
tags:
  - attack.t1003.001
"""

SIGMA_USER_TEMPLATE = """TECHNIQUE: {technique_id} - {technique_name}   (tag: {tag})

ATTACK EVENTS THAT EVADED ALL CURRENT RULES (sample):
{sample_events}

THE RULE RED IS NOW EVADING (its anchor is ALREADY BYPASSED — do NOT copy it):
{catching_rule}

WHAT RED MUTATED TO EVADE — anchor your new rule on THESE changed field values:
{mutation_context}

{count_hint}

INSTRUCTION: Identify the specific field(s) in the mutation context above that differ
from the catching rule. Write a Sigma rule whose PRIMARY detection anchor targets
those mutated values — NOT the values in the catching rule.
Output only the YAML.
"""

# ──────────────────────────────────────────────────────────────────────────
# FALLBACK PATH: if the model can't produce valid Sigma, generate raw SPL so
# the arena still progresses. (Kept from v1; small models sometimes need this.)
# ──────────────────────────────────────────────────────────────────────────
SPL_SYSTEM_PROMPT = """You are an expert Splunk detection engineer specializing in MITRE ATT&CK.
Write an SPL detection rule that catches an attack pattern that evaded existing rules.

Rules for your response:
- Return ONLY a JSON object: {{"spl": "...", "explanation": "one sentence"}}
- The SPL must search index={index}
- The SPL must end with: | eval technique="{technique_id}", rule_name="{rule_name}"
- Write the narrowest rule that catches the attack without matching normal activity
- Use `| where count >= N` AFTER a stats command, NOT inside it
- Use double quotes for string values; EventCode=4625 (no quotes on numbers)
- No markdown, no code fences, no text outside the JSON"""

SPL_USER_TEMPLATE = """TECHNIQUE: {technique_id} - {technique_name}

ATTACK EVENTS THAT WERE NOT CAUGHT (sample):
{sample_events}

RULE RED IS EVADING:
{catching_rule}

MUTATION APPLIED BY RED:
{mutation_context}

{count_hint}

The rule_name for your eval must be exactly: "{rule_name}"
Return JSON: {{"spl": "...", "explanation": "..."}}"""


def _technique_to_tag(technique_id: str) -> str:
    """T1021.001 -> t1021.001 (Sigma attack tag form)."""
    return technique_id.lower()


class Generator:
    """
    LLM rule generator. Authors portable Sigma (compiled to SPL for Splunk
    execution); falls back to raw SPL if Sigma generation fails.

    For every generated rule it saves:
      - <name>.yml  — the portable Sigma source (when the Sigma path succeeds)
      - <name>.spl  — the executable Splunk query (always; what the detector runs)
    """

    def __init__(self, llm: LLMClient, search_client: SearchClient, max_retries: int = 3, index: str = "arena_attacks"):
        self.llm = llm
        self.search = search_client
        self.max_retries = max_retries
        self.index = index

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
        """Generate and save a new detection rule. Returns the .spl path or None."""
        rule_name = f"generated_r{round_num}_{technique_id.replace('.', '_')}"

        # Shared context for both paths
        sample = missed_events[:8]
        clean_sample = [
            {k: v for k, v in ev.items() if not k.startswith("arena_") and k != "_time"}
            for ev in sample
        ]
        sample_json = json.dumps(clean_sample, indent=2)
        catching = catching_rule_spl or "(none — first miss for this technique)"
        mutation_context = json.dumps(mutation_overrides, indent=2) if mutation_overrides else "(unknown — first miss)"

        mutated_count = (mutation_overrides or {}).get("count")
        if mutated_count is not None and int(mutated_count) <= 5:
            count_hint = (
                f"NOTE: Red lowered event volume to {mutated_count}. Do NOT rely on a count "
                "threshold — detect on specific field values present in the sample events."
            )
        else:
            count_hint = ""

        # 1. Primary: Sigma → SPL
        path = self._generate_sigma(
            technique_id, technique_name, rule_name, sample_json,
            catching, mutation_context, count_hint,
        )
        if path:
            return path

        # 2. Fallback: raw SPL
        print(f"  [blue generator] Sigma path failed for {technique_id} — falling back to SPL")
        return self._generate_spl(
            technique_id, technique_name, rule_name, sample_json,
            catching, mutation_context, count_hint, existing_rules,
        )

    # ── Sigma path ──────────────────────────────────────────────────────────
    def _generate_sigma(self, technique_id, technique_name, rule_name, sample_json,
                         catching, mutation_context, count_hint) -> str | None:
        if not sigma_compiler.is_available():
            return None
        tag = _technique_to_tag(technique_id)
        system = SIGMA_SYSTEM_PROMPT.format(tag=tag)
        prompt = SIGMA_USER_TEMPLATE.format(
            technique_id=technique_id, technique_name=technique_name, tag=tag,
            sample_events=sample_json, catching_rule=catching,
            mutation_context=mutation_context, count_hint=count_hint,
        )

        for attempt in range(self.max_retries):
            try:
                raw = self.llm.complete(system, prompt)
                sigma_yaml = self._extract_yaml(raw)
                # Must be parseable YAML with the core Sigma keys
                doc = yaml.safe_load(sigma_yaml)
                if not isinstance(doc, dict) or "detection" not in doc:
                    raise ValueError("missing 'detection' block")

                ok, spl_or_err = sigma_compiler.validate(sigma_yaml, index=self.index)
                if not ok:
                    raise ValueError(f"Sigma compile failed: {spl_or_err}")
                spl = spl_or_err

                # Tag for the scorer, then syntax-check the compiled SPL.
                spl_tagged = spl + f'\n| eval technique="{technique_id}", rule_name="{rule_name}"'
                valid, parse_err = self._validate_spl_syntax(spl_tagged)
                if not valid:
                    raise ValueError(f"compiled SPL invalid: {parse_err}")

                # Persist both the portable source and the executable query.
                (GENERATED_DIR / f"{rule_name}.yml").write_text(sigma_yaml, encoding="utf-8")
                (GENERATED_DIR / f"{rule_name}.spl").write_text(spl_tagged, encoding="utf-8")
                desc = (doc.get("description") or "").strip()
                print(f"  [blue generator] OK (Sigma) saved: {rule_name}  ->  {spl}")
                if desc:
                    print(f"  [blue generator]   {desc}")
                return str(GENERATED_DIR / f"{rule_name}.spl")
            except Exception as e:
                print(f"  [blue generator] Sigma attempt {attempt+1} failed: {e}")
                prompt += f"\n\nYour previous YAML was invalid: {e}\nFix it and output only valid Sigma YAML."

        return None

    @staticmethod
    def _extract_yaml(raw: str) -> str:
        """Pull a Sigma YAML doc out of a model response (strip fences/prose)."""
        raw = raw.strip()
        if "```" in raw:
            blocks = raw.split("```")
            for b in blocks:
                b2 = b.strip()
                if b2.lower().startswith("yaml"):
                    b2 = b2[4:].strip()
                if "detection:" in b2 or b2.startswith("title:"):
                    raw = b2
                    break
            else:
                raw = raw.replace("```yaml", "").replace("```", "").strip()
        idx = raw.find("title:")
        if idx > 0:
            raw = raw[idx:]
        return raw

    # ── SPL fallback path ─────────────────────────────────────────────────────
    def _generate_spl(self, technique_id, technique_name, rule_name, sample_json,
                      catching, mutation_context, count_hint, existing_rules) -> str | None:
        system = SPL_SYSTEM_PROMPT.format(index=self.index, technique_id=technique_id, rule_name=rule_name)
        prompt = SPL_USER_TEMPLATE.format(
            technique_id=technique_id, technique_name=technique_name,
            sample_events=sample_json, catching_rule=catching,
            mutation_context=mutation_context, count_hint=count_hint, rule_name=rule_name,
        )

        for attempt in range(self.max_retries):
            try:
                raw = self.llm.complete_json(system, prompt)
                raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
                result = json.loads(raw)
                spl = result.get("spl", "").strip()
                if not spl:
                    continue
                if f'rule_name="{rule_name}"' not in spl and f"rule_name='{rule_name}'" not in spl:
                    spl += f'\n| eval technique="{technique_id}", rule_name="{rule_name}"'
                valid, parse_error = self._validate_spl_syntax(spl)
                if not valid:
                    prompt += f"\n\nYour previous SPL had this error: {parse_error}\nFix it."
                    continue
                (GENERATED_DIR / f"{rule_name}.spl").write_text(spl, encoding="utf-8")
                print(f"  [blue generator] OK (SPL fallback) saved: {rule_name}")
                return str(GENERATED_DIR / f"{rule_name}.spl")
            except Exception as e:
                print(f"  [blue generator] SPL attempt {attempt+1} error: {e}")

        print(f"  [blue generator] FAILED after {self.max_retries} attempts for {technique_id}")
        return None

    def _validate_spl_syntax(self, spl: str) -> tuple[bool, str]:
        """Validate SPL syntax via Splunk's parser endpoint. (True, '') if OK."""
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()
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
        except Exception:
            # If the parser endpoint is unreachable, don't block generation.
            return True, ""
