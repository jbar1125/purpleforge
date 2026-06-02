"""
Scores each round by comparing blue's detection results against red's injected events.

A technique is considered DETECTED if any rule returned results containing events
with the matching technique or arena_technique field.

Fallback: if a rule returns rows but lacks the technique eval field, we infer the
technique from the rule name using a known mapping.
"""

# Baseline rule name → technique ID (fallback when eval field is missing)
_RULE_NAME_TO_TECHNIQUE = {
    "brute_force": "T1110.001",
    "brute_force_baseline": "T1110.001",
    "rdp_lateral": "T1021.001",
    "rdp_lateral_baseline": "T1021.001",
    "scheduled_task": "T1053.005",
    "scheduled_task_baseline": "T1053.005",
    "new_account": "T1136.001",
    "new_account_baseline": "T1136.001",
    "lsass_dump": "T1003.001",
    "lsass_dump_baseline": "T1003.001",
    "registry_persist": "T1547.001",
    "registry_persist_baseline": "T1547.001",
}

# Generated rule name pattern: generated_rN_T<TTTT>_<SSS> → technique
def _infer_technique_from_rule_name(rule_name: str) -> str | None:
    """Infer technique ID from rule name. E.g. 'generated_r2_T1110_001' → 'T1110.001'."""
    # Check static map first
    if rule_name in _RULE_NAME_TO_TECHNIQUE:
        return _RULE_NAME_TO_TECHNIQUE[rule_name]
    # Generated rule pattern: generated_rN_T<digits>_<digits>
    parts = rule_name.split("_")
    # Find the part starting with 'T' followed by digits
    for i, part in enumerate(parts):
        if part.startswith("T") and part[1:].isdigit() and i + 1 < len(parts):
            tid = f"{part}.{parts[i+1]}"
            return tid
    return None


def score_round(
    injected: dict[str, list[dict]],
    detection_results: dict[str, list[dict]],
    technique_ids: list[str],
) -> tuple[dict[str, bool], dict[str, str]]:
    """
    Args:
        injected: {technique_id: [injected_event_dicts]} from red agent
        detection_results: {rule_name: [result_rows]} from blue detector
        technique_ids: full list of techniques in play

    Returns:
        detected: {technique_id: True|False}
        catching_rules: {technique_id: rule_name_that_caught_it}
    """
    detected: dict[str, bool] = {tid: False for tid in technique_ids}
    catching_rules: dict[str, str] = {}

    for rule_name, rows in detection_results.items():
        if not rows:
            continue

        # Try to get technique from result rows first (eval field is most reliable)
        rule_technique = None
        for row in rows:
            tid = row.get("technique") or row.get("arena_technique")
            if tid and tid in detected:
                detected[tid] = True
                if tid not in catching_rules:
                    catching_rules[tid] = rule_name
                rule_technique = tid
                break

        # Fallback: infer technique from rule name if rows didn't have the eval field
        if rule_technique is None and rows:
            inferred = _infer_technique_from_rule_name(rule_name)
            if inferred and inferred in detected:
                detected[inferred] = True
                if inferred not in catching_rules:
                    catching_rules[inferred] = rule_name
                print(f"  [scorer] inferred technique {inferred} from rule name '{rule_name}'")

    return detected, catching_rules
