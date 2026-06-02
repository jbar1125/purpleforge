"""
Scores each round by comparing blue's detection results against red's injected events.

A technique is considered DETECTED if any rule returned results containing events
with the matching arena_technique field (or technique field from the eval statement).
"""


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

    # Build a set of technique IDs that blue's rules returned hits for
    for rule_name, rows in detection_results.items():
        if not rows:
            continue
        for row in rows:
            # Blue rules end with: | eval technique="T1xxx.yyy"
            tid = row.get("technique") or row.get("arena_technique")
            if tid and tid in detected:
                detected[tid] = True
                if tid not in catching_rules:
                    catching_rules[tid] = rule_name

    return detected, catching_rules
