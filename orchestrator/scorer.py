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
    "powershell_encoded": "T1059.001",
    "powershell_encoded_baseline": "T1059.001",
    "process_injection": "T1055.001",
    "process_injection_baseline": "T1055.001",
    "defender_disabled": "T1562.001",
    "defender_disabled_baseline": "T1562.001",
    "cloud_account_anomaly": "T1078.004",
    "cloud_account_anomaly_baseline": "T1078.004",
    "email_forwarding_rule": "T1114.003",
    "email_forwarding_rule_baseline": "T1114.003",
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


def score_precision(
    detection_results: dict[str, list[dict]],
    benign_marker: str = "benign",
) -> tuple[float | None, dict[str, dict]]:
    """
    Measure how clean each rule's hits are, using benign traffic as ground truth.

    A result row is a:
      * false positive (FP) if it came from benign activity (arena_technique == benign)
      * true positive  (TP) if it came from a real attack technique
      * unscored       if it carries no arena_technique field (e.g. an aggregation
                         rule like password-spray that collapses per-event fields) —
                         we don't guess, we exclude it from the precision math.

    Returns (overall_precision_or_None, per_rule) where per_rule[name] =
    {tp, fp, unknown, precision}. Precision = TP / (TP + FP); None when a rule had
    no classifiable hits. This is honest: rules we can't attribute aren't counted.
    """
    per_rule: dict[str, dict] = {}
    total_tp = total_fp = 0

    for rule_name, rows in detection_results.items():
        tp = fp = unknown = 0
        for row in rows:
            origin = row.get("arena_technique")
            if origin is None:
                unknown += 1
            elif origin == benign_marker:
                fp += 1
            else:
                tp += 1
        classified = tp + fp
        per_rule[rule_name] = {
            "tp": tp,
            "fp": fp,
            "unknown": unknown,
            "precision": round(tp / classified, 3) if classified else None,
        }
        total_tp += tp
        total_fp += fp

    overall = round(total_tp / (total_tp + total_fp), 3) if (total_tp + total_fp) else None
    return overall, per_rule


def check_win(
    coverage_pct: float,
    compromised_count: int,
    total_techniques: int,
    blue_win_threshold: float = 70.0,
    red_win_threshold: float = 60.0,
    objectives_achieved: int = 0,
) -> str | None:
    """
    Check whether a decisive win condition has been reached.

    Red wins when it EITHER:
      - Compromised (burned the covering rule) >= red_win_threshold % of techniques, OR
      - Achieved kill-chain objectives on >= red_win_threshold % of techniques
        (evaded detection long enough for the mission to succeed)

    Blue wins when it maintains >= blue_win_threshold % detection coverage —
    it held the line against Red's full pressure.

    Returns "red", "blue", or None (game still in progress / contested).
    Red win takes precedence: even a high-coverage Blue loses if Red's
    objectives have already succeeded.
    """
    if total_techniques == 0:
        return None
    compromised_pct = compromised_count / total_techniques * 100
    objectives_pct  = objectives_achieved / total_techniques * 100
    if compromised_pct >= red_win_threshold or objectives_pct >= red_win_threshold:
        return "red"
    if coverage_pct >= blue_win_threshold:
        return "blue"
    return None
