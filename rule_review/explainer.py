"""
rule_review/explainer.py — turn a generated rule into plain English for the reviewer.

The analyst should not have to read SPL to make a deploy decision. This parses the
candidate rule's anchors (EventCode, field matches, count thresholds) and the
dry-run result into a short, scannable summary plus a recommendation.
"""
from __future__ import annotations

import re

_EVENTCODE = re.compile(r'EventCode\s*=\s*"?(\d+)"?', re.IGNORECASE)
_FIELD_EQ = re.compile(r'(\b[A-Z][A-Za-z0-9_]+)\s*=\s*"([^"]+)"')
_FIELD_MOD = re.compile(r'(\b[A-Za-z0-9_]+)\s+(contains|endswith|startswith)\s+"?([^"\s|]+)', re.IGNORECASE)
_COUNT = re.compile(r'count\b\s*(>=|>)\s*(\d+)', re.IGNORECASE)

# EventCode -> what it means, so the summary reads in security terms.
_CODE_MEANING = {
    "4625": "failed logon", "4624": "successful logon", "4720": "new account created",
    "4698": "scheduled task created", "4771": "Kerberos pre-auth failure",
    "10": "process accessed another's memory (e.g. LSASS)",
    "8": "remote thread created (injection)", "13": "registry value set",
    "3": "network connection", "1": "process created", "4104": "PowerShell script block",
}


def explain(rule, dry_run: dict | None = None) -> str:
    """`rule` is a PendingRule (or any object with .technique/.spl/.confidence)."""
    spl = getattr(rule, "spl", "") or ""
    lines: list[str] = []
    lines.append(f"Technique: {getattr(rule, 'technique', '?')}")

    codes = _EVENTCODE.findall(spl)
    if codes:
        described = ", ".join(f"{c} ({_CODE_MEANING.get(c, 'event')})" for c in dict.fromkeys(codes))
        lines.append(f"Triggers on EventCode {described}.")

    anchors = []
    for fld, val in _FIELD_EQ.findall(spl):
        if fld.lower() in ("technique", "rule_name", "eventcode"):
            continue
        anchors.append(f"{fld} = {val}")
    for fld, mod, val in _FIELD_MOD.findall(spl):
        anchors.append(f"{fld} {mod} {val}")
    if anchors:
        lines.append("Anchors on: " + "; ".join(dict.fromkeys(anchors)) + ".")

    m = _COUNT.search(spl)
    if m:
        lines.append(f"Fires when event count {m.group(1)} {m.group(2)} in the window.")

    if not anchors and m:
        lines.append("NOTE: volume-only rule (no specific field anchor) — prone to "
                     "false positives and to being evaded by lowering volume.")

    dr = dry_run if dry_run is not None else getattr(rule, "dry_run", {}) or {}
    if dr.get("total_hits") is not None:
        lines.append(f"Dry run ({dr.get('window', 'n/a')}): {dr['total_hits']} hit(s), "
                     f"~{dr.get('fp_estimate', 0)} suspected FP (rate {dr.get('fp_rate', 0)}).")

    conf = getattr(rule, "confidence", None)
    if conf is not None:
        verdict = ("looks safe to deploy" if conf >= 0.7 else
                   "review carefully" if conf >= 0.45 else
                   "likely reject")
        lines.append(f"Confidence {conf:.2f} — {verdict}.")
    return "\n".join(lines)


def recommendation(rule) -> str:
    conf = getattr(rule, "confidence", 0.0)
    fp_rate = (getattr(rule, "dry_run", {}) or {}).get("fp_rate", 0.0) or 0.0
    if conf >= 0.7 and fp_rate <= 0.1:
        return "APPROVE"
    if conf < 0.45 or fp_rate > 0.4:
        return "REJECT"
    return "REVIEW"
