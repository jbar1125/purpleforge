"""
splunk_client/sigma_matcher.py — evaluate a Sigma rule against a single event,
locally, in pure Python (no Splunk round-trip).

WHY THIS EXISTS
---------------
Real detection engineering is detection-AS-CODE: every rule ships with unit tests
that assert it fires on known-malicious events (recall) and stays silent on known-
benign events (precision). Those tests must run in CI, offline, in milliseconds —
you cannot stand up Splunk for every commit. This matcher evaluates the same Sigma
YAML the Blue agent authors, so tests/test_detections.py can prove every rule's
behavior without a live arena.

SCOPE (honest about what it supports)
-------------------------------------
This is a focused evaluator for the Sigma subset PurpleForge's rules actually use,
NOT a full Sigma engine. Supported:
  * field equality (scalar or list = OR), case-insensitive (matches Splunk)
  * modifiers: |contains, |startswith, |endswith, and the |all combiner
  * a selection = AND across its fields
  * condition expressions: and / or / not / parentheses over selection names,
    plus "1 of them" / "all of them" / "N of them" / "1 of <prefix>*"
Stateful/aggregation detections (count, dc, near) are intentionally NOT supported
— those stay native SPL (e.g. brute_force) and are excluded from per-event tests.
"""
from __future__ import annotations

import re
import yaml


class MatcherError(Exception):
    """Raised when a rule uses a construct this focused matcher can't evaluate."""


def load_rule(yaml_text: str) -> dict:
    """Parse a Sigma YAML rule into a dict."""
    return yaml.safe_load(yaml_text)


def _ci(v) -> str:
    """Normalize a value to a lowercase string for case-insensitive comparison."""
    return str(v).lower()


def _match_field(modifiers: list[str], expected, actual) -> bool:
    """
    Evaluate one `field[|mod...]: expected` clause against the event's actual value.
    A list `expected` is OR'd unless the `all` modifier makes it AND.
    """
    if actual is None:
        return False

    values = expected if isinstance(expected, list) else [expected]
    require_all = "all" in modifiers
    a = _ci(actual)

    def one(exp) -> bool:
        e = _ci(exp)
        if "contains" in modifiers:
            return e in a
        if "startswith" in modifiers:
            return a.startswith(e)
        if "endswith" in modifiers:
            return a.endswith(e)
        return a == e  # plain equality (case-insensitive, like Splunk)

    return all(one(v) for v in values) if require_all else any(one(v) for v in values)


def _match_selection(selection, event: dict) -> bool:
    """A selection is a dict of field-clauses AND'd together (Sigma semantics)."""
    if not isinstance(selection, dict):
        raise MatcherError(f"unsupported selection type: {type(selection).__name__}")
    for key, expected in selection.items():
        field, *modifiers = key.split("|")
        if not _match_field(modifiers, expected, event.get(field)):
            return False
    return True


# ── condition expression evaluation ─────────────────────────────────────────
_QUANT = re.compile(r"\b(all|\d+|1)\s+of\s+(them|[A-Za-z0-9_]+\*?)", re.IGNORECASE)
_TOKEN = re.compile(r"\(|\)|\b(?:and|or|not)\b|[A-Za-z0-9_]+", re.IGNORECASE)


def _resolve_quantifier(qty: str, target: str, sel_bools: dict[str, bool]) -> bool:
    """Resolve 'N of them' / 'all of prefix*' to a boolean over selection results."""
    if target.lower() == "them":
        names = list(sel_bools)
    elif target.endswith("*"):
        prefix = target[:-1]
        names = [n for n in sel_bools if n.startswith(prefix)]
    else:
        names = [target] if target in sel_bools else []
    hits = sum(1 for n in names if sel_bools[n])
    if qty.lower() == "all":
        return bool(names) and hits == len(names)
    return hits >= int(qty)


def _eval_condition(condition: str, sel_bools: dict[str, bool]) -> bool:
    """Evaluate a Sigma condition string against per-selection boolean results."""
    # Replace "N of TARGET" phrases with literal True/False first.
    def sub_quant(m):
        return "True" if _resolve_quantifier(m.group(1), m.group(2), sel_bools) else "False"
    expr = _QUANT.sub(sub_quant, condition)

    # Tokenize into selection names / operators / parens, then build a Python bool expr.
    out = []
    for tok in _TOKEN.findall(expr):
        low = tok.lower()
        if low in ("and", "or", "not", "(", ")"):
            out.append(low)
        elif tok in ("True", "False"):
            out.append(tok)
        elif tok in sel_bools:
            out.append("True" if sel_bools[tok] else "False")
        else:
            raise MatcherError(f"unknown token '{tok}' in condition '{condition}'")
    # Only boolean literals and operators remain — safe to eval in an empty namespace.
    py = " ".join(out)
    try:
        return bool(eval(py, {"__builtins__": {}}, {}))
    except Exception as exc:  # pragma: no cover - defensive
        raise MatcherError(f"could not evaluate condition '{condition}' -> '{py}': {exc}")


def match_event(rule: dict, event: dict) -> bool:
    """
    True if `event` satisfies `rule`'s detection block.
    `rule` is a parsed Sigma dict (from load_rule).
    """
    detection = rule.get("detection")
    if not detection:
        raise MatcherError("rule has no detection block")
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise MatcherError("matcher supports only a single string condition")

    sel_bools = {
        name: _match_selection(sel, event)
        for name, sel in detection.items()
        if name != "condition"
    }
    return _eval_condition(condition, sel_bools)
