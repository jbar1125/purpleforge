"""
tests/test_detections.py — detection-as-code unit tests for every Sigma rule.

Runs OFFLINE (no Splunk) via the local Sigma matcher, in milliseconds, so it can
gate every commit. Three guarantees:

  COMPILE   — every Sigma rule compiles to executable Splunk SPL.
  RECALL    — each technique's attack events trip its rule, on EVERY random fill
              (we repeat with fresh randomized context to catch fill-dependent gaps).
  PRECISION — benign events do NOT trip the precise rules. The two intentionally
              broad baseline rules (scheduled_task, new_account) are asserted to
              FIRE on benign activity — documenting their known false positives,
              which is exactly the precision gap the Blue agent should tighten.

Run:  python tests/test_detections.py            (no pytest required)
  or: python -m pytest tests/test_detections.py -q
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from splunk_client import sigma_matcher, sigma_compiler
from blue_agent.detector import technique_from_sigma
from red_agent.injector import _make_context, _fill_template
from red_agent.benign import BenignGenerator

SIGMA_DIR = ROOT / "blue_agent" / "rules" / "sigma"
TEMPLATE_DIR = ROOT / "red_agent" / "templates"
TRIALS = 25  # randomized context repeats — flushes out fill-dependent matches

# Rules deliberately broad in v1 — they SHOULD false-positive on benign activity.
# Asserting this keeps the "precision gap" honest and visible.
KNOWN_BROAD = {"scheduled_task", "new_account"}


def _sigma_paths():
    return sorted(SIGMA_DIR.glob("*.yml"))


def _template_events(tid: str) -> list[dict]:
    tpl = json.loads((TEMPLATE_DIR / f"{tid}.json").read_text(encoding="utf-8"))
    return tpl["events"]


def _fill(spec: dict) -> dict:
    return _fill_template(spec["template"], _make_context())


def _benign_events() -> list[dict]:
    bg = BenignGenerator(hec=None, index="arena_attacks")
    out = []
    for _sourcetype, template, count in bg._specs():
        for _ in range(count):
            out.append(bg._fill(template))
    return out


def test_all_sigma_rules_compile():
    assert sigma_compiler.is_available(), "pySigma + Splunk backend not installed"
    for path in _sigma_paths():
        ok, msg = sigma_compiler.validate(path.read_text(encoding="utf-8"))
        assert ok, f"{path.stem} failed to compile to SPL: {msg}"


def test_recall_each_rule_fires_on_its_attack():
    for path in _sigma_paths():
        text = path.read_text(encoding="utf-8")
        tid = technique_from_sigma(text)
        assert tid, f"{path.stem} has no attack.* technique tag"
        rule = sigma_matcher.load_rule(text)
        events = _template_events(tid)
        for trial in range(TRIALS):
            fired = any(sigma_matcher.match_event(rule, _fill(s)) for s in events)
            assert fired, f"RECALL: {path.stem} ({tid}) missed its own attack (trial {trial})"


def test_precision_benign_silent_except_known_broad():
    rules = {p.stem: sigma_matcher.load_rule(p.read_text(encoding="utf-8")) for p in _sigma_paths()}
    for trial in range(TRIALS):
        benign = _benign_events()
        for stem, rule in rules.items():
            hits = sum(1 for ev in benign if sigma_matcher.match_event(rule, ev))
            if stem in KNOWN_BROAD:
                assert hits >= 1, (
                    f"PRECISION: {stem} is a known-broad rule expected to FP on benign, "
                    f"but fired 0 times (trial {trial}). Did the benign generator change?"
                )
            else:
                assert hits == 0, (
                    f"PRECISION: {stem} false-positived on benign traffic "
                    f"({hits} hit(s), trial {trial}) — it should stay silent"
                )


# ── plain-script runner (so the suite works without pytest installed) ────────
def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"[PASS] {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"[FAIL] {t.__name__}: {e}")
        except Exception as e:  # surface unexpected errors clearly
            failures += 1
            print(f"[ERROR] {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_run_all())
