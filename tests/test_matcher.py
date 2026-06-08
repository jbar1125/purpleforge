"""
tests/test_matcher.py — focused unit tests for the local Sigma matcher.

The full detection suite exercises the matcher across every real rule, but a few
supported constructs (startswith, the "N of them" / "all of them" quantifiers)
aren't used by current rules. These tests verify every feature we CLAIM to
support, so the matcher's scope statement stays honest.

Run:  python tests/test_matcher.py   or   python -m pytest tests/test_matcher.py -q
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from splunk_client import sigma_matcher as m


def _rule(detection: dict) -> dict:
    return {"detection": detection}


def test_equality_is_case_insensitive():
    rule = _rule({"sel": {"Operation": "New-InboxRule"}, "condition": "sel"})
    assert m.match_event(rule, {"Operation": "new-inboxrule"})
    assert not m.match_event(rule, {"Operation": "Set-Mailbox"})


def test_list_value_is_or():
    rule = _rule({"sel": {"EventCode": [4624, 4625]}, "condition": "sel"})
    assert m.match_event(rule, {"EventCode": 4625})       # int matches
    assert m.match_event(rule, {"EventCode": "4624"})     # string matches too
    assert not m.match_event(rule, {"EventCode": 4672})


def test_contains_all_requires_every_substring():
    rule = _rule({"sel": {"CommandLine|contains|all": ["comsvcs", "MiniDump"]}, "condition": "sel"})
    assert m.match_event(rule, {"CommandLine": "rundll32 comsvcs.dll,MiniDump 640"})
    assert not m.match_event(rule, {"CommandLine": "rundll32 comsvcs.dll"})  # missing MiniDump


def test_startswith_and_endswith():
    start = _rule({"sel": {"Image|startswith": "C:\\Windows"}, "condition": "sel"})
    end = _rule({"sel": {"Image|endswith": "\\powershell.exe"}, "condition": "sel"})
    ev = {"Image": "C:\\Windows\\System32\\powershell.exe"}
    assert m.match_event(start, ev)
    assert m.match_event(end, ev)
    assert not m.match_event(end, {"Image": "C:\\Windows\\System32\\cmd.exe"})


def test_missing_field_does_not_match():
    rule = _rule({"sel": {"ResultType": 0}, "condition": "sel"})
    assert not m.match_event(rule, {"Operation": "x"})  # field absent → no match


def test_condition_and_not_with_parens():
    det = {
        "hit": {"EventCode": 10},
        "benign": {"SourceImage|endswith": "\\svchost.exe"},
        "condition": "hit and not benign",
    }
    rule = _rule(det)
    assert m.match_event(rule, {"EventCode": 10, "SourceImage": "C:\\evil\\rundll32.exe"})
    assert not m.match_event(rule, {"EventCode": 10, "SourceImage": "C:\\Windows\\svchost.exe"})


def test_quantifier_of_them_and_prefix():
    det = {
        "sel_a": {"EventCode": 1},
        "sel_b": {"User": "alice"},
        "sel_c": {"Host": "h1"},
        "condition": "1 of them",
    }
    assert m.match_event(_rule(det), {"EventCode": 1})           # one selection true
    assert not m.match_event(_rule(det), {"EventCode": 9})       # none true

    det_all = dict(det, condition="all of sel_*")
    assert m.match_event(_rule(det_all), {"EventCode": 1, "User": "alice", "Host": "h1"})
    assert not m.match_event(_rule(det_all), {"EventCode": 1, "User": "alice"})  # sel_c false


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
        except Exception as e:
            failures += 1
            print(f"[ERROR] {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_run_all())
