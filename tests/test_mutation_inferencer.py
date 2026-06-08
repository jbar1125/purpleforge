"""
Unit tests for blue_agent/mutation_inferencer.py — the field-diff "moat".

These prove Blue can infer Red's evasion WITHOUT being told, by diffing evading
events against the last batch it caught. Run:

    python -m pytest tests/test_mutation_inferencer.py -v
    (or)  python tests/test_mutation_inferencer.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blue_agent.mutation_inferencer import MutationInferencer


def _spray_events(sub_status="0xC000006A", ip="10.0.0.5", auth="NTLM",
                  logon_type="3", n=15):
    """A password-spray batch — every event shares the anchor fields, but each
    carries a unique Logon_GUID + _time (natural per-event noise)."""
    out = []
    for i in range(n):
        out.append({
            "EventCode": "4625",
            "Account_Name": f"user{i % 4}",        # a few accounts
            "Source_Network_Address": ip,
            "Sub_Status": sub_status,
            "Authentication_Package": auth,
            "Logon_Type": logon_type,
            "Logon_GUID": f"{{guid-{i}-abcdef}}",  # unique every event (noise)
            "_time": 1000 + i,                      # unique every event (noise)
            "arena_round": 3,                       # arena tag (ignored)
        })
    return out


def test_value_swap_sub_status():
    """Red swaps Sub_Status 0xC000006A -> 0xC000006D. Inferencer must catch it."""
    inf = MutationInferencer()
    inf.record_caught("T1110.001", _spray_events(sub_status="0xC000006A"))
    evading = _spray_events(sub_status="0xC000006D")
    out = inf.infer_mutation("T1110.001", evading)
    assert out.get("Sub_Status") == "0xC000006D", out
    print("PASS test_value_swap_sub_status:", out)


def test_value_swap_numeric_logon_type():
    """Numeric field swap 3 -> 8 should come back coerced to int 8."""
    inf = MutationInferencer()
    inf.record_caught("T1110.001", _spray_events(logon_type="3"))
    out = inf.infer_mutation("T1110.001", _spray_events(logon_type="8"))
    assert out.get("Logon_Type") == 8, out
    print("PASS test_value_swap_numeric_logon_type:", out)


def test_ip_rotation_detected():
    """One source IP -> many (spray fan-out) must register as a rotation."""
    inf = MutationInferencer()
    inf.record_caught("T1110.001", _spray_events(ip="10.0.0.5"))
    evading = []
    for i in range(12):
        ev = _spray_events(n=1)[0]
        ev["Source_Network_Address"] = f"10.0.{i}.{i}"  # 12 distinct IPs
        ev["Logon_GUID"] = f"{{g-{i}}}"
        ev["_time"] = 2000 + i
        evading.append(ev)
    out = inf.infer_mutation("T1110.001", evading)
    assert "Source_Network_Address" in out, out
    assert isinstance(out["Source_Network_Address"], list), out
    assert len(out["Source_Network_Address"]) >= 3, out
    print("PASS test_ip_rotation_detected:", out["Source_Network_Address"][:3], "...")


def test_volume_drop_detected():
    """Volume 15 -> 3 (below threshold) must surface a low count."""
    inf = MutationInferencer()
    inf.record_caught("T1110.001", _spray_events(n=15))
    out = inf.infer_mutation("T1110.001", _spray_events(n=3))
    assert out.get("count") == 3, out
    assert int(out["count"]) <= 5, "generator's count-hint branch must trigger"
    print("PASS test_volume_drop_detected:", out.get("count"))


def test_noise_fields_not_flagged():
    """Logon_GUID and _time differ on EVERY event but must NOT be reported —
    they are per-event noise, not deliberate evasion anchors."""
    inf = MutationInferencer()
    inf.record_caught("T1110.001", _spray_events())
    # identical anchors, only the natural per-event noise differs
    evading = _spray_events()
    for i, ev in enumerate(evading):
        ev["Logon_GUID"] = f"{{totally-different-{i}}}"
        ev["_time"] = 99999 + i
    out = inf.infer_mutation("T1110.001", evading)
    assert "Logon_GUID" not in out, out
    assert "_time" not in out, out
    assert "arena_round" not in out, out
    print("PASS test_noise_fields_not_flagged:", out or "{} (clean)")


def test_no_baseline_returns_empty():
    """No snapshot recorded yet -> {} (matches generator's 'first miss' path)."""
    inf = MutationInferencer()
    out = inf.infer_mutation("T1110.001", _spray_events())
    assert out == {}, out
    print("PASS test_no_baseline_returns_empty")


def test_combined_swap_and_volume():
    """Red can do two things at once: lower volume AND swap auth package."""
    inf = MutationInferencer()
    inf.record_caught("T1110.001", _spray_events(auth="NTLM", n=15))
    out = inf.infer_mutation("T1110.001", _spray_events(auth="Negotiate", n=4))
    assert out.get("Authentication_Package") == "Negotiate", out
    assert out.get("count") == 4, out
    print("PASS test_combined_swap_and_volume:", out)


def test_describe_is_human_readable():
    inf = MutationInferencer()
    inf.record_caught("T1110.001", _spray_events(sub_status="0xC000006A"))
    text = inf.describe("T1110.001", _spray_events(sub_status="0xC000006D"))
    assert "Sub_Status" in text and "->" in text, text
    print("PASS test_describe_is_human_readable:", text)


def test_persistence_roundtrip():
    """Snapshots survive a to_dict/from_dict cycle (cross-session memory)."""
    inf = MutationInferencer()
    inf.record_caught("T1110.001", _spray_events(sub_status="0xC000006A"))
    restored = MutationInferencer.from_dict(inf.to_dict())
    out = restored.infer_mutation("T1110.001", _spray_events(sub_status="0xC000006D"))
    assert out.get("Sub_Status") == "0xC000006D", out
    print("PASS test_persistence_roundtrip:", out)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
