"""
Offline unit tests for Track 5 levels 3 & 4 (the proactive half of the moat):
  blue_agent/edr_client.py    — normalize_crowdstrike_detections() + corroborate()
  blue_agent/threat_intel.py  — technique extraction + ThreatIntelParser.gap_analysis()

The HTTP clients need live CrowdStrike / network access, but the value — turning an EDR
report into ground truth, finding Blue's blind spots, and turning advisories into proactive
detection targets — lives in pure functions we can pin down offline.

Run:  python tests/test_track5_intel.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blue_agent.edr_client import normalize_crowdstrike_detections, corroborate
from blue_agent.threat_intel import (
    ThreatIntelParser, extract_techniques_from_text, techniques_from_navigator_layer,
)


# ── EDR ground truth (L3) ─────────────────────────────────────────────────────
_CS_PAYLOAD = {
    "resources": [
        {
            "detection_id": "ldt:abc:123",
            "created_timestamp": "2026-06-08T12:00:00Z",
            "max_severity_displayname": "High",
            "device": {"hostname": "CORP-WS-042", "platform_name": "Windows"},
            "behaviors": [
                {"tactic": "Credential Access", "technique": "OS Credential Dumping",
                 "technique_id": "T1003.001", "filename": "rundll32.exe",
                 "cmdline": "rundll32 comsvcs.dll, MiniDump 640 lsass.dmp", "severity": 70,
                 "timestamp": "2026-06-08T12:00:01Z"},
                {"tactic": "Execution", "technique": "Scheduled Task",
                 "technique_id": "T1053.005", "filename": "schtasks.exe",
                 "cmdline": "schtasks /create /tn Updater"},
                {"tactic": "Discovery", "technique": "System Owner Discovery",
                 "filename": "whoami.exe"},   # no technique_id → must be skipped
            ],
        },
    ],
}


def test_edr_normalize_flattens_behaviors():
    out = normalize_crowdstrike_detections(_CS_PAYLOAD)
    assert len(out) == 2, out                       # the unmapped behavior is dropped
    lsass = next(e for e in out if e["technique_id"] == "T1003.001")
    assert lsass["host"] == "CORP-WS-042"
    assert lsass["process"] == "rundll32.exe"
    assert "comsvcs.dll" in lsass["command"]
    assert lsass["arena_source"] == "edr" and lsass["arena_technique"] == "T1003.001"
    print("PASS test_edr_normalize_flattens_behaviors:", [e["technique_id"] for e in out])


def test_corroborate_finds_blind_spot():
    """The headline capability: the EDR saw a real T1053.005 that Blue's Splunk rules
    missed entirely — that's a BLIND SPOT, the highest-priority gap to close."""
    edr = normalize_crowdstrike_detections(_CS_PAYLOAD)         # {T1003.001, T1053.005}
    splunk_caught = {"T1003", "T1110.001"}                      # base T1003 + a brute force
    result = corroborate(edr, splunk_caught)
    assert result["confirmed"] == ["T1003.001"], result        # base T1003 ≡ T1003.001
    assert result["blind_spots"] == ["T1053.005"], result      # EDR saw it, logs didn't
    assert result["log_only"] == ["T1110.001"], result         # Blue fired, EDR silent
    assert result["edr_coverage_pct"] == 50.0, result
    print("PASS test_corroborate_finds_blind_spot:", result)


def test_corroborate_empty_edr_is_safe():
    result = corroborate([], {"T1003.001"})
    assert result["blind_spots"] == [] and result["edr_coverage_pct"] == 0.0
    assert result["log_only"] == ["T1003.001"]
    print("PASS test_corroborate_empty_edr_is_safe")


# ── Threat intel (L4) ─────────────────────────────────────────────────────────
_ADVISORY = """
CISA AA24-XXXA — Observed Activity

The actors used Valid Accounts (T1078) for initial access and PowerShell (T1059.001)
for execution. Persistence was established via Scheduled Task/Job: Scheduled Task
(T1053.005). Credentials were harvested through OS Credential Dumping: LSASS Memory
(T1003.001). PowerShell (T1059.001) was observed repeatedly across hosts.
"""

_NAV_LAYER = {
    "name": "APTxx",
    "techniques": [
        {"techniqueID": "T1547.001", "score": 100, "comment": "Registry Run Key persistence"},
        {"techniqueID": "T1053.005", "comment": "scheduled task"},
    ],
}


def test_extract_techniques_from_text():
    pairs = extract_techniques_from_text(_ADVISORY)
    tids = [t for t, _ in pairs]
    assert tids.count("T1059.001") == 2, tids        # cited twice
    assert "T1078" in tids and "T1003.001" in tids
    # context travels with the ID so an analyst sees why it was flagged
    assert any("PowerShell" in ctx for t, ctx in pairs if t == "T1059.001")
    print("PASS test_extract_techniques_from_text:", sorted(set(tids)))


def test_navigator_layer_extraction():
    pairs = techniques_from_navigator_layer(_NAV_LAYER)
    tids = {t for t, _ in pairs}
    assert tids == {"T1547.001", "T1053.005"}, tids
    print("PASS test_navigator_layer_extraction:", tids)


def test_gap_analysis_prioritizes_missing_techniques():
    ti = ThreatIntelParser()
    ti.ingest_text(_ADVISORY, source="AA24-XXXA")
    ti.ingest_navigator_layer(_NAV_LAYER, source="APTxx")
    # Blue already detects scheduled tasks and valid accounts.
    gaps = ti.gap_analysis(covered_techniques={"T1053.005", "T1078"})

    assert set(gaps["already_covered"]) == {"T1053.005", "T1078"}, gaps
    rec_ids = [r["technique_id"] for r in gaps["recommended_new"]]
    # Most-cited missing technique (T1059.001, seen twice) ranks first → build it first.
    assert rec_ids[0] == "T1059.001", rec_ids
    assert set(rec_ids) == {"T1059.001", "T1003.001", "T1547.001"}, rec_ids
    # 2 covered of 5 unique cited techniques.
    assert gaps["coverage_pct"] == 40.0, gaps
    print("PASS test_gap_analysis_prioritizes_missing_techniques:", rec_ids, gaps["coverage_pct"])


def test_gap_analysis_base_match_option():
    """With base_match, owning the parent technique (T1059) covers a cited sub-technique."""
    ti = ThreatIntelParser()
    ti.ingest_text("Execution via PowerShell (T1059.001).")
    strict = ti.gap_analysis(covered_techniques={"T1059"}, base_match=False)
    loose = ti.gap_analysis(covered_techniques={"T1059"}, base_match=True)
    assert [r["technique_id"] for r in strict["recommended_new"]] == ["T1059.001"]
    assert loose["recommended_new"] == [] and loose["already_covered"] == ["T1059.001"]
    print("PASS test_gap_analysis_base_match_option")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
