"""
Offline unit tests for Track 1 (real attack data via MITRE Caldera):
  red_agent/caldera_client.py  — normalize_operation_report() + _maybe_b64_decode()

The CalderaClient's HTTP methods need a live Caldera server, but the report → ground-truth
normalization is a pure function we can test against a recorded report fixture. That's the
part the scorer depends on, so it's the part worth pinning down. Run:

    python tests/test_caldera.py
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from red_agent.caldera_client import normalize_operation_report, _maybe_b64_decode


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


# A trimmed but realistic Caldera v2 operation report: one agent, three links — an LSASS
# dump (success), a scheduled task (success), and one internal link with NO ATT&CK mapping.
_REPORT = {
    "name": "purpleforge-r1",
    "host_group": [
        {"paw": "ab12cd", "host": "CORP-WS-042", "platform": "windows"},
    ],
    "steps": {
        "ab12cd": {
            "steps": [
                {
                    "link_id": "l-1", "ability_id": "a-lsass", "name": "Dump LSASS via comsvcs",
                    "command": _b64("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 lsass.dmp full"),
                    "status": 0, "pid": 4321,
                    "attack": {"technique_id": "T1003.001", "technique_name": "LSASS Memory",
                               "tactic": "credential-access"},
                    "finished_timestamp": "2026-06-08T12:00:05Z",
                    "output": "dump written",
                },
                {
                    "link_id": "l-2", "ability_id": "a-schtask", "name": "Create scheduled task",
                    "command": _b64("schtasks /create /tn Updater /tr evil.exe /sc onlogon"),
                    "status": 1,   # non-zero → failed execution
                    "attack": {"technique_id": "T1053.005", "technique_name": "Scheduled Task",
                               "tactic": "execution"},
                    "finished_timestamp": "2026-06-08T12:00:10Z",
                },
                {
                    "link_id": "l-3", "ability_id": "a-internal", "name": "agent heartbeat",
                    "command": _b64("echo ok"), "status": 0,
                    "attack": {},   # no technique mapping → must be skipped
                },
            ]
        }
    },
}


def test_normalize_extracts_only_attack_mapped_links():
    out = normalize_operation_report(_REPORT, round_num=1)
    # The unmapped heartbeat link is dropped; the two ATT&CK links survive.
    assert len(out) == 2, out
    tids = {e["technique_id"] for e in out}
    assert tids == {"T1003.001", "T1053.005"}, tids
    print("PASS test_normalize_extracts_only_attack_mapped_links:", tids)


def test_normalize_decodes_command_and_maps_host():
    lsass = next(e for e in normalize_operation_report(_REPORT, 1) if e["technique_id"] == "T1003.001")
    assert "comsvcs.dll" in lsass["command"], lsass["command"]   # base64 decoded back to the real command
    assert lsass["host"] == "CORP-WS-042"                        # paw resolved to hostname
    assert lsass["paw"] == "ab12cd"
    print("PASS test_normalize_decodes_command_and_maps_host")


def test_normalize_success_flag_tracks_status():
    out = {e["technique_id"]: e for e in normalize_operation_report(_REPORT, 1)}
    assert out["T1003.001"]["success"] is True   # status 0
    assert out["T1053.005"]["success"] is False  # status 1
    print("PASS test_normalize_success_flag_tracks_status")


def test_normalize_stamps_arena_tags_for_scorer():
    """The whole point: Caldera records carry the same arena_* tags as HEC events,
    so the existing scorer/coverage code consumes them without modification."""
    out = normalize_operation_report(_REPORT, round_num=7)
    for e in out:
        assert e["arena_round"] == 7
        assert e["arena_source"] == "caldera"
        assert e["arena_technique"] == e["technique_id"]
    print("PASS test_normalize_stamps_arena_tags_for_scorer")


def test_normalize_handles_empty_and_garbage():
    assert normalize_operation_report({}, 0) == []
    assert normalize_operation_report({"steps": {}}, 0) == []
    assert normalize_operation_report(None, 0) == []          # type: ignore[arg-type]
    print("PASS test_normalize_handles_empty_and_garbage")


def test_b64_decode_leaves_plaintext_alone():
    # A real Caldera command is base64; but if a version reports plain text, don't mangle it.
    assert _maybe_b64_decode("whoami /all") == "whoami /all"
    assert _maybe_b64_decode(_b64("net user")) == "net user"
    print("PASS test_b64_decode_leaves_plaintext_alone")


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
