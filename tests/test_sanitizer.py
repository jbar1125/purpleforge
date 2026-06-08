"""
Unit tests for the LLM data-security layer (Track 4):
  llm_client/sanitizer.py, audit.py, secure.py

Run:  python tests/test_sanitizer.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm_client.base import LLMClient
from llm_client.sanitizer import LogSanitizer
from llm_client.audit import PromptAuditor
from llm_client.secure import SanitizingLLMClient


def _events():
    return [
        {"EventCode": 4625, "Account_Name": "jsmith", "Source_Network_Address": "10.0.0.5",
         "Sub_Status": "0xC000006A", "Workstation_Name": "WS01", "Account_Domain": "CORP"},
        {"EventCode": 4625, "Account_Name": "mjones", "Source_Network_Address": "10.0.0.5",
         "Sub_Status": "0xC000006A", "Workstation_Name": "WS01", "Account_Domain": "CORP"},
    ]


def test_pii_fields_tokenized_protocol_preserved():
    san = LogSanitizer()
    out = san.sanitize_events(_events())
    # protocol fields preserved verbatim — the rule must anchor on these
    assert out[0]["EventCode"] == 4625
    assert out[0]["Sub_Status"] == "0xC000006A"
    # PII tokenized
    assert out[0]["Account_Name"].startswith("<USER_")
    assert out[0]["Source_Network_Address"].startswith("<IP_")
    assert out[0]["Workstation_Name"].startswith("<HOST_")
    assert out[0]["Account_Domain"].startswith("<DOMAIN_")
    print("PASS test_pii_fields_tokenized_protocol_preserved:", out[0])


def test_stable_mapping_preserves_cardinality():
    """Same IP across events -> same placeholder; distinct users -> distinct tokens."""
    san = LogSanitizer()
    out = san.sanitize_events(_events())
    assert out[0]["Source_Network_Address"] == out[1]["Source_Network_Address"]  # one IP
    assert out[0]["Account_Name"] != out[1]["Account_Name"]                       # two users
    print("PASS test_stable_mapping_preserves_cardinality")


def test_ip_rotation_cardinality_preserved():
    san = LogSanitizer()
    evs = [{"EventCode": 4625, "Source_Network_Address": f"10.0.{i}.{i}"} for i in range(12)]
    out = san.sanitize_events(evs)
    distinct = {e["Source_Network_Address"] for e in out}
    assert len(distinct) == 12, distinct  # 12 IPs -> 12 placeholders, rotation stays legible
    print("PASS test_ip_rotation_cardinality_preserved:", len(distinct), "distinct tokens")


def test_embedded_path_redacted_binary_kept():
    """A user-profile path inside CommandLine is redacted; the binary name stays."""
    san = LogSanitizer()
    out = san.sanitize_value("CommandLine", r"C:\Users\jsmith\AppData\evil.exe -enc ABC")
    assert "jsmith" not in out, out
    assert "evil.exe" in out, out  # the anchor the rule needs survives
    print("PASS test_embedded_path_redacted_binary_kept:", out)


def test_sanitize_text_field_aware_and_pattern():
    san = LogSanitizer()
    prompt = json.dumps(_events(), indent=2) + "\nGUID: 12345678-1234-1234-1234-123456789abc"
    safe = san.sanitize_text(prompt)
    assert "jsmith" not in safe and "mjones" not in safe, safe
    assert "10.0.0.5" not in safe, safe
    assert "WS01" not in safe and "CORP" not in safe, safe
    assert "12345678-1234-1234-1234-123456789abc" not in safe, "GUID must be redacted"
    assert "0xC000006A" in safe, "protocol value must survive"
    print("PASS test_sanitize_text_field_aware_and_pattern")


def test_rehydrate_roundtrip():
    san = LogSanitizer()
    safe = san.sanitize_text('{"Source_Network_Address": "10.0.0.5"}')
    # LLM "writes a rule" referencing the placeholder
    ip_token = safe.split('"')[3]
    rule = f"index=x Source_Network_Address={ip_token} | stats count"
    restored = san.rehydrate(rule)
    assert "10.0.0.5" in restored, restored
    assert ip_token not in restored, restored
    print("PASS test_rehydrate_roundtrip:", restored)


def test_rehydrate_no_prefix_clobber():
    """<IP_1> must not corrupt <IP_12> during rehydration."""
    san = LogSanitizer()
    evs = [{"Source_Network_Address": f"10.0.0.{i}"} for i in range(1, 13)]
    san.sanitize_events(evs)
    # Build text containing both <IP_1> and <IP_12>
    text = "a <IP_1> b <IP_12> c"
    out = san.rehydrate(text)
    assert "10.0.0.1" in out and "10.0.0.12" in out, out
    assert "<IP_" not in out, out
    print("PASS test_rehydrate_no_prefix_clobber:", out)


class _EchoLLM(LLMClient):
    """Fake provider: records what it received, echoes the prompt back as the 'rule'."""
    def __init__(self):
        self.last_user = None
    def complete(self, system, user):
        self.last_user = user
        return user


def test_secure_wrapper_blocks_pii_and_rehydrates():
    echo = _EchoLLM()
    with tempfile.TemporaryDirectory() as d:
        auditor = PromptAuditor(path=os.path.join(d, "audit.jsonl"))
        secure = SanitizingLLMClient(echo, auditor=auditor, provider="echo")
        prompt = json.dumps(_events())
        result = secure.complete("SYSTEM", prompt)
        # The inner provider must NEVER have seen raw PII
        assert "jsmith" not in echo.last_user, echo.last_user
        assert "10.0.0.5" not in echo.last_user, echo.last_user
        # The caller gets real values back (rehydrated) so the rule is executable
        assert "10.0.0.5" in result, result
        # One audit record written, chain valid
        assert auditor.count() == 1
        ok, msg = auditor.verify_chain()
        assert ok, msg
    print("PASS test_secure_wrapper_blocks_pii_and_rehydrates")


def test_audit_chain_detects_tampering():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        auditor = PromptAuditor(path=path)
        for i in range(3):
            auditor.record("sys", f"prompt {i} 10.0.0.{i}", f"resp {i}", redactions=1, provider="t")
        ok, msg = auditor.verify_chain()
        assert ok, msg
        # Tamper: rewrite the middle line's response hash
        lines = open(path, encoding="utf-8").read().splitlines()
        rec = json.loads(lines[1]); rec["response_sha256"] = "deadbeef" * 8
        lines[1] = json.dumps(rec)
        open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        ok2, msg2 = PromptAuditor(path=path).verify_chain()
        assert not ok2, "tamper must be detected"
    print("PASS test_audit_chain_detects_tampering:", msg2)


def test_hash_only_no_raw_content():
    """Default audit must NOT persist raw prompt/response text."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        PromptAuditor(path=path).record("sys", "secret user jsmith", "secret resp", provider="t")
        raw = open(path, encoding="utf-8").read()
        assert "jsmith" not in raw, "raw PII must never hit the audit log"
        assert "secret resp" not in raw, raw
        assert "prompt_sha256" in raw
    print("PASS test_hash_only_no_raw_content")


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
