"""
llm_client/sanitizer.py — strip PII before it reaches a cloud LLM, rehydrate after.

WHY THIS EXISTS
---------------
Blue's rule generator and Red's mutator both ship raw Windows/Sysmon events to an
LLM. Those events carry real internal data: employee usernames (Account_Name),
internal IPs (Source_Network_Address), hostnames (Workstation_Name), AD domains,
GUIDs, SIDs, and user-profile paths buried inside CommandLine/Image. Sending that
to a hosted model (Groq, Gemini, OpenAI) is a data-exfiltration and compliance
problem (GDPR / internal data-governance).

This sanitizer performs STRUCTURE-PRESERVING PSEUDONYMIZATION:

  - Every distinct real value maps to a STABLE placeholder within one prompt, so
    `10.0.0.5` seen in 15 events all become `<IP_1>`. The LLM still sees that all
    15 share one source IP (cardinality preserved) — it just never sees the value.
  - 12 distinct IPs become `<IP_1>..<IP_12>` — so an IP-rotation evasion is still
    legible to the model.
  - After the LLM returns a rule, `rehydrate()` swaps placeholders back to the real
    values so the rule is executable against production data.

A useful side effect: redacting environment-specific values nudges the LLM toward
anchoring on protocol fields (Sub_Status, GrantedAccess, EventCode) — which is
exactly what a portable, non-brittle detection should key on anyway.

CLASSIFICATION (per field)
--------------------------
  1. PRESERVE  — protocol/status fields kept verbatim (EventCode, Sub_Status,
                 GrantedAccess, Logon_Type, ...). The rule needs to anchor on these
                 and they carry no PII.
  2. PII       — whole value tokenized (Account_Name -> <USER_1>, ...).
  3. OTHER     — pattern-based redaction of embedded PII (a user path inside a
                 CommandLine becomes C:\\Users\\<USER_1>\\... while \\lsass.exe stays).
"""
from __future__ import annotations

import re

# Fields whose entire value is environment-specific PII → tokenize wholesale.
DEFAULT_PII_FIELDS = {
    "account_name", "user", "src_user", "dest_user", "samaccountname",
    "subject_user_name", "target_user_name", "target_username",
    "workstation_name", "computer", "computername", "host", "hostname", "dvc",
    "source_network_address", "src_ip", "dest_ip", "src", "dest",
    "client_address", "ipaddress", "ip",
    "account_domain", "dest_nt_domain", "domain",
    "logon_guid", "process_guid", "targetlogonid",
}

# Protocol/status fields that must NEVER be tokenized — the detection anchors here.
DEFAULT_PRESERVE_FIELDS = {
    "eventcode", "event_id", "sub_status", "status", "grantedaccess",
    "logon_type", "authentication_package", "logon_process", "failure_code",
    "failure_reason", "service_name", "sourcetype", "channel",
    "calltrace", "signaturestatus",
}

# Value patterns redacted anywhere they appear (also inside otherwise-kept fields).
# Order matters: GUID/SID/email before the broad IPv4 so we don't half-match.
_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("GUID",  re.compile(r"\{?[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?")),
    ("SID",   re.compile(r"S-1-(?:\d+-){1,}\d+")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("UPATH", re.compile(r"[A-Za-z]:\\Users\\[^\\\"\s]+", re.IGNORECASE)),
    ("UNC",   re.compile(r"\\\\[A-Za-z0-9._-]+\\[^\"\s]+")),
    ("IP6",   re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")),
    ("IP",    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

# Find `"Field": "value"` pairs in a JSON-serialized prompt for field-aware redaction.
_JSON_KV = re.compile(r'"([A-Za-z0-9_]+)"\s*:\s*"([^"\\]*)"')


class LogSanitizer:
    """
    Per-prompt pseudonymizer. Create a fresh one for each LLM call so the token map
    only ever contains that call's values and rehydration can't bleed across calls.
    """

    def __init__(self, pii_fields: set[str] | None = None, preserve_fields: set[str] | None = None):
        self.pii_fields = {f.lower() for f in (pii_fields or DEFAULT_PII_FIELDS)}
        self.preserve_fields = {f.lower() for f in (preserve_fields or DEFAULT_PRESERVE_FIELDS)}
        self._forward: dict[str, str] = {}   # real value  -> placeholder
        self._reverse: dict[str, str] = {}   # placeholder -> real value
        self._counters: dict[str, int] = {}  # kind -> running index

    # ── token bookkeeping ───────────────────────────────────────────────────────
    def _token_for(self, real: str, kind: str) -> str:
        if real in self._forward:
            return self._forward[real]
        self._counters[kind] = self._counters.get(kind, 0) + 1
        ph = f"<{kind}_{self._counters[kind]}>"
        self._forward[real] = ph
        self._reverse[ph] = real
        return ph

    def redaction_count(self) -> int:
        return len(self._reverse)

    # ── structured (event-dict) path ────────────────────────────────────────────
    def sanitize_value(self, field_name: str, value):
        """Redact one field's value according to its classification."""
        fname = field_name.lower()
        if fname in self.preserve_fields:
            return value
        if not isinstance(value, str):
            return value  # numbers (EventCode, Logon_Type as int) carry no PII
        if fname in self.pii_fields and value:
            return self._token_for(value, self._kind_for_field(fname))
        return self._redact_patterns(value)

    def sanitize_events(self, events: list[dict]) -> list[dict]:
        """Return redacted copies of event dicts (originals untouched)."""
        out = []
        for ev in events:
            out.append({k: self.sanitize_value(k, v) for k, v in ev.items()})
        return out

    # ── text (already-serialized prompt) path ───────────────────────────────────
    def sanitize_text(self, text: str) -> str:
        """
        Redact an arbitrary prompt string. Two passes:
          1. field-aware: `"PIIField": "value"` pairs get the value tokenized.
          2. pattern-based: IPs/GUIDs/SIDs/emails/user-paths anywhere else.
        """
        def _kv(m: "re.Match[str]") -> str:
            key, val = m.group(1), m.group(2)
            if key.lower() in self.preserve_fields or not val:
                return m.group(0)
            if key.lower() in self.pii_fields:
                ph = self._token_for(val, self._kind_for_field(key.lower()))
                return f'"{key}": "{ph}"'
            return f'"{key}": "{self._redact_patterns(val)}"'

        text = _JSON_KV.sub(_kv, text)
        return self._redact_patterns(text)

    # ── rehydration ─────────────────────────────────────────────────────────────
    def rehydrate(self, text: str) -> str:
        """Swap placeholders back to real values in the LLM's output."""
        # Replace longer placeholders first to avoid <IP_1> clobbering <IP_12>.
        for ph in sorted(self._reverse, key=len, reverse=True):
            text = text.replace(ph, self._reverse[ph])
        return text

    # ── internals ───────────────────────────────────────────────────────────────
    def _redact_patterns(self, value: str) -> str:
        for kind, pat in _PATTERNS:
            value = pat.sub(lambda m, k=kind: self._token_for(m.group(0), k), value)
        return value

    @staticmethod
    def _kind_for_field(fname: str) -> str:
        if "ip" in fname or "address" in fname or fname in ("src", "dest"):
            return "IP"
        if "domain" in fname:
            return "DOMAIN"
        if "workstation" in fname or "computer" in fname or "host" in fname or fname == "dvc":
            return "HOST"
        if "guid" in fname or "logonid" in fname:
            return "GUID"
        return "USER"
