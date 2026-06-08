"""
llm_client/audit.py — tamper-evident, hash-only audit trail for every LLM call.

WHY THIS EXISTS
---------------
A security product that calls an external LLM has to answer, later and under audit:
"What exactly did you send to the cloud, and did any PII leak?" Storing the raw
prompts would itself be a PII liability. So we store only SHA-256 fingerprints.

Each record is chained: it carries the hash of the previous record (`prev`), so the
log is append-only and tamper-evident — altering or deleting any line breaks every
hash downstream. `verify_chain()` re-walks the file and proves integrity.

Because we hash the SANITIZED prompt (the exact bytes that left the building), you
can later re-hash the sanitized prompt and match the record to prove no raw PII was
present in what was actually sent.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

_GENESIS = "0" * 64


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class PromptAuditor:
    """
    Append-only JSONL audit log. One line per LLM call. Hash-only by default
    (store_preview=False); set store_preview=True ONLY in a dev environment to keep
    a short truncated copy for debugging.
    """

    def __init__(self, path: str = "results/llm_audit.jsonl", store_preview: bool = False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.store_preview = store_preview
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return _GENESIS
        last = _GENESIS
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line).get("record_hash", last)
                    except json.JSONDecodeError:
                        continue
        return last

    def record(
        self,
        system_prompt: str,
        user_prompt: str,
        response: str,
        redactions: int = 0,
        provider: str = "",
        model: str = "",
    ) -> dict:
        """
        Append one audit record. `user_prompt` MUST be the sanitized prompt that was
        actually sent. Returns the record dict (also written to disk).
        """
        body = {
            "ts": round(time.time(), 3),
            "provider": provider,
            "model": model,
            "system_sha256": _sha(system_prompt),
            "prompt_sha256": _sha(user_prompt),
            "response_sha256": _sha(response),
            "prompt_chars": len(user_prompt),
            "response_chars": len(response),
            "redactions": redactions,
            "prev": self._last_hash,
        }
        if self.store_preview:
            body["prompt_preview"] = user_prompt[:200]
            body["response_preview"] = response[:200]

        # The record's own hash chains in everything above (including prev).
        record_hash = _sha(json.dumps(body, sort_keys=True))
        body["record_hash"] = record_hash

        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(body) + "\n")
        self._last_hash = record_hash
        return body

    def verify_chain(self) -> tuple[bool, str]:
        """
        Re-walk the file and confirm the hash chain is intact. Returns (ok, message).
        Detects edits, deletions, and reordering.
        """
        if not self.path.exists():
            return True, "no audit log yet"
        prev = _GENESIS
        n = 0
        with self.path.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"line {i}: not valid JSON"
                stored = rec.pop("record_hash", None)
                if rec.get("prev") != prev:
                    return False, f"line {i}: broken chain (prev mismatch)"
                recomputed = _sha(json.dumps(rec, sort_keys=True))
                if recomputed != stored:
                    return False, f"line {i}: record tampered (hash mismatch)"
                prev = stored
                n += 1
        return True, f"chain intact across {n} record(s)"

    def count(self) -> int:
        if not self.path.exists():
            return 0
        with self.path.open("r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
