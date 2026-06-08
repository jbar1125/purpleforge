"""
llm_client/secure.py — a privacy-preserving wrapper around ANY LLMClient.

Wrap any provider (Groq, Gemini, Ollama, Splunk-hosted) and every prompt is
sanitized on the way out and rehydrated on the way back, with a hash-only audit
record written for each call. Because it implements LLMClient, the generator and
mutator use it without knowing it's there:

    inner   = get_llm_client(cfg["llm"])
    secure  = SanitizingLLMClient(inner, auditor=PromptAuditor(), provider=cfg["llm"]["provider"])
    blue    = BlueAgent(search, llm=secure, ...)
    red     = RedAgent(hec, llm=secure, ...)

A fresh LogSanitizer is built per call so the placeholder map is scoped to one
prompt — rehydration can never bleed values between unrelated calls.
"""
from __future__ import annotations

from .base import LLMClient
from .sanitizer import LogSanitizer
from .audit import PromptAuditor


class SanitizingLLMClient(LLMClient):
    def __init__(
        self,
        inner: LLMClient,
        auditor: PromptAuditor | None = None,
        provider: str = "",
        model: str = "",
        pii_fields: set[str] | None = None,
        preserve_fields: set[str] | None = None,
    ):
        self.inner = inner
        self.auditor = auditor
        self.provider = provider
        self.model = model
        self._pii = pii_fields
        self._preserve = preserve_fields

    def _new_sanitizer(self) -> LogSanitizer:
        return LogSanitizer(pii_fields=self._pii, preserve_fields=self._preserve)

    def _run(self, system_prompt: str, user_prompt: str, json_mode: bool) -> str:
        san = self._new_sanitizer()
        safe_user = san.sanitize_text(user_prompt)
        if json_mode:
            raw = self.inner.complete_json(system_prompt, safe_user)
        else:
            raw = self.inner.complete(system_prompt, safe_user)
        if self.auditor:
            # Audit the sanitized prompt (what actually left) and the raw response.
            self.auditor.record(
                system_prompt=system_prompt,
                user_prompt=safe_user,
                response=raw,
                redactions=san.redaction_count(),
                provider=self.provider,
                model=self.model,
            )
        # Rehydrate placeholders so downstream gets an executable, real-valued rule.
        return san.rehydrate(raw)

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return self._run(system_prompt, user_prompt, json_mode=False)

    def complete_json(self, system_prompt: str, user_prompt: str) -> str:
        return self._run(system_prompt, user_prompt, json_mode=True)
