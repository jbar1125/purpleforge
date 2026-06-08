import random
import time

import requests

from .base import LLMClient

_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"

# Retry config for 429 rate-limit responses.
_MAX_RETRIES = 3
_BACKOFF_BASE = 5.0    # seconds — doubles each retry: 5, 10, 20
_BACKOFF_JITTER = 2.0  # add up to this many random seconds to each wait
# Cap how long we'll actually sleep on a 429 — Groq's Retry-After can be 60s
# which stalls the arena well past its intended duration. 10s is enough to
# respect back-pressure while keeping the run responsive.
_MAX_WAIT_SECONDS = 10.0


class GroqClient(LLMClient):
    """
    Groq inference — OpenAI-compatible API, no extra dependency beyond requests.
    Free tier: 6000 req/day, 30 req/min.  ~500 tok/s on LPU hardware.

    Recommended models (set in config):
      llama-3.3-70b-versatile   — best quality, fits in free tier
      llama-3.1-8b-instant      — fastest, good for JSON tasks
    """

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model = model

    def _post(self, payload: dict) -> dict:
        """POST to Groq with exponential backoff on 429 rate-limit responses."""
        delay = _BACKOFF_BASE
        last_resp = None
        for attempt in range(_MAX_RETRIES):
            resp = requests.post(
                _ENDPOINT,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=30,  # Groq responds in 2-10s when healthy; 30s is generous
            )
            last_resp = resp
            if resp.status_code != 429:
                break
            # Respect Retry-After but cap it — Groq sometimes sets 60s which
            # would stall the arena long past its intended duration.
            server_wait = float(resp.headers.get("Retry-After", delay))
            wait = min(max(server_wait, delay), _MAX_WAIT_SECONDS) + random.uniform(0, _BACKOFF_JITTER)
            if attempt < _MAX_RETRIES - 1:
                time.sleep(wait)
                delay *= 2  # exponential backoff
        last_resp.raise_for_status()
        return last_resp.json()

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        result = self._post({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "temperature": 0.3,
        })
        return result["choices"][0]["message"]["content"]

    def complete_json(self, system_prompt: str, user_prompt: str) -> str:
        """Use Groq's native JSON mode — more reliable than appending instructions."""
        result = self._post({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "temperature": 0.3,
            "response_format": {"type": "json_object"},
        })
        return result["choices"][0]["message"]["content"]
