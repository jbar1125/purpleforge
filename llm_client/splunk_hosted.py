import json
import requests
from .base import LLMClient

# Splunk AI Gateway / Foundation-sec-1.1 API format
# Endpoint: https://<instance>.splunkcloud.com/services/ml/models/foundation-sec-1.1-8b-instruct/predict
# Auth: Bearer token (Splunk Cloud service account token)
#
# Request body: {"inputs": [{"messages": [...]}]}
# Response:    {"predictions": [{"generated_text": "..."}]}
#              OR OpenAI-compatible: {"choices": [{"message": {"content": "..."}}]}


class SplunkHostedClient(LLMClient):
    """
    Splunk Cloud hosted Foundation-sec-1.1 client.
    Earns the 'Best Use of Splunk Hosted Models' prize ($1k).

    Foundation-sec-1.1-8b-instruct is fine-tuned specifically for security tasks —
    better SPL generation and red-team reasoning than general models.

    Setup:
      1. Create a Splunk Cloud trial: https://www.splunk.com/en_us/try-splunk.html
      2. In Splunk Cloud: Settings → Tokens → New Token (role: sc_admin)
      3. Copy the endpoint URL from the AI Gateway app or model catalog
      4. Set in config.yaml: provider: splunk_hosted
    """

    def __init__(self, endpoint: str, token: str, timeout: int = 120):
        self.endpoint = endpoint.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """
        Call Foundation-sec-1.1 via Splunk AI Gateway.
        Tries two request formats (predict API and OpenAI-compatible).
        """
        # Primary format: Splunk AI Gateway predict endpoint
        payload = {
            "inputs": [
                {
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ]
                }
            ]
        }
        try:
            resp = requests.post(
                self.endpoint,
                json=payload,
                headers=self.headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()

            # Format 1: Splunk predict API
            predictions = data.get("predictions", [])
            if predictions:
                first = predictions[0]
                if isinstance(first, dict):
                    return first.get("generated_text", str(first)).strip()
                return str(first).strip()

            # Format 2: OpenAI-compatible (some Splunk Gateway configs)
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "").strip()

            # Format 3: direct text response
            if isinstance(data, str):
                return data.strip()

            raise ValueError(f"Unrecognized response format: {json.dumps(data)[:200]}")

        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 422:
                # Try OpenAI-compatible format as fallback
                return self._complete_openai_compat(system_prompt, user_prompt)
            raise

    def _complete_openai_compat(self, system_prompt: str, user_prompt: str) -> str:
        """Fallback: OpenAI-compatible /v1/chat/completions format."""
        base = self.endpoint.rstrip("/predict").rstrip("/")
        url = f"{base}/v1/chat/completions"
        payload = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": 1024,
        }
        resp = requests.post(url, json=payload, headers=self.headers, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()
