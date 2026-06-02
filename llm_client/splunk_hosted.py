import requests
from .base import LLMClient


class SplunkHostedClient(LLMClient):
    """
    Splunk Cloud hosted Foundation-sec-1.1 client.
    Earns the 'Best Use of Splunk Hosted Models' prize.
    Requires Splunk Cloud instance with AI Gateway enabled.
    """

    def __init__(self, endpoint: str, token: str):
        self.endpoint = endpoint
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
        }
        resp = requests.post(self.endpoint, json=payload, headers=self.headers, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        # Foundation-sec response format
        return data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
