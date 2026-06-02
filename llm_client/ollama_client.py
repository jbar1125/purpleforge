import requests
from .base import LLMClient


class OllamaClient(LLMClient):
    """
    Local Ollama client. Fully free, runs on-device.
    Setup: https://ollama.com/download  then  `ollama pull llama3.1`
    """

    def __init__(self, model: str = "llama3.1", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def _chat(self, system_prompt: str, user_prompt: str, json_mode: bool = False) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
        }
        if json_mode:
            payload["format"] = "json"  # Ollama native JSON mode
        resp = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=300)
        resp.raise_for_status()
        return resp.json()["message"]["content"].strip()

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return self._chat(system_prompt, user_prompt)

    def complete_json(self, system_prompt: str, user_prompt: str) -> str:
        """Use Ollama's native JSON mode — guarantees valid JSON output."""
        return self._chat(system_prompt, user_prompt, json_mode=True)
