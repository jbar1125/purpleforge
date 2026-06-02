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

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
        }
        resp = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=120)
        resp.raise_for_status()
        return resp.json()["message"]["content"].strip()
