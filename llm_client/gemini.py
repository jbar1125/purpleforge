import google.generativeai as genai
from .base import LLMClient


class GeminiClient(LLMClient):
    """
    Google Gemini client. Free tier: gemini-2.0-flash at 15 req/min.
    Get API key: https://aistudio.google.com/app/apikey
    """

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(
            model_name=model,
            system_instruction=None,  # set per-call via chat
        )
        self._model_name = model

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        model = genai.GenerativeModel(
            model_name=self._model_name,
            system_instruction=system_prompt,
        )
        response = model.generate_content(user_prompt)
        return response.text.strip()
