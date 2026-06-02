import google.generativeai as genai
from .base import LLMClient


class GeminiClient(LLMClient):
    """
    Google Gemini client. Free tier: gemini-2.0-flash at 15 req/min.
    Get API key: https://aistudio.google.com/app/apikey
    """

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        genai.configure(api_key=api_key)
        self._model_name = model

    def _get_model(self, system_prompt: str, json_mode: bool = False):
        kwargs = {"model_name": self._model_name, "system_instruction": system_prompt}
        if json_mode:
            kwargs["generation_config"] = genai.GenerationConfig(
                response_mime_type="application/json"
            )
        return genai.GenerativeModel(**kwargs)

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        model = self._get_model(system_prompt)
        response = model.generate_content(user_prompt)
        return response.text.strip()

    def complete_json(self, system_prompt: str, user_prompt: str) -> str:
        """Use Gemini's native JSON mode for reliable structured output."""
        model = self._get_model(system_prompt, json_mode=True)
        response = model.generate_content(user_prompt)
        return response.text.strip()
