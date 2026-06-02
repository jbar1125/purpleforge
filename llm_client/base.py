from abc import ABC, abstractmethod


class LLMClient(ABC):
    """
    Abstract LLM client. Swap providers by implementing this interface.
    All methods return plain strings; callers are responsible for JSON parsing.
    """

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Send a prompt pair and return the model's text response."""
        ...

    def complete_json(self, system_prompt: str, user_prompt: str) -> str:
        """
        Like complete(), but asks the model to return only JSON.
        Subclasses can override this to use native JSON mode if the provider supports it.
        """
        json_instruction = "\n\nRespond with valid JSON only. No markdown, no explanation outside the JSON."
        return self.complete(system_prompt, user_prompt + json_instruction)
