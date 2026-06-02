from .base import LLMClient


def get_llm_client(cfg: dict) -> LLMClient:
    """Instantiate the correct LLM client from the llm section of config."""
    provider = cfg.get("provider", "gemini")

    if provider == "gemini":
        from .gemini import GeminiClient
        gcfg = cfg["gemini"]
        return GeminiClient(api_key=gcfg["api_key"], model=gcfg.get("model", "gemini-2.0-flash"))

    if provider == "ollama":
        from .ollama_client import OllamaClient
        ocfg = cfg.get("ollama", {})
        return OllamaClient(
            model=ocfg.get("model", "llama3.1"),
            base_url=ocfg.get("base_url", "http://localhost:11434"),
        )

    if provider == "splunk_hosted":
        from .splunk_hosted import SplunkHostedClient
        scfg = cfg["splunk_hosted"]
        return SplunkHostedClient(endpoint=scfg["endpoint"], token=scfg["token"])

    raise ValueError(f"Unknown LLM provider '{provider}'. Choose: gemini, ollama, splunk_hosted")
