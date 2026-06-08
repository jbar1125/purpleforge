from .base import LLMClient


def _build_inner(provider: str, cfg: dict) -> LLMClient:
    """Instantiate the raw provider client (no privacy wrapper)."""
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

    if provider == "groq":
        from .groq_client import GroqClient
        gcfg = cfg["groq"]
        return GroqClient(api_key=gcfg["api_key"], model=gcfg.get("model", "llama-3.3-70b-versatile"))

    raise ValueError(f"Unknown LLM provider '{provider}'. Choose: gemini, ollama, splunk_hosted, groq")


def get_llm_client(cfg: dict) -> LLMClient:
    """
    Instantiate the correct LLM client from the `llm` section of config.

    If `llm.secure` is set (truthy or a dict), the client is wrapped in a
    SanitizingLLMClient so every prompt is PII-stripped before it leaves the
    process and a hash-only audit record is written per call (Track 4). This is
    transparent to the generator and mutator — they just call complete().
    """
    provider = cfg.get("provider", "gemini")
    inner = _build_inner(provider, cfg)

    sec = cfg.get("secure")
    if not sec:
        return inner

    from .secure import SanitizingLLMClient
    from .audit import PromptAuditor

    opts = sec if isinstance(sec, dict) else {}
    auditor = None
    if opts.get("audit", True):
        auditor = PromptAuditor(
            path=opts.get("audit_path", "results/llm_audit.jsonl"),
            store_preview=opts.get("store_preview", False),
        )
    model = cfg.get(provider, {}).get("model", "") if isinstance(cfg.get(provider), dict) else ""
    return SanitizingLLMClient(inner, auditor=auditor, provider=provider, model=model)
