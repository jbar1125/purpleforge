import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from splunk_client.search import SearchClient
from splunk_client.mcp import MCPClient
from splunk_client import sigma_compiler

SIGMA_DIR = Path(__file__).parent / "rules" / "sigma"
BASELINE_DIR = Path(__file__).parent / "rules" / "baseline"
GENERATED_DIR = Path(__file__).parent / "rules" / "generated"

# Parse the MITRE technique from a Sigma `attack.tXXXX[.YYY]` tag.
_ATTACK_TAG = re.compile(r"attack\.t(\d{4})(?:\.(\d{3}))?", re.IGNORECASE)


def technique_from_sigma(yaml_text: str) -> str | None:
    """Extract e.g. 'T1021.001' from a Sigma rule's attack.* tags."""
    m = _ATTACK_TAG.search(yaml_text)
    if not m:
        return None
    return f"T{m.group(1)}.{m.group(2)}" if m.group(2) else f"T{m.group(1)}"


class Detector:
    """
    Loads all detection rules (Sigma baseline + SPL baseline + LLM-generated)
    and runs them against the current round's time window.

    Rule sources, in precedence order:
      1. rules/sigma/*.yml   — portable Sigma, compiled to SPL via pySigma
      2. rules/baseline/*.spl — native SPL for detections Sigma can't express
                                (e.g. password-spray aggregation), or fallback
      3. rules/generated/*.spl — LLM-authored rules (compiled from Sigma)

    Uses MCP Server when available (prize eligibility); falls back to the
    Splunk SDK for baseline rules (Developer Tools prize), then REST.

    RuleRegistry: if provided, burned rules are silently skipped so Red's
    alert-fatigue victories compound over time.
    """

    def __init__(
        self,
        search_client: SearchClient,
        mcp_client: MCPClient = None,
        index: str = "arena_attacks",
        registry=None,   # RuleRegistry | None — avoids circular import
    ):
        self.search = search_client
        self.mcp = mcp_client
        self.index = index
        self.registry = registry  # type: ignore

    def _load_rules(self) -> dict[str, dict]:
        """Load all rules. Returns {rule_name: {spl, source, format, file, sigma?}}."""
        rules: dict[str, dict] = {}

        # 1. Sigma baseline — compile each to SPL and tag for the scorer.
        if sigma_compiler.is_available():
            for yml in sorted(SIGMA_DIR.glob("*.yml")):
                text = yml.read_text(encoding="utf-8")
                try:
                    spl = sigma_compiler.compile_to_spl(text, index=self.index)
                except sigma_compiler.SigmaError as e:
                    print(f"  [blue] sigma '{yml.stem}' compile failed → .spl fallback: {e}")
                    continue
                tid = technique_from_sigma(text) or ""
                rule_name = f"{yml.stem}_baseline"
                # Tag identically to hand-written .spl rules so the scorer attributes hits.
                spl_tagged = spl + f'\n| eval technique="{tid}", rule_name="{rule_name}"'
                rules[yml.stem] = {
                    "spl": spl_tagged,
                    "source": "baseline",
                    "format": "sigma",
                    "file": str(yml),
                    "sigma": text,
                }

        # 2. SPL baseline — only for stems Sigma didn't already provide.
        for spl_file in sorted(BASELINE_DIR.glob("*.spl")):
            if spl_file.stem in rules:
                continue
            rules[spl_file.stem] = {
                "spl": spl_file.read_text().strip(),
                "source": "baseline",
                "format": "spl",
                "file": str(spl_file),
            }

        # 3. Generated rules (already compiled to SPL by the generator).
        for spl_file in sorted(GENERATED_DIR.glob("*.spl")):
            rules[spl_file.stem] = {
                "spl": spl_file.read_text().strip(),
                "source": "generated",
                "format": "spl",
                "file": str(spl_file),
            }

        # 4. Filter out burned rules so Red's alert-fatigue victories are respected.
        if self.registry is not None:
            burned = set(self.registry.burned_rules())
            if burned:
                before = len(rules)
                rules = {n: r for n, r in rules.items() if n not in burned}
                skipped = before - len(rules)
                if skipped:
                    print(f"  [blue] skipping {skipped} BURNED rule(s): {burned & set(rules) or burned}")

        return rules

    def _run_spl(self, spl: str, earliest: str, latest: str, source: str = "generated") -> list[dict]:
        """
        Run a search, choosing the best available backend:
          1. MCP Server (if configured) — earns Best Use of MCP prize
          2. Splunk SDK (for baseline rules) — earns Best Use of Developer Tools prize
          3. REST API (fallback for generated rules)
        """
        if self.mcp and self.mcp.is_available():
            return self.mcp.search(spl, earliest=earliest, latest=latest)
        if source == "baseline":
            # Use the official Splunk SDK for baseline rules — Developer Tools prize
            return self.search.run_search_sdk(spl, earliest=earliest, latest=latest)
        return self.search.run_search_async(spl, earliest=earliest, latest=latest)

    def run_all_rules(self, earliest: str, latest: str) -> dict[str, list[dict]]:
        """
        Run every rule in parallel and collect results.
        Returns {rule_name: [result_rows]}.
        """
        rules = self._load_rules()
        results: dict[str, list[dict]] = {}

        def _run_one(name: str, rule: dict) -> tuple[str, list[dict]]:
            rows = self._run_spl(rule["spl"], earliest=earliest, latest=latest, source=rule["source"])
            fmt = rule.get("format", "spl")
            status = f"{len(rows)} hits" if rows else "no hits"
            print(f"  [blue] rule '{name}' ({rule['source']}/{fmt}): {status}")
            return name, rows

        with ThreadPoolExecutor(max_workers=min(len(rules), 12)) as pool:
            futures = {pool.submit(_run_one, name, rule): name for name, rule in rules.items()}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    rule_name, rows = fut.result()
                    results[rule_name] = rows
                except Exception as e:
                    print(f"  [blue] rule '{name}' failed: {e}")
                    results[name] = []

        return results

    def get_all_rules(self) -> dict[str, dict]:
        """Expose the full rule inventory (used by generator and reporter)."""
        return self._load_rules()
