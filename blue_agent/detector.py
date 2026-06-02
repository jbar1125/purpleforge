from pathlib import Path
from splunk_client.search import SearchClient
from splunk_client.mcp import MCPClient

BASELINE_DIR = Path(__file__).parent / "rules" / "baseline"
GENERATED_DIR = Path(__file__).parent / "rules" / "generated"


class Detector:
    """
    Loads all SPL detection rules (baseline + LLM-generated) and runs them
    against the current round's time window.

    Uses MCP Server when available (prize eligibility); falls back to REST API.
    """

    def __init__(self, search_client: SearchClient, mcp_client: MCPClient = None):
        self.search = search_client
        self.mcp = mcp_client

    def _load_rules(self) -> dict[str, dict]:
        """Load all .spl files. Returns {rule_name: {spl, technique_id, source}}."""
        rules = {}

        for spl_file in sorted(BASELINE_DIR.glob("*.spl")):
            spl = spl_file.read_text().strip()
            rules[spl_file.stem] = {
                "spl": spl,
                "source": "baseline",
                "file": str(spl_file),
            }

        for spl_file in sorted(GENERATED_DIR.glob("*.spl")):
            spl = spl_file.read_text().strip()
            rules[spl_file.stem] = {
                "spl": spl,
                "source": "generated",
                "file": str(spl_file),
            }

        return rules

    def _run_spl(self, spl: str, earliest: str, latest: str) -> list[dict]:
        """Run a search via MCP if available, else REST API."""
        if self.mcp and self.mcp.is_available():
            return self.mcp.search(spl, earliest=earliest, latest=latest)
        return self.search.run_search_async(spl, earliest=earliest, latest=latest)

    def run_all_rules(self, earliest: str, latest: str) -> dict[str, list[dict]]:
        """
        Run every rule and collect results.
        Returns {rule_name: [result_rows]}.
        """
        rules = self._load_rules()
        results = {}
        for name, rule in rules.items():
            try:
                rows = self._run_spl(rule["spl"], earliest=earliest, latest=latest)
                results[name] = rows
                status = f"{len(rows)} hits" if rows else "no hits"
                print(f"  [blue] rule '{name}' ({rule['source']}): {status}")
            except Exception as e:
                print(f"  [blue] rule '{name}' failed: {e}")
                results[name] = []
        return results

    def get_all_rules(self) -> dict[str, dict]:
        """Expose the full rule inventory (used by generator and reporter)."""
        return self._load_rules()
