"""
Splunk MCP Server client.

The Splunk MCP Server is a Splunk app (not a standalone process).
It exposes the MCP JSON-RPC 2.0 protocol at:
  https://<host>:<rest_port>/servicesNS/nobody/Splunk_MCP_Server/mcp

Authentication uses a dedicated MCP token (RSA-encrypted JWT), NOT basic auth.
Generate a token once via setup_verify.py or the REST call in docs/splunk_setup.md,
then store it in config.yaml under splunk.mcp_token.

The built-in tool for running SPL searches is called `run_query`.
"""

import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MCPClient:
    """
    MCP JSON-RPC 2.0 client for the Splunk MCP Server app.
    Falls back gracefully — the rest of the system works without it.
    """

    def __init__(self, host: str, port: int, mcp_token: str, verify_ssl: bool = False):
        self.endpoint = f"https://{host}:{port}/servicesNS/nobody/Splunk_MCP_Server/mcp"
        self.headers = {
            "Authorization": f"Bearer {mcp_token}",
            "Content-Type": "application/json",
        }
        self.verify = verify_ssl
        self._available = None  # lazily checked on first use

    def is_available(self) -> bool:
        """
        Check if the MCP Server app is responding.
        Uses a lightweight REST ping rather than the full JSON-RPC handshake.
        """
        if self._available is None:
            try:
                import urllib3
                urllib3.disable_warnings()
                resp = requests.get(
                    self.endpoint,
                    headers=self.headers,
                    verify=self.verify,
                    timeout=5,
                )
                # Only treat 200 as available; 401 = bad token, fall back to REST
                self._available = resp.status_code == 200
            except Exception:
                self._available = False
        return self._available

    def _rpc(self, method: str, params: dict) -> dict:
        """Send a JSON-RPC 2.0 request and return the result."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
        resp = requests.post(
            self.endpoint,
            json=payload,
            headers=self.headers,
            verify=self.verify,
            timeout=90,
        )
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(f"MCP error: {data['error']}")
        return data.get("result", {})

    def search(self, spl: str, earliest: str = "-15m", latest: str = "now") -> list[dict]:
        """
        Run a SPL search via the MCP `run_query` built-in tool.
        Returns a list of result row dicts.
        """
        result = self._rpc("tools/call", {
            "name": "run_query",
            "arguments": {
                "query": spl,
                "earliest_time": earliest,
                "latest_time": latest,
                "row_limit": 500,
            },
        })
        # MCP returns content as an array of typed blocks
        for block in result.get("content", []):
            if block.get("type") == "text":
                try:
                    parsed = json.loads(block["text"])
                    # run_query returns {"results": [...]} or just a list
                    if isinstance(parsed, list):
                        return parsed
                    if isinstance(parsed, dict):
                        return parsed.get("results", [parsed])
                except (json.JSONDecodeError, KeyError):
                    pass
        return []

    @classmethod
    def from_config(cls, splunk_cfg: dict) -> "MCPClient":
        """Convenience constructor from the splunk section of config.yaml."""
        return cls(
            host=splunk_cfg["host"],
            port=splunk_cfg["rest_port"],
            mcp_token=splunk_cfg.get("mcp_token", ""),
            verify_ssl=splunk_cfg.get("verify_ssl", False),
        )

    @classmethod
    def disabled() -> "MCPClient":
        """Return a client that always reports itself as unavailable."""
        c = object.__new__(MCPClient)
        c._available = False
        return c
