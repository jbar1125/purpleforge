"""
Run this first to verify your Splunk config before running the full arena.
Usage: python setup_verify.py

Checks:
  1. Splunk REST API reachable + credentials valid
  2. HEC endpoint reachable + token valid
  3. Indexes exist (creates them if missing)
  4. LLM provider reachable
  5. MCP Server reachable (optional)
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import yaml
from rich.console import Console
from rich.table import Table

console = Console()


def load_config():
    path = Path(__file__).parent / "config.yaml"
    if not path.exists():
        console.print("[red]config.yaml not found. Copy config.example.yaml → config.yaml and fill in your values.[/red]")
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)


def check_rest_api(sc):
    from splunk_client.search import SearchClient
    client = SearchClient(
        host=sc["host"],
        port=sc["rest_port"],
        username=sc["username"],
        password=sc["password"],
        verify_ssl=sc.get("verify_ssl", False),
    )
    try:
        indexes = client.list_indexes()
        return True, f"Connected. Found {len(indexes)} indexes.", client
    except Exception as e:
        return False, str(e), None


def check_hec(sc):
    from splunk_client.hec import HECClient
    client = HECClient(
        host=sc["host"],
        port=sc["hec_port"],
        token=sc["hec_token"],
        verify_ssl=sc.get("verify_ssl", False),
    )
    try:
        client.send_event({"test": "purpleforge_setup_check"}, index=sc["index_attacks"], sourcetype="test")
        return True, "HEC injection successful.", client
    except Exception as e:
        return False, str(e), None


def check_indexes(search_client, sc):
    try:
        ok1 = search_client.create_index(sc["index_baseline"])
        ok2 = search_client.create_index(sc["index_attacks"])
        return True, f"Indexes ready: {sc['index_baseline']}, {sc['index_attacks']}"
    except Exception as e:
        return False, str(e)


def check_llm(llm_cfg):
    from llm_client.factory import get_llm_client
    try:
        client = get_llm_client(llm_cfg)
        response = client.complete(
            system_prompt="You are a test assistant.",
            user_prompt="Reply with exactly: OK",
        )
        return True, f"LLM responded: '{response[:50]}'"
    except Exception as e:
        return False, str(e)


def check_mcp(sc):
    from splunk_client.mcp import MCPClient
    token = sc.get("mcp_token", "")
    if not token:
        return False, "No mcp_token in config.yaml. Generate one (see instructions below) then add it."
    client = MCPClient.from_config(sc)
    if client.is_available():
        return True, "MCP Server reachable and token valid."
    return False, "MCP Server not responding. Is the Splunk_MCP_Server app installed? Try restarting Splunk."


def generate_mcp_token(sc):
    """Call the MCP token endpoint with basic auth to get a new token."""
    import base64
    import requests
    import urllib3
    urllib3.disable_warnings()
    creds = base64.b64encode(f"{sc['username']}:{sc['password']}".encode()).decode()
    url = f"https://{sc['host']}:{sc['rest_port']}/servicesNS/nobody/Splunk_MCP_Server/mcp_token"
    try:
        resp = requests.post(
            url,
            headers={"Authorization": f"Basic {creds}", "Content-Type": "application/json"},
            json={"expires_on": 9999999999},
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        token = data.get("token") or data.get("mcp_token") or str(data)
        return token
    except Exception as e:
        return None


def main():
    console.print("\n[bold cyan]PurpleForge Setup Verification[/bold cyan]\n")
    cfg = load_config()
    sc = cfg["splunk"]

    results = []

    # 1. REST API
    ok, msg, search_client = check_rest_api(sc)
    results.append(("Splunk REST API", ok, msg))

    # 2. HEC
    ok_hec, msg_hec, _ = check_hec(sc)
    results.append(("Splunk HEC", ok_hec, msg_hec))

    # 3. Indexes
    if search_client:
        ok_idx, msg_idx = check_indexes(search_client, sc)
        results.append(("Splunk Indexes", ok_idx, msg_idx))

    # 4. LLM
    ok_llm, msg_llm = check_llm(cfg["llm"])
    results.append((f"LLM ({cfg['llm']['provider']})", ok_llm, msg_llm))

    # 5. MCP (optional)
    ok_mcp, msg_mcp = check_mcp(sc)
    results.append(("Splunk MCP Server (optional)", ok_mcp, msg_mcp))

    # Print table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Check")
    table.add_column("Status", justify="center")
    table.add_column("Details")

    all_critical_pass = True
    for name, ok, msg in results:
        status = "[green]✓ PASS[/green]" if ok else "[red]✗ FAIL[/red]"
        table.add_row(name, status, msg)
        if not ok and "optional" not in name.lower():
            all_critical_pass = False

    console.print(table)

    if all_critical_pass:
        console.print("\n[bold green]All critical checks passed. You're ready to run: python orchestrator/main.py[/bold green]")
    else:
        console.print("\n[bold red]Fix the failing checks above before running the arena.[/bold red]")
        console.print("[dim]See docs/splunk_setup.md for step-by-step Splunk configuration.[/dim]")

    # If MCP app is installed but no token yet, offer to generate one
    if not sc.get("mcp_token") and search_client:
        console.print("\n[yellow]MCP token not set. Attempting to generate one from the installed app...[/yellow]")
        token = generate_mcp_token(sc)
        if token:
            console.print(f"\n[bold green]✓ MCP token generated![/bold green]")
            console.print(f"Add this to config.yaml under splunk.mcp_token:\n\n  [bold cyan]{token}[/bold cyan]\n")
        else:
            console.print("[dim]Could not generate token — MCP Server app may not be installed yet. Follow Step 6 in docs/splunk_setup.md.[/dim]")


if __name__ == "__main__":
    main()
