"""
Reset PurpleForge arena between runs.

Clears:
  - All events in arena_attacks index (Splunk)
  - All LLM-generated SPL rules (blue_agent/rules/generated/)
  - Old results files (results/*.json, results/*.json)

Usage:
    python clear_arena.py              # interactive confirmation
    python clear_arena.py --yes        # no confirmation prompt

Run this before recording a clean demo or starting fresh.
"""

import sys
import shutil
import requests
import urllib3
from pathlib import Path

urllib3.disable_warnings()
sys.path.insert(0, str(Path(__file__).parent))

import yaml

GENERATED_DIR = Path(__file__).parent / "blue_agent" / "rules" / "generated"
RESULTS_DIR = Path(__file__).parent / "results"


def load_config():
    path = Path(__file__).parent / "config.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


def clear_splunk_index(cfg: dict) -> bool:
    """Delete all events from arena_attacks using Splunk's delete command."""
    sc = cfg["splunk"]
    base = f"https://{sc['host']}:{sc['rest_port']}"
    auth = (sc["username"], sc["password"])
    verify = sc.get("verify_ssl", False)
    index = sc["index_attacks"]

    print(f"  Clearing Splunk index '{index}'...")
    # Create a search job with the delete command (requires can_delete role)
    resp = requests.post(
        f"{base}/services/search/jobs",
        auth=auth,
        data={"search": f"search index={index} | delete", "output_mode": "json"},
        params={"output_mode": "json"},
        verify=verify,
        timeout=30,
    )
    if resp.ok:
        print(f"  Splunk index '{index}' clear job submitted.")
        return True
    print(f"  Warning: could not clear Splunk index: {resp.status_code} — {resp.text[:200]}")
    print("  You can manually clear it in Splunk: search index=arena_attacks | delete")
    return False


def clear_generated_rules() -> int:
    """Delete all LLM-generated SPL rules. Returns count deleted."""
    deleted = 0
    for f in GENERATED_DIR.glob("*.spl"):
        if f.name != ".gitkeep":
            f.unlink()
            deleted += 1
    print(f"  Deleted {deleted} generated rule(s) from {GENERATED_DIR}")
    return deleted


def clear_results() -> int:
    """Delete old JSON results and Navigator layers. Returns count deleted."""
    deleted = 0
    if RESULTS_DIR.exists():
        for f in RESULTS_DIR.glob("run_*.json"):
            f.unlink()
            deleted += 1
        for f in RESULTS_DIR.glob("navigator_layer_*.json"):
            f.unlink()
            deleted += 1
        # Remove SQLite checkpoint too
        db = RESULTS_DIR / "arena.db"
        if db.exists():
            db.unlink()
            deleted += 1
    print(f"  Deleted {deleted} result file(s) from {RESULTS_DIR}")
    return deleted


def main():
    auto_yes = "--yes" in sys.argv or "-y" in sys.argv

    print("\nPurpleForge Arena Reset")
    print("=" * 40)
    print("This will delete:")
    print("  1. All events in arena_attacks Splunk index")
    print("  2. All LLM-generated SPL rules")
    print("  3. All results JSON and Navigator layer files")
    print("  4. SQLite checkpoint database")
    print()

    if not auto_yes:
        confirm = input("Proceed? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            sys.exit(0)

    cfg = load_config()
    clear_splunk_index(cfg)
    clear_generated_rules()
    clear_results()

    print("\nArena reset complete. Run: python orchestrator/main.py")


if __name__ == "__main__":
    main()
