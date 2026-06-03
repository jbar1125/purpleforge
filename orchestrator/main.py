"""
PurpleForge Orchestrator — the main round loop.

Round lifecycle:
  1. Red selects techniques and injects events via HEC
  2. Wait for Splunk to index
  3. Blue runs all detection rules
  4. Score: hits vs misses per technique
  5. Misses → Blue generates new SPL rules via LLM
  6. Hits → Red receives the catching rule and mutates for next round
  7. Update MITRE coverage matrix
  8. Log round results
"""

import sys
import time
from pathlib import Path
from datetime import datetime, timezone

# Allow running from project root without installing
sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
from rich.console import Console

from splunk_client.hec import HECClient
from splunk_client.search import SearchClient
from splunk_client.mcp import MCPClient
from llm_client.factory import get_llm_client
from red_agent.agent import RedAgent
from blue_agent.agent import BlueAgent
from mitre.coverage import CoverageMatrix
from mitre.techniques import TECHNIQUES
from orchestrator.scorer import score_round
from orchestrator.reporter import save_report, print_final_summary
from mitre.navigator import export_navigator_layer
from orchestrator.checkpoint import Checkpoint
from red_agent.injector import _MAX_SPREAD_SECONDS

console = Console()


def load_config(path: str = "config.yaml") -> dict:
    cfg_path = Path(__file__).parent.parent / path
    if not cfg_path.exists():
        console.print(f"[red]config.yaml not found. Copy config.example.yaml → config.yaml and fill it in.[/red]")
        sys.exit(1)
    with open(cfg_path) as f:
        return yaml.safe_load(f)


class Orchestrator:
    def __init__(self, config_path: str = "config.yaml"):
        self.cfg = load_config(config_path)
        sc = self.cfg["splunk"]
        arena = self.cfg["arena"]

        # Splunk clients
        self.hec = HECClient(
            host=sc["host"],
            port=sc["hec_port"],
            token=sc["hec_token"],
            verify_ssl=sc.get("verify_ssl", False),
        )
        self.search = SearchClient(
            host=sc["host"],
            port=sc["rest_port"],
            username=sc["username"],
            password=sc["password"],
            verify_ssl=sc.get("verify_ssl", False),
        )
        # MCP client — uses Splunk MCP Server app if token is configured
        mcp_token = sc.get("mcp_token", "")
        if mcp_token:
            self.mcp = MCPClient.from_config(sc)
        else:
            self.mcp = None  # falls back to REST API in blue agent

        # LLM
        self.llm = get_llm_client(self.cfg["llm"])

        # Agents
        technique_ids = arena["techniques"]
        self.red = RedAgent(
            hec=self.hec,
            llm=self.llm,
            index=sc["index_attacks"],
            technique_ids=technique_ids,
        )
        self.blue = BlueAgent(search=self.search, llm=self.llm, mcp=self.mcp)
        self.coverage = CoverageMatrix(technique_ids=technique_ids)

        self.num_rounds = arena["num_rounds"]
        self.indexing_wait = arena.get("indexing_wait_seconds", 4)
        self.index_attacks = sc["index_attacks"]
        self.round_logs = []
        self.checkpoint = Checkpoint(self.cfg)

    def _ensure_indexes(self) -> None:
        console.print("[dim]Ensuring Splunk indexes exist...[/dim]")
        sc = self.cfg["splunk"]
        self.search.create_index(sc["index_baseline"])
        self.search.create_index(sc["index_attacks"])

    def run(self) -> None:
        console.print("\n[bold magenta]╔══════════════════════════════════════╗[/bold magenta]")
        console.print("[bold magenta]║         PURPLEFORGE v1               ║[/bold magenta]")
        console.print("[bold magenta]║   Adversarial Detection Engineering  ║[/bold magenta]")
        console.print("[bold magenta]╚══════════════════════════════════════╝[/bold magenta]\n")

        self._ensure_indexes()

        for round_num in range(1, self.num_rounds + 1):
            console.print(f"\n[bold yellow]━━━ ROUND {round_num} / {self.num_rounds} ━━━[/bold yellow]")

            # ── 1. Red injects ──────────────────────────────────────────────
            console.print("[bold red]● RED AGENT — injecting attacks[/bold red]")
            round_start = datetime.now(timezone.utc)
            injected = self.red.run_round(round_num=round_num)
            inject_end = datetime.now(timezone.utc)

            # ── 2. Wait for indexing ────────────────────────────────────────
            console.print(f"  Waiting {self.indexing_wait}s for Splunk to index events...")
            time.sleep(self.indexing_wait)

            # Scope search to this round's injection window.
            # Events are backdated up to _MAX_SPREAD_SECONDS before injection time,
            # so we must reach back that far before round_start to capture them all.
            earliest = str(int(round_start.timestamp()) - _MAX_SPREAD_SECONDS - 10)
            latest = "now"
            # Also pass the round number so rules can optionally filter by arena_round
            self._current_round = round_num

            # ── 3. Blue detects ─────────────────────────────────────────────
            console.print("[bold blue]● BLUE AGENT — running detection rules[/bold blue]")
            self.blue.reset_round()
            detection_results = self.blue.run_detection(earliest=earliest, latest=latest)

            # ── 4. Score ─────────────────────────────────────────────────────
            detected, catching_rules = score_round(
                injected=injected,
                detection_results=detection_results,
                technique_ids=list(injected.keys()),
            )

            hits = [tid for tid, d in detected.items() if d]
            misses = [tid for tid, d in detected.items() if not d]
            console.print(f"  [green]Detected ({len(hits)}): {hits}[/green]")
            console.print(f"  [red]Missed ({len(misses)}): {misses}[/red]")

            # ── 5. Blue generates rules for misses ───────────────────────────
            if misses:
                console.print("[bold blue]● BLUE AGENT — generating new rules for misses[/bold blue]")
                missed_events = {tid: injected.get(tid, []) for tid in misses}
                new_rules = self.blue.generate_rules_for_misses(
                    missed_techniques=missed_events,
                    round_num=round_num,
                    red_mutations=self.red.get_current_overrides(),
                )
                for tid in misses:
                    self.coverage.record_rule_generated(tid)

            # ── 6. Red mutates for hits ──────────────────────────────────────
            if hits:
                console.print("[bold red]● RED AGENT — mutating to evade catching rules[/bold red]")
                for tid in hits:
                    rule_name = catching_rules.get(tid)
                    if rule_name:
                        self.blue.record_catching_rule(tid, rule_name)
                        catching_spl = self.blue.get_catching_rule_for(tid)
                        if catching_spl:
                            self.red.receive_catching_rule(tid, catching_spl)

            # ── 7. Update coverage matrix ────────────────────────────────────
            self.coverage.record_round(round_num=round_num, results=detected)

            # ── 8. Log round + inject summary event ──────────────────────────
            cov = self.coverage.coverage_percent()
            round_log = {
                "round": round_num,
                "detected": hits,
                "missed": misses,
                "catching_rules": catching_rules,
                "coverage_after_round": cov,
            }
            self.round_logs.append(round_log)
            self.checkpoint.save_round(
                round_num=round_num,
                injected=injected,
                detected=detected,
                catching_rules=catching_rules,
                coverage=cov,
                mutations=self.red.get_current_overrides(),
            )
            # Inject a summary event so the Splunk dashboard can track coverage over rounds
            summary_event = {
                "event_type": "purpleforge_round_summary",
                "round": round_num,
                "coverage_pct": cov,
                "detected_count": len(hits),
                "missed_count": len(misses),
                "detected_techniques": ",".join(hits),
                "missed_techniques": ",".join(misses),
                "rules_fired": len([r for r, rows in detection_results.items() if rows]),
            }
            self.hec.send_events([summary_event], index=self.index_attacks, sourcetype="purpleforge:summary")
            console.print(f"  Coverage after round {round_num}: [bold]{cov}%[/bold]")

        # ── Final report ─────────────────────────────────────────────────────
        summary = self.coverage.summary()
        print_final_summary(summary)
        path = save_report(summary, self.round_logs)
        console.print(f"\n[dim]Full report saved: {path}[/dim]")
        # Export ATT&CK Navigator layer for visual coverage heatmap
        results_dir = str(Path(__file__).parent.parent / "results")
        nav_path = export_navigator_layer(summary, output_dir=results_dir)
        console.print(f"[dim]ATT&CK Navigator layer: {nav_path}[/dim]")
        console.print("[dim]  -> Open at https://mitre-attack.github.io/attack-navigator/ (Upload from URL or file)[/dim]")
        self.checkpoint.mark_complete()
        self.checkpoint.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PurpleForge — Adversarial Detection Engineering")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    args = parser.parse_args()
    Orchestrator(config_path=args.config).run()
