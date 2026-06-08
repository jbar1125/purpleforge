"""
PurpleForge Orchestrator — the main round loop.

Round lifecycle:
  1. Red injects attacks  +  Red runs ongoing poison campaign (alert fatigue)
  2. Wait for Splunk to index
  3. Blue runs all ACTIVE (non-burned) detection rules
  4. Score: hits vs misses per technique
  5. Registry update: record rule precision; check for newly burned rules
  6. Win condition check — Red wins by compromising techniques; Blue holds the line
  7. Misses → Blue generates new rules (doubles-down after N consecutive misses)
  8. Hits → Red mutates to evade + starts / continues poisoning that rule
  9. Hits → Blue generates proactive hardening variant anticipating next mutation
 10. Update MITRE coverage matrix (with compromised state)
 11. Log round + ship summary event to Splunk dashboard
"""

import sys
import time
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
from rich.console import Console

from splunk_client.hec import HECClient
from splunk_client.search import SearchClient
from splunk_client.mcp import MCPClient
from llm_client.factory import get_llm_client
from red_agent.agent import RedAgent
from red_agent.benign import BenignGenerator
from blue_agent.agent import BlueAgent
from blue_agent.rule_registry import RuleRegistry
from mitre.coverage import CoverageMatrix
from mitre.techniques import TECHNIQUES
from orchestrator.scorer import score_round, score_precision, check_win
from orchestrator.reporter import save_report, print_final_summary
from orchestrator import memory as arena_memory
from mitre.navigator import export_navigator_layer
from orchestrator.checkpoint import Checkpoint
from red_agent.injector import _MAX_SPREAD_SECONDS

console = Console()

# Win-condition defaults (override in config arena.win_conditions)
_BLUE_WIN_THRESHOLD = 70.0   # Blue holds ≥70% coverage → Blue wins
_RED_WIN_THRESHOLD  = 60.0   # Red compromises ≥60% of techniques → Red wins


def load_config(path: str = "config.yaml") -> dict:
    cfg_path = Path(__file__).parent.parent / path
    if not cfg_path.exists():
        console.print("[red]config.yaml not found. Copy config.example.yaml → config.yaml and fill it in.[/red]")
        sys.exit(1)
    with open(cfg_path) as f:
        return yaml.safe_load(f)


class Orchestrator:
    def __init__(self, config_path: str = "config.yaml", campaign_name: str = None):
        self.cfg = load_config(config_path)
        sc   = self.cfg["splunk"]
        arena = self.cfg["arena"]
        win_cfg = arena.get("win_conditions", {})
        self.campaign_name = campaign_name

        self.blue_win_threshold = win_cfg.get("blue_coverage_pct", _BLUE_WIN_THRESHOLD)
        self.red_win_threshold  = win_cfg.get("red_compromise_pct", _RED_WIN_THRESHOLD)

        # Splunk clients
        self.hec = HECClient(
            host=sc["host"], port=sc["hec_port"], token=sc["hec_token"],
            verify_ssl=sc.get("verify_ssl", False),
        )
        self.search = SearchClient(
            host=sc["host"], port=sc["rest_port"],
            username=sc["username"], password=sc["password"],
            verify_ssl=sc.get("verify_ssl", False),
        )
        mcp_token = sc.get("mcp_token", "")
        self.mcp = MCPClient.from_config(sc) if mcp_token else None

        # LLM
        self.llm = get_llm_client(self.cfg["llm"])

        # ── Cross-session memory ───────────────────────────────────────────────
        self._mem = arena_memory.load()
        registry = arena_memory.load_registry(self._mem)
        initial_overrides = arena_memory.load_red_overrides(self._mem)
        if initial_overrides:
            total_burned = len(registry.burned_rules())
            console.print(
                f"[dim]Session memory loaded: {total_burned} rule(s) burned from prior runs; "
                f"{len(initial_overrides)} technique mutation(s) resumed[/dim]"
            )

        # Agents
        technique_ids = arena["techniques"]
        self.red = RedAgent(
            hec=self.hec, llm=self.llm, index=sc["index_attacks"],
            technique_ids=technique_ids, initial_overrides=initial_overrides,
        )
        self.blue = BlueAgent(
            search=self.search, llm=self.llm, mcp=self.mcp,
            index=sc["index_attacks"], registry=registry,
        )
        self.registry = registry
        self.coverage = CoverageMatrix(technique_ids=technique_ids)

        self.inject_benign = arena.get("benign", True)
        self.benign = BenignGenerator(hec=self.hec, index=sc["index_attacks"])

        self.campaign_runner = None
        if campaign_name:
            from red_agent.campaign import CampaignRunner, load_campaign
            self.campaign_runner = CampaignRunner(self.red, load_campaign(campaign_name))

        self.num_rounds   = arena["num_rounds"]
        self.indexing_wait = arena.get("indexing_wait_seconds", 4)
        self.index_attacks = sc["index_attacks"]
        self.round_logs: list[dict] = []
        self.checkpoint = Checkpoint(self.cfg)
        self._winner: str | None = None

    def _ensure_indexes(self) -> None:
        console.print("[dim]Ensuring Splunk indexes exist...[/dim]")
        sc = self.cfg["splunk"]
        self.search.create_index(sc["index_baseline"])
        self.search.create_index(sc["index_attacks"])

    def run(self) -> None:
        console.print("\n[bold magenta]╔══════════════════════════════════════╗[/bold magenta]")
        console.print("[bold magenta]║         PURPLEFORGE v2               ║[/bold magenta]")
        console.print("[bold magenta]║  Hacker vs Defender — Adaptive Arena ║[/bold magenta]")
        console.print("[bold magenta]╚══════════════════════════════════════╝[/bold magenta]\n")
        console.print(f"[dim]Win conditions: Blue ≥{self.blue_win_threshold:.0f}% coverage | "
                      f"Red compromises ≥{self.red_win_threshold:.0f}% of techniques[/dim]\n")

        self._ensure_indexes()

        for round_num in range(1, self.num_rounds + 1):
            console.print(f"\n[bold yellow]━━━ ROUND {round_num} / {self.num_rounds} ━━━[/bold yellow]")

            # ── 1. Red injects attacks + runs poison campaign ────────────────
            console.print("[bold red]● RED AGENT — injecting attacks[/bold red]")
            round_start = datetime.now(timezone.utc)
            if self.campaign_runner:
                injected = self.campaign_runner.run(
                    round_num=round_num, log=lambda m: console.print(f"  [red]{m}[/red]"))
            else:
                injected = self.red.run_round(round_num=round_num)

            # Poison campaign: flood Blue's catching rules with FPs
            poison_results = self.red.run_poison_campaign(round_num=round_num)
            if poison_results:
                console.print(f"  [red]Poisoned {len(poison_results)} rule(s) with FP floods[/red]")

            # Mix in structured benign activity for precision baseline
            if self.inject_benign:
                benign_events = self.benign.inject(round_num=round_num)
                console.print(f"  [dim]Injected {len(benign_events)} benign events[/dim]")

            # ── 2. Wait for indexing ─────────────────────────────────────────
            console.print(f"  Waiting {self.indexing_wait}s for Splunk to index events...")
            time.sleep(self.indexing_wait)

            earliest = str(int(round_start.timestamp()) - _MAX_SPREAD_SECONDS - 10)
            latest = "now"

            # ── 3. Blue detects (skips burned rules) ─────────────────────────
            console.print("[bold blue]● BLUE AGENT — running detection rules[/bold blue]")
            self.blue.reset_round()
            detection_results = self.blue.run_detection(earliest=earliest, latest=latest)

            # ── 4. Score ──────────────────────────────────────────────────────
            detected, catching_rules = score_round(
                injected=injected,
                detection_results=detection_results,
                technique_ids=list(injected.keys()),
            )
            hits   = [tid for tid, d in detected.items() if d]
            misses = [tid for tid, d in detected.items() if not d]
            console.print(f"  [green]Detected ({len(hits)}): {hits}[/green]")
            console.print(f"  [red]Missed ({len(misses)}): {misses}[/red]")

            overall_precision, rule_precision = score_precision(detection_results)
            if self.inject_benign:
                prec_str = f"{overall_precision:.0%}" if overall_precision is not None else "n/a"
                console.print(f"  [yellow]Precision: {prec_str}[/yellow]")
                for n, p in rule_precision.items():
                    if p["fp"] > 0:
                        console.print(f"    [dim]FP[/dim] {n}: {p['fp']} benign hit(s) "
                                      f"(precision {p['precision']:.0%})")

            # ── 5. Registry update — track rule health, check for burns ──────
            newly_burned = self.registry.record_batch(rule_precision, round_num=round_num)
            if newly_burned:
                for rule_name in newly_burned:
                    console.print(f"  [bold red]🔥 RULE BURNED: '{rule_name}' — Red has neutralized this defense![/bold red]")
                    # Find which technique this rule covers and mark for replacement
                    from orchestrator.scorer import _infer_technique_from_rule_name
                    tid = _infer_technique_from_rule_name(rule_name)
                    if tid:
                        self.blue.notify_rule_burned(tid)
                        self.red.stop_poisoning(tid)   # job done; don't waste FP budget
                        # Record Red's success in cross-session memory
                        arena_memory.record_red_evasion(
                            self._mem, tid,
                            overrides=self.red.get_current_overrides().get(tid, {}),
                            compromised=True,
                        )

            # Rule health summary
            health = self.registry.health_summary()
            console.print(
                f"  [dim]Rule health: {health['active']} active, "
                f"{health['degraded']} degraded, "
                f"[bold red]{health['burned']} burned[/bold red][/dim]"
            )

            # ── 6. Win condition check ────────────────────────────────────────
            compromised = set(self.coverage.compromised_techniques())
            # Also add any technique whose covering rule was just burned and is evading
            for tid in newly_burned:
                from orchestrator.scorer import _infer_technique_from_rule_name
                t = _infer_technique_from_rule_name(tid)
                if t and not detected.get(t):
                    compromised.add(t)

            winner = check_win(
                coverage_pct=self.coverage.coverage_percent(),
                compromised_count=len(compromised),
                total_techniques=len(injected),
                blue_win_threshold=self.blue_win_threshold,
                red_win_threshold=self.red_win_threshold,
            )
            if winner:
                self._winner = winner
                if winner == "red":
                    console.print(f"\n[bold red]⚡ RED WINS: Compromised {len(compromised)}/{len(injected)} "
                                  f"defense vectors — defender is neutralized![/bold red]")
                else:
                    console.print(f"\n[bold green]🛡  BLUE WINS: Maintained ≥{self.blue_win_threshold:.0f}% "
                                  f"coverage under full adversarial pressure![/bold green]")

            # ── 7. Blue generates rules for misses + burned replacements ──────
            all_need_rules = set(misses)
            for tid in self.blue.pop_burned_replacement_queue():
                all_need_rules.add(tid)  # replacement for burned rule

            if all_need_rules:
                console.print("[bold blue]● BLUE AGENT — generating/replacing detection rules[/bold blue]")
                missed_events = {tid: injected.get(tid, []) for tid in all_need_rules}
                new_rules = self.blue.generate_rules_for_misses(
                    missed_techniques=missed_events,
                    round_num=round_num,
                    red_mutations=self.red.get_current_overrides(),
                )
                console.print(f"  [blue]{len(new_rules)} rule(s) generated/replaced[/blue]")
                for tid in all_need_rules:
                    self.coverage.record_rule_generated(tid)
                    parent = self.blue.get_catching_rule_for(tid)
                    child  = f"generated_r{round_num}_{tid.replace('.', '_')}"
                    self.checkpoint.save_rule_provenance(
                        round_num=round_num, technique_id=tid,
                        child_rule=child, parent_rule=parent,
                        mutation=self.red.get_current_overrides().get(tid),
                    )

            # ── 8. Red mutates for hits + starts poisoning ────────────────────
            if hits:
                console.print("[bold red]● RED AGENT — mutating + starting poison campaign[/bold red]")
                for tid in hits:
                    rule_name = catching_rules.get(tid)
                    if rule_name:
                        self.blue.record_catching_rule(tid, rule_name)
                        catching_spl = self.blue.get_catching_rule_for(tid)
                        if catching_spl:
                            self.red.receive_catching_rule(tid, catching_spl)
                            # Update cross-session memory with current overrides
                            arena_memory.record_red_evasion(
                                self._mem, tid,
                                overrides=self.red.get_current_overrides().get(tid, {}),
                            )

            # ── 9. Blue generates proactive hardening variants for mutations ──
            if hits:
                console.print("[bold blue]● BLUE AGENT — generating hardening variants (proactive)[/bold blue]")
                for tid in hits:
                    events = injected.get(tid, [])
                    if events:
                        path = self.blue.generate_hardening_variant(
                            technique_id=tid, events=events,
                            round_num=round_num,
                            red_mutations=self.red.get_current_overrides(),
                        )
                        if path:
                            console.print(f"  [blue]Hardening variant: {Path(path).stem}[/blue]")

            # ── 10. Update coverage matrix ────────────────────────────────────
            self.coverage.record_round(round_num=round_num, results=detected, compromised=compromised)

            # ── 11. Log round + Splunk summary event ──────────────────────────
            cov = self.coverage.coverage_percent()
            game_counts = self.coverage.game_state_counts()
            round_log = {
                "round": round_num,
                "detected": hits, "missed": misses,
                "catching_rules": catching_rules,
                "coverage_after_round": cov,
                "precision": overall_precision,
                "rule_precision": rule_precision,
                "rules_burned": newly_burned,
                "compromised_techniques": list(compromised),
                "game_state_counts": game_counts,
                "winner": self._winner,
            }
            self.round_logs.append(round_log)
            self.checkpoint.save_round(
                round_num=round_num, injected=injected, detected=detected,
                catching_rules=catching_rules, coverage=cov,
                mutations=self.red.get_current_overrides(),
            )

            summary_event = {
                "event_type": "purpleforge_round_summary",
                "round": round_num,
                "coverage_pct": cov,
                "detected_count": len(hits),
                "missed_count": len(misses),
                "compromised_count": len(compromised),
                "rules_burned_total": health["burned"],
                "defense_strength_pct": health["defense_strength_pct"],
                "detected_techniques": ",".join(hits),
                "missed_techniques": ",".join(misses),
                "compromised_techniques": ",".join(sorted(compromised)),
                "rules_fired": len([r for r, rows in detection_results.items() if rows]),
                "precision_pct": round(overall_precision * 100, 1) if overall_precision is not None else None,
                "game_state_uncovered": game_counts.get("uncovered", 0),
                "game_state_detected": game_counts.get("detected", 0),
                "game_state_evading": game_counts.get("evading", 0),
                "game_state_compromised": game_counts.get("compromised", 0),
                "winner": self._winner or "none",
            }
            self.hec.send_events([summary_event], index=self.index_attacks, sourcetype="purpleforge:summary")
            console.print(f"  Coverage: [bold]{cov}%[/bold] | "
                          f"Compromised: [bold red]{len(compromised)}[/bold red] | "
                          f"Defense: [bold]{health['defense_strength_pct']}%[/bold]")

            if self._winner:
                break  # decisive win — end the arena early

        # ── Final report ──────────────────────────────────────────────────────
        summary = self.coverage.summary()
        summary["rule_health"] = self.registry.health_summary()
        summary["winner"] = self._winner or "contested"
        print_final_summary(summary)

        path = save_report(summary, self.round_logs)
        console.print(f"\n[dim]Full report: {path}[/dim]")

        results_dir = str(Path(__file__).parent.parent / "results")
        nav_path = export_navigator_layer(summary, output_dir=results_dir)
        console.print(f"[dim]ATT&CK Navigator layer: {nav_path}[/dim]")
        console.print("[dim]  -> https://mitre-attack.github.io/attack-navigator/[/dim]")

        # ── Persist cross-session memory ──────────────────────────────────────
        arena_memory.save_registry(self._mem, self.registry)
        rules_gen = sum(r.rules_generated for r in self.coverage.records.values())
        arena_memory.record_session(
            self._mem,
            run_id=self.checkpoint.run_id,
            coverage_end=self.coverage.coverage_percent(),
            rules_generated=rules_gen,
            rules_burned=self.registry.health_summary()["burned"],
            compromised_techniques=self.coverage.compromised_techniques(),
            winner=self._winner or "contested",
        )
        arena_memory.save(self._mem)
        improvement = arena_memory.cross_session_improvement(self._mem)
        if improvement is not None:
            delta = f"+{improvement}%" if improvement >= 0 else f"{improvement}%"
            console.print(f"[dim]Cross-session coverage change: {delta}[/dim]")
        console.print(f"[dim]Arena memory updated: {arena_memory.MEMORY_PATH}[/dim]")

        self.checkpoint.mark_complete()
        self.checkpoint.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PurpleForge — Hacker vs Defender Adaptive Arena")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument(
        "--mode", choices=["turn", "realtime"], default="turn",
        help="turn = deterministic round-based loop (clean for demo); "
             "realtime = concurrent adaptive Red/Blue arms race",
    )
    parser.add_argument("--duration", type=float, default=90.0,
                        help="Real-time mode: wall-clock seconds to run")
    parser.add_argument("--campaign", default=None,
                        help="Replay a named kill-chain: conti_ransomware, solarwinds_apt29")
    parser.add_argument(
        "--clean", action="store_true",
        help="Delete all LLM-generated rules before starting so Blue begins with "
             "only hand-written baselines. Use before every demo run to prevent "
             "Blue from 'memorizing' Red's prior mutations across sessions.",
    )
    parser.add_argument(
        "--reset-memory", action="store_true",
        help="Also wipe the cross-session arena_memory.json (Red evasion history, "
             "rule registry state). Implies --clean. Use for a completely fresh start.",
    )
    args = parser.parse_args()

    # ── Pre-flight cleanup ────────────────────────────────────────────────────
    generated_dir = Path(__file__).parent.parent / "blue_agent" / "rules" / "generated"
    memory_path   = Path(__file__).parent.parent / "results" / "arena_memory.json"

    if args.reset_memory or args.clean:
        cleared = 0
        # Remove both the compiled .spl and the portable Sigma .yml source.
        for ext in ("*.spl", "*.yml"):
            for f in generated_dir.glob(ext):
                f.unlink()
                cleared += 1
        if cleared:
            console.print(f"[dim]--clean: removed {cleared} generated rule(s) — "
                          f"Blue starts from baselines only[/dim]")
        else:
            console.print("[dim]--clean: no generated rules to remove[/dim]")

    if args.reset_memory:
        if memory_path.exists():
            memory_path.unlink()
            console.print("[dim]--reset-memory: arena_memory.json wiped — "
                          "Red starts without prior evasion knowledge[/dim]")
        else:
            console.print("[dim]--reset-memory: no memory file found[/dim]")

    # ── Launch arena ──────────────────────────────────────────────────────────
    orch = Orchestrator(config_path=args.config, campaign_name=args.campaign)
    if args.mode == "realtime":
        from orchestrator.engine import RealTimeEngine
        RealTimeEngine(orch, duration=args.duration).run()
    else:
        orch.run()
