import json
import os
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path(__file__).parent.parent / "results"


def save_report(coverage_summary: dict, round_logs: list[dict]) -> str:
    """Save a JSON report to the results/ directory and return the path."""
    RESULTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS_DIR / f"run_{ts}.json"

    report = {
        "generated_at": datetime.now().isoformat(),
        "coverage": coverage_summary,
        "rounds": round_logs,
    }

    path.write_text(json.dumps(report, indent=2))
    return str(path)


def print_final_summary(coverage_summary: dict) -> None:
    """Print a readable summary table to the terminal."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    console.print("\n[bold cyan]═══════════════════ PURPLEFORGE RESULTS ═══════════════════[/bold cyan]")
    console.print(f"\n[bold]Overall coverage: {coverage_summary['coverage_percent']}%[/bold]\n")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Technique ID", style="dim")
    table.add_column("Name")
    table.add_column("Tactic")
    table.add_column("Detected", justify="center")
    table.add_column("Evaded", justify="center")
    table.add_column("Rules Gen'd", justify="center")
    table.add_column("Status")

    status_colors = {
        "detected": "green",
        "evaded": "red",
        "uncovered": "yellow",
    }

    for tid, rec in coverage_summary["techniques"].items():
        status = rec["status"]
        color = status_colors.get(status, "white")
        table.add_row(
            tid,
            rec["name"],
            rec["tactic"],
            str(rec["detected"]),
            str(rec["evaded"]),
            str(rec["rules_generated"]),
            f"[{color}]{status}[/{color}]",
        )

    console.print(table)
