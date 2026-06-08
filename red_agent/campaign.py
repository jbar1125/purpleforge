"""
red_agent/campaign.py — replay a REAL adversary kill-chain, in order.

WHY THIS EXISTS
---------------
Firing nine techniques simultaneously is a stress test, not a story. Real
intrusions unfold as an ordered chain: initial access, then execution, then
credential access, lateral movement, persistence, and finally impact — each step
enabled by the last, separated by attacker dwell time. Defenders are judged on
whether they can catch the chain EARLY (before impact), so the order and timing
matter.

A campaign is a JSON file in red_agent/campaigns/ describing that ordered chain,
grounded in a documented incident (CISA/Mandiant advisories cited in each file).
This runner injects each step in sequence with its dwell, reusing the same
templates and HEC injector the per-technique path uses — so a campaign is just a
choreographed series of ordinary injections, fully compatible with scoring.

Dwell times are COMPRESSED for a live demo (seconds, not the real hours/days) and
each file says so. The ordering and causal chain are the faithful part.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

CAMPAIGNS_DIR = Path(__file__).parent / "campaigns"


def list_campaigns() -> list[str]:
    """Names (file stems) of all available campaigns."""
    return sorted(p.stem for p in CAMPAIGNS_DIR.glob("*.json"))


def load_campaign(name: str) -> dict:
    """Load a campaign by stem name (e.g. 'conti_ransomware'). Raises if missing."""
    path = CAMPAIGNS_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"Campaign '{name}' not found. Available: {', '.join(list_campaigns()) or '(none)'}"
        )
    return json.loads(path.read_text(encoding="utf-8"))


class CampaignRunner:
    """Inject a campaign's kill chain in order, reusing a RedAgent's templates."""

    def __init__(self, red, campaign: dict):
        self.red = red
        self.campaign = campaign

    @property
    def name(self) -> str:
        return self.campaign.get("name", "Unnamed Campaign")

    def run(self, round_num: int = 1, dwell: bool = True, log=None) -> dict[str, list[dict]]:
        """
        Inject every step in kill-chain order. Returns {technique_id: [events]},
        aggregated across steps so the scorer treats it like any other round.

        dwell: honor per-step dwell_seconds (set False to fire back-to-back, e.g.
        in automated tests). log: optional callable(str) for progress output.
        """
        steps = self.campaign.get("kill_chain", [])
        injected: dict[str, list[dict]] = {}
        say = log or (lambda _m: None)
        say(f"▶ Campaign: {self.name}  ({len(steps)} steps)")
        ref = self.campaign.get("reference")
        if ref:
            say(f"  reference: {ref}")

        for i, step in enumerate(steps, 1):
            tid = step["technique_id"]
            phase = step.get("phase", "")
            note = step.get("note", "")
            events = self.red.inject_technique(tid, round_num=round_num)
            if events:
                injected.setdefault(tid, []).extend(events)
                say(f"  [{i}/{len(steps)}] {phase:<18} {tid}  ({len(events)} events)  {note}")
            else:
                say(f"  [{i}/{len(steps)}] {phase:<18} {tid}  SKIPPED (no template loaded)")

            # Dwell between steps (not after the last one).
            d = float(step.get("dwell_seconds", 0))
            if dwell and d > 0 and i < len(steps):
                time.sleep(d)

        return injected


# ── standalone replay: python -m red_agent.campaign --campaign conti_ransomware ──
def _build_red_from_config(config_path: str):
    """Construct just the HEC client + RedAgent needed to replay a campaign."""
    import sys
    import yaml
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from splunk_client.hec import HECClient
    from llm_client.factory import get_llm_client
    from red_agent.agent import RedAgent

    cfg = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    sc = cfg["splunk"]
    hec = HECClient(host=sc["host"], port=sc["hec_port"], token=sc["hec_token"],
                    verify_ssl=sc.get("verify_ssl", False))
    llm = get_llm_client(cfg["llm"])  # only needed to satisfy RedAgent ctor; not used for replay
    red = RedAgent(hec=hec, llm=llm, index=sc["index_attacks"],
                   technique_ids=cfg["arena"]["techniques"])
    return red


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Replay an adversary kill-chain into Splunk")
    parser.add_argument("--campaign", help="Campaign name (file stem)")
    parser.add_argument("--list", action="store_true", help="List available campaigns and exit")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--no-dwell", action="store_true", help="Fire steps back-to-back")
    args = parser.parse_args()

    if args.list or not args.campaign:
        print("Available campaigns:")
        for name in list_campaigns():
            c = load_campaign(name)
            print(f"  {name:<22} — {c.get('name','')} ({len(c.get('kill_chain', []))} steps)")
        return

    campaign = load_campaign(args.campaign)
    red = _build_red_from_config(args.config)
    runner = CampaignRunner(red, campaign)
    injected = runner.run(round_num=1, dwell=not args.no_dwell, log=print)
    total = sum(len(v) for v in injected.values())
    print(f"\nInjected {total} events across {len(injected)} techniques into Splunk.")


if __name__ == "__main__":
    main()
