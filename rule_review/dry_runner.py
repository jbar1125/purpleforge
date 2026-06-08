"""
rule_review/dry_runner.py — measure a candidate rule's blast radius before deploy.

Two questions an analyst asks of any new detection:
  1. Does it actually fire on the attack it was written for?      (true positives)
  2. How much else does it light up?                              (false positives)

Against a KNOWN-BENIGN window every hit is a suspected false positive — that's the
blast-radius estimate. In the arena we can do better: events Red injected as noise
are tagged arena_technique="benign", so we can count labelled FPs exactly.

Takes any object with a `run_search(spl, earliest, latest)` method (the project's
SearchClient satisfies this), so it's unit-testable with a fake.
"""
from __future__ import annotations


class DryRunner:
    def __init__(self, search_client, benign_marker_field: str = "arena_technique",
                 benign_marker_value: str = "benign"):
        self.search = search_client
        self.marker_field = benign_marker_field
        self.marker_value = benign_marker_value

    def run(self, spl: str, earliest: str = "-24h", latest: str = "now") -> dict:
        """
        Run the rule over a window and summarize hits. If the rows carry the benign
        marker we count labelled FPs; otherwise total_hits IS the blast radius.
        """
        try:
            rows = self.search.run_search(spl, earliest=earliest, latest=latest)
        except Exception as e:  # never let a dry-run crash the review flow
            return {"total_hits": None, "fp_estimate": None, "fp_rate": None,
                    "window": f"{earliest}..{latest}", "error": str(e)[:200]}

        total = len(rows)
        labelled_fp = sum(1 for r in rows if str(r.get(self.marker_field)) == self.marker_value)
        # If nothing is labelled benign, fall back to "all hits are suspected FPs"
        fp_estimate = labelled_fp if labelled_fp else 0
        return {
            "total_hits": total,
            "fp_estimate": fp_estimate,
            "fp_rate": round(fp_estimate / total, 3) if total else 0.0,
            "window": f"{earliest}..{latest}",
        }

    def estimate_false_positives(self, spl: str, benign_earliest: str, benign_latest: str) -> dict:
        """
        Production blast-radius: run against a window you believe is clean. EVERY hit
        there is a suspected false positive.
        """
        try:
            rows = self.search.run_search(spl, earliest=benign_earliest, latest=benign_latest)
        except Exception as e:
            return {"suspected_fp": None, "window": f"{benign_earliest}..{benign_latest}", "error": str(e)[:200]}
        return {"suspected_fp": len(rows), "window": f"{benign_earliest}..{benign_latest}"}
