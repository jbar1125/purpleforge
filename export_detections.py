"""
export_detections.py — prove "integratable into any SIEM" by compiling every
Sigma detection (baseline + LLM-generated) to multiple SIEM dialects.

Usage:
    python export_detections.py            # print a portability matrix
    python export_detections.py --out results/detections_export.json

Each Sigma rule is the single source of truth; pySigma compiles it to Splunk
SPL, Elastic Lucene, and (if the backend is installed) Microsoft Sentinel KQL.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from splunk_client import sigma_compiler  # noqa: E402

SIGMA_BASELINE = Path(__file__).parent / "blue_agent" / "rules" / "sigma"
SIGMA_GENERATED = Path(__file__).parent / "blue_agent" / "rules" / "generated"


def collect_sigma_rules() -> list[tuple[str, str, str]]:
    """Return [(name, origin, yaml_text)] for every Sigma rule on disk."""
    rules = []
    for yml in sorted(SIGMA_BASELINE.glob("*.yml")):
        rules.append((yml.stem, "baseline", yml.read_text(encoding="utf-8")))
    for yml in sorted(SIGMA_GENERATED.glob("*.yml")):
        rules.append((yml.stem, "generated", yml.read_text(encoding="utf-8")))
    return rules


def main() -> None:
    parser = argparse.ArgumentParser(description="Compile Sigma detections to many SIEMs")
    parser.add_argument("--out", default=None, help="Write full export as JSON to this path")
    parser.add_argument("--index", default="arena_attacks", help="Splunk index to scope SPL to")
    args = parser.parse_args()

    if not sigma_compiler.is_available():
        print("pySigma not installed. Run: pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch")
        sys.exit(1)

    rules = collect_sigma_rules()
    if not rules:
        print("No Sigma rules found.")
        return

    export = []
    print(f"Compiling {len(rules)} Sigma detections to multiple SIEM dialects...\n")
    for name, origin, yaml_text in rules:
        report = sigma_compiler.portability_report(yaml_text, index=args.index)
        backends_ok = [k for k, v in report.items() if v and not str(v).startswith("ERROR")]
        print(f"* {name}  [{origin}]  -> {', '.join(backends_ok)}")
        print(f"    Splunk : {report.get('splunk_spl')}")
        if report.get("elastic_lucene"):
            print(f"    Elastic: {report['elastic_lucene']}")
        if report.get("sentinel_kql"):
            print(f"    Sentinel: {report['sentinel_kql']}")
        print()
        export.append({"name": name, "origin": origin, **report})

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(export, indent=2), encoding="utf-8")
        print(f"Full export written to {out_path}")


if __name__ == "__main__":
    main()
