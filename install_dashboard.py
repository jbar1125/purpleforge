"""
Install the PurpleForge dashboard into Splunk as a saved dashboard.

Usage:
    python install_dashboard.py

This creates a dashboard named 'purpleforge' in the 'search' app.
Access it at: http://localhost:8000/en-US/app/search/purpleforge
"""

import sys
import requests
import urllib3
from pathlib import Path

urllib3.disable_warnings()
sys.path.insert(0, str(Path(__file__).parent))

import yaml

DASHBOARD_XML = Path(__file__).parent / "dashboard" / "purpleforge_dashboard.xml"
DASHBOARD_NAME = "purpleforge"


def load_config():
    path = Path(__file__).parent / "config.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


def install_dashboard(cfg: dict) -> bool:
    sc = cfg["splunk"]
    base = f"https://{sc['host']}:{sc['rest_port']}"
    auth = (sc["username"], sc["password"])
    verify = sc.get("verify_ssl", False)

    xml_content = DASHBOARD_XML.read_text(encoding="utf-8")

    # Check if dashboard already exists
    check = requests.get(
        f"{base}/servicesNS/nobody/search/data/ui/views/{DASHBOARD_NAME}",
        auth=auth, verify=verify, params={"output_mode": "json"}, timeout=10
    )

    if check.status_code == 200:
        # Update existing
        resp = requests.post(
            f"{base}/servicesNS/nobody/search/data/ui/views/{DASHBOARD_NAME}",
            auth=auth,
            data={"eai:data": xml_content, "output_mode": "json"},
            verify=verify,
            timeout=15,
        )
        action = "updated"
    else:
        # Create new
        resp = requests.post(
            f"{base}/servicesNS/nobody/search/data/ui/views",
            auth=auth,
            data={"name": DASHBOARD_NAME, "eai:data": xml_content, "output_mode": "json"},
            verify=verify,
            timeout=15,
        )
        action = "created"

    if resp.ok:
        print(f"Dashboard {action} successfully.")
        print(f"  URL: http://{sc['host']}:8000/en-US/app/search/{DASHBOARD_NAME}")
        return True
    else:
        print(f"Failed to install dashboard: {resp.status_code} — {resp.text[:300]}")
        return False


if __name__ == "__main__":
    cfg = load_config()
    success = install_dashboard(cfg)
    sys.exit(0 if success else 1)
