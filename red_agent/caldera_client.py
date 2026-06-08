"""
red_agent/caldera_client.py — drive REAL adversary emulation via MITRE Caldera.

WHY THIS EXISTS
---------------
In the arena, Red *synthesizes* Windows event logs and ships them straight into Splunk
over HEC (see injector.py). That's perfect for a self-contained demo, but a judge's first
question is fair: "those are fabricated logs — would your Blue agent catch a REAL attack?"

This module answers that. MITRE Caldera (https://github.com/mitre/caldera) is MITRE's own
open-source adversary-emulation platform. It runs real ATT&CK techniques (real `mimikatz`,
real `schtasks`, real LSASS access) on real agents you deploy to lab hosts. Those hosts run
Sysmon + a Splunk Universal Forwarder, so the telemetry lands in Splunk the same way a real
endpoint's would — through the normal logging pipeline, NOT injected.

So the data flow changes shape:

    ARENA (synthetic):   Red → fabricate events → HEC → Splunk → Blue
    PRODUCTION (real):   Red → Caldera C2 → execute on host → Sysmon/EDR
                             → Universal Forwarder → Splunk → Blue
                         CalderaClient ───────────────────────────────┘
                         (returns ground-truth: what ran, when, where)

The orchestrator no longer learns the attack's "answer key" from the injector — it learns it
from Caldera's operation report (this client). Each executed ability is a ground-truth record
{technique_id, host, timestamp, command, status}; the scorer correlates Blue's detections in
Splunk against THOSE records instead of against fabricated events. Everything downstream
(scorer, coverage matrix, mutation inference) is unchanged because we normalize Caldera links
into the same arena_technique / arena_round shape the rest of the pipeline already speaks.

EXTERNAL SETUP REQUIRED (see the run-book at the bottom of this file)
--------------------------------------------------------------------
  1. A running Caldera server (`python server.py --insecure` on the C2 box).
  2. At least one Caldera agent (Sandcat/54ndc47) deployed on a Windows lab host.
  3. That host running Sysmon + a Splunk Universal Forwarder → index=arena_attacks.
This client talks ONLY to the Caldera REST API; it does not need Splunk credentials.

API: targets the Caldera v2 REST API (Caldera 4.x/5.x), authenticated with the `KEY` header.
No new dependency — uses `requests`, already required by the HEC/search clients.
"""
from __future__ import annotations

import base64
import binascii
import time
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Well-known default IDs shipped with Caldera. Used only as a fallback when we can't
# resolve a planner/source by name from the live server.
_DEFAULT_PLANNER_ID = "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"   # "atomic"
_DEFAULT_SOURCE_ID = "ed32b9c3-9593-4c33-b0db-e2007315096b"    # "basic"

# Caldera link status codes (status == 0 means the command ran successfully).
_STATUS_SUCCESS = 0


class CalderaError(RuntimeError):
    """Any Caldera API / operation failure. Callers can catch this specifically."""


class CalderaClient:
    """
    Thin, defensively-coded wrapper over the Caldera v2 REST API.

    Args:
        base_url:    e.g. "http://10.0.0.50:8888" (the Caldera server).
        api_key:     the red API key from Caldera's conf/local.yml (`api_key_red`).
                     Sent as the `KEY` header on every request.
        verify_ssl:  TLS verification (Caldera dev servers are usually plain HTTP).
        timeout:     per-request timeout in seconds.
    """

    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = False, timeout: float = 30.0):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.verify = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({"KEY": api_key, "Content-Type": "application/json"})

    # ── low-level HTTP ──────────────────────────────────────────────────────────
    def _request(self, method: str, path: str, **kw) -> Any:
        url = f"{self.base}{path}"
        try:
            resp = self.session.request(
                method, url, verify=self.verify, timeout=self.timeout, **kw
            )
        except requests.RequestException as e:
            raise CalderaError(f"{method} {path} failed to connect: {e}") from e
        if resp.status_code >= 400:
            raise CalderaError(f"{method} {path} -> HTTP {resp.status_code}: {resp.text[:300]}")
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    def _get(self, path: str) -> Any:
        return self._request("GET", path)

    def _post(self, path: str, body: dict | None = None) -> Any:
        return self._request("POST", path, json=body or {})

    def _patch(self, path: str, body: dict) -> Any:
        return self._request("PATCH", path, json=body)

    # ── connectivity / discovery ────────────────────────────────────────────────
    def health(self) -> bool:
        """True if the server answers and the API key is accepted."""
        try:
            self._get("/api/v2/agents")
            return True
        except CalderaError:
            return False

    def list_agents(self) -> list[dict]:
        """Deployed agents. Each has paw, host, platform, group, last_seen, trusted."""
        return self._get("/api/v2/agents") or []

    def list_adversaries(self) -> list[dict]:
        """Adversary profiles (ordered chains of abilities mapped to ATT&CK)."""
        return self._get("/api/v2/adversaries") or []

    def list_abilities(self) -> list[dict]:
        """All abilities. Each carries technique_id / technique_name / tactic."""
        return self._get("/api/v2/abilities") or []

    def list_planners(self) -> list[dict]:
        return self._get("/api/v2/planners") or []

    def list_sources(self) -> list[dict]:
        return self._get("/api/v2/sources") or []

    def abilities_for_techniques(self, technique_ids: list[str]) -> dict[str, list[dict]]:
        """
        Map the project's technique list (e.g. ["T1003.001", "T1053.005", ...]) to the
        Caldera abilities that emulate them — a quick coverage check before you build an
        adversary profile. Returns {technique_id: [ability, ...]} (empty list = no coverage).
        """
        wanted = {t.upper() for t in technique_ids}
        out: dict[str, list[dict]] = {t: [] for t in technique_ids}
        for ab in self.list_abilities():
            tid = str(ab.get("technique_id", "")).upper()
            if tid in wanted:
                # find the original-cased key to store under
                for t in technique_ids:
                    if t.upper() == tid:
                        out[t].append(ab)
        return out

    # ── operations ──────────────────────────────────────────────────────────────
    def _resolve_id(self, items: list[dict], name: str, id_key: str, fallback: str) -> str:
        for it in items:
            if str(it.get("name", "")).lower() == name.lower():
                return it.get(id_key) or it.get("id") or fallback
        return fallback

    def start_operation(
        self,
        adversary_id: str,
        name: str | None = None,
        group: str = "",
        planner_name: str = "atomic",
        source_name: str = "basic",
        obfuscator: str = "plain-text",
        auto_close: bool = True,
    ) -> dict:
        """
        Launch an operation: run an adversary profile against agents in `group`
        (empty group = all agents). Returns the created operation object (has `id`).

        planner_name / source_name are resolved to IDs against the live server, so this
        keeps working across Caldera versions even when the default UUIDs change.
        """
        planner_id = self._resolve_id(self.list_planners(), planner_name, "id", _DEFAULT_PLANNER_ID)
        source_id = self._resolve_id(self.list_sources(), source_name, "id", _DEFAULT_SOURCE_ID)
        body = {
            "name": name or f"purpleforge-{int(time.time())}",
            "adversary": {"adversary_id": adversary_id},
            "planner": {"id": planner_id},
            "source": {"id": source_id},
            "group": group,
            "auto_close": auto_close,
            "state": "running",
            "obfuscator": obfuscator,
            "visibility": 51,
        }
        op = self._post("/api/v2/operations", body)
        if not isinstance(op, dict) or "id" not in op:
            raise CalderaError(f"operation create returned no id: {op}")
        return op

    def get_operation(self, operation_id: str) -> dict:
        return self._get(f"/api/v2/operations/{operation_id}") or {}

    def set_operation_state(self, operation_id: str, state: str) -> dict:
        """state ∈ {running, paused, finished, cleanup}."""
        return self._patch(f"/api/v2/operations/{operation_id}", {"state": state})

    def operation_report(self, operation_id: str, agent_output: bool = True) -> dict:
        """
        Full operation report — the authoritative record of every executed ability
        (command, status, timestamps, ATT&CK mapping, and optionally agent output).
        """
        return self._post(
            f"/api/v2/operations/{operation_id}/report",
            {"enable_agent_output": agent_output},
        ) or {}

    def wait_for_operation(
        self, operation_id: str, poll_seconds: float = 5.0, max_wait: float = 600.0
    ) -> dict:
        """
        Block until the operation reaches a terminal state or max_wait elapses.
        Returns the final operation object. Raises CalderaError on timeout.
        """
        deadline = time.time() + max_wait
        terminal = {"finished", "cleanup", "out_of_time"}
        while time.time() < deadline:
            op = self.get_operation(operation_id)
            state = str(op.get("state", "")).lower()
            if state in terminal:
                return op
            time.sleep(poll_seconds)
        raise CalderaError(f"operation {operation_id} did not finish within {max_wait}s")

    # ── high-level driver ───────────────────────────────────────────────────────
    def run_adversary(
        self,
        adversary_id: str,
        round_num: int = 0,
        group: str = "",
        name: str | None = None,
        wait: bool = True,
        poll_seconds: float = 5.0,
        max_wait: float = 600.0,
    ) -> dict:
        """
        One-call adversary emulation: start the operation, (optionally) wait for it to
        finish, then return BOTH the raw report and the normalized ground-truth records
        the scorer consumes:

            {
              "operation_id": "...",
              "state": "finished",
              "executions": [ {technique_id, host, timestamp, command, status, ...}, ... ],
              "report": { ...raw Caldera report... },
            }

        `executions` is the attack "answer key": correlate Blue's Splunk detections against
        these instead of against fabricated HEC events.
        """
        op = self.start_operation(adversary_id, name=name, group=group)
        op_id = op["id"]
        if wait:
            self.wait_for_operation(op_id, poll_seconds=poll_seconds, max_wait=max_wait)
        report = self.operation_report(op_id)
        return {
            "operation_id": op_id,
            "state": str(self.get_operation(op_id).get("state", "unknown")),
            "executions": normalize_operation_report(report, round_num=round_num),
            "report": report,
        }


# ── normalization (pure function — offline-testable, no live server needed) ──────
def _maybe_b64_decode(value: str) -> str:
    """Caldera reports a link's command base64-encoded. Best-effort decode."""
    if not isinstance(value, str) or not value:
        return value
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return value
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return value
    # Only treat it as decoded text if it round-trips to printable content.
    return decoded if decoded.isprintable() or "\n" in decoded else value


def _first(d: dict, *keys: str, default=None):
    """Return the first present, non-None value among keys (versions differ on names)."""
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def normalize_operation_report(report: dict, round_num: int = 0) -> list[dict]:
    """
    Turn a Caldera operation report into a flat list of ground-truth execution records,
    one per executed ability (link). Shaped to match the arena's event tagging so the
    existing scorer/coverage code correlates Caldera runs exactly like HEC injections:

        {
          technique_id, technique_name, tactic, ability_name,
          command, status, success(bool), host, paw, pid, timestamp, output,
          arena_round, arena_technique, arena_source="caldera",
        }

    Defensive about field names because the report schema has drifted across Caldera
    releases. Skips links that carry no technique mapping.
    """
    if not isinstance(report, dict):
        return []

    # Build paw -> host from the report's host_group, so each step gets a hostname.
    paw_host: dict[str, str] = {}
    for agent in report.get("host_group", []) or []:
        paw = agent.get("paw")
        if paw:
            paw_host[paw] = _first(agent, "host", "display_name", default=paw)

    executions: list[dict] = []
    steps_by_paw = report.get("steps", {}) or {}
    for paw, block in steps_by_paw.items():
        for step in (block or {}).get("steps", []) or []:
            attack = step.get("attack", {}) or {}
            technique_id = _first(attack, "technique_id", "technique", default="")
            if not technique_id:
                continue
            status = _first(step, "status", default=None)
            executions.append({
                "technique_id": technique_id,
                "technique_name": _first(attack, "technique_name", default=""),
                "tactic": _first(attack, "tactic", default=""),
                "ability_name": _first(step, "name", "ability_name", default=""),
                "command": _maybe_b64_decode(_first(step, "command", default="")),
                "status": status,
                "success": status == _STATUS_SUCCESS,
                "host": paw_host.get(paw, paw),
                "paw": paw,
                "pid": _first(step, "pid", default=None),
                "timestamp": _first(
                    step, "finished_timestamp", "collected_timestamp",
                    "delegated_timestamp", "run", default=""),
                "output": _first(step, "output", default=""),
                # Arena-compatible tags so downstream scoring is unchanged.
                "arena_round": round_num,
                "arena_technique": technique_id,
                "arena_source": "caldera",
            })
    return executions


# ──────────────────────────────────────────────────────────────────────────────
# RUN-BOOK (external setup — this is the part a human must provision)
# ──────────────────────────────────────────────────────────────────────────────
# 1. Stand up Caldera (C2 server, on a Linux box or VM):
#       git clone https://github.com/mitre/caldera.git --recursive
#       cd caldera && pip install -r requirements.txt
#       python server.py --insecure --build
#    Web UI: http://<caldera-host>:8888  (default creds red/admin in conf/local.yml).
#    Copy the `api_key_red` value from conf/local.yml — that's the api_key for this client.
#
# 2. Deploy an agent (Sandcat) on a Windows LAB host (never production):
#    In the UI: Agents → Deploy an agent → Sandcat (Windows) → copy the PowerShell
#    one-liner → run it on the lab host. The agent calls back and appears in list_agents().
#
# 3. Ship that host's telemetry to Splunk (so Blue can see the real attack):
#    - Install Sysmon with a config (SwiftOnSecurity/Olaf Hartong) on the lab host.
#    - Install a Splunk Universal Forwarder; monitor WinEventLog:Security,
#      WinEventLog:System, and Microsoft-Windows-Sysmon/Operational; route to
#      index=arena_attacks on your Splunk indexer.
#
# 4. Build an adversary profile in Caldera that chains the techniques you care about
#    (T1110.001, T1021.001, T1053.005, T1136.001, T1003.001, T1547.001). Note its
#    adversary_id from the UI or list_adversaries().
#
# 5. Drive it from Python:
#       c = CalderaClient("http://<caldera-host>:8888", api_key="<api_key_red>")
#       assert c.health()
#       print(c.abilities_for_techniques(["T1003.001", "T1053.005"]))   # coverage check
#       result = c.run_adversary(adversary_id="<id>", round_num=1, group="red")
#       for ex in result["executions"]:
#           print(ex["technique_id"], ex["host"], ex["success"], ex["timestamp"])
#    Then point the scorer at result["executions"] as the ground-truth answer key.
