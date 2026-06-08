"""
blue_agent/edr_client.py — EDR ground truth: the oracle that reveals Blue's blind spots.

WHY THIS EXISTS  (Track 5, level 3 — extends the mutation-inference "moat")
--------------------------------------------------------------------------
mutation_inferencer.py (L1) infers what an attacker changed using only the data Blue can
see in Splunk. But there's a scarier evasion it can't reach: the attack that produces NO
Splunk event at all. If Red disables a log source, runs in memory, or hits a gap in your
forwarder coverage, Blue's logs are silent — and silence looks identical to safety.

An EDR (CrowdStrike Falcon, Microsoft Defender for Endpoint) watches the endpoint at the
kernel/sensor level, independent of your logging pipeline. It is a SECOND, authoritative
witness to what actually executed. Cross-checking Blue's log-based detections against the
EDR's ground truth turns "I saw nothing" into a measurable, actionable fact:

    CONFIRMED   — technique seen by BOTH the EDR and Blue's Splunk rules  → Blue is working
    BLIND SPOT  — technique seen by the EDR but NOT by Blue's Splunk rules → real miss, the
                  most dangerous gap: a real attack your detections are blind to
    LOG-ONLY    — Blue's rules fired but the EDR saw nothing → likely FP, or EDR gap

`corroborate()` computes exactly that split. Blind spots become the highest-priority targets
for new-rule generation — Blue learns what it CAN'T see from a sensor that can.

EXTERNAL SETUP REQUIRED (a human must provision this)
-----------------------------------------------------
  * A CrowdStrike Falcon tenant (or trial) with an API client:
      Falcon console → Support → API Clients & Keys → create client with scope
      "Detections/Alerts: READ". Note the client_id + client_secret + cloud base URL
      (e.g. https://api.crowdstrike.com or https://api.us-2.crowdstrike.com).
  * Falcon sensors deployed on the SAME lab hosts as the Caldera agents, so the EDR and
    Splunk observe the same attacks. (Defender for Endpoint works too — its alert schema
    differs; normalize_crowdstrike_detections covers the Falcon detection-summary schema.)
No new dependency — uses `requests`.
"""
from __future__ import annotations

from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EDRError(RuntimeError):
    """CrowdStrike API / auth failure."""


class EDRClient:
    """
    Minimal CrowdStrike Falcon client: OAuth2, then pull recent detections and normalize
    them into ground-truth records. Only the read paths Blue needs — no write scopes.

    Args:
        base_url:      Falcon cloud API base, e.g. "https://api.crowdstrike.com".
        client_id:     API client id.
        client_secret: API client secret.
        timeout:       per-request timeout (seconds).
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str, timeout: float = 30.0):
        self.base = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self._token: str | None = None
        self.session = requests.Session()

    # ── auth ────────────────────────────────────────────────────────────────────
    def _authenticate(self) -> str:
        try:
            resp = self.session.post(
                f"{self.base}/oauth2/token",
                data={"client_id": self.client_id, "client_secret": self.client_secret},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise EDRError(f"token request failed to connect: {e}") from e
        if resp.status_code >= 400:
            raise EDRError(f"oauth2/token -> HTTP {resp.status_code}: {resp.text[:200]}")
        token = resp.json().get("access_token")
        if not token:
            raise EDRError("oauth2/token returned no access_token")
        self._token = token
        return token

    def _headers(self) -> dict:
        if not self._token:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    def health(self) -> bool:
        try:
            self._authenticate()
            return True
        except EDRError:
            return False

    # ── detections ──────────────────────────────────────────────────────────────
    def _get(self, path: str, params: dict | None = None) -> Any:
        try:
            resp = self.session.get(f"{self.base}{path}", headers=self._headers(),
                                    params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise EDRError(f"GET {path} failed: {e}") from e
        if resp.status_code >= 400:
            raise EDRError(f"GET {path} -> HTTP {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    def _post(self, path: str, body: dict) -> Any:
        try:
            resp = self.session.post(f"{self.base}{path}", headers=self._headers(),
                                     json=body, timeout=self.timeout)
        except requests.RequestException as e:
            raise EDRError(f"POST {path} failed: {e}") from e
        if resp.status_code >= 400:
            raise EDRError(f"POST {path} -> HTTP {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    def get_detections(self, since_filter: str = "", limit: int = 200) -> list[dict]:
        """
        Pull recent detection summaries. `since_filter` is a Falcon FQL filter, e.g.
        `created_timestamp:>'2026-06-08T00:00:00Z'`. Returns the raw `resources` list.

        Two-step Falcon pattern: query for IDs, then fetch entity summaries by ID.
        """
        params = {"limit": limit, "sort": "created_timestamp.desc"}
        if since_filter:
            params["filter"] = since_filter
        ids = (self._get("/detects/queries/detects/v1", params).get("resources")) or []
        if not ids:
            return []
        summaries = self._post("/detects/entities/summaries/GET/v1", {"ids": ids})
        return summaries.get("resources", []) or []

    def ground_truth(self, since_filter: str = "", limit: int = 200) -> list[dict]:
        """High-level: recent detections normalized to ground-truth execution records."""
        return normalize_crowdstrike_detections({"resources": self.get_detections(since_filter, limit)})


# ── normalization + corroboration (pure functions — offline-testable) ────────────
def _first(d: dict, *keys: str, default=None):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _base_technique(tid: str) -> str:
    """'T1003.001' -> 'T1003'. Sub-technique-insensitive matching avoids false blind spots
    when the EDR reports a parent technique and Blue's rule tags the sub-technique (or vice
    versa)."""
    return str(tid).split(".")[0].upper()


def normalize_crowdstrike_detections(payload: dict) -> list[dict]:
    """
    Flatten a CrowdStrike detection-summaries payload into one ground-truth record per
    ATT&CK behavior:

        {technique_id, technique_name, tactic, host, process, command, severity,
         timestamp, detection_id, arena_technique, arena_source="edr"}

    A single detection can contain multiple behaviors (one per technique); each becomes its
    own record. Behaviors with no technique_id are skipped. Defensive about field names.
    """
    if not isinstance(payload, dict):
        return []
    out: list[dict] = []
    for det in payload.get("resources", []) or []:
        device = det.get("device", {}) or {}
        host = _first(device, "hostname", "device_id", default="")
        det_id = _first(det, "detection_id", "composite_id", "id", default="")
        det_sev = _first(det, "max_severity_displayname", "max_severity", default="")
        for beh in det.get("behaviors", []) or []:
            technique_id = _first(beh, "technique_id", default="")
            if not technique_id:
                continue
            out.append({
                "technique_id": technique_id,
                "technique_name": _first(beh, "technique", "technique_name", default=""),
                "tactic": _first(beh, "tactic", "tactic_name", default=""),
                "host": host,
                "process": _first(beh, "filename", "process_name", default=""),
                "command": _first(beh, "cmdline", "command_line", default=""),
                "severity": _first(beh, "severity", default=det_sev),
                "timestamp": _first(beh, "timestamp", default=_first(det, "created_timestamp", default="")),
                "detection_id": det_id,
                "arena_technique": technique_id,
                "arena_source": "edr",
            })
    return out


def corroborate(edr_truth: list[dict], splunk_detected_tids) -> dict:
    """
    Cross-check the EDR's ground truth against the techniques Blue's Splunk rules detected.

    Matching is at BASE-technique granularity (T1003.001 ≡ T1003) so a sub-technique
    mismatch doesn't masquerade as a blind spot. Returns:

        {
          confirmed:   [tid, ...],   # EDR saw it AND Blue's logs caught it
          blind_spots: [tid, ...],   # EDR saw it, Blue's logs did NOT  ← generate rules here
          log_only:    [tid, ...],   # Blue fired, EDR saw nothing      ← likely FP / EDR gap
          edr_coverage_pct: float,   # % of EDR-observed techniques Blue also caught
        }

    Pure function: the caller supplies `splunk_detected_tids` (a set/list of technique IDs)
    from the coverage matrix, so this needs neither Splunk nor a live EDR to test.
    """
    edr_full = {e["technique_id"] for e in edr_truth if e.get("technique_id")}
    edr_bases = {_base_technique(t) for t in edr_full}
    splunk_bases = {_base_technique(t) for t in (splunk_detected_tids or [])}

    confirmed = sorted(t for t in edr_full if _base_technique(t) in splunk_bases)
    blind_spots = sorted(t for t in edr_full if _base_technique(t) not in splunk_bases)
    log_only = sorted(t for t in (splunk_detected_tids or [])
                      if _base_technique(t) not in edr_bases)
    coverage = round(len(confirmed) / len(edr_full) * 100, 1) if edr_full else 0.0
    return {
        "confirmed": confirmed,
        "blind_spots": blind_spots,
        "log_only": log_only,
        "edr_coverage_pct": coverage,
    }
