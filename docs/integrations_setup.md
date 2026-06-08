# Production Integrations Setup — Caldera (real attacks) + CrowdStrike EDR (blind spots)

These two integrations are **optional** and **default-OFF**. The arena runs fully
self-contained without them (synthetic HEC injection + Splunk-only detection). Turn
them on to replace synthetic attacks with **real adversary emulation** (Caldera) and to
gain a second, authoritative witness that reveals what Blue's logs **can't see** (EDR).

> **Safety first.** Run all of this on **isolated lab hosts / VMs only — never production.**
> You are deploying a real C2 agent and running real ATT&CK commands. All credentials go in
> `config.yaml`, which is gitignored (verified: `.gitignore` line 1) — never commit it.

When you finish each part, `python setup_verify.py` will check it for you. The checks only
run when you set `enabled: true` in the matching config stanza, so a half-finished setup
never breaks the verifier.

---
---

# Part A — MITRE Caldera (Track 1: real attack data)

**What you get:** Caldera runs real ATT&CK commands on a lab host. That host's Sysmon +
Windows Event Log telemetry flows into `index=arena_attacks` the normal way (Universal
Forwarder), so Blue detects **real** attacks instead of synthetic JSON. Caldera's operation
report is the **ground-truth answer key** the scorer grades against —
`red_agent/caldera_client.py::normalize_operation_report()` reshapes it into the exact
`arena_technique` / `arena_round` records the scorer already consumes.

```
Caldera C2 ──drives──▶ Sandcat agent on LAB host ──runs──▶ real ATT&CK commands
                                  │
                          Sysmon + WinEventLog
                                  │
                      Splunk Universal Forwarder
                                  │
                                  ▼
                        index=arena_attacks ──▶ Blue (Sigma rules)
```

## A1. Stand up the Caldera server (Linux box or VM)

Native:
```bash
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip install -r requirements.txt
python server.py --insecure --build      # first build pulls UI deps; takes a few minutes
```

Or Docker:
```bash
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
docker build --build-arg WIN_BUILD=true . -t caldera:latest
docker run -p 8888:8888 caldera:latest
```

- Web UI: `http://<caldera-host>:8888`
- Default credentials are in `conf/local.yml` (created on first run): user `red`, the
  password is the `users.red` value.
- **Copy the `api_key_red` value from `conf/local.yml`** — that is the `api_key` for this client.

## A2. Deploy a Sandcat agent on a Windows LAB host

1. In the Caldera UI: **Agents → Deploy an agent → Sandcat → Windows**.
2. Set the agent's callback to your server's reachable address (`http://<caldera-host>:8888`).
3. Copy the generated PowerShell one-liner and run it (as Administrator) **on the lab host**.
4. The agent calls back within seconds and appears under **Agents** (and in `list_agents()`).
   Note its `group` (default `red`) — you'll put that in config.

## A3. Ship that host's telemetry to Splunk

The agent runs the attack; **Splunk only sees it if the host forwards its logs.**

1. **Install Sysmon** (Sysinternals) on the lab host with a good config:
   ```powershell
   # download Sysmon + a community config (SwiftOnSecurity or Olaf Hartong)
   sysmon.exe -accepteula -i sysmonconfig.xml
   ```
2. **Install a Splunk Universal Forwarder** on the lab host, pointed at your indexer:
   ```powershell
   "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" add forward-server <splunk-host>:9997
   ```
   (Enable receiving on the indexer once: **Settings → Forwarding and receiving → Configure
   receiving → New → 9997**.)
3. **Route the right sources into `arena_attacks`.** Create
   `…\SplunkUniversalForwarder\etc\system\local\inputs.conf`:
   ```ini
   [WinEventLog://Security]
   disabled = 0
   index = arena_attacks

   [WinEventLog://System]
   disabled = 0
   index = arena_attacks

   [WinEventLog://Microsoft-Windows-Sysmon/Operational]
   disabled = 0
   renderXml = true
   index = arena_attacks
   ```
   Restart the forwarder. Confirm in Splunk: `index=arena_attacks sourcetype=*Sysmon* | head 5`.

   > These are the **same sourcetypes** the synthetic generator uses
   > (`WinEventLog:Security`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`), so every
   > existing Sigma rule applies unchanged.

## A4. Build an adversary profile

1. UI: **Adversaries → + (new profile)**. Name it e.g. `PurpleForge Arena`.
2. Add abilities covering the arena techniques you want to emulate — T1110.001, T1021.001,
   T1053.005, T1136.001, T1003.001, T1547.001. (Use the search box; Caldera's stock ability
   library covers all of these on Windows.)
3. Save and **copy the profile's `adversary_id`** (shown in the URL / profile header, also via
   `list_adversaries()`).

Sanity-check coverage from Python before running:
```python
from red_agent.caldera_client import CalderaClient
c = CalderaClient("http://<caldera-host>:8888", api_key="<api_key_red>")
print(c.abilities_for_techniques(["T1003.001", "T1053.005"]))   # which abilities map to each
```

## A5. Fill in `config.yaml`

```yaml
caldera:
  enabled: true
  base_url: "http://<caldera-host>:8888"
  api_key: "<api_key_red from conf/local.yml>"
  adversary_id: "<adversary_id from A4>"
  group: "red"            # "" = all agents
  verify_ssl: false
```

## A6. Verify + run

```bash
python setup_verify.py      # adds a "MITRE Caldera (optional)" row — expect ✓ + agent count
```

Drive an operation and hand the result to the scorer as ground truth:
```python
from red_agent.caldera_client import CalderaClient
c = CalderaClient("http://<caldera-host>:8888", api_key="<api_key_red>")
result = c.run_adversary(adversary_id="<id>", round_num=1, group="red")
for ex in result["executions"]:      # already arena-shaped: arena_technique / arena_round / success
    print(ex["technique_id"], ex["host"], ex["success"], ex["timestamp"])
```
The `executions` list is the answer key: each entry is a technique Caldera actually executed,
so the scorer grades Blue's Splunk detections against **what really ran**, not what we injected.

---
---

# Part B — CrowdStrike Falcon EDR (Track 5, level 3: blind-spot detection)

**What you get:** an independent, kernel-level witness to what executed on the endpoint —
separate from your logging pipeline. Cross-checking Falcon's ground truth against Blue's
Splunk detections (`blue_agent/edr_client.py::corroborate()`) splits every technique into:

| Bucket          | Meaning                                              | Action |
|-----------------|------------------------------------------------------|--------|
| **CONFIRMED**   | EDR saw it **and** Blue's Splunk rules caught it     | Blue is working |
| **BLIND SPOT**  | EDR saw it but Blue's rules did **not**              | **Real miss — highest-priority rule-gen target** |
| **LOG-ONLY**    | Blue's rules fired but EDR saw nothing               | Likely false positive / EDR gap |

Blind spots are the scary case (a real attack your detections can't see) — they become the
top of Blue's proactive rule-generation queue.

## B1. Get a Falcon tenant

CrowdStrike offers a time-limited **Falcon Go** trial (sign up at crowdstrike.com → Free
Trial), or use an existing tenant. You need console access to create an API client and to
download a sensor.

## B2. Create an API client (read-only)

1. Falcon console: **Support and resources → API Clients and Keys → Create API client**.
2. Scope: **Detections: Read** (on newer tenants this is **Alerts: Read**). Read-only — Blue
   never writes.
3. Note the three values:
   - **Client ID**
   - **Client Secret** (shown once — copy it now)
   - **Cloud base URL** for your region:
     - US-1 → `https://api.crowdstrike.com`
     - US-2 → `https://api.us-2.crowdstrike.com`
     - EU-1 → `https://api.eu-1.crowdstrike.com`
     - Gov  → `https://api.laggar.gcw.crowdstrike.com`

## B3. Deploy sensors on the SAME lab hosts as the Caldera agents

So the EDR and Splunk observe the *same* attacks:
1. Falcon console: **Host setup and management → Sensor downloads** — download the Windows
   sensor and note your **CID** (customer ID checksum).
2. Install on each lab host:
   ```powershell
   WindowsSensor.exe /install /quiet /norestart CID=<your-CID>
   ```
3. Confirm the host appears under **Host management** as "Normal" / "RFM: No".

> Defender for Endpoint works too, but its alert schema differs;
> `normalize_crowdstrike_detections()` targets the Falcon detection-summary schema. Swapping
> in Defender means writing a `normalize_defender_alerts()` with the same output shape.

## B4. Fill in `config.yaml`

```yaml
edr:
  enabled: true
  base_url: "https://api.crowdstrike.com"     # your region from B2
  client_id: "<Falcon client id>"
  client_secret: "<Falcon client secret>"
```

## B5. Verify + use

```bash
python setup_verify.py      # adds a "CrowdStrike EDR (optional)" row
```
The check does OAuth **and** pulls one detection — so a ✓ proves both auth *and* the
Detections:Read scope (a missing scope shows up as an HTTP 403 in the row).

Compute blind spots after a round:
```python
from blue_agent.edr_client import EDRClient, corroborate
edr = EDRClient(base_url, client_id, client_secret)
truth = edr.ground_truth(since_filter="created_timestamp:>'2026-06-08T00:00:00Z'")
# splunk_caught = the set of technique IDs Blue detected this round (from the coverage matrix)
print(corroborate(truth, splunk_caught))
# -> {confirmed: [...], blind_spots: [...], log_only: [...], edr_coverage_pct: ...}
```

---
---

# How they combine (the full loop)

With **both** on, one Caldera operation exercises the entire moat:

1. **Caldera** runs a real attack on the lab host (Part A).
2. Telemetry flows to Splunk → **Blue** detects with its Sigma rules.
3. **Falcon** independently observes the same execution at the kernel (Part B).
4. **`corroborate()`** compares the two: anything Falcon saw that Blue missed is a
   **BLIND SPOT** → fed to the rule generator as the next proactive target.
5. Re-run: the new rule closes the blind spot, and coverage measurably climbs — now against
   **real** adversary activity, graded by **two independent** witnesses.

This is the production-grade version of the demo: real attacks (Caldera), log-based detection
(Splunk/Blue), and an EDR oracle that proves what the logs couldn't see.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Caldera row: "Server unreachable or api_key invalid" | Wrong `base_url` or `api_key` — re-copy `api_key_red` from `conf/local.yml`; confirm port 8888 is reachable from this machine. |
| Caldera row: "0 agents checked in" | Sandcat one-liner didn't run, or the host can't reach the C2 callback URL. Re-run as Admin; check firewall. |
| `index=arena_attacks` empty after an operation | Forwarder not sending — check `inputs.conf` index routing and that receiving is enabled on :9997. |
| EDR row: "OAuth failed" | Wrong region `base_url`, or client_id/secret mistyped. |
| EDR row: HTTP **403** on the detections read | API client is missing the **Detections:Read** scope — recreate it with that scope. |
| EDR returns 0 detections | Normal if no attacks have run yet, or widen `since_filter`. Falcon may also need a few minutes to surface a detection after execution. |

See the in-file RUN-BOOK comments at the bottom of `red_agent/caldera_client.py` and the
header of `blue_agent/edr_client.py` for the same steps alongside the code.
