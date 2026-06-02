# PurpleForge

**Adversarial detection engineering, automated.**

PurpleForge is a two-agent AI system that continuously stress-tests your Splunk detection rules against adaptive attack simulations mapped to MITRE ATT&CK. Red generates attacks. Blue detects them. When blue misses, it auto-generates a new SPL rule. When blue catches, red mutates to evade. After each run, your detection coverage measurably improves.

> *"Your detection rules are static. Attackers aren't. PurpleForge is the only tool that proves your rules are wrong — and then fixes them."*

---

## The Problem

Detection engineering is broken. Security teams write SIEM rules reactively — after incidents happen. MITRE ATT&CK documents 200+ techniques; most organizations detect fewer than 30%. Red team engagements that test coverage cost $50k–$200k and happen once or twice a year. Between engagements, detection gaps sit open and unnoticed.

Static tools — dashboards, investigation aids, alert tuners — all share the same flaw: they assume your rules are correct and your attacker is not adapting. They're wrong on both counts.

**SolarWinds** evaded detection for 9 months. **Volt Typhoon** lived in US critical infrastructure for years using only native Windows tools — because they knew what detection rules look for. These weren't zero-days. They were evasion against static defenses.

## The Solution

PurpleForge runs an automated purple team exercise inside Splunk:

1. **Red Agent** generates synthetic attack logs mapped to MITRE ATT&CK techniques and injects them into Splunk via HEC
2. **Blue Agent** runs SPL detection rules against the injected data and scores hits/misses
3. On a **miss** → Blue calls an LLM to generate a new SPL detection rule targeting the evasion pattern
4. On a **hit** → Red calls an LLM to mutate its attack template to evade the catching rule
5. The loop repeats, and **detection coverage improves every round**

The output is not a dashboard. The output is a self-improving detection ruleset and a MITRE ATT&CK coverage heatmap showing measurable before/after improvement.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ORCHESTRATOR                          │
│  Round loop: inject → index → detect → score → adapt   │
├──────────────────────┬──────────────────────────────────┤
│     RED AGENT        │         BLUE AGENT               │
│                      │                                  │
│  ATT&CK Templates    │  SPL Detection Rules             │
│  HEC Injector        │  Splunk REST / MCP Search        │
│  LLM Mutator         │  LLM Rule Generator              │
│                      │                                  │
│  → Synthetic events  │  → New SPL rules on miss         │
│  → Evasion variants  │  → Coverage matrix updates       │
└──────────┬───────────┴──────────────┬───────────────────┘
           │                          │
           ▼                          ▼
┌──────────────────────────────────────────────────────┐
│                  SPLUNK ENTERPRISE                    │
│                                                      │
│  index: arena_attacks  ← Red agent injections        │
│  Saved Searches        ← Blue agent detections       │
│  MCP Server            ← Agent ↔ Splunk interface    │
│  Dashboard             ← Coverage heatmap            │
└──────────────────────────────────────────────────────┘
```

**LLM providers supported:** Ollama (local), Google Gemini, Splunk Hosted Models (Foundation-sec-1.1)

---

## ATT&CK Coverage (v1)

| Technique | Name | Tactic |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1021.001 | Remote Services: RDP | Lateral Movement |
| T1053.005 | Scheduled Task/Job | Persistence |
| T1136.001 | Create Account: Local Account | Persistence |
| T1003.001 | OS Credential Dumping: LSASS | Credential Access |
| T1547.001 | Boot/Logon Autostart: Registry Run Keys | Persistence |

---

## Setup

### Prerequisites
- [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html) (free trial + Developer License)
- Python 3.11+
- [Ollama](https://ollama.com/download) with `llama3.1` pulled, **or** a Gemini/Splunk Cloud API key

### 1. Clone and install
```bash
git clone https://github.com/jbar1125/purpleforge.git
cd purpleforge
pip install -r requirements.txt
```

### 2. Configure Splunk
Follow [docs/splunk_setup.md](docs/splunk_setup.md) to:
- Enable HEC (port 8088) and get a token
- Create indexes: `arena_baseline`, `arena_attacks`
- Install the Splunk MCP Server app (optional, for MCP prize)

### 3. Configure PurpleForge
```bash
cp config.example.yaml config.yaml
```
Edit `config.yaml` with your Splunk credentials, HEC token, and LLM provider.

### 4. Verify setup
```bash
python setup_verify.py
```
All critical checks must pass before running.

### 5. Run
```bash
python orchestrator/main.py
```

---

## Configuration

```yaml
splunk:
  host: localhost
  rest_port: 8089
  hec_port: 8088
  hec_token: "your-hec-token"
  username: your-splunk-username
  password: "your-splunk-password"
  index_baseline: arena_baseline
  index_attacks: arena_attacks
  verify_ssl: false
  mcp_token: ""  # optional — generates via setup_verify.py

llm:
  provider: ollama  # ollama | gemini | splunk_hosted
  ollama:
    model: llama3.1
    base_url: http://localhost:11434

arena:
  num_rounds: 5
  indexing_wait_seconds: 4
  techniques:
    - T1110.001
    - T1021.001
    - T1053.005
    - T1136.001
    - T1003.001
    - T1547.001
```

---

## Extending PurpleForge

PurpleForge is designed for extensibility:

| What to add | How |
|---|---|
| New ATT&CK technique | Add a JSON template to `red_agent/templates/` + SPL rule to `blue_agent/rules/baseline/` |
| New LLM provider | Subclass `LLMClient` in `llm_client/`, add a case in `llm_client/factory.py` |
| More rounds / harder difficulty | Change `num_rounds` in `config.yaml` |
| Kill chain chaining | Modify `orchestrator/main.py` to sequence techniques per round |
| ATT&CK Navigator export | Add export method to `mitre/coverage.py` |

---

## Project Structure

```
purpleforge/
├── orchestrator/       # Round loop, scoring, reporting
├── red_agent/          # Attack templates + HEC injector + LLM mutator
│   └── templates/      # Per-technique JSON attack definitions
├── blue_agent/         # SPL detection + LLM rule generator
│   └── rules/
│       ├── baseline/   # Hand-written baseline SPL rules
│       └── generated/  # LLM-generated rules (auto-populated)
├── splunk_client/      # HEC, REST API, and MCP Server clients
├── llm_client/         # LLM abstraction (Ollama / Gemini / Splunk Hosted)
├── mitre/              # ATT&CK coverage matrix tracking
├── dashboard/          # Splunk Simple XML dashboard
├── docs/               # Setup guides
└── results/            # Run output JSON reports (gitignored)
```

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Built for the [Splunk Agentic Ops Hackathon](https://splunk.devpost.com/) — Security Track*
