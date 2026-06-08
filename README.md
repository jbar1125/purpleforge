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

**LLM providers supported:** Groq (Llama 3.3 70B — free tier), Ollama (local), Google Gemini, Splunk Hosted Models (Foundation-sec-1.1)

---

## How It Works — Real-Time Engine

PurpleForge runs three concurrent loops that race against each other:

```
RED  loop   →  inject  →  mutate on catch  →  inject again
BLUE loop   →  sweep   →  detect / miss     →  generate new rule
KILL CHAIN  →  dwell timer per technique    →  ACHIEVED if Blue misses too long
```

Each technique has a **kill-chain dwell threshold** (30–180s). If Red evades detection for longer than that threshold, the mission "ACHIEVED" — Red succeeded even if Blue eventually catches it. Blue must detect *before* the timer expires.

The result: not just a coverage metric, but a concrete answer to "did the attack succeed?"

---

## ATT&CK Coverage (11 Techniques)

| Technique | Name | Tactic | Dwell Threshold |
|---|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Credential Access | 45s |
| T1021.001 | Remote Services: RDP | Lateral Movement | 90s |
| T1053.005 | Scheduled Task/Job | Persistence | 120s |
| T1136.001 | Create Account: Local Account | Persistence | 90s |
| T1003.001 | OS Credential Dumping: LSASS | Credential Access | 90s |
| T1547.001 | Boot/Logon Autostart: Registry Run Keys | Persistence | 120s |
| T1059.001 | Command and Scripting: PowerShell | Execution | 45s |
| T1055.001 | Process Injection: DLL Injection | Defense Evasion | 90s |
| T1562.001 | Impair Defenses: Disable Defender | Defense Evasion | 90s |
| T1078.004 | Valid Accounts: Cloud Accounts (Azure AD) | Initial Access | 120s |
| T1114.003 | Email Collection: Email Forwarding Rule (M365) | Collection | 180s |

---

## Setup

### Prerequisites
- [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html) (free trial + Developer License)
- Python 3.11+
- [Ollama](https://ollama.com/download) with `qwen2.5:3b` pulled (`ollama pull qwen2.5:3b`), **or** a Gemini/Splunk Cloud API key

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

### 5. Install Splunk dashboard
```bash
python install_dashboard.py
```
Opens at `http://localhost:8000/en-US/app/search/purpleforge`

### 6. Run

**Real-time mode (recommended for demos):**
```bash
# Fresh run — clears accumulated generated rules for a clean arms race
python -m orchestrator.main --mode realtime --duration 600 --clean

# Subsequent runs — red mutates from where it left off (cross-session memory)
python -m orchestrator.main --mode realtime --duration 600

# Full reset — also wipes Red's cross-session memory
python -m orchestrator.main --mode realtime --duration 600 --reset-memory
```

**Turn-based mode (faster, no timing):**
```bash
python -m orchestrator.main --mode turn
```

After the run, find results in `results/`:
- `realtime_report_*.json` — full run data including event log
- `navigator_layer_*.json` — open at https://mitre-attack.github.io/attack-navigator/

### Reset between demo runs
```bash
# Wipe injected events from Splunk (keeps rules and memory)
python clear_arena.py

# Wipe rules + events for a clean re-run
python -m orchestrator.main --mode realtime --duration 600 --clean
```

---

## Configuration

See `config.example.yaml` for the full reference. Key sections:

```yaml
splunk:
  host: localhost
  rest_port: 8089
  hec_port: 8088
  hec_token: "YOUR_HEC_TOKEN"
  username: admin
  password: "YOUR_PASSWORD"
  mcp_token: ""  # optional — install Splunk MCP Server app first

llm:
  provider: groq   # groq | gemini | ollama | splunk_hosted
  groq:
    api_key: "YOUR_GROQ_API_KEY"   # free at console.groq.com
    model: llama-3.3-70b-versatile

arena:
  realtime:
    red_base_seconds: 6.0     # Red attack cadence
    blue_base_seconds: 4.0    # Blue sweep cadence
    window_seconds: 120       # sliding detection window
```

---

## Extending PurpleForge

| What to add | How |
|---|---|
| New ATT&CK technique | Add a JSON template to `red_agent/templates/` (include `dwell_threshold_seconds` in `mutation_hints`) + SPL rule to `blue_agent/rules/baseline/` |
| New LLM provider | Subclass `LLMClient` in `llm_client/`, add a case in `llm_client/factory.py` |
| Longer runs / higher difficulty | Increase `--duration` and adjust thresholds in `config.yaml` |
| Custom kill-chain threshold | Set `dwell_threshold_seconds` in the template's `mutation_hints` |
| ATT&CK Navigator export | Automatic after each run — open `results/navigator_layer_*.json` at navigator.mitre.org |

---

## Project Structure

```
purpleforge/
├── orchestrator/
│   ├── main.py         # Entry point: --mode realtime|turnbased, --clean, --reset-memory
│   ├── engine.py       # Real-time concurrent Red/Blue/metrics loops
│   ├── scorer.py       # Hit/miss scoring + precision + win conditions
│   └── memory.py       # Cross-session persistence (Red evasions, burned rules)
├── red_agent/
│   ├── agent.py        # Selects techniques, drives mutator
│   ├── injector.py     # HEC injection with spread timestamps
│   ├── mutator.py      # LLM-based evasion mutation
│   ├── poisoner.py     # Alert-fatigue FP flood campaigns
│   └── templates/      # 11× JSON ATT&CK technique definitions
├── blue_agent/
│   ├── agent.py        # Detection orchestration
│   ├── detector.py     # Parallel rule execution (MCP → SDK → REST)
│   ├── generator.py    # LLM rule generation (Sigma YAML → SPL)
│   ├── rule_registry.py # Rule health tracking (ACTIVE/DEGRADED/BURNED)
│   └── rules/
│       ├── sigma/      # Portable Sigma detection rules (compiled to SPL)
│       ├── baseline/   # Hand-written SPL fallbacks
│       └── generated/  # LLM-authored rules (auto-populated, gitkeep)
├── splunk_client/
│   ├── hec.py          # HEC injection client
│   ├── search.py       # REST API + Splunk SDK search
│   ├── mcp.py          # MCP Server client (JSON-RPC 2.0)
│   └── sigma_compiler.py # pySigma → Splunk SPL compilation
├── llm_client/         # Provider abstraction (Groq, Gemini, Ollama, Foundation-sec-1.1)
├── mitre/              # ATT&CK coverage matrix + Navigator layer export
├── dashboard/          # Splunk Simple XML dashboard (10 panels)
├── docs/               # Setup guides + demo script
├── config.example.yaml # Template config (copy to config.yaml, fill secrets)
├── install_dashboard.py # One-command dashboard installer
├── clear_arena.py      # Wipe injected events from Splunk between runs
└── results/            # Run reports + ATT&CK Navigator layers (gitignored)
```

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Built for the [Splunk Agentic Ops Hackathon](https://splunk.devpost.com/) — Security Track*
