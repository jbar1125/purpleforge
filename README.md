# PurpleForge

**Continuous adversarial detection engineering, powered by AI.**

PurpleForge is a two-agent AI system that continuously stress-tests your Splunk detection rules against adaptive, MITRE ATT&CK-mapped attack simulations. Red generates attacks. Blue detects them. When Blue misses, it auto-generates a new Sigma rule. When Blue catches, Red mutates to evade. Your detection coverage improves every round — automatically.

> *"Enterprise SIEMs detect just 21% of adversary techniques in the MITRE ATT&CK framework. PurpleForge closes that gap continuously, without a red team on retainer."*
>
> — CardinalOps 5th Annual Report, analysis of 2.5M+ log sources across hundreds of production SIEMs (June 2025)

---

## The Problem

Detection engineering is broken in three compounding ways:

**1. Coverage is catastrophically low.** The 2025 CardinalOps report — analyzing over 13,000 unique detection rules across hundreds of real SIEM deployments — found that enterprise SIEMs cover just **21% of MITRE ATT&CK techniques**. The other 79% sit undetected.

**2. Rules go stale.** Attackers adapt. Detection rules don't. SolarWinds evaded detection for 9 months. Volt Typhoon lived in US critical infrastructure for years — not because of zero-days, but because they understood what detection rules look for and stayed outside those patterns.

**3. Validation is episodic and expensive.** Red team exercises that test detection coverage cost $50,000–$200,000 and happen once or twice a year. Between engagements, gaps open silently. The 2025 CardinalOps report also found that **13% of existing detection rules are non-functional** — they will never trigger. Teams are operating blind and don't know it.

Static BAS (Breach and Attack Simulation) tools answer half the question: *"Did the attack get through?"* But they hand you a report. They don't fix anything. They don't tell your SIEM how to catch what it missed.

## The Solution

PurpleForge runs a continuous automated purple team inside your Splunk environment:

1. **Red Agent** injects synthetic MITRE ATT&CK-mapped attack telemetry into Splunk via HEC — realistic log events indistinguishable from real attacker activity
2. **Blue Agent** executes Sigma detection rules (compiled to SPL) against the injected data and scores hit/miss per technique
3. On a **miss** → Blue calls an LLM to generate a new Sigma rule targeting the evasion pattern. The rule enters a human-review queue before promotion to production.
4. On a **hit** → Red calls an LLM to mutate its attack template to evade the catching rule. The Mutation Inferencer learns what Blue's rules look for and routes Red around them.
5. The loop repeats. Detection coverage improves every round.

The output is not a PDF report. The output is a **self-improving Sigma ruleset** and a **MITRE ATT&CK coverage heatmap** showing measurable before/after improvement — with full ATT&CK Navigator export.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       ORCHESTRATOR                           │
│   Round loop: inject → index → detect → score → adapt      │
├──────────────────────────┬──────────────────────────────────┤
│       RED AGENT          │          BLUE AGENT              │
│                          │                                  │
│  ATT&CK Templates        │  Sigma Detection Rules           │
│  HEC Injector            │  Splunk REST / MCP Search        │
│  LLM Mutator             │  LLM Rule Generator              │
│  Mutation Inferencer     │  Human Review Queue              │
│  Campaign Runner         │  Rule Registry (health tracking) │
│                          │                                  │
│  → Adaptive attack logs  │  → New Sigma rules on miss       │
│  → Evasion variants      │  → Coverage matrix updates       │
└──────────────┬───────────┴──────────────┬───────────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────────────────────────────────┐
│                  SPLUNK ENTERPRISE                        │
│                                                          │
│  index: arena_attacks  ← Red agent injections            │
│  Saved Searches        ← Blue agent detections           │
│  MCP Server            ← Agent ↔ Splunk interface        │
│  Dashboard             ← Live coverage heatmap           │
└──────────────────────────────────────────────────────────┘
```

**LLM providers:** Groq (Llama 3.3 70B · free tier), Ollama (local), Google Gemini, Splunk Hosted Models (Foundation-sec-1.1)

---

## How It Works — Real-Time Engine

PurpleForge runs three concurrent loops:

```
RED  loop  →  inject  →  mutate on catch  →  inject again
BLUE loop  →  sweep   →  detect / miss    →  generate new rule
KILL CHAIN →  dwell timer per technique   →  ACHIEVED if Blue misses deadline
```

Each technique has a **kill-chain dwell threshold** (30–180s). If Red evades detection beyond that threshold, the mission "ACHIEVED" — Red succeeded even if Blue eventually catches it. Blue must detect *before* the timer expires.

This answers the question organizations actually care about: *"If a real attacker used this technique, would we have caught them in time?"*

---

## ATT&CK Coverage — 11 Techniques Across 5 Tactics

| Technique | Name | Tactic | Dwell Threshold |
|---|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Credential Access | 45s |
| T1021.001 | Remote Services: RDP | Lateral Movement | 90s |
| T1053.005 | Scheduled Task/Job | Persistence | 120s |
| T1136.001 | Create Account: Local Account | Persistence | 90s |
| T1003.001 | OS Credential Dumping: LSASS | Credential Access | 90s |
| T1547.001 | Boot/Logon Autostart: Registry Run Keys | Persistence | 120s |
| T1059.001 | PowerShell (encoded + IEX) | Execution | 45s |
| T1055.001 | Process Injection: DLL Injection | Defense Evasion | 90s |
| T1562.001 | Impair Defenses: Disable Defender | Defense Evasion | 90s |
| T1078.004 | Valid Accounts: Cloud (Azure AD) | Initial Access | 120s |
| T1114.003 | Email Forwarding Rule (M365) | Collection | 180s |

---

## What Makes PurpleForge Different

| | PurpleForge | AttackIQ | Cymulate | SafeBreach | CardinalOps |
|---|---|---|---|---|---|
| Automatic rule generation on miss | ✅ | ❌ | ❌ | ❌ | ❌ |
| Red adapts to Blue's rules | ✅ | ❌ | ❌ | ❌ | N/A |
| Sigma-native output (SIEM-portable) | ✅ | ❌ | ❌ | ❌ | Partial |
| Continuous (not point-in-time) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Human review queue before rule promotion | ✅ | N/A | N/A | N/A | Partial |
| EDR blind-spot corroboration | ✅ | ❌ | ❌ | ❌ | ❌ |
| Kill-chain dwell timing | ✅ | ❌ | ❌ | ❌ | ❌ |
| Open-source / self-hostable | ✅ | ❌ | ❌ | ❌ | ❌ |
| Starts at $0 | ✅ | ❌ | ❌ | ❌ | ❌ |

The fundamental difference: existing BAS tools **tell you what you missed**. PurpleForge **fixes what you missed and proves the fix works** — in the same run.

---

## Who Uses PurpleForge

**Detection Engineers** who want a continuous adversarial test harness instead of periodic red team engagements — and want LLM-assisted rule generation grounded in actual observed evasion patterns.

**SOC Managers** who need to demonstrate measurable detection coverage improvement to leadership and auditors, with ATT&CK Navigator exports tied to real simulation results.

**Security Architects** building detection-as-code pipelines who need a CI/CD-compatible adversarial test suite for Sigma rules before they ship.

**MSSPs** who want to offer clients a continuous detection quality guarantee backed by real simulation data, not just vendor benchmark scores.

---

## Setup

### Prerequisites
- [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html) (free trial + Developer License)
- Python 3.11+
- An LLM API key: [Groq](https://console.groq.com) (free), [Gemini](https://aistudio.google.com/app/apikey) (free), or Ollama (local)

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
- Install the Splunk MCP Server app (optional — required to earn MCP-tier query routing)

### 3. Configure PurpleForge
```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your Splunk credentials, HEC token, and LLM provider
```

### 4. Verify setup
```bash
python setup_verify.py
```
All critical checks must pass. The verifier creates missing indexes automatically.

### 5. Install the dashboard
```bash
python install_dashboard.py
```
Opens the live coverage heatmap at `http://localhost:8000/en-US/app/search/purpleforge`

### 6. Run

```bash
# Real-time mode — recommended; clean slate for the arms race
python -m orchestrator.main --mode realtime --duration 600 --clean

# Turn-based mode — faster for CI/CD pipelines, no timing
python -m orchestrator.main --mode turn

# After a run, reset injected events (keeps generated rules + Red's mutation memory)
python clear_arena.py

# Full reset — wipes everything including cross-session evasion memory
python -m orchestrator.main --mode realtime --duration 600 --reset-memory
```

---

## Configuration Reference

```yaml
splunk:
  host: localhost
  rest_port: 8089
  hec_port: 8088
  hec_token: "YOUR_HEC_TOKEN"
  username: admin
  password: "YOUR_PASSWORD"
  mcp_token: ""           # optional — install Splunk MCP Server app first

llm:
  provider: groq          # groq | gemini | ollama | splunk_hosted
  groq:
    api_key: "YOUR_GROQ_API_KEY"
    model: llama-3.3-70b-versatile

arena:
  realtime:
    red_base_seconds: 6.0       # Red attack cadence
    blue_base_seconds: 4.0      # Blue sweep cadence
    window_seconds: 120         # Sliding detection window
```

Full reference: `config.example.yaml`

---

## Optional Production Integrations

PurpleForge ships two optional integrations that are **off by default**. The arena runs fully without them; enable them to replace synthetic data with real adversary activity.

**MITRE Caldera** (`caldera.enabled: true`) — replaces synthetic HEC injection with real ATT&CK commands executed by a Sandcat C2 agent on an isolated lab host. Caldera's operation report becomes the ground-truth answer key.

**CrowdStrike Falcon EDR** (`edr.enabled: true`) — adds an independent kernel-level witness. Cross-checking EDR ground truth against Blue's Splunk detections reveals blind spots that your rules can't see. Blind spots feed directly to the rule generator as the highest-priority targets.

See [docs/integrations_setup.md](docs/integrations_setup.md) for full setup instructions.

---

## Project Structure

```
purpleforge/
├── orchestrator/
│   ├── main.py              # Entry point: --mode realtime|turn, --clean, --reset-memory
│   ├── engine.py            # Concurrent Red/Blue/metrics loops (asyncio)
│   ├── scorer.py            # Per-technique hit/miss + precision + win conditions
│   └── memory.py            # Cross-session evasion state (Red's learned mutations)
├── red_agent/
│   ├── agent.py             # Selects techniques, drives injection + mutation
│   ├── injector.py          # HEC injection with realistic timestamp spread
│   ├── mutator.py           # LLM-based evasion mutation with schema validation
│   ├── campaign_runner.py   # Multi-stage kill-chain campaign sequencing
│   ├── poisoner.py          # Alert-fatigue FP flood campaigns
│   ├── benign.py            # Realistic benign traffic (precision measurement)
│   ├── mutation_inferencer.py  # Learns what Blue's rules look for; routes around them
│   └── templates/           # 11× ATT&CK technique JSON definitions
├── blue_agent/
│   ├── agent.py             # Detection orchestration
│   ├── detector.py          # Parallel rule execution (MCP → SDK → REST fallback)
│   ├── generator.py         # Sigma YAML generation via LLM + pySigma → SPL compilation
│   ├── rule_registry.py     # Rule health tracking (ACTIVE / DEGRADED / BURNED)
│   ├── edr_client.py        # CrowdStrike Falcon integration + blind-spot corroboration
│   └── rules/
│       ├── sigma/           # Portable Sigma rules (primary detection format)
│       ├── baseline/        # SPL fallback rules
│       └── generated/       # LLM-authored rules (auto-populated each run)
├── splunk_client/
│   ├── hec.py               # HEC injection client
│   ├── search.py            # REST API + Splunk SDK search
│   ├── mcp.py               # Splunk MCP Server client (JSON-RPC 2.0)
│   └── sigma_compiler.py    # pySigma → Splunk SPL compilation
├── rule_review/             # Human-in-the-loop review workflow
│   ├── queue.py             # Review queue with confidence scoring
│   ├── deployer.py          # Rule promotion: shadow → canary → production
│   └── app.py               # Flask review UI
├── llm_client/              # Provider abstraction (Groq, Gemini, Ollama, Foundation-sec-1.1)
├── mitre/                   # ATT&CK coverage matrix + Navigator layer export
├── dashboard/               # Splunk Simple XML dashboard (10 panels)
├── docs/                    # Setup guides, integration runbooks, business docs
├── tests/                   # 69 detection-as-code tests across all techniques
├── config.example.yaml      # Full configuration reference
├── setup_verify.py          # Pre-flight check for all integrations
├── install_dashboard.py     # One-command dashboard installer
└── clear_arena.py           # Wipe injected events between runs
```

---

## Tests

```bash
pytest tests/ -v
# 69 tests: Sigma compilation, rule precision, campaign sequencing,
# mutation inference, EDR corroboration, human review queue
```

---

## Roadmap

See [docs/PRODUCT_ROADMAP.md](docs/PRODUCT_ROADMAP.md) for the full product roadmap including v2 (multi-SIEM via pySigma, RL red agent, RAG rule generation), v3 (cloud attack modules, CI/CD integration, multi-tenant), and the research directions (GAN-style coevolution, PSRO league, causal coverage metrics).

---

## License

MIT — see [LICENSE](LICENSE)
