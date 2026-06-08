# PurpleForge — Demo Script (3-minute video)

## Setup (off-camera)
1. `python setup_verify.py` — all checks pass
2. Clear previous data: `python clear_arena.py`
3. Arena config: 600s real-time, 11 techniques, Groq Llama 3.3 70B

---

## Section 1: The Problem (0:00–0:30)

**Say:**
> "Security teams write detection rules once — and attackers adapt constantly.
> Most organizations detect fewer than 30% of MITRE ATT&CK techniques.
> The tools we have today are dashboards and investigation aids — they assume your rules
> are correct. They're not. PurpleForge is different: it *proves* your rules are wrong
> and then *fixes them*."

**Show:** ATT&CK matrix website — briefly, just to establish the problem scale.

---

## Section 2: Architecture (0:30–1:00)

**Say:**
> "Two AI agents fighting inside Splunk. Red injects MITRE ATT&CK-mapped attack logs.
> Blue runs SPL detection rules and scores hits and misses.
> When blue misses, the LLM generates a new SPL rule.
> When blue catches, red's LLM mutates the attack to evade the rule.
> Every round, coverage goes up."

**Show:** Architecture diagram (`architecture.png`). Point to each component as you name it.

Key points to call out:
- "All Splunk queries route through the MCP Server — that's the protocol for agentic Splunk integration"
- "The LLM is Foundation-sec-1.1, Splunk's own security-specialized model — better SPL generation than general models"
- "ATT&CK coverage matrix updates live — we export a Navigator layer at the end"

---

## Section 3: Live Demo (1:00–2:30)

### Setup
```bash
python -m orchestrator.main --mode realtime --duration 600 --clean
```

### Split screen: terminal + Splunk dashboard

**Terminal side:** The running engine (rich-colored output)  
**Splunk side:** `localhost:8000` → PurpleForge dashboard (auto-refreshes every 15s)

**Narrate as it runs:**

**First 60s (initial injection):**
> "Red is injecting 11 ATT&CK techniques simultaneously — brute force, LSASS dump,
> RDP lateral movement, cloud account anomaly, email forwarding. Blue's baseline rules
> catch most of them immediately. Watch the coverage line jump to 80%+.
> But some techniques are slipping through."

Point to the dashboard coverage chart climbing.

**t=60–120s (first mutations):**
> "Red sees which rules caught it — and immediately mutates. Watch this.
> 'MUTATE T1110.001 gen1 — evading via GrantedAccess, SourceImage.'
> Red's LLM rewrote the attack to evade the exact rule that caught it.
> Coverage just dropped. Blue is already sweeping — it found the miss."

Point to: `[RED] MUTATE T1110.001 gen1 — evading via [...]`
Then: `[BLUE] GENERATE rule for missed T1110.001 gen1 ...`

**Kill-chain objective fires:**
> "See this — 'OBJECTIVE ACHIEVED: T1078.004 — Authenticate with valid cloud credentials.'
> Red evaded detection for 120 seconds. In a real environment, that's enough time
> for persistence. The attack succeeded even though Blue eventually caught it."

Point to: `[RED] ⚡ OBJECTIVE ACHIEVED: T1078.004`

**t=120–300s (arms race in progress):**
> "Blue just deployed a new rule — and Red's already mutating to gen2.
> This is the real game: Blue's LLM writes detection logic in response to Red's
> evasion, and Red's LLM reads the new rule and mutates again.
> Neither side is static."

Point to the dashboard: "Mutation Generation per Technique" bar chart climbing.

**Final state:**
> "11 techniques. [N] rules generated automatically. [X]% coverage.
> [Y] kill-chain objectives blocked — that's [Y] attacks that didn't succeed.
> Every generated rule is directly traceable to a real evasion attempt."

---

## Section 4: Results (2:30–3:00)

**Show:** Terminal final scoreboard (two tables — Technique status + Kill-Chain Objectives).
**Show:** Navigator layer in ATT&CK Navigator (open `results/navigator_layer_*.json` at https://mitre-attack.github.io/attack-navigator/).

**Say:**
> "In 10 minutes, we went from 6 hand-written rules to [N] total rules — [M] of them
> written by AI, each targeting a specific mutation Red tried.
> [Y]% detection coverage. [K] kill-chain objectives blocked out of 11.
> This is what adversarial detection engineering looks like at machine speed —
> not a red team engagement that costs $50k, but two AI agents fighting continuously
> inside your SIEM."

**Final line:**
> "PurpleForge. Open source. MIT license. Two AI agents fighting inside your SIEM,
> so attackers don't get to fight there instead."

---

## Technical Callouts (for judges reading submission text)

- **MCP Server**: All Splunk search queries route through the Splunk MCP Server JSON-RPC 2.0 protocol (`splunk_client/mcp.py`) — not raw REST — qualifying for the MCP prize
- **Hosted Models**: LLM inference via Foundation-sec-1.1-8b-instruct on Splunk Cloud (set `provider: splunk_hosted` in config.yaml) — qualifies for the Hosted Models prize
- **Developer Tools**: Uses Splunk REST API (HEC injection, search jobs, saved searches, parse endpoint for SPL validation) — qualifies for Developer Tools prize
- **Security**: Adversarial detection engineering is the core security use case — qualifies for Best of Security prize
