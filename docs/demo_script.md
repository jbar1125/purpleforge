# PurpleForge — Demo Script (3-minute video)

## Setup (off-camera)
1. `python setup_verify.py` — all checks pass
2. Clear previous data: `index=arena_attacks | delete` in Splunk search
3. Arena config: 5 rounds, 6 techniques, Ollama qwen2.5:3b

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

### Split screen: terminal + Splunk dashboard

**Terminal side:** Run `PYTHONIOENCODING=utf-8 python orchestrator/main.py`

**Splunk side:** Open `localhost:8000` → PurpleForge dashboard

**Narrate as it runs:**

**Round 1:**
> "Round 1. Red injects baseline attacks — brute force, LSASS dump, RDP lateral movement.
> Blue's baseline rules catch most of them. 83% coverage right away.
> But watch — the brute force rule has too high a threshold. It misses.
> Blue's LLM just wrote a new SPL rule targeting that evasion pattern."

Point to: `[blue generator] ✓ saved: generated_r1_T1110_001`

**Round 1 → Round 2 transition:**
> "Now red receives the catching rules. Its LLM mutates the attack parameters
> to evade what blue just deployed. Count reduced, timing spread changed,
> process names swapped."

Point to: `[red mutator] mutation accepted: ['GrantedAccess', 'SourceImage']`

**Round 2:**
> "Round 2. Red's mutations are working — detection drops. But now blue has new
> context: it knows exactly what changed. The next rule it generates targets the mutation."

**Round 3-4 (show dashboard updating):**
> "Watch the dashboard. Coverage is climbing. The generated rules are accumulating.
> This is a detection ruleset that improves itself."

**Show the dashboard coverage trend chart going up.**

**Round 5:**
> "Final round. Coverage is [X]%. We started with 6 baseline rules.
> We now have [Y] auto-generated rules — each one written in response to a real evasion."

---

## Section 4: Results (2:30–3:00)

**Show:** Terminal final summary table.
**Show:** Navigator layer in ATT&CK Navigator (open the JSON file at navigator.attackiq.com or the MITRE site).

**Say:**
> "In 5 rounds, we went from [X]% to [Y]% windowed coverage.
> [N] new rules generated automatically.
> Every rule is traceable to a specific evasion attempt.
> This is what adversarial detection engineering looks like at machine speed."

**Final line:**
> "PurpleForge. Open source. MIT license. Two AI agents fighting inside your SIEM,
> so attackers don't get to fight there instead."

---

## Technical Callouts (for judges reading submission text)

- **MCP Server**: All Splunk search queries route through the Splunk MCP Server JSON-RPC 2.0 protocol (`splunk_client/mcp.py`) — not raw REST — qualifying for the MCP prize
- **Hosted Models**: LLM inference via Foundation-sec-1.1-8b-instruct on Splunk Cloud (set `provider: splunk_hosted` in config.yaml) — qualifies for the Hosted Models prize
- **Developer Tools**: Uses Splunk REST API (HEC injection, search jobs, saved searches, parse endpoint for SPL validation) — qualifies for Developer Tools prize
- **Security**: Adversarial detection engineering is the core security use case — qualifies for Best of Security prize
