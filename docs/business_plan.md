# PurpleForge — Business Plan

## Executive Summary

PurpleForge is an AI-powered continuous detection engineering platform that automatically closes the gap between what attackers do and what your SIEM detects. Unlike point-in-time BAS (Breach and Attack Simulation) tools that hand you a report, PurpleForge runs a live arms race inside your Splunk environment: a Red AI agent continuously generates adaptive MITRE ATT&CK-mapped attacks; a Blue AI agent detects them and auto-generates new Sigma detection rules when it misses; and Red learns from Blue's rules to evolve its evasion — in a closed feedback loop that improves detection coverage every round.

**The market timing is right:** CardinalOps' 5th Annual Report (June 2025, analyzing 2.5M+ log sources across hundreds of production SIEMs) found that enterprise SIEMs detect just **21% of MITRE ATT&CK techniques** — a number that has barely moved in five years despite billions spent on security tooling. Existing solutions (AttackIQ, Cymulate, SafeBreach) tell organizations what they missed and charge $7,000–$91,000/year to do it. None of them fix anything automatically. PurpleForge does.

**Ask:** $500K pre-seed to complete multi-SIEM support, onboard 10 design-partner customers, and establish product-market fit. Target Seed: $3–5M at $1M ARR.

---

## 1. The Problem

### 1.1 Detection Coverage Is Catastrophically Low

The data is unambiguous:
- **79% of MITRE ATT&CK techniques are undetected** in the average enterprise SIEM (CardinalOps, 2025)
- **13% of existing detection rules are non-functional** — they will never fire due to misconfigured data sources or missing log fields
- Organizations cover only **4 of the top 10 most-used adversary techniques** in real-world attacks
- The root cause: *"The telemetry exists. The detection logic does not."* Data is flowing in; rules were never written.

### 1.2 Rules Go Stale While Attackers Adapt

Detection rules are written reactively — after incidents. Attackers study the rules and stay outside their patterns.

- **SolarWinds** (2020–2021): Evaded detection for 9 months across 18,000+ organizations, including US federal agencies
- **Volt Typhoon** (2021–2023): Lived in US critical infrastructure for years using only native Windows tools — specifically because they understood what detection rules look for
- These were not zero-days. They were evasion against static, unmaintained detection logic.

### 1.3 Validation Is Episodic and Expensive

The standard solution — red team exercises — costs $50,000–$200,000 per engagement and happens 1–2 times per year. Between engagements, new detection gaps open unnoticed. The budget is accessible only to large enterprises; mid-market security teams have no practical continuous validation option.

---

## 2. The Solution

### 2.1 Continuous Adversarial Detection Engineering

PurpleForge replaces episodic red team engagements with a continuous, automated arms race:

```
RED Agent                          BLUE Agent
---------                          ----------
Inject ATT&CK-mapped attack logs → Execute Sigma rules vs. injected data
                                    ↓ (miss)
Receive mutation signal from    ← Generate new Sigma rule via LLM
catching rule                       ↓ (human review queue)
                                    ↓ (approved)
Evasion-mutate the template     → Rule enters production ruleset
Repeat                             Repeat
```

**What makes the loop self-reinforcing:**
- Red does not just run the same simulations on repeat. The **Mutation Inferencer** reads Blue's active ruleset and learns what patterns Blue is watching for — then routes Red's attack templates around those patterns. Red gets harder as Blue gets better.
- Blue does not just generate rules blindly. The **Rule Registry** tracks each rule's health (ACTIVE / DEGRADED / BURNED) based on whether it keeps catching or gets evaded. Burned rules are retired; degraded rules are flagged for regeneration.

### 2.2 What Organizations Get

After a 10-round run on a fresh Splunk environment:
- **Coverage improvement**: Typically from 2–3 catching rules to 8–9 (depending on LLM quality and technique complexity)
- **ATT&CK Navigator export**: JSON layer showing exact technique coverage before and after, ready to present to CISO or auditors
- **Sigma rule library**: All LLM-generated rules are portable Sigma YAML — they work on Splunk, Microsoft Sentinel, Elastic, and Chronicle via pySigma
- **Human review queue**: Every generated rule passes through an analyst queue before production, preventing automated garbage from landing in live detection

### 2.3 Optional Production Integrations

Two integrations expand coverage from synthetic to real:

**MITRE Caldera** (`caldera.enabled: true`): Replaces synthetic log injection with real ATT&CK commands executed by a Sandcat C2 agent on an isolated lab host. Caldera's operation report becomes the ground-truth answer key, so Blue is graded against what actually ran.

**CrowdStrike Falcon EDR** (`edr.enabled: true`): Adds an independent kernel-level witness. Cross-checking EDR ground truth against Splunk's detections reveals blind spots that log-based rules structurally cannot see. Those blind spots feed directly to the rule generator as highest-priority targets.

---

## 3. Market

### 3.1 Size

| Market | 2025 Value | 2031 Projection | CAGR |
|--------|-----------|----------------|------|
| Breach & Attack Simulation (BAS) | $5.5B | $305.6B | 33.6% |
| Purple Team Services | $6.3B | ~$15.4B | 11.5% |
| AI Red Teaming Services | ~$1.2B | ~$8B+ | 30.5% |
| SIEM/Detection Engineering tooling | $10B+ | $25B+ | 14%+ |

PurpleForge sits at the intersection of BAS and detection engineering automation — a segment that did not exist 3 years ago and is now the fastest-growing area of the security market.

**TAM (Total Addressable Market):** $5.5B BAS market + adjacent detection engineering spend = ~$8B
**SAM (Serviceable Addressable Market):** Mid-market and enterprise organizations on Splunk (est. 25,000 worldwide) + MSSP market = ~$2B
**SOM Y1 (Serviceable Obtainable):** 50 paying customers × avg $30K ACV = ~$1.5M ARR

### 3.2 Ideal Customer Profile (ICP)

**Primary — Mid-market enterprise (500–5,000 employees):**
- Has Splunk Enterprise or Splunk Cloud
- Has a SOC (2–10 analysts) but **no dedicated purple team**
- Currently spends $50K–$200K/year on annual red team engagements
- Has a CISO or VP Security who reports detection coverage to the board
- Pain point: red team report sits on a shelf; nobody has time to implement the recommendations

**Secondary — MSSP (Managed Security Service Provider):**
- Manages Splunk environments for 10–100 clients
- Wants to offer "continuous detection assurance" as a differentiated service
- Currently delivers quarterly reports; wants to move to continuous metrics
- PurpleForge white-labels well — the dashboard and Navigator exports are customer-deliverable

**Tertiary — Security-conscious Series B–D tech company:**
- Engineering-driven culture: treats detection rules like code (detection-as-code pipeline)
- Uses Splunk as core SIEM
- Wants adversarial CI/CD tests for Sigma rules before they ship to production
- Pain point: rules are written but never tested against real evasion attempts

### 3.3 Buying Signal

An organization is a strong PurpleForge prospect if they answer yes to any of:
- "We've had a red team engagement in the last 12 months but haven't implemented the recommendations"
- "We don't know what percentage of MITRE ATT&CK we currently detect"
- "Our detection rules were written 2+ years ago and haven't been reviewed since"
- "We're adding new log sources to Splunk but have no process for writing detections for them"

---

## 4. Business Model

### 4.1 Pricing Tiers

| Tier | Price | What's Included | Target |
|------|-------|-----------------|--------|
| **Community** | Free | 6 techniques, turn-based only, Sigma export, no human review queue | Individual researchers, students, open-source users |
| **Starter** | $1,500/mo | 11 techniques, real-time engine, human review queue, Caldera integration, ATT&CK Navigator export, email support | Mid-market enterprises, initial land |
| **Growth** | $4,500/mo | Everything in Starter + EDR corroboration, custom technique templates, multi-environment, Slack alerts, 99.5% uptime SLA | Growing security orgs, MSSPs |
| **Enterprise** | $12,000/mo | Everything in Growth + adversary emulation profiles, multi-SIEM (Sentinel/Elastic/Chronicle), dedicated CSM, SSO/SAML, custom integrations | Large enterprise, regulated industries |

**Annual discount:** 20% off any tier with annual commitment.

**MSSP partner pricing:** 40% margin on Growth/Enterprise resale; private-label dashboard and report exports.

### 4.2 Revenue Model

PurpleForge is a **SaaS product with a self-hosted deployment model** — the software runs in the customer's own Splunk environment, with the LLM calls routed through either their own API key or PurpleForge's hosted inference. This is the preferred architecture for enterprise security buyers: no data leaves their perimeter.

For the hosted inference option (where we handle the LLM calls), we add a **consumption tier** ($0.05/LLM call) that converts to pure SaaS margin at scale.

### 4.3 Unit Economics (Target at Scale)

| Metric | Target |
|--------|--------|
| CAC (sales-assisted) | ~$8,000 |
| CAC (PLG / self-serve) | ~$1,200 |
| Average contract value | ~$36,000/yr (blended) |
| Gross margin | 82% (software; LLM inference at cost) |
| LTV/CAC | 8–10× (at 95%+ NRR) |
| Payback period | 3–5 months |

Security tooling typically sees very high retention: once a team builds their detection pipeline on PurpleForge, the generated rule library and the mutation memory Red has built up are hard to move. Switching cost is high.

---

## 5. Go-To-Market

### 5.1 Phase 1 — Community & Developer Adoption (Months 1–6)

**Goal:** 500 Community users, 10 design-partner customers

- **Open source first:** PurpleForge Community tier is free, fully functional, MIT licensed. GitHub is the primary distribution channel. Security engineers discover it via search ("Sigma rule testing"), DEF CON/BSidesLV talks, and the detection engineering community (Detection Lab Discord, Sigma HQ Slack).
- **Content:** Weekly blog posts on detection engineering tradecraft: "How we generated a brute-force rule that evaded PurpleForge for 3 rounds," "MITRE ATT&CK coverage gaps we found in our own test environment." These rank for high-intent search terms.
- **Splunkbase listing:** PurpleForge is a Splunk app; listing it on Splunkbase puts it in front of 60,000+ Splunk customers browsing for security apps.
- **Design partners:** Reach out to 20 mid-market security teams via LinkedIn/cold email with a "free full setup in exchange for feedback" offer. Target 10 yeses. These become case studies and references.

### 5.2 Phase 2 — Paid Conversion (Months 6–12)

**Goal:** 25 paying customers, $500K ARR

- **PLG motion:** Community users who hit usage limits (6 techniques, no human review queue) see a natural upgrade path. The pain of the limit is real (they've seen their coverage improve; they want more).
- **Sales assist for mid-market:** Hire one sales engineer at month 6. Warm inbound from GitHub/Splunkbase; demo → POC → close. POC is a 30-day free full-tier trial.
- **Conference presence:** RSA Innovation Sandbox application (deadline Nov). DEF CON 34 talk: "How AI agents fight over your SIEM — live."
- **Splunk partnership:** Apply to Splunk's Technology Alliance Partner program. Co-sell motion with Splunk AEs calling on mid-market accounts.

### 5.3 Phase 3 — Enterprise & MSSP (Months 12–24)

**Goal:** $3M ARR, Series A ready

- **MSSP channel:** 5–10 MSSP partners who white-label PurpleForge as "Continuous Detection Assurance" in their service catalog. Each MSSP brings 10–50 clients.
- **Enterprise sales:** Hire a VP Sales. Target Fortune 1000 security teams; $100K–$200K ACV with multi-year contracts.
- **Product-led enterprise:** Large enterprise teams often self-discover via their security engineers who use the Community tier; convert via SSO/SAML request (natural trigger for enterprise tier conversation).

---

## 6. Competitive Landscape

See [competitive_analysis.md](competitive_analysis.md) for the full analysis. The one-line summary:

**Existing BAS tools test defenses and hand you a report. PurpleForge tests defenses and fixes them.**

No existing tool combines adversarial simulation + automatic rule generation + Sigma-native output + a Red agent that learns from Blue's rules. The closed feedback loop is the moat.

---

## 7. Technology Moat

PurpleForge's durable differentiation is not "we use an LLM" — every security company will say that. The moat is the **coevolutionary feedback loop**:

1. **Mutation Memory**: Red's cross-session evasion history persists. When Red successfully evades a rule pattern once, that pattern is flagged in mutation memory. Future Red mutations avoid those patterns by default. This is a proprietary dataset that compounds over time.

2. **Rule Health Tracking**: Blue's Rule Registry tracks every generated rule's performance across rounds. Rules that get evaded are marked DEGRADED → BURNED. This history trains better prompts for the next generation cycle.

3. **Sigma Portability**: Every rule PurpleForge generates is portable to any SIEM via pySigma. Competitors generate proprietary detection content locked to their platform. PurpleForge's rules go anywhere — this is a strong adoption wedge for multi-SIEM organizations.

4. **Detection-as-Code Discipline**: The 69-test suite covers every rule's detection logic against known-positive and known-negative cases. This makes PurpleForge the first adversarial test harness that also has a unit test harness for the rules it generates. Security teams with engineering culture find this immediately compelling.

---

## 8. Team

**Current:** Solo-founder stage. Looking for a co-founder with:
- 3–5 years enterprise security (SOC analyst / detection engineer / red teamer)
- Existing relationships in mid-market security buying centers
- Strong technical communication skills (can present at RSA/DEF CON)

**Planned Hires (pre-seed to seed):**
1. **Sales Engineer** (Month 6) — technical pre-sales, demo delivery, POC management
2. **Senior Detection Engineer** (Month 8) — content quality: expand ATT&CK coverage, improve LLM prompts
3. **Full-Stack Engineer** (Month 10) — multi-SIEM support, dashboard improvements, cloud deployment

---

## 9. Financial Projections

### Revenue

| Year | Customers | Mix | ARR |
|------|-----------|-----|-----|
| Y1 | 15 Starter + 5 Growth | Mostly direct | ~$420K |
| Y2 | 40 Starter + 20 Growth + 5 Enterprise | PLG + sales assist | ~$1.8M |
| Y3 | 100 Starter + 60 Growth + 25 Enterprise | Sales-led + MSSP channel | ~$6.8M |

*These projections assume: no enterprise deals in Y1 (design-partner focused); MSSP channel launches Y2Q3; Series A closes Y2Q2.*

### Runway

| Round | Amount | Post-Money | Use of Funds |
|-------|--------|-----------|--------------|
| Pre-seed | $500K | ~$3M | Product + first hire + 10 design partners |
| Seed | $3–5M | ~$15–25M | 4 hires, sales motion, multi-SIEM, SOC 2 Type II |
| Series A | $15–25M | ~$80–120M | Enterprise GTM, international expansion, RL red agent |

### Monthly Burn at Pre-Seed

| Item | Monthly Cost |
|------|-------------|
| LLM API costs (shared infra) | ~$2,000 |
| Infrastructure (AWS) | ~$1,500 |
| Founder salary (minimal) | ~$5,000 |
| Legal + misc | ~$1,500 |
| **Total** | **~$10,000/mo** |

At $500K pre-seed, ~50 months runway — enough to reach $500K ARR before raising Seed.

---

## 10. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Cymulate/AttackIQ adds AI rule generation | High | Medium | First-mover advantage in open-source + community; Sigma portability differentiates |
| Splunk loses market share to Sentinel/Elastic | Medium | High | Multi-SIEM support (v2 roadmap) via pySigma — same rules, different backends |
| LLM-generated rules are low quality | Medium | High | 69-test suite + human review queue + Rule Registry health tracking catch bad rules before production |
| Enterprise security teams won't trust auto-generated rules | Medium | Medium | Human review queue is a first-class feature; rules never auto-promote without analyst approval |
| Open-source forks commoditize the product | Low | Medium | Hosted inference, mutation memory, and Splunk partnership create paid differentiation beyond the code |
| Regulatory friction (HIPAA/FedRAMP requirements) | Low | Medium | Self-hosted deployment means data never leaves customer perimeter — natural compliance story |

---

*PurpleForge — turning detection engineering from a reactive fire drill into a continuously improving, measurably better defense.*
