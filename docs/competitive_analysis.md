# PurpleForge — Competitive Analysis

## Market Context

PurpleForge sits at the intersection of two established security market categories:

1. **Breach and Attack Simulation (BAS):** Automated adversary emulation to test security controls. Market leaders: AttackIQ, Cymulate, SafeBreach. Market size: $5.5B (2025), projected $305.6B by 2031 at 33.6% CAGR.

2. **Detection Engineering / SIEM content management:** Building and maintaining the detection logic that makes SIEMs useful. Players: CardinalOps, Anvilogic, Panther, Prelude Security. Less consolidated; most organizations still do this manually.

PurpleForge creates a **new sub-category** that BAS tools don't cover: *continuous adversarial detection improvement* — not just "did it get through?" but "it got through; here's the new rule that catches it; here's the proof the rule works."

---

## Competitor-by-Competitor Analysis

### AttackIQ

**What it does:** BAS platform focused on MITRE ATT&CK control validation. Runs attack simulations and scores your controls (firewalls, EDR, SIEM) against ATT&CK technique coverage.

**Pricing:** Custom enterprise quotes. Estimated $50,000–$200,000+/year for mid-market. Not publicly disclosed.

**Strengths:**
- Deep ATT&CK mapping; co-developed MITRE ATT&CK evaluations methodology
- Strong brand in enterprise security
- Broad integration library (200+ security controls)
- FireDrill continuous validation feature

**Weaknesses:**
- Measures detection coverage; does **not** generate new detection rules
- Output is a report/dashboard, not a fixed ruleset
- No feedback loop between what Red does and what Blue learns
- Expensive; inaccessible to mid-market without enterprise sales cycle
- No Sigma output; control-agnostic scoring doesn't translate to SIEM rule improvement

**PurpleForge vs. AttackIQ:** AttackIQ tells you what you missed. PurpleForge fixes what you missed. An AttackIQ customer still has to hire a detection engineer to translate the report into new SPL/Sigma rules. PurpleForge generates those rules automatically and tests them in the same run.

---

### Cymulate

**What it does:** Continuous security validation platform. Runs attack scenarios across 8 attack vectors (email gateway, web gateway, endpoint, lateral movement, etc.) and scores control effectiveness.

**Pricing:** Publicly disclosed — **$7,000 for a month-long bundle up to $91,000/year** for the full platform. One of the few BAS vendors with published pricing.

**Strengths:**
- Same-day deployment (SaaS, no on-prem agent required)
- Broad attack vector coverage
- Daily threat intelligence updates
- Strong compliance reporting (NIST, ISO 27001, PCI DSS mapping)
- Purple team module with collaborative workflow

**Weaknesses:**
- Detection content is proprietary to Cymulate's platform — no Sigma export
- Does not generate SIEM detection rules
- Purple team module is manual (facilitates analyst review, doesn't auto-generate rules)
- SIEM coverage analysis is a report, not a closed feedback loop
- Price point still requires procurement cycle; not developer-friendly

**PurpleForge vs. Cymulate:** Cymulate's $91,000/year plan has no automated rule generation and no Sigma output. PurpleForge's $54,000/year Enterprise tier includes both. More importantly, Cymulate's output is a report that requires manual follow-through. PurpleForge's output is a working ruleset, automatically generated and tested.

---

### SafeBreach

**What it does:** BAS platform with a large "Hacker's Playbook" of 35,000+ simulations. Focuses on security control validation and breach risk quantification.

**Pricing:** Not publicly disclosed. Industry estimates: $60,000–$300,000+/year depending on scale.

**Strengths:**
- Large simulation library (35,000+ attack scenarios)
- Risk quantification in dollar terms (translates coverage gaps into business risk)
- Strong enterprise sales motion and customer success
- CrowdStrike, Palo Alto, CrowdStrike integrations

**Weaknesses:**
- No automated rule generation
- No Sigma or SIEM-specific output
- Extremely expensive; primarily targets Fortune 500
- No open-source / community tier; zero developer adoption
- No adaptive/coevolutionary element — simulations are static

**PurpleForge vs. SafeBreach:** SafeBreach is a compliance and executive reporting tool. PurpleForge is a detection engineering tool. Different buyers, different use cases. A CISO buys SafeBreach for the board presentation. A detection engineer buys PurpleForge to actually fix the gaps SafeBreach found.

---

### CardinalOps

**What it does:** Detection posture management — analyzes your existing SIEM rules, maps them to ATT&CK, identifies coverage gaps, and provides recommendations.

**Pricing:** Not publicly disclosed. Enterprise-focused; estimated $80,000–$150,000+/year.

**Strengths:**
- Deep analysis of existing rule quality (identified the "13% non-functional rules" finding)
- Integration with all major SIEMs (Splunk, Sentinel, QRadar, Chronicle)
- Multi-SIEM normalization
- Strong research credibility (annual ATT&CK coverage report is industry-cited)

**Weaknesses:**
- Analysis and recommendations only — does **not** write new detection rules
- Does not simulate attacks; coverage assessment is static, not adversarially tested
- Cannot close gaps automatically
- Does not verify that generated rules actually work (no simulation component)
- Expensive; no self-service

**PurpleForge vs. CardinalOps:** CardinalOps diagnoses the coverage problem. PurpleForge diagnoses and treats it. A CardinalOps customer learns "you're missing T1003.001" and still has to go write the rule. PurpleForge learns "you missed T1003.001 in round 3" and generates the rule in round 4. The 79% coverage gap statistic comes from CardinalOps' own research — they identified the problem PurpleForge solves.

---

### Anvilogic

**What it does:** Multi-SIEM detection engineering platform — detection content management, ATT&CK coverage tracking, and a library of pre-built detections.

**Pricing:** Not publicly disclosed. Enterprise SaaS.

**Strengths:**
- Multi-SIEM support (Splunk, Sentinel, Elastic, Chronicle)
- Large pre-built detection content library
- Detection-as-code workflow with version control
- Coverage measurement across SIEM environments

**Weaknesses:**
- Pre-built detection library, not adaptive/generated based on your environment
- No adversarial simulation — no Red agent to test the rules
- No feedback loop; gaps are identified but not automatically addressed
- Coverage measurement is static (not adversarially validated)

**PurpleForge vs. Anvilogic:** Anvilogic provides detection content; PurpleForge generates detection content through adversarial pressure and validates it before promotion. The key difference: Anvilogic's rules are written for a generic environment; PurpleForge's rules are generated in response to attacks that actually evaded *your* detection stack.

---

### Prelude Security

**What it does:** Open-source adversary emulation platform (Prelude Operator). Focused on red team automation and adversary emulation.

**Pricing:** Open-source core; Prelude Enterprise (custom pricing).

**Strengths:**
- Strong open-source credibility
- CALDERA integration (MITRE-backed)
- Used by actual red teams
- Good technique coverage

**Weaknesses:**
- Red-team-focused; no Blue agent or detection improvement component
- No SIEM integration out of the box
- No automated rule generation
- No coverage measurement
- Primarily a red team tool, not a purple team platform

**PurpleForge vs. Prelude:** Different tools for different jobs. Prelude is for red teams doing adversary emulation. PurpleForge is for blue teams (or purple teams) improving detection. PurpleForge actually uses Caldera (the MITRE project Prelude is based on) as an optional integration for real attack execution.

---

## Positioning Map

```
                         FIXES DETECTION GAPS
                                 ↑
                                 │
                    PurpleForge  │
                        ★        │
                                 │
    ←──────────────────────────────────────────────→
    STATIC ANALYSIS               ADVERSARIAL TESTING
    (CardinalOps, Anvilogic)      (AttackIQ, Cymulate, SafeBreach)
                                 │
                                 │
                                 │
                         REPORTS ONLY
                                 ↓
```

PurpleForge is the only tool in the top-right quadrant: adversarial testing + automatic gap remediation.

---

## Key Differentiators (Summary)

| Capability | PurpleForge | All competitors |
|-----------|-------------|----------------|
| Automatic Sigma rule generation on miss | ✅ | ❌ |
| Red adapts to Blue's active rules | ✅ | ❌ |
| Closed coevolutionary feedback loop | ✅ | ❌ |
| Sigma-native output (multi-SIEM portable) | ✅ | ❌ or partial |
| Detection-as-code unit test harness (69 tests) | ✅ | ❌ |
| EDR blind-spot corroboration | ✅ | ❌ |
| Kill-chain timing (did it succeed before detection?) | ✅ | ❌ |
| Open-source Community tier | ✅ | ❌ (except Prelude) |
| Self-hosted (data stays in your perimeter) | ✅ | ❌ (mostly cloud) |
| Starts at $0 | ✅ | ❌ |

---

## Emerging Threats to Watch

**Microsoft Security Copilot** is adding detection rule generation features. Microsoft's advantage: native Sentinel integration, huge installed base. Risk to PurpleForge: if Copilot adds a Red agent and feedback loop, the moat narrows in the Sentinel segment. **Mitigation:** Multi-SIEM support (v2 roadmap) makes PurpleForge SIEM-agnostic; Microsoft's tools will always prioritize Sentinel.

**Wiz / Orca / Tenable** are expanding from posture management into active validation. These tools reach the same buying center (security executives) but from a cloud/vulnerability angle. Low overlap today; could converge in 2–3 years.

**Vendor-native BAS** (CrowdStrike's BAS module in Falcon, Palo Alto's Cortex Attack Surface Management) is a feature bundled with EDR/XDR platforms. Risk: organizations on CrowdStrike get basic BAS "for free" with their existing contract. **Mitigation:** These are shallow integrations (limited to the vendor's own detection logic); PurpleForge works across any SIEM and generates portable Sigma rules.
