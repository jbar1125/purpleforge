# PurpleForge — Product Roadmap

*Versioning philosophy: v1 is the current open-source release. Each major version adds a capability layer that expands the addressable market and deepens the competitive moat.*

---

## Current: v1.x — Foundation (✅ Shipped)

**Theme: The closed feedback loop works.**

- Real-time concurrent Red/Blue engine with kill-chain dwell timing
- 11 MITRE ATT&CK techniques across 5 tactics (credential access, lateral movement, persistence, execution, defense evasion)
- Sigma-native rule generation via pySigma → Splunk SPL compilation
- LLM-powered evasion mutation (Groq, Gemini, Ollama, Foundation-sec-1.1)
- Mutation Inferencer: Red learns what Blue's rules watch for
- Rule Registry: health tracking (ACTIVE / DEGRADED / BURNED)
- Human review queue with confidence scoring and Flask UI
- Statistical baseliner + risk scorer + environment whitelist
- LLM data security: PII sanitizer + tamper-evident audit log
- Optional integrations: MITRE Caldera (real attack execution) + CrowdStrike Falcon EDR (blind-spot corroboration)
- ATT&CK Navigator JSON export
- 69 detection-as-code tests
- Splunk MCP Server integration

---

## v2.0 — Multi-SIEM + Rigor (Q3–Q4 2026)

**Theme: Any SIEM. Better rules.**

### Detection Quality Improvements
- **Benign baseline corpus**: Inject Mordor/BOTSv3 realistic benign traffic continuously. Every generated rule is tested for false-positive rate. Rules blocked from promotion if FP rate > 5%.
- **Few-shot + critique loop**: Generator uses 3 exemplar (attack events → rule) pairs as context, then a second LLM call critiques the candidate rule before final output. Substantially improves first-pass rule quality.
- **Tool-use LLM**: Blue's generator gains `splunk_search`, `get_field_values`, and `lookup_sigma_rule` as function-call tools — it can query your actual SIEM for field distributions before writing rules.
- **RAG rule retrieval**: Embed the full Sigma rules corpus (~3,500 rules). On miss, retrieve top-5 most similar Sigma rules by technique + event fields as few-shot examples. Blue's generated rules converge faster with retrieval context.
- **Weighted ATT&CK coverage**: Replace binary coverage % with a weighted F1 score incorporating ATT&CK technique prevalence scores (how often each technique is used in real-world attacks). T1003.001 (LSASS dump → domain compromise) weighs more than T1547.001.

### Platform Expansion
- **Multi-SIEM via pySigma**: Blue generates Sigma YAML; operator selects backend (Splunk, Microsoft Sentinel, Elastic Security, Google Chronicle, IBM QRadar). Same rules, any SIEM.
- **Kill-chain / multi-stage campaigns**: `AdversaryProfile` class defines ordered technique sequences with dependency edges. Blue must detect the chain, not just individual events.
- **30+ technique coverage**: Expand across all 14 ATT&CK tactics — add Initial Access (T1566 phishing, T1190 exploit public-facing), Discovery, Collection, Exfiltration, and C2. ADreach Active Directory log sources (Kerberoasting, AS-REP roasting via EID 4768/4769/4771).
- **Async rule execution**: All Blue detection queries run in parallel (asyncio + Splunk async job submission). Current serial execution (20 rules × 10s = 3+ min/round) drops to ~15 seconds.
- **SQLite checkpoint + replay**: Full run state serialized after each round. Crash-recoverable. Replay mode: skip injection, re-run detection-only against stored events.

---

## v3.0 — Platform + CI/CD Integration (Q1–Q2 2027)

**Theme: Detection rules treated like code.**

### CI/CD Pipeline
- **`purpleforge ci` command**: Integrates into GitHub Actions / GitLab CI. When a detection engineer opens a PR with a new Sigma rule, PurpleForge:
  1. Injects the technique the rule is designed to catch
  2. Runs the rule against injected data
  3. Runs the rule against benign traffic baseline
  4. Blocks the PR if detection rate < 90% or FP rate > 5%
  5. Posts results as a PR comment with ATT&CK coverage delta
- **Rule provenance graph**: SQLite graph of parent rule → mutation → child rule, traceable across sessions. Every rule knows its lineage.

### Multi-Tenant Architecture
- **Cloud deployment**: Hosted PurpleForge instances. Customer provides Splunk API credentials; we run the Red/Blue engine in our cloud, send events to their Splunk.
- **Tenant isolation**: Each customer environment is isolated. Mutation memory, rule registry, and generated rules are per-tenant.
- **MSSP console**: Single pane of glass for MSSPs managing multiple customer PurpleForge environments.

### Cloud + Identity Attack Modules
- **AWS CloudTrail**: T1552.001 (credentials in S3), T1537 (data transfer to cloud), T1548.002 (abuse IAM role), T1530 (data from cloud storage)
- **Azure AD / Entra ID**: T1078.004 (cloud account abuse), T1110.003 (password spray vs. AAD), T1550.001 (app-only auth abuse)
- **Microsoft 365**: T1114.003 (email forwarding rule — already in v1), T1534 (internal spearphishing), T1566.002 (spearphishing link)
- **GCP**: T1562.008 (impair cloud defenses), T1136.003 (cloud account creation)

### Compliance Reporting
- **SOC 2 / ISO 27001 / NIST CSF coverage mapping**: Each ATT&CK technique is cross-referenced to relevant compliance control requirements. Run report includes compliance coverage delta.
- **Executive summary PDF**: Auto-generated post-run report formatted for CISO presentation: before/after ATT&CK heatmap, rules generated, techniques closed, risk reduction in business terms.

---

## v4.0 — Intelligent Agents + Research (H2 2027+)

**Theme: Red and Blue get dramatically smarter.**

### Reinforcement Learning Red Agent
Replace the LLM-based mutator with a proper RL agent:
- **State**: Current Blue ruleset (encoded as embeddings) + prior evasion success rate per technique
- **Action**: Discrete mutation operations (timestamp spread, source IP variance, EventCode variant, alternative tool/LOLBIN)
- **Reward**: +1 evasion (technique dwell exceeded), −0.1 detection (Blue caught it)
- **Algorithm**: PPO with LSTM policy (handles partial observability of Blue's ruleset)

The RL red agent learns an optimal evasion policy specific to each customer's detection stack — simulations are no longer generic; they're calibrated to your exact blind spots.

### GAN-Style Coevolution Mode
- Red = Generator (produces synthetic attack log sequences)
- Blue = Discriminator (classifies attack vs. benign)
- Train in self-play: Blue improves only when Red gets better
- Produces a provably Nash-equilibrium ruleset — no single static attack pattern can systematically evade it
- Academic contribution: first application of GAN-style coevolution to log-based detection engineering

### Public Detection Benchmark Corpus
- Replay publicly released breach telemetry (Mandiant reports, CISA advisories with IOCs) through PurpleForge rulesets
- **Causal coverage metric**: "Would our current ruleset have detected SolarWinds? The Colonial Pipeline intrusion?"
- Differential privacy for sharing: generated synthetic logs that preserve attack patterns without exposing customer telemetry
- Community benchmark: public leaderboard of ruleset quality across techniques

---

## Non-Goals (Explicit)

To maintain focus and competitive clarity, PurpleForge will **not** build:

- A SIEM itself (we augment Splunk, Sentinel, Elastic — we don't replace them)
- A full EDR or endpoint agent (CrowdStrike, Defender, SentinelOne are integrations, not competition)
- A threat intelligence platform (TI feeds are inputs; MISP/Mandiant are partners)
- A SOC ticketing system (ServiceNow, Jira are already in every enterprise; we integrate)
- A phishing simulation platform (KnowBe4, Proofpoint own that segment)

---

## Feedback

The roadmap is driven by customer feedback from design partners. Current most-requested features (from the beta community):
1. Multi-SIEM support (Microsoft Sentinel — #1 request)
2. False positive measurement against benign baseline
3. CI/CD integration for detection rule PRs
4. Executive summary PDF export
5. More cloud attack modules (AWS CloudTrail)

Open an issue at [github.com/jbar1125/purpleforge/issues](https://github.com/jbar1125/purpleforge/issues) to add to the roadmap or upvote existing items.
