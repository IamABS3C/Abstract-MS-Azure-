# How this looks *in Abstract* — fit, unknowns, quick wins, and the market

Companion to [README.md](README.md) (the model) and [samples.md](samples.md) (the data). This
file does three things the others deliberately didn't:
1. Translate the generic model into **Abstract's own constructs** (pipelines, parsers/extractions,
   enrichments, detections, AIG, LakeVilla, routing, AI-enabled SecOps).
2. **Be honest about what we don't know** — assumptions to validate before anyone commits.
3. Flag **cool + cheap-to-build** wins, plus **how the rest of the market** uses WildFire and
   adjacent source classes (TIPs, identity exposure, agentic exposure, cookies/sessions).

> Abstract's public platform pillars: **Collection · Detection · Retention · AI-enabled SecOps**,
> with **AIG** (Abstract Intel Gallery), **LakeVilla** (retention + replay), **ASTRO** (threat
> content + proprietary feed), OCSF normalization, and shift-left in-stream detection. Everything
> below is mapped to those. Where a claim depends on a capability we can't confirm publicly, it's
> marked **[VALIDATE]**.

---

## 1. The model expressed in Abstract primitives

| Pillar | Abstract construct | What it does in *this* model | From the docs |
|---|---|---|---|
| **Collection** | Stream / source connector (Data Flow Management → Streams) | Ingest WildFire, PAN/Strata, IdP, EDR, cloud, email — via native connector **or** the [Event Hub source](../../README.md) this repo builds | samples §1–8 |
| | **Parsers / extractions** | Pull nested IOCs out of WildFire reports & PAN logs (process tree, DNS/TCP/URL arrays, JA3, hashes, MITRE) into fields | samples §1.2–1.3 |
| | **OCSF normalization** | Every source → Detection Finding / Network / DNS / HTTP / Authentication classes | samples §10, README §2 |
| **Detection** | **Enrichments** | In-stream identity/asset/geo/ASN + TI lookups before landing | README §3 |
| | **AIG** | Carries curated feeds + Abstract's proprietary feed **+ WildFire-derived IOCs** as live match inputs | README §5 |
| | **Shift-left detections** | Verdict fusion, IOC blast match, beaconing, ATO↔C2 bridge, lateral/exfil, campaign clustering | README §4 |
| | **ASTRO content** | Pre-built rule packs + ATT&CK-mapped detections | README §4, §6 |
| **Retention** | **LakeVilla** | Full-fidelity normalized telemetry; **replay** = retroactive blast-radius/scoping with no rehydration | README §6, §9 |
| | Routing / destinations | Alerts+context → Sentinel/Splunk/any SIEM; full fidelity → LakeVilla; findings → Event Hub/SOAR | README §9 |
| **AI-enabled SecOps** | MCP server (`mcp__abstract-security__*`) + (Canvas?) | Triage/hunt/loop-closer/tuning/ATO agents over the entity graph | README §8 |

**Reading this table is the answer to "how would it look in Abstract":** the entity model and
detections from README map 1:1 onto Collection→parse/extract→normalize→enrich→AIG-match→detect→
score→route→retain(LakeVilla), with agents reading the result via MCP.

---

## 2. What we don't know — validate before committing

These are the load-bearing assumptions. Each has a concrete way to confirm. **Do not present the
model as built until these are checked** — they change how much is "configure" vs. "engineer."

| # | Open question | Why it matters | How to confirm |
|---|---|---|---|
| 1 | **PAN/WildFire ingestion path** — native Abstract connector, or via Event Hub/syslog bridge / Strata forwarding? | Determines whether §1 collection is config or custom | Check Abstract integrations catalog / AIG for Palo Alto / Cortex / WildFire |
| 2 | **AIG dynamic write-back** — can a *pipeline-generated* IOC list (the §5 loop) be pushed into AIG at runtime via API, or are feeds curated/static only? | The WildFire-loop differentiator depends on it | Confirm AIG has a programmatic feed/list ingest API |
| 3 | **Detection expressiveness** — stateful cross-stream correlation, time-window joins, sequence/sessionization (for beaconing & ATO↔C2 over minutes/hours)? | §4.3/§4.4 need state, not just per-event rules | Review detection rule language / docs / with eng |
| 4 | **Mid-stream external calls** — can a detection/enrichment call WildFire `/get/report` inline, or must enrichment be precomputed (sidecar service feeding AIG)? | Shapes the §5 architecture (inline vs. async loop) | Test enrichment node external-API support + rate-limit handling |
| 5 | **Persistent entity store** — does Abstract keep a durable identity/asset/entity graph, or is correlation only within a streaming window? | "Find every host that ever talked to this C2" needs persistence or replay | Confirm entity persistence vs. window; else lean on LakeVilla replay |
| 6 | **LakeVilla retro-hunt** — can *current* detections re-run over historical data (replay through live workflows), with schema-on-read for new fields? | §6 retroactive scoping depends on it | Validate replay semantics + schema evolution |
| 7 | **What is Abstract Canvas?** — not publicly documented; likely an investigation/correlation surface. Is it the entity-graph UI we want for §6/§8? | Could be the ready-made investigation layer — or not | Ask product; demo it |
| 8 | **MCP server scope** — which tools does it expose (query findings? entities? trigger replays? push IOCs?)? | Defines what agents in §8 can actually do | Enumerate `mcp__abstract-security__*` tools after auth |
| 9 | **Schema coverage** — does `all_fields.json` represent nested arrays (multiple domains/IPs per WildFire report) cleanly for the Sentinel `_CL` table? | Affects mapping fidelity in [Sentinel dest](../../templates/destinations/sentinel-destination.bicep) | Inspect all_fields.json; test DCR with arrays |
| 10 | **Licensing / quotas / Gov** — feed counts, detection limits, multi-tenant, Azure Gov parity | Scopes a real deployment | Product/commercial |

> Honesty note: the README/samples are a *design*, deliberately written against Abstract's public
> capabilities. Items 2, 3, 4, 5 are the ones most likely to move effort from "config" to "build."

---

## 3. Cool + fairly easy to build (ranked by impact ÷ effort)

Effort: **S** = config/content, **M** = light engineering, **L** = real build. Assumes §2 resolves favorably.

| Win | Effort | Why it's cool |
|---|---|---|
| **WildFire verdict → label enrichment** (code 1/4/5 → malware/phishing/C2) | **S** | trivial lookup; instantly makes raw verdicts human/rule-usable |
| **ATO↔C2 shared-IP detection** (samples NL IP `91.219.236.12` in both Okta login *and* WildFire C2) | **S** | one cross-stream join; huge "the controls already told you" demo moment |
| **NRD / DGA / suspicious-TLD scoring** on DNS stream | **S** | cheap entropy/age heuristic; catches C2 staging before payload |
| **"Controls agree" verdict-fusion** finding + risk score | **S–M** | collapses 3 tools' manual correlation into one alert; kills fatigue |
| **WildFire-IOC auto-matchlist into AIG** (the §5 loop) | **M** | the real differentiator; report IOCs convict the *next* host automatically |
| **Stealer-log / stolen-cookie matchlist** (identity exposure feed → match auth + session streams) | **M** | pre-empts ATO from infostealers; ties to §6 below |
| **ATT&CK coverage rollup** from WildFire/EDR technique tags | **S** | free dashboard; shows detection gaps to leadership |
| **Pre-built Sentinel + Splunk dashboards** off the normalized table | **S** | same model, both SIEMs; proves destination-agnostic claim |
| **MCP triage agent** that returns subgraph + blast radius for a finding | **M–L** | the AI-SecOps story; gated on §2 item 8 |

**If you do only three for a demo:** verdict→label, ATO↔C2 shared-IP, and the AIG WildFire loop.
The first two are nearly free and land emotionally; the third is the defensible IP.

---

## 4. How the market uses WildFire and adjacent sources (references + where Abstract wins)

### 4.1 Security Data Pipeline Platforms (the direct peer set)
**Cribl** (Stream — lookups, Redis, GeoIP, DNS enrichment; schema-drift detection coming),
**DataBahn** (AI normalization to OCSF/CIM/UDM/ASIM/LEEF, STIX/TAXII enrichment, autonomous
connector generation, in-stream data protection — RSAC 2026), **Tarsal, Observo AI, Tenzir,
Monad, Auguria, Chronosphere**. Forrester now treats DPM as a category SOCs need.

- **What they mostly do:** plumbing — filter/parse/enrich/route/reduce to cut SIEM cost. TI
  enrichment is largely **lookup/tagging** (add a reputation field), not in-stream *detection*.
- **Where Abstract differentiates:** **shift-left detection** (decisions in-stream, not just
  enrichment) + **AIG** (intel operationalized as live match input, incl. the WildFire loop) +
  **LakeVilla replay** (retro-hunt without rehydration) + **ASTRO** content. The model in this
  folder leans on all four — a pure pipe can enrich a WildFire verdict but can't *fire and scope*
  on it pre-landing.

### 4.2 How WildFire specifically gets used today
- **Cortex XSOAR / XSIAM playbooks:** detonate, pull verdict/report, run a response playbook.
  Reactive, per-incident.
- **Splunk PAN add-on / SIEM correlation:** ingest threat logs, correlate after landing.
- **TIPs (Anomali, ThreatConnect, Recorded Future, ThreatQ, OpenCTI, MISP):** ingest WildFire
  IOCs as a feed, normalize to STIX, dedupe/score, redistribute to enforcement.
- **The gap nearly everyone leaves open:** treating the **WildFire *report* IOCs as a live,
  pre-landing stream matchlist across *all* other sources.** Most consume the *verdict* as an
  alert; few operationalize the *report* as continuous intel. **That's Abstract's opening** (§5).
  Think of **AIG as a TIP operationalized inside the pipeline** rather than a sidecar that emails
  IOCs to a SIEM.

### 4.3 Identity Exposure (a source class to add)
- **Leaked-credential / stealer-log feeds:** SpyCloud, Have I Been Pwned, Hudson Rock, Flare,
  Enzoic. **ITDR:** Microsoft Entra ID Protection, CrowdStrike Falcon Identity, Okta ITP, Push
  Security; AD attack-path: Semperis, SpecterOps BloodHound.
- **In this model:** exposure feeds become an **AIG list of compromised principals/passwords**,
  matched against IdP auth streams (samples §5) → pre-ATO warning. Slots straight into the §4.4
  ATO bridge. Effort **M**, very high resonance.

### 4.4 Cookies / session theft (the modern ATO without a password)
- **Why it matters:** AiTM phishing (Evilginx) and infostealers steal **session cookies/tokens**,
  bypassing MFA entirely. Stealer logs *contain* cookies. Vendors: Push Security, SpyCloud
  (session identity), Microsoft (token protection), Flare/Hudson Rock (stealer-log cookies).
- **In this model:** stolen-session indicators → AIG list → match against IdP session events
  (impossible travel / reused session ID / new-ASN session) → **session-hijack detection**
  even with no failed login. Pairs with §4.4 and the stealer-log win in §3. Effort **M**.

### 4.5 Agentic Exposure (bleeding edge — high "cool", high uncertainty)
- **The emerging problem:** non-human / agent identities (NHI), MCP tool sprawl, prompt-injection,
  over-permissioned agents. Vendors: Astrix Security, Token Security, Entro, Clutch; Microsoft
  **Entra Agent ID** (there's even an `azure:entra-agent-id` skill in this workspace).
- **In this model:** treat **agents/NHIs as first-class entities** alongside User/Host/Account
  (README §1) — monitor agent *actions* (tool calls, data access, token exchanges) as a stream,
  apply the same enrichment/detection (anomalous tool use, agent talking to a WildFire C2,
  exfil via an agent). **[VALIDATE]** heavily — this is greenfield; few do it well, which is
  exactly why it's a differentiator worth scoping. Effort **L**, but the *entity-modeling* of
  agents is **S–M** and a strong forward-looking demo.

---

## 5. Executive framing (the one-slide version)

> **Collection:** every source — WildFire to stealer logs to agent actions — normalized to OCSF.
> **Detection:** shift-left, in-stream, controls-agree fusion + the WildFire intelligence loop, so
> threats are caught and scoped *before* they land. **Retention:** LakeVilla holds full fidelity
> cheaply and lets you replay history against today's detections. **AI-enabled SecOps:** agents
> over the entity graph triage, hunt, and close the intel loop. Same model lands in Sentinel,
> Splunk, any SIEM, or LakeVilla — **destination is a cost choice, not a capability choice.**

---

### Sources
- [Shift-Left Detections with Abstract](https://www.abstract.security/blog/shift-left-detections-with-abstract)
- [What is an SDPP? — Abstract](https://www.abstract.security/blog/what-is-a-security-data-pipeline-platform-sdpp-and-why-do-security-teams-need-one)
- [LakeVilla launch](https://www.prnewswire.com/news-releases/abstract-security-launches-lakevilla-scalable-searchable-and-cost-efficient-cold-storage-for-security-telemetry-302489318.html)
- [Market Guide 2025: Rise of Security Data Pipelines](https://softwareanalyst.substack.com/p/market-guide-2025-the-rise-of-security)
- [DataBahn — autonomous in-stream data intelligence](https://www.databahn.ai/press-releases/databahn-advances-security-data-pipeline-with-autonomous-in-stream-data-intelligence)
- [Forrester — you need Data Pipeline Management](https://www.forrester.com/blogs/if-youre-not-using-data-pipeline-management-dpm-for-security-and-it-you-need-to/)
- [Abstract + Netskope — real-time stream detection](https://siliconangle.com/2026/01/28/abstract-security-partners-netskope-bring-real-time-detection-security-data-streams/)
