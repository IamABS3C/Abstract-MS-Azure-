# Abstract Security × Microsoft Sentinel — Integration Profile

> SIEM is a state of mind. Abstract is the world's first Composable SIEM — assemble collection, detection, retention and AI-SecOps by design, not by lock-in.

A reusable SE / evaluation asset describing the **transparent, bidirectional** Abstract↔Sentinel integration — how they connect, where they overlap or complement, and a low-risk augment→optimize→rebalance path. Machine-readable companion: [`abstract-sentinel-integration-profile.json`](abstract-sentinel-integration-profile.json).

**Positioning:** Abstract is the world's first Composable SIEM (collection · detection · retention · AI-SecOps); Microsoft Sentinel is one composable component you keep, augment, or rebalance.

## Deployment modes

| Mode | Mechanism | Use when |
| --- | --- | --- |
| **Abstract → Sentinel (destination)** | Azure Monitor Logs Ingestion API (DCE/DCR) into AbstractEventLogs_CL | Sentinel is a destination for Abstract-normalized findings + context. |
| **Abstract → Sentinel (insights API pull)** | Scheduled Logic App pulls insights/verdicts into AbstractInsights_CL via the Log Analytics Data Collector API | Sentinel is NOT the raw-telemetry destination but you still want Abstract insights/detections in Sentinel for side-by-side comparison. |
| **Sentinel → Abstract (API loop-back)** | SOAR playbooks call the Abstract API (verdict, search, tune-at-source) + Security Copilot plugin/agent + MCP | Triage in Sentinel and act on the pipeline in Abstract (bidirectional). |

## Change the game — the Composable SIEM Manifesto

*[The Composable SIEM Manifesto](https://www.abstract.security/manifesto) — Abstract Security*

“SIEM is a state of mind.” Not a box, not a single vendor — an organizational philosophy of adaptability, modularity, and choice. Abstract built the world's first **Composable SIEM**: collection, detection, retention, and AI-enabled security operations as independent, interoperable building blocks you assemble by design — with Microsoft Sentinel as one composable component you keep, augment, or rebalance.

**Tenets:**
- **Next-Gen SIEM is not a SIEM** — The true next generation breaks the monolith — it isn't a glorified log store with a new coat of paint.
- **Cut waste before storage** — Detect in the stream, before data becomes expensive, rigid, or locked in. Prioritize signal over noise, outcomes over ingestion volume.
- **Escape the data swamp** — Most collected security data is never used for detection. Store data intelligently — right data, right tier, right place — not everything in one indexed box.
- **AI is baked in, not bolted on** — Born in the AI era: AI-GEN is stream-first and composable by design. Without normalized, streaming, contextual data, AI is blind, shallow, and late.
- **AI-SOC is a capability, not a category** — Like SOAR before it, AI-SOC collapses into the fabric. AI augments SIEM across triage, investigation and response — it doesn't replace it.
- **Composable means intentional assembly** — Not fragmented, not complex — an architecture of choice. Pick components and vendors per outcome, evolve incrementally, no forced re-architecture.

**Four building blocks (assembled by design, not lock-in):**

| Block | | What | With Sentinel |
| --- | --- | --- | --- |
| **Collection** | The Security Data Fabric | The control plane where data is shaped, normalized and enriched before it becomes expensive or locked in — feeding many downstream systems, not one monolith. | Feeds Sentinel (and any SIEM) clean, enriched, cost-reduced data via the destination + insights connectors. |
| **Detection** | Signal at Speed | Portable detection logic — in-stream, historical, and federated — that runs where the data lives. Detection is no longer bound to storage. | Complements Sentinel analytics: shift-left convictions arrive as high-fidelity insights; Sentinel rules still run on what lands. |
| **Retention** | Context at Scale | Tiered + federated storage: high-signal data near detection, everything else affordable and still query-ready (LakeVilla, replay, no rehydration). | Route full fidelity to LakeVilla, send only convictions + context to Sentinel's hot tier — the big cost lever. |
| **AI-SecOps** | AI-Enabled Security Operations | AI embedded across triage, investigation, hunting and response — ASTRO enabling analysts, not replacing them, over pipeline-clean data + context. | ASTRO auto-triages and reasons; results flow back to Sentinel incidents via playbooks, Copilot and MCP. |

## The numbers behind the problem (cited)

| Stat | What | Why it matters | Source |
| --- | --- | --- | --- |
| **79%** | of MITRE ATT&CK techniques enterprise SIEMs miss | You pay to ingest data that never becomes a detection — CardinalOps found the data already ingested could cover 90%+. Abstract turns telemetry into detections in-stream. | [CardinalOps, 5th Annual State of SIEM Detection Risk, 2025](https://www.prnewswire.com/news-releases/enterprise-siems-miss-79-of-mitre-attck-techniques-used-by-adversaries-according-to-cardinalops-5th-annual-report-302473779.html) |
| **83%** | of SOC alerts are false positives | Abstract collapses repetitive/benign events upstream and auto-triages with ASTRO — analysts see signal, not noise. | [Vectra AI, 2023 State of Threat Detection (n=2,000 analysts)](https://www.vectra.ai/resources/2023-state-of-threat-detection) |
| **67%** | of daily alerts go unaddressed | Fewer, higher-fidelity insights mean the queue is workable — not a backlog nobody can clear. | [Vectra AI, 2023 State of Threat Detection](https://www.vectra.ai/resources/2023-state-of-threat-detection) |
| **4,484** | alerts hit the average SOC per day | Pipeline aggregation/dedupe (demo ~34:1) cuts the raw flood before it becomes alerts. | [Vectra AI, 2023 State of Threat Detection](https://www.vectra.ai/resources/2023-state-of-threat-detection) |
| **14 days** | median attacker dwell time | Shift-left detection (~0.5s) shrinks time-to-detect vs. ingest-then-schedule SIEM latency. | [Mandiant / Google Cloud, M-Trends 2026 (2025 data)](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026) |
| **29 min** | average eCrime breakout time (fastest 27 sec) | When lateral movement takes minutes, detecting after ingest+schedule is too slow — detect in-stream. | [CrowdStrike, 2026 Global Threat Report](https://www.crowdstrike.com/en-us/global-threat-report/) |
| **$4.44M** | average cost of a data breach — 241 days to identify + contain | Cost falls when you detect and contain faster; IBM attributes the 2025 drop to AI-driven defenses. Shift-left detection + ASTRO triage shrink that window. | [IBM, Cost of a Data Breach 2025](https://www.ibm.com/reports/data-breach) |
| **4.8M** | global cybersecurity workforce gap | You can't hire your way out — reclaim capacity by removing false-positive toil upstream. | [ISC2, 2024 Cybersecurity Workforce Study (latest published gap figure)](https://www.isc2.org/Insights/2024/09/ISC2-Publishes-2024-Cybersecurity-Workforce-Study-First-Look) |
| **64%** | of analysts spend >half their time on manual work | Auto-triage + tune-at-source give that time back to real investigation. | [Tines, Voice of the SOC Analyst 2022](https://www.tines.com/reports/voice-of-the-soc-analyst/) |
| **63%** | of security pros report burnout | Less noise, less swivel-chair — a pipeline that lands decision-ready insights protects the team. | [Tines, Voice of the SOC 2023](https://www.tines.com/reports/voice-of-the-soc-2023/) |

## What lands on day one — Abstract's shipped content portfolio

*Abstract content-packs portfolio — internal SE Source Value Guide (Jun 2026)*

| Metric | Value |
| --- | --- |
| supported source content packs | **141** |
| curated, MITRE-mapped detections (maintained as content) | **1,153** |
| streaming pipeline functions (shape + reduce in flight) | **591** |
| pre-built analytic views / dashboards | **27** |
| avg data reduction per pack (range 10–75%, n=105) | **~34.5%** |
| MITRE ATT&CK tactics covered out of the box | **13 / 13** |

## Abstract's own published claims (first-party / self-reported)

- **70–80%** — average data-volume reduction Abstract reports. By filtering on “actionable relevance and risk,” not blindly dropping events. ([source](https://www.abstract.security/use-cases/reduce-data-volume-costs))
- **10–15%** — of security telemetry actually drives detection & real-time analytics (Abstract). The other ~85–90% can live in low-cost, query-ready cold storage (LakeVilla) — no rehydration, no retrieval fees. ([source](https://www.abstract.security/blog/introducing-abstract-lakevilla-pipeline-powered-analyst-ready-and-efficient-storage))
- **“data volume, not data value”** — Abstract's own SIEM-cost framing. “Your SIEM bill is driven by data volume, not data value.” — the case for aligning spend with reduction. ([source](https://www.abstract.security/use-cases/reduce-data-volume-costs))

## Why Abstract + Sentinel win together

- **Cut SIEM cost at the source** — Abstract aggregates, dedupes, filters and routes upstream — the SIEM bill is volume-driven, so cutting volume before ingest cuts the bill. Demo: ~34:1 aggregation and ~99.6% volume routed away from the SIEM.
- **Shift-left detection** — Six in-stream detections (verdict fusion, IOC blast-match, beaconing/C2, ATO↔C2 bridge, lateral/exfil, campaign clustering) fire in ~0.5s — before data lands — vs. SIEM ingest+schedule latency.
- **100% enrichment, upstream** — A 5-step in-stream chain (identity/asset resolution, geo/ASN, TI/AIG IOC match, 29+ OSINT adapters, verdict fusion) enriches every event before it lands. The SIEM receives conclusions, not raw noise.
- **ASTRO — the AI SOC engine** — ASTRO is Abstract's AI security engineer, embedded natively in the platform — not a generic chatbot. It runs agentic triage, investigation and detection-tuning over pipeline-clean, correlated, enriched data and full case context: a grounded verdict + recommended actions before an analyst opens the case (e.g. Verdict, IP Threat Intelligence) — and considerably more.
- **Compliance handled in-stream** — Abstract states it detects and redacts PII in-stream (GDPR/HIPAA/PCI) before data lands anywhere, and normalizes to OCSF, ECS or Splunk CIM — so the same clean data fits any destination and sensitive fields never hit the SIEM.
- **Destination- & source-agnostic — less lock-in** — Normalize once to OCSF/ACS (473 fields); route the same events, detections and findings to Sentinel, Splunk, any SIEM, Event Hub, or LakeVilla. Pick destinations per-cost, not per-capability.
- **Retroactive hunts without rehydration** — Full-fidelity telemetry lives in LakeVilla, always query-ready; replay a new IOC through live detections across 90+ days to find historical victims — no SIEM archive rehydration cost.
- **Microsoft is validating the model** — Microsoft's own moves — Auxiliary/Basic logs tiers, the Sentinel data lake, and Defender XDR correlation — validate cheap tiered storage and pre-SIEM curation. Abstract does it upstream and vendor-agnostic, so the savings and the detections travel with you across SIEMs, not just within one.

## Better together — or better without

**Lean “better together” when:**
- Microsoft-heavy estate — Defender XDR, Entra, M365 already correlate in Sentinel.
- Compliance, reporting and IR runbooks are standardized in Sentinel today.
- The team is fluent in KQL and Sentinel content and wants uplift, not change.
- Goal is higher fidelity + AI-SOC (ASTRO) + cost relief with zero disruption.
- You want a fast, reversible win to prove value before any bigger decision.

**Lean “better without / rebalance” when:**
- SIEM spend is the pain — a volume-driven bill growing faster than the security value.
- Multi-SIEM / multi-cloud / vendor-neutral mandate; avoiding lock-in is strategic.
- Retention-heavy (long compliance windows) — hot-tier-everything doesn't scale.
- Noisy high-volume sources (firewall, DNS, proxy, flow) dominate ingestion.
- Migrating off a legacy or over-priced SIEM — you want a durable pipeline layer first.

**Use-case → posture:**

| Use case | Posture | Why |
| --- | --- | --- |
| Microsoft-centric SOC, Sentinel is home | together | Route Abstract findings + context into Sentinel; add ASTRO verdicts and tune-at-source. Keep everything you have, raise fidelity, trim noise. |
| Runaway SIEM ingest cost | hybrid | Send convictions + context to Sentinel, full fidelity to LakeVilla. Volume-based bill drops sharply (demo: ~99.6%) with no loss of hunt coverage. |
| Multi-SIEM / M&A / vendor-neutral | rebalance | Normalize once, fan out to Sentinel, Splunk, any SIEM simultaneously. Run a bake-off or consolidate without re-onboarding sources. |
| Long-retention compliance | hybrid | Keep multi-year full-fidelity in an always-queryable cold tier with replay; send only what the SIEM needs to the hot tier. |
| Legacy/over-priced SIEM migration | rebalance | Stand up the pipeline first; detections + normalization live in Abstract, so the SIEM becomes a swappable, per-cost destination and migration is low-risk. |
| Building an AI/agentic SOC | together | Feed agents decision-ready insights + an entity graph via API/MCP; Sentinel + Copilot and ASTRO operate on signal, not raw log soup. |

## Future-proof

- **Own your data gravity** — Normalizing to OCSF upstream means your detections, enrichment and history aren't trapped in one SIEM's schema. When the market shifts — new SIEM, new tier, new owner — your security logic travels with you instead of being rewritten.
- **AI-ready by construction** — Agentic SOC needs clean, correlated, enriched, entity-resolved data — not raw log soup. Abstract lands decision-ready insights + a queryable entity graph, and exposes them to agents via API/MCP, so ASTRO and your own AI stack operate on signal, not noise.
- **Ride Microsoft's own roadmap without the lock-in** — Microsoft's own Sentinel data lake (GA Oct 2025) and Basic/Auxiliary tiers price cheap storage at ~$0.05/GB vs. ~$4.30/GB for Analytics — proof of the pre-SIEM-curation thesis Abstract already delivers. Abstract lets you apply that economics upstream and across every SIEM you run, not just inside one.
- **Retention economics that scale with regulation** — As retention mandates grow, hot-tier-everything doesn't scale. Full-fidelity in an always-queryable cold tier (LakeVilla) with replay lets you satisfy multi-year retention and still hunt it — without multiplying SIEM ingest.
- **One model across a consolidating estate** — M&A, multi-cloud and tool consolidation are constant. A vendor- and destination-agnostic pipeline lets you absorb new sources and route to new destinations without re-onboarding or rewriting content each time.

## Positioning POV (our point of view — not a benchmark)

- **Speed vs. scale** — Abstract is pipeline-native and focused — one hard problem, solved deeply, shipped fast. A hyperscaler bundles the SIEM into a vast platform and ships on platform time; a focused vendor iterates on pipeline economics and detections at startup speed.
- **Incentive alignment** — A per-GB SIEM earns more the more you ingest — the opposite of your cost goal. A pipeline earns by making your data smaller and smarter. Align spend with a vendor whose incentive is your reduction, not your volume.
- **Neutral by design** — Abstract is Switzerland for security data — it doesn't need you all-in on one cloud or SIEM. That neutrality is the hedge: detections, normalization and history stay portable however the platform market shifts.
- **Focused roadmap** — Pipeline, cost, fidelity and AI-SOC are the whole roadmap here — not line items competing with hundreds of other platform priorities. Requests land with the team that owns the problem end to end.
- **Adopt the future without betting the SOC** — Because it's additive and reversible, put Abstract in front of Sentinel today and decide augment-vs-replace later — moving as fast as your risk tolerance allows, not as fast as a migration forces.

## Capability gap analysis — SIEM vs. Security Data Pipeline

| Dimension | Microsoft Sentinel (SIEM) | Abstract Security (Pipeline) | Why it matters |
| --- | --- | --- | --- |
| **Primary role** | Cloud-native SIEM/SOAR — detect, investigate, respond over *ingested* data. | Security data pipeline — normalize, enrich, correlate, detect and route *before* ingest (shift-left). | They occupy different layers: a pipeline in front of a SIEM is complementary, not a like-for-like swap. |
| **Cost model** | Priced per GB ingested + retention; cost scales with raw volume (unified Analytics ~$4.30/GB PAYG, East US; commitment tiers save up to 52%). | Reduce/aggregate/route before ingest; Abstract reports 70–80% volume reduction (demo here: ~34:1 aggregation, ~99.6% routed off the SIEM). | The SIEM bill is a volume bill. Cutting volume at the source is the largest, most durable cost lever. |
| **Volume handling** | Ingests what you send; limited native dedup/aggregation. | Aggregation, dedupe, filtering and down-sampling in-stream (aggregation_count on every record). | Most SIEM volume is repetitive/benign; collapsing it upstream is pure savings + less analyst noise. |
| **Storage & retention** | Tiered: Analytics ~$4.30/GB, Basic $0.50/GB, Auxiliary $0.05/GB (+$0.10 processing), and the data lake (GA Oct 2025) ~$0.05/GB ingest + $0.026/GB-mo — but tiering + retention are managed inside the SIEM, per source. | LakeVilla full-fidelity cold tier, always query-ready; replay with no rehydration, decided upstream and independent of any SIEM. | Keep everything affordably and still hunt it retroactively — and your tiering decision isn't locked to one SIEM's pricing. |
| **Normalization** | ASIM, applied post-ingest with per-source parsers. | OCSF + Abstract Common Schema (473 fields), normalized once in-stream before landing. | Normalize-once means the same detections/queries work across any vendor's data. |
| **Detections** | Scheduled analytics rules over already-ingested data. | Six shift-left in-stream detections at ~0.5s (verdict fusion, IOC blast-match, beaconing, ATO↔C2, lateral/exfil, campaign clustering). | Detecting before ingest shortens time-to-detect and avoids paying to store what you were going to alert on anyway. |
| **Enrichment** | TI/enrichment via connectors + playbooks, post-ingest. | 5-step in-stream enrichment (identity/asset, geo/ASN, TI/AIG, 29+ OSINT adapters, verdict fusion) — 100% coverage. | Enriched-at-landing data means higher-fidelity detections and less swivel-chair during triage. |
| **Identity & entity model** | UEBA add-on; entities scoped per incident. | Cross-source identity/entity graph (10 entity types) with cumulative risk scoring across products. | Cross-product identity risk is a signal a per-incident SIEM view rarely assembles on its own. |
| **AI SOC** | Security Copilot — a prompt-based assistant (add-on) layered on the SIEM. | ASTRO — an AI security engineer embedded in the platform — auto-triages, investigates and tunes detections over pipeline data + case context (Verdict, IP Threat Intelligence, and more). | Auto-triage + recommended actions reach the analyst with the case, not after they start digging. |
| **Insights vs. raw alerts** | Raw alerts → incidents; analysts triage the noise. | Correlated, verdicted insights (finding + context); noise collapsed upstream. | Fewer, richer, decision-ready items lowers alert fatigue and mean-time-to-decision. |
| **Noise tuning** | Tune rules post-ingest — you still pay to ingest the noise. | rule-tuning-filters down-sample the pattern *upstream* (tune-at-source loop). | A false-positive disposition permanently lowers *future* ingest AND future incidents — not just this one. |
| **Source & destination agnostic** | Microsoft-centric; strongest with Microsoft sources. | OCSF pipeline routes the same model to Sentinel, Splunk, any SIEM, Event Hub, LakeVilla. | Heterogeneous / M&A estates get one model; destinations become a per-cost choice. |
| **Vendor lock-in** | Data + detections live in the SIEM; switching = re-onboarding sources and rewriting content. | Pipeline decouples sources from the SIEM; portable normalization + detections; SIEM is a swappable destination. | Decoupling protects negotiating leverage and makes future platform changes low-risk. |
| **SOAR & automation cost** | Logic Apps playbooks bill per action; automation volume scales with incident/alert volume. | Fewer, higher-fidelity insights + upstream tune-at-source mean fewer incidents to automate against. | Cutting incident volume upstream lowers both SIEM ingest AND downstream automation spend. |
| **Multi-SIEM / multi-cloud** | One workspace is the destination; multi-SIEM or migration means re-onboarding sources. | Fan out the same normalized events + findings simultaneously — Abstract lists Sentinel, Splunk, AWS Security Lake, CrowdStrike NG-SIEM, Elastic, Google SecOps, Cortex XSIAM and SentinelOne as destinations. | Run a bake-off, support M&A/mixed estates, or migrate with no source re-onboarding. |
| **Compliance & PII** | Masking/redaction configured post-ingest or via connectors; sensitive data can land before it's handled. | Abstract states PII is detected and redacted in-stream (GDPR/HIPAA/PCI) before data reaches any destination. | Sensitive fields never hit the SIEM in the clear — compliance handled upstream, not after landing. |
| **Onboarding & upkeep** | Per-source connectors + ASIM parser upkeep as sources and schemas change. | Normalize once to OCSF/ACS upstream; new sources map once and every downstream query still works. | Less parser/rule maintenance as the estate changes — engineering time back to the SOC. |
| **Deployment relationship** | Terminal destination for data. | Bidirectional: feeds Sentinel (destination) AND reads back via API (verdict, search, tune-at-source). | Transparent two-way integration — augment today, rebalance later, on your timeline. |

## Augment → optimize → rebalance

- **Stage 1 — Augment (this solution)** — Keep Sentinel exactly as-is. Route Abstract findings + enriched context in via the destination connector; pull insights/verdicts back via the API connector. Immediate fidelity + AI-SOC uplift, zero disruption.
- **Stage 2 — Optimize cost** — Send only convictions + supporting context to Sentinel; route full-fidelity telemetry to LakeVilla. Volume-based ingest drops sharply (demo: ~99.6%) while retention/hunt coverage stays complete.
- **Stage 3 — Rebalance / decide** — With normalization + detections living in the pipeline, the SIEM becomes a swappable, per-cost destination. Evaluate augment-vs-replace on real numbers — using the TCO panels in this solution.

## Validate before external claims

- Insights list API endpoint (the pull connector path is parameterized; confirm against your OpenAPI spec).
- LakeVilla replay-through-live-detections semantics and retention limits.
- Detection-as-code / Sigma authoring format (not documented in this repo).
- Stateful cross-stream correlation window + persistent entity store durability.
- Licensing, quotas, and Azure Government parity.

---
*Quantitative $/% figures are demo-measured or modeled from parameters, not vendor benchmarks. Capability statements draw on the Abstract solution content in this repository plus well-known Microsoft Sentinel product facts. Product capabilities and pricing tiers on both sides change — validate against your environment and each vendor's current docs before external use.*
