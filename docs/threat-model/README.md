# From WildFire to Decisions — a destination-agnostic threat model on Abstract

**Goal:** turn Palo Alto WildFire verdicts/reports + PAN/Panorama/Strata logs + a mixed
estate (TI, OSINT, ATO/identity, IdP, cloud, EDR/XDR, email, apps) into one entity-centric
model with mappings, correlations, analytics, and agentic workflows — that lands the same
way whether the destination is **Microsoft Sentinel, Splunk, any other SIEM, or LakeVilla**.

Companion: [samples.md](samples.md) — real-shaped payloads for every source named here.

---

## 0. The premise (read this first)

Two design choices make this an Abstract model rather than a generic SIEM project:

1. **Shift-left.** Normalize → enrich → match IOCs → correlate → score **in the stream,
   before data lands.** A WildFire verdict and a PAN threat-log verdict are high-confidence
   signals *at stream time* — you act on them in seconds, not after indexing.
2. **Destination-agnostic by construction.** The model is built on **OCSF + an entity graph**,
   not on any one SIEM's table layout. So the *same* normalized events, the *same* detections,
   and the *same* enriched findings route to Sentinel (this repo's
   [Sentinel destination](../../templates/destinations/sentinel-destination.bicep)), to Splunk,
   to an Event Hub ([Event Hub destination](../../templates/destinations/eventhub-destination.bicep)),
   and to **LakeVilla** simultaneously. Pick destinations per-cost, not per-capability.

```
 SOURCES (samples.md)                ABSTRACT PIPELINE (this doc)              DESTINATIONS
 ─────────────────────               ────────────────────────────             ────────────
 WildFire verdict/report ┐           1 normalize  → OCSF                       ┌─ Sentinel  (alerts+context)
 PAN/Panorama/Strata     │           2 enrich     → identity·geo·TI·asset      ├─ Splunk    (alerts+context)
 other firewalls         │  ──────►  3 match      → AIG live IOC lists  ──────►├─ any SIEM  (alerts+context)
 TI/OSINT, Email         │           4 correlate  → entity graph + edges       ├─ Event Hub (downstream apps)
 Identity/IdP/ATO        │           5 detect     → shift-left content         └─ LakeVilla (full fidelity,
 EDR/XDR, Cloud, Apps    ┘           6 score+route → risk + campaign                          replay/scope)
```

---

## 1. The entity & identity model (the spine)

Stop modeling *logs*; model *entities* and the *edges* between them. Every source contributes
nodes and edges keyed on canonical identifiers so they stitch automatically.

### Nodes (entities) and their canonical key
| Entity | Canonical key (for stitching) | Key attributes | Top contributing sources |
|---|---|---|---|
| **Identity** | `upn`/`email` (lowercased) | display name, dept, manager, privilege, risk | IdP, HR/AD, ATO signals |
| **Account** | `provider:account_id` | enabled, MFA, last-auth, roles | Okta, Entra, AWS IAM, app logins |
| **Host / Asset** | `asset_id` → else hostname → else IP@time | OS, owner, criticality, zone | EDR/XDR, firewall, cloud inventory |
| **IP** | `ip` (+ first/last seen) | geo, ASN, reputation | firewall, IdP, cloud, TI |
| **Domain** | fqdn (lowercased) | NRD?, category, registrar, reputation | DNS, URL logs, WildFire, TI |
| **URL** | normalized url | method, category, verdict | URL/proxy logs, email, WildFire |
| **FileHash** | `sha256` (md5/sha1 alt-keys) | filetype, size, **verdict**, family | WildFire, EDR, email, VT |
| **Certificate / JA3** | thumbprint / ja3 hash | issuer, validity | firewall TLS, WildFire |
| **Process** | `host:pid:start` (+ image hash) | cmdline, parent, integrity | EDR/XDR, WildFire sandbox |
| **EmailMessage** | message-id | sender, subject, attachments | email security |
| **Detection / Finding** | dedupe key | severity, technique, action | every control |
| **Campaign** | cluster id | first/last seen, member IOCs | derived (correlation) |
| **ThreatActor** | actor id | aliases, TTPs | TI/OSINT attribution |

### Edges (relationships)
`authenticated_as` (Account→Identity) · `runs_on` (Process→Host) · `downloaded`
(Host→FileHash) · `executed` (Host→Process) · `resolved_to` (Domain→IP) · `connected_to`
(Host→IP) · `delivered` (EmailMessage→FileHash/URL) · `contacted` (Process→Domain/URL) ·
`indicates` (TI→IOC) · `attributed_to` (IOC/Campaign→ThreatActor) · `child_of`
(Process→Process) · `same_as` (entity resolution across sources).

> **Why this matters:** the ChatGPT "build a knowledge graph in Neo4j after it lands" step is
> replaced by **maintaining these edges in-stream**. "Find every host that talked to this C2"
> is an edge traversal (`Domain→IP←connected_to←Host`), not a SIEM search across raw logs.

---

## 2. Field mappings (source → OCSF → entity)

The discipline: map each source field once to OCSF, then OCSF to an entity attribute. Content
never references vendor fields.

| Source field (examples) | OCSF class · field | Entity · attribute |
|---|---|---|
| WildFire `verdict`, threat-log `wildfire_verdict` | Detection Finding · `malware.classification` | FileHash · verdict |
| WildFire/PAN/EDR `sha256`,`filedigest`,`SHA256HashData` | `file.hashes[SHA-256]` | FileHash · sha256 (key) |
| PAN `src`/`srcuser`, FortiGate `srcip`/`user`, Zscaler `clientip`/`login` | `src_endpoint.ip`, `actor.user` | Host·ip, Identity·upn |
| PAN `dst`, FortiGate `dstip`, DNS `response` | `dst_endpoint.ip` | IP · ip (key) |
| PAN `dns_query`, WildFire `<dns query>` | DNS Activity · `query.hostname` | Domain · fqdn (key) |
| PAN/Zscaler `url`, email `clickedURL` | HTTP Activity · `url.url_string` | URL · url (key) |
| WildFire `<process … commandline>`, EDR `CommandLine` | Process Activity · `process.cmd_line` | Process · cmdline |
| Okta/Entra principal, AWS `userName` | Authentication · `user.email_addr` | Identity · upn (key) |
| Okta `client.ipAddress`, CloudTrail `sourceIPAddress` | Authentication · `src_endpoint.ip` | IP · ip + Account edge |
| MITRE tags (WildFire/EDR) | `finding_info.attacks[].technique` | Detection · techniques |
| TI verdict (MISP/VT/GreyNoise) | `enrichments[]` | IOC entity · reputation |

OCSF target classes used: **Detection Finding, File System Activity, Process Activity, Network
Activity, DNS Activity, HTTP Activity, Authentication, Account Change, API Activity.** (Confirm
class UIDs against the OCSF version your pipeline targets — names are stable, UIDs version.)

For Sentinel specifically, this repo's [Sentinel destination](../../templates/destinations/sentinel-destination.bicep)
ships a custom `*_CL` table; populate `tableColumns` from Abstract's `all_fields.json` so the
full normalized schema (not just `Message`) lands — see the [README](../../README.md#destinations).

---

## 3. Enrichment chain (in-stream, before landing)

Applied to every event as it flows:

1. **Identity/asset** — resolve `src`/`srcuser` to Identity + Host + criticality + privilege.
2. **Geo/ASN** — on every IP; flags hosting/proxy/Tor/new-ASN.
3. **Threat intel (AIG)** — match hashes/domains/IPs/URLs/JA3 against curated feeds + Abstract's
   proprietary feed + **WildFire-derived IOCs** (see §5 loop) as a *live* input.
4. **OSINT** — VT ratios, GreyNoise classification, abuse scores, NRD/DGA scoring on domains.
5. **Verdict fusion** — fold WildFire + threat-log + EDR + TI verdicts into one confidence.

---

## 4. Correlations & shift-left detections (content)

Each detection = inputs (entities/edges) → logic → fires → routes. All run in-stream.

### 4.1 Verdict fusion — "independent controls agree"
- **Inputs:** FileHash.verdict (WildFire) · EDR detection on same Host+hash · TI reputation.
- **Logic:** `count(distinct control_family where malicious) ≥ 2` → elevate; weight by asset
  criticality + user privilege + persistence-observed.
- **Fires:** single high-confidence finding, `risk_score` 90+. **Routes:** SIEM + SOAR.

### 4.2 WildFire-IOC blast match (the differentiator)
- **Inputs:** AIG live list seeded from the WildFire report (§5) · all DNS/traffic/URL/proxy
  streams.
- **Logic:** any Host `connected_to`/`resolved_to`/`contacted` a report IOC → match.
- **Fires:** per-host hit with first-seen; **continuous & pre-landing** — this is the
  "search all data sources for the C2" step turned into a standing stream rule.

### 4.3 Beaconing / C2
- **Inputs:** TRAFFIC sessions (Host→IP), low jitter intervals, small consistent bytes, long
  duration; JA3 match.
- **Logic:** periodicity + low entropy payload size + dst reputation → C2 score.

### 4.4 ATO → malware bridge
- **Inputs:** Authentication (impossible travel / new-ASN-proxy / MFA fatigue) **and** the
  same IP/Identity appearing in firewall C2 or WildFire report network IOCs.
- **Logic:** identity-risk edge intersects network-threat edge on shared `IP` →
  account-compromise-with-active-malware. (In [samples.md](samples.md) the NL IP `91.219.236.12`
  is both the Okta login IP and a WildFire C2 host — that intersection *is* the detection.)

### 4.5 Lateral movement / exfil
- **Inputs:** internal Host→Host sessions after a conviction; large `bytes_sent` to new dst.

### 4.6 Campaign clustering
- **Inputs:** shared family / C2 infra / certificate / delivery vector across Findings.
- **Logic:** group Findings sharing ≥2 IOCs → emit one `Campaign` instead of N incidents.

---

## 5. The WildFire intelligence loop (the highest-leverage build)

```
first-seen hash ──► WildFire /get/verdict ──► if malicious: /get/report
                                                     │
                          extract IOCs + MITRE (samples.md §1.3)
                                                     │
                              write back into AIG as a live list
                                                     │
        every future DNS/traffic/URL/email/cloud event matched against it (§4.2)
```
This closes the loop the ChatGPT thread left manual: the sandbox report's intelligence becomes
a **standing enrichment** that convicts the *next* host automatically — something a
land-then-search SIEM model structurally can't do.

---

## 6. Insights & analytics workflows

Entity-centric, served from the graph + **LakeVilla replay** (always query-ready, no rehydration):

- **Hash-centric:** sha256 → verdict → family → every Host that downloaded/executed → delivery
  email → C2 contacted. One pivot, full story.
- **Domain/IP-centric:** IOC → resolved_to → every Host connected_to (across DNS/traffic/proxy/
  cloud) → **blast radius in one traversal**.
- **User/identity-centric:** Identity → auth anomalies → email attachment → hash → process →
  C2 → cloud actions → business context (dept/manager/criticality).
- **Campaign-centric:** cluster → members, timeline, affected assets/users, ATT&CK coverage.
- **Retroactive scoping (replay):** new IOC → replay 90+ days through the live detections →
  find historical victims instantly, no SIEM rehydration cost.
- **ATT&CK coverage dashboard:** technique counts from WildFire/EDR enrichments → detection gaps.
- **Risk scoring:** `f(verdicts, corroborating controls, asset criticality, privilege,
  persistence, exposure)` → single prioritized queue, kills alert fatigue.

---

## 7. Firewall-vendor-agnostic strategy

Because normalization happens once (samples.md §2–3), the WildFire-shaped model runs on **any**
NGFW estate:

- **Complement Palo Alto:** WildFire verdicts + Strata logs are the richest input; the loop in
  §5 makes them estate-wide intelligence.
- **Complement other vendors:** Fortinet/Zscaler/Check Point/Cisco/Prisma give {who, host, dst,
  app, action, hash, verdict} → identical entities, identical detections, **no rule rewrites.**
- **Mixed estates / M&A:** one model over heterogeneous firewalls; a WildFire IOC discovered on
  a PAN segment is matched against Fortinet/Zscaler traffic the same instant.
- **No-WildFire shops:** swap the detonation source (e.g., another sandbox/EDR verdict) into the
  same §5 loop — the model doesn't depend on WildFire specifically, it depends on *a verdict*.

---

## 8. Agentic use cases

Abstract already exposes an **MCP server** (`mcp__abstract-security__*`) — the natural substrate
for agents that read the model and drive workflows. Pair the entity graph + LakeVilla replay +
AIG as the agent's tools:

- **Triage agent:** on a new Finding, pulls the entity subgraph, fused verdicts, blast radius,
  and ATT&CK context; writes a one-paragraph verdict + recommended action. Replaces manual pivot.
- **Enrichment / loop-closer agent:** automates §5 — sees first-seen hash, calls WildFire,
  extracts IOCs, writes to AIG, kicks a replay to find prior victims.
- **Hunt / scoping agent:** given an IOC or hypothesis, traverses edges + replays history,
  returns affected hosts/users/timeline as a structured incident object.
- **Detection-tuning agent:** uses PAN/WildFire verdicts as labels to learn precursor traffic
  patterns; proposes new shift-left rules (human-approved before activation).
- **Identity/ATO agent:** watches the §4.4 bridge; on intersection, assembles the
  account-compromise case and hands a disable/reset action to SOAR.
- **Guardrails:** agents *recommend and assemble*; state-changing actions (isolate/disable/block)
  go through SOAR with approval. Per the security constraint, never surface raw secrets/tokens —
  agents read findings and entities, not credentials.

---

## 9. Destination-agnostic routing (what goes where)

| Destination | What it receives | Why |
|---|---|---|
| **Sentinel / Splunk / any SIEM** | alerts + minimal correlated context (the §10 object in samples.md) | analyst workflow, cases, compliance — **without paying to ingest raw telemetry** |
| **Event Hub** | findings/enriched events for downstream apps, custom analytics, other clouds | integration fan-out |
| **LakeVilla** | **full-fidelity** normalized telemetry | cheap retention + replay + retroactive scoping |
| **SOAR** | finding + enriched context object | automated response |

Same model, many sinks. The cost story: **route convictions+context to the SIEM, full fidelity
to LakeVilla** → SIEM ingest drops sharply while investigative completeness rises.

---

## 10. Build & prove sequence

1. **Land the data path** — deploy this repo's [Event Hub source](../../README.md#deploy-to-azure)
   + a destination ([Sentinel](../../templates/destinations/sentinel-destination.bicep) or Event
   Hub); point PAN/Strata + identity + EDR + email at it. (Splunk/other = swap the destination,
   model unchanged.)
2. **Normalize + map** — §2 mappings to OCSF; load full schema into the Sentinel `_CL` table.
3. **Enrich + wire AIG** — §3 chain; stand up the §5 WildFire loop.
4. **Activate content** — §4 detections (start with verdict fusion + IOC blast match).
5. **Prove value** (deployable POV, destination-agnostic):
   - **Cost:** % telemetry cut to SIEM, $/GB saved, retention cost vs. LakeVilla.
   - **Speed:** MTTD stream-time vs. SIEM-correlation time on the verdict-fusion case.
   - **Scope:** time-to-blast-radius via replay vs. SIEM rehydration (and its cost).
6. **Layer agents** (§8) once content is trusted.

---

### File map
- [samples.md](samples.md) — payloads for WildFire (verdict/report), PAN/Panorama/Strata, other
  firewalls, TI/OSINT, identity/ATO, EDR/XDR, cloud, email, and the OCSF-normalized unifier.
- This file — model, mappings, correlations, analytics, firewall-agnostic + agentic + routing.
- [abstract-fit-gaps-and-market.md](abstract-fit-gaps-and-market.md) — the model in Abstract's own
  constructs (pipelines/parsers/extractions/AIG/LakeVilla), **what we don't know** (validate-first
  list), cheap-but-cool wins, and how the market (Cribl/DataBahn/TIPs) + adjacent sources (identity
  exposure, cookies/sessions, agentic exposure) use WildFire and intel.
- [demo/](demo/) — a **runnable** dependency-free simulation: normalize → entity graph (user/NHI/
  agent) → shift-left detections → replay → continuous scoring → prediction → sub-agents →
  write-back, with a JupyterHub/MCP closed-loop notebook. `python3 demo/run_demo.py`.
