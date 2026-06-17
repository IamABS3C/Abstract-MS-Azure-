# Elaborate demo catalog — what gets built, live vs. simulated

[build_demo.py](build_demo.py) drives the full demo from [scenarios.py](scenarios.py) and creates
**real objects on the tenant** via the documented REST API. One run (verified) produces:

| Element | Count | How | Native Abstract object |
|---|---|---|---|
| **Field sets** (entity models / mappers) | 9 | `POST /v1/streamviewer/field-set` | reusable field projections |
| **Saved views / searches** (use-cases) | 32 | `POST /v1/streamviewer/view` | saved searches + filters |
| **Detection rules** (real, disabled) | 32 | `POST /v1/rules/` | rules → findings + insights |
| **Suppressions** (tuning filters) | 2 | `POST /v2/rule-tuning-filters/` | noise suppression |
| **MITRE ATT&CK coverage** | 318/363 | `GET /v3/rules/mitre` | analytics (rose 331→363 from our rules) |
| **Field analytics** (top-N) | 5 fields | `POST /v1/streamviewer/field-analytics` | aggregations |
| **Detection-effectiveness** | live | `GET /v2/rules/detection-effectiveness` | analytics |
| **Rule catalog** | 32 | staged (see below) | detection rules |

Run it:
```bash
cd docs/threat-model/demo
python3 build_demo.py            # build everything (cleans prior [ABS-DEMO] objects first)
python3 build_demo.py --cleanup  # remove all [ABS-DEMO] objects
```
Everything is prefixed `[ABS-DEMO]` and idempotent — re-running cleans and recreates. The run
writes `build_manifest.json` with every id + the analytics pulled.

## Entity models (field sets)

`identity`, `network_firewall`, `cloud`, `edr_xdr`, `email`, `dns_web`, `threat_intel`,
`nhi_agent`, `wildfire` — each a curated projection of valid Abstract Common Schema fields
(e.g. `source_address`, `dest_address`, `file.hash.sha256`, `destination.domain`,
`dns.question.name`, `tls.client.ja3`, `threat.technique_id`, `process.command_line`,
`email.attachments.file.hash.sha256`). These are the per-source **mappers** the views ride on.

## Use-case scenarios (32 saved views)

| Category | Scenarios |
|---|---|
| **Identity / ATO** | brute force, MFA fatigue, new-ASN login, impossible travel, account manipulation, OAuth grant |
| **Cloud (AWS/Azure/GCP)** | new access key, root usage, IAM policy change, bulk export/exfil, failed-API burst |
| **Network / Firewall** | C2 beaconing, threat reset-both, large outbound transfer, port scan |
| **DNS / Web** | tunneling, newly-registered domain |
| **EDR / XDR** | malware execution, encoded PowerShell, process injection, credential dumping |
| **Email** | malicious attachment, phishing URL |
| **WildFire / sandbox** | malicious verdict, report C2 IOC contact |
| **Threat intel / OSINT** | known-bad IP match, ATT&CK technique sighting |
| **Identity exposure / cookies** | stolen session / cookie reuse |
| **NHI / agentic** | service token from new ASN, AI-agent anomalous tool call |
| **Supply chain / GenAI** | CI token harvest + startup mod, GenAI agent abuse |

Each view carries its MITRE technique(s), severity, tags, a 30-day window, and its entity-model
field set — so they're real, clickable saved searches spanning every data source.

## Live analytics (pulled from the real tenant)

- **MITRE ATT&CK coverage:** 318 of 331 techniques enabled (full tactic/technique tree available).
- **Field analytics top-N** over `vendor`, `severity`, `event.outcome`, `source_address`,
  `user_name` — e.g. vendor mix is AWS-dominant (~99.9%), with Okta + Microsoft present.

## Detection rules (32) — REAL, created

Every scenario is created as a **real detection rule** (`conditional`/`realtime`) via
`POST /v1/rules/`, using [rules_engine.py](rules_engine.py) — which copies a canonical rule's
Avro `query_json` (`_rule_template.json`) and swaps the conditions. The template's actions are
**CREATE_FINDING + CREATE_INSIGHT**, so enabling a rule produces real insights. Rules are created
**disabled** to avoid tenant noise. Creating all 32 raised the tenant's MITRE coverage 331 → 363.
See [LIVE-RESULTS.md](LIVE-RESULTS.md).

## Visualization, identity & investigation layer

- **Branded command center** ([dashboard.py](dashboard.py) → `dashboard.html`): zero-dependency
  SVG **entity graph**, **blast-radius rings** (real-time vs replay), **MITRE ATT&CK heat strip**
  (live coverage in `--mode api`), **attack-chain timeline**, continuous-risk bars, **identity &
  machine taxonomy**, and an **OSINT panel** — opens in any browser, no installs.
- **Identity / entity taxonomy** ([identities.py](identities.py)): 9 kinds — human, service
  account, **NHI**, **service principal**, machine/host, **AI agent**, **session/cookie**, API key,
  workload identity — classified across 10 identity sources (Okta, Entra, AWS/GCP IAM, AD, K8s, …).
- **OSINT registry** (14 tools): Maltego, SpiderFoot, Criminal IP, GreyNoise, Shodan/Censys,
  VirusTotal, AbuseIPDB, OTX, MISP/OpenCTI, Recorded Future, urlscan, SpyCloud, Hudson Rock, HIBP —
  pluggable adapter stubs (`# ← plug real API here`).
- **Interactive notebook** ([soc_notebook.ipynb](soc_notebook.ipynb)): matplotlib/networkx entity
  graph, risk bars, MITRE heatmap, attack timeline, taxonomy, OSINT, what-if/replay, report + write-back.
- **Incident report** ([report.py](report.py)): analyst-ready Markdown + branded HTML (embedded
  graph + blast-radius), optional `--writeback` creates a dedicated Abstract view/field-set.

## Live vs. simulated (the honest line)

**Created live on the tenant (real, reversible objects):** field sets, saved views/searches,
suppressions, plus live analytics reads (MITRE coverage, field analytics).

**Simulated in the local engine** ([pipeline.py](pipeline.py) / [run_demo.py](run_demo.py) /
[soc_notebook.ipynb](soc_notebook.ipynb)) — the parts the API doesn't expose to this key:
entity graph + replay/retro-hunt, continuous scoring + prediction, triggers, sub-agent
orchestration, and the incident/investigation narrative. These ride on top of the live objects;
the model maps 1:1 to what Abstract Amplify already produces (verdict-fused, entity-correlated,
campaign-clustered insights — see ../README.md and ../abstract-fit-gaps-and-market.md).

**Not yet wired (API gaps for this key):** detection rules (Avro format), insights (not in the
public REST surface), `timeline`/`search` event reads (500s on this tenant — list + field
analytics used instead), forwarders/destinations (pipeline-config plane, not this API).
