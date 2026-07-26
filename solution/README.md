# Abstract Security × Microsoft Sentinel — solution bundle

Content that turns the **Azure Sentinel Destination** (Abstract → Sentinel) into a
first-class, *actionable* integration. Two reinforcing stories:

- **Data‑in** — make Abstract's delivered data discoverable and useful day one
  (connector tile, ASIM parser, analytics rule, workbook).
- **Loop‑back** — let the SOC reach back into the pipeline from Microsoft's tools
  (Logic Apps playbooks + a Security Copilot plugin that call the **Abstract API**).

> **Status: deployed & validated in a lab workspace.** The full solution
> (`Package/mainTemplate.json`) was deployed to a live Sentinel workspace
> (`abstract-pipeline`) — connector, ASIM parser, 2 analytics rules, 2 hunting
> queries, 2 workbooks, and 3 playbooks all install and link as solution content,
> and the seeded threat-model campaign proves the value model live (see below).
> Still lab/experimental; run Microsoft's packaging + `arm-ttk` before Content Hub
> submission. Secrets are never embedded — see *Secret handling*.

### Proven live (seeded threat-model campaign, 5k+ events)

| Signal | Measured |
| --- | --- |
| **Aggregation / dedupe ratio** | **~34:1** raw events represented : events ingested (from `aggregation_count`) |
| **Enrichment coverage** | **100%** risk-scored and tagged upstream |
| **Cross-product identity hunt** | `jsmith@acme.com` — cumulative risk 650 across 5 products (Okta, Email, DNS, Palo Alto, CrowdStrike) |

The **Value & ROI workbook** turns these into a parameterized cost model (Sentinel
$/GB + optional pre-Abstract source volume) so you can show dollars avoided by
aggregation/dedupe and upstream filtering.

---

## What's in the box

```
solution/
├── Package/
│   ├── mainTemplate.json                        # Content Hub solution: registers package + deploys content
│   ├── createUiDefinition.json                  # solution install wizard (branded)
│   ├── abstract-logo.svg                        # vector logo (Content Hub cert needs SVG)
│   └── PACKAGING.md                             # how to build/validate the official package
├── SolutionMetadata.json · ReleaseNotes.md      # Content Hub solution descriptor + notes
├── scripts/
│   ├── abstract_api.py                          # runnable API client/SDK (env-var auth) + CLI
│   └── seed_sentinel.py                         # Logs-Ingestion seeder -> AbstractEventLogs_CL (demo)
├── mcp/abstract_mcp_server.py (+ README)        # Abstract API + OSINT as MCP tools for Claude/Copilot/agents
├── osint/ (search_engines.json, osint_pivots.py)# IOC pivots from awesome-hacker-search-engines (MCP tool + agent)
├── connector/
│   ├── abstract-connector-definition.json        # Sentinel "Abstract Security" connector tile (CCF, destination)
│   ├── abstract-insights-pull.json               # API pull connector: Logic App -> AbstractInsights_CL (compare w/o Sentinel-as-destination)
│   └── abstract-api-sync.json                    # multi-endpoint sync: insights + tune-filters + pipeline-metrics + detection-effectiveness
├── notebooks/abstract-vs-sentinel-comparison.ipynb  # runnable side-by-side: Abstract API + Sentinel KQL (cost/reduction/MTTR/MTTD/AI-SOC)
├── parsers/ASim_AbstractEvent.kql               # ASIM-style normalizer over AbstractEventLogs_CL
├── analytics/
│   ├── abstract-high-severity-insight.json      # scheduled rule (ARM) -> incident (+ AbstractInsightId)
│   ├── AbstractHighSeverity.yaml                 # same rule in authoring (YAML) format for packaging
│   └── AbstractBruteForceSuccess.yaml           # authoring-format rule: failures -> success
├── hunting/
│   ├── AbstractRareProduct.yaml                 # rare / newly-seen sources
│   └── AbstractHighRiskIdentities.yaml          # high cumulative pipeline risk
├── workbooks/
│   ├── abstract-pipeline-overview.workbook.json  # volume / coverage / reduction estimate
│   ├── abstract-value-roi.workbook.json          # ROI: aggregation/dedupe ratio, enrichment %, hunt yield, $ avoided
│   └── abstract-competitive-tco.workbook.json    # Abstract vs Sentinel: cost/TCO, coverage, MTTR, gap matrix, migration
├── integration-profile/                          # reusable SE asset: dual-direction wiring, gap analysis, value props
│   ├── abstract-sentinel-integration-profile.json
│   └── README.md
├── sales/
│   ├── abstract-vs-sentinel.html                 # branded interactive competitive leave-behind (live TCO calculator)
│   └── gaps-and-gamechanger.md                   # SE strategy: why this is a homerun + gaps checklist + POV playbook
├── playbooks/
│   ├── abstract-enrich-incident.json            # incident -> Abstract search -> comment
│   ├── abstract-verdict.json                    # incident -> Abstract agentic Verdict -> comment + severity
│   └── abstract-tune-at-source.json             # incident closed FP -> create Abstract tuning filter (down-sample upstream)
└── copilot/
    ├── abstract-copilot-skillset.yaml           # Copilot API plugin (search + verdict; calls Abstract)
    ├── abstract-kql-skills.yaml                 # Copilot KQL skills (query the workspace; no key)
    └── abstract-agent.yaml                      # Copilot agentic triage agent (orchestrates the above)
```

### Content Hub solution

`solution/Package/mainTemplate.json` registers an **Abstract Security** solution
package (`contentPackages`) and deploys the connector tile, parser, analytics
rule, and workbook with linked `metadata` so they show as solution content.
Install via the portal (Template spec / Deploy a custom template) with the
`createUiDefinition.json` wizard, passing your `workspace`.

> Final Content Hub listing / Marketplace certification requires running
> Microsoft's Sentinel solution packaging + validation tooling against this
> source (and an SVG logo). This template is a deployable, self-contained
> approximation for lab use.

### Security Copilot (plugin + KQL + agent)

- **API plugin** (`abstract-copilot-skillset.yaml`) — calls the Abstract API
  (search events, get verdict). Key entered as a Copilot credential setting.
- **KQL skills** (`abstract-kql-skills.yaml`) — query the connected workspace
  (events by product, high-severity, identity activity). No Abstract key needed.
- **Agent** (`abstract-agent.yaml`) — an agentic triage agent that, on an
  Abstract-originated incident, orchestrates the KQL + API skills and Abstract's
  ASTRO **Verdict** workflow into a grounded recommendation. Suggest-only by
  default; writes require approval.

### MCP server

`solution/mcp/abstract_mcp_server.py` exposes the Abstract API as MCP tools so
Claude / Copilot / custom agents can use the pipeline as a source alongside
other MCP servers. See `solution/mcp/README.md` for registration.

### OSINT pivots

`solution/osint/` turns any IOC (IP, domain, hash, email, username, URL, ASN,
CVE) into curated investigation deep-links — Shodan, Censys, GreyNoise,
VirusTotal, crt.sh, AbuseIPDB, urlscan, IntelX, NVD, and more — distilled from
[awesome-hacker-search-engines](https://github.com/edoardottt/awesome-hacker-search-engines).
Exposed as the MCP `osint_pivots` tool and used by the Copilot triage agent to
cite references per IOC. Pure links, no API keys. `python solution/osint/osint_pivots.py 8.8.8.8`.

### Demo data (make it light up)

`solution/scripts/seed_sentinel.py` pushes ACS events into `AbstractEventLogs_CL`
through the Azure Monitor Logs Ingestion API (the DCE/DCR the destination
template created), so the workbook, analytics rule, hunting queries, and
connector graph populate without waiting on a live pipeline. It accepts JSON on
stdin, so it pairs with the threat-model demo generators:

```bash
python solution/scripts/seed_sentinel.py --from-demo --dry-run         # preview the demo campaign as ACS, no creds
# live (app SP needs Monitoring Metrics Publisher on the DCR):
export AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=…
export ABSTRACT_DCE_URL=… ABSTRACT_DCR_IMMUTABLE_ID=…
python solution/scripts/seed_sentinel.py --from-demo                   # seed the threat-model campaign into Sentinel
```

`--from-demo` reads the threat-model demo's synthetic estate
(`docs/threat-model/demo/data.py:events()` — the Qakbot campaign + ~5,000 benign
events), maps each to the Abstract Common Schema, and seeds it — so the **same
campaign that powers the demo** lights up the Sentinel analytics, workbook, and
connector graph. (The demo is read, never modified.) Or pipe any ACS JSON in.

### The full closed loop (now real)

```
incident created  ── Verdict playbook ──▶ Abstract ASTRO Verdict workflow ──▶ comment + severity
incident closed FP ── Tune-at-source ───▶ POST /v2/rule-tuning-filters/ ─────▶ down-sample upstream
analyst (Copilot/MCP) ── search/verdict ─▶ Abstract API ─────────────────────▶ grounded answer
```

> **Tune-at-source** uses the live `/v2/rule-tuning-filters/` endpoint (confirmed
> against the tenant). The exact `tuning_filter_combination` body should match
> what the Abstract UI produces; the playbook ships a sensible default.

Grounded in the live tenant: **473 ACS fields** drive the parser/analytics field
maps, and Abstract's agentic workflows **Verdict** and **IP Threat Intelligence**
are enabled (both fire on `insight_created`) — which is what makes the verdict
playbook and Copilot skills real rather than hypothetical.

## The closed loop

```
 Abstract pipeline ──(DCR / Logs Ingestion)──▶ AbstractEventLogs_CL
        ▲                                              │
        │                                     ASIM parser + analytics rule
        │                                              │
        │                                              ▼
   Abstract API ◀── Logic App playbook / Copilot ── Sentinel incident
   (verdict, search, tune)        (loop back)        (triage)
```

Triage in Sentinel → act on the pipeline in Abstract. No SIEM-only or
detection-only vendor can tell this story — only a pipeline can.

## Deploy order (lab)

1. **Azure Sentinel Destination** template (repo root → `templates/destinations/`) —
   workspace, Sentinel, DCE, `AbstractEventLogs_CL`, DCR, RBAC.
2. **Connector tile** — `connector/abstract-connector-definition.json` (pass `workspaceName`).
3. **Parser** — open `parsers/ASim_AbstractEvent.kql` in Logs → *Save as function*, alias `ASim_AbstractEvent`.
4. **Analytics rule** — `analytics/abstract-high-severity-insight.json` (pass `workspaceName`). Maps `AbstractInsightId`.
5. **Workbook** — `workbooks/abstract-pipeline-overview.workbook.json` (pass `workspaceName`).
6. **Playbooks** — deploy each `playbooks/*.json` (pass `abstractVendorAccountId` + `abstractApiKey`), then
   attach via an automation rule (incident created → run playbook). The Sentinel managed identity needs
   **Microsoft Sentinel Responder** on the workspace.
7. **Copilot plugin** — upload `copilot/abstract-copilot-skillset.yaml`; enter base URL, vendor id, API key as plugin settings.

```bash
# example: connector tile
az deployment group create -g rg-abstract-sentinel \
  --template-file solution/connector/abstract-connector-definition.json \
  --parameters workspaceName=<your-workspace>
```

## Secret handling (read this)

The Abstract API key is **never** written into these files or git.

- **Playbooks** take `abstractApiKey` as a `securestring` deploy parameter. For
  production, replace it with an **Azure Key Vault** reference / the Key Vault
  connector so the key is never passed in the template at all.
- **Copilot** stores the key as a `Credential` plugin setting.
- **The client** reads `ABSTRACT_API_KEY` (+ `ABSTRACT_VENDOR_ACCOUNT_ID`,
  `ABSTRACT_BASE_URL`) from the environment.

```bash
export ABSTRACT_API_KEY=<key>            # do not commit
export ABSTRACT_VENDOR_ACCOUNT_ID=<id>
python3 solution/scripts/abstract_api.py verify
python3 solution/scripts/abstract_api.py fields --grep ip
python3 solution/scripts/abstract_api.py workflows
```

## Built (v3.3.0)

- **Tune-at-source playbook** — `playbooks/abstract-tune-at-source.json`. On a
  FalsePositive/BenignPositive disposition it calls `POST /v2/rule-tuning-filters/`
  so the pattern is down-sampled upstream in the pipeline.
- **Content Hub packaging** — `Package/mainTemplate.json` + `createUiDefinition.json`
  install the whole solution in one deployment (connector, parser, 2 analytics
  rules, 2 hunting queries, workbook, 3 playbooks) with `contentPackages` +
  per-item `metadata`. See `Package/PACKAGING.md` for the official
  certification path (Marketplace verified badge).
- **Hunting queries** over `ASim_AbstractEvent` — `hunting/AbstractRareProduct.yaml`,
  `hunting/AbstractHighRiskIdentities.yaml`.
- **Official branding** — the connector tile, package icon, and install wizard
  use the official Abstract mark, embedded self-contained (SVG data-URI, no
  external image host).

## Roadmap

- **Marketplace certification** — run Microsoft's `createSolutionV4.ps1` +
  `arm-ttk` over `solution/` and submit via Partner Center for the verified badge.
- **Additional detections** — impossible-travel and data-exfiltration rules over
  the normalized `ASim_AbstractEvent` surface.
