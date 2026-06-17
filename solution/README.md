# Abstract Security × Microsoft Sentinel — solution bundle

Content that turns the **Azure Sentinel Destination** (Abstract → Sentinel) into a
first-class, *actionable* integration. Two reinforcing stories:

- **Data‑in** — make Abstract's delivered data discoverable and useful day one
  (connector tile, ASIM parser, analytics rule, workbook).
- **Loop‑back** — let the SOC reach back into the pipeline from Microsoft's tools
  (Logic Apps playbooks + a Security Copilot plugin that call the **Abstract API**).

> **Status: experimental / lab.** Authored and grounded against a live Abstract
> test tenant (org `setest`) — the API client is verified working; the ARM/KQL/YAML
> artifacts are schema-built and **not yet deployed to a live workspace**. Validate
> in a lab first. Secrets are never embedded — see *Secret handling*.

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
├── connector/abstract-connector-definition.json # Sentinel "Abstract Security" connector tile (CCF)
├── parsers/ASim_AbstractEvent.kql               # ASIM-style normalizer over AbstractEventLogs_CL
├── analytics/
│   ├── abstract-high-severity-insight.json      # scheduled rule (ARM) -> incident (+ AbstractInsightId)
│   └── AbstractBruteForceSuccess.yaml           # authoring-format rule: failures -> success
├── hunting/
│   ├── AbstractRareProduct.yaml                 # rare / newly-seen sources
│   └── AbstractHighRiskIdentities.yaml          # high cumulative pipeline risk
├── workbooks/abstract-pipeline-overview.workbook.json  # volume / coverage / reduction estimate
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
python solution/scripts/seed_sentinel.py --sample 50 --dry-run        # preview, no creds
# live (app SP needs Monitoring Metrics Publisher on the DCR):
export AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=…
export ABSTRACT_DCE_URL=… ABSTRACT_DCR_IMMUTABLE_ID=…
python docs/threat-model/demo/identities.py | python solution/scripts/seed_sentinel.py
```

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

## Roadmap / not yet built

- **Tune-at-source playbook** — analyst dispositions an alert false-positive →
  playbook calls Abstract to add a pipeline rule that down-samples that pattern
  upstream (needs the Abstract tuning/pipeline API surface confirmed).
- **Content Hub packaging** — wrap the above as a single installable Sentinel
  *solution* (mainTemplate + createUiDefinition) for in-product discovery, and
  pursue Marketplace / certification for the verified badge.
- **Hunting queries** over `ASim_AbstractEvent`.
