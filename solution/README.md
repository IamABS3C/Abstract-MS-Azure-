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
│   └── createUiDefinition.json                  # solution install wizard (branded)
├── SolutionMetadata.json · ReleaseNotes.md      # Content Hub solution descriptor + notes
├── scripts/abstract_api.py                      # runnable API client/SDK (env-var auth) + CLI
├── mcp/abstract_mcp_server.py (+ README)        # Abstract API as MCP tools for Claude/Copilot/agents
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
│   └── abstract-verdict.json                    # incident -> Abstract agentic Verdict -> comment + severity
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
