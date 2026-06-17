# Changelog

## 3.2.0 — 2026-06-17

Packaged the Sentinel work as a **Content Hub solution** and broadened the
Copilot/agent/MCP surface.

### Added
- **Content Hub solution** (`solution/Package/mainTemplate.json` + `createUiDefinition.json`,
  `solution/SolutionMetadata.json`, `ReleaseNotes.md`) — registers the solution
  package and deploys the connector tile, ASIM parser (savedSearch), analytics
  rule, and workbook with linked metadata. Branded with the Abstract logo.
- **Hunting queries** — `solution/hunting/` (rare/new product activity; high
  cumulative-risk identities) + a second analytics rule (`AbstractBruteForceSuccess.yaml`).
- **Security Copilot** — `abstract-kql-skills.yaml` (KQL skills over the workspace)
  and `abstract-agent.yaml` (an agentic triage agent that orchestrates the KQL +
  API skills and Abstract's ASTRO Verdict workflow; suggest-only by default).
- **Abstract MCP server** (`solution/mcp/`) — exposes the Abstract API as MCP
  tools (search, ACS schema, workflows, verdict) for Claude / Copilot / custom
  agents, reusing the same client as the SDK and playbooks.

### Notes
- Final Content Hub listing requires running Microsoft's Sentinel solution
  packaging/validation tooling against this source; logo should be supplied as SVG.
- The standalone demo under `docs/threat-model/demo/` is a separate workstream and
  is intentionally not modified or committed by this change.

## 3.1.0 — 2026-06-17

Added a Microsoft Sentinel **solution bundle** that makes the Sentinel
destination actionable, wired to the Abstract API.

### Added
- `solution/scripts/abstract_api.py` — runnable Abstract API client/SDK + CLI
  (env-var auth; verified live against the test tenant).
- `solution/connector/` — Customizable (CCF) **data connector tile** so Abstract
  appears in the Sentinel Data connectors gallery with a live ingestion-status graph.
- `solution/parsers/ASim_AbstractEvent.kql` — ASIM-style normalizer over
  `AbstractEventLogs_CL`, field-mapped from the live ACS catalog (473 fields).
- `solution/analytics/` — scheduled analytics rule that raises incidents for
  high/critical Abstract events and surfaces `AbstractInsightId` as a custom detail.
- `solution/workbooks/` — pipeline-overview workbook (volume, coverage,
  reduction/cost estimate).
- `solution/playbooks/` — two Logic App playbooks: **enrich incident** (Abstract
  StreamViewer search → comment) and **Verdict** (run Abstract's agentic Verdict
  workflow → comment + raise severity). API key via securestring/Key Vault.
- `solution/copilot/` — experimental Security Copilot plugin (search + verdict skills).

### Notes
- The API key is never committed — playbooks use a `securestring`/Key Vault, the
  Copilot plugin uses a `Credential` setting, the client reads `ABSTRACT_API_KEY`.
- Artifacts are schema-validated; deploy to a lab workspace before production.

## 3.0.0 — 2026-06-16

Added Abstract **destination** integrations alongside the existing Event Hub
**source** stack, retargeted the Deploy buttons to the public repo, and added
branding.

### Added
- **Azure Event Hub Destination** template (`templates/destinations/eventhub-destination.*`)
  — namespace + destination hub + least-privilege `abstract-send` Send SAS rule,
  optional Entra ID (`Azure Event Hubs Data Sender`) delivery, networking
  guardrails, and a dedicated portal wizard + Deploy to Azure button. Outputs
  map to the Abstract EventHub Destination modal (EventHub Name + connection
  string pointer).
- **Azure Sentinel Destination** template (`templates/destinations/sentinel-destination.*`)
  — full Logs Ingestion stack: Log Analytics workspace (new or existing),
  Microsoft Sentinel onboarding, Data Collection Endpoint, custom `*_CL` table
  (parameterizable schema), Data Collection Rule, and `Monitoring Metrics
  Publisher` + `Monitoring Contributor` role assignments on the DCR. Outputs the
  DCR Immutable ID, DCE logs-ingestion URL, and stream name for the Abstract modal.
- **Branded GitHub Pages landing page** (`docs/index.html`) with the Abstract
  logo and every Deploy to Azure button (sources + destinations, public + Gov).
- Abstract-branded intro text + doc links in every portal wizard's Basics step.
- Example parameter files for both destinations.
- `abstract-diagnostics-send` Send SAS rule + `abstractDiagnosticsAuthRuleId`
  output in the source template, so the subscription Activity Log export uses a
  least-privilege Send rule instead of RootManageSharedAccessKey
  (`createDiagnosticsSendRule` / `diagnosticsSendRuleName` parameters).
- `.github/workflows/validate.yml` — the CI the README referenced now exists:
  JSON parse + Bicep compile + ARM drift check + arm-ttk over all templates.

### Changed
- **Deploy to Azure buttons retargeted** to `IamABS3C/Abstract-MS-Azure-` @ `main`
  (were placeholder `Abstract-Security/azure-eventhub-onboarding`); added Gov
  buttons for the destinations.
- **ARM is now Bicep-compiled**, not hand-written — every `*.azuredeploy.json`
  is generated from its `*.bicep` with `az bicep build`.
- README retitled "Azure Onboarding" (sources + destinations) with a logo header
  and a Destinations section mapping both destination modals field-for-field.

### Fixed
- Storage-account outputs in `main.bicep` no longer trip Bicep `BCP318`
  null-dereference warnings (non-null assertion behind the `createStorageAccount`
  guard).

## 2.0.0 — 2026-06-11

Aligned with the official Abstract Security "Azure Event Hub" documentation and
made portal-deployable.

### Added
- **Checkpoint Storage Account stack** (required by Abstract): StorageV2 account
  (TLS 1.2, public blob access off, optional shared-key disable), private blob
  container `abstract-checkpoints`, `Storage Blob Data Contributor` role
  assignment, optional blob private endpoint + `privatelink.blob` DNS group,
  optional mirroring of the namespace IP allowlist to the storage firewall.
- **createUiDefinition.json** — 6-step portal wizard (basics, hubs, auth,
  networking, storage, monitoring) for the Deploy to Azure button.
- **Deploy to Azure buttons** (public + Azure Gov) in the README.
- **templates/subscription/activitylog** (Bicep + ARM) — subscription-scope
  diagnostic setting streaming the Azure Activity Log to the hub, with its own
  Deploy button.
- `defaultPartitionCount` (default 4 per Abstract guidance) and
  `defaultRetentionDays` parameters for generated hubs.
- `abstractOnboarding` output object mapping field-for-field to the Abstract
  integration modal for both auth methods (no secrets — pointers only).
- Script v2: `-AuthMethod ConnectionString|ServicePrincipal|Both`,
  `-CreateServicePrincipal` (creates `abstract-eventhub-ingestion` app +
  secret), checkpoint-storage parameters, `-ExportActivityLogs`,
  `-ExportEntraLogs` (best effort via microsoft.aadiam), and a Credentials
  action that prints the exact Abstract modal fields for both methods
  (storage connection string included).
- Repo scaffolding: LICENSE (MIT), CHANGELOG, .gitignore, GitHub Actions
  validation workflow (JSON checks + arm-ttk).

### Changed
- **Basic SKU removed** — Abstract requires Standard tier or above.
- Default SAS rights now **Listen-only** (least privilege for a consumer);
  the Send-capable `abstract-diagnostics-send` rule covers log producers.
- Default hub sources now `activity, entra, defender`; default hub prefix
  `evh-abstract`; environment token optional (empty by default).
- Hub-source and IP-range inputs are trimmed and empty entries filtered, so
  CSV-driven portal inputs cannot produce empty hub names or invalid IP rules.
- Default capacity 2 TU; sizing table from the Abstract docs embedded in the
  template metadata and README.

## 1.0.0 — 2026-06-11

Initial release: namespace, auto-named hubs, consumer group, SAS + RBAC auth,
SafeMode/IpAllowlist/PrivateOnly/Hybrid networking profiles, Log Analytics
diagnostics, four parameter profiles, guided PowerShell deployer. Fixed ten
defects found in a prior hand-written draft (wrong Service Bus role GUIDs,
invalid conditional-loop syntax, networkRuleSet placement, maximumThroughputUnits
handling, Basic-SKU guards, PrincipalNotFound races, allLogs category group,
secrets leaking into outputs, and more).
