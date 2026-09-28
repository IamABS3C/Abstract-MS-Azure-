# Changelog

## 4.1.0 — 2026-09-28

Review by cloud-architecture, security-engineering and Sentinel reviewers; every finding
below is fixed or documented.

### Changed: the Sentinel Destination is safe for an existing production workspace
- **ASIM tables are off by default** (`enableAsim` = false). The portal shows what turning
  them on does to existing ASIM rules, duplicates and cost.
- **Events more than two days old never reach the ASIM tables**, so a replay or backfill
  cannot look like live activity to ASIM rules.
- **A redeploy no longer resets the Abstract table's retention.** New
  `customTableRetentionDays` (default 0 = keep). Measured: a real deployment left a table
  at 60 / 120 days.
- **Monitoring Contributor on the DCR is opt-in** (`grantMonitoringContributor`).
  Monitoring Metrics Publisher is all ingestion needs; measured: Abstract kept delivering
  with Publisher only.
- With-app variant:
  - Key Vault purge protection;
  - the deployment script's container is always cleaned up;
  - the secret is written through a file, never on the command line;
  - the script refuses to overwrite another app's secret;
  - the provisioning identity is documented as tier-0.

### Changed: the content pack only ever acts on its own items
- Its analytics rules and automation rules install **disabled**.
- The automation rules are scoped to the pack's two rules by rule ID, not by an incident
  title containing "Abstract".
- The Verdict playbook no longer sets incident status, so it cannot reopen a closed
  incident.
- The Key Vault secret default no longer points at a specific vault.

### Security
- **Both app-registration paths now reuse only apps they created.** An app they create is
  tagged `abstract:appreg`; any other app with the predictable `Abstract-<subscription>`
  name is refused. Before, a user who pre-created that name could receive tenant-wide Graph
  consent.
- **The event-driven Logic App keeps secrets out of its run history.**
  `Check_existing_secret` and `Add_password` now have secure inputs and outputs. Rotate
  any `abstract-<subscription>` secret minted by an earlier version.
- **The Azure Policy app-registration path uses a durable existence check** (a
  resource-group tag written after consent and RBAC are verified), fails on a role
  assignment error, and always cleans up its container.
- The log-streams policy no longer grants an unneeded Monitoring Contributor to the
  resource-log assignments.

### Added
- **`sentinel-destination-graph`**: the Sentinel destination with the app registration
  created by the template itself (Microsoft Graph Bicep, as the person deploying), so **no
  managed identity has to exist beforehand**. Optional `automateSecret` creates an identity
  that owns only this app (`Application.ReadWrite.OwnedBy`) and stores the secret in a new
  Key Vault. Measured on a test tenant: that identity cannot add a secret to any other app,
  and the stored secret ingested through the DCR. Azure CLI or PowerShell only.
- `solutions/docs/sentinel-destination-assurance.md`: what the Sentinel templates create,
  change and never touch; identities and blast radius; ASIM; cost; rollout and rollback;
  evidence.
- `CONTRIBUTING.md`.
- Official brand assets in `solutions/brand/`.

### Removed
- **Azure Government deploy buttons and links.**
- The SOC demo (`docs/threat-model/`), internal planning documents (`docs/superpowers/`),
  sales material (`solution/sales/`), notebooks and the SE integration profile. They
  remain in git history at tag `archive/pre-cleanup-2026-09-28`.

### Fixed
- The portal wizards' logo was hot-linked from a third-party site; it is now served from
  this repository and generated from the manifest.
- GitHub Pages published every file in the repository; it now publishes only the deployment
  console (`docs/`). The old `/docs/` address redirects.
- `docs.abstract.security` links (which do not resolve) now point to
  `docs.abstractsecurity.app`.
- README: a branded overview with a "Start here" guide. The template reference moved to
  `solutions/README.md` and maintainer material to `CONTRIBUTING.md`.

## 4.0.0 — 2026-09-28

### Changed
- **The Sentinel Destination writes Microsoft's ASIM tables** (`enableAsim`, `asimSchemas`,
  both templates). Each event is mapped from the Abstract Common Schema into Microsoft's
  normalized table for its activity: Authentication, AuditEvent, NetworkSession, Dns,
  WebSession, ProcessEvent, FileEvent and RegistryEvent. Microsoft's built-in ASIM parsers
  read those tables, so Microsoft's ASIM analytics rules, hunting queries and workbooks
  work on Abstract data from every vendor. One mapping per schema, keyed on ACS, in
  `solutions/asim`: a new vendor needs nothing on the Sentinel side. Every event still
  also lands in the Abstract table. Abstract findings and alerts stay out of the activity
  tables.
- `solutions/scripts/gen-sentinel-asim.py` builds the routes, refuses KQL that Azure
  Monitor transformations reject and any column Microsoft's table lacks (Azure drops those
  silently), keeps the portal forms in sync and rebuilds the ARM templates. CI runs it with
  `--check`.
- The guide is now `solutions/docs/sentinel-asim.md`.

### Removed
- **`sourceRoutes`** and `gen-sentinel-source-routes.py`. They copied each vendor's
  published Sentinel connector parsing into the template, one vendor at a time, which
  Abstract would have had to maintain per vendor. A deployment that passes `sourceRoutes`
  must drop the parameter.

### Verified live
- Live AWS CloudTrail and Okta feeds from an Abstract test tenant: 95% and 100% of events landed in an ASIM
  table; the rest carry no ASIM-relevant category. Stored test-tenant events for the other
  schemas all landed. Microsoft's built-in `_Im_*` parsers returned every row, and
  Microsoft's `ASimDataTester` passed Authentication, AuditEvent, NetworkSession and
  FileEvent with no errors or warnings (details in the guide).
- A DCR update takes about 15 minutes to settle; see the guide.
- Not yet shown: a Microsoft rule alerting on these rows, and RegistryEvent (no data).

## 3.8.0 — 2026-09-28

### Added
- **`customTablePlan`** on both Sentinel templates: Keep (default), Analytics, Basic or
  Auxiliary (the Sentinel data lake tier) for the Abstract table. Keep sends no plan, so a
  redeploy never changes an existing table's plan or cost; a new table is created as Analytics.
- **Portal form controls** for the Abstract table plan, the vendor-table source routes (a
  multi-select the generator keeps in sync with the source list) and DCR error logging.
- **Per-source modes** in `docs/sentinel-source-routes.md`: vendor table (trim to the raw
  record and let the vendor's published connector parse it) or ACS (full Abstract schema for
  the Abstract content pack), with Microsoft first-party data left on its native connectors.
  States that none of it needs a Microsoft partnership.
- MIT attribution for the reused Microsoft transformations on every generated route.
- `gen-sentinel-source-routes.py` rebuilds the compiled ARM templates when the routes change,
  and `--check` fails when a portal form or template is missing or an ARM template does not
  embed the current routes. Before, a new source could appear in the portal while the
  deployed template silently skipped its route.

### Verified live
- Table plans: Azure accepted Analytics to Auxiliary and Auxiliary to Analytics on existing
  tables, and a table update without a plan kept the table's plan. Redeploying the template
  twice over an Auxiliary Abstract table (default plan, then with the Okta route added)
  succeeded both times, left the table Auxiliary and kept the DCR's immutable id.
- An Auxiliary Abstract table accepted the full schema through the DCR transformation: 10 of
  10 captured Okta events with every field present and `TimeGenerated` from the event.
- Found while testing: the standard `/query` API and `az monitor log-analytics query` return 0
  for an Auxiliary table that holds data; the `/search` API returns it. Documented in the guide.

## 3.7.0 — 2026-09-28

### Added
- **Source routes** (`sourceRoutes`, both Sentinel templates). For each listed source the
  DCR selects its events, unpacks `event.original` into the columns that vendor's published
  Sentinel connector expects, and runs Microsoft's own transformation into the vendor's table,
  so the vendor's Content Hub parsers, analytics rules and workbooks work unchanged. Every
  event still also lands in the Abstract table. Off by default.
- `solutions/scripts/gen-sentinel-source-routes.py` builds the routes from
  github.com/Azure/Azure-Sentinel at a pinned commit, from the list in
  `parameters/sentinel-source-routes.json`; CI fails if the generated file drifts. First
  source: Okta (`OktaV2_CL`).
- `docs/sentinel-source-routes.md`: the design, how to add a source, and which Microsoft
  first-party tables no outside sender can write, with how to reduce those instead.

### Verified live (Abstract test tenant → Abstract Sentinel Destination → test workspace)
- An Abstract route function (`SELECT_KEYS`, `raw: false`) trimmed a live feed to the raw
  record and routing fields: on the events after it was attached, those fields were present
  on 100% and every other parsed field on 0%.
- The generated Okta route, whose Microsoft transformation is identical to the one run by
  hand first, filled `OktaV2_CL`. Microsoft's `OktaSSO` parser and all 9 Okta Content Hub
  rules ran as published; columns left empty were empty in Okta's own raw records.
- Redeploying with `sourceRoutes` kept the same DCR immutable ID.

## 3.6.1 — 2026-09-28

### Added
- **DCR error logs are on by default** (`enableDcrErrorLogs`, both Sentinel
  templates). The rule's `LogErrors` go to `DCRLogErrors` in the workspace.
  Without it, a request Azure refuses or a row it drops is visible only as a
  metric count, with no reason, to the customer or to Abstract.

### Verified live (Abstract test tenant → real Sentinel destination → this template)
- Field fidelity, event by event and leaf by leaf, on real Abstract output: 390
  of 423 leaves exact and 24 equal after date/number formatting, across 114 paths
  including 77 `ext.*` paths nested several levels and lists inside `ext`. The
  only absent path is `@timestamp`, which lands as `timestamp` and `TimeGenerated`.
- Values of 130 KB in a string column, in a dynamic column and nested under `ext`
  were stored in full, not truncated at the 64 KB Microsoft documents for the Logs
  Ingestion API (Analytics plan, eastus, 2026-09-28).
- Re-running the template over an existing install keeps the same DCR immutable
  ID, so the Abstract destination keeps working.

### Known behaviour worth knowing
- The workspace name is derived from the resource group. Deleting the resource
  group soft-deletes the workspace for 14 days, and redeploying into a group of the
  same name RECOVERS it with its old data rather than creating an empty one.

## 3.6.0 — 2026-09-27

The Sentinel Destination table now matches what Abstract actually sends. The
Abstract Azure Sentinel Destination uploads each Abstract Common Schema event as
nested JSON with its own top-level keys, and the Logs Ingestion API drops every
property a stream does not declare. Measured on a live workspace with the same 18
real ACS events: the previous default (`TimeGenerated, Message, AbstractEvent`)
stored 18 rows with `AbstractEvent` and `Message` empty on all of them, and the
optional 474-column "full schema" (`cloud_account_id`-style flattened names) failed
to deploy at all, because `type` is a reserved column name. The new schema stored
all 18 with their fields populated.

### Changed
- **Sentinel table schema** — one column per top-level ACS key (75 columns;
  nested objects and lists are `dynamic`), generated from the live ACS catalog
  (`solution/schema/acs-fields.json`) by `solutions/scripts/gen-sentinel-schema.py`
  into `solutions/parameters/sentinel-destination.schema.json`. The DCR
  transformation sets `TimeGenerated` (from `timestamp`, else `ingested_time`,
  else ingestion time) and stores the reserved `id` and `type` keys as `acs_id`
  and `acs_type`. `sentinel-destination.full-schema.parameters.json` is removed:
  passed to the CLI it would have declared columns with no transformation.
- **`solution/schema/all_fields.json`** is now the one-record sample the Abstract
  documentation asks you to upload in the portal's "New custom log (DCR-based)"
  step, with `all_fields.transform.kql` to paste into its transformation editor.
- **Sentinel content** (ASIM parser, analytics rules, hunting, workbooks,
  connector, Copilot skills, package, notebook) reads both table shapes: the first
  step uses the `AbstractEvent` column when it exists and otherwise packs the
  row, and the reserved-key fields read `acs_id`/`acs_type`. All 21 queries were
  run on both shapes.
- **`seed_sentinel.py`** sends events the way the integration does instead of
  wrapped rows the new stream would drop.
- **Sentinel Destination + app registration** — Key Vault is now Create,
  Existing or None; newer API versions; per-resource tags.
- The provisioning identity for the app-registration variant needs only
  `Application.ReadWrite.All`; `AppRoleAssignment.ReadWrite.All` was listed as a
  prerequisite but is never used by that template.

### Fixed
- The app-registration template's Key Vault "None" mode failed ARM template
  validation (`The resource identifier '.../providers/Microsoft.KeyVault/' is
  malformed`), because the vault's name was empty in that mode while its id is
  still resolved. All three modes now pass `az deployment group validate`.
- The app-registration script reused any app with the requested display name, so
  a deployment naming an existing app could add a credential to it. It now reuses
  an app only when exactly one has the name and it carries the
  `abstract:sentinel-destination` tag the script writes on creation.
- The script reused a vault secret on expiry alone. It now reuses one only when
  the secret was stored for this app (`appId` tag) and the app still holds a
  matching credential, so a recreated app or a shared Existing vault gets a
  working secret.
- The Key Vault role assignment for the provisioning identity sets
  `principalType` again, avoiding `PrincipalNotFound` for a new identity.
- The app-registration script treated any Key Vault read failure (typically a
  403 while a fresh role assignment propagates) as "no secret", minted a client
  secret, and, if the vault write then failed, exited with that credential live
  and uncaptured. It now retries, treats only `SecretNotFound` as absent, and
  deletes a credential it could not store, and only one it can prove is new, so
  a lagging credential list can never make it revoke the secret Abstract uses.

### Removed
- `AGENTS.md`, `.github/copilot-instructions.md` and `.cursor/` are no longer
  published from this repository; they are generated per machine and ignored.

## 3.5.0 — 2026-06-17

Rebuilt the threat-model demo's **AI-SOC notebook** into a versatile analyst
workspace and made it reproducibly runnable + live-tested.

### Added
- **40-cell `soc_notebook.ipynb`** (generated from `build_notebook.py`) covering
  every Abstract use case end-to-end: REST + MCP connect, live tenant explorer,
  entity graph, continuous-risk trajectories + prediction, live MITRE coverage,
  attack timeline, detection coverage, a threat-hunting library, entity-360
  investigation, blast radius, identity/NHI/agent taxonomy, OSINT enrichment,
  efficiency model, what-if, multi-format reports, and write-back.
- **`mcp_client.py`** — connects the notebook to the Abstract **MCP server**
  (bundled stdio server, or a remote `ABSTRACT_MCP_URL`); lists + calls tools,
  loop-safe for notebooks. Verified end-to-end (`abstract_verify`, `osint_pivots`).
- **`enrichment.py`** — authenticated OSINT adapters (VirusTotal · Shodan ·
  GreyNoise · AbuseIPDB · OTX · urlscan · Censys · HIBP), env-keyed, never logged;
  keyless 24-engine pivot deep-links always available.
- **`hunts.py`** — reusable threat-hunting catalog (9 hunts) over the normalized
  event stream + entity graph; each maps to an Abstract rule/view.
- **`requirements.txt`** + an isolated `.venv` + an `abstract-soc` Jupyter kernel
  so the notebook installs and runs reproducibly.

### Changed
- **`abstract_client.py`** expanded to the full authenticated API surface —
  search / raw-search / translate, views, field-sets, rules, MITRE, and
  **insights** (list/get/create/update/delete, comments, verdicts).
- The MITRE cell now aggregates the tenant's real per-technique coverage into
  per-tactic totals (live: 662/683 techniques across 14 tactics on the test tenant).

### Fixed
- `translate` used `query_string`; the API expects `query` (was 422).
- `viz._mpl()` forced the Agg backend, suppressing inline charts in notebooks —
  now it respects an active `%matplotlib inline` backend (8 charts render).
- `greynoise_community` handles the now-key-required community endpoint
  (uses `GREYNOISE_API_KEY`, clear hint when keyless) instead of a raw 404.

### Verified
- Notebook executes end-to-end with **zero cell errors** both **offline**
  (synthetic estate) and **live** against the test tenant; all objects created
  during live testing were deleted (tenant left clean). Committed notebook
  contains only synthetic data — no key, tenant PII, or local paths.

## 3.4.0 — 2026-06-17

### Added
- **OSINT pivots** (`solution/osint/`) — a curated registry distilled from
  [awesome-hacker-search-engines](https://github.com/edoardottt/awesome-hacker-search-engines)
  (`search_engines.json`) plus `osint_pivots.py`, which auto-detects an indicator
  type (IP, CIDR, domain, hash, email, username, URL, ASN, CVE) and returns deep-
  links into Shodan/Censys/GreyNoise/VirusTotal/crt.sh/AbuseIPDB/urlscan/NVD/etc.
  Pure links — no API keys. Exposed as the MCP `osint_pivots` tool and used by the
  Copilot triage agent to cite references per IOC.
- **Demo → Sentinel bridge** — `seed_sentinel.py --from-demo` maps the threat-model
  demo's synthetic Qakbot estate (`docs/threat-model/demo/data.py`, ~5,000 events)
  to ACS and seeds `AbstractEventLogs_CL`, so the same campaign powers the Sentinel
  analytics/workbook/connector. The demo is read-only; never modified.

## 3.3.0 — 2026-06-17

Completed the closed loop and hardened the solution for packaging.

### Added
- **Tune-at-source playbook** (`solution/playbooks/abstract-tune-at-source.json`)
  — on an incident closed False/Benign Positive, creates an Abstract rule tuning
  filter via `POST /v2/rule-tuning-filters/` (endpoint confirmed live) so the
  noisy pattern is down-sampled upstream. The differentiated SOC↔pipeline loop.
- **Logs-Ingestion seeder** (`solution/scripts/seed_sentinel.py`) — pushes ACS
  events into `AbstractEventLogs_CL` (DCE/DCR) so the workbook/analytics/connector
  light up; accepts the threat-model demo's JSON output. `--dry-run` needs no creds.
- **Vector logo** (`solution/Package/abstract-logo.svg`) and **packaging guide**
  (`solution/Package/PACKAGING.md`) for the official Microsoft Sentinel solution
  tooling (createSolutionV4 + validation) and embedding playbooks as solution content.

### Notes
- Verified the tuning/pipeline/rules API surface against the tenant
  (`/v2/rule-tuning-filters/` = 2, `/v2/pipelines/` = 19, `/v1/functions/` = 220,
  `/v3/rules/` = 355).
- The standalone `docs/threat-model/demo/` workstream remains untouched/uncommitted.

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
