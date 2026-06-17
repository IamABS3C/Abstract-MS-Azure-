# Azure destination templates + branding — design

Date: 2026-06-16
Status: approved (design), implementing (PowerShell deferred)

## Goal

Extend the Abstract Security Azure onboarding repo so it can deploy, in addition to the
existing **Event Hub *source*** integration (Abstract reads *from* Event Hub):

1. **Azure Event Hub *Destination*** — Abstract writes processed events *to* an Event Hub.
2. **Azure Sentinel Destination** — Abstract writes events to Microsoft Sentinel via the
   Azure Monitor Logs Ingestion API (DCE/DCR/custom table).

Plus: retarget every **Deploy to Azure** button to the real public repo, add Abstract
branding (logo where technically possible, brand text in the portal wizards), and fix
existing template drift.

## Decisions (from brainstorming)

- **Separate templates + buttons** for each destination (not folded into the source wizard).
  Each button deploys ONE self-contained ARM file (no linked templates — robust for portal URI deploys).
- **Full-stack Sentinel**: LAW + enable Sentinel + DCE + DCR + custom `*_CL` table + RBAC.
- **Branding**: logo in README header + a `docs/index.html` GitHub Pages landing page;
  brand *text* in each wizard's Basics step (the portal createUiDefinition has no image element).
- **Button target**: `raw.githubusercontent.com/IamABS3C/Abstract-MS-Azure-/main/…`
- **PowerShell**: deferred — script is not modified in this change.

## Components

### Event Hub Destination (`templates/destinations/eventhub-destination.*`), RG scope
Namespace (Standard min) · one hub (`abstract-destination-hub`, 4 partitions default) ·
namespace-level **Send** SAS rule `abstract-send` (keys never in outputs) · TLS 1.2 ·
auto-inflate option · Safe Mode / IP-allowlist / private-endpoint guardrails (same model as
source, so Abstract egress can reach it) · **optional** RBAC `Azure Event Hubs Data Sender`
for an SP (default off).
Outputs → Abstract EventHub Destination modal: **EventHub Name**, namespace FQDN, and a
no-secrets pointer to the `abstract-send` connection string.

### Sentinel Destination (`templates/destinations/sentinel-destination.*`), RG scope
Log Analytics workspace (create new OR select existing) → **enable Microsoft Sentinel**
(`Microsoft.SecurityInsights/onboardingStates`) → **Data Collection Endpoint** →
**custom `*_CL` table** (default `AbstractEventLogs_CL`; schema parameterizable, default
`TimeGenerated:datetime` + `Message:string` + `AbstractEvent:dynamic`, documented to replace
with Abstract's `all_fields.json` columns) → **Data Collection Rule** (streamDeclaration
`Custom-<table>` → workspace) → **RBAC on the DCR** for the supplied SP object ID:
**Monitoring Metrics Publisher** + **Monitoring Contributor** (skipped when no SP id given).
App registration + client secret are NOT created in ARM (impossible) — supplied/entered in Abstract.
Outputs → Sentinel modal: **DCR Immutable ID**, **DCE logs-ingestion URI**, **stream name**
(`Custom-<table>`), plus pointers for Client/Tenant/Secret.

### Branding
- README: `<img>` logo header (`https://cybersecurity-excellence-awards.com/wp-content/uploads/163661.png`).
- `docs/index.html`: branded landing page (Abstract palette #f8226a / #01e69d / #060608, Barlow),
  logo + every Deploy to Azure button (source, EH dest, Sentinel dest, activity log; public + Gov).
- Wizards: Abstract-branded intro text + link in each Basics `description`.

### Build & correctness
- Compile every `.bicep` → `.azuredeploy.json` with Bicep v0.44.1 (removes the repo's
  "hand-compiled ARM" caveat). Fix the two BCP318 storage-output warnings via safe-dereference.
- Drift fixes in `main.bicep`: add the `abstract-diagnostics-send` (Send) namespace rule +
  outputs `abstractDiagnosticsAuthRuleId` and `storageAccountName` that the README and
  activity-log export already assume — so Activity Log export uses a least-privilege rule
  instead of RootManageSharedAccessKey.
- Add `.github/workflows/validate.yml` (JSON validation + arm-ttk over all templates).

## Built-in role IDs used
- Azure Event Hubs Data Sender: `2b629674-e913-4c01-ae53-ef4638d8f975`
- Monitoring Metrics Publisher: `3913510d-42f4-4e42-8a64-420c390055eb`
- Monitoring Contributor: `749f88d5-cbae-40b8-bcfc-e573ddc772fa`

## Out of scope
- Extending `Deploy-AbstractEventHub.ps1` to the destinations (deferred).
- Runtime testing against a live tenant (templates are syntax-validated + what-if where possible).
