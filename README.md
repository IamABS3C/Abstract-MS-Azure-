<p align="center">
  <img src="https://cybersecurity-excellence-awards.com/wp-content/uploads/163661.png" alt="Abstract Security" height="80" />
</p>

# Abstract Security — Azure Onboarding

Production-ready Azure infrastructure for Abstract Security **source** and **destination** integrations, deployable from the portal (Deploy to Azure buttons with guided wizards), the CLI, or a menu-driven PowerShell script:

- **Event Hub (Source)** — Abstract *reads from* Event Hub: namespace, one hub per log source, consumer group, the **checkpoint Storage Account + private blob container Abstract requires**, SAS and/or Entra ID (RBAC) auth, networking guardrails, log-export plumbing.
- **Event Hub Destination** — Abstract *writes to* an Event Hub: namespace, destination hub, least-privilege **Send** SAS rule (+ optional Entra ID delivery).
- **Azure Sentinel Destination** — Abstract *writes to* Microsoft Sentinel via the Logs Ingestion API: Log Analytics workspace, Sentinel, Data Collection Endpoint, custom `_CL` table, Data Collection Rule, and the DCR role assignments.

> **One page to deploy anything:** the branded landing page in [`docs/`](docs/index.html) (enable GitHub Pages on `/docs`) renders the logo and every Deploy to Azure button.

> **Make Sentinel actionable:** the [`solution/`](solution/) bundle adds a Sentinel connector tile, ASIM parser, analytics rule, workbook, Logic App playbooks, a Security Copilot plugin/agent, an MCP server, and OSINT pivots — all wired to the Abstract API (triage in Sentinel, act on the pipeline in Abstract). See [solution/README.md](solution/README.md).

> **See the model run:** the [`docs/threat-model/demo/`](docs/threat-model/demo/) shift-left simulation (entity graph, replay, continuous scoring, sub-agents, live write-back) produces the synthetic campaign that `solution/scripts/seed_sentinel.py --from-demo` streams into Sentinel.

> **Status:** templates are syntax-validated and Bicep-compiled but **not yet runtime-tested against a live tenant**. Run `az deployment group what-if` (or the script's `-Preview`) before the first production deployment. The `*.azuredeploy.json` files are generated from the matching `*.bicep` with `az bicep build` — recompile if you edit the Bicep.

---

## Deploy to Azure

Buttons target **`IamABS3C/Abstract-MS-Azure-`** on `main`. The repo must be **public** for the portal to fetch the templates.

### Sources — Abstract reads *from* Azure

| What | Deploy | Azure Gov | Notes |
| --- | --- | --- | --- |
| **Event Hub (Source)** — namespace, hubs, storage, auth, networking | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2FcreateUiDefinition.json) | [![Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2FcreateUiDefinition.json) | Guided 6-step wizard (basics → hubs → auth → networking → storage → monitoring) |
| **Activity Log export** (subscription scope, run after the source stack) | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fsubscription%2Factivitylog.azuredeploy.json) | [![Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fsubscription%2Factivitylog.azuredeploy.json) | Streams the subscription's Activity Log to the hub. Once per subscription. |

### Destinations — Abstract writes *to* Azure

| What | Deploy | Azure Gov | Notes |
| --- | --- | --- | --- |
| **Event Hub Destination** — namespace, destination hub, Send SAS rule | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Feventhub-destination.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Feventhub-destination.createUiDefinition.json) | [![Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Feventhub-destination.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Feventhub-destination.createUiDefinition.json) | Wizard: basics → destination hub → auth → networking |
| **Azure Sentinel Destination** — LAW + Sentinel + DCE + DCR + custom table + RBAC | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Fsentinel-destination.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Fsentinel-destination.createUiDefinition.json) | [![Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Fsentinel-destination.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Fsentinel-destination.createUiDefinition.json) | Wizard: workspace → ingestion (DCE/DCR/table) → auth & RBAC. **Create the Entra app first** (see [Destinations](#destinations)) |
| **Sentinel Destination — one-click incl. app registration** *(advanced)* | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Fsentinel-destination-with-app.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Fsentinel-destination-with-app.createUiDefinition.json) | [![Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Fsentinel-destination-with-app.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Ftemplates%2Fdestinations%2Fsentinel-destination-with-app.createUiDefinition.json) | Guided wizard (workspace → ingestion → app registration & Key Vault). Also creates the Entra app via a deploymentScript, secret → Key Vault. **Needs a user-assigned identity with Application Administrator** — see [Automate the app registration](#automate-the-app-registration--roles) |

> **Button URL format:** `https://portal.azure.com/#create/Microsoft.Template/uri/<URL-encoded raw azuredeploy.json>[/createUIDefinitionUri/<URL-encoded raw createUiDefinition.json>]` — URL-encode the `raw.githubusercontent.com` link (`:` → `%3A`, `/` → `%2F`). If you fork or rename, replace `IamABS3C/Abstract-MS-Azure-` throughout (and in `docs/index.html`).
>
> Test any wizard without deploying at the [CreateUiDef sandbox](https://portal.azure.com/#blade/Microsoft_Azure_CreateUIDef/SandboxBlade).

---

## What gets deployed

| Resource | Purpose | Default |
| --- | --- | --- |
| Event Hubs **namespace** | Container for hubs; Standard or Premium ([Abstract requires Standard+](#sizing)) | `Standard`, 2 TU, TLS 1.2 |
| **Event hub(s)** | One per log source, auto-named `<prefix>[-<env>]-<source>` | `evh-abstract-activity`, `-entra`, `-defender` · 4 partitions · 7-day retention |
| **Consumer group** | Dedicated group for Abstract's readers (don't share with other consumers) | `abstract` |
| **Storage Account** + private **blob container** | **Required by Abstract** — checkpoint/lease store for the consumer | auto-named `abs<hash>` · container `abstract-checkpoints` · TLS 1.2, no public blob access |
| **SAS rule** (optional) | Connection-string auth, **Listen-only** by default | `abstract-access` |
| **RBAC roles** (optional) | Entra service-principal auth: `Azure Event Hubs Data Receiver` on the namespace + `Storage Blob Data Contributor` on the storage account | off until you supply a principal |
| Diagnostics SAS rule | Send-only rule for *log producers* (Activity/Entra/Defender exports) | `abstract-diagnostics-send` |
| Network rule sets | Safe Mode / IP allowlist / private endpoints, optionally mirrored to storage | Safe Mode ON |
| Diagnostic settings | Namespace logs+metrics → Log Analytics (optional) | off |

### Repo layout

```
.
├── main.bicep                       # SOURCE: source of truth (resource-group scope)
├── azuredeploy.json                 # SOURCE: compiled ARM (what the button deploys)
├── createUiDefinition.json          # SOURCE: portal wizard
├── docs/
│   └── index.html                   # branded GitHub Pages landing page (logo + all buttons)
├── parameters/                      # ready-made profiles
│   ├── abstract-recommended.parameters.json
│   ├── safe-mode.parameters.json
│   ├── ip-allowlist.parameters.json
│   ├── private-only.parameters.json
│   ├── hybrid.parameters.json
│   ├── eventhub-destination.parameters.json
│   ├── sentinel-destination.parameters.json
│   ├── sentinel-destination.full-schema.parameters.json   # explicit per-field ACS columns
│   └── sentinel-destination-with-app.parameters.json      # one-click incl. app registration
├── scripts/
│   ├── Deploy-AbstractEventHub.ps1  # guided deploy / credentials / delete (source only)
│   ├── new-abstract-sentinel-app.sh    # create Entra app + SP + secret, grant DCR roles (bash)
│   ├── New-AbstractSentinelApp.ps1     # same, PowerShell 7 / Az
│   └── gen-sentinel-schema.py          # all_fields.json → Log Analytics tableColumns params
├── solution/
│   └── schema/
│       └── all_fields.json             # canonical Abstract ACS field catalog (from GET /v1/acs/fields)
├── templates/
│   ├── subscription/
│   │   ├── activitylog.bicep         # Activity Log → hub (subscription scope)
│   │   └── activitylog.azuredeploy.json
│   └── destinations/
│       ├── eventhub-destination.bicep / .azuredeploy.json / .createUiDefinition.json
│       ├── sentinel-destination.bicep / .azuredeploy.json / .createUiDefinition.json
│       └── sentinel-destination-with-app.bicep / .azuredeploy.json / .createUiDefinition.json  # one-click + app reg (deploymentScript → Key Vault)
└── .github/workflows/validate.yml   # CI: JSON parse + Bicep compile/drift + arm-ttk
```

Each Deploy button deploys ONE self-contained ARM file (no linked templates), so the buttons work the moment the repo is public.

---

## Quick starts

**Portal** — click the Deploy to Azure button and follow the wizard.

**PowerShell (guided)** — works in Cloud Shell or locally (PS 7+):

```powershell
./scripts/Deploy-AbstractEventHub.ps1
```

**PowerShell (one-liner, recommended happy path)** — Safe Mode, checkpoint storage, SPN created for you, Activity Log wired up:

```powershell
./scripts/Deploy-AbstractEventHub.ps1 -Action Deploy -ResourceGroup rg-abstract `
    -NamespaceName abs-eh001 -SecurityProfile SafeMode `
    -CreateServicePrincipal -ExportActivityLogs
```

**Azure CLI**:

```bash
az deployment group create -g rg-abstract \
  --template-file azuredeploy.json \
  --parameters parameters/abstract-recommended.parameters.json \
  --parameters namespaceName=abs-eh001 principalId=<spn-object-id>

# preview first (recommended):
az deployment group what-if -g rg-abstract --template-file azuredeploy.json \
  --parameters parameters/abstract-recommended.parameters.json namespaceName=abs-eh001
```

**Activity Log export** (subscription scope — separate by design, since subscription diagnostic settings can't be created from a resource-group deployment):

```bash
az deployment sub create --location eastus \
  --template-file templates/subscription/activitylog.azuredeploy.json \
  --parameters eventHubAuthorizationRuleId=<abstractDiagnosticsAuthRuleId output> \
               eventHubName=evh-abstract-activity
```

---

## Connectivity / security profiles

| Profile | safeMode | Public access | Firewall | Private endpoints | Abstract can connect? |
| --- | --- | --- | --- | --- | --- |
| `safe-mode` (default) | **true** | forced **Enabled** | forced Allow | no | **Always** — guardrails win |
| `ip-allowlist` | false | Enabled | **Deny** + your CIDRs | no | Only from allowlisted CIDRs — **include Abstract's egress IPs** |
| `hybrid` | false | Enabled | Deny + CIDRs | namespace + storage | Via allowlist; internal consumers go private |
| `private-only` | false | **Disabled** | n/a | namespace + storage | **No** (by design) — internal-only or in-VNet collectors |

Safe Mode exists so a hardened parameter file can never silently break ingestion during onboarding: when `safeMode=true` the template forces public access on and ignores the allowlist (on the storage account too). Flip it off when you're ready to harden.

`storageApplyIpRules=true` mirrors your namespace allowlist to the checkpoint Storage Account. Note Azure Storage rejects `/31` and `/32` CIDR entries — use individual IPs without a suffix or wider ranges.

---

## <a name="sizing"></a>Sizing (from the Abstract docs)

Abstract requires **Standard tier or above** and recommends **≥ 4 partitions** per hub. Throughput sizing:

| Expected ingress | Throughput units | Partitions |
| --- | --- | --- |
| 1 MB/s | 1 | 4 (default) |
| 2 MB/s | 2 | 4 |
| 10 MB/s | 10 | 10+ |
| 32 MB/s (max) | 32 (max 40) | 32 (max) |

Set `capacity` (TUs) and `defaultPartitionCount` accordingly; `autoInflate` + `maxThroughputUnits` lets Standard namespaces scale TUs automatically. **Partition count cannot be changed after hub creation** (Standard tier) — size it for peak.

---

## Onboarding in Abstract

In Abstract: **Data Flow Management → Streams → Add Stream → Azure Event Hub**. The deployment's `abstractOnboarding` output (and the script's `Credentials` action) gives you every field. Two auth methods:

**Method 1 — Connection String**

| Abstract modal field | Where it comes from |
| --- | --- |
| Event Hub Connection String | namespace SAS rule `abstract-access` primary connection string + `;EntityPath=<hub>` — the script prints it, or Portal → namespace → Shared access policies |
| Consumer Group | `abstract` (template output `consumerGroup`) |
| Storage Account Connection String | Portal → storage account → Access keys, or the script prints it |

**Method 2 — Service Principal** (no shared keys; the template grants the roles)

| Abstract modal field | Where it comes from |
| --- | --- |
| Event Hub Name | e.g. `evh-abstract-activity` (output `eventHubs`) |
| Consumer Group | `abstract` |
| Blob Container Name | `abstract-checkpoints` |
| Fully Qualified Namespace | `<namespace>.servicebus.windows.net` (output `namespaceFqdn`) |
| Storage Account URL | `https://<account>.blob.core.windows.net` (output `storageAccountBlobUrl`) |
| Tenant ID / Client ID / Client Secret | the app registration — `-CreateServicePrincipal` makes `abstract-eventhub-ingestion` and prints all three (secret shown **once**) |

The service principal needs **`Azure Event Hubs Data Receiver`** on the namespace and **`Storage Blob Data Contributor`** on the storage account — both are assigned by the template when you pass `principalId` (the SPN's **object ID**, not the app ID).

**Then point log sources at the hubs:** the Activity Log template above; Entra ID → Diagnostic settings → SignInLogs + AuditLogs → stream to event hub (or the script's `-ExportEntraLogs`, needs Entra P1/P2); Defender XDR Streaming API; any resource's diagnostic settings using the Send-only `abstract-diagnostics-send` rule.

---

## Destinations

These templates provision the **Azure side of an Abstract destination** — where Abstract delivers processed events. They are independent of the source stack; deploy whichever you need.

### Event Hub Destination

Per the [EventHub Destination docs](https://docs.abstractsecurity.app/docs/integrations/destination-integrations/azure-eventhub-destination/), Abstract delivers events to a hub using a Send connection string. The template (`templates/destinations/eventhub-destination.*`) creates a Standard+ namespace, the destination hub, and a least-privilege **Send** SAS rule (`abstract-send`), with optional Entra ID (`Azure Event Hubs Data Sender`) delivery.

| Abstract destination field | Where it comes from |
| --- | --- |
| EventHub Name | the hub you named (output `eventHubName`, default `abstract-destination-hub`) |
| EventHub Connection String | namespace → Shared access policies → `abstract-send` → **primary connection string** (a Send-only key; never emitted in outputs) |

```bash
az deployment group create -g rg-abstract-dest \
  --template-file templates/destinations/eventhub-destination.azuredeploy.json \
  --parameters parameters/eventhub-destination.parameters.json \
  --parameters namespaceName=abs-dest001
```

### Azure Sentinel Destination

Per the [Sentinel Destination docs](https://docs.abstractsecurity.app/docs/integrations/destination-integrations/azure-sentinel-destination/), Abstract delivers events through the Azure Monitor **Logs Ingestion API**. The template (`templates/destinations/sentinel-destination.*`) automates the Azure side in one deployment: Log Analytics workspace → **Microsoft Sentinel** → Data Collection Endpoint → custom `*_CL` table → Data Collection Rule → **both** DCR role assignments.

**Prerequisite — register the Entra app yourself (ARM cannot create app registrations).** Create a **single-tenant** app (e.g. `Abstract-Sentinel-App`), then:

- copy the **Application (client) ID** and **Directory (tenant) ID**;
- create a **client secret** and copy its **value immediately** (shown only once);
- get the app's **service principal object ID** and pass it to the template as `principalId`.

The template then grants that service principal **both** `Monitoring Metrics Publisher` **and** `Monitoring Contributor` on the DCR — the Logs Ingestion API needs both role assignments on the same app. Everything else in the doc's manual flow (workspace, Sentinel, DCE, custom `_CL` table, DCR + its Immutable ID and `Custom-<table>` stream name) is created by the deployment.

**Deployment outputs → Abstract "Azure Monitor Details":**

| Deployment output | Abstract modal field |
| --- | --- |
| `dataCollectionRuleImmutableId` | Data Collection Rule ID |
| `dataCollectionEndpointUrl` (logs-ingestion URI) | Data Collection Endpoint |
| `logStreamName` = `Custom-<table>` (default `Custom-AbstractEventLogs_CL`) | Log Stream Name |

The **Authentication** values are *not* template outputs — they come from the app registration: Client ID = Application (client) ID, Client Secret Value = the secret you copied, Application Tenant ID = Directory (tenant) ID.

**Add the destination in Abstract** — Integrations → Available → **Azure Sentinel Destination** → **Add Integration**:

1. **Name & instance** — Integration Name, Poll Interval (default `300`s), Abstract Instance, optional Forwarder.
2. **Authentication** — Client ID, Client Secret Value, Application Tenant ID (from the app registration).
3. **Azure Monitor Details** — Data Collection Rule ID, Data Collection Endpoint, Log Stream Name (from the outputs above).
4. *(Optional)* upload a custom **Parser/Mapper**.
5. **Validate → Save & Close**, then configure **Routing** to send a pipeline's events to this destination.

**Schema note — mind the columns.** The template's default table schema is minimal: three columns — `TimeGenerated` (datetime), `Message` (string), and `AbstractEvent` (dynamic). The whole Abstract Common Schema event lands in the `AbstractEvent` dynamic column, and the solution's `ASim_AbstractEvent` parser projects fields out of it. This is intentional, works with Abstract's default mapper, and is the **only** schema the portal Deploy button supports. **If your Abstract routing/mapper instead emits explicit per-field ACS columns** (the doc's `all_fields.json` approach), you must deploy via **CLI** and pass a matching `tableColumns` parameter built from Abstract's `all_fields.json` — otherwise the DCR silently **drops any column not declared in the table**, and you lose fields.

```bash
# default minimal schema (wrapped-dynamic AbstractEvent):
az deployment group create -g rg-abstract-sentinel \
  --template-file templates/destinations/sentinel-destination.azuredeploy.json \
  --parameters parameters/sentinel-destination.parameters.json \
  --parameters principalId=<spn-object-id>

# full per-field ACS schema (explicit columns) — generated from the real catalog:
az deployment group create -g rg-abstract-sentinel \
  --template-file templates/destinations/sentinel-destination.azuredeploy.json \
  --parameters parameters/sentinel-destination.full-schema.parameters.json \
  --parameters principalId=<spn-object-id>
```

The full-schema params file is **generated from the canonical Abstract Common Schema** — [`solution/schema/all_fields.json`](solution/schema/all_fields.json) (1,872 fields: 473 static + the `ext.*` vendor namespace, sourced from the Abstract API's `GET /v1/acs/fields`). Regenerate or re-tune it with [`scripts/gen-sentinel-schema.py`](scripts/gen-sentinel-schema.py), which maps Abstract types → Log Analytics types, flattens dotted ACS names to underscores, and collapses `ext.*` into one dynamic column (474 columns; `--static-only` or `--explode-ext` to change coverage).

> **Existing workspace in another region?** In *Existing* mode the DCE/DCR must sit in the workspace's region. Pass `existingWorkspaceLocation=<region>` (or set it in the wizard's "Existing workspace region" field) so they are created there.

#### Automate the app registration + roles

ARM can't create Entra app registrations, but you don't have to click through the portal for them either. Two options:

- **Standalone script (recommended)** — [`scripts/new-abstract-sentinel-app.sh`](scripts/new-abstract-sentinel-app.sh) (bash / `az`) and [`scripts/New-AbstractSentinelApp.ps1`](scripts/New-AbstractSentinelApp.ps1) (PowerShell 7 / Az) create the app + service principal + client secret, then (with `--deploy` / `-Deploy`) deploy the template so the SP gets **both** DCR roles, and print the exact modal values. The secret is shown **once** (or pushed to Key Vault with `--keyvault` / `-KeyVault`) and never written to disk. Lowest privilege — you only need rights to register an app, plus Owner/UAA on the RG to deploy.

  ```bash
  # identity + full ingestion stack + both DCR roles, in one shot:
  ./scripts/new-abstract-sentinel-app.sh --app-name Abstract-Sentinel-App \
    --deploy --resource-group rg-abstract-sentinel --location eastus
  ```

- **One-click ARM variant (advanced)** — [`templates/destinations/sentinel-destination-with-app.*`](templates/destinations/) does the *whole thing* — including the app registration — via an Azure `deploymentScript`, storing the client secret in **Key Vault** (never in a deployment output). It's heavier and has prerequisites: you must supply a **user-assigned managed identity that already holds "Application Administrator"** (`managedIdentityResourceId`), and the deployer needs Owner (or Contributor + User Access Administrator) on the resource group. Retrieve the secret from Key Vault to paste into Abstract; all other modal values are in the deployment outputs. Prefer the standalone script unless you specifically need pure one-click.

  ```bash
  az deployment group create -g rg-abstract-sentinel \
    --template-file templates/destinations/sentinel-destination-with-app.azuredeploy.json \
    --parameters parameters/sentinel-destination-with-app.parameters.json \
    --parameters managedIdentityResourceId=<uami-resource-id>
  ```

---

## Notable template behaviors (and the bugs they fix)

v1 fixed ten issues found in a hand-written draft, all still guarded here: correct **Event Hubs** role GUIDs (not Service Bus), no conditional-loop syntax, `networkRuleSets` as a child resource, `maximumThroughputUnits` omitted when auto-inflate is off, Basic-SKU feature guards (now moot — Basic removed per Abstract docs), `principalType` set to avoid `PrincipalNotFound` races, `allLogs` category group, and **no secrets in outputs** (the `abstractOnboarding` output points you to where each secret lives instead of echoing it).

v2 adds per the official Abstract documentation: the **checkpoint storage stack** (account + private container + Storage Blob Data Contributor + optional blob private endpoint + firewall mirroring), **Listen-only** default SAS rights, default hub sources `activity/entra/defender`, `defaultPartitionCount`/`defaultRetentionDays`, Standard-minimum SKU, input trimming/filtering so CSV-driven portal inputs can't produce empty hub names, and the portal wizard + subscription Activity Log template.

v3 adds the **Azure Event Hub Destination** and **Azure Sentinel Destination** templates (each with its own wizard + Deploy button), a branded `docs/index.html` landing page, Abstract branding in the wizards, the previously-missing `abstract-diagnostics-send` Send rule + `abstractDiagnosticsAuthRuleId` output (so Activity Log export uses a least-privilege rule instead of RootManageSharedAccessKey), and Bicep-compiled ARM for every template.

Caveats worth knowing:

- **Bicep-compiled ARM**: every `*.azuredeploy.json` is generated from its `*.bicep` with `az bicep build`. If you change a `.bicep`, regenerate the matching ARM (`az bicep build --file <f>.bicep --outfile <f>.azuredeploy.json`); CI flags drift.
- **Sentinel destination needs an Entra app** (client ID/secret/tenant) which ARM cannot create — make it first and pass the SP object ID for the DCR role grants. Existing-workspace mode expects the workspace in the same resource group with Sentinel already enabled.
- **Premium** ignores auto-inflate (capacity = PUs: 1/2/4/8/16) and `zoneRedundant` behavior differs by region.
- Deleting the namespace does **not** delete the storage account, private endpoints, diagnostic settings, or the app registration — the script's `Delete` action reminds you.
- The Entra log export uses the legacy `microsoft.aadiam` API (best effort) and needs Entra P1/P2 plus Security Administrator.

## License

MIT — see [LICENSE](LICENSE).
