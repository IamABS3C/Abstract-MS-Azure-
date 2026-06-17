<p align="center">
  <img src="https://cybersecurity-excellence-awards.com/wp-content/uploads/163661.png" alt="Abstract Security" height="80" />
</p>

# Abstract Security — Azure Onboarding

Production-ready Azure infrastructure for Abstract Security **source** and **destination** integrations, deployable from the portal (Deploy to Azure buttons with guided wizards), the CLI, or a menu-driven PowerShell script:

- **Event Hub (Source)** — Abstract *reads from* Event Hub: namespace, one hub per log source, consumer group, the **checkpoint Storage Account + private blob container Abstract requires**, SAS and/or Entra ID (RBAC) auth, networking guardrails, log-export plumbing.
- **Event Hub Destination** — Abstract *writes to* an Event Hub: namespace, destination hub, least-privilege **Send** SAS rule (+ optional Entra ID delivery).
- **Azure Sentinel Destination** — Abstract *writes to* Microsoft Sentinel via the Logs Ingestion API: Log Analytics workspace, Sentinel, Data Collection Endpoint, custom `_CL` table, Data Collection Rule, and the DCR role assignments.

> **One page to deploy anything:** the branded landing page in [`docs/`](docs/index.html) (enable GitHub Pages on `/docs`) renders the logo and every Deploy to Azure button.

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
│   └── sentinel-destination.parameters.json
├── scripts/
│   └── Deploy-AbstractEventHub.ps1  # guided deploy / credentials / delete (source only)
├── templates/
│   ├── subscription/
│   │   ├── activitylog.bicep         # Activity Log → hub (subscription scope)
│   │   └── activitylog.azuredeploy.json
│   └── destinations/
│       ├── eventhub-destination.bicep / .azuredeploy.json / .createUiDefinition.json
│       └── sentinel-destination.bicep / .azuredeploy.json / .createUiDefinition.json
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

Per the [Sentinel Destination docs](https://docs.abstractsecurity.app/docs/integrations/destination-integrations/azure-sentinel-destination/), Abstract delivers events through the Azure Monitor **Logs Ingestion API**. The template (`templates/destinations/sentinel-destination.*`) provisions the full stack: Log Analytics workspace → **Microsoft Sentinel** → Data Collection Endpoint → custom `*_CL` table → Data Collection Rule → DCR role assignments.

**Prerequisite — create the Entra app first (ARM cannot):** register an app (e.g. `Abstract-Sentinel-App`), add a client secret, and note its **Application (client) ID**, **Directory (tenant) ID**, the **secret value**, and the **service principal object ID**. Pass the object ID to the template so it grants the SP `Monitoring Metrics Publisher` + `Monitoring Contributor` on the DCR.

| Abstract Sentinel field | Where it comes from |
| --- | --- |
| Client ID | your app registration's Application (client) ID |
| Client Secret Value | the secret you created (store it once) |
| Application Tenant ID | Directory (tenant) ID (template output also surfaces it) |
| Data Collection Rule ID | output `dataCollectionRuleImmutableId` |
| Data Collection Endpoint | output `dataCollectionEndpointUrl` (logs-ingestion URI) |
| Log Stream Name | output `logStreamName` = `Custom-<table>` (default `Custom-AbstractEventLogs_CL`) |

The default custom-table schema is minimal (`TimeGenerated`, `Message`, `AbstractEvent`). To capture the full Abstract Common Schema, deploy via CLI and pass a `tableColumns` array built from Abstract's `all_fields.json`:

```bash
az deployment group create -g rg-abstract-sentinel \
  --template-file templates/destinations/sentinel-destination.azuredeploy.json \
  --parameters parameters/sentinel-destination.parameters.json \
  --parameters principalId=<spn-object-id>
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
