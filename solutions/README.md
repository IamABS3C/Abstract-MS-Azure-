<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/abstract-logo-white.png">
    <img src="brand/abstract-logo-black.png" alt="Abstract Security" height="44">
  </picture>
</p>

<h1 align="center">Template reference</h1>

<p align="center">
  <a href="#what-each-template-does">Templates</a> ·
  <a href="#the-fully-documented-alternative-template-specs">Template specs</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#verified-not-assumed">Verified</a> ·
  <a href="#known-gaps-stated-plainly">Known gaps</a> ·
  <a href="../README.md">Back to the overview</a>
</p>

Every template in this directory, with its scope, files, outputs, deploy button and CLI
command. The [overview](../README.md) has the "I want to…" guide, requirements and quick
start; production Sentinel customers should read the
[Sentinel Destination assurance guide](docs/sentinel-destination-assurance.md) first.

Every `*.bicep` has a compiled `*.azuredeploy.json` beside it and a matching
`*.createUiDefinition.json` or `*.uiFormDefinition.json`. CI fails if the ARM file is stale,
so what you review is what customers deploy.

---

## What each template does

<!-- BEGIN GENERATED: template-detail -->
#### Event Hub (Source)

Everything Abstract needs to READ from Azure: Event Hubs namespace, one hub per log source, consumer group, the checkpoint storage account + private blob container the Abstract consumer requires, SAS and/or Entra RBAC auth, networking guardrails.

- **Scope:** resource group · **Portal UI:** `createUiDefinition`
- **Deploy:** [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsource%2Feventhub-source.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsource%2Feventhub-source.createUiDefinition.json)
- **CLI:** `az deployment group create -g <rg> --template-file solutions/templates/source/eventhub-source.bicep`
- **Files:** `templates/source/eventhub-source.bicep` · `templates/source/eventhub-source.azuredeploy.json` · `templates/source/eventhub-source.createUiDefinition.json`
- **Outputs you need next:** `abstractDiagnosticsAuthRuleId`, `eventHubNames`
- **Note:** Deploy this first — every other source template consumes its outputs. Azure Policy never creates hubs, so hub names you pass elsewhere must exist here.

#### Activity Log export (single subscription)

Streams ONE subscription's Azure Activity Log to the Abstract Event Hub. For a whole estate, use the log-stream governance pack instead.

- **Scope:** subscription · **Portal UI:** `uiFormDefinition`
- **Deploy:** [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsubscription%2Factivitylog.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsubscription%2Factivitylog.uiFormDefinition.json)
- **CLI:** `az deployment sub create -l <region> --template-file solutions/templates/subscription/activitylog.bicep`
- **Files:** `templates/subscription/activitylog.bicep` · `templates/subscription/activitylog.azuredeploy.json` · `templates/subscription/activitylog.uiFormDefinition.json`
- **Note:** Subscription scope, so it uses a Form view — createUiDefinition cannot bind a portal deployment to a subscription.

#### Log streams at scale (Azure Policy)

Assign once at a management group and every subscription in it — current and future — streams Activity Log, resource logs, SQL auditing and Defender for Cloud to the Abstract Event Hub, and self-heals if a setting is deleted.

- **Scope:** management group · **Portal UI:** `uiFormDefinition`
- **Deploy:** [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-logstreams-policy.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-logstreams-policy.uiFormDefinition.json)
- **CLI:** `az deployment mg create -m <mg-id> -l <region> --template-file solutions/templates/policy/abstract-logstreams-policy.bicep`
- **Files:** `templates/policy/abstract-logstreams-policy.bicep` · `templates/policy/abstract-logstreams-policy.azuredeploy.json` · `templates/policy/abstract-logstreams-policy.uiFormDefinition.json`
- **Driver script:** `scripts/Deploy-AbstractLogStreams.sh`
- **Note:** Three gotchas decide whether this works: the region rule (one namespace per region), remediation is not optional, and new subscriptions must land in the right management group. See docs/azure-log-streams.md.

#### Pipeline health alerts

Alerts on the failure this pipeline cannot otherwise show you: Event Hubs publishes NO consumer-lag metric, so a stalled Abstract consumer leaves incoming messages healthy and every dashboard green while retention quietly expires the backlog. Infers the stall from outgoing traffic collapsing while incoming continues, plus ingestion-stopped, throttling, credential errors and quota ceilings.

- **Scope:** resource group · **Portal UI:** `createUiDefinition`
- **Deploy:** [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fmonitoring%2Fpipeline-health-alerts.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fmonitoring%2Fpipeline-health-alerts.createUiDefinition.json)
- **CLI:** `az deployment group create -g <rg> --template-file solutions/templates/monitoring/pipeline-health-alerts.bicep`
- **Files:** `templates/monitoring/pipeline-health-alerts.bicep` · `templates/monitoring/pipeline-health-alerts.azuredeploy.json` · `templates/monitoring/pipeline-health-alerts.createUiDefinition.json`
- **Prerequisite:** An existing Event Hubs namespace (deploy the Event Hub source template first), and ideally an Action Group to notify.
- **Note:** The consumer-stall rule is a scheduled QUERY rule, not a metric alert, and deliberately so: Event Hubs metrics are sparse, so a metric alert on 'outgoing < threshold' has no data to evaluate and sits in Insufficient Data forever. The KQL synthesises a zero row when the metric is silent. Does NOT cover the Auto-Inflate cost ratchet — there is no platform metric for provisioned throughput units, only the AutoScaleLogs diagnostic category, which needs a diagnostic setting on the namespace itself.

#### Microsoft Entra ID log streams

Tenant-wide Entra ID diagnostic setting: sign-ins (interactive, non-interactive, SP, MI), directory audit, provisioning, Identity Protection risk, and Microsoft Graph activity.

- **Scope:** tenant · **Portal UI:** `uiFormDefinition`
- **Deploy:** [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Ftenant%2Fentra-diagnostics.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Ftenant%2Fentra-diagnostics.uiFormDefinition.json)
- **CLI:** `az deployment tenant create -l <region> --template-file solutions/templates/tenant/entra-diagnostics.bicep`
- **Files:** `templates/tenant/entra-diagnostics.bicep` · `templates/tenant/entra-diagnostics.azuredeploy.json` · `templates/tenant/entra-diagnostics.uiFormDefinition.json`
- **Note:** No Azure Policy can manage this — Entra diagnostic settings are tenant-level, so there is no per-subscription object to evaluate. Expect up to three days for the first records.

#### App registrations (event-driven) ⭐ **recommended**

One central Logic App creates an Entra app + service principal per subscription, grants AND VERIFIES admin consent, writes the client secret to Key Vault, and assigns Azure RBAC on the target subscription.

- **Scope:** resource group · **Portal UI:** `createUiDefinition`
- **Deploy:** [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fautomation%2Fabstract-appreg-automation.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fautomation%2Fabstract-appreg-automation.createUiDefinition.json)
- **CLI:** `az deployment group create -g <rg> --template-file solutions/templates/automation/abstract-appreg-automation.bicep`
- **Files:** `templates/automation/abstract-appreg-automation.bicep` · `templates/automation/abstract-appreg-automation.azuredeploy.json` · `templates/automation/abstract-appreg-automation.createUiDefinition.json`
- **Prerequisite:** scripts/Deploy-AbstractAppReg.sh -a Bootstrap (Global Administrator, once per tenant)
- **Driver script:** `scripts/Deploy-AbstractAppReg.sh`
- **Note:** Recommended over the policy variant: one tier-0 identity in one place, one run history as the audit trail, no per-subscription compute. Live-tested end to end.

#### App registrations (Azure Policy)

Same outcome as the event-driven path, delivered through Azure Policy: a DeployIfNotExists policy deploys a deploymentScript container into each subscription which then calls Graph.

- **Scope:** management group · **Portal UI:** `uiFormDefinition`
- **Deploy:** [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-appreg-policy.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-appreg-policy.uiFormDefinition.json)
- **CLI:** `az deployment mg create -m <mg-id> -l <region> --template-file solutions/templates/policy/abstract-appreg-policy.bicep`
- **Files:** `templates/policy/abstract-appreg-policy.bicep` · `templates/policy/abstract-appreg-policy.azuredeploy.json` · `templates/policy/abstract-appreg-policy.uiFormDefinition.json`
- **Prerequisite:** scripts/Deploy-AbstractAppReg.sh -a Bootstrap (Global Administrator, once per tenant)
- **Driver script:** `scripts/Deploy-AbstractAppReg.sh`
- **Note:** Only when governance mandates Azure Policy. It spawns a privileged container in every subscription, needs Owner on each, and cannot see the Entra app it created.

#### Event Hub Destination

Where Abstract WRITES processed events: namespace, destination hub, least-privilege Send SAS rule, optional Entra ID (RBAC) delivery, Safe Mode networking.

- **Scope:** resource group · **Portal UI:** `createUiDefinition`
- **Deploy:** [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Feventhub-destination.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Feventhub-destination.createUiDefinition.json)
- **CLI:** `az deployment group create -g <rg> --template-file solutions/templates/destinations/eventhub-destination.bicep`
- **Files:** `templates/destinations/eventhub-destination.bicep` · `templates/destinations/eventhub-destination.azuredeploy.json` · `templates/destinations/eventhub-destination.createUiDefinition.json`
- **Note:** Keys are never emitted in deployment outputs — fetch the Send connection string from the portal or CLI.

#### Microsoft Sentinel Destination

Abstract writes to Sentinel via the Logs Ingestion API: Log Analytics workspace, Sentinel onboarding, Data Collection Endpoint, custom _CL table, Data Collection Rule, and the DCR role assignments.

- **Scope:** resource group · **Portal UI:** `createUiDefinition`
- **Deploy:** [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination.createUiDefinition.json)
- **CLI:** `az deployment group create -g <rg> --template-file solutions/templates/destinations/sentinel-destination.bicep`
- **Files:** `templates/destinations/sentinel-destination.bicep` · `templates/destinations/sentinel-destination.azuredeploy.json` · `templates/destinations/sentinel-destination.createUiDefinition.json`
- **Prerequisite:** Create a single-tenant Entra app and client secret first — scripts/New-AbstractSentinelApp.ps1. Pass the service principal object ID (not the client ID) for DCR role assignments.
- **Note:** The table has one column per top-level key of the Abstract Common Schema event, as the Abstract Azure Sentinel Destination sends it (nested objects are dynamic), generated from the ACS catalog by scripts/gen-sentinel-schema.py. The DCR transformation sets TimeGenerated and stores the reserved id and type keys as acs_id and acs_type. Override tableColumns only for a custom payload shape. Enter the client ID, secret value, tenant ID, DCR immutable ID, DCE ingestion URL, and exact stream name (Custom-<table name>) in Abstract. Use the with-app variant to create the app in the same deployment. Optionally (enableAsim, off by default) each event is also mapped into Microsoft's ASIM tables, so Microsoft's ASIM content works on Abstract data from every vendor; turning it on makes existing ASIM rules read Abstract data, so stage it first (docs/sentinel-asim.md). Only Monitoring Metrics Publisher is granted on the DCR unless grantMonitoringContributor is set. A redeploy keeps the Abstract table's retention and plan unless customTableRetentionDays or customTablePlan is set. Nothing touches existing analytics rules, automation, parsers, workbooks or workspace settings: see docs/sentinel-destination-assurance.md.

#### Sentinel Destination + app registration

The Sentinel destination plus the Entra app registration, created in one deployment via a deploymentScript. Choose a new Key Vault, an existing Key Vault, or no Key Vault.

- **Scope:** resource group · **Portal UI:** `createUiDefinition`
- **Deploy:** [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination-with-app.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination-with-app.createUiDefinition.json)
- **CLI:** `az deployment group create -g <rg> --template-file solutions/templates/destinations/sentinel-destination-with-app.bicep`
- **Files:** `templates/destinations/sentinel-destination-with-app.bicep` · `templates/destinations/sentinel-destination-with-app.azuredeploy.json` · `templates/destinations/sentinel-destination-with-app.createUiDefinition.json`
- **Prerequisite:** A user-assigned managed identity whose service principal has the Microsoft Graph Application.ReadWrite.All application permission with tenant admin consent (AppRoleAssignment.ReadWrite.All is not needed). If that identity or an existing Key Vault is in another subscription or resource group, the deploying principal also needs Managed Identity Operator on the identity and role-assignment rights on the vault. The deploying principal needs Owner (or Contributor plus User Access Administrator) on the resource group.
- **Note:** Create and Existing Key Vault modes store the generated client secret; re-runs reuse it while more than 30 days remain. None mode creates no secret; create one in Entra after deployment and copy its value into Abstract. Secret values are never returned in ARM outputs. A new secret is generated only when none is usable or it expires within 30 days; forceSecretRotation is for deliberate rotation. Deployment outputs include the client ID, tenant ID, DCR immutable ID, DCE URL, and exact stream name (Custom-<table name>). Set secretReaderObjectId to grant an optional user or group Key Vault Secrets User access to retrieve the secret. Optionally (enableAsim, off by default) each event is also mapped into Microsoft's ASIM tables, so Microsoft's ASIM content works on Abstract data from every vendor; turning it on makes existing ASIM rules read Abstract data, so stage it first (docs/sentinel-asim.md). Only Monitoring Metrics Publisher is granted on the DCR unless grantMonitoringContributor is set. A redeploy keeps the Abstract table's retention and plan unless customTableRetentionDays or customTablePlan is set. Nothing touches existing analytics rules, automation, parsers, workbooks or workspace settings: see docs/sentinel-destination-assurance.md.
<!-- END GENERATED: template-detail -->

---

## The fully documented alternative: template specs

<!-- BEGIN GENERATED: template-spec -->
The deploy buttons use `uiFormDefinitionUri`, which the portal accepts but which
Microsoft does **not** document for Deploy-to-Azure links. Template specs are the
documented delivery path for the identical wizard — use these when a customer's
policy allows only documented Microsoft flows, or if the button form ever changes:

**Activity Log export (single subscription)** (subscription scope)

```bash
az ts create --name activitylog --version 1.0 -g <rg> -l <region> \
  --template-file solutions/templates/subscription/activitylog.azuredeploy.json \
  --ui-form-definition solutions/templates/subscription/activitylog.uiFormDefinition.json
# then: portal → Template specs → activitylog → Deploy
```

**Log streams at scale (Azure Policy)** (management group scope)

```bash
az ts create --name abstract-logstreams-policy --version 1.0 -g <rg> -l <region> \
  --template-file solutions/templates/policy/abstract-logstreams-policy.azuredeploy.json \
  --ui-form-definition solutions/templates/policy/abstract-logstreams-policy.uiFormDefinition.json
# then: portal → Template specs → abstract-logstreams-policy → Deploy
```

**Microsoft Entra ID log streams** (tenant scope)

```bash
az ts create --name entra-diagnostics --version 1.0 -g <rg> -l <region> \
  --template-file solutions/templates/tenant/entra-diagnostics.azuredeploy.json \
  --ui-form-definition solutions/templates/tenant/entra-diagnostics.uiFormDefinition.json
# then: portal → Template specs → entra-diagnostics → Deploy
```

**App registrations (Azure Policy)** (management group scope)

```bash
az ts create --name abstract-appreg-policy --version 1.0 -g <rg> -l <region> \
  --template-file solutions/templates/policy/abstract-appreg-policy.azuredeploy.json \
  --ui-form-definition solutions/templates/policy/abstract-appreg-policy.uiFormDefinition.json
# then: portal → Template specs → abstract-appreg-policy → Deploy
```
<!-- END GENERATED: template-spec -->

---

## Architecture

```
                    ┌──────────────────────────────────────────┐
   AZURE ESTATE     │  Activity Log      (subscription scope)   │
                    │  Resource logs     (~140 resource types)  │
                    │  SQL auditing      (separate mechanism)   │
                    │  Defender for Cloud (continuous export)   │
                    └────────────────┬─────────────────────────┘
                                     │  Azure Policy, assigned ONCE
                                     │  at a management group
                                     ▼
   MICROSOFT ENTRA  ┌──────────────────────────────────────────┐
   (tenant scope)   │  Sign-ins · audit · provisioning · risk   │
                    │  Microsoft Graph activity                 │
                    └────────────────┬─────────────────────────┘
                                     │  ONE tenant diagnostic setting
                                     │  (no policy can reach this)
                                     ▼
                    ╔══════════════════════════════════════════╗
                    ║   EVENT HUBS  — one namespace per region   ║
                    ║   + checkpoint storage for the consumer    ║
                    ╚────────────────┬─────────────────────────╝
                                     ▼
                    ╔══════════════════════════════════════════╗
                    ║          ABSTRACT SECURITY               ║
                    ║  normalize · enrich · reduce · detect     ║
                    ╚────────┬───────────────────────┬─────────╝
                             ▼                       ▼
                    ┌────────────────┐      ┌────────────────────┐
                    │ Event Hub dest │      │ Sentinel via Logs  │
                    │ (any consumer) │      │ Ingestion API + DCR│
                    └────────────────┘      └────────────────────┘

   GRAPH / M365 (not Event Hub at all)
   ┌──────────────────────────────────────────────────────────────┐
   │ Entra app registration per subscription → Abstract polls      │
   │ Microsoft Graph and the Office 365 Management Activity API    │
   └──────────────────────────────────────────────────────────────┘
```

### Three constraints that decide every design here

**1. The region rule.** Azure Monitor **rejects** a diagnostic setting whose Event Hub is
in a different region from the monitored resource. Verified by attempting it:

```
ERROR: (BadRequest) Resources should be in the same region.
Resource '…/workspaces/abs-regiontest-eastus' is in region 'eastus' and
resource '…/namespaces/absfault-logs' is in region 'centralus'.
```

So: one Event Hubs namespace **per region** that holds regional resources, and one
resource-log policy assignment per region. Activity Log, Defender for Cloud and Entra ID
are exempt — they are not regional, so one hub serves the whole estate.

**2. `DeployIfNotExists` never touches what you already own.** It fires on resource create
or update. Your existing estate stays dark until a **remediation task** backfills it. Skip
that and the hub looks mysteriously quiet while compliance looks fine.

**3. "Future subscriptions" has a second half.** A management-group assignment covers
subscriptions added later — but a brand-new subscription lands in the **Tenant Root Group**
by default, not in your group. Set the tenant's *default management group for new
subscriptions*, or new subscriptions silently miss the policy.

Full detail: [docs/azure-log-streams.md](docs/azure-log-streams.md) ·
[docs/azure-app-registrations.md](docs/azure-app-registrations.md)

---

## Repository layout

```
solutions/
├── solution.manifest.json      single source of truth: repo coordinates, templates, docs, scripts
├── README.md                   this file; the template sections are generated
├── templates/
│   ├── source/                 Event Hub collection estate            (resource group)
│   ├── subscription/           Activity Log, one subscription          (subscription)
│   ├── tenant/                 Entra ID log streams                    (tenant)
│   ├── policy/                 estate-wide governance + appreg policy  (management group)
│   │   └── scripts/            deploymentScript bodies, loaded with loadTextContent()
│   ├── automation/             event-driven app registrations          (resource group)
│   ├── monitoring/             pipeline health alerts                  (resource group)
│   └── destinations/           Event Hub + Sentinel destinations       (resource group)
│       └── scripts/            deploymentScript bodies
├── asim/                       ACS → Microsoft ASIM mappings, and Microsoft's table columns
├── parameters/                 parameter presets and generated schemas
├── scripts/                    drivers, validators and generators
├── docs/                       guides
├── brand/                      official Abstract logos and README artwork
└── ci/                         CI helpers
```

---

## Verified, not assumed

Every claim below was tested against a live Azure tenant or the live Microsoft Graph
service principal, and the test artifacts were deleted afterwards. Where a test surfaced a
bug in our own code, the bug is named.

| Claim | How it was verified |
| --- | --- |
| Event Hub must share a region with the monitored resource | Attempted a cross-region diagnostic setting; got `BadRequest: Resources should be in the same region` |
| A `Send`-only SAS rule is sufficient | Created a subscription diagnostic setting with a `Send`-only rule; it succeeded and read back its categories |
| No Microsoft built-in exists for Activity Log → Event Hub | Queried the live built-in catalogue; only the Log Analytics variant `2465583e-…` exists. Three GUIDs published by third-party catalogues return `PolicyDefinitionNotFound` |
| `Security.Read.All` does not exist | Checked all 707 Graph application appRoles **and** the delegated scopes. Absent from both. It was in our own catalogue, silently creating a gap — removed |
| `map()`/`filter()` are unavailable in Logic Apps | A deployed workflow failed at runtime: `The template function 'filter' is not defined or not valid`. Rewrote with Query/Select data operations |
| `GET /subscriptions/{id}` hides `tags` from a Reader | Same call returned tags as Owner, omitted the property entirely as Reader — which made a tag gate skip the whole estate, silently. Now reads the dedicated tags endpoint |
| Policy-created app registrations work end to end | Deployed the Logic App path and drove it: trigger → resolve → subscription read → tags read → tag gate → Graph, failing exactly where the test identity lacked consent |
| Consent must be read back, not assumed | Our provisioner reported "Consent granted" unconditionally while swallowing every error. Now verifies against Graph and reports a count |

### Known gaps, stated plainly

- **The Azure Policy app-registration path is not runtime-tested.** Management-group
  validation is blocked by `AuthorizationFailed` at the tenant root in the test tenant. Its
  existence check now reads a durable resource-group tag, and it now refuses to reuse an app
  it did not create; both are compile-checked only.
- **The event-driven app-registration path has no working automatic trigger.** Its optional
  Event Grid system topic is created without an event subscription, so new subscriptions are
  onboarded by calling the workflow, not automatically.
- **The app-registration provisioning identity is tier-0.** It holds Microsoft Graph
  `Application.ReadWrite.All` and `AppRoleAssignment.ReadWrite.All` and Owner on each target
  subscription. Keep it tightly controlled and review [App registrations](docs/azure-app-registrations.md).
- **Pipeline health alerts need namespace diagnostics.** The "consumer stalled" alert reads
  `AzureMetrics`, which exists only when the Event Hubs namespace sends its metrics to a
  Log Analytics workspace (`enableDiagnostics` on the Event Hub source).
- **Redeploying an Event Hub template re-applies its settings.** Capacity, network rules and
  storage settings return to the template's values, so treat the namespace as dedicated to
  Abstract and redeploy with the values you run.
- **No scheduled secret rotation.** The templates avoid churning secrets, but nothing
  rotates them on a schedule and updates Abstract.
- **Wizards are contract-validated, not visually rendered.** Run them through the portal
  before a customer-facing demo.

---

## Support

- **Guides:** [Sentinel Destination assurance](docs/sentinel-destination-assurance.md) ·
  [Sending Abstract data into Sentinel (ASIM)](docs/sentinel-asim.md) ·
  [Azure log streams at scale](docs/azure-log-streams.md) ·
  [Per-subscription app registrations](docs/azure-app-registrations.md)
- **Maintainers:** [CONTRIBUTING.md](../CONTRIBUTING.md)
- **Abstract docs:** [docs.abstractsecurity.app](https://docs.abstractsecurity.app)

<p align="center"><sub>Abstract Security — the security data pipeline platform.</sub></p>
