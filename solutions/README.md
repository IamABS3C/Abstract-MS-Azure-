<p align="center">
  <img src="https://cybersecurity-excellence-awards.com/wp-content/uploads/163661.png" alt="Abstract Security" height="76" />
</p>

<h1 align="center">Abstract Security — Azure &amp; Microsoft Sentinel</h1>

<p align="center">
  <strong>Nine production templates. Four deployment scopes. Every one with a guided portal wizard, compiled ARM, and Bicep source.</strong><br>
  Get Microsoft telemetry into Abstract, govern it across the whole estate, and send enriched output back to Sentinel.
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#deploy">Deploy</a> ·
  <a href="#what-each-template-does">Templates</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#customize-it">Customize</a> ·
  <a href="#port-it-to-another-repo">Port it</a> ·
  <a href="#verified-not-assumed">Verified</a>
</p>

---

## Why this exists

Onboarding Azure into a security pipeline is usually a pile of half-documented portal
clicks that nobody can reproduce, audit, or hand to a customer. This is the opposite:
every path is a template, every template has a wizard, every wizard is checked in CI
against its template, and every non-obvious claim in these docs was **tested against a
live Azure tenant** rather than inferred from documentation.

Three things here you will not find in a generic Azure quickstart:

- **Estate-wide governance, not per-subscription toil.** One management-group assignment
  onboards every subscription — current *and* future — and puts a diagnostic setting back
  if someone deletes it.
- **App registrations, automated end to end** including admin consent that is **verified
  by reading it back from Graph**, so "we consented, why is Abstract getting 403s" stops
  being a support call.
- **Portal wizards at subscription, management-group and tenant scope.** Most solutions
  cannot do this, because the common `createUiDefinition` model physically cannot bind a
  portal deployment above a resource group. These use Form view where that matters.

---

## Quick start

The shortest path from nothing to Azure telemetry flowing into Abstract:

```bash
# 1. Event Hub estate — deploy FIRST, everything else consumes its outputs.
#    Note the abstractDiagnosticsAuthRuleId and eventHubNames outputs.
az deployment group create -g rg-abstract \
  --template-file solutions/templates/source/eventhub-source.bicep \
  --parameters namespaceName=<globally-unique-name>

# 2. Onboard the whole estate in report-only mode — changes nothing, tells you
#    exactly which subscriptions and resources would be collected.
./solutions/scripts/Deploy-AbstractLogStreams.sh -a Deploy \
  -m <management-group-id> -p solutions/parameters/logstreams-policy.parameters.json

# 3. Let the policy identities write to the hub, then backfill what you already own.
./solutions/scripts/Deploy-AbstractLogStreams.sh -a Grant     -m <mg-id> -n <namespace-resource-id>
./solutions/scripts/Deploy-AbstractLogStreams.sh -a Remediate -m <mg-id>

# 4. Identity telemetry — one command for the entire tenant.
az deployment tenant create -l eastus \
  --template-file solutions/templates/tenant/entra-diagnostics.bicep \
  --parameters eventHubAuthorizationRuleId=<rule-id> eventHubName=<entra-hub>
```

Prefer clicking? Every step above also has a **Deploy to Azure** button below.

---

## Deploy

<!-- BEGIN GENERATED: deploy-table -->
### Sources — Abstract reads *from* Azure

Get Microsoft telemetry into Abstract. Deploy the Event Hub source first — every other source template consumes its outputs.

| Template | Scope | Deploy | Gov | CLI |
| --- | --- | --- | --- | --- |
| **Event Hub (Source)** **(deploy first)** | resource group | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsource%2Feventhub-source.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsource%2Feventhub-source.createUiDefinition.json) | [![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsource%2Feventhub-source.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsource%2Feventhub-source.createUiDefinition.json) | `az deployment group create -g <rg> --template-file solutions/templates/source/eventhub-source.bicep` |
| **Activity Log export (single subscription)** | subscription | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsubscription%2Factivitylog.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsubscription%2Factivitylog.uiFormDefinition.json) | [![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsubscription%2Factivitylog.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fsubscription%2Factivitylog.uiFormDefinition.json) | `az deployment sub create -l <region> --template-file solutions/templates/subscription/activitylog.bicep` |
| **Microsoft Entra ID log streams** | tenant | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Ftenant%2Fentra-diagnostics.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Ftenant%2Fentra-diagnostics.uiFormDefinition.json) | [![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Ftenant%2Fentra-diagnostics.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Ftenant%2Fentra-diagnostics.uiFormDefinition.json) | `az deployment tenant create -l <region> --template-file solutions/templates/tenant/entra-diagnostics.bicep` |

### Governance — onboard the whole estate

Stop configuring diagnostic settings one subscription at a time. Assign once at a management group; current and future subscriptions onboard themselves.

| Template | Scope | Deploy | Gov | CLI |
| --- | --- | --- | --- | --- |
| **Log streams at scale (Azure Policy)** | management group | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-logstreams-policy.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-logstreams-policy.uiFormDefinition.json) | [![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-logstreams-policy.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-logstreams-policy.uiFormDefinition.json) | `az deployment mg create -m <mg-id> -l <region> --template-file solutions/templates/policy/abstract-logstreams-policy.bicep` |

### Identity — app registrations for Graph / M365 collection

Event Hub collection needs no app registration. These are for the other source set: Microsoft Graph and the Microsoft 365 unified audit log.

| Template | Scope | Deploy | Gov | CLI |
| --- | --- | --- | --- | --- |
| **App registrations (event-driven)** ⭐ | resource group | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fautomation%2Fabstract-appreg-automation.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fautomation%2Fabstract-appreg-automation.createUiDefinition.json) | [![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fautomation%2Fabstract-appreg-automation.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fautomation%2Fabstract-appreg-automation.createUiDefinition.json) | `az deployment group create -g <rg> --template-file solutions/templates/automation/abstract-appreg-automation.bicep` |
| **App registrations (Azure Policy)** | management group | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-appreg-policy.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-appreg-policy.uiFormDefinition.json) | [![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-appreg-policy.azuredeploy.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fpolicy%2Fabstract-appreg-policy.uiFormDefinition.json) | `az deployment mg create -m <mg-id> -l <region> --template-file solutions/templates/policy/abstract-appreg-policy.bicep` |

### Destinations — Abstract writes *to* Azure

Send Abstract's enriched, normalized output back into Azure.

| Template | Scope | Deploy | Gov | CLI |
| --- | --- | --- | --- | --- |
| **Event Hub Destination** | resource group | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Feventhub-destination.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Feventhub-destination.createUiDefinition.json) | [![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Feventhub-destination.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Feventhub-destination.createUiDefinition.json) | `az deployment group create -g <rg> --template-file solutions/templates/destinations/eventhub-destination.bicep` |
| **Microsoft Sentinel Destination** | resource group | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination.createUiDefinition.json) | [![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination.createUiDefinition.json) | `az deployment group create -g <rg> --template-file solutions/templates/destinations/sentinel-destination.bicep` |
| **Sentinel Destination + app registration** | resource group | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination-with-app.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination-with-app.createUiDefinition.json) | [![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination-with-app.azuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2FAbstract-MS-Azure-%2Fmain%2Fsolutions%2Ftemplates%2Fdestinations%2Fsentinel-destination-with-app.createUiDefinition.json) | `az deployment group create -g <rg> --template-file solutions/templates/destinations/sentinel-destination-with-app.bicep` |
<!-- END GENERATED: deploy-table -->

> **Buttons are generated, never hand-edited.** They are derived from
> [`solution.manifest.json`](solution.manifest.json) by
> [`scripts/gen-deploy-links.py`](scripts/gen-deploy-links.py), and CI fails if they drift.
> A repo rename can therefore never leave a 404 button in front of a customer.
>
> **Two portal URL forms appear above, deliberately.** `createUIDefinitionUri` is
> documented by Microsoft. `uiFormDefinitionUri` — needed for subscription,
> management-group and tenant scope — is used by the portal but is **not** in
> Microsoft's official deploy-button documentation. That is why every Form-view
> template also ships a CLI command and a template-spec path: if the undocumented
> button form ever changes, nobody is stranded.
>
> Test any wizard without deploying: [createUiDefinition sandbox](https://portal.azure.com/#blade/Microsoft_Azure_CreateUIDef/SandboxBlade) · [Form view sandbox](https://aka.ms/form/sandbox)

### The fully documented alternative: template specs

Form-view wizards are *officially* delivered through template specs. Use this when a
customer's policy requires only documented Microsoft paths:

```bash
az ts create --name abstract-logstreams --version 1.0 \
  --resource-group rg-abstract --location eastus \
  --template-file  solutions/templates/policy/abstract-logstreams-policy.azuredeploy.json \
  --ui-form-definition solutions/templates/policy/abstract-logstreams-policy.uiFormDefinition.json
# then: portal → Template specs → abstract-logstreams → Deploy (the wizard launches)
```

---

## What each template does

<!-- BEGIN GENERATED: template-detail -->
#### Event Hub (Source)

Everything Abstract needs to READ from Azure: Event Hubs namespace, one hub per log source, consumer group, the checkpoint storage account + private blob container the Abstract consumer requires, SAS and/or Entra RBAC auth, networking guardrails.

- **Scope:** resource group · **Portal UI:** `createUiDefinition`
- **Files:** `templates/source/eventhub-source.bicep` · `templates/source/eventhub-source.azuredeploy.json` · `templates/source/eventhub-source.createUiDefinition.json`
- **Outputs you need next:** `abstractDiagnosticsAuthRuleId`, `eventHubNames`
- **Note:** Deploy this first — every other source template consumes its outputs. Azure Policy never creates hubs, so hub names you pass elsewhere must exist here.

#### Activity Log export (single subscription)

Streams ONE subscription's Azure Activity Log to the Abstract Event Hub. For a whole estate, use the log-stream governance pack instead.

- **Scope:** subscription · **Portal UI:** `uiFormDefinition`
- **Files:** `templates/subscription/activitylog.bicep` · `templates/subscription/activitylog.azuredeploy.json` · `templates/subscription/activitylog.uiFormDefinition.json`
- **Note:** Subscription scope, so it uses a Form view — createUiDefinition cannot bind a portal deployment to a subscription.

#### Log streams at scale (Azure Policy)

Assign once at a management group and every subscription in it — current and future — streams Activity Log, resource logs, SQL auditing and Defender for Cloud to the Abstract Event Hub, and self-heals if a setting is deleted.

- **Scope:** management group · **Portal UI:** `uiFormDefinition`
- **Files:** `templates/policy/abstract-logstreams-policy.bicep` · `templates/policy/abstract-logstreams-policy.azuredeploy.json` · `templates/policy/abstract-logstreams-policy.uiFormDefinition.json`
- **Driver script:** `scripts/Deploy-AbstractLogStreams.sh`
- **Note:** Three gotchas decide whether this works: the region rule (one namespace per region), remediation is not optional, and new subscriptions must land in the right management group. See docs/azure-log-streams.md.

#### Microsoft Entra ID log streams

Tenant-wide Entra ID diagnostic setting: sign-ins (interactive, non-interactive, SP, MI), directory audit, provisioning, Identity Protection risk, and Microsoft Graph activity.

- **Scope:** tenant · **Portal UI:** `uiFormDefinition`
- **Files:** `templates/tenant/entra-diagnostics.bicep` · `templates/tenant/entra-diagnostics.azuredeploy.json` · `templates/tenant/entra-diagnostics.uiFormDefinition.json`
- **Note:** No Azure Policy can manage this — Entra diagnostic settings are tenant-level, so there is no per-subscription object to evaluate. Expect up to three days for the first records.

#### App registrations (event-driven) ⭐ **recommended**

One central Logic App creates an Entra app + service principal per subscription, grants AND VERIFIES admin consent, writes the client secret to Key Vault, and assigns Azure RBAC on the target subscription.

- **Scope:** resource group · **Portal UI:** `createUiDefinition`
- **Files:** `templates/automation/abstract-appreg-automation.bicep` · `templates/automation/abstract-appreg-automation.azuredeploy.json` · `templates/automation/abstract-appreg-automation.createUiDefinition.json`
- **Prerequisite:** scripts/Deploy-AbstractAppReg.sh -a Bootstrap (Global Administrator, once per tenant)
- **Driver script:** `scripts/Deploy-AbstractAppReg.sh`
- **Note:** Recommended over the policy variant: one tier-0 identity in one place, one run history as the audit trail, no per-subscription compute. Live-tested end to end.

#### App registrations (Azure Policy)

Same outcome as the event-driven path, delivered through Azure Policy: a DeployIfNotExists policy deploys a deploymentScript container into each subscription which then calls Graph.

- **Scope:** management group · **Portal UI:** `uiFormDefinition`
- **Files:** `templates/policy/abstract-appreg-policy.bicep` · `templates/policy/abstract-appreg-policy.azuredeploy.json` · `templates/policy/abstract-appreg-policy.uiFormDefinition.json`
- **Prerequisite:** scripts/Deploy-AbstractAppReg.sh -a Bootstrap (Global Administrator, once per tenant)
- **Driver script:** `scripts/Deploy-AbstractAppReg.sh`
- **Note:** Only when governance mandates Azure Policy. It spawns a privileged container in every subscription, needs Owner on each, and cannot see the Entra app it created.

#### Event Hub Destination

Where Abstract WRITES processed events: namespace, destination hub, least-privilege Send SAS rule, optional Entra ID (RBAC) delivery, Safe Mode networking.

- **Scope:** resource group · **Portal UI:** `createUiDefinition`
- **Files:** `templates/destinations/eventhub-destination.bicep` · `templates/destinations/eventhub-destination.azuredeploy.json` · `templates/destinations/eventhub-destination.createUiDefinition.json`
- **Note:** Keys are never emitted in deployment outputs — fetch the Send connection string from the portal or CLI.

#### Microsoft Sentinel Destination

Abstract writes to Sentinel via the Logs Ingestion API: Log Analytics workspace, Sentinel onboarding, Data Collection Endpoint, custom _CL table, Data Collection Rule, and the DCR role assignments.

- **Scope:** resource group · **Portal UI:** `createUiDefinition`
- **Files:** `templates/destinations/sentinel-destination.bicep` · `templates/destinations/sentinel-destination.azuredeploy.json` · `templates/destinations/sentinel-destination.createUiDefinition.json`
- **Prerequisite:** Create the Entra app first — scripts/New-AbstractSentinelApp.ps1
- **Note:** Use the with-app variant to create the app registration in the same deployment.

#### Sentinel Destination + app registration

The Sentinel destination plus the Entra app registration, created in one deployment via a deploymentScript, with the client secret written to Key Vault.

- **Scope:** resource group · **Portal UI:** `createUiDefinition`
- **Files:** `templates/destinations/sentinel-destination-with-app.bicep` · `templates/destinations/sentinel-destination-with-app.azuredeploy.json` · `templates/destinations/sentinel-destination-with-app.createUiDefinition.json`
- **Prerequisite:** A user-assigned managed identity holding Application.ReadWrite.All
- **Note:** Re-running is safe: the script rotates a secret only when none exists or the current one expires within 30 days. This app needs no Graph permissions and no admin consent — it only receives DCR RBAC.
<!-- END GENERATED: template-detail -->

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
├── solution.manifest.json      ← SINGLE SOURCE OF TRUTH (repo coords, templates, docs)
├── README.md                   ← this file; deploy tables are generated into it
├── templates/
│   ├── source/                 Event Hub collection estate            (resource group)
│   ├── subscription/           Activity Log, one subscription          (subscription)
│   ├── tenant/                 Entra ID log streams                    (tenant)
│   ├── policy/                 estate-wide governance + appreg policy  (management group)
│   │   └── scripts/            deploymentScript bodies, loadTextContent()-ed in
│   ├── automation/             event-driven app registrations          (resource group)
│   └── destinations/           Event Hub + Sentinel destinations       (resource group)
│       └── scripts/            deploymentScript bodies
├── scripts/
│   ├── Deploy-AbstractLogStreams.sh   governance driver
│   ├── Deploy-AbstractAppReg.sh       app-registration driver (incl. Bootstrap)
│   ├── Deploy-AbstractEventHub.ps1    Event Hub deployment (PowerShell)
│   ├── New-AbstractSentinelApp.ps1    Sentinel app registration (PowerShell)
│   ├── validate-templates.py          UI ↔ template contract validator
│   └── gen-deploy-links.py            regenerates README + Pages from the manifest
├── parameters/                 ready-to-edit parameter files per scenario
└── docs/                       the two deep references
```

Every `*.bicep` has a compiled `*.azuredeploy.json` beside it and a matching
`*.createUiDefinition.json` or `*.uiFormDefinition.json`. CI fails if the ARM file is
stale, so what you review is what customers deploy.

---

## Customize it

Nothing here requires reading Bicep to change. In rough order of how often you will want it:

| I want to… | Edit | Then run |
| --- | --- | --- |
| Change hub names, partitions, retention, tiers | `parameters/*.parameters.json` | nothing — pass with `--parameters @file` |
| Change which log categories are collected | the wizard, or the `*Categories` parameter | nothing |
| Add/remove Graph permissions | `graphPermissions` parameter (names are validated at runtime) | nothing |
| Add a new template | `solution.manifest.json` → `templates[]` | `gen-deploy-links.py --write` |
| Change branding, colours, copy on the site | `../docs/index.html` | nothing |
| Rename or move the repo | `solution.manifest.json` → `repo` | `gen-deploy-links.py --write` |
| Change template logic | the `.bicep` | `az bicep build …` then `validate-templates.py` |

**Guardrails while you edit:**

```bash
python3 solutions/scripts/validate-templates.py          # contract check
python3 solutions/scripts/validate-templates.py --fix    # also recompile stale ARM
python3 solutions/scripts/gen-deploy-links.py --check    # are the buttons current?
```

The validator catches what `az bicep build` cannot: a UI output that is not a template
parameter, a required parameter the UI never supplies, a broken `steps()` reference, and a
UI model that cannot bind to the template's scope. It found a real shipped bug the first
time it ran — a management-group template with a `createUiDefinition`, which can never work.

---

## Port it to another repo

This directory is self-contained and designed to be lifted out:

```bash
# 1. Copy the solution into the new repo
cp -r solutions/ /path/to/new-repo/

# 2. Point the manifest at the new home — this is the ONLY place repo coords live
#    Edit solutions/solution.manifest.json → "repo": { owner, name, branch }

# 3. Regenerate every button, table and link
cd /path/to/new-repo && python3 solutions/scripts/gen-deploy-links.py --write

# 4. Prove it
python3 solutions/scripts/validate-templates.py
```

No other file contains the repo owner, name or branch. That is enforced by CI:
`gen-deploy-links.py --check` fails if any generated region is stale.

**One caveat:** Deploy-to-Azure buttons need the raw template URLs to be **publicly
readable**. A private repo will render buttons that 404. Use the CLI or template-spec
paths there, or publish the templates to a public location.

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

- **The Azure Policy app-registration path is not runtime-tested.** MG-scope validation is
  blocked by `AuthorizationFailed` at Tenant Root in the test tenant. Its Graph logic is
  the same code the Logic App path exercised, but its proxy-gating and per-subscription
  container path are compile-checked only.
- **No scheduled secret rotation.** The templates avoid *churning* secrets but nothing
  rotates them on a schedule and updates Abstract. Not built.
- **Wizards are contract-validated, not visually rendered.** Run them through the sandboxes
  before a customer-facing demo.
- **Deploy buttons require a public repo** (see above).

---

## Requirements

| For | You need |
| --- | --- |
| Event Hub + destination templates | Contributor on the target resource group |
| Activity Log export | Monitoring Contributor on the subscription |
| Log-stream governance | Owner, or Resource Policy Contributor + User Access Administrator, on the management group |
| Entra ID log streams | **Security Administrator** on the Entra tenant |
| App registrations (bootstrap) | **Global Administrator**, once per tenant — Application Administrator is *not* enough to grant admin consent |
| Tooling | Azure CLI ≥ 2.60, Bicep CLI ≥ 0.44, Python 3.8+, PowerShell 7+ for the `.ps1` scripts |

---

## Support

- **Deep references:** [Azure log streams at scale](docs/azure-log-streams.md) ·
  [Per-subscription app registrations](docs/azure-app-registrations.md)
- **Abstract docs:** [docs.abstractsecurity.app](https://docs.abstractsecurity.app)
- **Abstract:** [abstract.security](https://abstract.security)

<p align="center"><sub>Abstract Security — the security data pipeline platform.</sub></p>
