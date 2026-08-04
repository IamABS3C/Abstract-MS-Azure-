<p align="center">
  <img src="https://cybersecurity-excellence-awards.com/wp-content/uploads/163661.png" alt="Abstract Security" height="80" />
</p>

<h1 align="center">Abstract Security — Microsoft Azure &amp; Sentinel</h1>

<p align="center">
  Production Azure infrastructure, Sentinel content, and a live SOC demo for Abstract Security's
  Microsoft integrations.<br>
  <strong><a href="https://iamabs3c.github.io/Abstract-MS-Azure-/docs/">Open the deployment console →</a></strong>
</p>

---

## Three things live in this repository

| | What it is | Start here |
| --- | --- | --- |
| 🚀 **[`solutions/`](solutions/)** | **The deployable product.** Nine Azure templates across four deployment scopes — Event Hub collection, estate-wide log-stream governance, automated per-subscription app registrations, and Sentinel ingestion. Every one has a guided portal wizard, compiled ARM, and Bicep source. | **[solutions/README.md](solutions/README.md)** |
| 🎯 **[`solution/`](solution/)** | **Sentinel content** that makes the data actionable: connector tile, ASIM parser, analytics + hunting rules, workbooks, Logic App playbooks, a Security Copilot plugin, and an MCP server. | [solution/README.md](solution/README.md) |
| 🔬 **[`docs/threat-model/`](docs/threat-model/)** | **A working SOC demo** — shift-left threat model, entity graph, replay, continuous scoring, ASTRO verdicts, live write-back to a real tenant. | [docs/threat-model/README.md](docs/threat-model/README.md) |

**Deploying Azure infrastructure? Go to [`solutions/`](solutions/README.md).** Everything below is
orientation; that directory is self-contained and portable.

---

## Deploy

Every template offers a portal wizard, an Azure Government button, and a CLI command.
Tables and buttons are **generated** from
[`solutions/solution.manifest.json`](solutions/solution.manifest.json) — CI fails if they drift,
so a repo rename can never leave a 404 in front of a customer.

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

Full detail, prerequisites, architecture and the customization guide:
**[solutions/README.md](solutions/README.md)**

---

## Quick start

```bash
# 1. Event Hub estate — deploy FIRST; everything else consumes its outputs.
az deployment group create -g rg-abstract \
  --template-file solutions/templates/source/eventhub-source.bicep \
  --parameters namespaceName=<globally-unique-name>

# 2. Onboard the whole estate in report-only mode. Changes nothing; tells you exactly
#    which subscriptions and resources would be collected.
./solutions/scripts/Deploy-AbstractLogStreams.sh -a Deploy \
  -m <management-group-id> -p solutions/parameters/logstreams-policy.parameters.json

# 3. Grant hub access, then backfill what you already own — DeployIfNotExists never
#    touches existing resources on its own.
./solutions/scripts/Deploy-AbstractLogStreams.sh -a Grant     -m <mg-id> -n <namespace-id>
./solutions/scripts/Deploy-AbstractLogStreams.sh -a Remediate -m <mg-id>

# 4. Identity telemetry — one command for the entire tenant.
az deployment tenant create -l eastus \
  --template-file solutions/templates/tenant/entra-diagnostics.bicep \
  --parameters eventHubAuthorizationRuleId=<rule-id> eventHubName=<entra-hub>
```

---

## What makes this different

- **Estate-wide governance, not per-subscription toil.** One management-group assignment
  onboards every subscription — current *and* future — and restores a diagnostic setting if
  someone deletes it.
- **App registrations automated end to end**, including admin consent that is **verified by
  reading it back from Graph**. "We consented, why is Abstract getting 403s?" stops being a
  support call.
- **Portal wizards above resource-group scope.** Most solutions cannot do this: the common
  `createUiDefinition` model physically cannot bind a portal deployment to a subscription,
  management group or tenant. These use Form view where that matters.
- **Claims are tested, not inferred.** Each non-obvious statement in the docs was verified
  against a live Azure tenant, and the gaps are named rather than glossed. See
  [Verified, not assumed](solutions/README.md#verified-not-assumed).

---

## Repository layout

```
solutions/           ← THE DEPLOYABLE PRODUCT (self-contained, portable)
├── solution.manifest.json   single source of truth: repo coords, templates, docs
├── templates/{source,subscription,tenant,policy,automation,destinations}/
├── scripts/                 drivers + validator + generators
├── parameters/              ready-to-edit parameter files
├── docs/                    two deep references
└── ci/                      CI helper scripts

solution/            Sentinel content pack (connector, parser, rules, workbooks, playbooks)
docs/                GitHub Pages site (generated) + threat-model SOC demo
.github/workflows/   validate.yml — discovers what to check; nothing hardcoded
```

---

## Contributing

```bash
# after editing any template or the manifest:
python3 solutions/scripts/validate-templates.py        # UI ↔ template contracts
python3 solutions/scripts/validate-templates.py --fix  # also recompile stale ARM
python3 solutions/scripts/gen-deploy-links.py --write   # regenerate README tables
python3 solutions/scripts/gen-pages.py                  # regenerate the Pages site
```

CI runs all of the above plus JSON, shell, PowerShell and secret-literal checks. The
contract validator exists because `az bicep build` cannot see a UI whose outputs do not
match its template — and it caught exactly that bug the first time it ran.

**Porting this to another repository** is a two-step change: edit `repo` in
[`solutions/solution.manifest.json`](solutions/solution.manifest.json), then run
`gen-deploy-links.py --write` and `gen-pages.py`. No other file contains the repo owner,
name or branch.

---

## License

[MIT](LICENSE) · Abstract Security — the security data pipeline platform ·
[abstract.security](https://abstract.security) · [docs.abstractsecurity.app](https://docs.abstractsecurity.app)
