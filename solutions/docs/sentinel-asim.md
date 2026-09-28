# Sending Abstract data into Sentinel

Abstract collects each source and normalizes it into the Abstract Common Schema (ACS).
The Sentinel Destination sends every event to Sentinel once, and the Data Collection Rule
the templates deploy writes it to two places:

- **The Abstract table** (`AbstractEventLogs_CL`): every event, every ACS field, for the
  Abstract content pack and your own KQL.
- **Microsoft's ASIM tables**: each event that is a sign-in, a network session, a DNS
  query and so on is mapped from ACS into Microsoft's normalized table for that activity
  (`ASimAuthenticationEventLogs`, `ASimNetworkSessionLogs`, ...). Microsoft's built-in
  ASIM parsers (`_Im_Authentication`, `_Im_NetworkSession`, ...) read those tables, so
  Microsoft's ASIM analytics rules, hunting queries and workbooks work on Abstract data
  from every vendor.

```
source -> Abstract (collect, normalize to ACS, filter, reduce, enrich)
       -> Azure Sentinel Destination (one per workspace, full ACS event)
       -> one DCR
            |- every event                        -> AbstractEventLogs_CL
            |- sign-ins and sessions              -> ASimAuthenticationEventLogs
            |- admin, IAM and configuration       -> ASimAuditEventLogs
            |- network sessions and flows         -> ASimNetworkSessionLogs
            '- DNS, web, process, file, registry  -> their ASim tables
```

There is one mapping per ASIM schema, and it reads ACS, not any vendor's format. Adding
a vendor to Abstract needs nothing on the Sentinel side: once Abstract parses the vendor
into ACS, its events land in the right ASIM table. Nothing here needs a Microsoft
partnership, a marketplace listing or a Content Hub publication; it all runs in the
customer's own workspace.

## What goes where

An event goes to an ASIM table when its ACS says what kind of activity it is. That is
`event.category`, set by the Abstract parser, plus the field that makes the activity
meaningful. Events that match none of these stay in the Abstract table only. Abstract
findings and alerts (`type` = `finding` or `alert`) never go to the activity tables.

| ASIM schema | Microsoft table | Selected when |
| --- | --- | --- |
| Authentication | ASimAuthenticationEventLogs | `event.category` is authentication or session, and the event has a user |
| AuditEvent | ASimAuditEventLogs | `event.category` is iam, configuration or audit, or the event is a cloud control-plane call (`cloud.provider` set and no category); either way it needs an action |
| NetworkSession | ASimNetworkSessionLogs | `event.category` is network, with a source or destination IP, and it is not a DNS query |
| Dns | ASimDnsActivityLogs | `dns.question.name` is set |
| WebSession | ASimWebSessionLogs | `event.category` is web, or the event has a URL and an HTTP method |
| ProcessEvent | ASimProcessEventLogs | `event.category` is process, with a process name, executable or command line |
| FileEvent | ASimFileEventLogs | `event.category` is file, with a file path or name |
| RegistryEvent | ASimRegistryEventLogs | `registry.path` or `registry.key` is set |

The mappings are in [solutions/asim](../asim), one DCR transformation per schema, each
readable on its own.

**Fields ASIM has no column for** stay in the Abstract table, including every `ext.*`
field. Each ASIM row carries `AdditionalFields.AbstractEventId`, so an analyst can pivot
from a Microsoft alert to the full Abstract event:

```kusto
AbstractEventLogs_CL | where acs_id == "<AdditionalFields.AbstractEventId>"
```

## What the customer should know

- **Vendor-specific content does not fire.** Only Microsoft's ASIM content (and the
  Abstract content pack) reads these tables. A rule written for one vendor's own table, such
  as a rule that queries `OktaV2_CL`, sees nothing. Microsoft publishes most new content
  for ASIM; the ASIM version of a rule usually says "(ASIM)" or "Uses Authentication
  Normalization" in its name.
- **Some published rule templates call `imAuthentication`**, the older workspace-deployed
  parser, instead of the built-in `_Im_Authentication`. A workspace without the
  workspace-deployed parsers returns an error for those queries: change the query to the
  built-in parser, or deploy Microsoft's workspace-deployed ASIM parsers.
- **Duplicates.** If Microsoft's own connector for a vendor also runs, the ASIM parsers
  return that vendor's events twice, once from each table. Keep one of the two.
- **Coverage depends on the Abstract parser.** An event without `event.category` stays in
  the Abstract table only. Fixing the parser in Abstract fixes it for Sentinel and for
  Abstract's own detections at the same time.
- **Cost.** Mapped events are stored twice: in the Abstract table and in an ASIM table. To
  pay full price for one copy, set the Abstract table to the Auxiliary plan
  (`customTablePlan`) and keep the ASIM tables on Analytics. That only suits workspaces that
  do not use the Abstract content pack, which reads the Abstract table. `asimSchemas`
  limits which ASIM tables are written, and `enableAsim` turns them off.
- **Do not trim events with a `SELECT_KEYS` function on the route to Sentinel.** The ASIM
  mappings read the ACS fields, so a trimmed event lands in no ASIM table.
- **A template redeploy takes about 15 minutes to settle.** In testing, events kept going
  through the previous transformation for up to 15 minutes after a DCR update, and the ASIM
  tables missed some events in the first few minutes. Steady state was complete. Whether the
  Abstract table has the same gap was not measured. Redeploy during a quiet period.

## Template settings

| Setting | Default | What it does |
| --- | --- | --- |
| `enableAsim` | true | Write the ASIM tables. Needs Microsoft Sentinel on the workspace (the ASim tables come with it) and the generated Abstract schema (`tableColumns` left empty) |
| `asimSchemas` | all | Which ASIM schemas to write |
| `customTablePlan` | Keep | Keep leaves an existing Abstract table's plan alone and creates a new one as Analytics. Pick Analytics, Basic or Auxiliary (the data lake tier) to set it. Picking a plan for an existing table switches the whole table |
| `enableDcrErrorLogs` | true | Rejected and malformed ingestion goes to `DCRLogErrors` |

**Querying an Auxiliary table.** Use the Log Analytics portal with an explicit time range,
or the `/search` API (`POST https://api.loganalytics.io/v1/workspaces/<id>/search` with a
`timespan`). The standard `/query` API and `az monitor log-analytics query` return a count
of **0** for an Auxiliary table that holds data.

## Changing a mapping

1. Edit the schema's file in `solutions/asim`. Only KQL that Azure Monitor transformations
   accept will deploy: no `coalesce`, `has_any`, `in~` or `bag_pack`, for example.
2. Run `python3 solutions/scripts/gen-sentinel-asim.py`. It refuses unsupported KQL, any
   column Microsoft's table does not have (Azure would drop it silently), and a
   transformation over Azure's 15,360-character limit. It then updates both portal forms
   and rebuilds both ARM templates (it needs `az bicep`). Commit all of them: CI's `--check`
   fails if any lags.
3. When Microsoft adds columns to an ASIM table, refresh its column list in
   `solutions/asim/tables` from a Sentinel workspace
   (`az monitor log-analytics workspace table show -n <table>`).

## Microsoft's own data: what this cannot do

Microsoft allows only its own connectors to write the tables its first-party cloud data
lives in. Abstract, and any other sender, cannot write them through the Logs Ingestion API.
These tables also feed UEBA and the Microsoft Entra ID solution's analytics rules.

| Data | Sentinel table | Can Abstract write it? | Ingestion cost | How to reduce it |
| --- | --- | --- | --- | --- |
| Entra ID sign-ins | SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs | No | Paid (E5 data grant eligible) | Workspace transformation DCR or Sentinel filter/split; Basic or Auxiliary plan |
| Entra ID audit | AuditLogs | No | Paid (E5 data grant eligible) | Workspace transformation DCR |
| Microsoft 365 audit | OfficeActivity | No | Free | Nothing to save |
| Azure Activity | AzureActivity | No | Free | Nothing to save |
| Defender XDR alerts and incidents | SecurityAlert, SecurityIncident | No | Free | Nothing to save |
| Defender XDR advanced hunting | Device\*, Email\*, Identity\*, CloudAppEvents | No | Paid | Per-table choices in the Defender XDR connector; custom detections in Defender |
| Azure resource logs | Resource-specific tables, AzureDiagnostics | No | Paid | Choose categories in the diagnostic setting; use resource-specific mode (AzureDiagnostics cannot be transformed) |

Microsoft's ASIM parsers already read its own first-party tables, so ASIM content covers
Microsoft's data and Abstract's data together.

With Microsoft Sentinel enabled, a workspace transformation that drops data is not charged
for Analytics tables. For Microsoft's first-party data that is the reduction path.

Abstract can still take a copy of this data for its own detections (a second diagnostic
setting to Event Hub, and the Defender XDR streaming API). That adds visibility and cost;
it reduces the Sentinel bill only once the customer moves those detections to Abstract and
trims the native connectors.

## Verified

On a test workspace, from QA1 through the Abstract Azure Sentinel Destination, with these
templates deployed:

- **Live feeds** (AWS CloudTrail from QA1's event generator, and a live Okta System Log):
  over a settled six-minute window, 323 of 340 AWS events (95%) and 5 of 5 Okta events
  landed in an ASIM table. The other 17 were S3 bucket calls that the Abstract parser labels
  `file` without a file path. Every event also landed in the Abstract table.
- **The other schemas**, using QA1's stored API test events replayed through the DCR: every
  event that meets a schema's rule landed in its table (NetworkSession 80, Dns 40,
  WebSession 21, ProcessEvent 48, FileEvent 28, Authentication 57, AuditEvent 2). The two
  DNS-category events not mapped have no query name.
- **Microsoft's built-in parsers** (`_Im_Authentication`, `_Im_AuditEvent`,
  `_Im_NetworkSession`, `_Im_Dns`, `_Im_WebSession`, `_Im_ProcessEvent`, `_Im_FileEvent`)
  returned every row in their tables.
- **Microsoft's ASIM data tester** (`ASimDataTester`, from Azure-Sentinel) reported no
  errors or warnings for Authentication, AuditEvent, NetworkSession and FileEvent. For Dns
  and WebSession it reported only type mismatches on columns of Microsoft's own tables that
  these mappings do not write (Dns `Threat*`, WebSession `FileSize`). For ProcessEvent it
  warned only where the source events had no value: no parent process ID, a user on 6 of 48
  events, a command line on 26 of 48.

Not yet shown:

- **A Microsoft rule alerting on these rows.** Ten published ASIM rules ran against them and
  returned nothing, because the test data contains none of the activity they look for; two
  older ones also read `SrcDvcIpAddr`, which the built-in parser does not produce.
- **RegistryEvent.** It is mapped, but QA1 has no registry events.
- Whether UEBA reads these tables, and whether Microsoft's data allowances cover them.

## The Abstract Sentinel Destination documentation

The destination's own guide asks you to upload `all_fields.json` when creating the table in
the portal. That still works for the Abstract table:
[solution/schema/all_fields.json](../../solution/schema/all_fields.json) with
[all_fields.transform.kql](../../solution/schema/all_fields.transform.kql) in the portal's
transformation editor. The templates here do the same without the manual steps, and add the
ASIM tables, error logging and table plan.
