# Sending Abstract data into Sentinel

Abstract reduces and manages the data. For each source, choose where Sentinel stores it:
in that vendor's own table, parsed by the vendor's published Microsoft connector logic, so
the vendor's Content Hub parsers, rules and workbooks work unchanged; or in the Abstract
table as the full Abstract Common Schema (ACS), read by the Abstract content pack. Either
way the event also lands in the Abstract table.

Everything here runs in the customer's own workspace: the Logs Ingestion API, a DCR, and
templates the customer deploys. It needs no Microsoft partnership, marketplace listing or
Content Hub publication.

```
source -> Abstract (filter, dedup, aggregate, enrich)
       -> route to the Azure Sentinel Destination (one per workspace)
            vendor-table sources: route function keeps event.original + routing fields
            ACS sources:          full ACS event, no route function
       -> one DCR, one input stream
            |- every event                 -> AbstractEventLogs_CL
            |- vendor = okta               -> OktaV2_CL  (Microsoft's Okta parsing)
            '- vendor = <next source>      -> that vendor's table
```

## Choose a mode per source

| Use | When | Abstract route | Template | Sentinel content that works |
| --- | --- | --- | --- | --- |
| **Vendor table** | The vendor publishes a Sentinel connector whose DCR parses the raw record, and the source's Abstract events keep `event.original` | Route function `SELECT_KEYS` (below) | List the source in `sourceRoutes`; install the vendor's Content Hub solution | The vendor's parsers, analytics rules, hunting queries and workbooks, unchanged |
| **ACS** | No published connector, no raw record, or you want the Abstract content pack | No function: send the full ACS event | Nothing extra | The Abstract content pack (ASIM-style `ASim_AbstractEvent` parser, rules, workbooks) and your own KQL |
| **Microsoft first-party** | Entra ID, Microsoft 365, Azure Activity, Defender XDR | Keep Microsoft's native connectors; optionally a copy to Abstract for its own detections | Nothing | Everything Microsoft ships, including UEBA. See the limits below |

Do not trim an ACS-mode source: the Abstract content pack reads its ACS columns, and a
trimmed event leaves them empty.

## What each piece does

| Piece | Where it lives | What it does |
| --- | --- | --- |
| Route function | Abstract, on each source's route to Sentinel | `SELECT_KEYS` keeps only `event.original` and the routing fields, so parsed ACS fields Sentinel's content does not read are not sent |
| One destination | Abstract | A single Azure Sentinel Destination per workspace. It does not need one per source: each source already has its own route |
| Source routes | The DCR, from `sourceRoutes` in the Sentinel Destination templates | For each listed source, selects its events, unpacks `event.original` into the columns Microsoft's connector expects, and runs Microsoft's published transformation into the vendor's table |
| Abstract table | The same DCR | Receives every event. `customTablePlan`: Analytics (default) to run rules and the content pack on it, Auxiliary (the data lake tier) for cheap retention when every source is in vendor-table mode, or Basic. Set it at creation: Azure does not change an Analytics table to Auxiliary |

**Querying an Auxiliary table.** Use the Log Analytics portal with an explicit time range, or the `/search` API (`POST https://api.loganalytics.io/v1/workspaces/<id>/search` with a `timespan`). The standard `/query` API and `az monitor log-analytics query` return a count of **0** for an Auxiliary table that holds data. Tested with the full Abstract schema: every event and field arrived, and `TimeGenerated` came from the event.

The route function used in testing:

```json
{"field_operation_type": "TRANSFORMATION", "execution_context": "PIPELINES",
 "block": {"config": {"field_operation": "SELECT_KEYS", "raw": false,
   "fields": ["event.original", "vendor", "product", "data_stream.dataset",
              "@timestamp", "ingested_time", "id", "type"]}, "groups": []}}
```

Sentinel bills what is stored in a table. When Microsoft Sentinel is enabled, fields a DCR
transformation drops are not charged, so trimming mainly saves bandwidth and the Logs
Ingestion API's 1 MB-per-call and 2 GB-per-minute headroom.

## Adding a source

1. Find the vendor's connector in [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel)
   under `Solutions/<solution>/Data Connectors/`. Use it when its DCR declares an input stream
   and a `transformKql`.
2. Add it to `solutions/parameters/sentinel-source-routes.json`: its DCR path, its table
   definition for a custom `_CL` target, a KQL `match` on the routing fields, and `defaults`
   for any column Microsoft's own poller adds that the raw record lacks.
3. Run `python3 solutions/scripts/gen-sentinel-source-routes.py`. It refuses a transformation
   it cannot safely re-point, or one over Azure's 15,360-character limit.
4. Deploy with `sourceRoutes` listing the source (the portal form lists every source the
   generator knows), and install the vendor's Content Hub solution for its parsers, rules and
   workbooks. Installing a Content Hub solution is free and needs no partnership.
5. Check that the source's Abstract events carry `event.original`. Some parsers do not keep
   it, and a route selects nothing without it.

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
| Windows events | SecurityEvent, WindowsEvent, Event | Yes | Paid | Abstract can reduce these and write the native table, but the row cannot carry `_ResourceId`, and whether UEBA and the Defender for Servers allowance apply to rows it writes is unverified |
| Syslog and CEF | Syslog, CommonSecurityLog | Yes | Paid | Abstract reduces and writes the native table |

With Microsoft Sentinel enabled, a workspace transformation that drops data is not charged
for Analytics tables. For Microsoft's first-party data that is the reduction path.

Abstract can still take a copy of this data for its own detections (a second diagnostic
setting to Event Hub, and the Defender XDR streaming API). That adds visibility and cost;
it reduces the Sentinel bill only once the customer moves those detections to Abstract and
trims the native connectors.

## Verified

On a test workspace, from QA1 through the Abstract Azure Sentinel Destination:

- The route function trimmed a live feed to the selected keys: on the events after it was
  attached, the routing fields were present on 100% and every other parsed field on 0%.
- Microsoft's Okta transformation, generated from the published connector at the pinned
  commit, filled `OktaV2_CL`; Microsoft's `OktaSSO` parser and all 9 Okta Content Hub rules
  ran as published. Columns left empty were empty in Okta's own raw records.
- Every event continued to land in the Abstract table.

## Licensing and support

The transformations come from [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel),
which is MIT-licensed (Copyright (c) Microsoft Corporation). The generator records the notice,
the source path and the pinned commit on every route. Microsoft supports its connectors, not
this reuse: if a vendor route misbehaves, the fix is ours, by regenerating from a newer commit
or adjusting the source's `match` and `defaults`. Bump the pinned `ref` deliberately and
re-verify, because a solution update can change its table or transformation.

Not verified: whether UEBA uses rows written this way, and whether Microsoft's data allowances
(the E5 grant, the Defender for Servers allowance) cover them. Plan costs without them.

## The Abstract Sentinel Destination documentation

The destination's own guide asks you to upload `all_fields.json` when creating the table in
the portal. That still works for ACS mode:
[solution/schema/all_fields.json](../../solution/schema/all_fields.json) with
[all_fields.transform.kql](../../solution/schema/all_fields.transform.kql) in the portal's
transformation editor. The templates here do the same without the manual steps, and add the
vendor-table routes, error logging and table plan.
