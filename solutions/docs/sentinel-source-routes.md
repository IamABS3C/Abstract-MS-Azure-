# Sending Abstract data into Sentinel's own tables

Abstract reduces and manages the data. Sentinel parses each source's raw record with that
vendor's own published connector logic, so the vendor's tables, parsers, analytics rules and
workbooks work unchanged. Every event also lands in the Abstract table for full fidelity and
replay.

```
source -> Abstract (filter, dedup, aggregate, enrich)
       -> route function: keep event.original + routing fields
       -> Azure Sentinel Destination (one per workspace)
       -> one DCR, one input stream
            |- route: all events               -> AbstractEventLogs_CL
            |- route: vendor = okta            -> OktaV2_CL  (Microsoft's Okta parsing)
            '- route: vendor = <next source>   -> that vendor's table
```

## What each piece does

| Piece | Where it lives | What it does |
| --- | --- | --- |
| Route function | Abstract, on each source's route to Sentinel | `SELECT_KEYS` keeps only `event.original` and the routing fields, so parsed ACS fields Sentinel's content does not read are not sent |
| One destination | Abstract | A single Azure Sentinel Destination per workspace. It does not need one per source: each source already has its own route |
| Source routes | The DCR, from `sourceRoutes` in the Sentinel Destination templates | For each listed source, selects its events, unpacks `event.original` into the columns Microsoft's connector expects, and runs Microsoft's published transformation into the vendor's table |
| Abstract table | The same DCR | Receives every event. Put it on the Auxiliary (lake) plan for cheap full-fidelity retention, or Analytics if you hunt on it |

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
4. Deploy with `sourceRoutes` listing the source, and install the vendor's Content Hub
   solution for its parsers, rules and workbooks.
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

Open with Microsoft: whether a third party may reuse a published connector's transformation
(nothing documents or forbids it), whether UEBA uses rows written this way, and whether
Microsoft's data allowances cover them.
