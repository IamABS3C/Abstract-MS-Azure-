#!/usr/bin/env python3
"""
Generate the Sentinel Destination table schema from Abstract's ACS field catalog.

What Abstract actually sends
----------------------------
The managed Azure Sentinel Destination integration uploads each Abstract Common
Schema (ACS) event to the Logs Ingestion API as-is: nested JSON whose top-level
keys are ACS roots (action, user_name, cloud{...}, user{...}, event{...}, ext{...}).
Its transformer also adds timestamp (copy of @timestamp), acs_type (copy of type)
and flattened resource_* keys. It never sends TimeGenerated, and never wraps the
event in a single property.

So the table is one column per top-level ACS key (objects and lists as dynamic),
and a DCR transformation supplies TimeGenerated and renames the two keys Log
Analytics reserves (id, type). Flattening nested paths into columns such as
cloud_account_id does not work: the payload has no such property, so every one of
those columns stays empty.

Outputs
-------
  --schema-out   sentinel-destination.schema.json: tableColumns, streamColumns and
                 transformKql, loaded by the Sentinel Destination Bicep templates
  --sample-out   all_fields.json: a one-record sample for the Azure portal's
                 "New custom log (DCR-based)" upload, which infers columns from the
                 record's top-level keys
  --kql-out      the portal-path transformation (TimeGenerated only, since the
                 sample carries no id or type), for pasting into the portal's editor

Run with --check in CI: exits 1 when a committed output is stale.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# Log Analytics custom-table column rules (learn.microsoft.com, create-custom-table).
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,44}$")
RESERVED = {"id", "billedsize", "isbillable", "invalidtimegenerated", "tenantid",
            "title", "type", "uniqueid", "_itemid", "_resourcegroup", "_resourceid",
            "_subscriptionid", "_timereceived", "timegenerated"}

TYPE_MAP = {"String": "string", "Ipv4": "string", "Ipv6": "string",
            "StringifyJSON": "string", "Float64": "real", "Date": "datetime",
            "Boolean": "boolean"}

# Keys added by the managed integration's transformer (pipelines/default.yml).
TRANSFORMER_KEYS = [("timestamp", "datetime"), ("acs_type", "string"),
                    ("acs_resource_id", "string"), ("acs_resource_name", "string"),
                    ("acs_resource_type", "string"), ("resource_additional_data", "string")]

# Reserved ACS keys that arrive in the payload and are renamed by the transformation.
RENAMED = {"id": "acs_id", "type": "acs_type"}

SAMPLE_VALUE = {"string": "string", "real": 1.5, "boolean": True,
                "datetime": "2026-01-01T00:00:00.000Z", "dynamic": {"key": "value"}}


def la_type(abstract_type):
    return TYPE_MAP.get(abstract_type, "dynamic")


def top_level_columns(catalog):
    """One (name, type) per top-level ACS key, in catalog order."""
    columns, parents = {}, set()
    for item in catalog:
        name = item["field"]
        root = name.split(".")[0]
        if "." in name:
            parents.add(root)
            columns.setdefault(root, "dynamic")
        else:
            columns.setdefault(root, la_type(item.get("data_type", "String")))
    for root in parents:
        columns[root] = "dynamic"
    columns.setdefault("ext", "dynamic")
    return [(name, columns[name]) for name in sorted(columns) if not name.startswith("@")]


TIME_KQL = ("source\n"
            "| extend TimeGenerated = case(isnotnull(['timestamp']), ['timestamp'], "
            "isnotnull(ingested_time), ingested_time, now())\n")


def transform_kql():
    """Template path: the DCR stream also declares id and type, renamed here."""
    return (TIME_KQL +
            "| extend acs_id = tostring(['id']), "
            "acs_type = iif(isnotempty(acs_type), acs_type, tostring(['type']))\n"
            "| project-away ['id'], ['type']\n")


def portal_kql():
    """Portal path: the sample upload has no id or type, so only TimeGenerated is set."""
    return TIME_KQL


def build(catalog):
    acs = top_level_columns(catalog)
    stream = [{"name": n, "type": t} for n, t in acs]
    have = {c["name"] for c in stream}
    stream += [{"name": n, "type": t} for n, t in TRANSFORMER_KEYS if n not in have]

    table = [{"name": "TimeGenerated", "type": "datetime"}]
    for column in stream:
        name = RENAMED.get(column["name"], column["name"])
        if name not in {c["name"] for c in table}:
            table.append({"name": name, "type": column["type"]})

    bad = [c["name"] for c in table
           if not NAME_RE.match(c["name"])
           or (c["name"].lower() in RESERVED and c["name"] != "TimeGenerated")]
    if bad:
        raise ValueError(f"Invalid Log Analytics column names: {bad}")
    if len(table) > 500:
        raise ValueError(f"{len(table)} columns exceeds the 500-column custom table limit.")

    sample = {c["name"]: SAMPLE_VALUE[c["type"]] for c in table if c["name"] != "TimeGenerated"}
    sample.pop("acs_id", None)  # the portal path has no transformation to populate it
    return table, stream, sample


def render(catalog):
    table, stream, sample = build(catalog)
    schema = {
        "description": ("Generated by gen-sentinel-schema.py from the ACS field catalog "
                        "(acs-fields.json). One column per top-level ACS key; nested "
                        "objects and lists are dynamic. The DCR transformation sets "
                        "TimeGenerated and renames the reserved id and type keys."),
        "tableColumns": table,
        "streamColumns": stream,
        "transformKql": transform_kql(),
    }
    return {
        "schema": json.dumps(schema, indent=2) + "\n",
        "sample": json.dumps([sample], indent=2) + "\n",
        "kql": portal_kql(),
    }, len(table)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", default="solution/schema/acs-fields.json",
                        help="GET /v1/acs/fields output: a list, or an object with 'fields'.")
    parser.add_argument("--schema-out", default="solutions/parameters/sentinel-destination.schema.json")
    parser.add_argument("--sample-out", default="solution/schema/all_fields.json")
    parser.add_argument("--kql-out", default="solution/schema/all_fields.transform.kql")
    parser.add_argument("--check", action="store_true",
                        help="Exit 1 if any output differs from what would be generated.")
    args = parser.parse_args()

    try:
        document = json.loads(Path(args.catalog).read_text(encoding="utf-8"))
        catalog = document["fields"] if isinstance(document, dict) else document
        outputs, count = render(catalog)
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as error:
        parser.error(str(error))

    targets = {"schema": args.schema_out, "sample": args.sample_out, "kql": args.kql_out}
    stale = []
    for key, path in targets.items():
        target = Path(path)
        if args.check:
            if not target.is_file() or target.read_text(encoding="utf-8") != outputs[key]:
                stale.append(path)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(outputs[key], encoding="utf-8")
    if args.check:
        if stale:
            print("stale (run solutions/scripts/gen-sentinel-schema.py): " + ", ".join(stale),
                  file=sys.stderr)
            sys.exit(1)
        print(f"sentinel schema current: {count} table columns")
        return
    print(f"wrote {', '.join(targets.values())} ({count} table columns)")


if __name__ == "__main__":
    main()
