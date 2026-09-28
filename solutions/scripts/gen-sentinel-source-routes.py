#!/usr/bin/env python3
"""
Generate Sentinel Destination "source routes" from Microsoft's own published connectors.

Why
---
Abstract sends each event with the vendor's raw record in `event.original` plus a few
routing fields (vendor, product, data_stream.dataset, timestamps). Microsoft's Content Hub
connectors already contain the parsing that turns that vendor's raw record into the
vendor's Sentinel table: each publishes a Data Collection Rule whose input stream is the
vendor's raw API shape and whose transformKql maps it into the table the solution's
parsers, analytics rules and workbooks read.

This script reuses that parsing unchanged. For each source listed in
parameters/sentinel-source-routes.json it reads the connector's published DCR (and, for a
custom `_CL` target, its table definition) from github.com/Azure/Azure-Sentinel at a
PINNED commit, and emits one DCR dataflow that:

  1. selects that source's events from the Abstract stream (a KQL condition on the
     routing fields),
  2. unpacks `event.original` into exactly the columns Microsoft's input stream declares,
     filling any column Microsoft's own poller adds (for example Okta's DomainName) from
     the source's `defaults`, then
  3. runs Microsoft's published transformKql, with its one reference to `source` pointed
     at step 2.

Output: parameters/sentinel-source-routes.generated.json, loaded by the Sentinel
Destination templates. A source is only deployed when the customer lists it in the
`sourceRoutes` template parameter.

Run with --check in CI (exits 1 when the committed output is stale). Needs network access
to raw.githubusercontent.com, or --repo <local clone of Azure-Sentinel>.
"""
import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

RAW = "https://raw.githubusercontent.com/Azure/Azure-Sentinel/{ref}/{path}"
TRANSFORM_LIMIT = 15360          # Azure Monitor: characters per transformKql
SOURCE_REF = re.compile(r"(^|[;\n]\s*)source\b")

CAST = {"string": "tostring", "datetime": "todatetime", "int": "toint", "long": "tolong",
        "real": "toreal", "boolean": "tobool", "guid": "tostring"}


def fetch(ref, path, repo):
    if repo:
        return (Path(repo) / path).read_text(encoding="utf-8")
    url = RAW.format(ref=ref, path=urllib.parse.quote(path))
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8")


def find(obj, test):
    if isinstance(obj, dict):
        if test(obj):
            return obj
        for value in obj.values():
            hit = find(value, test)
            if hit is not None:
                return hit
    elif isinstance(obj, list):
        for value in obj:
            hit = find(value, test)
            if hit is not None:
                return hit
    return None


def build_route(source, ref, repo):
    dcr_doc = json.loads(fetch(ref, source["connector"]["dcr"], repo))
    dcr = find(dcr_doc, lambda o: "streamDeclarations" in o and "dataFlows" in o)
    if dcr is None:
        raise ValueError(f"{source['name']}: no DCR with streamDeclarations in {source['connector']['dcr']}")
    flows = dcr["dataFlows"]
    flow = next((f for f in flows if f.get("outputStream") == source.get("outputStream")), None) \
        if source.get("outputStream") else (flows[0] if len(flows) == 1 else None)
    if flow is None:
        raise ValueError(f"{source['name']}: DCR has {len(flows)} dataflows; set outputStream to pick one")
    stream = flow["streams"][0]
    columns = dcr["streamDeclarations"][stream]["columns"]
    published = flow.get("transformKql") or "source"

    defaults = source.get("defaults", {})
    projected = []
    for column in columns:
        name, kind = column["name"], column["type"].lower()
        if name in defaults:
            projected.append(f"{name} = {json.dumps(defaults[name])}" if kind == "string"
                             else f"{name} = {CAST.get(kind, 'tostring')}({json.dumps(defaults[name])})")
        elif kind == "dynamic":
            projected.append(f"{name} = r['{name}']")
        else:
            projected.append(f"{name} = {CAST.get(kind, 'tostring')}(r['{name}'])")

    matches = list(SOURCE_REF.finditer(published))
    if len(matches) != 1:
        raise ValueError(f"{source['name']}: expected exactly one table reference to `source` in the "
                         f"published transform, found {len(matches)}; review it by hand")
    body = SOURCE_REF.sub(lambda m: m.group(1) + "abstractSource", published, count=1)
    transform = ("let abstractSource = source\n"
                 f"| where {source['match']} and isnotempty(tostring(event.original))\n"
                 "| extend r = parse_json(tostring(event.original))\n"
                 "| project " + ", ".join(projected) + ";\n" + body)
    if len(transform) > TRANSFORM_LIMIT:
        raise ValueError(f"{source['name']}: transform is {len(transform)} characters, over the "
                         f"{TRANSFORM_LIMIT} Azure limit")

    route = {"name": source["name"], "outputStream": flow["outputStream"], "transformKql": transform,
             "provenance": {"repository": "Azure/Azure-Sentinel", "ref": ref,
                            "dcr": source["connector"]["dcr"], "inputStream": stream,
                            "rawColumns": [c["name"] for c in columns]}}

    table_path = source["connector"].get("tables")
    if flow["outputStream"].startswith("Custom-"):
        if not table_path:
            raise ValueError(f"{source['name']}: output is a custom table; set connector.tables")
        table_doc = json.loads(fetch(ref, table_path, repo))
        table_name = flow["outputStream"][len("Custom-"):]
        schema = find(table_doc, lambda o: isinstance(o.get("schema"), dict)
                      and o["schema"].get("name") == table_name and "columns" in o["schema"])
        if schema is None:
            raise ValueError(f"{source['name']}: no schema for {table_name} in {table_path}")
        route["table"] = {"name": table_name,
                          "columns": [{"name": c["name"], "type": c["type"]} for c in schema["schema"]["columns"]]}
        route["provenance"]["tables"] = table_path
    return route


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="solutions/parameters/sentinel-source-routes.json")
    parser.add_argument("--out", default="solutions/parameters/sentinel-source-routes.generated.json")
    parser.add_argument("--repo", help="Local clone of Azure-Sentinel (defaults to GitHub at the pinned ref)")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    try:
        routes = [build_route(s, config["ref"], args.repo) for s in config["sources"]]
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    output = json.dumps({"description": "Generated by gen-sentinel-source-routes.py from Microsoft's "
                                        "published Sentinel connectors. Do not edit by hand.",
                         "ref": config["ref"], "routes": routes}, indent=2) + "\n"
    target = Path(args.out)
    if args.check:
        if not target.is_file() or target.read_text(encoding="utf-8") != output:
            print(f"stale (run solutions/scripts/gen-sentinel-source-routes.py): {args.out}", file=sys.stderr)
            sys.exit(1)
        print(f"sentinel source routes current: {len(routes)} route(s)")
        return
    target.write_text(output, encoding="utf-8")
    for route in routes:
        print(f"{route['name']}: -> {route['outputStream']} ({len(route['transformKql'])} chars)")


if __name__ == "__main__":
    main()
