#!/usr/bin/env python3
"""
Seed AbstractEventLogs_CL via the Azure Monitor Logs Ingestion API.

Pushes Abstract Common Schema (ACS) events straight into the custom table the
Sentinel Destination template creates, so the workbook, analytics rule, hunting
queries, and connector graph light up for a demo — without waiting on a live
pipeline.

    python solution/scripts/seed_sentinel.py --file events.json
    python solution/scripts/seed_sentinel.py --sample 50 --dry-run     # no creds needed

LAB WORKSPACES ONLY. Seeded rows are indistinguishable from real ones: they reach the
Abstract content pack and, if the destination writes ASIM tables, every ASIM rule in
the workspace. Never run this against a production workspace.

Input: JSON (one event per line, or a JSON array) of bare ACS events. Each is sent
the way the Abstract Azure Sentinel Destination sends it: the event's own top-level
keys, plus timestamp (copy of @timestamp) and acs_type (copy of type). The DCR
transformation sets TimeGenerated from timestamp. Older wrapped rows
({TimeGenerated, Message, AbstractEvent}) are unwrapped automatically.

Auth/target from env (the app + DCR the Sentinel Destination template created —
never hard-code; the app's SP needs Monitoring Metrics Publisher on the DCR):
    AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
    ABSTRACT_DCE_URL              e.g. https://abstract-dce-xxxx.eastus-1.ingest.monitor.azure.com
    ABSTRACT_DCR_IMMUTABLE_ID     e.g. dcr-xxxxxxxxxxxxxxxx
    ABSTRACT_STREAM_NAME          default: Custom-AbstractEventLogs_CL
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

STREAM_DEFAULT = "Custom-AbstractEventLogs_CL"
INGEST_API_VERSION = "2023-01-01"


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_token(tenant: str, client_id: str, secret: str) -> str:
    """client_credentials token for the Logs Ingestion (Azure Monitor) audience."""
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    body = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": secret,
        "grant_type": "client_credentials",
        "scope": "https://monitor.azure.com/.default",
    }).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())["access_token"]


def to_row(item: dict) -> dict:
    """Shape an input item like the event the Abstract integration uploads."""
    event = dict(item.get("AbstractEvent") or item)
    # A wrapped row keeps its own time when its inner event carries none.
    event.setdefault("@timestamp", item.get("TimeGenerated") or _now_iso())
    event.setdefault("timestamp", event["@timestamp"])
    if "type" in event:
        event.setdefault("acs_type", event["type"])
    return event


def read_events(args) -> list:
    if args.sample:
        base = {"product": "Demo", "vendor": "Abstract", "severity": "high", "type": "event",
                "action": "success", "user_name": "demo.user", "source_ipv4": "203.0.113.10",
                "message": "sample event", "id": "demo-0", "tags": ["demo"]}
        return [to_row({**base, "id": f"demo-{i}", "@timestamp": _now_iso()}) for i in range(args.sample)]
    raw = open(args.file).read() if args.file else sys.stdin.read()
    raw = raw.strip()
    if not raw:
        return []
    if raw.startswith("["):
        return [to_row(x) for x in json.loads(raw)]
    return [to_row(json.loads(line)) for line in raw.splitlines() if line.strip()]


def post_rows(dce: str, dcr: str, stream: str, token: str, rows: list):
    url = f"{dce.rstrip('/')}/dataCollectionRules/{dcr}/streams/{stream}?api-version={INGEST_API_VERSION}"
    sent = 0
    for i in range(0, len(rows), 500):
        chunk = rows[i:i + 500]
        req = urllib.request.Request(url, data=json.dumps(chunk).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            if r.status not in (200, 204):
                raise RuntimeError(f"ingest HTTP {r.status}")
        sent += len(chunk)
    return sent


def main():
    p = argparse.ArgumentParser(description="Seed AbstractEventLogs_CL via Logs Ingestion API")
    p.add_argument("--file", help="JSON file of events (array or one-per-line)")
    p.add_argument("--sample", type=int, default=0, help="generate N sample events instead of reading input")
    p.add_argument("--dry-run", action="store_true", help="print rows; do not send (no creds needed)")
    args = p.parse_args()

    rows = read_events(args)
    print(f"{len(rows)} rows prepared", file=sys.stderr)
    if args.dry_run:
        print(json.dumps(rows[:3], indent=2))
        print(f"... (dry run, {len(rows)} total not sent)", file=sys.stderr)
        return
    env = os.environ
    missing = [k for k in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
                           "ABSTRACT_DCE_URL", "ABSTRACT_DCR_IMMUTABLE_ID") if not env.get(k)]
    if missing:
        raise SystemExit("missing env: " + ", ".join(missing) + " (use --dry-run to preview without creds)")
    token = get_token(env["AZURE_TENANT_ID"], env["AZURE_CLIENT_ID"], env["AZURE_CLIENT_SECRET"])
    stream = env.get("ABSTRACT_STREAM_NAME", STREAM_DEFAULT)
    sent = post_rows(env["ABSTRACT_DCE_URL"], env["ABSTRACT_DCR_IMMUTABLE_ID"], stream, token, rows)
    print(f"sent {sent} rows to {stream}", file=sys.stderr)


if __name__ == "__main__":
    main()
