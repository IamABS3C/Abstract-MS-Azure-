#!/usr/bin/env python3
"""
Seed AbstractEventLogs_CL via the Azure Monitor Logs Ingestion API.

Pushes Abstract Common Schema (ACS) events straight into the custom table the
Sentinel Destination template creates, so the workbook, analytics rule, hunting
queries, and connector graph light up for a demo — without waiting on a live
pipeline. Pairs with the threat-model demo:

    python docs/threat-model/demo/identities.py | python solution/scripts/seed_sentinel.py
    python solution/scripts/seed_sentinel.py --file events.json
    python solution/scripts/seed_sentinel.py --sample 50 --dry-run     # no creds needed

Input: JSON (one event per line, or a JSON array). Each item is either a full
table row ({TimeGenerated, Message, AbstractEvent}) or a bare ACS event (it gets
wrapped automatically).

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
    """Normalize an input item into a table row {TimeGenerated, Message, AbstractEvent}."""
    if "AbstractEvent" in item:
        item.setdefault("TimeGenerated", item.get("AbstractEvent", {}).get("@timestamp") or _now_iso())
        return item
    return {
        "TimeGenerated": item.get("@timestamp") or _now_iso(),
        "Message": item.get("message", ""),
        "AbstractEvent": item,
    }


def _sev_to_risk(sev: str) -> float:
    return {"critical": 95, "high": 80, "medium": 40, "low": 20, "informational": 5, "info": 5}.get((sev or "").lower(), 10)


def _demo_to_acs(e: dict, idx: int) -> dict:
    """Map one threat-model demo event (data.py:events() shape) to an ACS event."""
    t = e.get("_t", "")
    ts = e.get("ts")
    iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(ts, "strftime") else _now_iso()
    user = (e.get("user") or e.get("to") or e.get("account") or e.get("nhi") or e.get("agent") or "")
    user = user.split(":")[-1] if user else ""
    sev = e.get("sev") or ("high" if t in ("email", "pan_wildfire", "edr") else "info")
    catalog = {
        "email":       ("Email Security", "Email", "email", "deliver"),
        "dns":         ("DNS", "DNS", "dns", "query"),
        "pan_traffic": ("Palo Alto Networks", "Palo Alto Networks", "network", "traffic"),
        "pan_wildfire":("Palo Alto Networks", "Palo Alto Networks", "malware", "wildfire_verdict"),
        "edr":         ("CrowdStrike Falcon", "CrowdStrike", "process", "suspicious_exec"),
        "okta":        ("Okta", "Okta", "authentication", "login"),
        "cloudtrail":  ("AWS CloudTrail", "AWS", "cloud", "api_call"),
        "nhi":         ("Non-Human Identity", "Abstract", "iam", "token_use"),
        "agent":       ("AI Agent", "Abstract", "agent", "beacon"),
        "benign_traffic": ("Network", "Benign", "network", "traffic"),
        "benign_dns":  ("DNS", "Benign", "dns", "query"),
        "benign_auth": ("Okta", "Benign", "authentication", "login"),
    }
    product, vendor, etype, action = catalog.get(t, ("Abstract", "Abstract", t or "event", "observe"))
    acs = {
        "id": f"demo-{idx:05d}", "@timestamp": iso, "type": etype, "action": action,
        "product": product, "vendor": vendor, "severity": sev,
        "user_name": user, "host_name": e.get("host", ""),
        "source_ipv4": e.get("src_ip", ""),
        "dest_ipv4": e.get("dst") if str(e.get("dst", "")).count(".") == 3 else e.get("resp", ""),
        "risk_score": _sev_to_risk(sev),
        "message": e.get("query") or e.get("url") or e.get("proc") or f"{t} event",
        "tags": ["demo", "threat-model", t],
    }
    if e.get("sha256"):
        acs["file"] = {"hash": {"sha256": e["sha256"]}}
    return {k: v for k, v in acs.items() if v not in ("", None)}


def _events_from_demo() -> list:
    demo = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "threat-model", "demo")
    if not os.path.isdir(demo):
        raise SystemExit("threat-model demo not found at docs/threat-model/demo — run from the repo root.")
    sys.path.insert(0, demo)
    import data  # the demo's synthetic estate (data.events()); imports pipeline.py from same dir
    return [to_row(_demo_to_acs(e, i)) for i, e in enumerate(data.events())]


def read_events(args) -> list:
    if getattr(args, "from_demo", False):
        return _events_from_demo()
    if args.sample:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "docs", "threat-model", "demo"))
        try:
            import identities  # the demo's ACS scenario generator
            evs = identities.generate_scenario() + identities.background_noise(max(0, args.sample - 20))
            return [to_row(e) for e in evs]
        except Exception:  # fall back to a tiny built-in sample
            base = {"product": "Demo", "vendor": "Abstract", "severity": "high", "type": "authentication",
                    "action": "success", "user_name": "demo.user", "source_ipv4": "203.0.113.10",
                    "message": "sample event", "id": "demo-0"}
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
    p.add_argument("--sample", type=int, default=0, help="generate N demo events instead of reading input")
    p.add_argument("--from-demo", action="store_true", help="map the threat-model demo's synthetic estate (data.py) to ACS and seed it")
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
