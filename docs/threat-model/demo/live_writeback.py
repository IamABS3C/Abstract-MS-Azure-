"""
Live write-back to a real Abstract tenant — the closed loop, proven.

  python3 live_writeback.py            # clean prior demo objects, create fresh, verify
  python3 live_writeback.py --cleanup  # delete demo objects and exit

Creates (via the documented REST API, fields validated against the live FieldEnum):
  • a Field Set  — the entity-centric projection for WildFire/PAN threat research
  • a View       — threat-research findings surface, bound to that field set

Both are clearly named "(demo)" and are reversible (DELETE endpoints). Reads
(timeline / lists) confirm the tenant is live. The DETECTION RULE step is staged
but not fired: the rule body is an internal Avro format (query needs
`condition_combination` + a union-typed field) gated behind login-only docs, and
GET /v1/rules currently 500s so a created rule can't be verified/cleaned — so we
stop at validate() rather than post a malformed rule. See LIVE-RESULTS.md.
"""
from __future__ import annotations

import json
import sys

from abstract_client import AbstractClient

DEMO_TAG = "threat research"  # matches our demo objects by name (case-insensitive)

FIELDSET = {
    "name": "WildFire/PAN Threat Research — Entity Fields (demo)",
    "tags": ["demo", "wildfire", "threat-research"],
    "fields": ["type", "@timestamp", "severity", "vendor", "event.dataset", "action",
               "event.outcome", "user_name", "user.email", "source_address", "dest_address",
               "dest_port", "host_name", "destination.geo.country_iso_code", "file.hash.sha256",
               "file.name", "url.original", "destination.domain", "dns.question.name",
               "tls.client.ja3", "threat.indicator", "threat.technique_id", "threat.group_name",
               "process.name", "process.command_line", "email.sender",
               "email.attachments.file.hash.sha256", "rule.name", "message"],
}


def view_body(fieldset_id):
    return {
        "name": "WildFire / PAN Threat Research (Abstract model demo)",
        "query": [{"id": "q1", "depth": 0, "field": "type", "index": 0, "value": "Finding",
                   "parentId": None, "fieldType": "String", "field_operation": "EQUALS",
                   "subFieldOperation": ""}],
        "time_selection": {"type": "Relative", "numeric_value": 30, "option_selected": "days",
                           "end_date": None, "start_date": None, "end_numeric_value": None,
                           "end_option_selected": None},
        "fieldset_ids": [fieldset_id] if fieldset_id else None,
        "fields": ["type", "@timestamp", "severity", "vendor", "user_name", "source_address",
                   "dest_address", "destination.domain", "file.hash.sha256", "threat.technique_id",
                   "rule.name", "message"],
        "order_by": "@timestamp", "order_type": "DESC",
    }


def cleanup(c):
    n = 0
    for v in (c.list_views().get("body", {}) or {}).get("views", []):
        if DEMO_TAG in (v.get("name") or "").lower() and "demo" in (v.get("name") or "").lower():
            c.delete_view(v["id"]); n += 1; print("  deleted view", v["id"], v["name"])
    for f in (c.list_fieldsets().get("body", {}) or {}).get("fieldsets", []):
        if DEMO_TAG in (f.get("name") or "").lower() and "demo" in (f.get("name") or "").lower():
            c.delete_fieldset(f["id"]); n += 1; print("  deleted fieldset", f["id"], f["name"])
    return n


def run(cleanup_only=False) -> dict:
    """Connect → clean prior demo objects → create field-set + view → verify.
    Returns a dict the dashboard/runner can render. Raises on connect failure."""
    c = AbstractClient("api")
    conn = c.connect()
    if not conn.get("ok"):
        return {"ok": False, "connect": conn}
    removed = cleanup(c)
    if cleanup_only:
        return {"ok": True, "cleanup_only": True, "removed": removed, "scheme": conn.get("scheme")}

    fs = c.create_fieldset(FIELDSET)
    fid = (fs.get("body") or {}).get("id")
    vw = c.create_view(view_body(fid))
    vid = (vw.get("body") or {}).get("id")

    views = {v["id"] for v in (c.list_views().get("body", {}) or {}).get("views", [])}
    fsets = {f["id"] for f in (c.list_fieldsets().get("body", {}) or {}).get("fieldsets", [])}
    return {
        "ok": True, "scheme": conn.get("scheme"), "removed": removed,
        "fieldset_id": fid, "view_id": vid,
        "created_by": (vw.get("body") or {}).get("created_by"),
        "verified": (vid in views and fid in fsets),
        "total_views": len(views), "total_fieldsets": len(fsets),
    }


def main():
    r = run(cleanup_only="--cleanup" in sys.argv)
    print(json.dumps(r, indent=2))
    if not r.get("ok"):
        sys.exit(1)


if __name__ == "__main__":
    main()
