"""
Elaborate live demo builder — exercises the breadth of natively-supported Abstract
elements against a real tenant, driven by scenarios.py.

Creates / pulls (all idempotent; everything tagged "[ABS-DEMO]"):
  • Field sets   — one per entity model (identity, cloud, network, edr, email, dns, ti, nhi, wildfire)
  • Saved views  — one per use-case scenario (saved searches across every data source)
  • Suppressions — tuning filters (best-effort; schema-resilient)
  • Analytics    — live MITRE ATT&CK coverage + field-analytics top-N + detection effectiveness
  • Manifest     — build_manifest.json: every id created + analytics pulled

  python3 build_demo.py            # build everything (cleans prior [ABS-DEMO] objects first)
  python3 build_demo.py --cleanup  # remove all [ABS-DEMO] objects and exit

Local-only elements (the engine in pipeline.py simulates what the API doesn't expose:
replay, triggers, continuous scoring, sub-agents, incidents/investigations) — see README.
"""
from __future__ import annotations

import json
import sys
import time

import re

from abstract_client import AbstractClient, ABSTRACT_ACCOUNT_ID, EP
import scenarios as S
import rules_engine as RE

WIN = ("2026-05-16T00:00:00Z", "2026-06-16T23:59:59Z")


def _retry(fn, tries=3):
    for i in range(tries):
        r = fn()
        if r.get("status") != 429:
            return r
        time.sleep(1.5 * (i + 1))
    return r


def _list_rules_stable(c, tries=6):
    """/v3/rules intermittently returns an empty data array while total_count is correct
    (caching race). Retry until the array is populated (or total_count says 0)."""
    for _ in range(tries):
        b = c._req("GET", "/v3/rules?page_size=500").get("body", {}) or {}
        arr = b.get("data") or b.get("rules") or b.get("items") or []
        if arr or not b.get("total_count"):
            return arr
        time.sleep(1.2)
    return arr


def cleanup(c):
    removed = {"views": 0, "fieldsets": 0, "suppressions": 0, "rules": 0}
    for v in (c.list_views().get("body", {}) or {}).get("views", []):
        if S.MARKER in (v.get("name") or ""):
            c.delete_view(v["id"]); removed["views"] += 1
    for f in (c.list_fieldsets().get("body", {}) or {}).get("fieldsets", []):
        if S.MARKER in (f.get("name") or ""):
            c.delete_fieldset(f["id"]); removed["fieldsets"] += 1
    tf = c._req("GET", "/v2/rule-tuning-filters?page_size=500")
    for it in (tf.get("body", {}) or {}).get("items", []):
        if S.MARKER in (it.get("title") or ""):
            tid = it.get("nanoid") or it.get("id")
            c._req("DELETE", f"/v2/rule-tuning-filters/{tid}"); removed["suppressions"] += 1
    for r in _list_rules_stable(c):
        if S.MARKER in (r.get("name") or "") and r.get("nanoid"):
            c._req("DELETE", f"/v1/rules/{r['nanoid']}"); removed["rules"] += 1
    return removed


def build_rules(c, action="realtime", enabled=False):
    """Create a real detection rule per scenario — rules generate findings + insights.
    action='batch' evaluates historical data (replay); 'realtime' fires on new events."""
    made, failed = [], []
    op = lambda o: "EQUALS" if o == "EQUALS" else "CONTAINS"  # engine string comparison
    for sc in S.SCENARIOS:
        conds = [(f, op(o), v) for (f, o, v) in sc["conditions"] if o != "IS_IN_SUBNET"]
        body = RE.rule_body(f"{S.MARKER} {sc['title']}", sc["severity"],
                            f"Model demo detection — {sc['title']} (see docs/threat-model).",
                            sc["mitre"], ["abs-demo"] + sc["tags"], conds,
                            event_categories=["threat"], action=action)
        body["is_enabled"] = enabled
        r = _retry(lambda b=body: c._req("POST", "/v1/rules/", b))
        if r.get("ok"):
            rid = (re.search(r"id (\w+)", str((r.get("body") or {}).get("message", ""))) or [None, None])
            made.append({"key": sc["key"], "id": rid[1] if rid else None})
            print(f"  rule {sc['key']:<22} -> created {rid[1] if rid else ''}")
        else:
            failed.append({"key": sc["key"], "status": r.get("status")})
            print(f"  rule {sc['key']:<22} -> FAIL {r.get('status')}")
    return made, failed


def build_fieldsets(c):
    ids = {}
    for model, fields in S.FIELDSETS.items():
        r = _retry(lambda: c.create_fieldset({
            "name": f"{S.MARKER} {model} — entity fields",
            "fields": fields, "tags": ["abs-demo", "entity-model", model]}))
        fid = (r.get("body") or {}).get("id")
        ids[model] = fid
        print(f"  fieldset {model:<16} -> {fid or 'FAIL ' + str(r.get('status'))}")
    return ids


def build_views(c, fieldset_ids):
    created, failed = [], []
    for sc in S.SCENARIOS:
        body = {
            "name": f"{S.MARKER} {sc['title']}",
            "query": S.view_query_from_conditions(sc["conditions"]),
            "time_selection": {"type": "Relative", "numeric_value": 30, "option_selected": "days",
                               "end_date": None, "start_date": None, "end_numeric_value": None,
                               "end_option_selected": None},
            "fieldset_ids": [fieldset_ids[sc["model"]]] if fieldset_ids.get(sc["model"]) else None,
            "fields": S.FIELDSETS[sc["model"]],
            "order_by": "@timestamp", "order_type": "DESC",
        }
        r = _retry(lambda: c.create_view(body))
        vid = (r.get("body") or {}).get("id")
        if vid:
            created.append({"key": sc["key"], "title": sc["title"], "id": vid,
                            "model": sc["model"], "mitre": [m[0] for m in sc["mitre"]],
                            "severity": sc["severity"], "tags": sc["tags"]})
            print(f"  view {sc['key']:<22} -> {vid}")
        else:
            failed.append({"key": sc["key"], "status": r.get("status"),
                           "error": (r.get("error") or "")[:160]})
            print(f"  view {sc['key']:<22} -> FAIL {r.get('status')}")
    return created, failed


def build_suppressions(c):
    made = []
    for sup in S.SUPPRESSIONS:
        conds = [{"field": f, "field_operation": op,
                  "fieldType": ("Ipv4" if op == "IS_IN_SUBNET" else "String"), "value": v}
                 for (f, op, v) in sup["conditions"]]
        body = {"title": sup["title"],
                "tuning_filter_combination": {"combination": "ANY", "conditions": conds}}
        r = _retry(lambda b=body: c._req("POST", "/v2/rule-tuning-filters/", b))
        tid = (r.get("body") or {}).get("nanoid") or (r.get("body") or {}).get("id")
        made.append({"title": sup["title"], "id": tid, "status": r.get("status")})
        print(f"  suppression -> {'ok ' + str(tid) if tid else 'staged (' + str(r.get('status')) + ')'}")
    return made


def pull_analytics(c):
    a = {}
    mitre = c._req("GET", "/v3/rules/mitre")
    if mitre.get("ok"):
        a["mitre_coverage"] = (mitre.get("body") or {}).get("summary")
    de = c._req("GET", "/v2/rules/detection-effectiveness")
    a["detection_effectiveness_status"] = de.get("status")
    a["field_analytics"] = {}
    for field in S.ANALYTICS_FIELDS:
        r = _retry(lambda f=field: c._req("POST", "/v1/streamviewer/field-analytics",
                                          {"start_time": WIN[0], "end_time": WIN[1], "field": f,
                                           "vendor_account_id": ABSTRACT_ACCOUNT_ID}))
        if r.get("ok"):
            cats = ((r.get("body") or {}).get("analytics") or {}).get("categorical") or []
            a["field_analytics"][field] = {
                "total": (r.get("body") or {}).get("analytics", {}).get("total_count"),
                "top": [(x.get("field_value"), x.get("count")) for x in cats[:5]]}
        else:
            a["field_analytics"][field] = {"status": r.get("status")}
    return a


def main():
    c = AbstractClient("api")
    conn = c.connect()
    print("connect:", json.dumps(conn))
    if not conn.get("ok"):
        sys.exit(1)

    print("\ncleanup prior [ABS-DEMO] objects:", json.dumps(cleanup(c)))
    if "--cleanup" in sys.argv:
        print("cleanup-only done."); return

    print("\nfield sets (entity models / mappers):")
    fsets = build_fieldsets(c)
    print("\nsaved views (use-case scenarios / saved searches):")
    views, failed = build_views(c, fsets)
    print("\ndetection rules (real, disabled — generate findings + insights when enabled):")
    rules_made, rules_failed = build_rules(c)
    print("\nsuppressions (tuning filters):")
    sups = build_suppressions(c)
    print("\nlive analytics:")
    analytics = pull_analytics(c)
    print("  mitre coverage:", json.dumps(analytics.get("mitre_coverage")))
    for f, v in analytics["field_analytics"].items():
        print(f"  top {f:<16}:", v.get("top", v))

    manifest = {
        "catalog": S.summary(),
        "fieldsets": fsets,
        "views_created": len(views), "views_failed": len(failed),
        "views": views, "failed": failed,
        "suppressions": sups,
        "rules_created": len(rules_made), "rules_failed": len(rules_failed), "rules": rules_made,
        "analytics": analytics,
    }
    with open("build_manifest.json", "w") as fh:
        json.dump(manifest, fh, indent=2)

    print("\n=== SUMMARY ===")
    print(f"  field sets created : {sum(1 for v in fsets.values() if v)}/{len(fsets)}")
    print(f"  views created      : {len(views)} (failed {len(failed)})")
    print(f"  detection rules    : {len(rules_made)} created (failed {len(rules_failed)}) — disabled, ready to enable")
    print(f"  suppressions       : {sum(1 for s in sups if s['id'])} created, "
          f"{sum(1 for s in sups if not s['id'])} staged")
    mc = analytics.get("mitre_coverage") or {}
    print(f"  MITRE coverage     : {mc.get('enabled')}/{mc.get('total')} techniques enabled")
    print(f"  manifest           : build_manifest.json")


if __name__ == "__main__":
    main()
