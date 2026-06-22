"""Live Abstract authoring — build · validate · apply · review.

Centralizes create/update across every object type the Abstract API actually supports,
mapping the user-facing kinds to real endpoints (never inventing one):

  Saved view        → POST /v1/streamviewer/view        (create_view)
  Field set         → POST /v1/streamviewer/field-set   (create_fieldset)
  Detection rule    → POST /v1/rules/ (+ /v3/rules/validations)  (rules_engine)
  Suppression       → POST /v2/rule-tuning-filters/      (tuning filter)
  Insight           → POST /v1/insights/                 (create_insight)
  Schema/field-map  → persisted as a field-set projection (no native schema API)
  Identity model    → persisted as a tagged insight carrying the model JSON
  Parser            → exported as a JSON artifact (no native parser API)

Everything is dry-run-first: build() returns the exact payload + a human diff; apply()
only mutates when called explicitly. review() reads the live tenant (or the modeled
estate offline) and proposes concrete optimizations."""
from __future__ import annotations

import json
import rules_engine as RE

LABEL_TO_KIND = {
    "Saved view": "view", "Field set": "fieldset", "Detection rule": "rule",
    "Suppression": "suppression", "Insight": "insight", "Identity model": "identity_model",
    "Schema / field-map": "schema", "Parser": "parser",
}
# kinds with a real endpoint (the rest are export-only)
LIVE_KINDS = {"view", "fieldset", "rule", "suppression", "insight", "schema", "identity_model"}
MARKER = "[ABS-DEMO]"


def _norm_kind(k):
    return LABEL_TO_KIND.get(k, k)


def _list(resp, *keys):
    body = resp.get("body") if isinstance(resp, dict) else None
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for k in keys:
            if isinstance(body.get(k), list):
                return body[k]
    return []


def build(kind, state=None, model=None, **opts) -> dict:
    """Return {kind, method, live_capable, payload, diff[, export_name]} for a dry-run."""
    kind = _norm_kind(kind)
    name = opts.get("name") or f"{MARKER} console authored"

    if kind == "view":
        payload = {"name": f"{name} — view",
                   "query": [{"id": "q1", "depth": 0, "field": "severity", "index": 0,
                              "value": "critical", "parentId": None, "fieldType": "String",
                              "field_operation": "EQUALS", "subFieldOperation": ""}],
                   "fields": ["type", "@timestamp", "severity", "user_name", "source_address", "message"],
                   "order_by": "@timestamp", "order_type": "DESC"}
        return {"kind": kind, "method": "create_view", "live_capable": True, "payload": payload,
                "diff": f"CREATE view '{payload['name']}' (severity == critical, +{len(payload['fields'])} fields)"}

    if kind == "fieldset":
        payload = {"name": f"{name} — fieldset",
                   "fields": ["type", "@timestamp", "severity", "user_name", "source_address",
                              "file.hash.sha256", "threat.technique_id", "message"],
                   "tags": ["abs-demo", "console"]}
        return {"kind": kind, "method": "create_fieldset", "live_capable": True, "payload": payload,
                "diff": f"CREATE field-set '{payload['name']}' (+{len(payload['fields'])} fields)"}

    if kind == "rule":
        conditions = opts.get("conditions") or [("severity", "EQUALS", "critical")]
        payload = RE.rule_body(
            name=f"{name} — detection", severity="critical",
            description="Identity-driven detection authored from the console.",
            mitre=[("T1078", "Valid Accounts")], tags=["abs-demo", "console"],
            conditions=conditions, action=opts.get("action", "realtime"))
        return {"kind": kind, "method": "create_rule", "live_capable": True, "payload": payload,
                "diff": f"CREATE rule '{payload['name']}' ({len(conditions)} condition(s); "
                        f"validate → create DISABLED → enable to fire)"}

    if kind == "suppression":
        field, op, value = opts.get("condition", ("source_address", "IS_IN_SUBNET", "52.20.10.5/32"))
        ftype = "Ipv4" if op == "IS_IN_SUBNET" else "String"
        payload = {"title": f"{name} — suppression",
                   "tuning_filter_combination": {"combination": "ANY",
                       "conditions": [{"field": field, "field_operation": op,
                                       "fieldType": ftype, "value": value}]}}
        return {"kind": kind, "method": "suppression", "live_capable": True, "payload": payload,
                "diff": f"CREATE tuning-filter '{payload['title']}' ({field} {op} {value})"}

    if kind == "insight":
        payload = {"title": f"{name} — insight", "status": "open", "severity": "high",
                   "summary": "Identity re-exposure survives IDP restore; credential still leaked.",
                   "categories": ["detection"],
                   "mitre_attack_techniques": [{"id": "T1078", "name": "Valid Accounts", "sub_id": ""}]}
        return {"kind": kind, "method": "create_insight", "live_capable": True, "payload": payload,
                "diff": f"CREATE insight '{payload['title']}' (severity high, T1078)"}

    if kind == "schema":
        mapping = opts.get("map") or {"src_ip": "source_address", "account": "user_name",
                                      "user": "actor.user.name", "sev": "severity",
                                      "sha256": "file.hash.sha256"}
        payload = {"name": f"{name} — schema (field-map)",
                   "fields": sorted(set(mapping.values())), "tags": ["abs-demo", "schema"]}
        return {"kind": kind, "method": "create_fieldset", "live_capable": True, "payload": payload,
                "diff": f"PERSIST schema as field-set '{payload['name']}' "
                        f"({len(mapping)} source→OCSF maps → {len(payload['fields'])} fields)"}

    if kind == "identity_model":
        import entity_model as EM
        if model is None:
            if state is None:
                from live_data import build_state
                state = build_state()
            model = EM.build_entity_model(state)
        ab = EM.to_abstract(model, name=f"{name} — identity-risk model")
        payload = {"title": ab["name"], "status": "open", "severity": "medium",
                   "summary": json.dumps(ab)[:1900], "categories": ["identity", "model"],
                   "mitre_attack_techniques": [{"id": "T1078", "name": "Valid Accounts", "sub_id": ""}]}
        return {"kind": kind, "method": "create_insight", "live_capable": True, "payload": payload,
                "diff": f"PERSIST identity model as insight '{payload['title']}' "
                        f"({len(ab['top_risks'])} ranked identities, {len(ab['entity_kinds'])} kinds)",
                "model": ab}

    if kind == "parser":
        payload = {"name": f"{name} — parser", "source": opts.get("source", "okta"),
                   "extract": opts.get("extract", {"account": "$.actor.alternateId",
                                                    "src_ip": "$.client.ipAddress",
                                                    "event": "$.eventType"})}
        return {"kind": kind, "method": None, "live_capable": False, "payload": payload,
                "export_name": "parser_okta",
                "diff": "EXPORT parser spec (okta → fields) — no native parser API; exported as JSON"}

    raise ValueError(f"unknown authoring kind: {kind}")


def validate(client, authored) -> dict:
    if authored.get("method") == "create_rule":
        return RE.validate(client, authored["payload"])
    return {"is_valid": True, "note": "no validation endpoint for this kind"}


def apply(client, authored, *, enabled=False) -> dict:
    """Mutate the tenant. Offline clients return simulated results. Rules are validated first
    and created DISABLED unless enabled=True."""
    payload, method = authored["payload"], authored.get("method")

    if not authored.get("live_capable"):
        path = f"{authored.get('export_name', 'authored')}.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return {"applied": False, "exported": path, "note": "no live endpoint; exported artifact"}

    if method == "create_rule":
        v = RE.validate(client, payload)
        if not v.get("is_valid"):
            return {"applied": False, "validation": v}
        res = RE.create(client, payload, enabled=enabled)
        return {"applied": bool(res.get("ok")), "id": res.get("nanoid"),
                "status": res.get("status"), "validation": v}

    if method == "suppression":
        res = client._req("POST", "/v2/rule-tuning-filters/", payload)
        body = res.get("body") or {}
        return {"applied": bool(res.get("ok")), "id": body.get("nanoid") or body.get("id"),
                "status": res.get("status")}

    fn = getattr(client, method)
    res = fn(payload)
    body = res.get("body") or {}
    return {"applied": bool(res.get("ok")), "id": body.get("id") or body.get("nanoid"),
            "status": res.get("status"), "simulated": res.get("simulated", False)}


def review(client=None, state=None) -> dict:
    """Evaluate the existing posture and propose concrete optimizations. Uses the live tenant
    when a connected client is supplied; otherwise reviews the modeled estate."""
    if client is not None and getattr(client, "mode", "offline") == "api":
        rules = _list(client.list_rules(), "rules", "data")
        views = _list(client.list_views(), "views", "data")
        fsets = _list(client.list_fieldsets(), "fieldsets", "field_sets", "data")
        disabled = [r for r in rules if r.get("is_enabled") is False]
        untagged = [v for v in views if not v.get("tags")]
        recs = []
        if disabled:
            recs.append(f"Enable or prune {len(disabled)} disabled rules")
        if untagged:
            recs.append(f"Tag {len(untagged)} views for discoverability")
        if not fsets:
            recs.append("No field-sets — create entity-model projections")
        return {"live": True,
                "summary": {"rules": len(rules), "disabled_rules": len(disabled),
                            "views": len(views), "untagged_views": len(untagged),
                            "fieldsets": len(fsets)},
                "recommendations": recs or ["posture looks healthy"]}

    import entity_model as EM
    if state is None:
        from live_data import build_state
        state = build_state()
    m = EM.build_entity_model(state)
    ev = EM.evaluate(m)
    recs = []
    if ev["high_risk"]:
        recs.append(f"Create insights for {ev['high_risk']} high-risk identities")
    if ev["survives_restore"]:
        recs.append(f"{ev['survives_restore']} entities survive restore — rotate creds + revoke "
                    f"sessions + author a re-exposure detection, not just restore")
    if ev["vip_at_risk"]:
        recs.append(f"{ev['vip_at_risk']} VIP(s) at risk — prioritize + add a VIP suppression-exempt rule")
    if ev["signal_coverage_pct"] < 100:
        recs.append("Author detections for the uncovered identity factors")
    return {"live": False, "model_eval": ev, "recommendations": recs}


def selftest():
    from abstract_client import AbstractClient
    from live_data import build_state
    st = build_state(None)
    kinds = ["Saved view", "Field set", "Detection rule", "Suppression", "Insight",
             "Schema / field-map", "Identity model", "Parser"]
    built = {}
    for k in kinds:
        a = build(k, state=st)
        assert "payload" in a and "diff" in a, k
        built[k] = a
    assert built["Detection rule"]["method"] == "create_rule"
    assert built["Identity model"]["method"] == "create_insight" and "model" in built["Identity model"]
    assert built["Parser"]["live_capable"] is False

    off = AbstractClient("offline")
    r_view = apply(off, built["Saved view"])           # simulated create
    assert r_view["applied"] is True and r_view.get("simulated")
    r_parser = apply(off, built["Parser"])             # export only
    assert r_parser["applied"] is False and r_parser["exported"].endswith(".json")

    rev = review(state=st)
    assert "recommendations" in rev and "model_eval" in rev
    return {"ok": True, "kinds": len(kinds),
            "live_capable": sum(1 for a in built.values() if a["live_capable"]),
            "recs": len(rev["recommendations"])}


if __name__ == "__main__":
    print(selftest())
