"""
Real detection-rule authoring against POST /v1/rules.

The rule `query_json` is an Avro-encoded structure (union type tags like
`security.abs.rules.avro.state.*`). Rather than reverse-engineer it, we copy a
canonical rule captured from the tenant (`_rule_template.json`) and swap only the
condition list — guaranteeing a structurally valid body. The template's actions
include CREATE_FINDING + CREATE_INSIGHT, so a created rule produces real insights.

  validate(client, rule)  → dry-run via POST /v3/rules/validations
  create(client, rule, enabled=False) → POST /v1/rules

Rules are created DISABLED by default so they don't generate tenant noise; flip
is_enabled to let them fire. Reversible via DELETE /v1/rules/{nanoid}.
"""
from __future__ import annotations

import copy
import json
import os

_TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_rule_template.json")


def _load_template():
    with open(_TEMPLATE_PATH) as fh:
        return json.load(fh)


def condition(field: str, op: str, value: str) -> dict:
    """String comparison condition in the engine's Avro shape."""
    return {
        "field": {"fieldPath": field, "fieldType": "STRING"},
        "comparison": {"security.abs.rules.avro.state.Compare_String_String": {
            "target": {"string": value}, "operator": op, "case_sensitive": False}},
    }


def build_query_json(conditions, operator="ALL") -> dict:
    """Clone the canonical template; replace only the condition list."""
    qj = copy.deepcopy(_load_template())
    cc = qj["condition_combination"]["security.abs.rules.avro.state.ConditionCombination"]
    cc["operator"] = operator
    cc["conditions"] = [condition(f, op, v) for (f, op, v) in conditions]
    return qj


def rule_body(name, severity, description, mitre, tags, conditions,
              event_categories=None, operator="ALL", action="realtime") -> dict:
    # action="realtime" → fires on new events; "batch" → evaluates historical data (replay)
    return {
        "name": name, "type": "conditional", "action": action,
        "severity": severity, "description": description,
        "mitre_attack_techniques": [{"id": i, "name": n} for (i, n) in mitre],
        "tags": tags, "event_categories": event_categories or ["threat"],
        "query_json": build_query_json(conditions, operator),
        "query_snapshot": [],            # create requires this (empty = derive from query_json)
        "local_filter_combination": {},
        "reference_links": [],
    }


def validate(client, body: dict) -> dict:
    r = client._req("POST", "/v3/rules/validations", body)
    b = r.get("body") or {}
    if isinstance(b, dict) and "is_valid" in b:
        return {"is_valid": b["is_valid"], "errors": b.get("errors")}
    return {"is_valid": False, "raw": (r.get("error") or json.dumps(b))[:300], "status": r.get("status")}


def create(client, body: dict, enabled=False) -> dict:
    body = dict(body); body["is_enabled"] = enabled
    r = client._req("POST", "/v1/rules/", body)  # trailing slash avoids 307
    b = r.get("body") or {}
    nano = (b.get("nanoid") or (b.get("rule_details") or {}).get("nanoid")
            or (b.get("rule") or {}).get("nanoid"))
    return {"ok": r.get("ok"), "status": r.get("status"), "nanoid": nano,
            "error": None if r.get("ok") else (r.get("error") or "")[:300]}


def delete(client, nanoid: str) -> dict:
    return client._req("DELETE", f"/v1/rules/{nanoid}")
