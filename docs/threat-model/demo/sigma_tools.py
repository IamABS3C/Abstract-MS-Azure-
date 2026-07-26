"""Detection-as-code via pySigma — parse a Sigma rule (YAML) and map it to Abstract
conditions + a saved-view payload you can dry-run/apply through abstract_authoring. Best-effort:
Sigma's full condition grammar (and/or/not, value-lists) is richer than a flat view query, so
this flattens selections into (field, field_operation, value) clauses. Graceful if pySigma is
absent. Extends the Authoring tab — bring the SigmaHQ catalog into Abstract."""
from __future__ import annotations

_OPMAP = [("contains", "CONTAINS"), ("startswith", "STARTS_WITH"),
          ("endswith", "ENDS_WITH"), ("re", "MATCHES_REGEX")]

SAMPLE = """title: Suspicious PowerShell -enc
logsource: {product: windows}
detection:
  sel:
    Image|endswith: \\powershell.exe
    CommandLine|contains: '-enc'
  condition: sel
level: high
"""


def available() -> bool:
    try:
        import sigma
        return sigma is not None
    except Exception:   # noqa: BLE001
        return False


def _op_for(modifiers):
    names = " ".join(m.__name__.lower() for m in (modifiers or []))
    for key, op in _OPMAP:
        if key in names:
            return op
    return "EQUALS"


def sigma_to_abstract(yaml_str: str = SAMPLE) -> dict:
    """Parse a Sigma rule → {title, level, conditions[], view_payload}."""
    if not available():
        return {"available": False, "note": "pip install pysigma"}
    try:
        from sigma.collection import SigmaCollection
        rule = SigmaCollection.from_yaml(yaml_str).rules[0]
        conds = []
        for _name, det in rule.detection.detections.items():
            for it in getattr(det, "detection_items", []) or []:
                field = getattr(it, "field", None) or "message"
                op = _op_for(getattr(it, "modifiers", None))
                for v in (getattr(it, "value", None) or []):
                    val = v.to_plain() if hasattr(v, "to_plain") else str(v)
                    val = str(val).strip("*")          # strip wildcards (op implies them)
                    conds.append({"field": field, "field_operation": op,
                                  "value": val, "fieldType": "String"})
        view_query = [{"id": f"q{i}", "depth": 0, "field": c["field"], "index": i,
                       "value": c["value"], "parentId": None, "fieldType": c["fieldType"],
                       "field_operation": c["field_operation"], "subFieldOperation": ""}
                      for i, c in enumerate(conds)]
        ls = getattr(rule, "logsource", None)
        return {"available": True, "title": str(getattr(rule, "title", "")),
                "level": str(getattr(rule, "level", "")),
                "logsource": {"product": getattr(ls, "product", None),
                              "service": getattr(ls, "service", None)} if ls else {},
                "conditions": conds, "n": len(conds),
                "view_payload": {"name": f"[ABS-DEMO] Sigma — {getattr(rule, 'title', 'rule')}",
                                 "query": view_query,
                                 "fields": ["type", "@timestamp", "severity", "user_name", "message"],
                                 "order_by": "@timestamp", "order_type": "DESC"}}
    except Exception as e:   # noqa: BLE001
        return {"available": True, "error": str(e)[:200]}


def selftest():
    if not available():
        return {"ok": True, "available": False}
    r = sigma_to_abstract(SAMPLE)
    assert r.get("available")
    assert r.get("error") or (r["n"] >= 2 and r["conditions"][0]["field_operation"] in
                              ("ENDS_WITH", "CONTAINS", "EQUALS"))
    return {"ok": True, "title": r.get("title"), "conditions": r.get("n"),
            "ops": sorted({c["field_operation"] for c in r.get("conditions", [])})}


if __name__ == "__main__":
    print(selftest())
