"""Unified investigation state. Pulls LIVE Abstract Insights/detections/analytics/
identity models when a connected AbstractClient is supplied; falls back to the
synthetic estate offline. Dedups overlapping records so merged sources don't
double-count.

The live methods follow abstract_client.AbstractClient's real contract: every call
returns an {"ok": bool, "body": ...} envelope, so we unwrap + extract defensively and
never assume a given endpoint is populated (one empty/erroring endpoint must not break
the console — it degrades to the synthetic baseline)."""
from __future__ import annotations
from dataclasses import dataclass, field

from pipeline import (normalize, Graph, run_detections, run_investigation,
                      continuous_scores, efficiency)
from data import events as _events, IOCS, INCIDENT_START


@dataclass
class State:
    live: bool = False
    norm: list = field(default_factory=list)
    graph: object = None
    findings: list = field(default_factory=list)
    inv: dict = field(default_factory=dict)
    scores: dict = field(default_factory=dict)
    metrics: dict = field(default_factory=dict)
    insights: list = field(default_factory=list)
    detections: list = field(default_factory=list)
    analytics: dict = field(default_factory=dict)
    mitre: list = field(default_factory=list)
    iocs: object = None


def _dedup(records, key):
    """Stable de-dup: keep first occurrence per key(record)."""
    seen, out = set(), []
    for r in records:
        k = key(r)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def _offline_state():
    norm = [normalize(i, r) for i, r in enumerate(_events())]
    g = Graph()
    for ev in norm:
        g.add(ev)
    findings = run_detections(norm, IOCS)
    inv = run_investigation(g, findings, IOCS, INCIDENT_START, norm)
    return State(live=False, norm=norm, graph=g, findings=findings, inv=inv,
                 scores=continuous_scores(norm, IOCS), metrics=efficiency(norm, findings),
                 iocs=IOCS)


# ── live-Abstract pull (defensive unwrapping of the {ok,body} envelope) ───────────
def _safe(call, default):
    try:
        return call()
    except Exception:   # noqa: BLE001 — one bad endpoint must not break the console
        return default


def _body(resp):
    """Unwrap an AbstractClient response → its body payload (or {} on failure)."""
    if not isinstance(resp, dict) or not resp.get("ok"):
        return {}
    return resp.get("body") or {}


def _as_list(body, *keys):
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for k in keys:
            v = body.get(k)
            if isinstance(v, list):
                return v
    return []


def _live_state(connection, window_days):
    """connection: an already-connected AbstractClient. Pull live objects, dedup, and
    merge onto the synthetic baseline so the graph/timeline still render if a given
    endpoint is empty."""
    base = _offline_state()
    c = connection
    ins_resp = _safe(lambda: c.list_insights(page_size=500), {})
    rules_resp = _safe(lambda: c.list_rules(), {})
    mitre_resp = _safe(lambda: c.mitre(), {})
    views_resp = _safe(lambda: c.list_views(), {})
    fs_resp = _safe(lambda: c.list_fieldsets(), {})

    ins_body = _body(ins_resp)
    insights = _dedup(_as_list(ins_body, "insights", "data", "results"),
                      lambda r: r.get("id") or r.get("nanoid") or id(r))
    detections = _dedup(_as_list(_body(rules_resp), "rules", "data", "results"),
                        lambda r: r.get("id") or r.get("nanoid") or id(r))
    mitre_body = _body(mitre_resp)
    mitre = (mitre_body.get("tactics") if isinstance(mitre_body, dict)
             else mitre_body if isinstance(mitre_body, list) else [])
    analytics = {
        "views": len(_as_list(_body(views_resp), "views", "data")),
        "fieldsets": len(_as_list(_body(fs_resp), "fieldsets", "field_sets", "data")),
        "insights_total": (ins_body.get("metadata", {}) or {}).get("total_count")
        if isinstance(ins_body, dict) else None,
    }
    base.live = True
    base.insights, base.detections, base.analytics, base.mitre = insights, detections, analytics, mitre
    return base


def build_state(connection=None, *, window_days: int = 30) -> State:
    if connection is None:
        return _offline_state()
    return _live_state(connection, window_days)


def selftest():
    s = build_state(None)
    assert s.live is False and s.graph is not None and len(s.findings) > 0
    assert _dedup([{"id": 1}, {"id": 1}, {"id": 2}], lambda r: r["id"]) == [{"id": 1}, {"id": 2}]

    class _Fake:   # mirrors AbstractClient's {ok,body} contract
        def list_insights(self, page_size=50, **kw):
            return {"ok": True, "body": {"insights": [{"id": "i1"}, {"id": "i1"}],
                                         "metadata": {"total_count": 1}}}
        def list_rules(self):
            return {"ok": True, "body": {"rules": [{"id": "r1"}]}}
        def mitre(self):
            return {"ok": True, "body": {"tactics": [{"name": "Initial Access", "total": 10, "enabled": 8}]}}
        def list_views(self):
            return {"ok": True, "body": {"views": [{"id": "v1"}]}}
        def list_fieldsets(self):
            return {"ok": True, "body": {"fieldsets": [{"id": "f1"}]}}

    sl = build_state(_Fake())
    assert sl.live is True and len(sl.insights) == 1 and sl.mitre[0]["total"] == 10
    assert sl.analytics["views"] == 1 and sl.analytics["insights_total"] == 1
    return {"ok": True, "findings": len(s.findings), "scored": len(s.scores),
            "live_insights": len(sl.insights)}


if __name__ == "__main__":
    print(selftest())
