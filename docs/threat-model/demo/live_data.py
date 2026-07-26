"""Unified investigation State — runs INDEPENDENTLY of the demo data.

Three ways to populate State, in priority order:
  1. LIVE  — a connected AbstractClient → pull real events/insights/detections/MITRE,
             normalize live events into the entity graph (portable; no demo modules needed).
  2. DEMO  — the synthetic estate (data.py) when present, for an offline teaching run.
  3. EMPTY — neither available → a valid empty State so the dashboard still loads anywhere
             (e.g. a bare JupyterHub) and the user connects from the Settings tab.

Only `pipeline` (stdlib engine: Graph / IOCSet / Norm primitives) is required at import; the
synthetic `data.py` is imported lazily and is entirely optional. Live mode never touches it.

The State *contract* (graph, norm, findings, scores, inv, metrics, iocs, insights, detections,
mitre, live, source) is what every dashboard module consumes — so the engine behind it can be
swapped without touching the UI."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from pipeline import Graph, IOCSet, Norm, ek

PRINCIPAL_PREFIXES = ("identity", "account", "host", "nhi", "agent", "device", "session")


@dataclass
class State:
    live: bool = False
    source: str = "empty"          # live | synthetic | empty
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


@dataclass
class Finding:
    rule: str
    title: str
    detail: str
    risk: int
    severity: str
    entities: list = field(default_factory=list)


def _dedup(records, key):
    seen, out = set(), []
    for r in records:
        k = key(r)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


# ── envelope unwrap helpers (AbstractClient returns {ok, body}) ───────────────────
def _safe(call, default):
    try:
        return call()
    except Exception:   # noqa: BLE001
        return default


def _body(resp):
    if not isinstance(resp, dict) or not resp.get("ok"):
        return {}
    return resp.get("body") or {}


def _as_list(body, *keys):
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for k in keys:
            if isinstance(body.get(k), list):
                return body[k]
    return []


# ── portable live normalizer (Abstract/OCSF event dict → Norm; no demo deps) ──────
_SEV_NUM = {0: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical", 5: "critical"}


def _first(raw, *names):
    for n in names:
        v = raw.get(n)
        if v not in (None, ""):
            return v
    return None


def _parse_ts(val, idx):
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:   # noqa: BLE001
            pass
    return datetime(2026, 1, 1) + timedelta(seconds=idx)


def _norm_sev(val):
    if isinstance(val, (int, float)):
        return _SEV_NUM.get(int(val), "informational")
    return str(val or "informational").lower()


def normalize_live(idx, raw):
    """Map a live Abstract/OCSF event to a Norm (entities + edges). Defensive: unknown
    shapes still yield whatever identities/hosts/IOCs are present."""
    ts = _parse_ts(_first(raw, "@timestamp", "timestamp", "ts", "time", "event_time"), idx)
    src = _first(raw, "vendor", "source_type", "datasource", "product", "source", "_t") or "event"
    sev = _norm_sev(_first(raw, "severity", "sev", "event.severity", "risk_level"))
    user = _first(raw, "user_name", "user", "actor.user.name", "username", "src_user")
    acct = _first(raw, "account", "account_name", "actor", "principal")
    host = _first(raw, "host", "hostname", "device.hostname", "src_host", "computer")
    sip = _first(raw, "source_address", "src_ip", "ip", "client.ip", "srcip")
    dip = _first(raw, "destination_address", "dst_ip", "dest_address", "dstip")
    dom = _first(raw, "domain", "dns.question.name", "query", "dns_query")
    url = _first(raw, "url", "http.url", "uri")
    fhash = _first(raw, "file.hash.sha256", "sha256", "hash", "file_hash")
    ents, edges = [], []

    def add(t, i):
        if i in (None, ""):
            return None
        ents.append((t, str(i), {}))
        return ek(t, str(i))

    ku = add("identity", user)
    ka = add("account", acct or (f"id:{user}" if user else None))
    kh = add("host", host)
    ksip = add("ip", sip)
    kdip = add("ip", dip)
    kd = add("domain", dom)
    kurl = add("url", url)
    khash = add("hash", fhash)
    for rel, a, b in [("authenticated_as", ka, ku), ("auth_from", ka, ksip),
                      ("on_host", kh, ku), ("connected_to", kh, kdip),
                      ("resolved", kh, kd), ("has", kh, khash), ("contacted", kh, kurl)]:
        if a and b:
            edges.append((rel, a, b))
    mal = "live-signal" if sev in ("high", "critical") else ""
    return Norm(idx, ts, str(src), "OCSF", sev, ents, edges, "", mal, raw)


def _heuristic_scores(norm):
    bump = {"critical": 90, "high": 72, "medium": 45, "low": 22, "informational": 10}
    scores = {}
    for ev in norm:
        b = bump.get(ev.severity, 10)
        for k in ev.entity_keys():
            if k.split(":", 1)[0] in PRINCIPAL_PREFIXES:
                cur = scores.setdefault(k, {"final": 0, "trend": 0, "trajectory": []})
                cur["final"] = min(100, max(cur["final"], b))
                cur["trajectory"].append((ev.ts, cur["final"]))
    return scores


def _iocs_from(norm):
    ips, doms, urls, hashes = set(), set(), set(), set()
    buckets = {"ip": ips, "domain": doms, "url": urls, "hash": hashes}
    for ev in norm:
        for (t, i, _a) in ev.entities:
            if t in buckets:
                buckets[t].add(i)
    return IOCSet(doms, ips, urls, hashes)


def _findings_from(norm, insights):
    out = []
    for ins in insights[:50]:
        if not isinstance(ins, dict):
            continue
        out.append(Finding(rule=ins.get("rule_name") or ins.get("category") or "insight",
                            title=ins.get("title") or "Abstract insight",
                            detail=(ins.get("summary") or ins.get("description") or "")[:300],
                            risk={"critical": 95, "high": 80, "medium": 55, "low": 30}.get(
                                str(ins.get("severity", "")).lower(), 60),
                            severity=str(ins.get("severity", "high")).lower(), entities=[]))
    for ev in norm:
        if ev.severity in ("high", "critical"):
            out.append(Finding(rule=ev.source, title=f"{ev.severity} {ev.source} event",
                               detail=str(ev.raw)[:200],
                               risk=90 if ev.severity == "critical" else 72,
                               severity=ev.severity, entities=sorted(ev.entity_keys())))
    return out[:60]


def _portable_inv(scores, findings):
    principals = [k for k in scores if k.split(":", 1)[0] in PRINCIPAL_PREFIXES]
    ranked = sorted(principals, key=lambda k: -scores[k]["final"])
    high = [k for k in ranked if scores[k]["final"] >= 70]
    lead = max(findings, key=lambda f: f.risk) if findings else None
    return {"subagents": {"scoping": {"victims": high or ranked[:8],
                                      "realtime": high or ranked[:8], "historical": []},
                          "identity": {}},
            "prediction": {"predicted_next_targets": ranked[len(high):len(high) + 3],
                           "rationale": "entities trending toward high risk (heuristic)"},
            "lead_finding": lead,
            "triage": {"verdict": "true-positive" if high else "needs-info"}}


def _portable_metrics(norm, findings):
    total, fwd = len(norm), len(findings)
    return {"total_events": total, "forwarded_to_siem": fwd,
            "reduction_pct": round(100 * (1 - fwd / total), 1) if total else 0,
            "raw_alerts": fwd, "incidents": len({f.rule for f in findings}) if findings else 0,
            "fatigue_reduction_pct": 0, "mttd_siem_sec": 1200, "mttd_stream_sec": 1}


_IPRE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMRE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
_HASHRE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_EMAILRE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", re.I)


def _norm_from_insights(insights, start_idx=0):
    """Build real Norm events from live insights — subject (created_by) entity + any
    IP/domain/hash/email indicators extracted from the title/summary — so the live graph,
    scoring, and identity-intel run on REAL tenant alerts even when raw event-search is
    gated/disabled on the tenant."""
    out = []
    for j, ins in enumerate(insights):
        if not isinstance(ins, dict):
            continue
        text = " ".join(str(ins.get(k, "")) for k in ("title", "summary", "description", "name"))
        raw = {"_t": "insight", "ts": ins.get("created_at"),
               "severity": str(ins.get("severity", "high")).lower(),
               "title": ins.get("title"), "nanoid": ins.get("nanoid"), "status": ins.get("status")}
        if ins.get("created_by_entity_id"):
            raw["account"] = f"{ins.get('created_by_entity_type', 'entity')}:{ins['created_by_entity_id']}"
        ips = _IPRE.findall(text)
        emails = _EMAILRE.findall(text)
        hashes = _HASHRE.findall(text)
        doms = [d for d in _DOMRE.findall(text) if d not in ips and "@" not in d]
        if ips:
            raw["source_address"] = ips[0]
        if emails:
            raw["user_name"] = emails[0]
        if hashes:
            raw["file.hash.sha256"] = hashes[0]
        if doms:
            raw["domain"] = doms[0]
        out.append(normalize_live(start_idx + j, raw))
    return out


def _build_from_events(raw_events, insights, detections, mitre, analytics):
    norm = [normalize_live(i, r) for i, r in enumerate(raw_events) if isinstance(r, dict)]
    norm += _norm_from_insights(insights, start_idx=len(norm))   # real entities from live insights
    g = Graph()
    for ev in norm:
        g.add(ev)
    scores = _heuristic_scores(norm)
    findings = _findings_from(norm, insights)
    return State(live=True, source="live", norm=norm, graph=g, iocs=_iocs_from(norm),
                 scores=scores, findings=findings, inv=_portable_inv(scores, findings),
                 metrics=_portable_metrics(norm, findings), insights=insights,
                 detections=detections, mitre=mitre, analytics=analytics)


# ── live pull (raw event-search needs a typed condition; gated on this tenant → best-effort) ──
def _pull_events(c, size=300):
    body = _body(_safe(lambda: c.search(size=size), {}))
    evs = _as_list(body, "events", "results", "data", "records")
    if not evs and isinstance(body, dict):
        hits = (body.get("hits") or {}).get("hits")
        if isinstance(hits, list):
            evs = [h.get("_source", h) for h in hits]
    return evs


def _live_state(connection, window_days):
    c = connection
    insights = _dedup(_as_list(_body(_safe(lambda: c.list_insights(page_size=500), {})),
                               "insights", "data", "results"),
                      lambda r: (r.get("id") or r.get("nanoid") or id(r)) if isinstance(r, dict) else id(r))
    ins_total = (_body(_safe(lambda: c.list_insights(page_size=1), {})).get("metadata") or {}).get("total_count")
    detections = _dedup(_as_list(_body(_safe(lambda: c.list_rules(), {})), "rules", "items", "data"),
                        lambda r: (r.get("id") or r.get("nanoid") or id(r)) if isinstance(r, dict) else id(r))
    mitre_body = _body(_safe(lambda: c.mitre(), {}))
    mitre = (mitre_body.get("tactics") if isinstance(mitre_body, dict)
             else mitre_body if isinstance(mitre_body, list) else [])
    analytics = {"views": len(_as_list(_body(_safe(lambda: c.list_views(), {})), "views", "data")),
                 "fieldsets": len(_as_list(_body(_safe(lambda: c.list_fieldsets(), {})),
                                           "fieldsets", "field_sets", "data")),
                 "rules": len(detections), "insights_total": ins_total}
    raw_events = _safe(lambda: _pull_events(c), [])
    return _build_from_events(raw_events, insights, detections, mitre, analytics)


# ── synthetic demo (optional) + empty fallback ───────────────────────────────────
def _synthetic_state():
    """The teaching estate. Lazily imports the optional demo modules; returns None if absent."""
    try:
        from pipeline import (normalize, run_detections, run_investigation,
                              continuous_scores, efficiency)
        from data import events as _events, IOCS, INCIDENT_START
    except Exception:   # noqa: BLE001 — demo data not shipped → no synthetic mode
        return None
    norm = [normalize(i, r) for i, r in enumerate(_events())]
    g = Graph()
    for ev in norm:
        g.add(ev)
    findings = run_detections(norm, IOCS)
    return State(live=False, source="synthetic", norm=norm, graph=g, findings=findings,
                 inv=run_investigation(g, findings, IOCS, INCIDENT_START, norm),
                 scores=continuous_scores(norm, IOCS), metrics=efficiency(norm, findings),
                 iocs=IOCS)


def _empty_state():
    return State(live=False, source="empty", graph=Graph(), iocs=IOCSet(set(), set(), set(), set()),
                 inv={"subagents": {"scoping": {"victims": [], "realtime": [], "historical": []}},
                      "prediction": {"predicted_next_targets": [], "rationale": ""}})


def build_state(connection=None, *, window_days: int = 30, demo: bool = True) -> State:
    """Build State. With a connection → LIVE. Else synthetic demo (if available and demo=True),
    else a valid empty State so the dashboard always loads."""
    if connection is not None:
        return _live_state(connection, window_days)
    if demo:
        syn = _synthetic_state()
        if syn is not None:
            return syn
    return _empty_state()


def selftest():
    # empty path always works (no demo deps required)
    e = build_state(demo=False)
    assert e.source == "empty" and e.graph is not None and e.iocs is not None

    # synthetic path when demo data present
    s = build_state(None)
    assert s.source in ("synthetic", "empty")

    # live path builds a real graph from events with NO demo dependency
    class _Fake:
        def search(self, **kw):
            return {"ok": True, "body": {"events": [
                {"@timestamp": "2026-06-16T14:00:00Z", "vendor": "okta", "severity": "high",
                 "user_name": "jsmith@acme.com", "account": "okta:jsmith@acme.com",
                 "source_address": "91.219.236.12"},
                {"@timestamp": "2026-06-16T14:01:00Z", "vendor": "edr", "severity": "critical",
                 "host": "ACME-LT-4471", "user_name": "jsmith@acme.com",
                 "file.hash.sha256": "abc123"}]}}
        def list_insights(self, page_size=50, **kw):
            return {"ok": True, "body": {"insights": [{"id": "i1", "title": "ATO", "severity": "high"}]}}
        def list_rules(self):
            return {"ok": True, "body": {"rules": [{"id": "r1"}]}}
        def mitre(self):
            return {"ok": True, "body": {"tactics": [{"name": "Initial Access", "total": 10, "enabled": 8}]}}
        def list_views(self):
            return {"ok": True, "body": {"views": [{"id": "v1"}]}}
        def list_fieldsets(self):
            return {"ok": True, "body": {"fieldsets": [{"id": "f1"}]}}
        def raw_search(self, *a, **k):
            return {"ok": True, "body": {}}

    lv = build_state(_Fake())
    assert lv.live and lv.source == "live"
    assert len(lv.graph.nodes) > 0
    # 2 search events + ≥1 insight-derived event (real entities pulled from live insights)
    assert len(lv.norm) >= 3 and len(lv.scores) > 0 and len(lv.findings) > 0
    assert lv.mitre and lv.mitre[0]["total"] == 10
    return {"ok": True, "synthetic": s.source, "live_nodes": len(lv.graph.nodes),
            "live_findings": len(lv.findings), "live_scores": len(lv.scores)}


if __name__ == "__main__":
    print(selftest())
