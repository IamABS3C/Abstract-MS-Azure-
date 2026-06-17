"""
Mini shift-left pipeline — a runnable, dependency-free model of the design in
../README.md. It normalizes mixed-source events to a common shape, builds an
entity graph (user / host / account / NHI / agent / IOC), runs in-stream
detections, replays history, scores risk, and orchestrates sub-agents.

This is a SIMULATION for demonstration. The seams marked "# ← in Abstract"
show where the real platform (parsers, AIG, LakeVilla replay, MCP agents)
takes over. See demo/README.md for the simulated-vs-real boundary.

Python 3.9+, stdlib only.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Entity keys
# ─────────────────────────────────────────────────────────────────────────────
def ek(etype: str, ident: str) -> str:
    return f"{etype}:{ident}"


ENTITY_TYPES = ("identity", "host", "account", "nhi", "agent",
                "ip", "domain", "url", "hash", "process")
# "principal" entity types we care about as victims/actors (non-IOC):
PRINCIPAL_TYPES = ("identity", "host", "account", "nhi", "agent")
IOC_TYPES = ("ip", "domain", "url", "hash")


# ─────────────────────────────────────────────────────────────────────────────
# Normalized event
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Norm:
    idx: int
    ts: datetime
    source: str
    ocsf: str
    severity: str
    entities: List[Tuple[str, str, dict]]          # (type, id, attrs)
    edges: List[Tuple[str, str, str]]              # (rel, src_key, dst_key)
    verdict: str = ""
    malicious_control: str = ""                    # which control family convicted
    raw: dict = field(default_factory=dict)

    def entity_keys(self) -> Set[str]:
        return {ek(t, i) for (t, i, _) in self.entities}


def normalize(idx: int, raw: dict) -> Norm:
    """source-specific extraction → common shape (# ← in Abstract: parsers + OCSF)."""
    t = raw["_t"]
    ts = raw["ts"]
    ents: List[Tuple[str, str, dict]] = []
    edges: List[Tuple[str, str, str]] = []
    verdict = ""
    convicted = ""
    sev = raw.get("sev", "informational")
    ocsf = "Network Activity"

    def host(h): ents.append(("host", h, {}));    return ek("host", h)
    def idn(i): ents.append(("identity", i, {})); return ek("identity", i)
    def acct(a): ents.append(("account", a, {})); return ek("account", a)
    def ip(i, attrs=None): ents.append(("ip", i, attrs or {})); return ek("ip", i)
    def dom(d): ents.append(("domain", d, {}));   return ek("domain", d)
    def url(u): ents.append(("url", u, {}));       return ek("url", u)
    def fhash(h): ents.append(("hash", h, {}));    return ek("hash", h)
    def proc(p): ents.append(("process", p, {}));  return ek("process", p)
    def nhi(n): ents.append(("nhi", n, {}));        return ek("nhi", n)
    def agent(a): ents.append(("agent", a, {}));    return ek("agent", a)

    if t == "email":
        ocsf = "Email Activity"
        a = acct(raw["to"]); h = fhash(raw["sha256"]); u = url(raw["url"])
        edges += [("delivered", a, h), ("lure_url", h, u)]
        verdict = raw.get("verdict", "")

    elif t == "pan_wildfire":
        ocsf = "Detection Finding"; sev = "critical"
        hh = host(raw["host"]); ii = idn(raw["user"]); dip = ip(raw["dst"])
        u = url(raw["url"]); h = fhash(raw["sha256"])
        edges += [("on_host", ii, hh), ("downloaded", hh, h),
                  ("connected_to", hh, dip), ("contacted", hh, u)]
        verdict = "malware"; convicted = "NGFW/WildFire"

    elif t == "edr":
        ocsf = "Detection Finding"; sev = "high"
        hh = host(raw["host"]); ii = idn(raw["user"])
        h = fhash(raw["sha256"]); p = proc(raw["proc"])
        edges += [("on_host", ii, hh), ("executed", hh, p), ("has", hh, h)]
        verdict = "malware"; convicted = "EDR"

    elif t == "dns":
        ocsf = "DNS Activity"
        hh = host(raw["host"]); d = dom(raw["query"])
        edges.append(("resolved", hh, d))
        if raw.get("resp"):
            rip = ip(raw["resp"]); edges.append(("resolved_to", d, rip))
        sev = raw.get("sev", "informational")

    elif t == "pan_traffic":
        hh = host(raw["host"]); dip = ip(raw["dst"])
        edges.append(("connected_to", hh, dip))

    elif t in ("okta", "entra"):
        ocsf = "Authentication"; sev = raw.get("sev", "informational")
        a = acct(raw["account"]); ii = idn(raw["user"]); sip = ip(raw["src_ip"])
        edges += [("authenticated_as", a, ii), ("auth_from", a, sip)]

    elif t == "cloudtrail":
        ocsf = "API Activity"; sev = raw.get("sev", "informational")
        a = acct(raw["account"]); sip = ip(raw["src_ip"])
        edges.append(("action_from", a, sip))

    elif t == "nhi":
        ocsf = "API Activity"; sev = raw.get("sev", "informational")
        n = nhi(raw["nhi"]); sip = ip(raw["src_ip"])
        edges.append(("auth_from", n, sip))

    elif t == "agent":
        ocsf = "Application Activity"; sev = raw.get("sev", "informational")
        ag = agent(raw["agent"]); sip = ip(raw["src_ip"])
        edges.append(("auth_from", ag, sip))
        if raw.get("dst"):
            edges.append(("connected_to", ag, ip(raw["dst"])))

    elif t == "benign_traffic":
        hh = host(raw["host"]); dip = ip(raw["dst"])
        edges.append(("connected_to", hh, dip))
    elif t == "benign_dns":
        hh = host(raw["host"]); d = dom(raw["query"])
        edges.append(("resolved", hh, d))
    elif t == "benign_auth":
        ocsf = "Authentication"
        a = acct(raw["account"]); sip = ip(raw["src_ip"])
        edges.append(("auth_from", a, sip))

    return Norm(idx, ts, t, ocsf, sev, ents, edges, verdict, convicted, raw)


# ─────────────────────────────────────────────────────────────────────────────
# Entity graph
# ─────────────────────────────────────────────────────────────────────────────
class Graph:
    def __init__(self):
        self.nodes: Dict[str, dict] = {}
        self.adj: Dict[str, Set[str]] = defaultdict(set)   # undirected for traversal
        self.first_seen: Dict[str, datetime] = {}

    def add(self, ev: Norm):
        for (etype, ident, attrs) in ev.entities:
            k = ek(etype, ident)
            n = self.nodes.setdefault(k, {"type": etype, "id": ident, "attrs": {}})
            n["attrs"].update(attrs)
            if k not in self.first_seen or ev.ts < self.first_seen[k]:
                self.first_seen[k] = ev.ts
        for (_rel, a, b) in ev.edges:
            self.adj[a].add(b); self.adj[b].add(a)

    def reachable_principals(self, seeds: Set[str]) -> Set[str]:
        """BFS from IOC seeds → connected principal entities (blast radius)."""
        seen, stack, out = set(seeds), list(seeds), set()
        while stack:
            cur = stack.pop()
            for nb in self.adj.get(cur, ()):
                if nb in seen:
                    continue
                seen.add(nb); stack.append(nb)
                if self.nodes.get(nb, {}).get("type") in PRINCIPAL_TYPES:
                    out.add(nb)
        return out


# ─────────────────────────────────────────────────────────────────────────────
# IOC set (the WildFire report → live matchlist  # ← in Abstract: AIG)
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class IOCSet:
    domains: Set[str]
    ips: Set[str]
    urls: Set[str]
    hashes: Set[str]

    def keys(self) -> Set[str]:
        return ({ek("domain", d) for d in self.domains}
                | {ek("ip", i) for i in self.ips}
                | {ek("url", u) for u in self.urls}
                | {ek("hash", h) for h in self.hashes})

    def hit(self, key: str) -> bool:
        return key in self.keys()


# ─────────────────────────────────────────────────────────────────────────────
# Findings + detections
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    rule: str
    title: str
    ts: datetime
    severity: str
    risk: int
    entities: Set[str]
    detail: str
    evidence_idx: List[int] = field(default_factory=list)


def detect_verdict_fusion(events: List[Norm]) -> List[Finding]:
    """≥2 independent control families convict the same host+hash → fused finding."""
    by_host: Dict[str, dict] = defaultdict(lambda: {"controls": set(), "idx": [],
                                                     "ts": None, "hash": "", "id": ""})
    for ev in events:
        if ev.malicious_control:
            hk = next((ek(t, i) for (t, i, _) in ev.entities if t == "host"), None)
            hh = next((i for (t, i, _) in ev.entities if t == "hash"), "")
            ii = next((i for (t, i, _) in ev.entities if t == "identity"), "")
            if not hk:
                continue
            r = by_host[hk]
            r["controls"].add(ev.malicious_control); r["idx"].append(ev.idx)
            r["hash"] = hh or r["hash"]; r["id"] = ii or r["id"]
            r["ts"] = ev.ts if r["ts"] is None else max(r["ts"], ev.ts)
    out = []
    for hk, r in by_host.items():
        controls = r["controls"] | ({"TI"} if r["hash"] else set())  # ← AIG/VT corroboration
        if len(controls) >= 2:
            risk = min(99, 70 + 10 * len(controls))
            out.append(Finding(
                "verdict-fusion",
                f"Malware confirmed by {len(controls)} independent controls on {hk}",
                r["ts"], "critical", risk,
                {hk, ek("identity", r["id"]), ek("hash", r["hash"])},
                f"controls agree: {', '.join(sorted(controls))}; user={r['id']}",
                r["idx"]))
    return out


def detect_ioc_blast(events: List[Norm], iocs: IOCSet) -> List[Finding]:
    """Any principal entity touching a WildFire IOC → match (continuous, pre-landing)."""
    hits: Dict[str, dict] = defaultdict(lambda: {"iocs": set(), "ts": None, "idx": []})
    for ev in events:
        matched = [k for k in ev.entity_keys() if iocs.hit(k)]
        if not matched:
            continue
        principals = [ek(t, i) for (t, i, _) in ev.entities if t in PRINCIPAL_TYPES]
        for p in principals:
            h = hits[p]
            h["iocs"].update(matched); h["idx"].append(ev.idx)
            h["ts"] = ev.ts if h["ts"] is None else min(h["ts"], ev.ts)
    out = []
    for p, h in hits.items():
        risk = min(95, 55 + 8 * len(h["iocs"]))
        out.append(Finding(
            "ioc-blast-match",
            f"{p} contacted {len(h['iocs'])} known-bad IOC(s)",
            h["ts"], "high", risk, {p} | h["iocs"],
            "matched: " + ", ".join(sorted(x.split(':', 1)[1] for x in h["iocs"])),
            h["idx"]))
    return out


def detect_ato_c2_shared_ip(events: List[Norm], iocs: IOCSet) -> List[Finding]:
    """An IP that is BOTH a C2 host and an auth source → account-compromise bridge."""
    auth_ip_to_principals: Dict[str, Set[str]] = defaultdict(set)
    idx_by_ip: Dict[str, List[int]] = defaultdict(list)
    ts_by_ip: Dict[str, datetime] = {}
    for ev in events:
        if ev.source in ("okta", "entra", "cloudtrail", "nhi", "agent", "benign_auth"):
            for (rel, a, b) in ev.edges:
                if rel in ("auth_from", "action_from") and b.startswith("ip:"):
                    src_principal = a
                    auth_ip_to_principals[b].add(src_principal)
                    idx_by_ip[b].append(ev.idx)
                    ts_by_ip[b] = ev.ts if b not in ts_by_ip else max(ts_by_ip[b], ev.ts)
    out = []
    for ipk, principals in auth_ip_to_principals.items():
        if iocs.hit(ipk):                                   # the intersection IS the detection
            out.append(Finding(
                "ato-c2-bridge",
                f"Auth from C2 infrastructure {ipk.split(':',1)[1]} — likely account takeover",
                ts_by_ip[ipk], "critical", 96,
                {ipk} | principals,
                "principals authenticating from a known C2 IP: "
                + ", ".join(sorted(principals)),
                idx_by_ip[ipk]))
    return out


def detect_beaconing(events: List[Norm]) -> List[Finding]:
    """Regular small sessions host→ip → C2 beacon (low interval jitter)."""
    series: Dict[Tuple[str, str], List[Tuple[datetime, int, int]]] = defaultdict(list)
    for ev in events:
        if ev.source in ("pan_traffic",):
            hh = next((i for (t, i, _) in ev.entities if t == "host"), None)
            dip = next((i for (t, i, _) in ev.entities if t == "ip"), None)
            if hh and dip:
                series[(hh, dip)].append((ev.ts, ev.raw.get("bytes", 0), ev.idx))
    out = []
    for (hh, dip), pts in series.items():
        if len(pts) < 4:
            continue
        pts.sort()
        gaps = [(pts[i + 1][0] - pts[i][0]).total_seconds() for i in range(len(pts) - 1)]
        mean = statistics.mean(gaps)
        jitter = (statistics.pstdev(gaps) / mean) if mean else 1.0
        avg_bytes = statistics.mean(b for _, b, _ in pts)
        if jitter < 0.25 and avg_bytes < 8192:              # periodic + low volume
            out.append(Finding(
                "beaconing",
                f"Beaconing {hh} → {dip} ({len(pts)} sessions, ~{int(mean)}s interval)",
                pts[-1][0], "high", 82,
                {ek("host", hh), ek("ip", dip)},
                f"jitter={jitter:.2f}, avg_bytes={int(avg_bytes)}",
                [i for _, _, i in pts]))
    return out


def run_detections(events: List[Norm], iocs: IOCSet) -> List[Finding]:
    f = []
    f += detect_verdict_fusion(events)
    f += detect_ioc_blast(events, iocs)
    f += detect_ato_c2_shared_ip(events, iocs)
    f += detect_beaconing(events)
    f.sort(key=lambda x: x.risk, reverse=True)
    return f


# ─────────────────────────────────────────────────────────────────────────────
# Efficiency + latency model (assumptions, clearly labeled)
# ─────────────────────────────────────────────────────────────────────────────
SIEM_INGEST_LAG_MIN = 5      # time for raw logs to land + index
SIEM_RULE_CADENCE_MIN = 15   # scheduled correlation-rule interval (avg)
SIEM_TOTAL_DELAY_MIN = SIEM_INGEST_LAG_MIN + SIEM_RULE_CADENCE_MIN


def cluster_incidents(findings: List[Finding]) -> List[Set[str]]:
    """Group findings that share any entity into incidents (connected components)."""
    parent: Dict[int, int] = {i: i for i in range(len(findings))}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            if findings[i].entities & findings[j].entities:
                union(i, j)
    groups: Dict[int, Set[str]] = defaultdict(set)
    for i, f in enumerate(findings):
        groups[find(i)].add(f.rule + ":" + f.title)
    return list(groups.values())


def efficiency(events: List[Norm], findings: List[Finding]):
    total = len(events)
    finding_entities: Set[str] = set()
    forwarded_idx: Set[int] = set()
    for fnd in findings:
        finding_entities |= fnd.entities
        forwarded_idx.update(fnd.evidence_idx)
    # supporting context: any event touching a finding entity goes to SIEM too
    for ev in events:
        if ev.entity_keys() & finding_entities:
            forwarded_idx.add(ev.idx)
    forwarded = len(forwarded_idx)
    # SIEM surfaces one alert per alertable event; Abstract fuses into incidents.
    raw_alerts = sum(1 for ev in events
                     if ev.severity in ("high", "critical") or ev.malicious_control)
    incidents = len(cluster_incidents(findings))
    return {
        "total_events": total,
        "forwarded_to_siem": forwarded,
        "to_lakevilla_only": total - forwarded,
        "reduction_pct": round(100 * (1 - forwarded / total), 1) if total else 0,
        "raw_alerts": raw_alerts,
        "fused_findings": len(findings),
        "incidents": incidents,
        "fatigue_reduction_pct": round(100 * (1 - incidents / raw_alerts), 1) if raw_alerts else 0,
        "mttd_stream_sec": 0.5,
        "mttd_siem_sec": SIEM_TOTAL_DELAY_MIN * 60,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Sub-agent orchestration (# ← in Abstract: LLM agents over MCP)
# Deterministic stand-ins; each seam notes where a model call goes in production.
# ─────────────────────────────────────────────────────────────────────────────
def triage_agent(findings: List[Finding]) -> dict:
    # ← LLM via Abstract MCP: read the correlated finding set + entity context, decide dispatch
    rules = {f.rule for f in findings}
    dispatch = ["scoping"]
    if "ato-c2-bridge" in rules:
        dispatch.append("identity")
    if rules & {"verdict-fusion", "ioc-blast-match"}:
        dispatch.append("enrichment")
    return {"verdict": "true-positive (high confidence)", "dispatch": dispatch,
            "reason": findings[0].detail}


def _ioc_contact_times(events: List[Norm], iocs: IOCSet) -> Dict[str, List[datetime]]:
    """Per principal, the timestamps at which it touched a known IOC."""
    times: Dict[str, List[datetime]] = defaultdict(list)
    for ev in events:
        if any(iocs.hit(k) for k in ev.entity_keys()):
            for (t, i, _) in ev.entities:
                if t in PRINCIPAL_TYPES:
                    times[ek(t, i)].append(ev.ts)
    return times


def scoping_subagent(graph: Graph, iocs: IOCSet, incident_start: datetime,
                     events: List[Norm]) -> dict:
    # ← sub-agent: graph traversal (real-time) + LakeVilla replay (historical retro-hunt)
    victims = graph.reachable_principals(iocs.keys())
    contact = _ioc_contact_times(events, iocs)
    realtime, historical = [], []
    for v in victims:
        ts = contact.get(v)
        # historical (replay win) = touched IOCs ONLY before we had the verdict
        if ts and max(ts) < incident_start:
            historical.append(v)
        else:
            realtime.append(v)
    by_type = defaultdict(list)
    for v in victims:
        by_type[graph.nodes[v]["type"]].append(v.split(":", 1)[1])
    return {"victims": sorted(victims), "realtime": sorted(realtime),
            "historical": sorted(historical), "by_type": dict(by_type)}


def enrichment_subagent(iocs: IOCSet) -> dict:
    # ← loop-closer sub-agent: pull WildFire /get/report, push IOCs to AIG, trigger replay
    return {"action": "WildFire report IOCs published to AIG live matchlist",
            "iocs_published": len(iocs.keys()),
            "effect": "every future + historical event now matched against these"}


def identity_subagent(findings: List[Finding]) -> dict:
    # ← identity sub-agent: assess ATO + non-human exposure
    ato = [f for f in findings if f.rule == "ato-c2-bridge"]
    compromised = set()
    for f in ato:
        compromised |= {e for e in f.entities
                        if e.split(":", 1)[0] in ("account", "identity", "nhi", "agent")}
    return {"compromised_principals": sorted(compromised),
            "recommended_actions": ["disable sessions / force re-auth",
                                     "rotate NHI/service tokens",
                                     "review agent tool grants"] if compromised else []}


def predictive_layer(graph: Graph, findings: List[Finding], iocs: IOCSet) -> dict:
    """Hosts that touched C2 but are NOT yet convicted → predicted next victims."""
    convicted_hosts = {e for f in findings if f.rule == "verdict-fusion"
                       for e in f.entities if e.startswith("host:")}
    c2_touchers = set()
    for f in findings:
        if f.rule in ("ioc-blast-match", "beaconing"):
            c2_touchers |= {e for e in f.entities if e.startswith("host:")}
    predicted = sorted(c2_touchers - convicted_hosts)
    return {"convicted": sorted(convicted_hosts),
            "predicted_next_targets": predicted,
            "rationale": "contacted known C2 infrastructure with no local conviction yet — "
                         "intervene before payload/execution"}


def run_investigation(graph: Graph, findings: List[Finding], iocs: IOCSet,
                      incident_start: datetime, events: List[Norm]) -> dict:
    lead = findings[0]
    plan = triage_agent(findings)
    report = {"lead_finding": lead, "triage": plan, "subagents": {}}
    if "scoping" in plan["dispatch"]:
        report["subagents"]["scoping"] = scoping_subagent(graph, iocs, incident_start, events)
    if "enrichment" in plan["dispatch"]:
        report["subagents"]["enrichment"] = enrichment_subagent(iocs)
    if "identity" in plan["dispatch"]:
        report["subagents"]["identity"] = identity_subagent(findings)
    report["prediction"] = predictive_layer(graph, findings, iocs)
    return report


# ─────────────────────────────────────────────────────────────────────────────
# Continuous scoring — entity risk that accrues, decays, and forecasts over time
# (# ← in Abstract: a stateful scoring model updated per-event, written back as
#  an entity insight/score; this is a transparent EWMA stand-in for any model.)
# ─────────────────────────────────────────────────────────────────────────────
# weight each observable contributes to an entity's running risk
SIGNAL_WEIGHTS = {
    "ioc_contact": 30, "malware_verdict": 45, "beacon": 25,
    "risky_auth": 20, "ato_bridge": 50, "nrd_dns": 8,
}


def continuous_scores(events: List[Norm], iocs: IOCSet, half_life_min: float = 720.0):
    """
    Replay events in time order, maintaining a decaying risk score per principal.
    Returns per-entity trajectory + final score + a simple forecast (slope).
    """
    import math
    decay_per_min = math.log(2) / half_life_min
    score: Dict[str, float] = defaultdict(float)
    last_ts: Dict[str, datetime] = {}
    trajectory: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)

    def bump(key, weight, ts):
        if key in last_ts:
            dt_min = (ts - last_ts[key]).total_seconds() / 60.0
            score[key] *= math.exp(-decay_per_min * max(dt_min, 0))
        score[key] = min(100.0, score[key] + weight)
        last_ts[key] = ts
        trajectory[key].append((ts, round(score[key], 1)))

    for ev in events:
        principals = [ek(t, i) for (t, i, _) in ev.entities if t in PRINCIPAL_TYPES]
        touches_ioc = any(iocs.hit(k) for k in ev.entity_keys())
        for p in principals:
            if touches_ioc:
                bump(p, SIGNAL_WEIGHTS["ioc_contact"], ev.ts)
            if ev.malicious_control:
                bump(p, SIGNAL_WEIGHTS["malware_verdict"], ev.ts)
            if ev.source in ("okta", "entra") and ev.severity in ("high", "critical"):
                bump(p, SIGNAL_WEIGHTS["risky_auth"], ev.ts)
            if ev.source == "dns" and ev.severity in ("high", "critical"):
                bump(p, SIGNAL_WEIGHTS["nrd_dns"], ev.ts)

    out = {}
    for k, traj in trajectory.items():
        final = traj[-1][1]
        # crude forecast: score change over the last two observations → trend
        slope = (traj[-1][1] - traj[-2][1]) if len(traj) > 1 else traj[-1][1]
        out[k] = {"final": final, "trend": round(slope, 1), "points": len(traj),
                  "trajectory": traj}
    return dict(sorted(out.items(), key=lambda kv: kv[1]["final"], reverse=True))


# ─────────────────────────────────────────────────────────────────────────────
# Write-back — turn a finding into an Abstract-style finding/insight payload
# (# ← in Abstract: POST to the findings/insights API or emit via MCP, so the
#  notebook's calculated/predictive output becomes a first-class platform object
#  that lands in Views and routes to destinations like everything else.)
# ─────────────────────────────────────────────────────────────────────────────
def finding_to_abstract(f: Finding, scores: Optional[dict] = None,
                        incident: Optional[str] = None) -> dict:
    principals = {p.split(":", 1)[0]: [] for p in f.entities}
    for p in f.entities:
        t, i = p.split(":", 1)
        principals.setdefault(t, []).append(i)
    payload = {
        "class_name": "Detection Finding",
        "time": f.ts.isoformat() + "Z",
        "severity": f.severity,
        "finding_info": {"title": f.title, "rule": f.rule, "types": ["Malware", "C2", "ATO"]},
        "risk_score": f.risk,
        "entities": principals,
        "detail": f.detail,
        "abstract": {"origin": "jupyter-notebook", "campaign": incident or "auto-cluster",
                     "writeback": "findings+insights+views"},
    }
    if scores:
        payload["entity_scores"] = {k: scores[k]["final"]
                                    for k in f.entities if k in scores}
    return payload
