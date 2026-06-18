"""
Threat-hunting catalog — a reusable library of hunts over the normalized event
stream + entity graph + continuous scores produced by pipeline.py.

Each hunt is a small, transparent function `fn(ctx) -> list[dict rows]` registered
in HUNTS with metadata (key, title, MITRE tactic/technique, description). The
notebook renders the rows as tables; an agent can call run(key) / run_all().

Every hunt maps to something the live Abstract platform expresses as a detection
rule or saved view — these are the runnable, model-side equivalents. Dep-free.

    python3 hunts.py            # run the whole catalog against the demo estate
    python3 hunts.py auth_from_c2
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable, List

from pipeline import (ek, PRINCIPAL_TYPES, IOCSet,
                      detect_verdict_fusion, detect_ioc_blast, detect_beaconing,
                      detect_ato_c2_shared_ip)


@dataclass
class HuntContext:
    """Everything a hunt needs: the normalized events, graph, IOC set, scores."""
    norm: list
    graph: object
    iocs: IOCSet
    scores: dict


def _row(entity="", severity="", technique="", why="", **extra):
    r = {"entity": entity, "severity": severity, "technique": technique, "why": why}
    r.update(extra)
    return r


# ── hunts ────────────────────────────────────────────────────────────────────
def hunt_auth_from_c2(ctx: HuntContext) -> List[dict]:
    """Identities/accounts/NHIs authenticating from known-bad (C2) infrastructure → ATO."""
    rows = []
    for f in detect_ato_c2_shared_ip(ctx.norm, ctx.iocs):
        ip = next((e for e in f.entities if e.startswith("ip:")), "")
        for p in sorted(e for e in f.entities if e.split(":", 1)[0] in PRINCIPAL_TYPES):
            rows.append(_row(p, "critical", "T1078", f"auth from C2 {ip.split(':',1)[1]}",
                             risk=f.risk, source_ip=ip.split(":", 1)[1]))
    return rows


def hunt_ioc_contact(ctx: HuntContext) -> List[dict]:
    """Any principal that touched a known IOC (continuous, pre-landing matchlist)."""
    rows = []
    for f in detect_ioc_blast(ctx.norm, ctx.iocs):
        p = next((e for e in f.entities if e.split(":", 1)[0] in PRINCIPAL_TYPES), "")
        iocs = sorted(e.split(":", 1)[1] for e in f.entities if e.split(":", 1)[0] in ("ip", "domain", "url", "hash"))
        rows.append(_row(p, "high", "T1071", f"contacted {len(iocs)} IOC(s)",
                         risk=f.risk, iocs=", ".join(iocs)))
    return rows


def hunt_verdict_fusion(ctx: HuntContext) -> List[dict]:
    """Hosts convicted by ≥2 independent control families (NGFW/WildFire + EDR + TI)."""
    return [_row(next((e for e in f.entities if e.startswith("host:")), ""), "critical", "T1204",
                 f.detail, risk=f.risk, title=f.title)
            for f in detect_verdict_fusion(ctx.norm)]


def hunt_beaconing(ctx: HuntContext) -> List[dict]:
    """Periodic, low-volume host→IP sessions → C2 beacon (low interval jitter)."""
    return [_row(next((e for e in f.entities if e.startswith("host:")), ""), "high", "T1071.001",
                 f.detail, risk=f.risk, title=f.title)
            for f in detect_beaconing(ctx.norm)]


def hunt_high_risk_identities(ctx: HuntContext, threshold: float = 60.0) -> List[dict]:
    """Entities whose decaying continuous-risk score crossed a threshold."""
    rows = []
    for k, s in ctx.scores.items():
        if s["final"] >= threshold:
            rows.append(_row(k, "critical" if s["final"] >= 85 else "high", "—",
                             f"continuous risk {s['final']} (trend {s['trend']:+})",
                             score=s["final"], trend=s["trend"], observations=s["points"]))
    return rows


def hunt_nhi_agent_exposure(ctx: HuntContext) -> List[dict]:
    """Non-human (NHI) and AI-agent identities reaching the internet / IOCs — agentic exposure."""
    rows = []
    for ev in ctx.norm:
        for (t, i, _) in ev.entities:
            if t in ("nhi", "agent"):
                touched = sorted(e.split(":", 1)[1] for e in ev.entity_keys() if ctx.iocs.hit(e))
                ips = [x for (tt, x, _) in ev.entities if tt == "ip"]
                rows.append(_row(ek(t, i), "high" if touched else "medium", "T1078.004",
                                 ("touched IOC " + ", ".join(touched)) if touched
                                 else f"{t} egress to {', '.join(ips) or 'network'}",
                                 kind=t, ioc_hit=bool(touched)))
    return rows


def hunt_impossible_travel(ctx: HuntContext, window_min: int = 60) -> List[dict]:
    """A principal authenticating from ≥2 distinct source IPs within a short window."""
    auths = defaultdict(list)  # principal -> [(ts, ip)]
    for ev in ctx.norm:
        if ev.source in ("okta", "entra", "cloudtrail", "benign_auth", "nhi", "agent"):
            ip = next((i for (t, i, _) in ev.entities if t == "ip"), None)
            pr = next((ek(t, i) for (t, i, _) in ev.entities if t in PRINCIPAL_TYPES), None)
            if ip and pr:
                auths[pr].append((ev.ts, ip))
    rows = []
    for pr, seq in auths.items():
        seq.sort()
        for a in range(len(seq)):
            near_ips = {ip for (ts, ip) in seq if abs((ts - seq[a][0]).total_seconds()) <= window_min * 60}
            if len(near_ips) >= 2:
                rows.append(_row(pr, "high", "T1078",
                                 f"{len(near_ips)} source IPs within {window_min}m: {', '.join(sorted(near_ips))}",
                                 source_ips=", ".join(sorted(near_ips))))
                break
    return rows


def hunt_rare_destinations(ctx: HuntContext, max_clients: int = 2) -> List[dict]:
    """Destination IPs contacted by very few hosts → rare egress worth a look."""
    dst_hosts = defaultdict(set)
    for ev in ctx.norm:
        if ev.source in ("pan_traffic", "benign_traffic"):
            h = next((i for (t, i, _) in ev.entities if t == "host"), None)
            d = next((i for (t, i, _) in ev.entities if t == "ip"), None)
            if h and d:
                dst_hosts[d].add(h)
    rows = []
    for d, hosts in sorted(dst_hosts.items(), key=lambda kv: len(kv[1])):
        if len(hosts) <= max_clients:
            sev = "high" if ctx.iocs.hit(ek("ip", d)) else "low"
            rows.append(_row(ek("ip", d), sev, "T1071",
                             f"contacted by only {len(hosts)} host(s)",
                             clients=", ".join(sorted(hosts)), known_bad=ctx.iocs.hit(ek("ip", d))))
    return rows[:25]


def hunt_dns_to_ioc(ctx: HuntContext) -> List[dict]:
    """Hosts resolving a domain that is a known IOC or resolved to an IOC IP."""
    rows = []
    for ev in ctx.norm:
        if ev.source not in ("dns", "benign_dns"):
            continue
        h = next((i for (t, i, _) in ev.entities if t == "host"), "")
        dom = next((i for (t, i, _) in ev.entities if t == "domain"), "")
        bad_dom = ctx.iocs.hit(ek("domain", dom))
        resp_ip = ev.raw.get("resp", "")
        bad_ip = ctx.iocs.hit(ek("ip", resp_ip)) if resp_ip else False
        if bad_dom or bad_ip:
            rows.append(_row(ek("host", h), "high", "T1071.004",
                             f"resolved {dom}" + (f" → {resp_ip}" if resp_ip else ""),
                             domain=dom, resolved_ip=resp_ip, ioc=bad_dom or bad_ip))
    return rows


# key → (title, tactic, technique, description, fn)
HUNTS = {
    "auth_from_c2":         ("Auth from C2 infrastructure", "Initial Access / Credential Access",
                             "T1078", "Account takeover — principals authenticating from a known C2 IP.",
                             hunt_auth_from_c2),
    "ioc_contact":          ("Principal touched a known IOC", "Command and Control",
                             "T1071", "Continuous matchlist — any principal contacting a WildFire/AIG IOC.",
                             hunt_ioc_contact),
    "verdict_fusion":       ("Multi-control malware conviction", "Execution",
                             "T1204", "Hosts convicted by ≥2 independent control families.",
                             hunt_verdict_fusion),
    "beaconing":            ("C2 beaconing", "Command and Control",
                             "T1071.001", "Periodic, low-volume sessions to a single destination.",
                             hunt_beaconing),
    "high_risk_identities": ("High continuous-risk entities", "—",
                             "—", "Decaying per-entity risk score above threshold.",
                             hunt_high_risk_identities),
    "nhi_agent_exposure":   ("NHI / AI-agent exposure", "Persistence / Lateral Movement",
                             "T1078.004", "Non-human and agentic identities reaching the internet / IOCs.",
                             hunt_nhi_agent_exposure),
    "impossible_travel":    ("Impossible travel", "Credential Access",
                             "T1078", "One principal authenticating from multiple IPs in a short window.",
                             hunt_impossible_travel),
    "rare_destinations":    ("Rare egress destinations", "Command and Control",
                             "T1071", "Destination IPs contacted by very few hosts.",
                             hunt_rare_destinations),
    "dns_to_ioc":           ("DNS to known-bad", "Command and Control",
                             "T1071.004", "Hosts resolving an IOC domain or to an IOC IP.",
                             hunt_dns_to_ioc),
}


def catalog() -> List[dict]:
    return [{"key": k, "title": t, "tactic": ta, "technique": te, "description": d}
            for k, (t, ta, te, d, _fn) in HUNTS.items()]


def make_context(norm=None, graph=None, iocs=None, scores=None) -> HuntContext:
    """Build a HuntContext from the demo estate if pieces aren't supplied."""
    if norm is None:
        from pipeline import normalize, Graph, continuous_scores
        from data import events, IOCS
        norm = [normalize(i, r) for i, r in enumerate(events())]
        graph = Graph()
        for ev in norm:
            graph.add(ev)
        iocs, scores = IOCS, continuous_scores(norm, IOCS)
    return HuntContext(norm, graph, iocs, scores)


def run(key: str, ctx: HuntContext = None, **kw) -> List[dict]:
    ctx = ctx or make_context()
    return HUNTS[key][4](ctx, **kw)


def run_all(ctx: HuntContext = None) -> dict:
    ctx = ctx or make_context()
    return {k: HUNTS[k][4](ctx) for k in HUNTS}


def selftest() -> dict:
    ctx = make_context()
    res = run_all(ctx)
    return {"hunts": len(HUNTS), "total_rows": sum(len(v) for v in res.values()),
            "with_hits": [k for k, v in res.items() if v]}


if __name__ == "__main__":
    import json
    import sys
    ctx = make_context()
    if len(sys.argv) > 1:
        print(json.dumps(run(sys.argv[1], ctx), indent=2, default=str))
    else:
        for k, rows in run_all(ctx).items():
            print(f"\n## {k} — {HUNTS[k][0]}  ({len(rows)} rows)")
            for r in rows[:6]:
                print("  ", {x: y for x, y in r.items() if y not in ("", None)})
