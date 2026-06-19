"""Identity Intelligence — re-exposure (incl. survival across IDP / immutable-backup
restore), session hijacking, MFA bombing, password reuse, persistent bad hygiene,
VIP-at-risk, and predictive / situational awareness. Operates over live_data.State.

Entity keys match the engine's graph keys exactly ("account:okta:jsmith@acme.com",
"nhi:svc-ci-pipeline", "agent:agent-soc-autobot", "identity:jsmith@acme.com") so the
fused scores line up with continuous_scores().

In Abstract (real): these signals come from the identity models + insights over the live
estate. Here they are modeled deterministically over the synthetic/normalized stream so
you can see the shape; the live path uses State.insights/detections where available."""
from __future__ import annotations
from dataclasses import dataclass, field
from collections import Counter


@dataclass
class ReExposure:
    entity: str
    count: int
    events: list = field(default_factory=list)
    survives_restore: bool = False
    first: object = None
    last: object = None


@dataclass
class Signal:
    entity: str
    kind: str
    detail: str
    score: int


_AUTH_SOURCES = ("okta", "entra", "cloudtrail", "nhi", "agent")


def _acct_key(ev) -> str | None:
    """Principal entity key for an event, matching the engine's graph keys."""
    raw = ev.raw
    if raw.get("account"):
        return f"account:{raw['account']}"
    if raw.get("nhi"):
        return f"nhi:{raw['nhi']}"
    if raw.get("agent"):
        return f"agent:{raw['agent']}"
    if raw.get("user"):
        return f"identity:{raw['user']}"
    return None


def _exposed(ev) -> bool:
    return bool(ev.malicious_control) or ev.severity in ("high", "critical") \
        or ev.raw.get("pwned") or ev.raw.get("password_reused") \
        or ev.raw.get("exposed") or ev.raw.get("infostealer") \
        or ev.source in _AUTH_SOURCES


def re_exposure(state) -> list:
    """Group exposure-bearing events per principal. `survives_restore` is True when an
    IDP/backup-restore marker exists AND an exposure recurs *after* that restore — i.e.
    the entity keeps getting re-exposed because the underlying credential/pattern is
    still leaked, not because tenant state wasn't cleaned."""
    by_ent: dict[str, list] = {}
    for ev in state.norm:
        key = _acct_key(ev)
        if not key:
            continue
        exposed = _exposed(ev)
        restore = bool(ev.raw.get("idp_restore") or ev.raw.get("backup_restore"))
        if exposed or restore:
            by_ent.setdefault(key, []).append((ev, exposed, restore))
    out = []
    for ent, items in by_ent.items():
        items = sorted(items, key=lambda it: it[0].ts)
        exposures = [it[0] for it in items if it[1]]
        restore_ts = [it[0].ts for it in items if it[2]]
        survives = bool(restore_ts) and any(e.ts > min(restore_ts) for e in exposures)
        if not exposures:
            continue
        out.append(ReExposure(entity=ent, count=len(exposures), events=exposures,
                              survives_restore=survives,
                              first=exposures[0].ts, last=exposures[-1].ts))
    return sorted(out, key=lambda r: -r.count)


def session_hijacking(state) -> list:
    """Same account authenticating from a new IP, gated so benign IP churn doesn't fire:
    only when the new IP is a known-bad/IOC IP or the auth event is high/critical
    (impossible-travel / token-reuse stand-in)."""
    ioc_ips = set(getattr(state.iocs, "ips", set()) or set())
    sig, seen = [], {}
    for ev in sorted(state.norm, key=lambda e: e.ts):
        acct, ipv = ev.raw.get("account"), ev.raw.get("src_ip")
        if not (acct and ipv):
            continue
        prev = seen.get(acct)
        suspicious = ipv in ioc_ips or ev.severity in ("high", "critical")
        if prev and prev != ipv and suspicious:
            tag = " [known-bad IP]" if ipv in ioc_ips else ""
            sig.append(Signal(f"account:{acct}", "session_hijacking",
                              f"auth from new IP {ipv} (was {prev}){tag}", 75))
        seen[acct] = ipv
    return sig


def mfa_bombing(state) -> list:
    c = Counter()
    for ev in state.norm:
        if ev.raw.get("mfa_prompt") or ev.raw.get("event") == "mfa_challenge":
            acct = ev.raw.get("account")
            if acct:
                c[acct] += 1
    return [Signal(f"account:{a}", "mfa_bombing", f"{n} MFA prompts in burst", min(90, 30 + n * 10))
            for a, n in c.items() if n >= 3]


def password_reuse(state) -> list:
    out = []
    for ev in state.norm:
        if ev.raw.get("pwned") or ev.raw.get("password_reused"):
            key = _acct_key(ev)
            if key:
                out.append(Signal(key, "password_reuse",
                                  "credential seen in breach/infostealer corpus", 60))
    return out


def persistent_bad_hygiene(state) -> list:
    return [Signal(r.entity, "persistent_bad_hygiene",
                   f"{r.count} exposures; survives restore={r.survives_restore}",
                   min(95, 50 + r.count * 5))
            for r in re_exposure(state) if r.count >= 2]


def vip_at_risk(state, vips=None) -> list:
    vips = vips or set()
    out = []
    for k, s in state.scores.items():
        if any(v in k for v in vips) and s.get("final", 0) >= 50:
            out.append(Signal(k, "vip_at_risk", f"VIP elevated risk {s['final']}", s["final"]))
    return out


def predictive(state) -> dict:
    pred = (state.inv or {}).get("prediction", {}) or {}
    return {"predicted_next_targets": pred.get("predicted_next_targets", []),
            "rationale": pred.get("rationale", ""),
            "situational": {"principals": sum(1 for k in (state.scores or {})),
                            "high_risk": sum(1 for s in state.scores.values() if s.get("final", 0) >= 80)}}


def score(state) -> dict:
    """Fuse identity signals into the continuous scores (take the max bump per entity, capped 100)."""
    bumps: dict[str, int] = {}
    for fn in (session_hijacking, mfa_bombing, password_reuse, persistent_bad_hygiene):
        for sig in fn(state):
            bumps[sig.entity] = max(bumps.get(sig.entity, 0), sig.score)
    fused = dict(state.scores)
    for ent, bump in bumps.items():
        cur = fused.get(ent, {"final": 0})
        fused[ent] = {**cur, "final": min(100, max(cur.get("final", 0), bump))}
    return fused


def summary(state, vips=None) -> dict:
    return {"re_exposure": re_exposure(state),
            "session_hijacking": session_hijacking(state),
            "mfa_bombing": mfa_bombing(state),
            "password_reuse": password_reuse(state),
            "persistent_bad_hygiene": persistent_bad_hygiene(state),
            "vip_at_risk": vip_at_risk(state, vips),
            "predictive": predictive(state)}


def selftest():
    from live_data import build_state
    st = build_state(None)
    summ = summary(st, vips={"jsmith@acme.com"})
    for k in ("re_exposure", "session_hijacking", "mfa_bombing", "password_reuse",
              "persistent_bad_hygiene", "vip_at_risk"):
        assert isinstance(summ[k], list)
    fused = score(st)
    assert isinstance(fused, dict)
    return {"ok": True, "re_exposed": len(summ["re_exposure"]),
            "hijack": len(summ["session_hijacking"]), "mfa": len(summ["mfa_bombing"]),
            "reuse": len(summ["password_reuse"]),
            "predicted": len(summ["predictive"]["predicted_next_targets"])}


if __name__ == "__main__":
    print(selftest())
