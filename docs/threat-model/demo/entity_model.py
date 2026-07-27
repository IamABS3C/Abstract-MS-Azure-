"""Full-scale entity & identity modeling + predictive analytics + threat modeling.

Builds a weighted, explainable risk model over every principal (human / service-principal /
managed-identity / NHI / agent / host / session), ranks identity risk with contributing
factors, forecasts next targets, derives an ATT&CK kill-chain threat model from the graph,
and can evaluate + optimize itself. `to_abstract()` serializes the model for write-back via
abstract_authoring (persisted as a tagged insight/view since Abstract has no native model API).

Pure-stdlib; fuses identity_intel signals + pipeline continuous scores + the entity graph."""
from __future__ import annotations

import identity_intel as II
import identities as ID

# default explainable weights (sum to 1.0)
DEFAULT_WEIGHTS = {"base_risk": 0.30, "exposure": 0.20, "hijack": 0.15,
                   "mfa_bombing": 0.08, "reuse": 0.10, "hygiene": 0.10, "blast": 0.07}

PRINCIPAL_PREFIXES = ("account", "identity", "host", "nhi", "agent", "device", "session")


def _signal_maxes(state):
    """One pass over identity_intel → per-entity max signal scores + exposure facts."""
    hijack, mfa, reuse, hygiene = {}, {}, {}, {}
    for s in II.session_hijacking(state):
        hijack[s.entity] = max(hijack.get(s.entity, 0), s.score)
    for s in II.mfa_bombing(state):
        mfa[s.entity] = max(mfa.get(s.entity, 0), s.score)
    for s in II.password_reuse(state):
        reuse[s.entity] = max(reuse.get(s.entity, 0), s.score)
    for s in II.persistent_bad_hygiene(state):
        hygiene[s.entity] = max(hygiene.get(s.entity, 0), s.score)
    rex = {r.entity: r for r in II.re_exposure(state)}
    return hijack, mfa, reuse, hygiene, rex


def _features(entity, state, sig):
    hijack, mfa, reuse, hygiene, rex = sig
    r = rex.get(entity)
    return {
        "base_risk": state.scores.get(entity, {}).get("final", 0),
        "exposure": min(100, (r.count * 15) if r else 0),
        "hijack": hijack.get(entity, 0),
        "mfa_bombing": mfa.get(entity, 0),
        "reuse": reuse.get(entity, 0),
        "hygiene": hygiene.get(entity, 0),
        "blast": min(100, len(state.graph.adj.get(entity, ())) * 8),
    }


def _score(features, weights):
    return round(min(100, sum(weights.get(k, 0) * v for k, v in features.items())), 1)


def _attach_anomaly(rows):
    """Unsupervised anomaly score per entity (PyOD ECOD over the feature matrix) — a
    data-science complement to the weighted score. Graceful: skips if PyOD absent or n<4."""
    try:
        from pyod.models.ecod import ECOD
        import numpy as np
    except Exception:   # noqa: BLE001
        return
    if len(rows) < 4:
        return
    keys = list(DEFAULT_WEIGHTS)
    X = np.array([[r["features"].get(k, 0) for k in keys] for r in rows], dtype=float)
    try:
        clf = ECOD(contamination=0.2)
        clf.fit(X)
        s = clf.decision_scores_
        mx = float(s.max()) or 1.0
        for i, r in enumerate(rows):
            r["anomaly"] = round(100 * float(s[i]) / mx, 1)
    except Exception:   # noqa: BLE001
        pass


def build_entity_model(state, weights=None, vips=None) -> dict:
    """Return the full model: weights + per-entity feature vectors + explainable scores."""
    weights = weights or dict(DEFAULT_WEIGHTS)
    vips = set(vips or getattr(state, "vips", set()) or set())
    sig = _signal_maxes(state)
    entities = (set(state.scores) | set(sig[4])
                | {e for d in sig[:4] for e in d})
    entities = {e for e in entities if e.split(":", 1)[0] in PRINCIPAL_PREFIXES}
    rows = []
    for e in sorted(entities):
        t, ident = (e.split(":", 1) + [""])[:2]
        feats = _features(e, state, sig)
        rex = sig[4].get(e)
        rows.append({
            "entity": e,
            "kind": ID.classify_entity({"type": t, "id": ident}),
            "vip": any(v in e for v in vips),
            "features": feats,
            "model_score": _score(feats, weights),
            "survives_restore": bool(rex and rex.survives_restore),
            "top_factors": sorted(feats.items(), key=lambda kv: -kv[1])[:3],
        })
    rows.sort(key=lambda r: -r["model_score"])
    _attach_anomaly(rows)
    kinds = {}
    for r in rows:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    return {"weights": weights, "entities": rows, "kinds": kinds,
            "vip_tags": sorted(vips), "n": len(rows)}


def identity_risk(model, top=12) -> list:
    """Ranked identity risk with the factors driving each score (for the dashboard)."""
    return [{"entity": r["entity"], "kind": r["kind"], "vip": r["vip"],
             "score": r["model_score"], "survives_restore": r["survives_restore"],
             "drivers": [f"{k}={v}" for k, v in r["top_factors"] if v]}
            for r in model["entities"][:top]]


def predict(state, model=None, cves=None) -> dict:
    """Predictive analytics: model-flagged next targets + escalation forecast +
    (live, optional) EPSS exploit probability for supplied CVEs."""
    model = model or build_entity_model(state)
    inv_pred = (state.inv or {}).get("prediction", {}) or {}
    # escalation: re-exposed / signal-bearing but not yet high — likely to climb
    emerging = [r["entity"] for r in model["entities"]
                if 30 <= r["model_score"] < 80 and (r["features"]["exposure"]
                or r["features"]["hijack"] or r["features"]["reuse"])][:10]
    exploit = {}
    for cve in (cves or []):
        try:
            import enrichment as EN
            exploit[cve] = EN._epss(cve, "cve")   # live FIRST EPSS
        except Exception:   # noqa: BLE001
            exploit[cve] = {"error": "epss unavailable"}
    return {"predicted_next_targets": inv_pred.get("predicted_next_targets", []),
            "rationale": inv_pred.get("rationale", ""),
            "escalation_watch": emerging,
            "exploit_prediction": exploit,
            "situational": {"principals": model["n"],
                            "high_risk": sum(1 for r in model["entities"] if r["model_score"] >= 80),
                            "survives_restore": sum(1 for r in model["entities"] if r["survives_restore"])}}


def forecast(state, entity, horizon_days: int = 7) -> dict:
    """Linear risk-trajectory forecast for one entity. Recomputes the slope itself from the last
    two trajectory points — it never trusts state.scores[entity]['trend'] (hardcoded 0 on the
    live path). Pure stdlib; degrades to an empty projection when history is insufficient."""
    from datetime import timedelta
    sc = state.scores.get(entity) or {}
    hist = [(t, float(v)) for t, v in (sc.get("trajectory") or [])]
    if len(hist) < 2:
        return {"entity": entity, "history": hist, "projected": [],
                "slope_per_day": 0.0, "note": "insufficient history"}
    (t0, v0), (t1, v1) = hist[-2], hist[-1]
    try:                                        # datetime trajectory (normal case)
        span = max((t1 - t0).total_seconds() / 86400.0, 1e-6)
        step, base = timedelta(days=1), t1
    except Exception:                           # non-datetime ts → unit spacing
        span, step, base = 1.0, None, None
    slope = (v1 - v0) / span
    projected = []
    for i in range(1, horizon_days + 1):
        pv = round(max(0.0, min(100.0, v1 + slope * i)), 1)
        projected.append(((base + step * i) if base is not None else i, pv))
    return {"entity": entity, "history": hist, "projected": projected,
            "slope_per_day": round(slope, 3)}


def threat_model(state) -> dict:
    """ATT&CK-aligned kill-chain threat model derived from the campaign graph + findings."""
    # map observed event sources → kill-chain stages
    STAGE = {"email": "Initial Access", "pan_wildfire": "Execution", "edr": "Execution",
             "dns": "Command and Control", "pan_traffic": "Command and Control",
             "okta": "Credential Access", "entra": "Credential Access",
             "cloudtrail": "Lateral Movement / Cloud", "nhi": "Persistence",
             "agent": "Persistence"}
    stages = {}
    for ev in state.norm:
        st = STAGE.get(ev.source)
        if not st:
            continue
        node = stages.setdefault(st, {"events": 0, "entities": set(), "severity": "low"})
        node["events"] += 1
        node["entities"].update(k for k in ev.entity_keys()
                                if k.split(":", 1)[0] in PRINCIPAL_PREFIXES)
        if ev.severity in ("high", "critical"):
            node["severity"] = ev.severity
    tree = [{"stage": k, "events": v["events"], "entities": sorted(v["entities"])[:8],
             "severity": v["severity"]} for k, v in stages.items()]
    techniques = sorted({f.title for f in state.findings})[:10]
    return {"kill_chain": tree, "observed_findings": techniques,
            "lead": (state.inv or {}).get("lead_finding").title
            if (state.inv or {}).get("lead_finding") else None}


def evaluate(model) -> dict:
    """Quality of the model: coverage, separation, high-risk + VIP exposure."""
    scs = [r["model_score"] for r in model["entities"]]
    high = [r for r in model["entities"] if r["model_score"] >= 80]
    covered = [r for r in model["entities"]
               if any(v for k, v in r["features"].items() if k != "base_risk")]
    return {"entities": model["n"],
            "mean_score": round(sum(scs) / len(scs), 1) if scs else 0,
            "max_score": max(scs) if scs else 0,
            "high_risk": len(high),
            "vip_at_risk": sum(1 for r in high if r["vip"]),
            "signal_coverage_pct": round(100 * len(covered) / len(scs), 1) if scs else 0,
            "survives_restore": sum(1 for r in model["entities"] if r["survives_restore"]),
            "max_anomaly": max((r.get("anomaly", 0) for r in model["entities"]), default=0)}


def optimize(model, state) -> dict:
    """Data-driven re-weighting: shift weight toward factors that actually fired in this
    estate (so a noisy/empty factor doesn't dilute the score), renormalize, re-score."""
    activity = {k: 0.0 for k in DEFAULT_WEIGHTS}
    for r in model["entities"]:
        for k, v in r["features"].items():
            if k in activity and v:
                activity[k] += 1
    total = sum(activity.values()) or 1.0
    # blend prior (DEFAULT) with observed activity so unseen factors keep a floor
    new = {k: round(0.5 * DEFAULT_WEIGHTS[k] + 0.5 * (activity[k] / total), 4) for k in DEFAULT_WEIGHTS}
    s = sum(new.values()) or 1.0
    new = {k: round(v / s, 4) for k, v in new.items()}
    return build_entity_model(state, weights=new, vips=set(model["vip_tags"]))


def to_abstract(model, name="[ABS-DEMO] Identity risk model") -> dict:
    """Serialize for write-back (abstract_authoring persists this as a tagged insight)."""
    return {"name": name, "kind": "identity-risk-model",
            "entity_kinds": sorted(model["kinds"]),
            "risk_weights": model["weights"],
            "vip_tags": model["vip_tags"],
            "top_risks": [{"entity": r["entity"], "score": r["model_score"],
                           "kind": r["kind"], "survives_restore": r["survives_restore"]}
                          for r in model["entities"][:15]]}


def selftest():
    from live_data import build_state
    st = build_state(None)
    st.vips = {"jsmith@acme.com"}
    m = build_entity_model(st)
    assert m["n"] > 0 and m["entities"][0]["model_score"] >= m["entities"][-1]["model_score"]
    assert identity_risk(m) and "drivers" in identity_risk(m)[0]
    p = predict(st, m)
    assert "escalation_watch" in p and "situational" in p
    tm = threat_model(st)
    assert tm["kill_chain"] and "stage" in tm["kill_chain"][0]
    ev = evaluate(m)
    assert ev["entities"] == m["n"] and 0 <= ev["signal_coverage_pct"] <= 100
    fc = forecast(st, m["entities"][0]["entity"])
    assert "projected" in fc and "slope_per_day" in fc
    opt = optimize(m, st)
    assert abs(sum(opt["weights"].values()) - 1.0) < 0.01
    ab = to_abstract(m)
    assert ab["risk_weights"] and ab["top_risks"]
    return {"ok": True, "entities": m["n"], "kinds": m["kinds"],
            "top": m["entities"][0]["entity"], "top_score": m["entities"][0]["model_score"],
            "kill_chain_stages": len(tm["kill_chain"])}


if __name__ == "__main__":
    print(selftest())
