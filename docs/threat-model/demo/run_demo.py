"""
Narrated end-to-end run of the shift-left model over the synthetic estate.
Run:  python3 run_demo.py
Verifies the engine the notebook reuses. Numbers below are produced live.
"""
from __future__ import annotations

from pipeline import (normalize, Graph, run_detections, efficiency,
                      run_investigation, continuous_scores)
from data import events, IOCS, INCIDENT_START


def hr(t): return "─" * 78 + "\n" + t + "\n" + "─" * 78


def main():
    raw = events()
    norm = [normalize(i, r) for i, r in enumerate(raw)]
    g = Graph()
    for ev in norm:
        g.add(ev)

    print(hr("1. INGEST"))
    print(f"   events ingested        : {len(norm):,}")
    print(f"   entities in graph      : {len(g.nodes):,}")
    print(f"   distinct entity types  : {len({n['type'] for n in g.nodes.values()})}")

    findings = run_detections(norm, IOCS)
    print("\n" + hr("2. SHIFT-LEFT DETECTIONS (in-stream, pre-landing)"))
    for f in findings:
        print(f"   [{f.risk:>2}] {f.rule:<16} {f.title}")
        print(f"        └ {f.detail}")

    print("\n" + hr("3. BLAST RADIUS — real-time vs historical (graph + replay)"))
    inv = run_investigation(g, findings, IOCS, INCIDENT_START, norm)
    sc = inv["subagents"].get("scoping", {})
    print(f"   victims (total)        : {len(sc.get('victims', []))}")
    print(f"   discovered real-time   : {', '.join(p.split(':',1)[1] for p in sc.get('realtime', [])) or '—'}")
    print(f"   discovered via replay  : {', '.join(p.split(':',1)[1] for p in sc.get('historical', [])) or '—'}")
    print("   by entity type (user / non-user / machine / agent):")
    for et, members in sorted(sc.get("by_type", {}).items()):
        print(f"        {et:<9}: {', '.join(members)}")

    print("\n" + hr("4. PREDICTIVE LAYER"))
    pr = inv["prediction"]
    print(f"   convicted hosts        : {', '.join(h.split(':',1)[1] for h in pr['convicted']) or '—'}")
    print(f"   PREDICTED next targets : {', '.join(h.split(':',1)[1] for h in pr['predicted_next_targets']) or '—'}")
    print(f"   rationale              : {pr['rationale']}")

    print("\n" + hr("5. AGENTIC INVESTIGATION (orchestrated sub-agents)"))
    print(f"   lead finding           : {inv['lead_finding'].title}")
    print(f"   triage verdict         : {inv['triage']['verdict']}")
    print(f"   dispatched sub-agents  : {', '.join(inv['triage']['dispatch'])}")
    if "enrichment" in inv["subagents"]:
        e = inv["subagents"]["enrichment"]
        print(f"   enrichment/loop-closer : {e['action']} ({e['iocs_published']} IOCs)")
    if "identity" in inv["subagents"]:
        idn = inv["subagents"]["identity"]
        print(f"   compromised principals : {', '.join(p.split(':',1)[1] for p in idn['compromised_principals']) or '—'}")
        print(f"   recommended actions    : {'; '.join(idn['recommended_actions'])}")

    print("\n" + hr("6. CONTINUOUS SCORING — decaying risk + trend (top entities)"))
    scores = continuous_scores(norm, IOCS)
    print(f"   {'entity':<34}{'score':>6}{'trend':>8}{'obs':>5}")
    for k, s in list(scores.items())[:8]:
        arrow = "↑" if s["trend"] > 0 else ("↓" if s["trend"] < 0 else "→")
        print(f"   {k:<34}{s['final']:>6}{arrow + str(abs(s['trend'])):>8}{s['points']:>5}")

    print("\n" + hr("7. EFFICIENCY (modeled assumptions — see pipeline.py)"))
    m = efficiency(norm, findings)
    print(f"   ingested               : {m['total_events']:,}")
    print(f"   forwarded to SIEM      : {m['forwarded_to_siem']:,}  "
          f"(only findings + context)")
    print(f"   to LakeVilla only      : {m['to_lakevilla_only']:,}")
    print(f"   >>> SIEM volume cut     : {m['reduction_pct']}%")
    print(f"   raw alerts (SIEM-style): {m['raw_alerts']}  →  findings: {m['fused_findings']}  "
          f"→  correlated incidents: {m['incidents']}")
    print(f"   >>> alert-fatigue cut   : {m['fatigue_reduction_pct']}%  "
          f"(alerts → incidents)")
    print(f"   MTTD shift-left        : ~{m['mttd_stream_sec']}s")
    print(f"   MTTD SIEM (ingest+rule): ~{int(m['mttd_siem_sec']/60)}m  "
          f"(modeled: {int(m['mttd_siem_sec']/60)}x+ slower)")

    print("\n" + hr("DONE"))


if __name__ == "__main__":
    main()
