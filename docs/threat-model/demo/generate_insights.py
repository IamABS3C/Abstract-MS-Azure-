"""
Generate REAL Abstract insights from the model's findings — the reliable way to
put visible, demo-ready data into the tenant (realtime rules only fire on new
incoming events; this pushes the campaign straight into the Insights UI).

  python3 generate_insights.py            # clean prior demo insights, create fresh
  python3 generate_insights.py --cleanup  # delete all [ABS-DEMO] insights (kill switch)

Each insight is [ABS-DEMO]-titled, carries MITRE techniques + severity, and the lead
carries blast radius + predicted targets + a LIVE GreyNoise verdict. Reversible.
"""
from __future__ import annotations

import sys

from abstract_client import AbstractClient
import report
import identities as ID

MARKER = "[ABS-DEMO]"
SEV = lambda r: "critical" if r >= 90 else "high" if r >= 75 else "medium" if r >= 60 else "low"
MITRE = {
    "verdict-fusion": [("T1204", "User Execution"), ("T1071.001", "Web Protocols")],
    "ato-c2-bridge":  [("T1078", "Valid Accounts"), ("T1071.001", "Web Protocols")],
    "ioc-blast-match": [("T1071", "Application Layer Protocol")],
    "beaconing":      [("T1071.001", "Web Protocols")],
}


def cleanup(c):
    n = 0
    for i in (c._req("GET", "/v1/insights/?page_size=200").get("body", {}) or {}).get("insights", []):
        if MARKER in (i.get("title") or "") and i.get("nanoid"):
            c._req("DELETE", f"/v1/insights/{i['nanoid']}"); n += 1
    return n


def main():
    c = AbstractClient("api")
    print("connect:", c.connect().get("scheme"))
    print("cleanup prior demo insights:", cleanup(c))
    if "--cleanup" in sys.argv:
        return

    norm, g, findings, inv, scores, metrics = report.build()
    sc = inv["subagents"]["scoping"]
    gn = ID.greynoise_community("185.220.101.45")  # LIVE threat-intel call

    made = []
    for idx, f in enumerate(findings[:8]):
        mitre = [{"id": i, "name": n, "sub_id": ""} for (i, n) in
                 MITRE.get(f.rule, [("T1071", "Application Layer Protocol")])]
        extra = ""
        if idx == 0:
            kinds = len({v.split(":", 1)[0] for v in sc["victims"]})
            preds = ", ".join(p.split(":", 1)[1] for p in inv["prediction"]["predicted_next_targets"])
            extra = (f"  Blast radius: {len(sc['victims'])} entities across {kinds} identity kinds; "
                     f"predicted next targets: {preds}. "
                     f"Live GreyNoise(185.220.101.45) = {gn.get('classification', 'n/a')}. "
                     f"SIEM volume cut {metrics['reduction_pct']}%, fatigue cut "
                     f"{metrics['fatigue_reduction_pct']}%. Model demo — see docs/threat-model.")
        body = {"title": f"{MARKER} {f.title}", "status": "open", "severity": SEV(f.risk),
                "summary": (f.detail + extra)[:1500], "categories": ["detection"],
                "resolution": None, "mitre_attack_techniques": mitre}
        r = c._req("POST", "/v1/insights/", body)
        nano = (r.get("body") or {}).get("nanoid")
        made.append(nano)
        print(f"  insight {f.rule:<16} sev={SEV(f.risk):<8} -> {nano or 'FAIL ' + str(r.get('status'))}")

    ok = len([m for m in made if m])
    tot = (c._req("GET", "/v1/insights/?page_size=1").get("body", {}) or {}).get("metadata", {}).get("total_count")
    print(f"\ncreated {ok} insights | tenant total insights now: {tot}")
    print("kill switch: python3 generate_insights.py --cleanup")


if __name__ == "__main__":
    main()
