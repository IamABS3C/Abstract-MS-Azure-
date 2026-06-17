"""
Investigation report generator — turns the model's findings into an analyst-ready
incident report (Markdown + branded HTML), and can write the investigation back to
Abstract as a dedicated saved view + field set.

  python3 report.py               # write investigation_report.md + .html
  python3 report.py --writeback   # also create an Abstract view for this investigation

The report is the artifact an analyst attaches to a case / hands to IR / sends to
leadership: narrative, kill chain, blast radius, identities, OSINT, MITRE, actions.
"""
from __future__ import annotations

import sys
import html

from pipeline import normalize, Graph, run_detections, run_investigation, continuous_scores, efficiency
from data import events, IOCS, INCIDENT_START
import identities as ID
import viz_svg as V


def build():
    raw = events()
    norm = [normalize(i, r) for i, r in enumerate(raw)]
    g = Graph()
    for ev in norm:
        g.add(ev)
    findings = run_detections(norm, IOCS)
    inv = run_investigation(g, findings, IOCS, INCIDENT_START, norm)
    scores = continuous_scores(norm, IOCS)
    metrics = efficiency(norm, findings)
    return norm, g, findings, inv, scores, metrics


def markdown(findings, inv, scores, metrics):
    sc = inv["subagents"]["scoping"]
    idn = inv["subagents"].get("identity", {})
    pred = inv["prediction"]
    lines = []
    A = lines.append
    A("# Incident Report — Qakbot-style intrusion (model demo)\n")
    A(f"**Lead finding:** {inv['lead_finding'].title}  ")
    A(f"**Severity:** critical · **Risk:** {inv['lead_finding'].risk}/100 · "
      f"**Triage:** {inv['triage']['verdict']}\n")
    A("## Executive summary\n")
    A("A malware verdict corroborated by endpoint execution and C2 beaconing, with an identity "
      "authenticating from the same C2 infrastructure (account takeover). Detected in-stream "
      f"before landing. **{len(sc['victims'])} entities** implicated across "
      f"{len({v.split(':',1)[0] for v in sc['victims']})} identity kinds; "
      f"**{len(pred['predicted_next_targets'])}** predicted next targets.\n")

    A("## Detections (shift-left)\n")
    for f in findings[:8]:
        A(f"- **[{f.risk}] {f.rule}** — {f.title}  \n  _{f.detail}_")
    A("")

    A("## Blast radius\n")
    A(f"- **Real-time:** {', '.join(p.split(':',1)[1] for p in sc['realtime']) or '—'}")
    A(f"- **Historical (LakeVilla replay):** {', '.join(p.split(':',1)[1] for p in sc['historical']) or '—'}")
    A("- **By identity kind:**")
    counts = {}
    for v in sc["victims"]:
        t, i = v.split(":", 1)
        counts.setdefault(ID.classify_entity({"type": t, "id": i}), []).append(i)
    for kind, members in sorted(counts.items()):
        A(f"  - `{kind}` — {', '.join(members)}")
    A("")

    A("## Prediction\n")
    A(f"- **Predicted next targets:** {', '.join(p.split(':',1)[1] for p in pred['predicted_next_targets']) or '—'}")
    A(f"- _{pred['rationale']}_\n")

    A("## Continuous risk (top entities)\n")
    for k, s in list(scores.items())[:6]:
        A(f"- `{k}` — {s['final']} (trend {s['trend']:+})")
    A("")

    A("## OSINT enrichment\n")
    for kind, vals in (("ip", IOCS.ips), ("domain", IOCS.domains), ("hash", IOCS.hashes)):
        for val in list(vals)[:1]:
            tools = ", ".join(list(ID.osint_enrich(val, kind).keys())[:8])
            A(f"- **{kind}** `{val}` → {tools}")
    A("")

    if idn.get("compromised_principals"):
        A("## Recommended actions\n")
        for a in idn["recommended_actions"]:
            A(f"- {a}")
        A(f"- Compromised principals: {', '.join(p.split(':',1)[1] for p in idn['compromised_principals'])}")
    A("")

    A("## Efficiency vs. SIEM-first\n")
    A(f"- SIEM volume cut **{metrics['reduction_pct']}%** ({metrics['total_events']:,} → {metrics['forwarded_to_siem']})")
    A(f"- Alert fatigue cut **{metrics['fatigue_reduction_pct']}%** ({metrics['raw_alerts']} alerts → {metrics['incidents']} incident)")
    A(f"- MTTD ~0.5s shift-left vs ~{int(metrics['mttd_siem_sec']/60)}m SIEM (modeled)\n")
    A("> Model demo. Verdict fusion / entity correlation / campaign clustering mirror what "
      "Abstract Amplify produces; replay, scoring, prediction, and sub-agents run in the local engine.")
    return "\n".join(lines)


def html_report(md_text, g, scores, inv):
    body = html.escape(md_text)
    # cheap markdown → HTML (headings, bold, lists)
    import re
    h = body
    h = re.sub(r'^# (.+)$', r'<h1>\1</h1>', h, flags=re.M)
    h = re.sub(r'^## (.+)$', r'<h2>\1</h2>', h, flags=re.M)
    h = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', h)
    h = re.sub(r'`(.+?)`', r'<code>\1</code>', h)
    h = re.sub(r'^- (.+)$', r'<li>\1</li>', h, flags=re.M)
    h = h.replace("\n\n", "<br>")
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Incident Report — Abstract</title>
<link href="https://fonts.googleapis.com/css2?family=Barlow:wght@400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
<style>body{{background:{V.BG};color:{V.INK};font-family:Barlow,sans-serif;max-width:1100px;margin:0 auto;padding:34px;line-height:1.6}}
h1{{color:{V.PINK};font-size:26px}} h2{{color:{V.TEAL};font-size:15px;text-transform:uppercase;letter-spacing:1.3px;margin-top:26px}}
code{{font-family:"JetBrains Mono",monospace;background:#16161e;padding:1px 5px;border-radius:4px;font-size:12px;color:#cfcfe0}}
li{{margin:3px 0}} b{{color:#fff}} .viz{{background:{V.PANEL};border:1px solid #1d1d27;border-radius:14px;padding:14px;margin:18px 0}}</style></head>
<body><div class="viz">{V.entity_graph_svg(g, IOCS, scores)}</div>{h}
<div class="viz">{V.blast_radius_svg(inv['subagents']['scoping'])}</div></body></html>"""


def main():
    norm, g, findings, inv, scores, metrics = build()
    md = markdown(findings, inv, scores, metrics)
    open("investigation_report.md", "w").write(md)
    open("investigation_report.html", "w").write(html_report(md, g, scores, inv))
    print(f"wrote investigation_report.md ({len(md)} chars) + investigation_report.html")

    if "--writeback" in sys.argv:
        from abstract_client import AbstractClient
        c = AbstractClient("api"); c.connect()
        fs = c.create_fieldset({"name": "[ABS-DEMO] Investigation — Qakbot campaign",
                                "fields": ["type", "@timestamp", "severity", "user_name",
                                           "source_address", "dest_address", "file.hash.sha256",
                                           "threat.technique_id", "message"], "tags": ["abs-demo", "investigation"]})
        fid = (fs.get("body") or {}).get("id")
        vw = c.create_view({"name": "[ABS-DEMO] Investigation — Qakbot campaign",
                            "query": [{"id": "q1", "depth": 0, "field": "severity", "index": 0,
                                       "value": "critical", "parentId": None, "fieldType": "String",
                                       "field_operation": "EQUALS", "subFieldOperation": ""}],
                            "time_selection": {"type": "Relative", "numeric_value": 30,
                                               "option_selected": "days", "end_date": None,
                                               "start_date": None, "end_numeric_value": None,
                                               "end_option_selected": None},
                            "fieldset_ids": [fid] if fid else None,
                            "fields": ["type", "@timestamp", "severity", "user_name", "message"],
                            "order_by": "@timestamp", "order_type": "DESC"})
        print("  write-back → view", (vw.get("body") or {}).get("id"), "fieldset", fid)


if __name__ == "__main__":
    main()
