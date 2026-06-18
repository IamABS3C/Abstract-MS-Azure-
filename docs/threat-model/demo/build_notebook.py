#!/usr/bin/env python3
"""
Generator for soc_notebook.ipynb — the Abstract AI-SOC analyst workspace.

Keeping the (large) notebook in a generator makes it maintainable and proves the
content is real: every code cell calls the same engine + adapters the rest of the
demo uses (pipeline / hunts / enrichment / mcp_client / abstract_client / viz).

    python3 build_notebook.py            # (re)writes soc_notebook.ipynb (no outputs)

Validate end-to-end with the venv kernel:
    .venv/bin/jupyter nbconvert --to notebook --execute --inplace \
        --ExecutePreprocessor.kernel_name=abstract-soc soc_notebook.ipynb
"""
from __future__ import annotations

import nbformat
from nbformat.v4 import new_notebook, new_markdown_cell, new_code_cell

CELLS = []


def md(src):
    CELLS.append(new_markdown_cell(src.strip("\n")))


def code(src):
    CELLS.append(new_code_cell(src.strip("\n")))


LOGO = "https://docs.abstractsecurity.app/img/logos/logo-dark.svg"

# ─────────────────────────────────────────────────────────────────────────────
md(f"""
<img src='{LOGO}' height='44'>

# Abstract AI-SOC Notebook

### One analyst workspace over the Abstract pipeline — hunt · investigate · enrich · report · act

A single, branded notebook that exercises **every Abstract use case** end-to-end:

| | |
|---|---|
| **Connect** | Abstract **REST API** *and* the Abstract **MCP server** (the way agents consume it) |
| **Hunt** | a reusable threat-hunting catalog over the normalized event stream + entity graph |
| **Investigate** | entity-360, blast radius (real-time vs LakeVilla replay), attack timeline, prediction |
| **Score** | continuous, decaying per-entity risk with trajectories + forecast |
| **Enrich** | authenticated OSINT (VirusTotal · Shodan · GreyNoise · AbuseIPDB · OTX · urlscan · Censys) + 24-engine keyless pivots |
| **Report** | analyst-ready incident report (Markdown + branded HTML) |
| **Act** | write back to Abstract — field-sets · views · insights · verdicts |

> Runs **offline** out of the box (synthetic Qakbot-style campaign). Add an Abstract key
> (`~/.abstract.env`) and OSINT keys (env vars) to light up the live paths. The engine is
> pure-stdlib; the notebook adds matplotlib / networkx / pandas (see `requirements.txt`).
""")

# 0 · Setup ────────────────────────────────────────────────────────────────────
md("## 0 · Setup & dependencies")
code("""
# one-time (uncomment to install into the active kernel):
# %pip install -r requirements.txt
%matplotlib inline
import warnings; warnings.filterwarnings("ignore")
import pandas as pd
pd.set_option("display.max_colwidth", 60); pd.set_option("display.max_rows", 40)

import matplotlib, networkx, numpy
print("matplotlib", matplotlib.__version__, "| networkx", networkx.__version__,
      "| numpy", numpy.__version__, "| pandas", pd.__version__)
""")

# 1 · Engine ────────────────────────────────────────────────────────────────────
md("""
## 1 · Load the Abstract model engine

Normalize the mixed-source estate to a common shape, build the **entity graph**
(user / host / account / NHI / agent / IOC), run the **shift-left detections**,
orchestrate the **sub-agents**, and compute **continuous risk** + **efficiency**.
""")
code("""
from pipeline import (normalize, Graph, run_detections, run_investigation,
                      continuous_scores, efficiency, IOCSet)
from data import events, IOCS, INCIDENT_START
import viz, identities as ID, hunts, enrichment

raw  = events()
norm = [normalize(i, r) for i, r in enumerate(raw)]
g = Graph()
for ev in norm:
    g.add(ev)
findings = run_detections(norm, IOCS)
inv      = run_investigation(g, findings, IOCS, INCIDENT_START, norm)
scores   = continuous_scores(norm, IOCS)
metrics  = efficiency(norm, findings)

print(f"{len(norm):,} events | {len(g.nodes)} entities | {len(findings)} findings | "
      f"{len(inv['subagents']['scoping']['victims'])} entities in blast radius")
""")

# 2 · REST connect ──────────────────────────────────────────────────────────────
md("""
## 2 · Connect to Abstract — REST API *(optional, live)*

Reads the key from `~/.abstract.env` (outside the repo) or the environment. With no
key the notebook stays **offline** and every live cell falls back to the local model.
`LIVE` gates the authenticated paths below.
""")
code("""
client = None
LIVE = False
try:
    from abstract_client import AbstractClient, ABSTRACT_ACCOUNT_ID
    client = AbstractClient("api")
    conn = client.connect()
    LIVE = bool(conn.get("ok"))
    print("Abstract REST:", conn, "| tenant:", ABSTRACT_ACCOUNT_ID or "(unset)")
except Exception as e:
    print("offline — no Abstract key set (", str(e)[:80], ")")
""")

# 3 · MCP connect ────────────────────────────────────────────────────────────────
md("""
## 3 · Connect to Abstract — **MCP server**

The same Abstract API over the **Model Context Protocol** — exactly how Claude /
Copilot / agents consume it. We launch the bundled stdio server
(`solution/mcp/abstract_mcp_server.py`), list its tools, and make a real call.
Set `ABSTRACT_MCP_URL` to point at a remote MCP endpoint instead.
""")
code("""
from mcp_client import AbstractMCP
mcp = AbstractMCP()
print("MCP status:", mcp.status())

tools = mcp.list_tools()
tools_df = pd.DataFrame([t for t in tools if "name" in t])
display(tools_df[["name", "description"]] if "name" in tools_df.columns else tools_df)

# a keyless tool call, end-to-end through MCP (no Abstract key required):
piv = mcp.call("osint_pivots", indicator="185.220.101.45")
print("\\nMCP call osint_pivots ->", "ok" if piv.get("ok") else piv.get("error"),
      "| pivots:", (piv.get("result") or {}).get("count"))
""")

# 4 · Live tenant explorer ───────────────────────────────────────────────────────
md("""
## 4 · Live tenant explorer — views · field-sets · insights

When connected, browse the real saved **views**, **field-sets**, and **insights**
on the tenant. Offline, this shows what the queries would return.
""")
code("""
if LIVE:
    views = (client.list_views().get("body", {}) or {}).get("views", [])
    fsets = (client.list_fieldsets().get("body", {}) or {}).get("fieldsets", [])
    ins   = client.list_insights(page_size=10).get("body", {}) or {}
    print(f"views={len(views)}  field-sets={len(fsets)}  "
          f"insights(total)={ins.get('metadata', {}).get('total_count')}")
    display(pd.DataFrame([{"name": v.get("name"), "tags": v.get("tags")} for v in views[:12]]))
    display(pd.DataFrame([{"nanoid": i.get("nanoid"), "severity": i.get("severity"),
                           "status": i.get("status"), "title": i.get("title")}
                          for i in ins.get("insights", [])[:10]]))
else:
    print("offline — set ~/.abstract.env to browse the live tenant.")
    print("Equivalent MCP reads:  mcp.call('abstract_search_events', hours=24)  ·  list_insights / list_views")
""")

# 5 · Entity graph ────────────────────────────────────────────────────────────────
md("## 5 · Campaign entity graph\nUser / host / account / NHI / AI-agent / IOC — node size scales with continuous risk.")
code("viz.draw_entity_graph(g, IOCS, scores);")

# 6 · Risk + trajectories + prediction ────────────────────────────────────────────
md("## 6 · Continuous entity risk, trajectories & prediction")
code("""
viz.draw_risk_bars(scores)
viz.draw_score_trajectories(scores, top=6)
print("PREDICTED next targets:", [p.split(':', 1)[1] for p in inv["prediction"]["predicted_next_targets"]])
print("rationale:", inv["prediction"]["rationale"])
""")

# 7 · MITRE ──────────────────────────────────────────────────────────────────────
md("""
## 7 · MITRE ATT&CK coverage *(live if connected)*

When connected, this pulls the tenant's real rule→technique coverage from
`/v3/rules/mitre` and aggregates per-tactic (the API reports `total`/`enabled`
per technique). Offline, it shows a representative coverage profile.
""")
code("""
tactics = None
if LIVE:
    raw_tactics = ((client.mitre().get("body") or {}).get("tactics")) or []
    agg = []
    for ta in raw_tactics:
        techs = ta.get("techniques") or []
        total = sum(t.get("total", 0) for t in techs)
        enabled = sum(t.get("enabled", 0) for t in techs)
        if total:
            agg.append({"name": ta.get("name"), "total": total, "enabled": enabled})
    tactics = agg or None
    if tactics:
        cov = sum(t["enabled"] for t in tactics), sum(t["total"] for t in tactics)
        print(f"LIVE MITRE coverage: {cov[0]}/{cov[1]} techniques enabled across {len(tactics)} tactics")
if not tactics:
    tactics = [{"name": "Initial Access", "total": 10, "enabled": 9},
               {"name": "Execution", "total": 14, "enabled": 13},
               {"name": "Persistence", "total": 19, "enabled": 17},
               {"name": "Defense Evasion", "total": 42, "enabled": 38},
               {"name": "Cred Access", "total": 17, "enabled": 16},
               {"name": "C2", "total": 17, "enabled": 16},
               {"name": "Exfiltration", "total": 9, "enabled": 9}]
    print("offline — representative MITRE coverage profile")
viz.draw_mitre_heatmap(tactics);
""")

# 8 · Timeline ────────────────────────────────────────────────────────────────────
md("## 8 · Attack-chain timeline")
code("viz.draw_attack_timeline(norm);")

# 9 · Detection coverage ──────────────────────────────────────────────────────────
md("## 9 · Detection coverage — findings")
code("""
findings_df = pd.DataFrame([{
    "rule": f.rule, "severity": f.severity, "risk": f.risk,
    "entities": len(f.entities), "title": f.title} for f in findings])
display(findings_df.sort_values("risk", ascending=False).reset_index(drop=True))
viz.draw_findings_by_rule(findings);
""")

# 10 · Hunting library ────────────────────────────────────────────────────────────
md("""
## 10 · Threat-hunting library

A reusable catalog of hunts over the normalized stream + entity graph. Each maps to
something Abstract expresses as a detection rule or saved view. `hunts.run(key)` runs
one; `hunts.run_all()` runs the catalog.
""")
code("""
ctx = hunts.make_context(norm, g, IOCS, scores)
display(pd.DataFrame(hunts.catalog()))

results = hunts.run_all(ctx)
rows = []
for key, hrows in results.items():
    for r in hrows:
        rows.append({"hunt": key, **{k: v for k, v in r.items() if k in
                     ("entity", "severity", "technique", "why")}})
hunt_df = pd.DataFrame(rows)
print(f"{len(hunt_df)} hunt rows across {len(results)} hunts")
display(hunt_df.head(30))
""")

# 11 · Entity-360 ─────────────────────────────────────────────────────────────────
md("""
## 11 · Entity-360 investigation

Pivot on any entity: its graph neighborhood, contributing findings, risk trajectory,
and raw event timeline — the analyst's single pane for one principal.
""")
code("""
def investigate(entity):
    out = {"entity": entity, "kind": ID.classify_entity(
        {"type": entity.split(':', 1)[0], "id": entity.split(':', 1)[1]})}
    out["score"] = scores.get(entity, {}).get("final")
    out["neighbors"] = sorted(g.adj.get(entity, set()))[:12]
    out["findings"] = [f.title for f in findings if entity in f.entities]
    tl = [{"ts": str(ev.ts), "source": ev.source, "ocsf": ev.ocsf, "severity": ev.severity}
          for ev in norm if entity in ev.entity_keys()]
    out["events"] = len(tl)
    return out, pd.DataFrame(tl)

# investigate the highest-risk principal in the campaign
lead_entity = next(iter(scores))
summary, timeline_df = investigate(lead_entity)
import json as _json; print(_json.dumps(summary, indent=2, default=str))
display(timeline_df.head(15))
""")

# 12 · Blast radius ───────────────────────────────────────────────────────────────
md("## 12 · Blast radius — real-time vs LakeVilla replay, across all identity kinds")
code("""
sc = inv["subagents"]["scoping"]
print("real-time :", [p.split(':', 1)[1] for p in sc["realtime"]])
print("replay    :", [p.split(':', 1)[1] for p in sc["historical"]])
counts = {}
for v in sc["victims"]:
    t, i = v.split(":", 1)
    k = ID.classify_entity({"type": t, "id": i})
    counts[k] = counts.get(k, 0) + 1
print("identity kinds:", counts)
viz.draw_identity_taxonomy(counts);
""")

# 13 · Identity taxonomy ──────────────────────────────────────────────────────────
md("""
## 13 · Identity / NHI / agent taxonomy

The full spectrum a modern SOC must reason about — human, service, **non-human (NHI)**,
service principals, **AI agents**, stolen sessions — and which sources emit them.
""")
code("""
tax_df = pd.DataFrame([{"kind": k, "description": v[0], "key_fields": ", ".join(v[1]),
                        "why_it_matters": v[3]} for k, v in ID.IDENTITY_TYPES.items()])
display(tax_df)

classified = pd.DataFrame([{
    "entity": k, "type": n["type"],
    "identity_kind": ID.classify_entity(n),
    "risk": scores.get(k, {}).get("final", 0)}
    for k, n in g.nodes.items() if n["type"] in ("identity", "account", "host", "nhi", "agent")])
display(classified.sort_values("risk", ascending=False).head(15).reset_index(drop=True))
""")

# 14 · OSINT workbench ────────────────────────────────────────────────────────────
md("""
## 14 · OSINT enrichment workbench — authenticated + keyless pivots

Authenticated adapters (VirusTotal · Shodan · GreyNoise · AbuseIPDB · OTX · urlscan ·
Censys · HIBP) run when their key env var is set — **keys are read from the environment,
sent only to their provider, never logged**. Keyless one-click **pivot deep-links** (24
engines, distilled from *awesome-hacker-search-engines*) are always available.
""")
code("""
from IPython.display import HTML, display
print("configured OSINT adapters (booleans only):")
display(pd.DataFrame([{"tool": k, "configured": v} for k, v in enrichment.available().items()]))

# clickable pivots for the campaign IOCs (no keys, no outbound calls):
ioc_samples = [("ip", "185.220.101.45"), ("ip", "91.219.236.12"),
               ("domain", "cdn.evil-delivery.com")]
html = ["<table style='font-family:JetBrains Mono,monospace;font-size:12px'>"]
for kind, val in ioc_samples:
    links = ID.pivot_urls(val, kind)
    cells = " · ".join(f"<a href='{d['url']}' target='_blank' style='color:#01e69d'>{name}</a>"
                       for name, d in list(links.items())[:8])
    html.append(f"<tr><td style='color:#f8226a;padding:4px 10px'><b>{kind}</b> {val}</td><td>{cells}</td></tr>")
html.append("</table>")
display(HTML("".join(html)))

if LIVE or any(enrichment.available().values()):
    print("\\nLIVE enrichment (185.220.101.45):")
    res = enrichment.enrich("185.220.101.45", "ip")
    display(pd.DataFrame([{"tool": k, **(v.get("result", {}) if isinstance(v.get("result"), dict) else {"result": v.get("result"), "note": v.get("skipped")})}
                          for k, v in res["tools"].items()]))
else:
    print("\\nset VT_API_KEY / SHODAN_API_KEY / ABUSEIPDB_API_KEY / … to run live enrichment.")
""")

# 15 · Efficiency ─────────────────────────────────────────────────────────────────
md("## 15 · Efficiency / value model *(modeled)*")
code("""
viz.draw_efficiency_panel(metrics)
print({k: metrics[k] for k in ("total_events", "forwarded_to_siem", "reduction_pct",
                               "raw_alerts", "incidents", "fatigue_reduction_pct")})
""")

# 16 · What-if ────────────────────────────────────────────────────────────────────
md("## 16 · What-if / hypotheticals\nQuantify the WildFire-loop's value, and test an arbitrary 'if this were C2' hypothesis.")
code("""
from pipeline import detect_verdict_fusion, detect_ioc_blast
vf = detect_verdict_fusion(norm)
known_wo = {e for f in vf for e in f.entities if e.split(':', 1)[0] in ('host', 'identity')}
with_loop = g.reachable_principals(IOCS.keys())
print('victims WITHOUT loop:', len(known_wo), '| WITH loop:', len(with_loop))

ip = next(n['id'] for n in g.nodes.values() if n['type'] == 'ip' and n['id'].startswith('52.'))
hyp = detect_ioc_blast(norm, IOCSet(set(), {ip}, set(), set()))
print(f'HYPOTHESIS: if {ip} were C2 -> {len(hyp)} entities implicated')
""")

# 17 · Report ─────────────────────────────────────────────────────────────────────
md("## 17 · Generate the incident report (Markdown + branded HTML)")
code("""
import report
norm2, g2, findings2, inv2, scores2, metrics2 = report.build()
md_text = report.markdown(findings2, inv2, scores2, metrics2)
open("investigation_report.md", "w").write(md_text)
open("investigation_report.html", "w").write(report.html_report(md_text, g2, scores2, inv2))
print(md_text[:900], "\\n...\\nwrote investigation_report.md + investigation_report.html")
""")

# 18 · Write-back ─────────────────────────────────────────────────────────────────
md("""
## 18 · Write back to Abstract — field-set · view · insight

Turn the investigation into first-class platform objects via the REST API (needs a
write-scoped key). Idempotent + clearly `[ABS-DEMO]`-tagged so it's reversible.
""")
code("""
if LIVE:
    fs = client.create_fieldset({
        "name": "[ABS-DEMO] Notebook investigation",
        "fields": ["type", "@timestamp", "severity", "user_name", "source_address",
                   "file.hash.sha256", "threat.technique_id", "message"],
        "tags": ["abs-demo", "notebook"]})
    fid = (fs.get("body") or {}).get("id")
    lead = findings[0]
    ins = client.create_insight({
        "title": "[ABS-DEMO] " + lead.title, "status": "open",
        "severity": lead.severity, "summary": lead.detail[:1500],
        "categories": ["detection"], "resolution": None,
        "mitre_attack_techniques": [{"id": "T1078", "name": "Valid Accounts", "sub_id": ""}]})
    print("field-set:", fid, "status", fs.get("status"))
    print("insight  :", (ins.get("body") or {}).get("nanoid"), "status", ins.get("status"))
    print("cleanup  : python3 generate_insights.py --cleanup  &&  python3 live_writeback.py --cleanup")
else:
    from pipeline import finding_to_abstract
    print("offline — payload preview (fires as-is once a write-scoped key is set):")
    import json as _json
    print(_json.dumps(finding_to_abstract(findings[0], scores), indent=2)[:900])
""")

# 19 · Closing ────────────────────────────────────────────────────────────────────
md("""
## 19 · The closed loop

```
 Abstract pipeline ──(REST · MCP)──► this notebook ──(field-sets · views · insights · verdicts · reports)──► Abstract
   triggers:  new finding · new AIG IOC · hourly re-score · score-threshold → SOAR / agent
```

**Live** (with a key): tenant views/field-sets/insights, MITRE coverage, OSINT enrichment,
MCP tool calls, write-back. **Modeled in-engine**: replay, continuous scoring, prediction,
sub-agents, the incident narrative — see `DEMO-CATALOG.md` for the exact live-vs-modeled line.

Every capability here is also reachable as an **MCP tool** (`mcp.call(...)`) or a **REST**
call (`client...`), so the same logic drops into a Copilot/Claude agent, a Logic App
playbook, or a scheduled job — the notebook is just the analyst-facing surface.
""")

# ─────────────────────────────────────────────────────────────────────────────
nb = new_notebook(cells=CELLS, metadata={
    "kernelspec": {"name": "python3", "display_name": "Python 3 (ipykernel)", "language": "python"},
    "language_info": {"name": "python"},
})

if __name__ == "__main__":
    nbformat.write(nb, "soc_notebook.ipynb")
    print(f"wrote soc_notebook.ipynb — {len(CELLS)} cells "
          f"({sum(1 for c in CELLS if c.cell_type == 'code')} code, "
          f"{sum(1 for c in CELLS if c.cell_type == 'markdown')} markdown)")
