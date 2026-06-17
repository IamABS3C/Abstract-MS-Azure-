"""
Abstract AI-SOC command center — a branded, zero-dependency HTML dashboard with
SVG attack maps, entity graphs, MITRE heat strips, blast-radius rings, risk and
identity analytics. Renders the local engine; in --mode api it also writes back
to the tenant and pulls live MITRE coverage.

  python3 dashboard.py             # offline (synthetic engine) -> dashboard.html
  python3 dashboard.py --mode api  # + live write-back + live MITRE coverage
"""
from __future__ import annotations

import sys
import html

from pipeline import (normalize, Graph, run_detections, run_investigation,
                      continuous_scores, efficiency)
from data import events, IOCS, INCIDENT_START
import viz_svg as V
import identities as ID

LOGO = "https://docs.abstractsecurity.app/img/logos/logo-dark.svg"
SYNTH_TACTICS = [  # offline stand-in so the heat strip renders without the tenant
    {"name": "Initial Access", "total": 10, "enabled": 9},
    {"name": "Execution", "total": 14, "enabled": 13},
    {"name": "Persistence", "total": 19, "enabled": 17},
    {"name": "Priv Esc", "total": 13, "enabled": 11},
    {"name": "Defense Evasion", "total": 42, "enabled": 38},
    {"name": "Cred Access", "total": 17, "enabled": 16},
    {"name": "Discovery", "total": 31, "enabled": 27},
    {"name": "Lateral Move", "total": 9, "enabled": 8},
    {"name": "Collection", "total": 17, "enabled": 15},
    {"name": "C2", "total": 17, "enabled": 16},
    {"name": "Exfiltration", "total": 9, "enabled": 9},
    {"name": "Impact", "total": 14, "enabled": 12},
]


def compute(mode):
    raw = events()
    norm = [normalize(i, r) for i, r in enumerate(raw)]
    g = Graph()
    for ev in norm:
        g.add(ev)
    findings = run_detections(norm, IOCS)
    inv = run_investigation(g, findings, IOCS, INCIDENT_START, norm)
    scores = continuous_scores(norm, IOCS)
    metrics = efficiency(norm, findings)

    # identity taxonomy over the blast-radius victims
    victims = inv["subagents"].get("scoping", {}).get("victims", [])
    id_counts = {}
    for v in victims:
        t, i = v.split(":", 1)
        kind = ID.classify_entity({"type": t, "id": i})
        id_counts[kind] = id_counts.get(kind, 0) + 1

    # OSINT panel: live GreyNoise verdict + one-click pivot links per campaign IOC
    osint_rows = []
    for kind, vals in (("ip", IOCS.ips), ("domain", IOCS.domains), ("hash", IOCS.hashes)):
        for val in list(vals)[:2]:
            gn = ID.greynoise_community(val).get("classification") if kind == "ip" else None
            pivots = ID.pivot_urls(val, kind)
            osint_rows.append((kind, val, gn, pivots))

    live, mitre, live_insights = None, SYNTH_TACTICS, None
    if mode in ("api", "live"):
        import live_writeback
        live = live_writeback.run()
        from abstract_client import AbstractClient
        c = AbstractClient("api"); c.connect()
        mt = (c._req("GET", "/v3/rules/mitre").get("body") or {}).get("tactics")
        if mt:
            mitre = mt
        ins = (c._req("GET", "/v1/insights/?page_size=200").get("body", {}) or {}).get("insights", [])
        live_insights = sum(1 for i in ins if "[ABS-DEMO]" in (i.get("title") or ""))
    return dict(norm=norm, g=g, findings=findings, inv=inv, scores=scores, metrics=metrics,
                id_counts=id_counts, osint_rows=osint_rows, live=live, mitre=mitre,
                live_insights=live_insights)


def card(big, label, accent=V.TEAL):
    return (f'<div class="card"><div class="big" style="color:{accent}">{big}</div>'
            f'<div class="lbl">{html.escape(label)}</div></div>')


def render(d, mode):
    m, inv, sc = d["metrics"], d["inv"], d["inv"]["subagents"]["scoping"]
    pred = inv["prediction"]["predicted_next_targets"]
    live = d.get("live")

    cards = "".join([
        card(f'{m["reduction_pct"]}%', "SIEM volume cut", V.TEAL),
        card(f'{m["fatigue_reduction_pct"]}%', "alert-fatigue cut", V.TEAL),
        card(f'~{int(m["mttd_siem_sec"]/60)}m→0.5s', "MTTD shift-left", V.PINK),
        card(str(len(sc["victims"])), "entities in blast radius", V.PINK),
        card(str(len(pred)), "predicted next targets", V.PINK),
        card((f'{d["live_insights"]} live' if d.get("live_insights") is not None
              else f'{len(d["id_counts"])}'),
             "insights generated on tenant" if d.get("live_insights") is not None
             else "identity kinds implicated", V.PINK if d.get("live_insights") else V.TEAL),
    ])

    det_rows = "".join(
        f'<tr><td class="risk">{f.risk}</td><td>{html.escape(f.rule)}</td>'
        f'<td>{html.escape(f.title)}</td></tr>' for f in d["findings"][:8])

    def _gn_badge(gn):
        if gn == "malicious":
            return f'<span style="color:{V.PINK};font-weight:700">● malicious</span>'
        if gn:
            return f'<span style="color:{V.TEAL}">● {html.escape(gn)}</span>'
        return f'<span style="color:{V.MUT}">—</span>'

    def _pivots(pv):
        chips = []
        for name, info in list(pv.items())[:9]:
            chips.append(f'<a href="{info["url"]}" target="_blank" style="color:{V.TEAL};'
                         f'text-decoration:none;border:1px solid #243;border-radius:10px;'
                         f'padding:1px 7px;margin:2px;display:inline-block;font-size:10.5px">'
                         f'{html.escape(name)}</a>')
        return "".join(chips)

    osint = "".join(
        f'<tr><td>{html.escape(k)}</td><td class="mono">{html.escape(v[:30])}</td>'
        f'<td>{_gn_badge(gn)}</td><td>{_pivots(pv)}</td></tr>'
        for k, v, gn, pv in d["osint_rows"])

    banner = ("LIVE — wrote field-set " + str((live or {}).get("fieldset_id")) + " + view "
              + str((live or {}).get("view_id")) + " to the tenant"
              if (live and live.get("ok")) else
              "SIMULATED — run `dashboard.py --mode api` to write back + pull live MITRE coverage")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Abstract · AI-SOC Command Center</title>
<link href="https://fonts.googleapis.com/css2?family=Barlow:wght@400;600;800&family=Barlow+Semi+Condensed:wght@600&family=JetBrains+Mono&display=swap" rel="stylesheet">
<style>
 :root{{--pink:{V.PINK};--teal:{V.TEAL};--bg:{V.BG};--panel:{V.PANEL};--ink:{V.INK};--mut:{V.MUT}}}
 *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font-family:Barlow,system-ui,sans-serif;line-height:1.5}}
 header{{padding:28px 40px 18px;border-bottom:1px solid #1d1d27;display:flex;align-items:center;gap:18px}}
 header img{{height:34px}} h1{{font-family:"Barlow Semi Condensed",Barlow;font-size:26px;margin:0}}
 h1 b{{color:var(--pink)}} .sub{{color:var(--mut);font-size:14px;margin-top:3px}}
 .banner{{display:inline-block;margin-top:10px;padding:5px 12px;border-radius:20px;font-size:12px;font-weight:600;background:#16161e;color:var(--teal);border:1px solid #243}}
 main{{padding:24px 40px 70px;max-width:1240px;margin:0 auto}}
 .cards{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:26px}}
 .card{{background:var(--panel);border:1px solid #1d1d27;border-radius:14px;padding:16px}}
 .big{{font-size:23px;font-weight:800;font-family:"Barlow Semi Condensed",Barlow}}
 .lbl{{color:var(--mut);font-size:12px;margin-top:3px}}
 h2{{font-size:14px;text-transform:uppercase;letter-spacing:1.5px;color:var(--teal);margin:28px 0 12px;font-weight:600}}
 .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:22px}}
 .panel{{background:var(--panel);border:1px solid #1d1d27;border-radius:14px;padding:16px}}
 table{{width:100%;border-collapse:collapse}} td,th{{padding:8px 12px;border-bottom:1px solid #18181f;font-size:13px;text-align:left}}
 th{{color:var(--mut);text-transform:uppercase;font-size:10.5px;letter-spacing:1px}}
 .risk{{color:var(--pink);font-weight:800;font-family:"JetBrains Mono",monospace}}
 .mono{{font-family:"JetBrains Mono",monospace;font-size:11px}}
 .note{{background:var(--panel);border:1px solid #1d1d27;border-radius:12px;padding:14px 16px;color:var(--mut);font-size:12.5px}}
 .note b{{color:var(--ink)}} pre{{background:#0b0b10;border:1px solid #1d1d27;border-radius:12px;padding:14px;color:#cfcfe0;font-family:"JetBrains Mono",monospace;font-size:11.5px;overflow:auto}}
 .legend{{display:flex;gap:14px;flex-wrap:wrap;font-size:11px;color:var(--mut);margin-top:8px}}
 .dot{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:4px;vertical-align:middle}}
</style></head><body>
<header>
 <img src="{LOGO}" alt="Abstract Security" onerror="this.style.display='none'">
 <div><h1><b>Abstract</b> · AI-SOC Command Center</h1>
 <div class="sub">WildFire-driven shift-left detection · entity graph · blast radius · prediction · live write-back</div>
 <div class="banner">{banner}</div></div>
</header>
<main>
 <div class="cards">{cards}</div>

 <div class="grid2">
  <div><h2>Entity graph — campaign subgraph</h2>
   <div class="panel">{V.entity_graph_svg(d["g"], IOCS, d["scores"])}
   <div class="legend">
     <span><span class="dot" style="background:{V.TYPE_COLOR['identity']}"></span>identity/user</span>
     <span><span class="dot" style="background:{V.TYPE_COLOR['host']}"></span>host</span>
     <span><span class="dot" style="background:{V.TYPE_COLOR['nhi']}"></span>NHI</span>
     <span><span class="dot" style="background:{V.TYPE_COLOR['agent']}"></span>AI agent</span>
     <span><span class="dot" style="background:{V.TYPE_COLOR['ip']}"></span>IOC</span></div></div></div>
  <div><h2>Blast radius — real-time vs replay</h2>
   <div class="panel">{V.blast_radius_svg(sc)}</div></div>
 </div>

 <h2>MITRE ATT&CK coverage {'(live)' if (live and live.get('ok')) else '(sample)'}</h2>
 <div class="panel">{V.mitre_heatstrip_svg(d["mitre"])}</div>

 <h2>Attack-chain timeline</h2>
 <div class="panel">{V.attack_timeline_svg(d["norm"])}</div>

 <div class="grid2">
  <div><h2>Continuous entity risk (decaying + trend)</h2>
   <div class="panel">{V.risk_bars_svg(d["scores"])}
   <div class="note" style="margin-top:10px"><b style="color:{V.PINK}">Predicted next targets:</b>
     {html.escape(", ".join(p.split(":",1)[1] for p in pred) or "—")}</div></div></div>
  <div><h2>Identity & machine taxonomy (blast radius)</h2>
   <div class="panel">{V.identity_taxonomy_svg(d["id_counts"])}
   <div class="note" style="margin-top:10px">Human · service account · NHI · service principal ·
     machine · <b style="color:{V.PINK}">AI agent</b> · session/cookie — classified across all identity sources.</div></div></div>
 </div>

 <h2>Shift-left detections</h2>
 <div class="panel"><table><tr><th>Risk</th><th>Rule</th><th>Finding</th></tr>{det_rows}</table></div>

 <h2>OSINT enrichment & pivots (per IOC) — GreyNoise is a <span style="color:{V.TEAL}">live</span> call</h2>
 <div class="panel"><table><tr><th>Kind</th><th>Indicator</th><th>GreyNoise (live)</th><th>One-click pivots → hacker search engines</th></tr>{osint}</table>
   <div class="note" style="margin-top:8px"><b>{len(ID.SEARCH_ENGINES)} search engines</b> wired as
   direct-pivot links (Shodan · Censys · ZoomEye · FOFA · Criminal IP · VirusTotal · urlscan · crt.sh ·
   IntelligenceX · Dehashed · Hudson Rock · Exploit-DB …), curated from
   <a href="https://github.com/edoardottt/awesome-hacker-search-engines" target="_blank" style="color:{V.TEAL}">awesome-hacker-search-engines</a>.
   GreyNoise community is a real API call; others are one-click pivots (add keys in <b>identities.py</b> for inline results).</div></div>

 <h2>Closed loop — JupyterHub + Abstract API/MCP</h2>
 <pre> Abstract pipeline ──(API/MCP)──► notebook (graph · stats · ML · what-if · forecast) ──(write back: field-sets · views · suppressions · insights)──► Abstract
 triggers: new finding · new AIG IOC · hourly re-score · score-threshold → SOAR</pre>
 <div class="note">{("<b style='color:" + V.TEAL + "'>Live write-back:</b> field-set <b>" + str(live.get('fieldset_id')) + "</b> + view <b>" + str(live.get('view_id')) + "</b> created on the tenant (" + str(live.get('created_by')) + "); cleaned " + str(live.get('removed', {})) + " prior demo object(s).") if (live and live.get('ok')) else "<b>Offline.</b> Engine numbers produced live by run_demo.py; --mode api writes field-sets/views to the tenant. build_demo.py creates the full 32-view catalog."}
   MTTD / reduction are modeled to illustrate the architecture (constants in <b>pipeline.py</b>), not SLAs.</div>
</main></body></html>"""


def main():
    mode = sys.argv[sys.argv.index("--mode") + 1] if "--mode" in sys.argv else "offline"
    d = compute(mode)
    with open("dashboard.html", "w") as fh:
        fh.write(render(d, mode))
    print(f"wrote dashboard.html (mode={mode}, {len(d['findings'])} findings, "
          f"{len(d['scores'])} scored, {len(d['id_counts'])} identity kinds, "
          f"mitre tactics={len(d['mitre'])})")


if __name__ == "__main__":
    main()
