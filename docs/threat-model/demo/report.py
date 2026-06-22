"""Investigation report generator — turns the model's findings into an analyst-ready
incident report (Markdown + a self-contained, officially-branded HTML artifact that
embeds the live interactive visuals + Identity Intelligence), and can write the
investigation back to Abstract as a saved view.

  python3 report.py                 # write investigation_report.md + .html
  python3 report.py --writeback     # DRY-RUN: preview the exact view payload + diff
  python3 report.py --writeback --apply   # actually POST it to the tenant

The HTML is fully self-contained (all JS/CSS inline, official fonts with system
fallback, no CDN) so it opens anywhere and prints clean to PDF."""
from __future__ import annotations

import html
import sys

import brand
import identities as ID
import identity_intel as II
import viz_interactive as VI
import mitre_layer as ML
from live_data import build_state


def build():
    return build_state(None)


def markdown(state) -> str:
    inv = state.inv or {}
    sc = inv.get("subagents", {}).get("scoping", {})
    idn = inv.get("subagents", {}).get("identity", {})
    pred = inv.get("prediction", {})
    findings, scores, metrics, iocs = state.findings, state.scores, state.metrics, state.iocs
    lead = inv.get("lead_finding")
    summ = II.summary(state, vips={"jsmith@acme.com"})
    out = []
    A = out.append
    A("# Incident Report — Qakbot-style intrusion (model demo)\n")
    if lead is not None:
        A(f"**Lead finding:** {lead.title}  ")
        A(f"**Severity:** critical · **Risk:** {lead.risk}/100 · "
          f"**Triage:** {inv.get('triage', {}).get('verdict', '—')}\n")
    A("## Executive summary\n")
    A("A malware verdict corroborated by endpoint execution and C2 beaconing, with an identity "
      "authenticating from the same C2 infrastructure (account takeover). Detected in-stream "
      f"before landing. **{len(sc.get('victims', []))} entities** implicated; "
      f"**{len(pred.get('predicted_next_targets', []))}** predicted next targets.\n")

    A("## Detections (shift-left)\n")
    for f in findings[:8]:
        A(f"- **[{f.risk}] {f.rule}** — {f.title}  \n  _{f.detail}_")
    A("")

    A("## Identity Intelligence\n")
    A("**Continuous re-exposure**")
    for r in summ["re_exposure"][:6]:
        flag = " — **survives IDP/backup restore**" if r.survives_restore else ""
        A(f"- `{r.entity}` — {r.count}× exposure{flag}")
    sigs = summ["session_hijacking"] + summ["mfa_bombing"] + summ["password_reuse"] + summ["vip_at_risk"]
    if sigs:
        A("\n**Signals**")
        for s in sigs[:8]:
            A(f"- `{s.entity}` — {s.kind} ({s.score}): {s.detail}")
    A("")

    A("## Blast radius\n")
    A(f"- **Real-time:** {', '.join(p.split(':',1)[1] for p in sc.get('realtime', [])) or '—'}")
    A(f"- **Historical (replay):** {', '.join(p.split(':',1)[1] for p in sc.get('historical', [])) or '—'}")
    A("")

    A("## Prediction\n")
    A(f"- **Predicted next targets:** "
      f"{', '.join(p.split(':',1)[1] for p in pred.get('predicted_next_targets', [])) or '—'}")
    A(f"- _{pred.get('rationale', '')}_\n")

    A("## Continuous risk (top entities)\n")
    for k, s in list(scores.items())[:6]:
        A(f"- `{k}` — {s.get('final', 0)} (trend {s.get('trend', 0):+})")
    A("")

    A("## OSINT enrichment\n")
    for kind, vals in (("ip", iocs.ips), ("domain", iocs.domains), ("hash", iocs.hashes)):
        for val in list(vals)[:1]:
            tools = ", ".join(list(ID.osint_enrich(val, kind).keys())[:8])
            A(f"- **{kind}** `{val}` → {tools}")
    A("")

    if idn.get("compromised_principals"):
        A("## Recommended actions\n")
        for a in idn.get("recommended_actions", []):
            A(f"- {a}")
    A("")

    A("## Efficiency vs. SIEM-first\n")
    if metrics:
        A(f"- SIEM volume cut **{metrics.get('reduction_pct')}%** "
          f"({metrics.get('total_events'):,} → {metrics.get('forwarded_to_siem')})")
        A(f"- Alert fatigue cut **{metrics.get('fatigue_reduction_pct')}%** "
          f"({metrics.get('raw_alerts')} alerts → {metrics.get('incidents')} incident)")
    A("> Model demo. Verdict fusion / entity correlation / identity intelligence mirror what "
      "Abstract produces; replay, scoring, prediction run in the local engine.")
    return "\n".join(out)


def _md_to_html(md_text: str) -> str:
    import re
    h = html.escape(md_text)
    h = re.sub(r'^# (.+)$', r'<h1>\1</h1>', h, flags=re.M)
    h = re.sub(r'^## (.+)$', r'<h2>\1</h2>', h, flags=re.M)
    h = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', h)
    h = re.sub(r'`(.+?)`', r'<code>\1</code>', h)
    h = re.sub(r'^- (.+)$', r'<li>\1</li>', h, flags=re.M)
    return h.replace("\n\n", "<br>")


def html_report(state) -> str:
    import entity_model as EM
    from datetime import datetime
    body = _md_to_html(markdown(state))

    # interactive visuals: include Plotly's JS ONCE (not per panel)
    VI._NO_INLINE = True
    panels = [("Continuous entity risk", "Risk", VI.risk_panel(state)),
              ("Identity re-exposure timeline", "Exposure", VI.exposure_timeline(state)),
              ("Attack-flow", "Flow", VI.attack_flow_sankey(state)),
              ("MITRE ATT&CK coverage", "Framework", ML.matrix_html(state))]
    VI._NO_INLINE = False
    plotly_js = VI.plotlyjs_script()

    graph_doc = VI.correlation_graph(state)        # full HTML doc → isolate in an iframe srcdoc
    graph_iframe = (f'<iframe srcdoc="{html.escape(graph_doc)}" loading="lazy" '
                    f'style="width:100%;height:660px;border:0;border-radius:12px;'
                    f'background:{brand.BG}"></iframe>')
    blast = VI.blast_radius(state)
    legend = VI.graph_legend_html()
    logo = brand.logo_svg("white")

    model = EM.build_entity_model(state, vips={"jsmith@acme.com", "ceo@acme.example", "cfo@acme.example"})
    ev = EM.evaluate(model)
    m = state.metrics or {}
    lead = (state.inv or {}).get("lead_finding")
    kpis = [("entities modeled", ev["entities"]), ("high-risk", ev["high_risk"]),
            ("survives restore", ev["survives_restore"]), ("VIP at risk", ev["vip_at_risk"]),
            ("SIEM volume cut", f"{m.get('reduction_pct', '—')}%"), ("findings", len(state.findings))]
    kpi_html = "".join(f'<div class="kpi"><div class="kpi-n">{v}</div>'
                       f'<div class="kpi-l">{html.escape(str(k))}</div></div>' for k, v in kpis)

    def panel(title, eyebrow, frag, *, wide=False, delay=0.0):
        cls = "panel reveal scroll" + (" wide" if wide else "")
        return (f'<section class="{cls}" style="animation-delay:{delay:.2f}s">'
                f'<div class="eyebrow">{html.escape(eyebrow)}</div>'
                f'<h3>{html.escape(title)}</h3>{frag}</section>')

    main_html = (panel("Entity correlation graph", "Relationships · Correlation",
                       f'<div class="legend">{legend}</div>{graph_iframe}', wide=True, delay=.12)
                 + panel("Patient zero → replay", "Blast radius", blast, delay=.18)
                 + "".join(panel(t, e, f, delay=.22 + i * .04) for i, (t, e, f) in enumerate(panels)))

    live = state.live
    status = "LIVE TENANT" if live else ("DEMO ESTATE" if state.source == "synthetic" else "OFFLINE")
    gen = datetime.now().strftime("%Y-%m-%d %H:%M")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Investigation Report — Abstract</title>
{plotly_js}
<style>
:root{{--pink:{brand.PINK};--pink-mid:{brand.PINK_MID};--teal:{brand.TEAL};--amber:{brand.AMBER};
--blue:{brand.BLUE};--bg:{brand.BG};--panel:{brand.PANEL};--ink:{brand.INK};--mut:{brand.MUT};--line:#1d1d27;
--display:"Barlow Semi Condensed","Barlow Condensed",{brand.FONT_STACK};--body:{brand.FONT_STACK};--mono:{brand.MONO_STACK}}}
*{{box-sizing:border-box}} html{{scroll-behavior:smooth}}
body{{margin:0;background:var(--bg);color:var(--ink);font-family:var(--body);font-size:15px;
line-height:1.65;-webkit-font-smoothing:antialiased;position:relative;min-height:100vh}}
.bg{{position:fixed;inset:0;z-index:-3;pointer-events:none}}
.bg-mesh{{background:radial-gradient(60vw 60vw at 8% -10%,rgba(255,33,107,.16),transparent 60%),
radial-gradient(55vw 55vw at 105% 8%,rgba(1,230,157,.12),transparent 55%),
radial-gradient(70vw 50vw at 50% 120%,rgba(46,155,240,.08),transparent 60%)}}
.bg-grid{{z-index:-2;opacity:.5;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),
linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:46px 46px;
-webkit-mask-image:radial-gradient(circle at 50% 25%,#000,transparent 85%);
mask-image:radial-gradient(circle at 50% 25%,#000,transparent 85%)}}
.bg-grain{{z-index:-1;opacity:.05;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='2'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")}}
.wrap{{max-width:1180px;margin:0 auto;padding:0 28px 64px}}
header.top{{position:relative;z-index:5;display:flex;align-items:center;gap:18px;padding:18px 28px;
background:linear-gradient(180deg,rgba(255,33,107,.06),transparent);border-bottom:1px solid var(--line)}}
header.top::after{{content:"";position:absolute;left:0;right:0;bottom:-1px;height:2px;
background:linear-gradient(90deg,var(--pink),var(--teal),var(--blue),var(--pink));
background-size:300% 100%;animation:slide 9s linear infinite}}
@keyframes slide{{to{{background-position:300% 0}}}}
header.top .logo svg{{height:30px;width:auto;display:block}}
.title-block .kicker{{font-family:var(--mono);font-size:11px;letter-spacing:3px;color:var(--teal);text-transform:uppercase}}
.title-block h1{{font-family:var(--display);font-weight:800;font-size:30px;line-height:1;margin:2px 0 0;
text-transform:uppercase;letter-spacing:.5px;color:#fff}}
.spacer{{flex:1}}
.pill{{font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:1.5px;padding:5px 11px;
border-radius:999px;border:1px solid;display:inline-flex;align-items:center;gap:7px}}
.pill.live{{color:var(--teal);border-color:rgba(1,230,157,.4);background:rgba(1,230,157,.07)}}
.pill.off{{color:var(--amber);border-color:rgba(245,198,30,.4);background:rgba(245,198,30,.07)}}
.pill .dot{{width:7px;height:7px;border-radius:50%;background:currentColor;animation:pulse 2.4s infinite}}
.gen{{font-family:var(--mono);font-size:11px;color:var(--mut)}}
@keyframes pulse{{0%{{box-shadow:0 0 0 0 rgba(1,230,157,.5)}}70%{{box-shadow:0 0 0 7px rgba(1,230,157,0)}}100%{{box-shadow:0 0 0 0 rgba(1,230,157,0)}}}}
.hero{{padding:42px 0 6px}}
.hero .lead{{font-family:var(--display);font-weight:700;font-size:clamp(28px,4.6vw,48px);line-height:1.02;
letter-spacing:.4px;margin:0;max-width:20ch;text-transform:uppercase}}
.hero .lead em{{font-style:normal;color:var(--pink)}}
.hero .sub{{color:var(--mut);max-width:64ch;margin:14px 0 0}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:30px 0 8px}}
.kpi{{position:relative;background:linear-gradient(160deg,rgba(255,255,255,.05),rgba(255,255,255,.012));
backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
border:1px solid rgba(255,255,255,.09);border-radius:14px;padding:18px;overflow:hidden;
box-shadow:inset 0 1px 0 rgba(255,255,255,.07)}}
.kpi::before{{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--pink),var(--teal))}}
.kpi-n{{font-family:var(--display);font-weight:800;font-size:38px;line-height:1;color:#fff;text-shadow:0 0 22px rgba(255,33,107,.25)}}
.kpi-l{{font-family:var(--mono);font-size:10.5px;letter-spacing:1.4px;text-transform:uppercase;color:var(--mut);margin-top:8px}}
main{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}}
.panel{{background:linear-gradient(165deg,rgba(255,255,255,.045),rgba(255,255,255,.012));
backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
border:1px solid rgba(255,255,255,.09);border-radius:16px;padding:18px;position:relative;
box-shadow:0 24px 60px -34px rgba(0,0,0,.95),inset 0 1px 0 rgba(255,255,255,.06)}}
.panel.wide{{grid-column:1/-1}} .panel.scroll{{overflow-x:auto}}
.panel.wide::before{{content:"";position:absolute;inset:-1px;border-radius:16px;padding:1px;z-index:-1;
background:linear-gradient(120deg,rgba(255,33,107,.5),rgba(1,230,157,.4),transparent 60%);
-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
-webkit-mask-composite:xor;mask-composite:exclude}}
.eyebrow{{font-family:var(--mono);font-size:10px;letter-spacing:2.4px;color:var(--teal);text-transform:uppercase}}
.panel h3{{font-family:var(--display);font-weight:700;font-size:19px;letter-spacing:.4px;margin:4px 0 12px;color:#fff;text-transform:uppercase}}
.legend{{margin-bottom:8px}}
.narrative{{grid-column:1/-1;background:linear-gradient(165deg,rgba(255,255,255,.04),rgba(255,255,255,.01));
backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,.09);
border-radius:16px;padding:14px 32px 30px;box-shadow:inset 0 1px 0 rgba(255,255,255,.05)}}
.narrative h1{{font-family:var(--display);font-weight:800;text-transform:uppercase;letter-spacing:.5px;font-size:26px;
color:var(--pink);border-bottom:1px solid var(--line);padding-bottom:10px}}
.narrative h2{{font-family:var(--mono);color:var(--teal);font-size:12px;text-transform:uppercase;letter-spacing:2.2px;
margin:30px 0 8px;padding-left:12px;border-left:3px solid var(--pink)}}
.narrative code{{font-family:var(--mono);background:#16161e;padding:1px 6px;border-radius:5px;font-size:12.5px;color:#d7d7e6}}
.narrative b{{color:#fff}} .narrative li{{margin:4px 0}}
.reveal{{opacity:0;transform:translateY(14px);animation:rise .7s cubic-bezier(.2,.7,.2,1) forwards}}
@keyframes rise{{to{{opacity:1;transform:none}}}}
footer{{margin-top:42px;padding-top:18px;border-top:1px solid var(--line);color:var(--mut);font-family:var(--mono);font-size:11px;letter-spacing:.6px}}
footer b{{color:var(--ink)}}
@media (max-width:820px){{main{{grid-template-columns:1fr}}}}
@media (prefers-reduced-motion:reduce){{.reveal{{animation:none;opacity:1;transform:none}}.pill .dot{{animation:none}}}}
@media print{{.bg{{display:none}}header.top::after{{animation:none}}body{{background:#fff;color:#111}}
.panel,.narrative,.kpi{{break-inside:avoid;box-shadow:none;background:#fff;border-color:#ddd;
backdrop-filter:none;-webkit-backdrop-filter:none}}.reveal{{animation:none;opacity:1;transform:none}}}}
</style></head>
<body>
<div class="bg bg-mesh"></div><div class="bg bg-grid"></div><div class="bg bg-grain"></div>
<header class="top">
  <div class="logo">{logo}</div>
  <div class="title-block"><div class="kicker">Abstract · AI-SOC</div><h1>Investigation Report</h1></div>
  <div class="spacer"></div>
  <span class="pill {'live' if live else 'off'}"><span class="dot"></span>{status}</span>
  <span class="gen">generated {gen}</span>
</header>
<div class="wrap">
  <section class="hero reveal">
    <div class="lead">Identity-centric intrusion — <em>convicted, correlated, contained.</em></div>
    <p class="sub">{html.escape(lead.title) if lead else 'Investigation'} — malware verdict corroborated by
    endpoint &amp; C2, with account takeover and identity re-exposure that survives IDP / immutable-backup
    restore. Live interactive graph, blast radius, predictive risk and ATT&amp;CK coverage below.</p>
  </section>
  <section class="kpis reveal" style="animation-delay:.06s">{kpi_html}</section>
  <main>{main_html}
    <section class="narrative reveal" style="animation-delay:.42s">{body}</section>
  </main>
  <footer>ABSTRACT SECURITY · AI-SOC INVESTIGATION CONSOLE · self-contained / offline ·
  <b>{status}</b> · modeled-vs-live boundary per DEMO-CATALOG.md</footer>
</div>
</body></html>"""


def main():
    state = build()
    md = markdown(state)
    with open("investigation_report.md", "w", encoding="utf-8") as fh:
        fh.write(md)
    h = html_report(state)
    with open("investigation_report.html", "w", encoding="utf-8") as fh:
        fh.write(h)
    print(f"wrote investigation_report.md ({len(md)} chars) + investigation_report.html ({len(h)} bytes)")

    if "--writeback" in sys.argv:
        import console
        wb = console.writeback_preview(state)
        print("\n── DRY-RUN write-back ──")
        print(wb["diff"])
        print(wb["payload"])
        if "--apply" not in sys.argv:
            print("\n(dry-run only — re-run with --apply to POST to the tenant)")
            return
        from abstract_client import AbstractClient
        c = AbstractClient("api")
        c.connect()
        res = c.create_view(wb["payload"])
        print("applied → view id:", (res.get("body") or {}).get("id"), "status:", res.get("status"))


def selftest():
    import re
    state = build()
    h = html_report(state)
    # self-contained: no element LOADS an external asset (CDN script/style/font/image).
    # (License URLs inside inlined JS are fine; the pyvis doc is escaped inside an iframe.)
    assert not re.search(r'<script[^>]+\bsrc\s*=', h), "external <script src> present"
    assert not re.search(r'<link\b', h), "external <link> stylesheet present"
    assert not re.search(r'url\(\s*["\']?https?://', h), "external CSS url() present"
    assert not re.search(r'<img[^>]+src\s*=\s*["\']https?://', h), "external image present"
    assert "Abstract" in h and ("vis-network" in h or "<svg" in h)
    assert "Identity Intelligence" in h
    return {"ok": True, "bytes": len(h), "live": state.live}


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        print(selftest())
    else:
        main()
