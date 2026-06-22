"""Self-contained INTERACTIVE dashboard — the full navigation / settings / wizard experience
as one HTML file that opens in ANY browser with NO Jupyter kernel.

`python3 console_app.py`  →  writes console.html (and prints the path).
`build_app(state)`        →  returns the HTML string.

It embeds the real engine State (entities, identity intel, findings, integrations, AI providers,
pivot templates) as JSON and renders it client-side with vanilla JS: sidebar nav across all
views, a Settings panel, a 3-step Setup wizard, entity selection → drill-down + categorized
external-search pivots. The interactive correlation graph (pyvis) and the Plotly panels are
embedded inline (offline). This is the clickable experience to evaluate UX; the ipywidgets
`console.Console` is the live, write-capable runtime in JupyterLab.

All assets inline → no CDN, works offline, opens from disk."""
from __future__ import annotations

import html as _h
import json as _json

import brand
import viz_interactive as VI
import mitre_layer as ML


def _data(state):
    import entity_model as EM
    import identity_intel as II
    import integrations as IN
    import ai_agents as AI
    import enrichment as EN
    import osint_pivots as OP
    import console as C
    from collections import Counter

    model = EM.build_entity_model(state, vips={"jsmith@acme.com", "ceo@acme.example", "cfo@acme.example"})
    ev = EM.evaluate(model)
    summ = II.summary(state, set(model["vip_tags"]))
    pred = summ["predictive"]
    idx = VI._entity_index(state)
    m = state.metrics or {}

    ents = []
    for r in model["entities"]:
        rec = idx.get(r["entity"], {})
        ents.append({"key": r["entity"], "id": r["entity"].split(":", 1)[-1], "kind": r["kind"],
                     "risk": r["model_score"], "vip": r["vip"], "restore": r["survives_restore"],
                     "drivers": [f"{k}={v}" for k, v in r["top_factors"] if v],
                     "fields": {str(k): str(v)[:90] for k, v in list(rec.get("fields", {}).items())[:16]},
                     "neighbors": rec.get("neighbors", [])[:18], "events": rec.get("events", 0),
                     "sources": sorted(rec.get("sources", []))})

    import hunts
    ctx = hunts.make_context(state.norm, state.graph, state.iocs, state.scores)
    hres = hunts.run_all(ctx)
    cat = {c["key"]: c for c in hunts.catalog()}
    hunts_data = [{"title": cat.get(k, {}).get("title", k), "tactic": cat.get(k, {}).get("tactic", ""),
                   "n": len(v), "rows": [{"e": r.get("entity", ""), "why": r.get("why", "")}
                                         for r in v[:5]]} for k, v in hres.items()]

    by_source = Counter(e.source for e in state.norm)
    by_sev = Counter(e.severity for e in state.norm)

    authoring = []
    import abstract_authoring as AA
    for k in AA.LABEL_TO_KIND:
        a = AA.build(k, state=state)
        authoring.append({"kind": k, "diff": a["diff"], "live": a["live_capable"]})

    return {
        "live": state.live, "source": state.source,
        "kpis": [["entities", ev["entities"]], ["high-risk", ev["high_risk"]],
                 ["survives restore", ev["survives_restore"]], ["VIP at risk", ev["vip_at_risk"]],
                 ["SIEM volume cut", f"{m.get('reduction_pct', '—')}%"], ["findings", len(state.findings)]],
        "entities": ents,
        "findings": [{"rule": f.rule, "title": f.title, "risk": f.risk, "sev": f.severity}
                     for f in sorted(state.findings, key=lambda x: -x.risk)[:30]],
        "identity": {
            "reexp": [{"e": r.entity, "n": r.count, "restore": r.survives_restore}
                      for r in summ["re_exposure"][:12]],
            "signals": [{"e": s.entity, "k": s.kind, "d": s.detail, "sc": s.score}
                        for s in (summ["session_hijacking"] + summ["mfa_bombing"]
                                  + summ["password_reuse"] + summ["vip_at_risk"])[:16]],
            "predicted": pred["predicted_next_targets"], "rationale": pred["rationale"]},
        "pipeline": {"source": by_source.most_common(10), "sev": by_sev.most_common(6),
                     "metrics": {k: m.get(k) for k in ("total_events", "forwarded_to_siem",
                                 "reduction_pct", "incidents", "fatigue_reduction_pct")}},
        "hunts": hunts_data,
        "integrations": IN.registry_status(),
        "ai": AI.available(),
        "adapters": EN.available(),
        "stubs": {k: v[2] for k, v in EN.STUBS.items()},
        "authoring": authoring,
        "pivot_tpl": OP._TEMPLATES, "pivot_lbl": C._CATLBL,
        "weights": EM.DEFAULT_WEIGHTS,
    }


def build_app(state) -> str:
    data = _data(state)
    VI._NO_INLINE = True
    top_entity = data["entities"][0]["key"] if data["entities"] else "account:okta:jsmith@acme.com"
    frags = {
        "__VIZ_RISK__": VI.risk_panel(state),
        "__VIZ_EXPO__": VI.exposure_timeline(state),
        "__VIZ_SANKEY__": VI.attack_flow_sankey(state),
        "__VIZ_HEAT__": VI.temporal_heatmap(state),
        "__VIZ_RADAR__": VI.risk_radar(state, top_entity),
        "__VIZ_SUN__": VI.exposure_sunburst(state),
        "__VIZ_TREE__": VI.tactic_treemap(state),
        "__VIZ_MITRE__": ML.matrix_html(state),
    }
    VI._NO_INLINE = False
    graph_doc = VI.correlation_graph(state)
    graph_iframe = (f'<iframe srcdoc="{_h.escape(graph_doc)}" loading="lazy" '
                    f'style="width:100%;height:640px;border:0;border-radius:12px;background:{brand.BG}"></iframe>')

    html_doc = _TEMPLATE
    repl = {
        "__PINK__": brand.PINK, "__PINKMID__": brand.PINK_MID, "__TEAL__": brand.TEAL,
        "__AMBER__": brand.AMBER, "__BLUE__": brand.BLUE, "__BG__": brand.BG,
        "__PANEL__": brand.PANEL, "__INK__": brand.INK, "__MUT__": brand.MUT,
        "__FONT__": brand.FONT_STACK, "__MONO__": brand.MONO_STACK,
        "__LOGO__": brand.logo_svg("white"), "__GRAPHLEGEND__": VI.graph_legend_html(),
        "__PLOTLYJS__": VI.plotlyjs_script(), "__GRAPH__": graph_iframe,
        "__DATA__": _json.dumps(data),
    }
    repl.update(frags)
    for k, v in repl.items():
        html_doc = html_doc.replace(k, v)
    return html_doc


# ── the app (placeholders replaced above; CSS/JS braces stay literal) ─────────────
_TEMPLATE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Abstract AI-SOC Console</title>
__PLOTLYJS__
<style>
:root{--pink:__PINK__;--pink-mid:__PINKMID__;--teal:__TEAL__;--amber:__AMBER__;--blue:__BLUE__;
--bg:__BG__;--panel:__PANEL__;--ink:__INK__;--mut:__MUT__;--line:rgba(255,255,255,.09);
--font:__FONT__;--mono:__MONO__;--display:"Barlow Semi Condensed","Barlow Condensed",__FONT__}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--ink);font-family:var(--font);font-size:14.5px;line-height:1.6;
-webkit-font-smoothing:antialiased;overflow:hidden}
.bg{position:fixed;inset:0;z-index:-3;pointer-events:none}
.bg-mesh{background:radial-gradient(60vw 60vw at 6% -12%,rgba(255,33,107,.16),transparent 60%),
radial-gradient(55vw 55vw at 108% 6%,rgba(1,230,157,.12),transparent 55%),
radial-gradient(70vw 50vw at 50% 122%,rgba(46,155,240,.08),transparent 60%)}
.bg-grid{z-index:-2;opacity:.45;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),
linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:46px 46px;
-webkit-mask-image:radial-gradient(circle at 60% 10%,#000,transparent 80%)}
.app{display:grid;grid-template-columns:236px 1fr;grid-template-rows:64px 1fr;height:100vh}
header{grid-column:1/-1;display:flex;align-items:center;gap:16px;padding:0 22px;border-bottom:1px solid var(--line);
background:linear-gradient(180deg,rgba(255,33,107,.06),transparent);position:relative}
header::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:2px;
background:linear-gradient(90deg,var(--pink),var(--teal),var(--blue),var(--pink));background-size:300% 100%;animation:slide 9s linear infinite}
@keyframes slide{to{background-position:300% 0}}
header .logo svg{height:26px;width:auto;display:block}
header .brandtxt{font-family:var(--display);font-weight:800;font-size:20px;text-transform:uppercase;letter-spacing:.5px;color:#fff}
header .kick{font-family:var(--mono);font-size:10px;letter-spacing:3px;color:var(--teal);text-transform:uppercase}
.spacer{flex:1}
.pill{font-family:var(--mono);font-size:10.5px;font-weight:700;letter-spacing:1.2px;padding:5px 11px;border-radius:999px;border:1px solid;display:inline-flex;align-items:center;gap:7px}
.pill.live{color:var(--teal);border-color:rgba(1,230,157,.4);background:rgba(1,230,157,.07)}
.pill.off{color:var(--amber);border-color:rgba(245,198,30,.4);background:rgba(245,198,30,.07)}
.pill .dot{width:7px;height:7px;border-radius:50%;background:currentColor;animation:pulse 2.4s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(1,230,157,.5)}70%{box-shadow:0 0 0 7px rgba(1,230,157,0)}100%{box-shadow:0 0 0 0 rgba(1,230,157,0)}}
button.wiz{font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:1px;color:var(--bg);background:var(--pink);
border:0;border-radius:999px;padding:7px 14px;cursor:pointer;text-transform:uppercase}
button.wiz:hover{background:var(--pink-mid)}
nav{border-right:1px solid var(--line);padding:14px 10px;overflow-y:auto;background:rgba(255,255,255,.012)}
nav a{display:flex;align-items:center;gap:11px;padding:9px 12px;border-radius:11px;color:var(--mut);
text-decoration:none;font-size:13.5px;cursor:pointer;margin:2px 0;border:1px solid transparent}
nav a .i{width:20px;text-align:center;font-size:15px}
nav a:hover{color:var(--ink);background:rgba(255,255,255,.04)}
nav a.active{color:#fff;background:linear-gradient(120deg,rgba(255,33,107,.22),rgba(1,230,157,.1));border-color:rgba(255,33,107,.4)}
main{overflow-y:auto;padding:24px 28px 60px}
.view{display:none;animation:rise .5s cubic-bezier(.2,.7,.2,1)}
.view.active{display:block}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
h2.vt{font-family:var(--display);font-weight:800;font-size:26px;text-transform:uppercase;letter-spacing:.5px;margin:0 0 4px;color:#fff}
.sub{color:var(--mut);margin:0 0 18px;font-size:13px}
.glass{background:linear-gradient(165deg,rgba(255,255,255,.045),rgba(255,255,255,.012));
backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid var(--line);border-radius:16px;
box-shadow:0 24px 60px -34px rgba(0,0,0,.95),inset 0 1px 0 rgba(255,255,255,.06)}
.panel{padding:18px;margin-bottom:18px;overflow-x:auto}
.eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:2.4px;color:var(--teal);text-transform:uppercase}
.panel h3{font-family:var(--display);font-weight:700;font-size:18px;letter-spacing:.4px;margin:4px 0 12px;color:#fff;text-transform:uppercase}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:18px}
.kpi{padding:16px}.kpi .n{font-family:var(--display);font-weight:800;font-size:34px;line-height:1;color:#fff;text-shadow:0 0 22px rgba(255,33,107,.25)}
.kpi .l{font-family:var(--mono);font-size:10px;letter-spacing:1.3px;text-transform:uppercase;color:var(--mut);margin-top:7px}
.kpi{position:relative;overflow:hidden}.kpi::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--pink),var(--teal))}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--teal);font-family:var(--mono);font-size:10px;letter-spacing:1.4px;text-transform:uppercase;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.05)}
tr.row{cursor:pointer}tr.row:hover{background:rgba(255,33,107,.08)}
.bar{height:11px;border-radius:5px;background:rgba(255,255,255,.07);overflow:hidden}
.bar>span{display:block;height:100%}
.tag{font-family:var(--mono);font-size:10px;padding:2px 7px;border-radius:6px;background:rgba(255,255,255,.07);color:var(--ink)}
.sev-critical{color:var(--pink)}.sev-high{color:var(--amber)}.sev-medium{color:var(--blue)}
.chip{display:inline-block;margin:3px 6px 3px 0;padding:4px 11px;border-radius:999px;background:rgba(255,255,255,.05);
border:1px solid var(--line);color:var(--blue);font-size:11px;text-decoration:none}
.chip:hover{border-color:var(--pink);color:#fff}
.extcat{margin:8px 0}.extlbl{font-family:var(--mono);font-size:10px;letter-spacing:1.4px;color:var(--teal);text-transform:uppercase;margin-bottom:3px}
.split{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.field-k{color:var(--mut);font-family:var(--mono);font-size:11px}.field-v{color:var(--ink);font-family:var(--mono);font-size:11px}
.act{font-family:var(--mono);font-size:11px;font-weight:700;color:var(--ink);background:rgba(255,255,255,.05);
border:1px solid var(--line);border-radius:9px;padding:6px 11px;cursor:pointer;margin:0 6px 6px 0}
.act:hover{border-color:var(--teal);color:#fff}
.inp{width:100%;background:rgba(0,0,0,.35);border:1px solid var(--line);border-radius:9px;color:var(--ink);
padding:8px 11px;font-family:var(--mono);font-size:12px;margin:4px 0}
label.fld{display:block;color:var(--mut);font-size:11px;margin-top:10px;font-family:var(--mono);letter-spacing:.5px}
.ok{color:var(--teal)}.warn{color:var(--amber)}
.overlay{position:fixed;inset:0;background:rgba(4,4,7,.74);backdrop-filter:blur(6px);z-index:50;display:none;align-items:center;justify-content:center}
.overlay.open{display:flex}
.modal{width:min(640px,92vw);max-height:88vh;overflow-y:auto;padding:26px}
.steps{display:flex;gap:8px;margin:6px 0 18px}
.step{flex:1;height:4px;border-radius:3px;background:rgba(255,255,255,.1)}.step.on{background:var(--pink)}
.wstep{display:none}.wstep.on{display:block}
.row-btns{display:flex;justify-content:space-between;margin-top:18px}
footer{grid-column:1/-1;display:none}
@media (max-width:900px){.app{grid-template-columns:1fr}nav{display:none}.split{grid-template-columns:1fr}}
</style></head>
<body>
<div class="bg bg-mesh"></div><div class="bg bg-grid"></div>
<div class="app">
  <header>
    <div class="logo">__LOGO__</div>
    <div><div class="kick">Abstract · AI-SOC</div><div class="brandtxt">Investigation Console</div></div>
    <div class="spacer"></div>
    <span id="statusPill" class="pill off"><span class="dot"></span>OFFLINE</span>
    <button class="wiz" onclick="openWiz()">⚙ Setup wizard</button>
  </header>
  <nav id="nav"></nav>
  <main id="main">
    <section class="view" id="v-overview">
      <h2 class="vt">Overview</h2><p class="sub">Investigation at a glance — KPIs, continuous risk, top findings.</p>
      <div class="kpis"></div>
      <div class="glass panel"><div class="eyebrow">Risk</div><h3>Continuous entity risk</h3>__VIZ_RISK__</div>
      <div class="glass panel"><div class="eyebrow">Detections</div><h3>Top findings</h3>
        <table><thead><tr><th>Risk</th><th>Sev</th><th>Rule</th><th>Title</th></tr></thead><tbody id="findTbl"></tbody></table></div>
    </section>
    <section class="view" id="v-graph">
      <h2 class="vt">Correlation graph</h2><p class="sub">Drag · zoom · hover. Shapes + glyphs per entity kind; edges labeled by relationship.</p>
      <div class="glass panel"><div class="eyebrow">Relationships · Correlation</div>__GRAPHLEGEND__ __GRAPH__</div>
    </section>
    <section class="view" id="v-identity">
      <h2 class="vt">Identity intelligence</h2><p class="sub">Continuous re-exposure (survives restore), hijack, MFA bombing, reuse, predictions.</p>
      <div class="split">
        <div class="glass panel"><div class="eyebrow">Continuous re-exposure</div><h3>Re-exposed identities</h3><ul style="font-size:13px" id="idReexp"></ul></div>
        <div class="glass panel"><div class="eyebrow">Signals</div><h3>Hijack · MFA · reuse · VIP</h3><ul style="font-size:13px" id="idSig"></ul></div>
      </div>
      <div class="glass panel"><div class="eyebrow">Predictive</div><h3>Predicted next targets</h3><p id="idPred"></p></div>
      <div class="glass panel"><div class="eyebrow">Exposure</div><h3>Re-exposure timeline</h3>__VIZ_EXPO__</div>
    </section>
    <section class="view" id="v-investigate">
      <h2 class="vt">Investigate</h2><p class="sub">Select any entity → drill down, pivot, compare, and search the web / actor DBs / dark-web indexes.</p>
      <div class="glass panel">
        <select class="inp" id="entSel" onchange="selectEntity(this.value)" style="max-width:560px"></select>
        <div style="margin:8px 0">
          <button class="act" onclick="show('graph')">🔭 Pivot to graph</button>
          <button class="act" onclick="addCompare()">⚖️ Add to compare</button>
          <span class="field-k">Enrich · cross-ref · author run live in the JupyterLab console.</span></div>
        <div id="entDetail"><i class="sub">Select an entity to drill down.</i></div>
      </div>
      <div id="cmpBox"></div>
    </section>
    <section class="view" id="v-hunt">
      <h2 class="vt">Threat hunting</h2><p class="sub">Reusable hunt catalog over the normalized stream + entity graph.</p>
      <div id="huntBox"></div>
    </section>
    <section class="view" id="v-pipeline">
      <h2 class="vt">Pipeline &amp; metrics</h2><p class="sub">Source / severity mix, efficiency, and activity over time.</p>
      <div class="glass panel"><div class="eyebrow">Efficiency</div><div id="pipeMet" style="margin:6px 0"></div></div>
      <div class="split">
        <div class="glass panel"><div class="eyebrow">By source</div><h3>Events by source</h3><div id="pipeSrc"></div></div>
        <div class="glass panel"><div class="eyebrow">Severity</div><h3>Severity mix</h3><div id="pipeSev"></div></div>
      </div>
      <div class="glass panel"><div class="eyebrow">Temporal</div><h3>Activity heatmap</h3>__VIZ_HEAT__</div>
      <div class="glass panel"><div class="eyebrow">Flow</div><h3>Attack-flow Sankey</h3>__VIZ_SANKEY__</div>
    </section>
    <section class="view" id="v-models">
      <h2 class="vt">Models &amp; predict</h2><p class="sub">Weighted, explainable identity-risk model — click a row to investigate.</p>
      <div class="glass panel"><div class="eyebrow">Ranked</div><h3>Identity risk</h3>
        <table><thead><tr><th>Score</th><th>Entity</th><th>Kind</th><th>Restore</th><th>Drivers</th></tr></thead><tbody id="modelTbl"></tbody></table></div>
      <div class="glass panel"><div class="eyebrow">Calculations</div><h3>Customize weights</h3><div id="weightBox"></div>
        <p class="field-k">Sliders illustrate here; the live console re-scores on change.</p></div>
      <div class="split">
        <div class="glass panel"><div class="eyebrow">Profile</div><h3>Risk radar</h3>__VIZ_RADAR__</div>
        <div class="glass panel"><div class="eyebrow">Exposure</div><h3>By kind → entity</h3>__VIZ_SUN__</div>
      </div>
      <div class="glass panel"><div class="eyebrow">Findings</div><h3>Severity → rule</h3>__VIZ_TREE__</div>
    </section>
    <section class="view" id="v-mitre">
      <h2 class="vt">MITRE ATT&amp;CK</h2><p class="sub">Coverage matrix (live /v3/rules/mitre when connected; modeled offline).</p>
      <div class="glass panel"><div class="eyebrow">Framework</div><h3>Coverage</h3>__VIZ_MITRE__</div>
    </section>
    <section class="view" id="v-enrichment">
      <h2 class="vt">Enrichment fabric</h2><p class="sub">25 adapters — keyless ones live now; add keys for the rest.</p>
      <div class="split">
        <div class="glass panel"><div class="eyebrow">Adapters</div><h3>OSINT · intel · exposure</h3>
          <table><thead><tr><th>Adapter</th><th>Status</th></tr></thead><tbody id="adaptTbl"></tbody></table></div>
        <div class="glass panel"><div class="eyebrow">Pivots</div><h3>Non-API</h3>
          <table><thead><tr><th>Source</th><th>Note</th></tr></thead><tbody id="stubTbl"></tbody></table></div>
      </div>
    </section>
    <section class="view" id="v-authoring">
      <h2 class="vt">Authoring</h2><p class="sub">Dry-run → confirm → apply. Views/field-sets/rules/suppressions/insights apply live; models/schemas/parsers scaffold or export.</p>
      <div class="glass panel"><ul style="font-size:13px" id="authBox"></ul></div>
    </section>
    <section class="view" id="v-settings">
      <h2 class="vt">Settings &amp; integrations</h2><p class="sub">Add a key / endpoint and the tool lights up. Keys here stay in this browser.</p>
      <div class="split">
        <div class="glass panel"><div class="eyebrow">Integrations</div><h3>SIEM · MCP · core</h3>
          <table><thead><tr><th>Integration</th><th>Status</th></tr></thead><tbody id="integTbl"></tbody></table></div>
        <div class="glass panel"><div class="eyebrow">AI providers</div><h3>Summarize · triage</h3>
          <table><thead><tr><th>Provider</th><th>Status</th></tr></thead><tbody id="aiTbl"></tbody></table></div>
      </div>
      <div class="glass panel"><div class="eyebrow">Connect</div><h3>Abstract</h3>
        <label class="fld">ABSTRACT_API_KEY</label><input class="inp" type="password" placeholder="key (browser only)">
        <label class="fld">VENDOR ACCOUNT ID</label><input class="inp" placeholder="X-AS-Vendor-Account-ID">
        <button class="wiz" style="margin-top:12px" onclick="openWiz()">Open setup wizard</button></div>
    </section>
  </main>
</div>

<div class="overlay" id="wiz">
  <div class="modal glass">
    <div class="kick" style="font-family:var(--mono);color:var(--teal);letter-spacing:3px;font-size:10px">GUIDED SETUP</div>
    <h2 class="vt">Connect &amp; launch</h2>
    <div class="steps"><div class="step on"></div><div class="step"></div><div class="step"></div></div>
    <div class="wstep on" data-step="0">
      <p class="sub">Runs offline out of the box. Add an Abstract key (or MCP) to go live.</p>
      <label class="fld">MODE</label>
      <select class="inp" id="wmode"><option value="demo">Offline / demo</option><option value="live">Live Abstract tenant</option></select>
      <div id="wlive" style="display:none">
        <label class="fld">ABSTRACT_API_KEY</label><input class="inp" id="wkey" type="password" placeholder="key (saved to this browser only)">
        <label class="fld">VENDOR ACCOUNT ID</label><input class="inp" id="wacct" placeholder="X-AS-Vendor-Account-ID">
        <label class="fld">API BASE</label><input class="inp" id="wbase" value="https://api.abstractsecurity.app">
      </div>
    </div>
    <div class="wstep" data-step="1">
      <p class="sub">Optional integrations &amp; AI — drop a key and that tool lights up (Sentinel · Splunk · Elastic · Claude · OpenAI · Gemini · …).</p>
      <div id="wkeys"></div>
    </div>
    <div class="wstep" data-step="2">
      <p class="sub">Review &amp; launch. (In JupyterLab this builds State and renders the live console; here it returns you to the dashboard.)</p>
      <div id="wsummary" class="glass panel"></div>
    </div>
    <div class="row-btns">
      <button class="act" onclick="wizBack()">← Back</button>
      <button class="wiz" id="wizNext" onclick="wizNext()">Next →</button>
    </div>
  </div>
</div>

<script>const DATA = __DATA__;</script>
<script>
const VIEWS = [
  ["overview","◆","Overview"],["graph","◈","Graph"],["identity","◉","Identity"],
  ["investigate","◎","Investigate"],["hunt","✦","Hunt"],["pipeline","≋","Pipeline"],
  ["models","◇","Models"],["mitre","▣","MITRE"],["enrichment","☉","Enrichment"],
  ["authoring","✎","Authoring"],["settings","⚙","Settings"]];
const esc=s=>String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const risksort=(a,b)=>b.risk-a.risk;
let CMP=[];

function buildNav(){
  document.getElementById('nav').innerHTML = VIEWS.map(([id,ic,lbl])=>
    `<a data-v="${id}" onclick="show('${id}')"><span class="i">${ic}</span>${lbl}</a>`).join('');
}
function show(id){
  document.querySelectorAll('nav a').forEach(a=>a.classList.toggle('active',a.dataset.v===id));
  document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id==='v-'+id));
  window.dispatchEvent(new Event('resize'));
}
function bars(rows,color){let mx=Math.max(1,...rows.map(r=>r[1]));return rows.map(r=>
  `<div style="display:flex;align-items:center;gap:10px;margin:5px 0;font-size:12px">
   <span style="width:160px;color:var(--ink)">${esc(r[0])}</span>
   <span class="bar" style="flex:1"><span style="width:${Math.round(100*r[1]/mx)}%;background:${color}"></span></span>
   <span style="width:54px;text-align:right;color:var(--mut)">${r[1]}</span></div>`).join('');}

function extLinks(id){
  const q=encodeURIComponent(id);let h='';
  for(const cat in DATA.pivot_tpl){
    h+=`<div class="extcat"><div class="extlbl">${esc(DATA.pivot_lbl[cat]||cat)}</div>`;
    h+=DATA.pivot_tpl[cat].map(([n,t])=>`<a class="chip" target="_blank" href="${t.replace('{q}',q)}">${esc(n)}</a>`).join('');
    h+=`</div>`;}
  return h;
}
function entityDetail(key){
  const e=DATA.entities.find(x=>x.key===key);if(!e)return '<i>select an entity</i>';
  const f=Object.entries(e.fields).map(([k,v])=>`<tr><td class="field-k">${esc(k)}</td><td class="field-v">${esc(v)}</td></tr>`).join('');
  const nb=e.neighbors.map(n=>`<span class="tag">${esc(n)}</span>`).join(' ');
  const sg=DATA.identity.signals.filter(s=>s.e===key).map(s=>`<li>${esc(s.k)} (${s.sc}) — ${esc(s.d)}</li>`).join('')||'<li>none</li>';
  return `<div class="eyebrow">Entity</div><h3>${esc(e.id)}</h3>
   <p class="sub">kind <b>${esc(e.kind)}</b> · risk <b class="ok">${e.risk}</b> · events ${e.events}
   ${e.vip?'· <b>VIP</b>':''} ${e.restore?'· <b class="warn">survives restore</b>':''}</p>
   <div style="margin:6px 0">${e.drivers.map(d=>`<span class="tag">${esc(d)}</span>`).join(' ')}</div>
   <div class="split">
     <div><div class="extlbl">All fields</div><table>${f||'<tr><td>—</td></tr>'}</table>
       <div class="extlbl" style="margin-top:10px">Identity signals</div><ul style="font-size:12px">${sg}</ul>
       <div class="extlbl" style="margin-top:10px">Related (pivot)</div><div>${nb||'—'}</div></div>
     <div><div class="extlbl">External search &amp; corroboration</div>${extLinks(e.id)}</div>
   </div>`;
}
function selectEntity(key){
  document.getElementById('entDetail').innerHTML=entityDetail(key);
  document.getElementById('entSel').value=key;
}
function addCompare(){
  const k=document.getElementById('entSel').value;if(!k)return;
  if(!CMP.includes(k))CMP=[...CMP,k].slice(-2);
  const box=document.getElementById('cmpBox');
  box.innerHTML = CMP.length===2
    ? `<div class="split">${CMP.map(k=>`<div class="glass panel">${entityDetail(k)}</div>`).join('')}</div>`
    : `<p class="sub">Compare: select a second entity then "Add to compare" (have: ${CMP.map(x=>x.split(':').pop()).join(', ')})</p>`;
}

function render(){
  // Overview
  document.getElementById('v-overview').querySelector('.kpis').innerHTML =
    DATA.kpis.map(([l,n])=>`<div class="kpi glass"><div class="n">${n}</div><div class="l">${esc(l)}</div></div>`).join('');
  // Investigate
  const opts=DATA.entities.slice().sort(risksort).map(e=>`<option value="${e.key}">${esc(e.id)} · risk ${e.risk} [${esc(e.kind)}]</option>`).join('');
  document.getElementById('entSel').innerHTML='<option value="">— select an entity —</option>'+opts;
  // Identity
  document.getElementById('idReexp').innerHTML=DATA.identity.reexp.map(r=>
    `<li>${esc(r.e)} — <b>${r.n}×</b>${r.restore?' · <b class="warn">survives restore</b>':''}</li>`).join('')||'<li>none</li>';
  document.getElementById('idSig').innerHTML=DATA.identity.signals.map(s=>
    `<li>${esc(s.e)} — ${esc(s.k)} <b class="sev-critical">(${s.sc})</b> · ${esc(s.d)}</li>`).join('')||'<li>none</li>';
  document.getElementById('idPred').textContent=DATA.identity.predicted.map(p=>p.split(':').pop()).join(', ')||'—';
  // Findings (overview)
  document.getElementById('findTbl').innerHTML=DATA.findings.map(f=>
    `<tr><td><b>${f.risk}</b></td><td class="sev-${f.sev}">${esc(f.sev)}</td><td>${esc(f.rule)}</td><td>${esc(f.title)}</td></tr>`).join('');
  // Pipeline
  document.getElementById('pipeSrc').innerHTML=bars(DATA.pipeline.source,'var(--blue)');
  document.getElementById('pipeSev').innerHTML=bars(DATA.pipeline.sev,'var(--pink)');
  document.getElementById('pipeMet').innerHTML=Object.entries(DATA.pipeline.metrics).map(([k,v])=>`<span class="tag">${esc(k)}: ${esc(v)}</span>`).join(' ');
  // Hunts
  document.getElementById('huntBox').innerHTML=DATA.hunts.map(h=>
    `<div class="glass panel"><div class="eyebrow">${esc(h.tactic)}</div><h3>${esc(h.title)} · ${h.n}</h3>
     <ul style="font-size:12px">${h.rows.map(r=>`<li>${esc(r.e)} — ${esc(r.why)}</li>`).join('')||'<li>no hits</li>'}</ul></div>`).join('');
  // Models
  document.getElementById('modelTbl').innerHTML=DATA.entities.slice().sort(risksort).slice(0,12).map(e=>
    `<tr class="row" onclick="show('investigate');selectEntity('${e.key}')"><td><b>${e.risk}</b></td><td>${esc(e.id)}</td>
     <td>${esc(e.kind)}</td><td>${e.restore?'<span class="warn">yes</span>':''}</td><td>${esc(e.drivers.join(', '))}</td></tr>`).join('');
  document.getElementById('weightBox').innerHTML=Object.entries(DATA.weights).map(([k,v])=>
    `<div style="display:flex;align-items:center;gap:10px;margin:4px 0;font-size:12px"><span style="width:120px">${esc(k)}</span>
     <input type="range" min="0" max="1" step="0.01" value="${v}" style="flex:1"><span class="tag">${v}</span></div>`).join('');
  // Enrichment + Settings
  document.getElementById('adaptTbl').innerHTML=Object.entries(DATA.adapters).map(([n,ok])=>
    `<tr><td>${esc(n)}</td><td>${ok?'<span class="ok">configured</span>':'<span class="warn">add key</span>'}</td></tr>`).join('');
  document.getElementById('stubTbl').innerHTML=Object.entries(DATA.stubs).map(([n,note])=>
    `<tr><td>${esc(n)}</td><td class="warn">${esc(note)}</td></tr>`).join('');
  document.getElementById('integTbl').innerHTML=DATA.integrations.map(s=>
    `<tr><td>${esc(s.name)} <span class="tag">${esc(s.kind)}</span></td>
     <td>${s.configured?'<span class="ok">configured</span>':'<span class="warn">add '+esc((s.needs||[]).join(', ')||'endpoint')+'</span>'}</td></tr>`).join('');
  document.getElementById('aiTbl').innerHTML=Object.entries(DATA.ai).map(([n,ok])=>
    `<tr><td>${esc(n)}</td><td>${ok?'<span class="ok">on</span>':'off'}</td></tr>`).join('');
  document.getElementById('authBox').innerHTML=DATA.authoring.map(a=>
    `<li><b>${esc(a.kind)}</b> ${a.live?'<span class="ok">live</span>':'<span class="warn">scaffold/export</span>'} — <span class="field-k">${esc(a.diff)}</span></li>`).join('');
  // status pill
  const sp=document.getElementById('statusPill');
  if(DATA.live){sp.className='pill live';sp.innerHTML='<span class="dot"></span>LIVE TENANT';}
  else{sp.className='pill off';sp.innerHTML='<span class="dot"></span>'+(DATA.source==='synthetic'?'DEMO ESTATE':'OFFLINE');}
}

// wizard
let wstep=0;
function openWiz(){document.getElementById('wiz').classList.add('open');setWiz(0);
  document.getElementById('wkeys').innerHTML=DATA.integrations.flatMap(s=>s.needs||[]).concat(Object.keys(DATA.ai).map(()=>'')).filter(Boolean)
    .filter((v,i,a)=>a.indexOf(v)===i).map(k=>`<label class="fld">${esc(k)}</label><input class="inp" type="password" placeholder="value (browser only)">`).join('')
    +'<label class="fld">ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY</label><input class="inp" type="password" placeholder="AI provider key">';}
function closeWiz(){document.getElementById('wiz').classList.remove('open');}
function setWiz(n){wstep=n;document.querySelectorAll('.wstep').forEach(s=>s.classList.toggle('on',+s.dataset.step===n));
  document.querySelectorAll('.steps .step').forEach((s,i)=>s.classList.toggle('on',i<=n));
  document.getElementById('wizNext').textContent=n===2?'🚀 Launch':'Next →';
  if(n===2){const mode=document.getElementById('wmode').value;
    document.getElementById('wsummary').innerHTML=`<div class="eyebrow">Summary</div>
      <p>Mode: <b>${mode==='live'?'LIVE Abstract':'Offline / demo'}</b></p>
      <p class="sub">${DATA.entities.length} entities · ${DATA.findings.length} findings · ${DATA.integrations.length} integrations · ${Object.keys(DATA.ai).length} AI providers available.</p>`;}}
function wizNext(){if(wstep<2)setWiz(wstep+1);else closeWiz();}
function wizBack(){if(wstep>0)setWiz(wstep-1);else closeWiz();}
document.addEventListener('change',e=>{if(e.target.id==='wmode')document.getElementById('wlive').style.display=e.target.value==='live'?'block':'none';});

buildNav();render();show('overview');
</script>
</body></html>"""


def main():
    from live_data import build_state
    state = build_state()
    out = build_app(state)
    with open("console.html", "w", encoding="utf-8") as fh:
        fh.write(out)
    print(f"wrote console.html ({len(out):,} bytes) — open in any browser")


def selftest():
    from live_data import build_state
    h = build_app(build_state())
    assert "<title>Abstract AI-SOC Console</title>" in h
    assert "const DATA =" in h and '"entities"' in h
    for tok in ("__DATA__", "__PINK__", "__GRAPH__", "__VIZ_RISK__", "__PLOTLYJS__"):
        assert tok not in h, f"unreplaced {tok}"
    assert "vis-network" in h or "<svg" in h
    assert "Setup wizard" in h and "Investigate" in h and "Settings" in h
    return {"ok": True, "bytes": len(h)}


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        print(selftest())
    else:
        main()
