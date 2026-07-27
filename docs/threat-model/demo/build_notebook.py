#!/usr/bin/env python3
"""
Generator for soc_notebook.ipynb — the Abstract AI-SOC analyst workspace.

Dashboard-first: Run All Cells and the **setup wizard + full console launch at the very top**.
Everything below is the same engine exposed as **interactive** building blocks (ipywidgets +
pyvis/plotly) — no static chart dumps. Keeping the notebook in a generator keeps it
maintainable and proves the content is real (every cell calls the shipped modules).

    python3 build_notebook.py            # (re)writes soc_notebook.ipynb (no outputs)

Validate end-to-end with the env kernel:
    jupyter nbconvert --to notebook --execute --inplace \
        --ExecutePreprocessor.kernel_name=abstract-soc soc_notebook.ipynb
"""
from __future__ import annotations

import os
import nbformat
from nbformat.v4 import new_notebook, new_markdown_cell, new_code_cell

CELLS = []


def md(src):
    CELLS.append(new_markdown_cell(src.strip("\n")))


def code(src, hide=True):
    c = new_code_cell(src.strip("\n"))
    if hide:
        # Dashboard mode: collapse the input by default; the interactive output stays visible.
        c.metadata["jupyter"] = {"source_hidden": True}
    CELLS.append(c)


from brand import logo_svg, PINK, TEAL, MUT
_LOGO = logo_svg("white")  # inline official SVG → renders offline, on-brand


def section(title, phase, howto, useit):
    """Consistent, branded per-section intro: title + phase badge + how-to + what-it's-for."""
    md(f"""### {title}
<span style="background:{PINK};color:#060608;padding:2px 9px;border-radius:6px;font-weight:800;font-size:11px;font-family:'JetBrains Mono',monospace">{phase}</span>

**How:** {howto}
**Use it to:** {useit}""")

# ── Title ─────────────────────────────────────────────────────────────────────────
md(f"""
<div style="height:46px">{_LOGO}</div>

# Abstract AI-SOC Console

### An **extension** to the Abstract Platform — Run ▸ **Run All Cells** and the wizard + dashboard launch right here ⬇️

This **augments** Abstract (it does **not** replace it): hunt · enrich · **research** · validate ·
lookup · context & evaluation — pulling live Insights/detections/analytics from your tenant and
adding outside context. **Keyless external providers work out of the box** (no personal API keys):
EPSS · CISA KEV · NVD · URLhaus · MalwareBazaar · Hudson Rock · ThreatFox · GreyNoise + **live web
search / Wikipedia / page-scrape** that *return real results*, plus one-click deep-links. Add keys
(Sentinel/Splunk/Elastic/VT/AI…) only to light up the extras.

The console is the whole experience (12 tabs); everything below it is the same engine as
**interactive building blocks** (every action shows ⏳ progress + full errors/responses). Runs
**offline** out of the box. *Dashboard mode: code is collapsed — click a bar to read/edit.*

---
**The flow — six phases.** The 12-tab console (up top) does all of them in one pane; the sections
below are the same steps, one at a time:

<code style="font-family:'JetBrains Mono',monospace">1 · Connect&nbsp;→&nbsp;2 · Explore&nbsp;→&nbsp;3 · Investigate&nbsp;→&nbsp;4 · Hunt&nbsp;→&nbsp;5 · Model &amp; AI&nbsp;→&nbsp;6 · Act &amp; Report</code>
""")

# ── THE DASHBOARD + WIZARD (first & foremost) ──────────────────────────────────────
code("""
%matplotlib inline
import warnings; warnings.filterwarnings("ignore")
import os, sys
# Runnable from any location (repo root, the demo dir, or solution/notebooks/): locate the demo modules.
def _find_demo():
    d = os.getcwd()
    for _ in range(7):
        if os.path.isfile(os.path.join(d, "live_data.py")):
            return os.path.abspath(d)
        c = os.path.join(d, "docs", "threat-model", "demo")
        if os.path.isfile(os.path.join(c, "live_data.py")):
            return os.path.abspath(c)
        d = os.path.dirname(d)
    return None
_demo = _find_demo()
if _demo and _demo not in sys.path:
    sys.path.insert(0, _demo)
import pandas as pd
pd.set_option("display.max_colwidth", 80); pd.set_option("display.max_rows", 50)
from IPython.display import display, HTML
import ipywidgets as W

import brand
display(HTML(brand.theme_css()))                       # dark hunter theme — keeps all text high-contrast
from console import setup_wizard                       # full operator console
from live_data import build_state

# ⬇️  Pick Offline / Live, set optional keys, click 🚀 Launch — the 12-tab console renders here.
setup_wizard()
""", hide=False)

md("""
> **Prefer one line?** Run `launch()` for the full console on the offline estate, or
> `launch(client)` once connected. The wizard above does both with a guided UI.

---

## Interactive building blocks
The same engine, broken out as **live widgets** (select / type / click — nothing is a static
image). These share one `state`; the console above is the integrated view of all of them.
""")

# ── shared state + connect ─────────────────────────────────────────────────────────
code("""
state = build_state()                       # offline synthetic estate by default
client = None
try:
    from abstract_client import AbstractClient
    _c = AbstractClient("api")
    if _c.connect().get("ok"):
        client = _c; state = build_state(client)     # LIVE Abstract data
except Exception:
    pass

import viz_interactive as VI, entity_model as EM, abstract_authoring as AA
import enrichment as EN, integrations as IN, osint_pivots as OP, research as RS, hunts
import json as _json, traceback as _tb

def _act(out, label, work):
    \"\"\"Run work() with a ⏳ progress indicator and FULL error+traceback capture into `out`
    so every action surfaces its real response/error for troubleshooting.\"\"\"
    out.clear_output(wait=True)
    with out:
        display(HTML(f"<span style='color:#f5c61e;font-family:JetBrains Mono,monospace'>⏳ {label} …</span>"))
    try:
        r = work()
    except Exception:
        out.clear_output(wait=True)
        with out:
            display(HTML(f"<b style='color:#FF216B'>✗ {label} failed</b>"
                         f"<pre style='color:#ff6b6b;white-space:pre-wrap;font-size:11px'>"
                         f"{_tb.format_exc()[-2000:]}</pre>"))
        return
    out.clear_output(wait=True)
    with out:
        if isinstance(r, str):
            display(HTML(r))
        elif r is not None:
            display(r)

def _pre(obj):                       # pretty JSON block for raw responses/errors
    return "<pre style='white-space:pre-wrap;font-size:11px'>" + _json.dumps(obj, indent=1, default=str)[:2200] + "</pre>"

print(f"state: {state.source}  ·  {len(state.scores)} entities scored  ·  "
      f"{len(state.findings)} findings  ·  {'LIVE' if state.live else 'offline'}")
""")

# ── interactive graph & visuals ─────────────────────────────────────────────────────
section("🕸 Interactive graph &amp; visuals", "Phase 2 · Explore",
        "pick a **View** (network · Sankey · MITRE · sunburst · treemap · timelines · risk) and a **Layout**; focus an entity from the Investigate section to center it here.",
        "see blast radius, attack flow, and MITRE coverage gaps at a glance.")
code("""
_VIEWS = {
    "Network graph":        lambda: VI.correlation_graph(state, layout=_layout.value, focus=_focus["k"]),
    "Attack-flow Sankey":   lambda: VI.attack_flow_sankey(state),
    "Association matrix":   lambda: VI.association_matrix(state),
    "Re-exposure timeline": lambda: VI.exposure_timeline(state),
    "Entity timeline":      lambda: VI.entity_event_timeline(state, _focus["k"]),
    "MITRE coverage":       lambda: VI.mitre_matrix(state),
    "Exposure sunburst":    lambda: VI.exposure_sunburst(state),
    "Findings treemap":     lambda: VI.tactic_treemap(state),
    "Temporal heatmap":     lambda: VI.temporal_heatmap(state),
    "Continuous risk":      lambda: VI.risk_panel(state),
}
_focus = {"k": None}
_view   = W.Dropdown(options=list(_VIEWS), description="View:")
_layout = W.Dropdown(options=["force", "hierarchical", "radial", "clustered"], description="Layout:")
_gout   = W.Output()
def _draw(*_):
    _act(_gout, "rendering " + _view.value, lambda: _VIEWS[_view.value]())
_view.observe(_draw, "value"); _layout.observe(_draw, "value"); _draw()
display(W.VBox([W.HBox([_view, _layout]), _gout]))
""")

# ── interactive entity investigator ─────────────────────────────────────────────────
section("🔎 Investigate any entity", "Phase 3 · Investigate",
        "search/pick an entity → drill-down detail, **🌐 Enrich** (keyless intel), **🛰 Cross-ref SIEM/MCP**, and open curated OSINT pivots.",
        "build the who/what/where of a suspect identity, host, or IOC fast.")
code("""
_idx = VI._entity_index(state)
_all_ents = sorted(_idx, key=lambda k: -_idx[k].get("risk", 0))
_efind = W.Text(placeholder="filter by kind / id / risk…", description="Search:",
                continuous_update=False, layout=W.Layout(width="560px"))
_esel  = W.Dropdown(options=_all_ents or ["(none)"], description="Entity:", layout=W.Layout(width="560px"))
_enr   = W.Button(description="🌐 Enrich", button_style="info")
_xrf   = W.Button(description="🛰 Cross-ref SIEM/MCP")
_eout  = W.Output()
def _filter(*_):
    q = _efind.value.lower().strip()
    opts = [k for k in _all_ents
            if q in (k + " " + _idx[k].get("kind", "") + " r" + str(_idx[k].get("risk", 0))).lower()]
    _esel.options = opts or ["(no match)"]
def _ent_detail(*_):
    _focus["k"] = _esel.value if _esel.value in _idx else None
    _eout.clear_output(wait=True)
    with _eout:
        if not _focus["k"]:
            display(HTML("<i>no entity selected</i>")); return
        display(HTML(VI.entity_detail_html(state, _esel.value)))
        for cat, items in OP.entity_pivots(_esel.value).items():
            display(HTML(f"<b style='color:#01e69d'>{cat}</b> · " +
                         " · ".join(f"<a href='{i['url']}' target='_blank'>{i['name']}</a>" for i in items)))
def _ent_enrich(*_):
    v = (_esel.value or "").split(":", 1)[-1]
    _act(_eout, f"enrich {v}", lambda: _pre(EN.enrich_entity(v, EN.detect_kind(v))))
def _ent_xref(*_):
    v = (_esel.value or "").split(":", 1)[-1]
    _act(_eout, f"cross-ref {v}", lambda: _pre(IN.lookup_all(v, EN.detect_kind(v)) or {"note": "no configured SIEM/MCP — add creds in Settings"}))
_efind.observe(_filter, "value"); _esel.observe(_ent_detail, "value")
_enr.on_click(_ent_enrich); _xrf.on_click(_ent_xref); _ent_detail()
display(W.VBox([_efind, W.HBox([_esel, _enr, _xrf]), _eout]))
""")

# ── bidirectional Sentinel / Azure-MS MCP console ────────────────────────────────────
section("🔷 Sentinel &amp; Azure-MS — two-way console", "Phase 3 · Investigate",
        "**◀ Read** from Microsoft Sentinel (Log Analytics KQL) · **▶ write back** the finding as an Abstract insight *or* a Sentinel incident comment/bookmark · **🔌 call** the Sentinel / Security-Copilot MCP. The focused entity seeds the query.",
        "close the loop both ways between Abstract and Microsoft Sentinel — read evidence, push verdicts/notes, discover MCP tools. (Large result sets are truncated in-cell.)")
code("""
# Two-way bridge: READ (KQL) ←→ WRITE (Abstract insight · Sentinel incident/bookmark) ←→ MCP.
# Degrades offline — with no keys each pane shows exactly which env vars to set; Abstract dry-runs.
_sent_read  = IN.get("Microsoft Sentinel (Log Analytics)")
_sent_write = IN.get("Microsoft Sentinel Incidents (ARM)")
def _seed_kql():
    ent = (_focus.get("k") or "").split(":", 1)[-1]
    return (f'search "{ent}"\\n| take 20') if ent else "AbstractEventLogs_CL\\n| take 20"
_kql     = W.Textarea(value=_seed_kql(), description="KQL:", layout=W.Layout(width="660px", height="80px"))
_kql_btn = W.Button(description="◀ Read from Sentinel", button_style="info")
_kql_out = W.Output()
_kql_btn.on_click(lambda *_: _act(_kql_out, "Sentinel KQL", lambda: _pre(_sent_read.search(_kql.value))))

# ▶ write-back → Abstract (Sentinel evidence becomes an Abstract insight; dry-run → apply)
_ta_dry = W.Button(description="▶ Draft Abstract insight")
_ta_app = W.Button(description="▶ Create in Abstract", button_style="danger", disabled=(client is None))
_ta_out = W.Output()
def _to_abstract(apply_it):
    def work():
        built = AA.build("Insight", state=state)
        return _pre(built if not apply_it else (AA.apply(client, built) if client else {"note": "connect a tenant first"}))
    _act(_ta_out, "insight " + ("apply" if apply_it else "dry-run"), work)
_ta_dry.on_click(lambda *_: _to_abstract(False)); _ta_app.on_click(lambda *_: _to_abstract(True))

# ▶ write-back → Sentinel incident (ARM); an explicit authorize checkbox gates the write
_inc_list = W.Button(description="▶ List incidents")
_inc_id   = W.Text(placeholder="incident name/id", description="Incident:", layout=W.Layout(width="340px"))
_inc_txt  = W.Text(placeholder="comment to write back…", description="Comment:", layout=W.Layout(width="440px"))
_inc_ok   = W.Checkbox(value=False, description="authorize write to Sentinel")
_inc_btn  = W.Button(description="▶ Add comment", button_style="danger")
_inc_out  = W.Output()
_inc_list.on_click(lambda *_: _act(_inc_out, "list incidents", lambda: _pre(_sent_write.list_incidents())))
def _inc_comment(*_):
    if not _inc_ok.value:
        _act(_inc_out, "authorize", lambda: "<b style='color:#f5c61e'>tick ‘authorize’ first</b>"); return
    _act(_inc_out, "add comment", lambda: _pre(_sent_write.add_comment(_inc_id.value, _inc_txt.value)))
_inc_btn.on_click(_inc_comment)

# 🔌 Azure / MS MCP — discover tools on the Sentinel MCP / Security Copilot MCP
_mcp_pick  = W.Dropdown(options=["Microsoft Sentinel MCP", "Security Copilot MCP"], description="MCP:")
_mcp_btn   = W.Button(description="🔌 List MCP tools")
_mcp_out   = W.Output()
_mcp_btn.on_click(lambda *_: _act(_mcp_out, "MCP tools", lambda: pd.DataFrame(IN.get(_mcp_pick.value).list_tools())))

display(W.VBox([
    W.HTML("<b style='color:#01e69d'>◀ Read — Microsoft Sentinel (Log Analytics KQL)</b>"), _kql, _kql_btn, _kql_out,
    W.HTML("<b style='color:#FF216B'>▶ Write back → Abstract insight</b>"), W.HBox([_ta_dry, _ta_app]), _ta_out,
    W.HTML("<b style='color:#FF216B'>▶ Write back → Sentinel incident (ARM)</b>"),
    _inc_list, W.HBox([_inc_id, _inc_txt]), W.HBox([_inc_ok, _inc_btn]), _inc_out,
    W.HTML("<b style='color:#8a8a99'>🔌 Azure / MS MCP</b>"), W.HBox([_mcp_pick, _mcp_btn]), _mcp_out,
]))
""")

# ── interactive hunt runner ──────────────────────────────────────────────────────────
section("🎯 Threat-hunt runner", "Phase 4 · Hunt",
        "run the **whole catalog** or a single hunt against the current estate; results table shows entity · severity · technique · why.",
        "surface ATO, C2 beaconing, lateral movement, and exfil across the estate.")
code("""
_ctx  = hunts.make_context(state.norm, state.graph, state.iocs, state.scores)
_hmap = {c["title"]: c["key"] for c in hunts.catalog()}
_hsel = W.Dropdown(options=["(all hunts)"] + list(_hmap), description="Hunt:", layout=W.Layout(width="520px"))
_hout = W.Output()
def _run_hunt(*_):
    def work():
        res = hunts.run_all(_ctx) if _hsel.value == "(all hunts)" else {_hmap[_hsel.value]: hunts.run(_hmap[_hsel.value], _ctx)}
        rows = [{"hunt": k, **{kk: vv for kk, vv in r.items() if kk in ("entity", "severity", "technique", "why")}}
                for k, v in res.items() for r in v]
        return pd.DataFrame(rows) if rows else HTML("<i>no hits</i>")
    _act(_hout, "running " + _hsel.value, work)
_hsel.observe(_run_hunt, "value"); _run_hunt()
display(W.VBox([_hsel, _hout]))
""")

# ── interactive lookup (any indicator / actor) ──────────────────────────────────────
section("🌐 Research any indicator or actor", "Phase 4 · Hunt",
        "type an **IP / domain / hash / email / CVE / APT or ransomware group** → live web + Wikipedia + intel + one-click pivots (keyless, returns real scraped results).",
        "get real outside context on an IOC or threat actor without any personal API keys.")
code("""
_q    = W.Text(placeholder="IP / domain / hash / email / CVE / APT or ransomware group…",
               description="Lookup:", continuous_update=False, layout=W.Layout(width="620px"))
_qbtn = W.Button(description="Enrich + pivots", button_style="info")
_qout = W.Output()
def _do_q(*_):
    v = _q.value.strip()
    if not v: return
    def work():
        r = RS.research_entity(v)                       # keyless: returns REAL web + wiki results
        out, wk = "", r["wikipedia"]
        if wk.get("ok") and wk.get("extract"):
            out += (f"<div><b style='color:#01e69d'>📖 {wk['title']}</b> — {wk['extract'][:380]} "
                    f"<a href='{wk.get('url','')}' target='_blank'>↗</a></div>")
        if r["web"]:
            out += ("<div style='margin-top:6px'><b style='color:#01e69d'>🔎 Web (live, scraped)</b>"
                    "<ul style='font-size:12px'>" + "".join(
                    f"<li><a href='{w['url']}' target='_blank'>{(w['title'] or '')[:80]}</a> — "
                    f"{(w['snippet'] or '')[:150]}</li>" for w in r["web"]) + "</ul></div>")
        out += "<div style='margin-top:6px'><b style='color:#01e69d'>🛰 Intel</b>" + _pre(EN.enrich_entity(v)) + "</div>"
        for cat, items in OP.entity_pivots(v).items():
            out += (f"<div><b style='color:#8a8a99'>{cat} (open)</b> · "
                    + " · ".join(f"<a href='{i['url']}' target='_blank'>{i['name']}</a>" for i in items) + "</div>")
        return out
    _act(_qout, f"research {v}", work)
_qbtn.on_click(_do_q); _q.observe(lambda ch: _do_q(), "value")
display(W.VBox([W.HBox([_q, _qbtn]), _qout]))
""")

# ── AI assist + posture review ───────────────────────────────────────────────────────
section("🤖 AI assist &amp; posture", "Phase 5 · Model &amp; AI",
        "**Summarize investigation** · **Triage** · **Review &amp; optimize model** (uses Claude/OpenAI/Gemini if a key is set, else a capable offline fallback).",
        "get an analyst-grade narrative + data-driven risk-model tuning.")
code("""
import ai_agents as AI
_ai_sum = W.Button(description="Summarize investigation", button_style="info")
_ai_tri = W.Button(description="Triage")
_ai_rev = W.Button(description="Review & optimize model")
_ai_out = W.Output()
def _ai(action):
    def work():
        if action == "review":
            rev = AA.review(client, state=state)
            out = "<b>recommendations</b><ul>" + "".join(f"<li>{r}</li>" for r in rev.get("recommendations", [])) + "</ul>"
            return out + "<b>data-driven optimized weights</b>" + _pre(EM.optimize(EM.build_entity_model(state), state)["weights"])
        r = (AI.triage if action == "triage" else AI.summarize_investigation)(state)
        return f"<b>[{r['provider']}]</b><pre style='white-space:pre-wrap'>{r['text']}</pre>"
    _act(_ai_out, action, work)
_ai_sum.on_click(lambda *_: _ai("summarize")); _ai_tri.on_click(lambda *_: _ai("triage")); _ai_rev.on_click(lambda *_: _ai("review"))
display(W.VBox([W.HBox([_ai_sum, _ai_tri, _ai_rev]), _ai_out]))
""")

# ── Ask ASTRO — free-form NL console ──────────────────────────────────────────────────
section("🧠 Ask ASTRO", "Phase 5 · Model &amp; AI",
        "type a question in plain English → ASTRO gathers tool context (extracts IOCs → keyless intel) then answers via your configured LLM (Claude/OpenAI/Gemini/Azure/Bedrock) or a grounded offline synthesis.",
        "ask the investigation anything — 'who's most at risk and why', 'what do I contain first', 'is 52.20.10.5 known-bad' — and get an analyst-grade answer.")
code("""
import ai_agents as AI
_astro_q   = W.Text(placeholder="e.g. which identities are most at risk and why? what do I contain first?",
                    description="Ask ASTRO:", continuous_update=False, layout=W.Layout(width="720px"))
_astro_btn = W.Button(description="🧠 Ask", button_style="info")
_astro_out = W.Output()
def _astro(*_):
    q = _astro_q.value.strip()
    if not q:
        return
    def work():
        iocs = RS.extract_iocs(q)
        if isinstance(iocs, dict):
            flat = [v for vs in iocs.values() if isinstance(vs, (list, tuple)) for v in vs]
        else:
            flat = list(iocs) if isinstance(iocs, (list, tuple)) else []
        extra = ""
        for ioc in flat[:3]:                                  # agentic: enrich the IOCs the question implies
            extra += f"\\n[intel {ioc}] " + _json.dumps(EN.enrich_entity(ioc), default=str)[:400]
        r = AI.answer_question(state, q, extra_context=extra)
        note = (f"<div style='color:#8a8a99;font-size:11px'>tool context: {len(flat)} IOC(s) enriched</div>"
                if flat else "")
        return (f"<div><b style='color:#01e69d'>[{r.get('provider','?')}]</b></div>"
                f"<pre style='white-space:pre-wrap'>{r['text']}</pre>{note}")
    _act(_astro_out, f"ASTRO · {q[:40]}", work)
_astro_btn.on_click(_astro); _astro_q.observe(lambda ch: _astro(), "value")
display(W.VBox([W.HBox([_astro_q, _astro_btn]), _astro_out]))
""")

# ── predictive & data-science ─────────────────────────────────────────────────────────
section("🔮 Predictive &amp; data-science", "Phase 5 · Model &amp; AI",
        "unsupervised **anomaly ranking** (PyOD) · model risk ranking · **escalation watch** + predicted next targets · a per-entity **risk forecast** (dashed projection). No keys required.",
        "surface the entities the weighted score alone misses, and see where risk is heading next.")
code("""
_pm      = EM.build_entity_model(state, vips=getattr(state, "vips", set()))
_pv_ent  = W.Dropdown(options=[r["entity"] for r in _pm["entities"]] or ["(none)"],
                      description="Entity:", layout=W.Layout(width="520px"))
_pv_fc   = W.Button(description="🔮 Forecast risk", button_style="info")
_pv_an   = W.Button(description="📈 Anomalies + prediction")
_pv_out  = W.Output()
_pv_fc.on_click(lambda *_: _act(_pv_out, "forecast", lambda: VI.forecast_chart(state, _pv_ent.value)))
def _pv_anoms(*_):
    def work():
        rows = sorted(_pm["entities"], key=lambda r: -r.get("anomaly", 0))[:12]
        pred = EM.predict(state, _pm); sit = pred["situational"]
        head = (f"<div style='color:#01e69d'>principals {sit['principals']} · high-risk {sit['high_risk']} · "
                f"survives-restore {sit['survives_restore']}</div>"
                f"<div style='color:#8a8a99;font-size:12px'>escalation watch: "
                f"{', '.join(e.split(':',1)[-1] for e in pred['escalation_watch'][:6]) or 'none'} · "
                f"predicted next: {', '.join(p.split(':',1)[-1] for p in pred['predicted_next_targets']) or 'none'}</div>")
        df = pd.DataFrame([{"entity": r["entity"], "kind": r["kind"], "model_score": r["model_score"],
                            "anomaly": r.get("anomaly", 0), "survives_restore": r["survives_restore"]} for r in rows])
        return head + (df.to_html(index=False) if not df.empty else "<i>no entities</i>")
    _act(_pv_out, "anomalies + prediction", work)
_pv_an.on_click(_pv_anoms)
display(W.VBox([W.HBox([_pv_ent, _pv_fc, _pv_an]), _pv_out]))
""")

# ── authoring (dry-run → apply) ──────────────────────────────────────────────────────
section("✍️ Author Abstract objects", "Phase 6 · Act",
        "pick an object (view · detection · insight · **data model** · **identity model** · tuning filter) → **Dry-run** → **Apply to tenant** (enabled when connected live).",
        "turn findings into real Abstract content in your tenant — safely, dry-run first.")
code("""
_akind = W.Dropdown(options=list(AA.LABEL_TO_KIND), description="Object:", layout=W.Layout(width="360px"))
_adry  = W.Button(description="Dry-run", button_style="info")
_aapp  = W.Button(description="Apply to tenant", button_style="danger", disabled=(client is None))
_aout  = W.Output()
def _a_dry(*_):
    _act(_aout, f"dry-run {_akind.value}", lambda: _pre(AA.build(_akind.value, state=state)))
def _a_apply(*_):
    _act(_aout, f"apply {_akind.value}",
         lambda: _pre(AA.apply(client, AA.build(_akind.value, state=state)) if client else {"note": "connect a tenant first"}))
_adry.on_click(_a_dry); _aapp.on_click(_a_apply)
display(W.VBox([W.HBox([_akind, _adry, _aapp]), _aout]))
""")

# ── detection · verdict · insight workflows ──────────────────────────────────────────
section("⚙️ Detection · verdict · insight workflows", "Phase 6 · Act",
        "author a **detection** from an editable field/op/value condition → **dry-run → create (DISABLED)**; set an analyst **verdict** on a live insight; **update** an insight. Writes enable only when connected to a tenant.",
        "turn a hunt result into a real detection and record the analyst decision back on the tenant's insight — safely, dry-run first.")
code("""
# --- detection from an editable condition (dry-run → create DISABLED) ---
_wf_field = W.Text(value="severity", description="Field:", layout=W.Layout(width="230px"))
_wf_op    = W.Dropdown(options=["EQUALS", "NOT_EQUALS", "CONTAINS", "GREATER_THAN", "LESS_THAN"], description="Op:")
_wf_val   = W.Text(value="critical", description="Value:", layout=W.Layout(width="230px"))
_wf_dry   = W.Button(description="Dry-run detection", button_style="info")
_wf_app   = W.Button(description="Create (disabled) in tenant", button_style="danger", disabled=(client is None))
_wf_out   = W.Output()
def _wf_detect(apply_it):
    def work():
        built = AA.build("Detection rule", state=state,
                         conditions=[(_wf_field.value, _wf_op.value, _wf_val.value)])
        return _pre(built if not apply_it else (AA.apply(client, built) if client else {"note": "connect a tenant first"}))
    _act(_wf_out, "detection " + ("apply" if apply_it else "dry-run"), work)
_wf_dry.on_click(lambda *_: _wf_detect(False)); _wf_app.on_click(lambda *_: _wf_detect(True))

# --- verdict on a live insight (nanoids present only when connected) ---
_live_ins = [i.get("nanoid") or i.get("id") for i in (getattr(state, "insights", None) or []) if isinstance(i, dict)]
_vi_sel   = W.Dropdown(options=_live_ins or ["(no live insights — connect a tenant)"],
                       description="Insight:", layout=W.Layout(width="420px"))
_vi_verd  = W.Combobox(placeholder="verdict (tenant-specific)", ensure_option=False, description="Verdict:",
                       options=["MALICIOUS", "BENIGN", "SUSPICIOUS", "FALSE_POSITIVE"])
_vi_dry   = W.Button(description="Dry-run verdict")
_vi_app   = W.Button(description="Set verdict", button_style="danger", disabled=(client is None or not _live_ins))
_vi_out   = W.Output()
def _vi(apply_it):
    nid = _vi_sel.value if _live_ins else None
    def work():
        return _pre(AA.verdict_preview(nid, _vi_verd.value) if not apply_it
                    else AA.apply_verdict(client, nid, _vi_verd.value))
    _act(_vi_out, "verdict " + ("apply" if apply_it else "dry-run"), work)
_vi_dry.on_click(lambda *_: _vi(False)); _vi_app.on_click(lambda *_: _vi(True))

display(W.VBox([
    W.HTML("<b style='color:#01e69d'>Author a detection (editable condition)</b>"),
    W.HBox([_wf_field, _wf_op, _wf_val]), W.HBox([_wf_dry, _wf_app]), _wf_out,
    W.HTML("<b style='color:#01e69d'>Set an analyst verdict on a live insight</b>"),
    W.HBox([_vi_sel, _vi_verd]), W.HBox([_vi_dry, _vi_app]), _vi_out,
]))
""")

# ── report export + MCP ───────────────────────────────────────────────────────────────
section("📄 Export branded report · 🔌 MCP tools", "Phase 6 · Report",
        "choose a **report scope** (full · or a single phase) → generate branded **HTML + Markdown**; also list/call the Abstract **MCP tools**.",
        "produce a client-ready investigation outbrief, whole or per-phase.")
code("""
import report
_rscope = W.Dropdown(options=list(report.PHASES), value="Full report", description="Report scope:",
                     layout=W.Layout(width="360px"))
_rbtn = W.Button(description="📄 Generate report", button_style="info")
_mbtn = W.Button(description="🔌 List + call MCP tools")
_rout = W.Output()
def _gen_report(*_):
    def work():
        scope = _rscope.value
        slug = "".join(ch if ch.isalnum() else "_" for ch in scope.lower())
        htmlf, mdf = f"investigation_report_{slug}.html", f"investigation_report_{slug}.md"
        open(htmlf, "w").write(report.scoped_html(state, scope))
        open(mdf, "w").write(report.scoped_markdown(state, scope))
        return HTML(f"wrote <b>{htmlf}</b> (open in any browser) + {mdf}"
                    f"<div style='color:#8a8a99;font-size:12px'>scope: <b>{scope}</b> — "
                    f"pick another scope to export just that phase, or <b>Full report</b> for everything.</div>")
    _act(_rout, f"generating report — {_rscope.value}", work)
def _mcp(*_):
    def work():
        from mcp_client import AbstractMCP
        m = AbstractMCP()
        df = pd.DataFrame([t for t in m.list_tools() if "name" in t])
        return df[["name", "description"]] if "name" in df.columns else HTML("MCP status: " + str(m.status()))
    _act(_rout, "MCP tools", work)
_rbtn.on_click(_gen_report); _mbtn.on_click(_mcp)
display(W.VBox([W.HBox([_rscope, _rbtn, _mbtn]), _rout]))
""")

# ── roadmap power-tools (keyless libs) ────────────────────────────────────────────────
section("🧪 Power-tools",
        "Phase 5 · Model &amp; AI",
        "**Sigma → Abstract** (detection-as-code) · **ATT&amp;CK actor intel** (attackcti/TAXII) · **IOC extract** (msticpy) · **Cytoscape** interactive graph — all keyless.",
        "author detections from Sigma, pull adversary TTPs, extract IOCs from any report, and explore the graph interactively.")
code("""
import sigma_tools as SG, attack_intel as AK
# Detection-as-code: Sigma rule → Abstract conditions + view payload
_sig = W.Textarea(value=SG.SAMPLE, description="Sigma:", layout=W.Layout(width="660px", height="150px"))
_sigbtn = W.Button(description="Sigma → Abstract", button_style="info")
_sigout = W.Output()
_sigbtn.on_click(lambda *_: _act(_sigout, "compile Sigma", lambda: _pre(SG.sigma_to_abstract(_sig.value))))
# ATT&CK actor intel (first call fetches MITRE over TAXII, keyless)
_akq = W.Text(placeholder="actor / group — e.g. Lazarus Group, LockBit, FIN7", description="Actor:")
_akbtn = W.Button(description="ATT&CK group intel")
_akout = W.Output()
_akbtn.on_click(lambda *_: _act(_akout, "ATT&CK lookup (first call downloads MITRE)", lambda: _pre(AK.find_group(_akq.value))))
# IOC extractor (msticpy IoCExtract → regex fallback)
_iocq = W.Textarea(placeholder="paste advisory / report text…", description="Text:", layout=W.Layout(width="660px", height="90px"))
_iocbtn = W.Button(description="Extract IOCs")
_iocout = W.Output()
_iocbtn.on_click(lambda *_: _act(_iocout, "extract IOCs", lambda: _pre(RS.extract_iocs(_iocq.value))))
# Cytoscape interactive graph (ipycytoscape)
_cybtn = W.Button(description="🕸 Cytoscape graph", button_style="info")
_cyout = W.Output()
def _cy(*_):
    _cyout.clear_output(wait=True)
    with _cyout:
        cg = VI.cytoscape_graph(state)
        display(cg if cg is not None else HTML("<i>ipycytoscape not installed</i>"))
_cybtn.on_click(_cy)
display(W.VBox([W.HTML("<b>Detection-as-code — Sigma → Abstract</b>"), _sig, _sigbtn, _sigout,
               W.HTML("<b>ATT&CK actor intel</b>"), W.HBox([_akq, _akbtn]), _akout,
               W.HTML("<b>IOC extractor</b>"), _iocq, _iocbtn, _iocout,
               W.HTML("<b>Cytoscape graph</b>"), _cybtn, _cyout]))
""")

# ── closing ───────────────────────────────────────────────────────────────────────────
md("""
---
### The closed loop
```
 Abstract pipeline ──(REST · MCP)──► this console ──(views · field-sets · insights · rules · reports)──► Abstract
   triggers: new finding · new AIG IOC · hourly re-score · score-threshold → SOAR / agent
```
**Live** (with a key): tenant views/insights, MITRE coverage, OSINT/SIEM enrichment, MCP calls,
authoring write-back. **Modeled in-engine**: replay, continuous scoring, prediction, sub-agents.
Same engine powers the browser app — `./run.sh --serve` (fully-live, no kernel) or `--app` (static).
""")

# ─────────────────────────────────────────────────────────────────────────────────────
nb = new_notebook(cells=CELLS, metadata={
    "kernelspec": {"name": "abstract-soc", "display_name": "Abstract AI-SOC", "language": "python"},
    "language_info": {"name": "python"},
})

if __name__ == "__main__":
    targets = ["soc_notebook.ipynb"]
    # keep the packaged solution copy in sync (it uses the path-bootstrap above to find the modules)
    _sol = os.path.join(os.path.dirname(__file__), "..", "..", "..", "solution", "notebooks", "soc_notebook.ipynb")
    if os.path.isdir(os.path.dirname(_sol)):
        targets.append(os.path.abspath(_sol))
    for t in targets:
        nbformat.write(nb, t)
    print(f"wrote {len(targets)} copy/ies — {len(CELLS)} cells "
          f"({sum(1 for c in CELLS if c.cell_type == 'code')} code, "
          f"{sum(1 for c in CELLS if c.cell_type == 'markdown')} markdown): " + ", ".join(targets))
