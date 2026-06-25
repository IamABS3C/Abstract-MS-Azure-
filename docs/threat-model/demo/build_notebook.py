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


from brand import logo_svg
_LOGO = logo_svg("white")  # inline official SVG → renders offline, on-brand

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
""")

# ── THE DASHBOARD + WIZARD (first & foremost) ──────────────────────────────────────
code("""
%matplotlib inline
import warnings; warnings.filterwarnings("ignore")
import pandas as pd
pd.set_option("display.max_colwidth", 80); pd.set_option("display.max_rows", 50)
from IPython.display import display, HTML
import ipywidgets as W

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
md("### 🕸 Interactive graph & visuals — switch view + layout")
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
md("### 🔎 Investigate any entity — drill-down + enrich + external pivots")
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

# ── interactive hunt runner ──────────────────────────────────────────────────────────
md("### 🎯 Threat-hunt runner — run the catalog or a single hunt")
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
md("### 🌐 Research any indicator or actor — keyless live web + Wikipedia + intel (returns scraped results, not just links)")
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
md("### 🤖 AI assist & posture — summarize / triage / optimize (offline fallback if no key)")
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

# ── authoring (dry-run → apply) ──────────────────────────────────────────────────────
md("### ✍️ Author Abstract objects — dry-run → confirm → apply (live when connected)")
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

# ── report export + MCP ───────────────────────────────────────────────────────────────
md("### 📄 Export branded report · 🔌 MCP tools")
code("""
_rbtn = W.Button(description="📄 Generate branded report", button_style="info")
_mbtn = W.Button(description="🔌 List + call MCP tools")
_rout = W.Output()
def _gen_report(*_):
    def work():
        import report
        open("investigation_report.html", "w").write(report.html_report(state))
        open("investigation_report.md", "w").write(report.markdown(state))
        return HTML("wrote <b>investigation_report.html</b> (open in any browser) + investigation_report.md")
    _act(_rout, "generating branded report", work)
def _mcp(*_):
    def work():
        from mcp_client import AbstractMCP
        m = AbstractMCP()
        df = pd.DataFrame([t for t in m.list_tools() if "name" in t])
        return df[["name", "description"]] if "name" in df.columns else HTML("MCP status: " + str(m.status()))
    _act(_rout, "MCP tools", work)
_rbtn.on_click(_gen_report); _mbtn.on_click(_mcp)
display(W.VBox([W.HBox([_rbtn, _mbtn]), _rout]))
""")

# ── roadmap power-tools (keyless libs) ────────────────────────────────────────────────
md("### 🧪 Power-tools — detection-as-code (pySigma) · ATT&CK actor intel (attackcti) · "
   "IOC extract (msticpy) · Cytoscape graph (all keyless)")
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
    nbformat.write(nb, "soc_notebook.ipynb")
    print(f"wrote soc_notebook.ipynb — {len(CELLS)} cells "
          f"({sum(1 for c in CELLS if c.cell_type == 'code')} code, "
          f"{sum(1 for c in CELLS if c.cell_type == 'markdown')} markdown)")
