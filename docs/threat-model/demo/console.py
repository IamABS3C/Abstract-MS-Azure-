"""Operator console — the in-notebook GUI / living dashboard. Split into pure
HTML/preview builders (fully testable headless) and an ipywidgets shell (import-guarded
so this module imports under bare Python).

The shell is a tabbed workspace:
  Overview · Graph · Identity · Investigate · Hunt · Pipeline · MITRE · Enrichment ·
  Authoring · Settings · Actions
with a build progress bar, view-type + layout selectors, entity search/drill-down,
annotations, an integrations/config panel, and dry-run → confirm → apply authoring of
Abstract objects (views/fieldsets/insights live; models/schemas/parsers scaffolded)."""
from __future__ import annotations
import os
import html
import brand
import abstract_authoring as AA

# Graph-tab view registry: label → (viz_interactive fn name, needs_focus)
VIEW_TYPES = [
    ("Network graph", "correlation_graph", False),
    ("Attack-flow Sankey", "attack_flow_sankey", False),
    ("Association matrix", "association_matrix", False),
    ("Entity timeline", "entity_event_timeline", False),
    ("Re-exposure timeline", "exposure_timeline", False),
    ("MITRE matrix", "mitre_matrix", False),
    ("Exposure sunburst", "exposure_sunburst", False),
    ("Findings treemap", "tactic_treemap", False),
    ("Temporal heatmap", "temporal_heatmap", False),
    ("Risk radar (focus)", "risk_radar", True),
]
LAYOUTS = ["force", "hierarchical", "radial", "clustered"]

# Authoring object kinds — sourced from abstract_authoring so the GUI stays in sync with
# what the live API actually supports (view/fieldset/rule/suppression/insight/schema/
# identity-model are live; parser exports a JSON artifact).
AUTHORING_KINDS = list(AA.LABEL_TO_KIND)


# ── pure builders (no ipywidgets, no network) ─────────────────────────────────────
def _badge(state):
    txt = "LIVE tenant" if state.live else "OFFLINE — modeled data"
    col = brand.TEAL if state.live else brand.AMBER
    return (f'<span style="background:{col};color:{brand.BG};padding:2px 9px;border-radius:6px;'
            f'font-weight:700;font-family:{brand.FONT_STACK}">{txt}</span>')


def overview_html(state) -> str:
    m = state.metrics or {}
    kpis = [("findings", len(state.findings)), ("insights", len(state.insights)),
            ("detections", len(state.detections)), ("scored entities", len(state.scores)),
            ("SIEM cut %", m.get("reduction_pct", "—")), ("incidents", m.get("incidents", "—"))]
    cards = "".join(
        f'<div style="background:{brand.PANEL};border:1px solid #1d1d27;border-radius:10px;'
        f'padding:12px 16px;min-width:120px"><div style="font-size:24px;color:{brand.PINK};'
        f'font-weight:800">{v}</div><div style="color:{brand.MUT};font-size:12px">{k}</div></div>'
        for k, v in kpis)
    return (f'<div style="font-family:{brand.FONT_STACK};color:{brand.INK}">{_badge(state)}'
            f'<h2 style="color:{brand.PINK};margin:10px 0">Investigation overview</h2>'
            f'<div style="display:flex;gap:10px;flex-wrap:wrap">{cards}</div></div>')


def identity_html(state, vips=None) -> str:
    import identity_intel as II
    s = II.summary(state, vips or set())
    rex = "".join(
        f'<li>{html.escape(r.entity)} — <b>{r.count}×</b> exposure'
        + (f' · <b style="color:{brand.AMBER}">survives restore</b>' if r.survives_restore else '')
        + '</li>' for r in s["re_exposure"][:10])
    sig = "".join(
        f'<li>{html.escape(x.entity)} — {html.escape(x.kind)} '
        f'<b style="color:{brand.PINK}">({x.score})</b> · {html.escape(x.detail)}</li>'
        for x in (s["session_hijacking"] + s["mfa_bombing"] + s["password_reuse"]
                  + s["vip_at_risk"])[:12])
    pred = s["predictive"]
    nxt = ", ".join(html.escape(p.split(":", 1)[-1]) for p in pred["predicted_next_targets"]) or "—"
    return (f'<div style="font-family:{brand.FONT_STACK};color:{brand.INK}">'
            f'<h3 style="color:{brand.TEAL}">Continuous re-exposure</h3><ul>{rex or "<li>none</li>"}</ul>'
            f'<h3 style="color:{brand.TEAL}">Identity signals (hijack · MFA bombing · reuse · VIP)</h3>'
            f'<ul>{sig or "<li>none</li>"}</ul>'
            f'<h3 style="color:{brand.TEAL}">Predicted next targets</h3><p>{nxt}</p>'
            f'<p style="color:{brand.MUT}">{html.escape(pred["rationale"])}</p></div>')


def enrichment_html(result: dict) -> str:
    recs = "".join(
        f'<li><b style="color:{brand.TEAL}">{html.escape(str(r.get("source", "")))}</b> · '
        f'{html.escape(str(r.get("type", "")))} = {html.escape(str(r.get("value", "")))}</li>'
        for r in result.get("records", []))
    pivots = "".join(
        f'<a href="{html.escape(str(p.get("url", p) if isinstance(p, dict) else p))}" '
        f'target="_blank" style="color:{brand.BLUE};margin-right:10px">'
        f'{html.escape(str(p.get("name", "pivot") if isinstance(p, dict) else p))[:24]}</a>'
        for p in (result.get("pivots") or [])[:10])
    return (f'<div style="font-family:{brand.FONT_STACK};color:{brand.INK}">'
            f'<b>{html.escape(str(result.get("value", "")))}</b> '
            f'({html.escape(str(result.get("kind", "")))}) → sources: '
            f'{", ".join(result.get("sources", [])) or "none"}'
            f'<ul>{recs or "<li>no records (offline / no keys)</li>"}</ul>'
            f'<div style="font-size:12px">{pivots}</div></div>')


def pipeline_html(state) -> str:
    """Pipeline analysis: source breakdown, OCSF classes, severity mix, efficiency."""
    from collections import Counter
    by_source = Counter(ev.source for ev in state.norm)
    by_ocsf = Counter(getattr(ev, "ocsf", "?") for ev in state.norm)
    by_sev = Counter(ev.severity for ev in state.norm)
    m = state.metrics or {}

    def rows(counter, color):
        mx = max(counter.values()) if counter else 1
        return "".join(
            f'<div style="display:flex;align-items:center;gap:8px;margin:3px 0;font-size:12px">'
            f'<span style="width:170px;color:{brand.INK}">{html.escape(str(k))}</span>'
            f'<span style="flex:1;background:#16161e;border-radius:5px;height:12px">'
            f'<span style="display:block;height:100%;width:{int(100*v/mx)}%;background:{color}"></span></span>'
            f'<span style="width:54px;text-align:right;color:{brand.MUT}">{v:,}</span></div>'
            for k, v in counter.most_common(12))
    eff = (f'SIEM volume cut <b style="color:{brand.TEAL}">{m.get("reduction_pct","—")}%</b> · '
           f'fatigue cut <b style="color:{brand.PINK}">{m.get("fatigue_reduction_pct","—")}%</b> · '
           f'{m.get("total_events","—"):,} events → {m.get("forwarded_to_siem","—")} forwarded · '
           f'{m.get("incidents","—")} incident(s)') if m else "no metrics"
    return (f'<div style="font-family:{brand.FONT_STACK};color:{brand.INK}">'
            f'<h3 style="color:{brand.TEAL}">Pipeline efficiency</h3><p>{eff}</p>'
            f'<h3 style="color:{brand.TEAL}">Events by source</h3>{rows(by_source, brand.BLUE)}'
            f'<h3 style="color:{brand.TEAL}">Events by OCSF class</h3>{rows(by_ocsf, brand.TEAL)}'
            f'<h3 style="color:{brand.TEAL}">Severity mix</h3>{rows(by_sev, brand.PINK)}</div>')


def hunt_html(state) -> str:
    """Run the threat-hunting catalog over the normalized stream + graph."""
    import hunts
    ctx = hunts.make_context(state.norm, state.graph, state.iocs, state.scores)
    results = hunts.run_all(ctx)
    cat = {c["key"]: c for c in hunts.catalog()}
    blocks = []
    for key, rows in results.items():
        c = cat.get(key, {})
        items = "".join(
            f'<li>{html.escape(str(r.get("entity","")))} · '
            f'<span style="color:{brand.AMBER}">{html.escape(str(r.get("severity","")))}</span> · '
            f'{html.escape(str(r.get("technique","")))} — {html.escape(str(r.get("why","")))}</li>'
            for r in rows[:8])
        blocks.append(
            f'<div style="margin:8px 0"><b style="color:{brand.PINK}">{html.escape(c.get("title", key))}</b> '
            f'<span style="color:{brand.MUT};font-size:11px">{html.escape(c.get("tactic",""))} · '
            f'{html.escape(c.get("technique",""))} · {len(rows)} hits</span>'
            f'<ul style="font-size:12px;margin:4px 0">{items or "<li>no hits</li>"}</ul></div>')
    return (f'<div style="font-family:{brand.FONT_STACK};color:{brand.INK}">'
            f'<h3 style="color:{brand.TEAL}">Threat-hunting catalog ({len(results)} hunts)</h3>'
            + "".join(blocks) + '</div>')


def settings_html(state) -> str:
    """Integrations / config status — adapters, stubs, MCP, Abstract connection."""
    import enrichment as EN
    avail = EN.available()
    adlist = "".join(
        f'<li>{html.escape(n)} — '
        + (f'<b style="color:{brand.TEAL}">configured</b>' if ok else
           f'<span style="color:{brand.MUT}">needs key</span>') + '</li>'
        for n, ok in avail.items())
    stubs = "".join(
        f'<li>{html.escape(n)} — <span style="color:{brand.AMBER}">{html.escape(note)}</span></li>'
        for n, (_c, _k, note) in EN.STUBS.items())
    mcp_url = os.environ.get("ABSTRACT_MCP_URL", "(bundled stdio server)")
    base = os.environ.get("ABSTRACT_API_BASE", "https://api.abstractsecurity.app")
    keyset = "set" if os.environ.get("ABSTRACT_API_KEY") else "not set"
    return (f'<div style="font-family:{brand.FONT_STACK};color:{brand.INK}">'
            f'<h3 style="color:{brand.TEAL}">Abstract connection</h3>'
            f'<p>{_badge(state)} · API base <code>{html.escape(base)}</code> · '
            f'API key <b>{keyset}</b> · MCP <code>{html.escape(mcp_url)}</code></p>'
            f'<h3 style="color:{brand.TEAL}">Enrichment adapters</h3><ul style="font-size:12px">{adlist}</ul>'
            f'<h3 style="color:{brand.TEAL}">Slice-3 connectors (planned)</h3>'
            f'<ul style="font-size:12px">{stubs}</ul></div>')


def authoring_preview(kind: str, state=None) -> dict:
    """Dry-run payload + diff for an Abstract object — delegates to abstract_authoring so
    views/fieldsets/rules/suppressions/insights/schemas/identity-models produce real live
    payloads (parser exports a JSON artifact)."""
    return AA.build(kind, state=state)


def models_html(state) -> str:
    """Identity-risk model + predictive analytics + threat model, for the Models tab."""
    import entity_model as EM
    m = EM.build_entity_model(state, vips=getattr(state, "vips", set()))
    risks = EM.identity_risk(m, top=10)
    pred = EM.predict(state, m)
    tm = EM.threat_model(state)
    ev = EM.evaluate(m)
    rrows = "".join(
        f"<li>{html.escape(r['entity'])} — <b style='color:{brand.PINK}'>{r['score']}</b> "
        f"({html.escape(r['kind'])}"
        + (" · <b>VIP</b>" if r["vip"] else "")
        + (f" · <b style='color:{brand.AMBER}'>survives restore</b>" if r["survives_restore"] else "")
        + f") · <span style='color:{brand.MUT}'>{html.escape(', '.join(r['drivers']))}</span></li>"
        for r in risks)
    chain = " &rarr; ".join(
        f"{html.escape(s['stage'])} <span style='color:{brand.MUT}'>({s['events']})</span>"
        for s in tm["kill_chain"])
    esc = ", ".join(html.escape(e.split(":", 1)[-1]) for e in pred["escalation_watch"]) or "—"
    sit = pred["situational"]
    return (f"<div style='font-family:{brand.FONT_STACK};color:{brand.INK}'>"
            f"<h3 style='color:{brand.TEAL}'>Identity-risk model (weighted · explainable)</h3>"
            f"<p style='color:{brand.MUT}'>entities {ev['entities']} · high-risk {ev['high_risk']} · "
            f"VIP at risk {ev['vip_at_risk']} · survives restore {ev['survives_restore']} · "
            f"signal coverage {ev['signal_coverage_pct']}%</p><ul>{rrows}</ul>"
            f"<h3 style='color:{brand.TEAL}'>Predictive — escalation watch</h3><p>{esc}</p>"
            f"<p style='color:{brand.MUT}'>{html.escape(pred['rationale'])}</p>"
            f"<h3 style='color:{brand.TEAL}'>Threat model — kill chain "
            f"({sit['principals']} principals)</h3><p>{chain}</p></div>")


def writeback_preview(state, name="[ABS-DEMO] Investigation — console") -> dict:
    """Back-compat alias used by report.py: the Saved-view authoring preview."""
    wb = authoring_preview("Saved view", state)
    wb["payload"]["name"] = name
    wb["action"] = "create_view"
    wb["applied"] = False
    return wb


def selftest():
    from live_data import build_state
    st = build_state(None)
    st.vips = {"jsmith@acme.com"}
    assert "Investigation overview" in overview_html(st)
    assert "re-exposure" in identity_html(st, st.vips).lower()
    assert "Pipeline efficiency" in pipeline_html(st)
    assert "Threat-hunting catalog" in hunt_html(st)
    assert "Enrichment adapters" in settings_html(st)
    assert "Identity-risk model" in models_html(st)
    assert enrichment_html({"value": "1.1.1.1", "kind": "ip", "sources": ["t"],
                            "records": [{"source": "t", "type": "x", "value": "1"}], "pivots": []})
    for k in AUTHORING_KINDS:
        a = authoring_preview(k, st)
        assert "payload" in a and "diff" in a and isinstance(a["live_capable"], bool)
    assert authoring_preview("Saved view", st)["live_capable"] is True
    assert authoring_preview("Parser", st)["live_capable"] is False
    wb = writeback_preview(st)
    assert wb["applied"] is False and wb["action"] == "create_view"
    c = Console(st, vips=st.vips)
    assert c.state is not None and c.connection is None
    return {"ok": True, "views": len(VIEW_TYPES), "layouts": len(LAYOUTS),
            "authoring_kinds": len(AUTHORING_KINDS)}


# ── ipywidgets shell (import-guarded) ─────────────────────────────────────────────
def _widgets():
    import ipywidgets as w
    from IPython.display import HTML, display
    return w, HTML, display


class Console:
    """Tabbed operator dashboard. Headless-constructible; `.show()` builds the widgets.
    `.attach(connection)` enables live write-back (still dry-run → confirm → apply)."""

    def __init__(self, state, vips=None, connection=None):
        self.state = state
        self.vips = set(vips or [])
        self.connection = connection
        self.annotations: dict = {}
        if not hasattr(state, "vips"):
            state.vips = self.vips

    def attach(self, connection):
        self.connection = connection
        return self

    def _render_view(self, view_label, layout, focus):
        import viz_interactive as VI
        fn_name = dict((lbl, fn) for lbl, fn, _ in VIEW_TYPES).get(view_label, "correlation_graph")
        fn = getattr(VI, fn_name)
        if fn_name == "correlation_graph":
            return fn(self.state, focus=focus, layout=layout)
        if fn_name == "risk_radar":
            return fn(self.state, focus or next(iter(self.state.scores), "account:okta:jsmith@acme.com"))
        if fn_name == "entity_event_timeline":
            return fn(self.state, focus)
        return fn(self.state)

    def show(self):
        w, HTML, display = _widgets()
        import viz_interactive as VI
        import mitre_layer as ML
        import enrichment as EN
        st = self.state
        focus = {"key": None}

        progress = w.IntProgress(value=0, min=0, max=11, description="Building…",
                                 bar_style="info", style={"bar_color": brand.PINK})

        def tick(label):
            progress.value += 1
            progress.description = label

        # ── Graph tab: view selector + layout + filter ───────────────────────────
        view_dd = w.Dropdown(options=[lbl for lbl, _, _ in VIEW_TYPES], value="Network graph",
                             description="View:")
        layout_dd = w.Dropdown(options=LAYOUTS, value="force", description="Layout:")
        risk_min = w.IntSlider(value=0, min=0, max=100, step=5, description="Min risk:")
        graph_out = w.Output()

        def draw_graph(*_):
            graph_out.clear_output(wait=True)
            with graph_out:
                display(HTML(self._render_view(view_dd.value, layout_dd.value, focus["key"])))
        view_dd.observe(draw_graph, "value")
        layout_dd.observe(draw_graph, "value")
        graph_tab = w.VBox([w.HBox([view_dd, layout_dd, risk_min]), graph_out])
        tick("Graph")

        # ── Investigate: search / drill-down / enrichment / annotations ──────────
        search = w.Text(placeholder="entity / IP / email / CVE …", description="Find:",
                        continuous_update=False)
        detail_out = w.Output()
        enrich_out = w.Output()

        def do_search(*_):
            val = search.value.strip()
            if not val:
                return
            kind = EN.detect_kind(val)
            key = val if ":" in val else (f"identity:{val}" if "@" in val else None)
            focus["key"] = key or focus["key"]
            detail_out.clear_output(wait=True)
            with detail_out:
                if focus["key"]:
                    display(HTML(VI.entity_detail_html(st, focus["key"])))
                else:
                    display(HTML(f"<i>looked up <b>{html.escape(val)}</b> ({kind})</i>"))
            enrich_out.clear_output(wait=True)
            with enrich_out:
                display(HTML(enrichment_html(EN.enrich_entity(val, kind))))
            draw_graph()
        search.observe(lambda ch: do_search(), "value")
        search_btn = w.Button(description="Lookup + pivot", button_style="info")
        search_btn.on_click(do_search)
        annot = w.Textarea(placeholder="analyst note for the focused entity…", description="Note:")
        annot_btn = w.Button(description="Save note")
        annot_log = w.Output()

        def save_note(*_):
            k = focus["key"] or "investigation"
            self.annotations.setdefault(k, []).append(annot.value)
            annot.value = ""
            annot_log.clear_output(wait=True)
            with annot_log:
                display(HTML("<br>".join(f"<b>{html.escape(kk)}</b>: {html.escape('; '.join(vv))}"
                                         for kk, vv in self.annotations.items())))
        annot_btn.on_click(save_note)
        invest_tab = w.VBox([w.HBox([search, search_btn]), detail_out, enrich_out,
                             w.HBox([annot, annot_btn]), annot_log])
        tick("Investigate")

        # ── Settings / Integrations: set key + reconnect ─────────────────────────
        set_status = w.HTML(settings_html(st))
        key_in = w.Password(placeholder="ABSTRACT_API_KEY (session only)", description="API key:")
        base_in = w.Text(value=os.environ.get("ABSTRACT_API_BASE", "https://api.abstractsecurity.app"),
                         description="API base:")
        acct_in = w.Text(value=os.environ.get("ABSTRACT_ACCOUNT_ID", ""), description="Tenant:")
        connect_btn = w.Button(description="Apply & reconnect", button_style="success")
        connect_out = w.Output()

        def do_connect(*_):
            connect_out.clear_output(wait=True)
            with connect_out:
                if key_in.value:
                    os.environ["ABSTRACT_API_KEY"] = key_in.value      # session only; never printed
                if base_in.value:
                    os.environ["ABSTRACT_API_BASE"] = base_in.value
                if acct_in.value:
                    os.environ["ABSTRACT_ACCOUNT_ID"] = acct_in.value
                try:
                    from abstract_client import AbstractClient
                    c = AbstractClient("api")
                    conn = c.connect()
                    if conn.get("ok"):
                        self.connection = c
                        print("connected:", {k: v for k, v in conn.items() if k != "key"})
                    else:
                        print("connect failed:", conn)
                except Exception as e:   # noqa: BLE001
                    print("offline / error:", str(e)[:120])
                set_status.value = settings_html(st)
        connect_btn.on_click(do_connect)
        settings_tab = w.VBox([set_status, w.HTML("<hr>"), key_in, base_in, acct_in,
                               connect_btn, connect_out])
        tick("Settings")

        # ── Authoring: dry-run → confirm → apply (multi object kind) ─────────────
        kind_dd = w.Dropdown(options=AUTHORING_KINDS, value="Saved view", description="Object:")
        a_dry = w.Button(description="Dry-run", button_style="info")
        a_confirm = w.Checkbox(value=False, description="I confirm this live mutation")
        a_apply = w.Button(description="Apply to tenant", button_style="danger", disabled=True)
        a_out = w.Output()
        a_state = {"prev": None}

        def refresh_apply():
            prev = a_state["prev"]
            a_apply.disabled = not (prev and prev.get("live_capable") and self.connection
                                    and a_confirm.value)

        def on_dry(*_):
            a_out.clear_output(wait=True)
            prev = authoring_preview(kind_dd.value, st)
            a_state["prev"] = prev
            with a_out:
                print(prev["diff"])
                print(prev["payload"])
                if not prev["live_capable"]:
                    print("\n(scaffolded — this object type lands in Slice 2 / API pending; dry-run only)")
                elif not self.connection:
                    print("\n(no live connection — attach in Settings to enable apply)")
            refresh_apply()
        a_confirm.observe(lambda ch: refresh_apply(), "value")
        kind_dd.observe(lambda ch: refresh_apply(), "value")

        def on_apply(*_):
            with a_out:
                prev = a_state["prev"]
                if not (prev and prev.get("live_capable") and self.connection):
                    print("apply unavailable for this object / no connection.")
                    return
                res = AA.apply(self.connection, prev)   # validates rules, routes per kind
                print("applied →", prev["kind"], ":", res)
        a_dry.on_click(on_dry)
        a_apply.on_click(on_apply)
        authoring_tab = w.VBox([
            w.HTML(f'<div style="color:{brand.MUT};font-family:{brand.FONT_STACK}">Create/update '
                   f'Abstract objects. Views · field-sets · insights apply live; identity models · '
                   f'schemas · parsers · suppressions are scaffolded (Slice 2). Always dry-run first.</div>'),
            w.HBox([kind_dd, a_dry]), a_confirm, a_apply, a_out])
        tick("Authoring")

        # ── Actions: investigation write-back ────────────────────────────────────
        dry = w.Button(description="Dry-run write-back", button_style="info")
        confirm = w.Checkbox(value=False, description="I confirm this live mutation")
        apply = w.Button(description="Apply to tenant", button_style="danger", disabled=True)
        act_out = w.Output()

        def refresh_wb():
            apply.disabled = not (self.connection and confirm.value)

        def on_wb_dry(*_):
            act_out.clear_output(wait=True)
            with act_out:
                wb = writeback_preview(st)
                print(wb["diff"])
                print(wb["payload"])
                if not self.connection:
                    print("\n(no live connection — attach in Settings; dry-run only)")
            refresh_wb()
        confirm.observe(lambda ch: refresh_wb(), "value")

        def on_wb_apply(*_):
            with act_out:
                if not self.connection:
                    print("No connection attached.")
                    return
                wb = writeback_preview(st)
                res = self.connection.create_view(wb["payload"])
                print("applied → view id:", (res.get("body") or {}).get("id"), "status:", res.get("status"))
        dry.on_click(on_wb_dry)
        apply.on_click(on_wb_apply)
        actions_tab = w.VBox([w.HTML(f'<div style="color:{brand.MUT}">Write this investigation back '
                                     f'as a saved view. Dry-run first; apply only after confirm.</div>'),
                              dry, confirm, apply, act_out])
        tick("Actions")

        # ── Models / Predict: identity-risk model + threat model + review/optimize ─
        review_btn = w.Button(description="Review & optimize posture", button_style="info")
        review_out = w.Output()

        def on_review(*_):
            import entity_model as EM
            review_out.clear_output(wait=True)
            with review_out:
                rev = AA.review(self.connection, state=st)
                print("posture review" + (" (LIVE)" if rev.get("live") else " (modeled)") + ":")
                for r in rev.get("recommendations", []):
                    print("  •", r)
                m = EM.build_entity_model(st, vips=self.vips)
                opt = EM.optimize(m, st)
                print("\ndata-driven optimized weights:", opt["weights"])
        review_btn.on_click(on_review)
        models_tab = w.VBox([w.HTML(models_html(st)), review_btn, review_out]); tick("Models")

        # ── static tabs ──────────────────────────────────────────────────────────
        overview_tab = w.HTML(overview_html(st)); tick("Overview")
        identity_tab = w.HTML(identity_html(st, self.vips)); tick("Identity")
        hunt_tab = w.HTML(hunt_html(st)); tick("Hunt")
        pipeline_tab = w.HTML(pipeline_html(st)); tick("Pipeline")
        mitre_tab = w.HTML(ML.matrix_html(st)); tick("MITRE")

        tabs = w.Tab(children=[overview_tab, graph_tab, identity_tab, invest_tab, hunt_tab,
                               pipeline_tab, models_tab, mitre_tab, authoring_tab,
                               settings_tab, actions_tab])
        for i, t in enumerate(["Overview", "Graph", "Identity", "Investigate", "Hunt",
                               "Pipeline", "Models", "MITRE", "Authoring", "Settings", "Actions"]):
            tabs.set_title(i, t)
        draw_graph()
        progress.value = progress.max
        progress.description = "Ready"
        progress.bar_style = "success"
        header = w.HTML(f'<h2 style="color:{brand.PINK};font-family:{brand.FONT_STACK};margin:0">'
                        f'Abstract AI-SOC Investigation Console</h2>'
                        f'<div style="color:{brand.MUT};font-family:{brand.FONT_STACK};font-size:12px">'
                        f'living dashboard · {len(VIEW_TYPES)} views · {len(LAYOUTS)} layouts · '
                        f'dry-run-first authoring</div>')
        return w.VBox([header, progress, tabs])


def launch(connection=None, vips=None):
    """Convenience: build state (live if a connected client is passed) and show the console."""
    from live_data import build_state
    return Console(build_state(connection), vips=vips, connection=connection).show()


if __name__ == "__main__":
    print(selftest())
