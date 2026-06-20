"""Operator console — the in-notebook GUI. Split into pure HTML/preview builders
(fully testable headless) and an ipywidgets shell (import-guarded so this module
imports under bare Python). The shell offers a tabbed workspace with a graph
view-type selector + layout switcher + filters, entity search/drill-down, per-entity
detail with pivots, annotations, and a dry-run → confirm → apply write-back."""
from __future__ import annotations
import html
import brand

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
        f'{" · <b style=\"color:"+brand.AMBER+"\">survives restore</b>" if r.survives_restore else ""}</li>'
        for r in s["re_exposure"][:10])
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


def writeback_preview(state, name="[ABS-DEMO] Investigation — console") -> dict:
    """Dry-run ONLY: build the exact saved-view payload + a human diff. No network."""
    payload = {"name": name,
               "query": [{"id": "q1", "depth": 0, "field": "severity", "index": 0,
                          "value": "critical", "parentId": None, "fieldType": "String",
                          "field_operation": "EQUALS", "subFieldOperation": ""}],
               "fields": ["type", "@timestamp", "severity", "user_name", "source_address", "message"],
               "order_by": "@timestamp", "order_type": "DESC"}
    diff = (f"CREATE view '{name}'  (+{len(payload['fields'])} fields, 1 query clause; "
            f"severity == critical)")
    return {"action": "create_view", "payload": payload, "diff": diff, "applied": False}


def selftest():
    from live_data import build_state
    st = build_state(None)
    st.vips = {"jsmith@acme.com"}
    assert "Investigation overview" in overview_html(st)
    assert "re-exposure" in identity_html(st, st.vips).lower()
    assert enrichment_html({"value": "1.1.1.1", "kind": "ip", "sources": ["t"],
                            "records": [{"source": "t", "type": "x", "value": "1"}], "pivots": []})
    wb = writeback_preview(st)
    assert wb["applied"] is False and wb["action"] == "create_view"
    c = Console(st, vips=st.vips)
    assert c.state is not None and c.connection is None
    return {"ok": True, "views": len(VIEW_TYPES), "layouts": len(LAYOUTS)}


# ── ipywidgets shell (import-guarded) ─────────────────────────────────────────────
def _widgets():
    import ipywidgets as w
    from IPython.display import HTML, display
    return w, HTML, display


class Console:
    """Tabbed operator console. Headless-constructible; `.show()` builds the widgets.
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

        # ── Graph tab: view selector + layout + filters ──────────────────────────
        view_dd = w.Dropdown(options=[lbl for lbl, _, _ in VIEW_TYPES],
                             value="Network graph", description="View:")
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

        # ── search / drill-down / enrichment ─────────────────────────────────────
        search = w.Text(placeholder="entity / IP / email / CVE …", description="Find:",
                        continuous_update=False)
        detail_out = w.Output()
        enrich_out = w.Output()

        def do_search(*_):
            val = search.value.strip()
            if not val:
                return
            kind = EN.detect_kind(val)
            key = val if ":" in val else f"identity:{val}" if "@" in val else None
            focus["key"] = key or focus["key"]
            detail_out.clear_output(wait=True)
            with detail_out:
                if focus["key"]:
                    display(HTML(VI.entity_detail_html(st, focus["key"])))
                else:
                    display(HTML(f"<i>looked up <b>{val}</b> ({kind})</i>"))
            enrich_out.clear_output(wait=True)
            with enrich_out:
                display(HTML(enrichment_html(EN.enrich_entity(val, kind))))
            draw_graph()
        search.observe(lambda ch: do_search(), "value")   # fires on Enter (continuous_update=False)
        search_btn = w.Button(description="Lookup + pivot", button_style="info")
        search_btn.on_click(do_search)

        # annotations
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

        # ── Actions tab: dry-run → confirm → apply ───────────────────────────────
        dry = w.Button(description="Dry-run write-back", button_style="info")
        confirm = w.Checkbox(value=False, description="I confirm this live mutation")
        apply = w.Button(description="Apply to tenant", button_style="danger", disabled=True)
        act_out = w.Output()

        def refresh_apply():
            apply.disabled = not (self.connection and confirm.value)

        def on_dry(*_):
            act_out.clear_output(wait=True)
            with act_out:
                wb = writeback_preview(st)
                print(wb["diff"])
                print(wb["payload"])
                if not self.connection:
                    print("\n(no live connection attached — dry-run only. "
                          "Console(state, connection=client) to enable apply.)")
            refresh_apply()
        confirm.observe(lambda ch: refresh_apply(), "value")

        def on_apply(*_):
            with act_out:
                if not self.connection:
                    print("No connection attached.")
                    return
                wb = writeback_preview(st)
                res = self.connection.create_view(wb["payload"])
                print("applied → view id:", (res.get("body") or {}).get("id"), "status:", res.get("status"))
        dry.on_click(on_dry)
        apply.on_click(on_apply)
        actions_tab = w.VBox([w.HTML(f'<div style="color:{brand.MUT}">Write the investigation back '
                                     f'to Abstract as a saved view. Dry-run first; apply only after '
                                     f'an explicit confirm.</div>'), dry, confirm, apply, act_out])

        # ── assemble tabs ────────────────────────────────────────────────────────
        ana = w.HTML(f'<pre style="color:{brand.INK}">{html.escape(str(st.analytics))}</pre>')
        insights_html = w.HTML(f'<pre style="color:{brand.INK}">{len(st.insights)} insights · '
                               f'{len(st.detections)} detections (live)</pre>')
        tabs = w.Tab(children=[
            w.HTML(overview_html(st)), graph_tab, insights_html, ana,
            w.HTML(identity_html(st, self.vips)), invest_tab,
            w.HTML(ML.matrix_html(st)), actions_tab])
        for i, t in enumerate(["Overview", "Graph", "Insights/Detections", "Analytics",
                               "Identity", "Investigate", "MITRE", "Actions"]):
            tabs.set_title(i, t)
        draw_graph()
        header = w.HTML(f'<h2 style="color:{brand.PINK};font-family:{brand.FONT_STACK};margin:0">'
                        f'Abstract AI-SOC Investigation Console</h2>')
        return w.VBox([header, tabs])


def launch(connection=None, vips=None):
    """Convenience: build state (live if a connected client is passed) and show the console."""
    from live_data import build_state
    return Console(build_state(connection), vips=vips, connection=connection).show()


if __name__ == "__main__":
    print(selftest())
