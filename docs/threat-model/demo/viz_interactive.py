"""Interactive, browser-native visuals for the investigation console — way more than
bubbles. pyvis (vis.js) for the expressive relationship graph; Plotly for the diagram
suite (Sankey, association matrix, timelines, MITRE matrix, risk radar, sunburst,
treemap, temporal heatmap). All JS is bundled INLINE so the notebook + exported report
work fully offline. Every function degrades gracefully (SVG via viz_svg / a <div> notice)
when an optional lib is missing.

Brand comes from brand.py (official palette). Entity keys match the engine graph keys
("account:okta:jsmith@acme.com", "host:ACME-LT-4471", "ip:91.219.236.12", ...)."""
from __future__ import annotations
import brand

# vis.js node shape per entity kind — distinctive silhouettes, not just colored dots.
_SHAPE = {"host": "box", "nhi": "diamond", "agent": "triangle", "device": "square",
          "session": "hexagon", "account": "dot", "identity": "dot",
          "ip": "triangleDown", "domain": "square", "url": "square", "hash": "dot"}

# Offline fallback coverage so the MITRE visual renders something honest (labeled modeled)
# when no live /v3/rules/mitre data is present.
_MODELED_TACTICS = [
    {"name": "Initial Access", "total": 3, "enabled": 2},
    {"name": "Execution", "total": 4, "enabled": 3},
    {"name": "Persistence", "total": 3, "enabled": 1},
    {"name": "Defense Evasion", "total": 5, "enabled": 2},
    {"name": "Credential Access", "total": 4, "enabled": 3},
    {"name": "Command and Control", "total": 3, "enabled": 3},
    {"name": "Exfiltration", "total": 2, "enabled": 1},
    {"name": "Impact", "total": 2, "enabled": 1},
]


# ── availability guards ──────────────────────────────────────────────────────────
def available() -> bool:
    try:
        import pyvis  # noqa: F401
        return True
    except Exception:   # noqa: BLE001
        return False


def _plotly_ok() -> bool:
    try:
        import plotly  # noqa: F401
        return True
    except Exception:   # noqa: BLE001
        return False


def _fig_html(fig, include_js: bool = True) -> str:
    import plotly.io as pio
    return pio.to_html(fig, include_plotlyjs=("inline" if include_js else False),
                       full_html=False, config={"displaylogo": False, "responsive": True})


def plotlyjs_script() -> str:
    """The Plotly library as one inline <script> — include ONCE in a report, then render
    every panel with include_js=False to avoid embedding it many times."""
    if not _plotly_ok():
        return ""
    import plotly.io as pio
    return "<script>" + pio.get_plotlyjs() + "</script>"


# ── graph helpers ──────────────────────────────────────────────────────────────
def _nodes_edges(state):
    g, iocs, scores = state.graph, state.iocs, state.scores
    nodes = set(g.reachable_principals(iocs.keys())) | {k for k in iocs.keys() if k in g.nodes}
    edges = []
    for a in nodes:
        for b in g.adj.get(a, ()):
            if b in nodes and a < b:
                edges.append((a, b))
    return nodes, edges, scores


def _edge_rels(state):
    """Map each undirected edge → set of relationship labels seen on it (from norm events)."""
    rels = {}
    for ev in state.norm:
        for (rel, a, b) in ev.edges:
            key = (a, b) if a < b else (b, a)
            rels.setdefault(key, set()).add(rel)
    return rels


def _entity_index(state):
    """Per-entity rollup: merged raw fields, event count, sources, risk, neighbors —
    powers the full-field hover tooltip and the per-entity detail card."""
    idx = {}
    for ev in state.norm:
        for (etype, ident, _attrs) in ev.entities:
            k = f"{etype}:{ident}"
            rec = idx.setdefault(k, {"kind": etype, "id": ident, "fields": {},
                                     "events": 0, "sources": set()})
            rec["events"] += 1
            rec["sources"].add(ev.source)
            for fk, fv in ev.raw.items():
                if fk in ("_t", "ts"):
                    continue
                rec["fields"].setdefault(fk, fv)
    for k, rec in idx.items():
        rec["risk"] = state.scores.get(k, {}).get("final", 0)
        rec["neighbors"] = sorted(state.graph.adj.get(k, ()))
    return idx


def _tooltip(k, rec):
    lines = [k, f"kind={rec.get('kind')}  risk={rec.get('risk', 0)}",
             "sources=" + ",".join(sorted(rec.get("sources", [])))[:60]]
    lines += [f"{fk}={fv}" for fk, fv in list(rec.get("fields", {}).items())[:8]]
    return "\n".join(str(x) for x in lines)


# ── 1. expressive relationship graph (pyvis) ──────────────────────────────────────
def correlation_graph(state, *, focus=None, layout="force", height="640px") -> str:
    """Drag/zoom/hover/click relationship graph: shape per entity kind, edge relationship
    labels, layout modes (force|hierarchical|radial|clustered), all-fields hover tooltip."""
    if not available():
        import viz_svg
        return viz_svg.entity_graph_svg(state.graph, state.iocs, state.scores)
    try:
        from pyvis.network import Network
        import math
        net = Network(height=height, width="100%", bgcolor=brand.BG, font_color=brand.INK,
                      notebook=False, cdn_resources="in_line", directed=False)
        nodes, edges, scores = _nodes_edges(state)
        idx = _entity_index(state)
        rels = _edge_rels(state)
        vips = set(getattr(state, "vips", []) or [])
        nodes = list(nodes)
        n = len(nodes)
        for i, k in enumerate(nodes):
            t, ident = k.split(":", 1)
            rec = idx.get(k, {})
            risk = rec.get("risk", scores.get(k, {}).get("final", 0))
            shape = "star" if any(v in k for v in vips) else _SHAPE.get(t, "dot")
            kw = dict(label=ident[:22], shape=shape, color=brand.TYPE_COLOR.get(t, brand.MUT),
                      value=10 + risk, title=_tooltip(k, rec), group=t,
                      borderWidth=4 if (focus and k == focus) else 1)
            if layout == "radial":
                ang = 2 * math.pi * i / max(n, 1)
                r = 110 if t in ("ip", "domain", "url", "hash") else 260
                kw.update(x=int(r * math.cos(ang)), y=int(r * math.sin(ang)), physics=False)
            net.add_node(k, **kw)
        for a, b in edges:
            lbl = ", ".join(sorted(rels.get((a, b), ())))[:40]
            net.add_edge(a, b, color="#33334a", title=lbl,
                         label=("" if layout == "force" else lbl))
        if layout == "hierarchical":
            net.set_options('{"layout": {"hierarchical": {"enabled": true, "direction": "UD",'
                            ' "sortMethod": "hubsize", "nodeSpacing": 150, "levelSeparation": 160}},'
                            ' "physics": {"enabled": false}}')
        elif layout == "radial":
            net.toggle_physics(False)
        else:
            net.barnes_hut(gravity=-12000, spring_length=120)
        return net.generate_html(notebook=False)
    except Exception:   # noqa: BLE001 — any pyvis API hiccup → SVG fallback
        import viz_svg
        return viz_svg.entity_graph_svg(state.graph, state.iocs, state.scores)


def blast_radius(state) -> str:
    import viz_svg
    return viz_svg.blast_radius_svg((state.inv or {}).get("subagents", {}).get("scoping", {}))


# ── 2. Plotly core panels ─────────────────────────────────────────────────────────
def risk_panel(state) -> str:
    if not _plotly_ok():
        return "<div>risk panel needs plotly</div>"
    import plotly.graph_objects as go
    items = list(state.scores.items())[:14]
    ys = [k.split(":", 1)[-1][:26] for k, _ in items][::-1]
    xs = [s.get("final", 0) for _, s in items][::-1]
    colors = [brand.PINK if v >= 80 else (brand.TEAL if v >= 50 else brand.MUT) for v in xs]
    fig = go.Figure(go.Bar(x=xs, y=ys, orientation="h", marker_color=colors))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, plot_bgcolor=brand.BG,
                      title="Continuous entity risk", height=440, margin=dict(l=170, r=20, t=46, b=30))
    return _fig_html(fig)


def timeline(state) -> str:
    if not _plotly_ok():
        return "<div>timeline needs plotly</div>"
    import plotly.graph_objects as go
    pts = sorted([e for e in state.norm if e.malicious_control or e.severity in ("high", "critical")],
                 key=lambda e: e.ts)[:24]
    if not pts:
        return "<div>no high-severity events</div>"
    cols = [brand.PINK if (e.severity == "critical" or e.malicious_control) else brand.AMBER for e in pts]
    fig = go.Figure(go.Scatter(x=[e.ts for e in pts], y=[e.source for e in pts], mode="markers",
                    marker=dict(size=13, color=cols),
                    text=[f"{e.source} · {e.severity}" for e in pts]))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, plot_bgcolor=brand.BG,
                      title="Attack-chain timeline", height=380)
    return _fig_html(fig)


def coverage_by_rule(state) -> str:
    if not _plotly_ok():
        return "<div>coverage needs plotly</div>"
    import plotly.graph_objects as go
    from collections import Counter
    c = Counter(f.rule for f in state.findings)
    rules = list(c)
    vals = [c[r] for r in rules]
    fig = go.Figure(go.Bar(x=vals, y=rules, orientation="h", marker_color=brand.TEAL))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, plot_bgcolor=brand.BG,
                      title="Detection coverage by rule",
                      height=max(300, 30 * len(rules)), margin=dict(l=210, r=20, t=46, b=30))
    return _fig_html(fig)


def exposure_timeline(state) -> str:
    if not _plotly_ok():
        return "<div>exposure needs plotly</div>"
    import plotly.graph_objects as go
    import identity_intel as II
    rex = II.re_exposure(state)
    if not rex:
        return "<div>no re-exposure events</div>"
    fig = go.Figure()
    for r in rex[:8]:
        fig.add_trace(go.Scatter(
            x=[e.ts for e in r.events], y=[r.entity.split(":", 1)[-1][:18]] * len(r.events),
            mode="markers+lines", name=r.entity.split(":", 1)[-1][:18],
            marker=dict(size=10, color=brand.AMBER if r.survives_restore else brand.BLUE)))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, plot_bgcolor=brand.BG,
                      title="Identity re-exposure timeline (amber = survives restore)",
                      height=440, showlegend=False)
    return _fig_html(fig)


# ── 3. diverse diagram suite ──────────────────────────────────────────────────────
def attack_flow_sankey(state) -> str:
    if not _plotly_ok():
        return "<div>sankey needs plotly</div>"
    import plotly.graph_objects as go
    from collections import Counter
    flows = Counter()
    for ev in state.norm:
        kinds = {t for (t, _i, _a) in ev.entities if t in ("account", "identity", "host", "nhi", "agent")}
        for kind in (kinds or {"infra"}):
            flows[(f"src:{ev.source}", f"kind:{kind}")] += 1
            flows[(f"kind:{kind}", f"sev:{ev.severity}")] += 1
    if not flows:
        return "<div>no flow data</div>"
    labels = sorted({x for pair in flows for x in pair})
    li = {l: i for i, l in enumerate(labels)}
    src = [li[a] for (a, _b) in flows]
    dst = [li[b] for (_a, b) in flows]
    val = list(flows.values())
    fig = go.Figure(go.Sankey(
        node=dict(label=[l.split(":", 1)[-1] for l in labels], color=brand.TEAL, pad=14),
        link=dict(source=src, target=dst, value=val)))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, font_color=brand.INK,
                      title="Attack-flow Sankey (source → identity kind → severity)", height=480)
    return _fig_html(fig)


def association_matrix(state) -> str:
    if not _plotly_ok():
        return "<div>matrix needs plotly</div>"
    import plotly.graph_objects as go
    nodes, edges, _ = _nodes_edges(state)
    nodes = sorted(nodes)[:30]
    ni = {k: i for i, k in enumerate(nodes)}
    z = [[0] * len(nodes) for _ in nodes]
    for a, b in edges:
        if a in ni and b in ni:
            z[ni[a]][ni[b]] = 1
            z[ni[b]][ni[a]] = 1
    labels = [k.split(":", 1)[-1][:14] for k in nodes]
    if not labels:
        return "<div>no entities to correlate</div>"
    fig = go.Figure(go.Heatmap(z=z, x=labels, y=labels, showscale=False,
                    colorscale=[[0, brand.PANEL], [1, brand.PINK]]))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG,
                      title="Entity association matrix", height=560)
    return _fig_html(fig)


def entity_event_timeline(state, entity=None) -> str:
    if not _plotly_ok():
        return "<div>timeline needs plotly</div>"
    import plotly.graph_objects as go
    idx = _entity_index(state)
    if entity:
        keys = [entity]
    else:
        keys = [k for k in idx if k.split(":", 1)[0] in ("account", "identity", "host", "nhi", "agent")]
    keys = sorted(set(keys), key=lambda k: -idx.get(k, {}).get("risk", 0))[:10]
    sevcol = {"critical": brand.PINK, "high": brand.AMBER, "medium": brand.BLUE}
    fig = go.Figure()
    plotted = False
    for k in keys:
        xs, cs, txt = [], [], []
        for ev in state.norm:
            if k in ev.entity_keys():
                xs.append(ev.ts)
                cs.append(sevcol.get(ev.severity, brand.MUT))
                txt.append(f"{ev.source}/{ev.severity}")
        if xs:
            plotted = True
            fig.add_trace(go.Scatter(x=xs, y=[k.split(":", 1)[-1][:18]] * len(xs), mode="markers",
                          marker=dict(size=11, color=cs), text=txt, name=k.split(":", 1)[-1][:18]))
    if not plotted:
        return "<div>no events for selection</div>"
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, plot_bgcolor=brand.BG,
                      title="Entity event timeline", height=460, showlegend=False)
    return _fig_html(fig)


def mitre_matrix(state) -> str:
    if not _plotly_ok():
        return "<div>MITRE matrix needs plotly</div>"
    import plotly.graph_objects as go
    tactics = state.mitre or _MODELED_TACTICS
    modeled = not state.mitre
    names = [t.get("name") or t.get("id") for t in tactics]
    cov = [((t.get("enabled") or 0) / t["total"] if t.get("total") else 0) for t in tactics]
    txt = [f"{t.get('enabled', 0)}/{t.get('total', 0)}" for t in tactics]
    fig = go.Figure(go.Heatmap(z=[cov], x=names, y=["coverage"], text=[txt], texttemplate="%{text}",
                    zmin=0, zmax=1, colorscale=[[0, brand.PANEL], [1, brand.TEAL]]))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, height=240,
                      title="MITRE ATT&CK coverage" + (" (modeled)" if modeled else ""))
    return _fig_html(fig)


def _risk_dims(state, entity):
    import identity_intel as II
    base = state.scores.get(entity, {}).get("final", 0)
    rex = {r.entity: r for r in II.re_exposure(state)}
    exposure = min(100, rex[entity].count * 12) if entity in rex else 0
    hijack = max([s.score for s in II.session_hijacking(state) if s.entity == entity] + [0])
    reuse = max([s.score for s in II.password_reuse(state) if s.entity == entity] + [0])
    hygiene = max([s.score for s in II.persistent_bad_hygiene(state) if s.entity == entity] + [0])
    blast = min(100, len(state.graph.adj.get(entity, ())) * 8)
    return {"base risk": base, "exposure": exposure, "hijack": hijack,
            "reuse": reuse, "hygiene": hygiene, "blast radius": blast}


def risk_radar(state, entity) -> str:
    if not _plotly_ok():
        return "<div>radar needs plotly</div>"
    import plotly.graph_objects as go
    dims = _risk_dims(state, entity)
    cats = list(dims)
    vals = [dims[c] for c in cats]
    fig = go.Figure(go.Scatterpolar(r=vals + [vals[0]], theta=cats + [cats[0]], fill="toself",
                    line_color=brand.PINK))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, height=430,
                      title=f"Risk profile — {entity.split(':', 1)[-1][:24]}",
                      polar=dict(radialaxis=dict(range=[0, 100])))
    return _fig_html(fig)


def exposure_sunburst(state) -> str:
    if not _plotly_ok():
        return "<div>sunburst needs plotly</div>"
    import plotly.graph_objects as go
    import identity_intel as II
    labels, parents, values = ["exposure"], [""], [0]
    seen = set()
    for r in II.re_exposure(state):
        kind = r.entity.split(":", 1)[0]
        if kind not in seen:
            labels.append(kind)
            parents.append("exposure")
            values.append(0)
            seen.add(kind)
        labels.append(r.entity.split(":", 1)[-1][:20])
        parents.append(kind)
        values.append(r.count)
    if len(labels) <= 1:
        return "<div>no exposure data</div>"
    fig = go.Figure(go.Sunburst(labels=labels, parents=parents, values=values))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, height=480,
                      title="Exposure by identity kind → entity")
    return _fig_html(fig)


def tactic_treemap(state) -> str:
    if not _plotly_ok():
        return "<div>treemap needs plotly</div>"
    import plotly.graph_objects as go
    from collections import Counter
    c = Counter((f.severity, f.rule) for f in state.findings)
    if not c:
        return "<div>no findings</div>"
    labels, parents, values = [], [], []
    for s in sorted({s for s, _ in c}):
        labels.append(s)
        parents.append("")
        values.append(0)
    for (s, rule), n in c.items():
        labels.append(rule)
        parents.append(s)
        values.append(n)
    fig = go.Figure(go.Treemap(labels=labels, parents=parents, values=values))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, height=460,
                      title="Findings — severity → rule")
    return _fig_html(fig)


def temporal_heatmap(state) -> str:
    if not _plotly_ok():
        return "<div>heatmap needs plotly</div>"
    import plotly.graph_objects as go
    ts_all = [ev.ts for ev in state.norm]
    if not ts_all:
        return "<div>no events</div>"
    t0 = min(ts_all)
    sources = sorted({ev.source for ev in state.norm})

    def day(ev):
        return int((ev.ts - t0).total_seconds() // 86400)
    buckets = sorted({day(ev) for ev in state.norm})
    bi = {b: i for i, b in enumerate(buckets)}
    si = {s: i for i, s in enumerate(sources)}
    z = [[0] * len(buckets) for _ in sources]
    for ev in state.norm:
        z[si[ev.source]][bi[day(ev)]] += 1
    fig = go.Figure(go.Heatmap(z=z, x=[f"day {b}" for b in buckets], y=sources,
                    colorscale=[[0, brand.BG], [1, brand.TEAL]]))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, height=420,
                      title="Activity heatmap (source × day)")
    return _fig_html(fig)


# ── 4. per-entity detail card (all fields, signals, pivots) ───────────────────────
def entity_detail_html(state, entity) -> str:
    import html as _h
    idx = _entity_index(state)
    rec = idx.get(entity)
    if not rec:
        return (f'<div style="color:{brand.MUT};font-family:{brand.FONT_STACK}">'
                f'No detail for {_h.escape(str(entity))}</div>')
    import identity_intel as II
    sigs = [s for fn in (II.session_hijacking, II.mfa_bombing, II.password_reuse,
                         II.persistent_bad_hygiene)
            for s in fn(state) if s.entity == entity]
    field_rows = "".join(
        f'<tr><td style="color:{brand.MUT};padding:2px 10px 2px 0;white-space:nowrap">'
        f'{_h.escape(str(k))}</td><td style="color:{brand.INK}">{_h.escape(str(v))}</td></tr>'
        for k, v in sorted(rec["fields"].items()))
    sig_rows = "".join(
        f'<li>{_h.escape(s.kind)} — {_h.escape(s.detail)} '
        f'<b style="color:{brand.PINK}">({s.score})</b></li>' for s in sigs) or "<li>none</li>"
    neigh = "".join(
        f'<span style="background:{brand.BG};color:{brand.INK};padding:2px 8px;border-radius:6px;'
        f'margin:2px;display:inline-block;font-family:{brand.MONO_STACK};font-size:11px">'
        f'{_h.escape(n)}</span>' for n in rec["neighbors"][:24]) or "—"
    return (
        f'<div style="font-family:{brand.FONT_STACK};color:{brand.INK};background:{brand.PANEL};'
        f'border:1px solid #1d1d27;border-radius:12px;padding:16px">'
        f'<div style="font-size:18px;color:{brand.PINK};font-weight:700">{_h.escape(str(entity))}</div>'
        f'<div style="color:{brand.MUT};margin:4px 0 10px">kind '
        f'<b style="color:{brand.INK}">{_h.escape(rec["kind"])}</b> · risk '
        f'<b style="color:{brand.TEAL}">{rec["risk"]}</b> · events {rec["events"]} · sources '
        f'{_h.escape(", ".join(sorted(rec["sources"])))}</div>'
        f'<h4 style="color:{brand.TEAL};margin:8px 0 4px">All fields</h4>'
        f'<table style="font-size:12px;font-family:{brand.MONO_STACK}">{field_rows}</table>'
        f'<h4 style="color:{brand.TEAL};margin:12px 0 4px">Identity signals</h4>'
        f'<ul style="font-size:12px;margin:0">{sig_rows}</ul>'
        f'<h4 style="color:{brand.TEAL};margin:12px 0 4px">Related entities (pivot)</h4>'
        f'<div>{neigh}</div></div>')


def selftest():
    from live_data import build_state
    st = build_state(None)
    st.vips = {"jsmith@acme.com"}
    g = correlation_graph(st)
    assert "<" in g and len(g) > 500
    assert "<" in correlation_graph(st, layout="hierarchical")
    assert "<" in correlation_graph(st, layout="radial")
    assert "<" in correlation_graph(st, layout="clustered", focus="account:okta:jsmith@acme.com")
    ent = "account:okta:jsmith@acme.com"
    for fn in (risk_panel, timeline, coverage_by_rule, exposure_timeline, blast_radius,
               attack_flow_sankey, association_matrix, entity_event_timeline,
               mitre_matrix, exposure_sunburst, tactic_treemap, temporal_heatmap):
        out = fn(st)
        assert "<" in out, fn.__name__
    assert "<" in risk_radar(st, ent)
    assert ent in entity_detail_html(st, ent)
    return {"ok": True, "pyvis": available(), "plotly": _plotly_ok(),
            "graph_bytes": len(g), "panels": 14}


if __name__ == "__main__":
    print(selftest())
