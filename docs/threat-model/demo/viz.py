"""
Interactive (matplotlib / networkx) visualizations for the analyst notebook.

Heavy viz libs are imported lazily so this module imports even where they're absent
(only networkx is guaranteed here). The notebook's first cell pip-installs the rest:
    pip install matplotlib networkx numpy

Brand palette mirrors viz_svg. Each draw_* returns a matplotlib Figure.
"""
from __future__ import annotations

PINK, TEAL, BG, PANEL, INK, MUT = "#f8226a", "#01e69d", "#060608", "#101016", "#e9e9f0", "#8a8a99"
TYPE_COLOR = {"identity": TEAL, "account": "#36c5f0", "host": "#b388ff", "nhi": "#ffb547",
              "agent": PINK, "ip": "#ff6b6b", "domain": "#ff9f43", "url": "#feca57", "hash": "#9b9b9b"}


def _mpl():
    import matplotlib
    # Only force the headless Agg backend in script/headless contexts. If a
    # notebook has already selected an inline/interactive backend (via
    # %matplotlib inline), leave it alone so figures flush to inline PNGs.
    backend = matplotlib.get_backend().lower()
    if not any(b in backend for b in ("inline", "nbagg", "ipympl", "widget", "qt", "tk", "macosx")):
        try:
            matplotlib.use("Agg")
        except Exception:  # noqa: BLE001
            pass
    import matplotlib.pyplot as plt
    plt.rcParams.update({"figure.facecolor": BG, "axes.facecolor": BG, "text.color": INK,
                         "axes.edgecolor": "#33334a", "xtick.color": MUT, "ytick.color": MUT,
                         "axes.labelcolor": INK, "font.size": 10})
    return plt


def build_nx_graph(graph, iocs, scores):
    """Return a networkx.Graph of the campaign subgraph with node color/size attrs."""
    import networkx as nx
    G = nx.Graph()
    nodes = set(graph.reachable_principals(iocs.keys())) | {k for k in iocs.keys() if k in graph.nodes}
    for k in nodes:
        t = k.split(":", 1)[0]
        G.add_node(k, kind=t, color=TYPE_COLOR.get(t, MUT),
                   size=300 + scores.get(k, {}).get("final", 0) * 12)
    for a in nodes:
        for b in graph.adj.get(a, ()):
            if b in nodes and not G.has_edge(a, b):
                G.add_edge(a, b)
    return G


def draw_entity_graph(graph, iocs, scores, title="Campaign entity graph"):
    import networkx as nx
    plt = _mpl()
    G = build_nx_graph(graph, iocs, scores)
    fig, ax = plt.subplots(figsize=(9, 7))
    pos = nx.spring_layout(G, seed=42, k=0.7)
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#33334a", width=1)
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=[G.nodes[n]["color"] for n in G],
                           node_size=[G.nodes[n]["size"] for n in G])
    nx.draw_networkx_labels(G, pos, ax=ax, font_size=7, font_color=INK,
                            labels={n: n.split(":", 1)[1][:16] for n in G})
    ax.set_title(title, color=INK); ax.axis("off")
    return fig


def draw_risk_bars(scores, top=10):
    plt = _mpl()
    items = list(scores.items())[:top][::-1]
    labels = [k for k, _ in items]; vals = [s["final"] for _, s in items]
    colors = [PINK if v >= 80 else (TEAL if v >= 50 else MUT) for v in vals]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(range(len(vals)), vals, color=colors)
    ax.set_yticks(range(len(vals))); ax.set_yticklabels(labels, fontsize=7)
    ax.set_xlim(0, 100); ax.set_title("Continuous entity risk", color=INK)
    return fig


def draw_mitre_heatmap(tactics):
    """tactics: [{name,total,enabled}] (live /v3/rules/mitre summary per tactic)."""
    plt = _mpl()
    names = [t.get("name", t.get("id")) for t in tactics]
    cov = [((t.get("enabled") or 0) / t["total"] if t.get("total") else 0) for t in tactics]
    fig, ax = plt.subplots(figsize=(min(1.1 * len(tactics), 12), 1.8))
    ax.imshow([cov], aspect="auto", cmap="BuGn", vmin=0, vmax=1)
    ax.set_xticks(range(len(names))); ax.set_xticklabels(names, rotation=45, ha="right", fontsize=7)
    ax.set_yticks([]); ax.set_title("MITRE ATT&CK coverage", color=INK)
    return fig


def draw_attack_timeline(norm_events):
    plt = _mpl()
    pts = sorted([e for e in norm_events if e.malicious_control or e.severity in ("high", "critical")
                  or e.source in ("email", "okta", "cloudtrail", "nhi", "agent")], key=lambda e: e.ts)[:12]
    if not pts:
        return _mpl().figure()
    t0 = pts[0].ts
    xs = [(e.ts - t0).total_seconds() / 60 for e in pts]
    fig, ax = plt.subplots(figsize=(10, 3))
    for i, (x, e) in enumerate(zip(xs, pts)):
        col = PINK if (e.severity == "critical" or e.malicious_control) else TEAL
        ax.scatter([x], [0], s=80, color=col, zorder=3)
        ax.annotate(e.source, (x, 0), xytext=(0, 12 if i % 2 == 0 else -18),
                    textcoords="offset points", ha="center", fontsize=7, color=INK)
    ax.axhline(0, color="#33334a"); ax.set_yticks([]); ax.set_xlabel("minutes from first event")
    ax.set_title("Attack-chain timeline", color=INK)
    return fig


def draw_score_trajectories(scores, top=6):
    """Per-entity continuous-risk trajectory over time (decaying EWMA)."""
    plt = _mpl()
    fig, ax = plt.subplots(figsize=(10, 4.5))
    for k, s in list(scores.items())[:top]:
        traj = s.get("trajectory") or []
        if len(traj) < 1:
            continue
        xs = [t for (t, _v) in traj]
        ys = [v for (_t, v) in traj]
        t = k.split(":", 1)[0]
        ax.plot(xs, ys, marker="o", ms=3, lw=1.6, color=TYPE_COLOR.get(t, MUT),
                label=k.split(":", 1)[1][:18])
    ax.axhline(80, color=PINK, ls="--", lw=0.8, alpha=0.6)
    ax.set_ylim(0, 100); ax.set_ylabel("risk"); ax.set_title("Continuous risk trajectories", color=INK)
    ax.legend(fontsize=6, loc="upper left", facecolor=PANEL, edgecolor="#33334a", labelcolor=INK)
    fig.autofmt_xdate()
    return fig


def draw_findings_by_rule(findings):
    """Count of findings per detection rule, colored by peak severity."""
    plt = _mpl()
    from collections import defaultdict
    counts = defaultdict(int); peak = {}
    order = {"critical": 3, "high": 2, "medium": 1, "low": 0, "informational": 0}
    for f in findings:
        counts[f.rule] += 1
        if order.get(f.severity, 0) >= order.get(peak.get(f.rule, "low"), 0):
            peak[f.rule] = f.severity
    rules = sorted(counts, key=counts.get)
    vals = [counts[r] for r in rules]
    colors = [PINK if peak.get(r) == "critical" else (TEAL if peak.get(r) == "high" else MUT) for r in rules]
    fig, ax = plt.subplots(figsize=(9, max(2.2, 0.5 * len(rules))))
    ax.barh(range(len(rules)), vals, color=colors)
    ax.set_yticks(range(len(rules))); ax.set_yticklabels(rules, fontsize=8)
    ax.set_xlabel("findings"); ax.set_title("Detection coverage by rule", color=INK)
    for i, v in enumerate(vals):
        ax.text(v + 0.05, i, str(v), va="center", fontsize=8, color=INK)
    return fig


def draw_efficiency_panel(metrics):
    """Big-number KPI panel: SIEM volume cut, alert-fatigue cut, incidents, MTTD."""
    plt = _mpl()
    cards = [
        (f"{metrics['reduction_pct']}%", "SIEM volume cut",
         f"{metrics['total_events']:,} → {metrics['forwarded_to_siem']:,}", TEAL),
        (f"{metrics['fatigue_reduction_pct']}%", "alert fatigue cut",
         f"{metrics['raw_alerts']} alerts → {metrics['incidents']} incident(s)", PINK),
        (f"{metrics['incidents']}", "fused incidents",
         f"from {metrics['fused_findings']} findings", "#b388ff"),
        (f"~{metrics['mttd_stream_sec']}s", "MTTD shift-left",
         f"vs ~{int(metrics['mttd_siem_sec'] / 60)}m SIEM (modeled)", "#36c5f0"),
    ]
    fig, axes = plt.subplots(1, 4, figsize=(12, 2.6))
    for ax, (big, label, sub, col) in zip(axes, cards):
        ax.axis("off")
        ax.add_patch(plt.Rectangle((0.02, 0.05), 0.96, 0.9, transform=ax.transAxes,
                                   facecolor=PANEL, edgecolor="#1d1d27", lw=1))
        ax.text(0.5, 0.66, big, ha="center", va="center", fontsize=26, color=col, fontweight="bold")
        ax.text(0.5, 0.36, label, ha="center", va="center", fontsize=9, color=INK)
        ax.text(0.5, 0.18, sub, ha="center", va="center", fontsize=7, color=MUT)
    fig.suptitle("Efficiency vs. SIEM-first (modeled)", color=INK, fontsize=11)
    return fig


def draw_identity_taxonomy(counts):
    """Bar of victim/entity counts by identity kind (human/NHI/agent/…)."""
    plt = _mpl()
    items = sorted(counts.items(), key=lambda kv: kv[1])
    labels = [k for k, _ in items]; vals = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(8, max(2, 0.5 * len(labels))))
    ax.barh(range(len(labels)), vals, color=PINK)
    ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("entities"); ax.set_title("Implicated identities by kind", color=INK)
    for i, v in enumerate(vals):
        ax.text(v + 0.02, i, str(v), va="center", fontsize=8, color=INK)
    return fig


def selftest():
    # only networkx is guaranteed; verify graph construction (no rendering)
    from pipeline import normalize, Graph, run_detections, continuous_scores
    from data import events, IOCS
    norm = [normalize(i, r) for i, r in enumerate(events())]
    g = Graph()
    for ev in norm:
        g.add(ev)
    scores = continuous_scores(norm, IOCS)
    G = build_nx_graph(g, IOCS, scores)
    return {"nodes": G.number_of_nodes(), "edges": G.number_of_edges()}


if __name__ == "__main__":
    print(selftest())
