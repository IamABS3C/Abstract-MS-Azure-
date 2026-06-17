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
    matplotlib.use("Agg")  # safe default; notebooks override with %matplotlib inline
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
