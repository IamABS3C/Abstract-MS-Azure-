"""
Zero-dependency, Abstract-branded SVG visualizations for the dashboard — so the
"powerful charts/graphs/attack maps/heat maps/blast radius" render in any browser
with no pip installs. The notebook uses matplotlib/networkx for the interactive
versions; these SVGs are the always-works, leadership-facing artifacts.

Brand: #f8226a pink, #01e69d teal, #060608 bg, #101016 panel.
"""
from __future__ import annotations

import html
import math

PINK, TEAL, BG, PANEL, INK, MUT = "#f8226a", "#01e69d", "#060608", "#101016", "#e9e9f0", "#8a8a99"
TYPE_COLOR = {
    "identity": TEAL, "account": "#36c5f0", "host": "#b388ff", "nhi": "#ffb547",
    "agent": PINK, "ip": "#ff6b6b", "domain": "#ff9f43", "url": "#feca57", "hash": "#9b9b9b",
}


def _esc(s): return html.escape(str(s))


def _risk_color(v):
    return PINK if v >= 80 else (TEAL if v >= 50 else MUT)


# ── entity graph (radial: IOCs inner ring, principals outer ring) ────────────
def entity_graph_svg(graph, iocs, scores, W=560, H=420):
    iock = sorted(k for k in iocs.keys() if k in graph.nodes)
    principals = sorted(graph.reachable_principals(iocs.keys()))
    cx, cy = W / 2, H / 2
    pos = {}
    for i, k in enumerate(iock):
        a = 2 * math.pi * i / max(len(iock), 1)
        pos[k] = (cx + 70 * math.cos(a), cy + 70 * math.sin(a))
    for i, k in enumerate(principals):
        a = 2 * math.pi * i / max(len(principals), 1) - math.pi / 2
        pos[k] = (cx + 165 * math.cos(a), cy + 165 * math.sin(a))
    edges = []
    nodeset = set(pos)
    for a in nodeset:
        for b in graph.adj.get(a, ()):
            if b in nodeset and a < b:
                edges.append((a, b))
    out = [f'<svg viewBox="0 0 {W} {H}" width="100%" xmlns="http://www.w3.org/2000/svg">']
    out.append(f'<rect width="{W}" height="{H}" fill="{BG}" rx="12"/>')
    for a, b in edges:
        (x1, y1), (x2, y2) = pos[a], pos[b]
        out.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                   f'stroke="#26263a" stroke-width="1"/>')
    for k, (x, y) in pos.items():
        t, ident = k.split(":", 1)
        r = 6 + (scores.get(k, {}).get("final", 0) / 100) * 9
        col = TYPE_COLOR.get(t, MUT)
        label = ident if len(ident) <= 16 else ident[:14] + "…"
        out.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{r:.0f}" fill="{col}" '
                   f'stroke="{BG}" stroke-width="1.5"/>')
        out.append(f'<text x="{x:.0f}" y="{y + r + 10:.0f}" fill="{MUT}" font-size="9" '
                   f'text-anchor="middle" font-family="JetBrains Mono,monospace">{_esc(label)}</text>')
    out.append('</svg>')
    return "".join(out)


# ── blast-radius rings (patient-zero → real-time → replay) ────────────────────
def blast_radius_svg(scoping, W=560, H=420):
    realtime = scoping.get("realtime", []); historical = scoping.get("historical", [])
    cx, cy = W / 2, H / 2
    out = [f'<svg viewBox="0 0 {W} {H}" width="100%" xmlns="http://www.w3.org/2000/svg">',
           f'<rect width="{W}" height="{H}" fill="{BG}" rx="12"/>']
    for r, col, lbl in [(170, "#26263a", "replay (historical)"), (110, "#33334a", "real-time"),
                        (45, PINK, "patient zero")]:
        out.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{col}" stroke-width="1.5"/>')
        out.append(f'<text x="{cx}" y="{cy - r - 4:.0f}" fill="{MUT}" font-size="9" '
                   f'text-anchor="middle">{lbl}</text>')

    def place(items, radius, color):
        for i, p in enumerate(items):
            a = 2 * math.pi * i / max(len(items), 1)
            x, y = cx + radius * math.cos(a), cy + radius * math.sin(a)
            nm = p.split(":", 1)[1]
            out.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="6" fill="{color}"/>')
            out.append(f'<text x="{x:.0f}" y="{y - 9:.0f}" fill="{INK}" font-size="8.5" '
                       f'text-anchor="middle" font-family="JetBrains Mono,monospace">'
                       f'{_esc(nm[:14])}</text>')
    place(realtime, 110, TEAL)
    place(historical, 170, "#ffb547")
    out.append(f'<circle cx="{cx}" cy="{cy}" r="9" fill="{PINK}"/>')
    out.append('</svg>')
    return "".join(out)


# ── MITRE ATT&CK coverage heat strip (live /v3/rules/mitre tactics) ───────────
def mitre_heatstrip_svg(tactics, W=900, cell=64):
    if not tactics:
        return f'<div style="color:{MUT}">MITRE coverage unavailable (offline)</div>'
    n = len(tactics); gap = 8
    cw = (W - gap * (n - 1)) / n
    H = cell + 46
    out = [f'<svg viewBox="0 0 {W} {H}" width="100%" xmlns="http://www.w3.org/2000/svg">']
    for i, t in enumerate(tactics):
        total = t.get("total") or sum(x.get("total", 0) for x in t.get("techniques", []))
        enabled = t.get("enabled") or sum(x.get("enabled", 0) for x in t.get("techniques", []))
        cov = (enabled / total) if total else 0
        # blend MUT→TEAL by coverage
        g = int(0x01 + cov * (0xe6 - 0x01)); b = int(0x08 + cov * (0x9d - 0x08))
        col = f"#{int(0x33*(1-cov)):02x}{g:02x}{b:02x}"
        x = i * (cw + gap)
        out.append(f'<rect x="{x:.0f}" y="20" width="{cw:.0f}" height="{cell}" rx="6" fill="{col}"/>')
        out.append(f'<text x="{x + cw/2:.0f}" y="{20 + cell/2:.0f}" fill="{INK}" font-size="13" '
                   f'text-anchor="middle" font-weight="700">{enabled}/{total}</text>')
        nm = (t.get("name") or t.get("id"))[:14]
        out.append(f'<text x="{x + cw/2:.0f}" y="{cell + 38:.0f}" fill="{MUT}" font-size="9" '
                   f'text-anchor="middle">{_esc(nm)}</text>')
    out.append('</svg>')
    return "".join(out)


# ── attack-chain timeline (incident events) ──────────────────────────────────
def attack_timeline_svg(events, W=900, H=150):
    pts = [e for e in events if e.malicious_control or e.severity in ("high", "critical")
           or e.source in ("email", "okta", "cloudtrail", "nhi", "agent")]
    pts = sorted(pts, key=lambda e: e.ts)[:12]
    if not pts:
        return ""
    t0, t1 = pts[0].ts, pts[-1].ts
    span = max((t1 - t0).total_seconds(), 1)
    y = H / 2
    out = [f'<svg viewBox="0 0 {W} {H}" width="100%" xmlns="http://www.w3.org/2000/svg">',
           f'<rect width="{W}" height="{H}" fill="{BG}" rx="12"/>',
           f'<line x1="40" y1="{y}" x2="{W-40}" y2="{y}" stroke="#33334a" stroke-width="2"/>']
    for i, e in enumerate(pts):
        x = 40 + ((e.ts - t0).total_seconds() / span) * (W - 80)
        col = PINK if e.severity == "critical" or e.malicious_control else TEAL
        up = (i % 2 == 0)
        ly = y - 16 if up else y + 28
        label = (e.source + ":" + (e.raw.get("host") or e.raw.get("account") or
                 e.raw.get("agent") or e.raw.get("nhi") or e.raw.get("query") or ""))[:22]
        out.append(f'<circle cx="{x:.0f}" cy="{y}" r="6" fill="{col}"/>')
        out.append(f'<line x1="{x:.0f}" y1="{y}" x2="{x:.0f}" y2="{ly + (6 if up else -6):.0f}" stroke="#33334a"/>')
        out.append(f'<text x="{x:.0f}" y="{ly}" fill="{INK}" font-size="9" text-anchor="middle" '
                   f'font-family="JetBrains Mono,monospace">{_esc(label)}</text>')
    out.append('</svg>')
    return "".join(out)


# ── horizontal risk bars ──────────────────────────────────────────────────────
def risk_bars_svg(scores, top=8):
    rows = list(scores.items())[:top]
    out = []
    for k, s in rows:
        w = int(s["final"]); col = _risk_color(s["final"])
        trend = "▲" if s["trend"] > 0 else ("▼" if s["trend"] < 0 else "■")
        out.append(
            f'<div style="display:flex;align-items:center;gap:10px;margin:6px 0;font-size:12px">'
            f'<span style="width:230px;color:{INK};font-family:JetBrains Mono,monospace;'
            f'overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{_esc(k)}</span>'
            f'<span style="flex:1;background:#18181f;border-radius:6px;height:14px;overflow:hidden">'
            f'<span style="display:block;height:100%;width:{w}%;background:{col}"></span></span>'
            f'<span style="width:62px;text-align:right;color:{MUT}">{s["final"]} {trend}</span></div>')
    return "".join(out)


# ── identity taxonomy bars (counts by kind) ───────────────────────────────────
def identity_taxonomy_svg(counts):
    if not counts:
        return ""
    mx = max(counts.values())
    out = []
    for kind, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        w = int((n / mx) * 100) if mx else 0
        out.append(
            f'<div style="display:flex;align-items:center;gap:10px;margin:5px 0;font-size:12px">'
            f'<span style="width:170px;color:{INK}">{_esc(kind)}</span>'
            f'<span style="flex:1;background:#18181f;border-radius:6px;height:12px;overflow:hidden">'
            f'<span style="display:block;height:100%;width:{w}%;background:{TEAL}"></span></span>'
            f'<span style="width:30px;text-align:right;color:{MUT}">{n}</span></div>')
    return "".join(out)


def selftest():
    # dep-free shape checks (no rendering libs needed)
    s = mitre_heatstrip_svg([{"name": "Initial Access", "total": 10, "enabled": 8},
                             {"name": "Execution", "total": 12, "enabled": 12}])
    assert "<svg" in s and "8/10" in s
    assert "<div" in identity_taxonomy_svg({"human_user": 3, "ai_agent": 1})
    return {"ok": True}


if __name__ == "__main__":
    print(selftest())
