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
    lines, A = [], None
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
    md = markdown(state)
    body = _md_to_html(md)

    # interactive visuals: include Plotly's JS ONCE (not per panel)
    VI._NO_INLINE = True
    panels = [("Continuous entity risk", VI.risk_panel(state)),
              ("Identity re-exposure timeline", VI.exposure_timeline(state)),
              ("Attack-flow", VI.attack_flow_sankey(state)),
              ("MITRE ATT&CK coverage", ML.matrix_html(state))]
    VI._NO_INLINE = False
    plotly_js = VI.plotlyjs_script()

    # pyvis graph is a full HTML doc → isolate it in an iframe srcdoc
    graph_doc = VI.correlation_graph(state)
    graph_iframe = (f'<iframe srcdoc="{html.escape(graph_doc)}" '
                    f'style="width:100%;height:660px;border:0;border-radius:14px"></iframe>')
    blast = VI.blast_radius(state)
    logo = brand.logo_svg("white")
    panel_html = "".join(
        f'<div class="viz"><h3>{html.escape(title)}</h3>{frag}</div>' for title, frag in panels)
    badge = ("LIVE tenant" if state.live else "OFFLINE — modeled data")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Investigation Report — Abstract</title>
{plotly_js}
<style>
:root{{--pink:{brand.PINK};--teal:{brand.TEAL};--bg:{brand.BG};--panel:{brand.PANEL};--ink:{brand.INK};--mut:{brand.MUT}}}
*{{box-sizing:border-box}}
body{{background:var(--bg);color:var(--ink);font-family:{brand.FONT_STACK};
max-width:1180px;margin:0 auto;padding:30px;line-height:1.6}}
.logo{{height:34px;margin-bottom:8px}} .logo svg{{height:34px;width:auto}}
.badge{{background:var(--teal);color:var(--bg);padding:2px 9px;border-radius:6px;font-weight:700;font-size:12px}}
h1{{color:var(--pink);font-size:26px}}
h2{{color:var(--teal);font-size:14px;text-transform:uppercase;letter-spacing:1.3px;margin-top:26px}}
h3{{color:var(--ink);font-size:14px;margin:0 0 8px}}
code{{font-family:{brand.MONO_STACK};background:#16161e;padding:1px 5px;border-radius:4px;font-size:12px;color:#cfcfe0}}
li{{margin:3px 0}} b{{color:#fff}}
.viz{{background:var(--panel);border:1px solid #1d1d27;border-radius:14px;padding:16px;margin:16px 0;overflow-x:auto}}
.grid{{display:grid;grid-template-columns:1fr;gap:4px}}
@media print{{body{{max-width:none}} .viz{{break-inside:avoid}}}}
</style></head>
<body>
<div class="logo">{logo}</div>
<span class="badge">{badge}</span>
<div class="viz"><h3>Entity correlation graph</h3>{graph_iframe}</div>
<div class="viz"><h3>Blast radius</h3>{blast}</div>
{panel_html}
<div class="report-body">{body}</div>
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
