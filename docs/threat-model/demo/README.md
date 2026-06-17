# Runnable demo — shift-left model end-to-end

A dependency-free simulation of the model in [../README.md](../README.md): it ingests a mixed
estate, normalizes to a common shape, builds an entity graph across **user / account / host /
NHI / agent** identities, runs in-stream detections, replays history, scores entities
continuously, predicts next targets, orchestrates sub-agents, and serializes findings for
**write-back into Abstract**.

> **This is a teaching simulation, not the product.** It exists so you can *see* the shape and
> the numbers. The seams marked `# ← in Abstract` in [pipeline.py](pipeline.py) show where the
> real platform takes over. See **"Simulated vs. real"** below.

## Run it

```bash
cd docs/threat-model/demo
python3 run_demo.py          # narrated CLI run (Python 3.9+, stdlib only)
```

For the analyst/JupyterHub experience, open [soc_notebook.ipynb](soc_notebook.ipynb) (needs
`jupyter`; `pip install jupyter matplotlib`). It reuses the exact engine the CLI verifies.

**Live mode (writes to a real tenant):** put a write-scoped key in `~/.abstract.env`
(see `.env.example`), then:

```bash
python3 live_writeback.py        # minimal loop: one field-set + view (idempotent, self-cleaning)
python3 build_demo.py            # ELABORATE: 9 field sets + 32 views + suppressions + live analytics
python3 build_demo.py --cleanup  # remove all [ABS-DEMO] objects
python3 dashboard.py --mode api  # write-back + render dashboard.html with a LIVE banner
```

**Proven working** against a real Abstract tenant via the documented REST API. The elaborate
build creates 9 entity-model field sets + 32 use-case saved views + suppressions and pulls live
MITRE coverage + field analytics — full catalog in [DEMO-CATALOG.md](DEMO-CATALOG.md); endpoints
and the rule-step status in [LIVE-RESULTS.md](LIVE-RESULTS.md).

## What it shows (live numbers from the synthetic estate)

One Qakbot-style campaign woven across email → firewall/WildFire → EDR → identity → cloud,
plus a 5,000-event benign floor. Representative output:

| Outcome | Result | Why it matters |
|---|---|---|
| **SIEM volume cut** | 5,018 ingested → **18 forwarded** (~99.6%) | rest goes to LakeVilla; you pay SIEM for findings+context, not raw telemetry |
| **Alert fatigue** | 8 raw alerts → **1 incident** (~87.5%) | controls-agree fusion collapses the storm into one case |
| **MTTD** | shift-left ~0.5s vs SIEM ~20m (modeled) | decisions at stream time, not after index+rule cadence |
| **Blast radius** | 8 victims across 5 entity types | user, account, host, **NHI**, **agent** — not just endpoints |
| **Replay (retro-hunt)** | finds `ACME-LT-2210` from **9 days before** the verdict | the WildFire IOC loop convicts the past, not just the present |
| **Prediction** | flags `ACME-LT-8802` / `ACME-LT-2210` as **next targets** | touched C2 with no conviction yet → intervene early |
| **WildFire-loop value** | 2 victims known without it → **8 with it** | counterfactual in the notebook (what-if A) |

## How the pieces map to the model

| File | Role | Model section |
|---|---|---|
| [pipeline.py](pipeline.py) | normalize · graph · detections · replay · continuous scoring · sub-agents · write-back | README §1–6, §8 |
| [data.py](data.py) | synthetic estate (campaign + benign floor + NHI + agent) | [samples.md](../samples.md) |
| [run_demo.py](run_demo.py) | narrated CLI run (verifies the engine) | §10 build sequence |
| [soc_notebook.ipynb](soc_notebook.ipynb) | JupyterHub AI-SOC workspace + write-back + what-if | §8 agentic |
| [abstract_client.py](abstract_client.py) | live REST adapter (auth auto-detect, reads, creates, deletes) | §9 routing |
| [live_writeback.py](live_writeback.py) | minimal **real** loop: create field-set + view, verify, clean | §5 loop |
| [scenarios.py](scenarios.py) | the catalog: 9 entity-model field sets + 32 use-case scenarios | §1, §4 |
| [build_demo.py](build_demo.py) | **elaborate** live build: 9 field sets + 32 views + **32 real rules** + suppressions + analytics | all |
| [rules_engine.py](rules_engine.py) + `_rule_template.json` | real detection-rule authoring (Avro `query_json` via canonical template → CREATE_INSIGHT) | §4, §5 |
| [identities.py](identities.py) | identity taxonomy (human/NHI/SP/agent/cookie) + **live GreyNoise** + 24-engine pivot registry | §1, §8 |
| [viz_svg.py](viz_svg.py) | zero-dep branded SVG visuals (entity graph, MITRE heat strip, attack map, blast radius) | §6 |
| [viz.py](viz.py) | matplotlib/networkx interactive viz for the notebook | §6 |
| [report.py](report.py) | analyst incident report (Markdown + branded HTML) + write-back | §8 |
| [enable_rules.py](enable_rules.py) | enable/apply all rules (`--disable` kill switch) | §4 |
| [generate_insights.py](generate_insights.py) | push model findings as **real tenant insights** (`--cleanup` kill switch) | §5, §8 |
| [replay.py](replay.py) | author scenarios as **batch** rules (historical evaluation) + fire (`--cleanup` kill switch) | §4, §5 |
| [dashboard.py](dashboard.py) | branded **command center** HTML (all SVG visuals + live MITRE + write-back) | §6, §9 |
| [DEMO-CATALOG.md](DEMO-CATALOG.md) | full catalog + live-vs-simulated boundary | — |
| [LIVE-RESULTS.md](LIVE-RESULTS.md) | REST proof + endpoints + created objects + rule-step status | — |

**The "show everyone" artifacts:** `python3 dashboard.py` → branded `dashboard.html` (entity graph,
blast-radius rings, MITRE heat strip, attack timeline, risk + identity analytics, OSINT panel —
zero installs, opens in any browser). `python3 report.py` → analyst incident report. The
[soc_notebook.ipynb](soc_notebook.ipynb) is the interactive hunter experience
(`pip install matplotlib networkx numpy`).

## The closed loop — JupyterHub + Abstract API/MCP + triggers + write-back

This is the architecture the notebook stands in for:

```
 Abstract pipeline ──(API / MCP: normalized OCSF events + findings)──► JupyterHub notebook
        ▲                                                                     │
        │                                   graph · statistics · ML · what-if · forecast
        │                                                                     │
        └────(write back: findings · insights · entity scores · views)◄───────┘
```

- **Data in** — the Abstract **API or MCP** (`mcp__abstract-security__*`) streams normalized
  events and existing findings into the notebook. No CSV exports.
- **Compute** — the notebook adds what a streaming engine shouldn't carry inline: heavier graph
  traversal, statistical baselining, ML scoring, **hypotheticals/what-if**, and forecasting.
- **Data out** — results serialize back as Abstract **findings / insights / entity scores /
  views** (`finding_to_abstract()` shows the payload) and route to destinations like anything
  else. The notebook's output is a first-class platform object, not a dead-end report.
- **Triggers** — pipeline events (new verdict-fusion finding, new AIG IOC), JupyterHub/Papermill
  schedules (hourly re-score + forecast), or an agent decision. Each trigger parameterizes and
  runs the relevant notebook.
- **Continuous** — `continuous_scores()` re-scores every entity on every event (decaying EWMA
  stand-in for any model); scores crossing a threshold emit a predicted-target insight + SOAR
  action. The loop never stops: new events re-score, new findings spawn the next investigation.

## Simulated vs. real (the honest boundary)

| In this demo (simulated) | In Abstract (real) |
|---|---|
| `normalize()` hand-maps a few sources | parsers + OCSF normalization across 100s of sources |
| Python `IOCSet` matchlist | **AIG** live feeds + proprietary intel + dynamic lists |
| in-process detection functions | shift-left detection content (+ **ASTRO** packs) |
| `Graph` (dict adjacency) + replay over a list | persistent entity store + **LakeVilla** replay |
| `continuous_scores()` EWMA | production scoring model(s) updated in-stream |
| sub-agent functions (deterministic) | LLM agents over **MCP**, human-gated actions |
| `finding_to_abstract()` prints JSON | POST to findings/insights API → Views + routing |
| 5,018 synthetic events | your real estate |

The **modeled assumptions** (SIEM ingest lag 5m + rule cadence 15m; signal weights; EWMA
half-life 12h) are constants at the top of [pipeline.py](pipeline.py) — change them and re-run.
The MTTD and reduction figures are illustrative of the *architecture*, not benchmarked SLAs.
