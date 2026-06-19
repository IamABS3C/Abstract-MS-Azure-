# Design — Abstract AI-SOC Investigation Console (Slice 1)

**Date:** 2026-06-19
**Status:** Proposed (awaiting user review)
**Program:** A notebook-native **operator console** driven by *live* Abstract data, with
deep visual correlation, a pluggable enrichment fabric, Identity Intelligence depth, and
dry-run-first write-back. Built as slices; each slice gets its own spec → plan → build.

This spec is **Slice 1** — the foundation **plus** Identity Intelligence depth (per the
"bigger Slice 1" decision). Slices 2–3 are sequenced in the Roadmap and are out of scope here.

---

## 1. Goal

Make `docs/threat-model/demo/soc_notebook.ipynb` the easiest-to-run, most interactive,
picture-perfect **investigation console** an analyst/hunter/researcher would use — primarily
driven by **live Abstract Insights, detections, analytics, and identity (+ other) models**,
visualizing deep **relationships / associations / correlations**, enriched from a pluggable
fabric of external sources (deduped), and able to write findings back to Abstract safely.

### Decisions locked in (from brainstorming)
- **Environment:** Miniforge `abstract-soc` env. ✅ installed, verified, kernel registered.
- **Interactivity:** pyvis + plotly, JS **bundled inline** (fully offline); `viz_svg.py` kept
  as zero-install fallback.
- **Data posture:** **maximize live Abstract** — pull Insights / detections / analytics /
  identity + other models via REST + MCP wherever the API supports it; fall back to the
  synthetic estate / offline with a clear badge.
- **Write-back safety:** **dry-run → confirm → apply** for every live mutation.
- **Enrichment fabric v1 (free / free-tier):** HIBP Pwned Passwords (k-anonymity), Intelligence
  X free tier, Hudson Rock infostealer (Cavalier), GreyNoise + the existing 24-engine registry,
  CISA KEV + NVD (free, no-auth). Extensible registry with labeled stubs + key-slots for any
  other user/password/PII/OSINT/HUMINT source; results **deduped/merged**.
- **Slice 1 scope:** foundation **+ Identity Intelligence depth**.

### Priorities (from the user, verbatim intent)
Deep relationships/associations/correlations in detailed views & graphs, prioritized by what's
visible in **all** Abstract Insights/detections/analytics; use Abstract's Identity models and
any other models; enrich from external tools/feeds Abstract may not have. Identity is a key
lens among **all** detections — not the only one.

### Non-goals (Slice 1)
- Full Abstract write surface for *every* object type (rules/filters/schemas/models/…): the
  **GUI menus appear** in the console shell, but only the report → view/insight write-back is
  wired live in Slice 1; the rest land in Slice 2.
- Live connectors to Sentinel/Splunk/Copilot, WildFire, JA3 capture, gov/TLP ingest, and
  dark-web/social/forum scraping: **adapter stubs** appear in the fabric (labeled, behind
  explicit enablement / keys), wired live in Slice 3.
- No change to the core detection/scoring math in `pipeline.py` beyond additive hooks.

### Responsible-use note
External exposure lookups (infostealer/breach/PII) target **the org's own identities** for
defensive exposure monitoring (the SpyCloud/HIBP-for-enterprise pattern). Adapters for sources
with restrictive ToS or no sanctioned API ship as **disabled, labeled stubs** — we wire only
sources with a legitimate free API in Slice 1. Secrets are env-read, never printed or logged.

---

## 2. Architecture

Additive and modular — one module = one purpose, pure functions where possible, lazy imports of
heavy/optional libs, a `selftest()` per module (dep-free shape checks, matching the existing style).

```
 brand.py ── official palette / fonts / logo SVGs (single source) ── consumed everywhere
     │
 live_data.py ──┐  pull + normalize + DEDUP live Abstract Insights/detections/analytics/
 (NEW)          │  identity+other models via abstract_client(REST)+mcp_client(MCP);
                │  offline → synthetic estate (data.py). Emits the unified Graph + entities.
                ▼
 pipeline.py (engine, +additive hooks) ── Graph · detections · replay · scoring · prediction
                │
     ┌──────────┼───────────────────────────┬───────────────────────────┐
 identity_intel.py (NEW)            enrichment.py (UPGRADED:        viz_interactive.py (NEW)
 re-exposure · session-hijack ·     pluggable adapter registry +   pyvis correlation graph +
 MFA-bombing · password-reuse ·     dedup/merge; free feeds wired;  blast radius; plotly charts;
 VIP/at-risk · persistent-hygiene · stubs for the rest)            mitre_layer.py (NEW: Navigator
 predictive/situational awareness                                  layer.json + matrix)
     └──────────┴───────────────────────────┴───────────────────────────┘
                                            │
                              console.py (NEW) — ipywidgets operator console
                              tabs: Overview · Graph · Insights/Detections · Analytics ·
                              Identity · Enrichment · Report · Actions; search/lookup/navigate;
                              dry-run → confirm → apply controls
                                            │
                              report.py (UPGRADED) — self-contained branded HTML report
                              (embeds interactive panels + identity section); dry-run write-back
                                            │
                              build_notebook.py (UPGRADED) → soc_notebook.ipynb (regenerated,
                              re-validated headless) ; environment.yml + run.sh + README
```

**Degradation contract:** any module that needs an optional dep (pyvis/plotly) or a live
connection lazy-imports/guards it and falls back (matplotlib `viz.py` / SVG `viz_svg.py` /
synthetic estate) so the notebook never hard-fails.

---

## 3. Components & interfaces

### 3.0 Environment & dead-simple run
- **`environment.yml`** pins the `abstract-soc` env (python 3.12 + jupyterlab, ipykernel,
  ipywidgets, nbformat, nbconvert, matplotlib, networkx, numpy, pandas, plotly, requests, pyvis;
  `mcp` via pip).
- **`run.sh`** — one command: resolves the **trailing-space repo path**, activates the env via
  `$HOME/miniforge3/bin/activate abstract-soc` (no shell-init required), registers the kernel if
  missing, launches `jupyter lab soc_notebook.ipynb`. Idempotent; helpful errors. Windows note included.
- **README** gets a top-of-file "Quick start in 3 commands" block.

### 3.1 `brand.py` (NEW — single source of truth)
- Official palette: `PINK="#FF216B"`, `PINK_MID="#E8005D"`, `PINK_DEEP="#C2004C"`, `BG="#060608"`,
  `WHITE="#FFFFFF"`, `TEAL="#01e69d"`, `AMBER="#f5c61e"`, `BLUE="#2e9bf0"`, + `INK/MUT/PANEL`,
  `TYPE_COLOR` entity map.
- Fonts: Barlow / Barlow Semi Condensed / JetBrains Mono — **self-contained** (system-font
  fallback stack; no CDN). `logo_svg(variant)` returns the official logo markup from the memory
  assets (`abstract-logo-{white,black,mark}.svg`, confirmed present).
- `viz.py` / `viz_svg.py` refactored to import from `brand.py` (replaces the off-brand `#f8226a`).

### 3.2 `live_data.py` (NEW — "maximize live Abstract")
- `Source` abstraction with two backends: REST (`abstract_client.AbstractClient`) and MCP
  (`mcp_client`). Methods: `insights()`, `detections()`, `analytics()`, `identity_models()`,
  `other_models()`, `events(window)`, `mitre_coverage()`.
- `build_state(connection, *, window) -> State` — pulls live objects, **normalizes** them into
  the engine's shapes (entities, findings, graph edges), **dedups/merges** overlapping records
  (stable key per entity/IOC/finding), and returns a unified `State` (graph, findings, scores,
  insights, analytics, mitre). Offline / no key → builds `State` from `data.py` synthetic estate
  and stamps `state.live=False` for the offline badge.
- Never logs the API key; reuses the existing AES/secret hygiene (env-read only).

### 3.3 `enrichment.py` (UPGRADED — pluggable fabric)
- Formalize the existing OSINT adapters into a registry: each adapter implements `name`, `kinds`
  (which entity types it supports: ip/domain/hash/email/username/password/url/asn/ja3…),
  `enabled()` (key present / sanctioned), and `enrich(value, kind) -> list[Record]` (normalized).
- **Wired free adapters (Slice 1):** HIBP Pwned Passwords (k-anonymity range — never sends the
  password), Intelligence X (free tier), Hudson Rock Cavalier (infostealer), GreyNoise + the
  existing 24-engine pivot registry, CISA KEV, NVD. Existing key-gated adapters (VT, Shodan,
  AbuseIPDB, OTX, urlscan, Censys, HIBP-breach) remain.
- **Stubs (labeled, disabled):** DeHashed/LeakCheck/SpyCloud (key-slots), WildFire, JA3/JA4,
  Sentinel/Splunk, dark-web/social/forum, gov/TLP — appear in the registry as "needs key /
  Slice 3" so the GUI shows the full surface honestly.
- `enrich_entity(value, kind) -> Enrichment` fans out across enabled adapters, **dedups/merges**
  results, returns provenance per field. Rate-limit/backoff + per-adapter timeout; failures are
  isolated (one bad adapter never breaks enrichment).

### 3.4 `identity_intel.py` (NEW — Identity Intelligence depth)
Operates over the unified `State` + enrichment fabric; entity taxonomy reuses `identities.py`
(human / NHI / service-principal / managed-identity / agent / device / session/cookie).
- `re_exposure(state) -> list[ReExposure]` — tracks each entity's exposure events over time;
  flags **continuous / repeat** exposure. Models **survival across IDP / immutable-backup
  restore**: a restore event clears tenant state but the entity is **re-flagged** because the
  underlying credential/pattern is still exposed in feeds (honest "modeled in demo / live where
  Abstract insights support it" seam).
- `session_hijacking(state) -> list[Signal]` — impossible-travel, token/cookie reuse,
  UA/JA3 mismatch (uses fabric fingerprints).
- `mfa_bombing(state)`, `password_reuse(state)` (HIBP k-anonymity + pattern heuristics),
  `persistent_bad_hygiene(state)` (recurring offenders), `vip_at_risk(state)` (VIP tag × risk).
- `predictive(state) -> Forecast` — next-likely targets + situational-awareness rollup
  (reuses `pipeline` prediction + identity signals).
- `score(state)` — fuses identity signals into `continuous_scores` so the graph/risk panels
  reflect identity risk. Each function returns plain dataclasses/dicts → easy to render & test.

### 3.5 `viz_interactive.py` (NEW) + `mitre_layer.py` (NEW)
- `correlation_graph(state, *, focus=None) -> html` — pyvis vis.js graph of entities +
  relationships + correlations; drag/zoom/hover tooltips (kind, risk, exposure, last-seen),
  click-to-pivot/expand, dedup-aware; node color `brand.TYPE_COLOR`, size by risk.
- `blast_radius(state) -> html`; `risk_panel / timeline / trajectories / coverage_by_rule /
  efficiency / identity_taxonomy / exposure_timeline` → Plotly (inline JS). All degrade to
  `viz.py`/`viz_svg.py` if libs absent.
- `mitre_layer.build_layer(state) / write_layer() / matrix_html(state)` — standard ATT&CK
  Navigator `layer.json` (coverage + observed techniques) + in-notebook interactive matrix.

### 3.6 `console.py` (NEW — the total GUI)
- An `ipywidgets` operator console with tabs: **Overview · Graph · Insights/Detections ·
  Analytics · Identity · Enrichment · Report · Actions**, plus a **search/lookup/navigate** bar
  (find an entity/IOC/finding → focus the graph + pull enrichment + identity intel).
- **Add/update menus** present across tabs (the "total GUI"): Slice-1 wires the report →
  view/insight write-back live; other create/update forms are visible but render a "lands in
  Slice 2" notice — honest, no fake actions.
- Every mutating action follows **dry-run → confirm → apply** (preview payload + diff, explicit
  confirm widget, then POST). Orchestrates `live_data` + `viz_interactive` + `identity_intel` +
  `enrichment` + `mitre_layer` + `report`.

### 3.7 `report.py` (UPGRADED) + `build_notebook.py` (UPGRADED)
- One self-contained branded HTML report: official header/logo, exec summary, embedded
  interactive correlation graph + blast radius + Plotly panels + KPI cards + **Identity
  Intelligence section** (re-exposure, VIPs at risk, persistent offenders, predictions) + MITRE
  matrix + recommended actions; print-to-PDF clean; all JS inline. Dry-run-first write-back.
- `build_notebook.py` generates the console-centric notebook, regenerates `soc_notebook.ipynb`,
  and **re-validates** it executes headless via nbconvert with the `abstract-soc` kernel.

---

## 4. Data flow
1. **Connect** (REST + MCP) → `live_data.build_state` pulls Insights/detections/analytics/
   identity+other models, normalizes + **dedups** → unified `State` (offline → synthetic estate).
2. **Engine + Identity** — `pipeline` + `identity_intel` compute graph, findings, fused risk,
   re-exposure, predictions.
3. **Enrich** — fabric fans out over enabled adapters, dedups/merges, attaches provenance.
4. **Render** — `console` shows correlation graph, blast radius, MITRE, timelines, risk &
   identity panels; search/navigate/pivot.
5. **Export** — self-contained branded report + Navigator `layer.json`.
6. **Write-back** — dry-run preview → confirm → apply (view/insight) via `abstract_client`.

## 5. Error handling
- Missing optional dep → lazy-guard → matplotlib/SVG fallback + one-line note.
- Offline / no key → synthetic estate + visible "offline — modeled data" badge; live-only panels
  (MITRE coverage, write-back) clearly disabled.
- Enrichment: per-adapter timeout + backoff; one failing/ratelimited adapter never breaks the rest.
- Write-back: dry-run is default; live POST only after explicit confirm; failures show HTTP
  status + body, **never** a raw key/token.
- Trailing-space repo path handled by quoting + kernel-by-name (no absolute-path interpolation).

## 6. Testing
- `selftest()` per new/changed module (dep-free shape checks), runnable as `python <module>.py`.
- `build_notebook.py` regenerates + headless-executes the notebook
  (`jupyter nbconvert --to notebook --execute --inplace --ExecutePreprocessor.kernel_name=abstract-soc`).
- Report validated self-contained (no `http(s)://` asset refs); opens with no console errors.
- Live paths guarded so the offline path passes with no key.
- Manual: drive the console end-to-end, export the report, load `mitre_layer.json` in Navigator.

## 7. Roadmap (out of scope here — own specs next)
- **Slice 2 — Abstract write surface ("add/update all things").** Dry-run-first create/update of
  rules, detections, filters, schemas, suppressions, alerts, models, analytics, insights, views,
  fieldsets — docking into the console's existing menus.
- **Slice 3 — External tool & feed connectors.** Sentinel · Splunk · Security Copilot/Workspaces;
  WildFire API; JA3/JA3S/JA4 fingerprinting; gov/TLP advisory ingest (CISA/DHS/FBI/DISA);
  dark-web/social/forum + HUMINT adapters (where API/ToS permit); MCP/AI-agent enrichment;
  file ingest — flipping the labeled stubs in the fabric to live.
