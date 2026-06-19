# Abstract AI-SOC Investigation Console — Implementation Plan (Slice 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `soc_notebook.ipynb` into a live-Abstract-driven, picture-perfect investigation console (interactive correlation graphs, Identity Intelligence depth, pluggable enrichment fabric, dry-run write-back) that runs locally with one command.

**Architecture:** Additive modules around the existing stdlib engine (`pipeline.py`, `identities.py`). A `live_data` layer pulls + dedups live Abstract Insights/detections/analytics/identity models (offline → synthetic estate). `identity_intel`, an upgraded `enrichment` fabric, `viz_interactive` (pyvis/plotly), and `mitre_layer` feed an ipywidgets `console`. `report.py` and `build_notebook.py` produce the branded report + regenerated notebook.

**Tech Stack:** Python 3.12 (Miniforge `abstract-soc` env), JupyterLab, ipywidgets, pyvis, plotly, networkx, matplotlib, pandas, requests, mcp.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-19-investigation-console-design.md`. Every task implicitly inherits these.
- Working dir: `docs/threat-model/demo/` inside the repo whose root path has a **trailing space** (`/Users/mherbert/Documents/GitHub/Abstract-MS-Azure `) — always quote paths; never interpolate the absolute path into scripts unquoted.
- **Testing pattern (follow existing):** each module exposes `selftest()` and a `if __name__ == "__main__": print(selftest())` block; run with `python <module>.py`. Do **not** add pytest. Tests are dep-free shape checks (mirror `viz_svg.py:181` / `viz.py:190`).
- **Optional deps lazy-imported:** pyvis/plotly/matplotlib/networkx imported inside functions so modules import under bare stdlib; degrade to `viz.py`/`viz_svg.py`/synthetic estate. (Mirror `viz.py:17` `_mpl()`.)
- **Offline-safe:** any embedded JS bundled inline (pyvis `notebook=False`+local assets; plotly `include_plotlyjs="inline"`). No `http(s)://` asset refs in generated reports/notebook outputs except the optional MITRE Navigator deep-link.
- **Brand:** official palette only — `#FF216B` pink, `#E8005D`, `#C2004C`, `#060608` bg, `#FFFFFF`, accents `#01e69d` teal, `#f5c61e` amber, `#2e9bf0` blue. Fonts Barlow / Barlow Semi Condensed / JetBrains Mono with system fallback, no font CDN. Logos from `/Users/mherbert/.claude/projects/-Users-mherbert/memory/assets/abstract-logo-{white,black,mark}.svg`.
- **Secret hygiene:** API keys/tokens read from env only; never printed, logged, or embedded in outputs. Reuse `abstract_client.py` env handling.
- **Write safety:** every live mutation is **dry-run → confirm → apply**: preview exact payload + diff, require explicit confirmation, only then POST.
- **Commit style (user):** imperative subject, one sentence, NO `Co-Authored-By` footer.
- Commit after every task with the exact message given.

---

## File structure

| File | Responsibility | New/Mod |
|---|---|---|
| `docs/threat-model/demo/environment.yml` | Pin the `abstract-soc` conda env | NEW |
| `docs/threat-model/demo/run.sh` | One-command local launcher (`--check` mode for tests) | NEW |
| `docs/threat-model/demo/README.md` | Top "Quick start in 3 commands" block | MOD |
| `docs/threat-model/demo/brand.py` | Single source: palette, fonts, logo SVGs | NEW |
| `docs/threat-model/demo/viz.py` | Import palette from `brand` | MOD |
| `docs/threat-model/demo/viz_svg.py` | Import palette from `brand` | MOD |
| `docs/threat-model/demo/live_data.py` | `State` + `build_state` (REST/MCP pull, dedup, offline) | NEW |
| `docs/threat-model/demo/enrichment.py` | Pluggable adapter fabric + free feeds + dedup | MOD |
| `docs/threat-model/demo/identity_intel.py` | Identity Intelligence depth | NEW |
| `docs/threat-model/demo/viz_interactive.py` | pyvis correlation graph + blast radius + plotly | NEW |
| `docs/threat-model/demo/mitre_layer.py` | ATT&CK Navigator layer.json + matrix html | NEW |
| `docs/threat-model/demo/console.py` | ipywidgets operator console (the GUI) | NEW |
| `docs/threat-model/demo/report.py` | Self-contained branded report + dry-run write-back | MOD |
| `docs/threat-model/demo/build_notebook.py` | Generate console-centric notebook | MOD |
| `docs/threat-model/demo/requirements.txt` | Add pyvis, plotly | MOD |

---

## Phase 0 — Environment & dead-simple local run

### Task 0.1: `environment.yml` + `requirements.txt` + run.sh launcher

**Files:**
- Create: `docs/threat-model/demo/environment.yml`
- Create: `docs/threat-model/demo/run.sh`
- Modify: `docs/threat-model/demo/requirements.txt`

**Interfaces:**
- Produces: a `run.sh` with a `--check` mode (`run.sh --check` validates env + kernel and exits 0 without launching Jupyter) consumed by this task's test only.

- [ ] **Step 1: Write `environment.yml`**

```yaml
name: abstract-soc
channels:
  - conda-forge
dependencies:
  - python=3.12
  - jupyterlab>=4.0
  - ipykernel>=6.29
  - ipywidgets>=8.1
  - nbformat>=5.9
  - nbconvert>=7.10
  - matplotlib>=3.7
  - networkx>=3.1
  - numpy>=1.24
  - pandas>=2.0
  - plotly>=5.20
  - pyvis>=0.3.2
  - requests>=2.31
  - pip
  - pip:
      - mcp>=1.2
```

- [ ] **Step 2: Append the two new deps to `requirements.txt`** (under the visualization block, after `pandas>=2.0`)

```
# interactive (browser-native) visuals — bundled inline so the notebook works offline
plotly>=5.20
pyvis>=0.3.2
```

- [ ] **Step 3: Write `run.sh`** (handles trailing-space path; `--check` mode for CI)

```bash
#!/usr/bin/env bash
# Abstract AI-SOC — one-command local launcher.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # safe under trailing-space repo path
CONDA="${HOME}/miniforge3/bin/conda"
ENV="abstract-soc"

if [ ! -x "$CONDA" ]; then
  echo "Miniforge not found at $CONDA. Install: https://github.com/conda-forge/miniforge" >&2
  exit 1
fi
if ! "$CONDA" env list | grep -q "/${ENV}\$\|^${ENV} "; then
  echo "Creating '${ENV}' env from environment.yml ..."
  "$CONDA" env create -f "${HERE}/environment.yml"
fi
# Register the Jupyter kernel if missing.
if ! "$CONDA" run -n "$ENV" jupyter kernelspec list 2>/dev/null | grep -q "abstract-soc"; then
  "$CONDA" run -n "$ENV" python -m ipykernel install --user \
    --name abstract-soc --display-name "Abstract AI-SOC"
fi

if [ "${1:-}" = "--check" ]; then
  "$CONDA" run -n "$ENV" python -c "import jupyterlab,ipywidgets,matplotlib,networkx,pandas,plotly,pyvis,mcp,requests; print('env OK')"
  exit 0
fi
echo "Launching JupyterLab — pick the 'Abstract AI-SOC' kernel."
exec "$CONDA" run -n "$ENV" jupyter lab "${HERE}/soc_notebook.ipynb"
```

- [ ] **Step 4: Make executable + run the check**

Run: `chmod +x "docs/threat-model/demo/run.sh" && "docs/threat-model/demo/run.sh" --check`
Expected: prints `env OK` and exits 0.

- [ ] **Step 5: Commit**

```bash
git add docs/threat-model/demo/environment.yml docs/threat-model/demo/run.sh docs/threat-model/demo/requirements.txt
git commit -m "Add conda environment.yml and one-command run.sh launcher"
```

### Task 0.2: README quick-start

**Files:**
- Modify: `docs/threat-model/demo/README.md` (insert after line 1 heading, before "A dependency-free simulation")

- [ ] **Step 1: Insert quick-start block** at the top of `README.md`

```markdown
## Quick start (3 commands)

```bash
# 1. one-time: create the env (needs Miniforge — https://github.com/conda-forge/miniforge)
conda env create -f docs/threat-model/demo/environment.yml
# 2. launch (registers the kernel + opens JupyterLab; handles the trailing-space repo path)
./docs/threat-model/demo/run.sh
# 3. in JupyterLab, open soc_notebook.ipynb and pick the "Abstract AI-SOC" kernel
```

Runs fully **offline** out of the box. Add `~/.abstract.env` (Abstract key) + OSINT keys to light up live paths. Existing `.venv` users: `pip install -r docs/threat-model/demo/requirements.txt` still works.
```

- [ ] **Step 2: Verify** the block renders (no broken fences): `python -c "open('docs/threat-model/demo/README.md').read()"` (no error) and visually confirm.

- [ ] **Step 3: Commit**

```bash
git add docs/threat-model/demo/README.md
git commit -m "Add 3-command quick-start to the demo README"
```

---

## Phase 1 — Brand single-source

### Task 1.1: `brand.py`

**Files:**
- Create: `docs/threat-model/demo/brand.py`

**Interfaces:**
- Produces: constants `PINK, PINK_MID, PINK_DEEP, BG, WHITE, INK, MUT, PANEL, TEAL, AMBER, BLUE` (str hex); `TYPE_COLOR: dict[str,str]`; `FONT_STACK: str`; `logo_svg(variant: str = "white") -> str`; `selftest() -> dict`.

- [ ] **Step 1: Write the failing selftest + skeleton**

```python
"""Single source of Abstract brand truth — palette, fonts, official logos.
Every viz/report imports from here. Official colors per brand guide."""
from __future__ import annotations
import os

PINK, PINK_MID, PINK_DEEP = "#FF216B", "#E8005D", "#C2004C"
BG, WHITE = "#060608", "#FFFFFF"
TEAL, AMBER, BLUE = "#01e69d", "#f5c61e", "#2e9bf0"
INK, MUT, PANEL = "#e9e9f0", "#8a8a99", "#101016"
TYPE_COLOR = {"identity": TEAL, "account": BLUE, "host": "#b388ff", "nhi": AMBER,
              "agent": PINK, "device": "#b388ff", "session": "#feca57",
              "ip": "#ff6b6b", "domain": "#ff9f43", "url": "#feca57", "hash": "#9b9b9b"}
FONT_STACK = ('"Barlow","Barlow Semi Condensed",-apple-system,BlinkMacSystemFont,'
              '"Segoe UI",Roboto,sans-serif')
MONO_STACK = '"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace'

_LOGO_DIR = "/Users/mherbert/.claude/projects/-Users-mherbert/memory/assets"

def logo_svg(variant: str = "white") -> str:
    """Return official Abstract logo SVG markup ('white'|'black'|'mark'); '' if absent."""
    path = os.path.join(_LOGO_DIR, f"abstract-logo-{variant}.svg")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""

def selftest():
    assert PINK == "#FF216B"
    assert set(TYPE_COLOR) >= {"identity", "nhi", "agent", "device", "session"}
    assert logo_svg("mark") == "" or "<svg" in logo_svg("mark")
    return {"ok": True, "pink": PINK, "logo_present": bool(logo_svg("white"))}

if __name__ == "__main__":
    print(selftest())
```

- [ ] **Step 2: Run it to verify it passes** — Run: `cd "docs/threat-model/demo" && python brand.py` — Expected: `{'ok': True, 'pink': '#FF216B', 'logo_present': True}`

- [ ] **Step 3: Commit** — `git add docs/threat-model/demo/brand.py && git commit -m "Add brand.py single-source palette, fonts, official logos"`

### Task 1.2: Point `viz.py` + `viz_svg.py` at `brand.py`

**Files:**
- Modify: `docs/threat-model/demo/viz.py:12-14`
- Modify: `docs/threat-model/demo/viz_svg.py:14-18`

**Interfaces:**
- Consumes: `brand.{PINK,TEAL,BG,PANEL,INK,MUT,TYPE_COLOR}`.

- [ ] **Step 1:** In `viz.py` replace the `PINK, TEAL, BG, PANEL, INK, MUT = ...` line and the inline `TYPE_COLOR` dict with:

```python
from brand import PINK, TEAL, BG, PANEL, INK, MUT, TYPE_COLOR  # official palette
```

- [ ] **Step 2:** In `viz_svg.py` replace its `PINK, TEAL, BG, PANEL, INK, MUT = ...` line and inline `TYPE_COLOR` with the same import.

- [ ] **Step 3: Run both selftests** — Run: `cd "docs/threat-model/demo" && python viz_svg.py && python viz.py` — Expected: `viz_svg` prints `{'ok': True}`; `viz.py` prints `{'nodes': N, 'edges': M}` with N>0 (uses official pink now).

- [ ] **Step 4: Commit** — `git add docs/threat-model/demo/viz.py docs/threat-model/demo/viz_svg.py && git commit -m "Route viz modules through brand.py (official pink #FF216B)"`

---

## Phase 2 — Live Abstract data layer

> Read `abstract_client.py` (REST surface: search, views, fieldsets, rules, MITRE, insights) and `mcp_client.py` (list/call MCP tools) before this phase. Reuse their connect/auth; do not reimplement HTTP.

### Task 2.1: `live_data.py` — `State` + offline `build_state`

**Files:**
- Create: `docs/threat-model/demo/live_data.py`

**Interfaces:**
- Consumes: `pipeline.{normalize,Graph,run_detections,run_investigation,continuous_scores,efficiency}`, `data.{events,IOCS,INCIDENT_START}`.
- Produces: dataclass `State` with attrs `live: bool, norm: list, graph, findings: list, inv: dict, scores: dict, metrics: dict, insights: list, detections: list, analytics: dict, mitre: list, iocs`; function `build_state(connection=None, *, window_days: int = 30) -> State`; `_dedup(records: list[dict], key) -> list[dict]`; `selftest() -> dict`.

- [ ] **Step 1: Write the failing selftest + offline path**

```python
"""Unified investigation state. Pulls LIVE Abstract Insights/detections/analytics/
identity models when a connection is supplied; falls back to the synthetic estate offline.
Dedups overlapping records so merged sources don't double-count."""
from __future__ import annotations
from dataclasses import dataclass, field

from pipeline import (normalize, Graph, run_detections, run_investigation,
                      continuous_scores, efficiency)
from data import events as _events, IOCS, INCIDENT_START

@dataclass
class State:
    live: bool = False
    norm: list = field(default_factory=list)
    graph: object = None
    findings: list = field(default_factory=list)
    inv: dict = field(default_factory=dict)
    scores: dict = field(default_factory=dict)
    metrics: dict = field(default_factory=dict)
    insights: list = field(default_factory=list)
    detections: list = field(default_factory=list)
    analytics: dict = field(default_factory=dict)
    mitre: list = field(default_factory=list)
    iocs: object = None

def _dedup(records, key):
    """Stable de-dup: keep first occurrence per key(record)."""
    seen, out = set(), []
    for r in records:
        k = key(r)
        if k in seen:
            continue
        seen.add(k); out.append(r)
    return out

def _offline_state():
    norm = [normalize(i, r) for i, r in enumerate(_events())]
    g = Graph()
    for ev in norm:
        g.add(ev)
    findings = run_detections(norm, IOCS)
    inv = run_investigation(g, findings, IOCS, INCIDENT_START, norm)
    return State(live=False, norm=norm, graph=g, findings=findings, inv=inv,
                 scores=continuous_scores(norm, IOCS), metrics=efficiency(norm, findings),
                 iocs=IOCS)

def build_state(connection=None, *, window_days: int = 30) -> State:
    if connection is None:
        return _offline_state()
    return _live_state(connection, window_days)   # Task 2.2

def selftest():
    s = build_state(None)
    assert s.live is False and s.graph is not None and len(s.findings) > 0
    assert _dedup([{"id": 1}, {"id": 1}, {"id": 2}], lambda r: r["id"]) == [{"id": 1}, {"id": 2}]
    return {"ok": True, "findings": len(s.findings), "scored": len(s.scores)}

if __name__ == "__main__":
    print(selftest())
```

- [ ] **Step 2: Run to verify it fails** — Run: `cd "docs/threat-model/demo" && python live_data.py` — Expected: FAIL `NameError: name '_live_state' is not defined` only if `connection` passed; offline selftest should PASS. (selftest passes — `_live_state` referenced lazily.) If it errors on import, fix imports.

- [ ] **Step 3: Confirm offline selftest passes** — Expected: `{'ok': True, 'findings': >0, 'scored': >0}`.

- [ ] **Step 4: Commit** — `git add docs/threat-model/demo/live_data.py && git commit -m "Add live_data State model with offline synthetic build_state + dedup"`

### Task 2.2: `live_data._live_state` — pull + normalize + dedup live Abstract

**Files:**
- Modify: `docs/threat-model/demo/live_data.py`

**Interfaces:**
- Consumes: `abstract_client.AbstractClient` (methods discovered by reading the file: search/raw-search, list views, list fieldsets, rules, MITRE, insights). `mcp_client` for read-only tool calls.
- Produces: `_live_state(connection, window_days) -> State`.

- [ ] **Step 1: Add the live path** (graceful: any sub-pull that 4xx/5xx or is unsupported falls back to its offline equivalent; never raise)

```python
def _safe(call, default):
    try:
        return call()
    except Exception:   # noqa: BLE001 — one bad endpoint must not break the console
        return default

def _live_state(connection, window_days):
    """connection: an already-connected AbstractClient (REST). Pull live objects,
    normalize to engine shapes, dedup, and merge onto the synthetic baseline so the
    graph/timeline still render if a given endpoint is empty."""
    base = _offline_state()
    c = connection
    insights = _dedup(_safe(lambda: c.list_insights(), []), lambda r: r.get("id") or id(r))
    detections = _dedup(_safe(lambda: c.list_rules(), []), lambda r: r.get("id") or id(r))
    analytics = _safe(lambda: c.field_analytics(), {})
    mitre = _safe(lambda: c.mitre_summary(), [])
    base.live = True
    base.insights, base.detections, base.analytics, base.mitre = insights, detections, analytics, mitre
    return base
```

> NOTE for implementer: the exact client method names (`list_insights`, `list_rules`, `field_analytics`, `mitre_summary`) must match `abstract_client.py`. Read it first; if names differ, use the real ones and update the `Produces` block here. Do **not** invent endpoints.

- [ ] **Step 2: Add a live-path selftest** that monkeypatches a fake connection:

```python
# inside selftest(), append:
class _Fake:
    def list_insights(self): return [{"id": "i1"}, {"id": "i1"}]
    def list_rules(self): return [{"id": "r1"}]
    def field_analytics(self): return {"fields": 3}
    def mitre_summary(self): return [{"name": "Initial Access", "total": 10, "enabled": 8}]
    def raise_(self): raise RuntimeError
    list_views = list_fieldsets = lambda self: []
sl = build_state(_Fake())
assert sl.live is True and len(sl.insights) == 1 and sl.mitre[0]["total"] == 10
```

- [ ] **Step 3: Run** — Run: `cd "docs/threat-model/demo" && python live_data.py` — Expected: `{'ok': True, ...}` including the live-path asserts.

- [ ] **Step 4: Commit** — `git add docs/threat-model/demo/live_data.py && git commit -m "Add live_data._live_state: pull+dedup Abstract insights/detections/analytics/MITRE"`

---

## Phase 3 — Enrichment fabric

> Read the existing `enrichment.py` and `identities.py` (24-engine pivot registry, GreyNoise) first. Keep existing key-gated adapters working; add the registry + free adapters around them.

### Task 3.1: Adapter registry + dedup/merge core

**Files:**
- Modify: `docs/threat-model/demo/enrichment.py`

**Interfaces:**
- Produces: `class Adapter` (attrs/methods `name: str`, `kinds: set[str]`, `enabled() -> bool`, `enrich(value: str, kind: str) -> list[dict]`); `REGISTRY: list[Adapter]`; `register(a: Adapter)`; `enrich_entity(value: str, kind: str) -> dict` returning `{"value","kind","records":[...],"by_source":{name:[...]},"sources":[...]}` with deduped records; `_merge(record_lists) -> list[dict]`.

- [ ] **Step 1: Write failing selftest + registry core** (append to enrichment.py; do not remove existing functions)

```python
# ── Pluggable enrichment fabric ───────────────────────────────────────────────
import os

class Adapter:
    name = "base"; kinds: set = set()
    def enabled(self) -> bool: return True
    def enrich(self, value: str, kind: str) -> list: return []

REGISTRY: list = []
def register(a: Adapter): REGISTRY.append(a); return a

def _merge(record_lists):
    seen, out = set(), []
    for recs in record_lists:
        for r in recs:
            k = (r.get("source"), r.get("type"), str(r.get("value")))
            if k in seen: continue
            seen.add(k); out.append(r)
    return out

def enrich_entity(value: str, kind: str) -> dict:
    by_source, lists = {}, []
    for a in REGISTRY:
        if kind not in a.kinds or not a.enabled():
            continue
        try:
            recs = a.enrich(value, kind) or []
        except Exception:   # noqa: BLE001 — isolate adapter failures
            recs = [{"source": a.name, "type": "error", "value": "unavailable"}]
        by_source[a.name] = recs; lists.append(recs)
    return {"value": value, "kind": kind, "records": _merge(lists),
            "by_source": by_source, "sources": list(by_source)}

def fabric_selftest():
    class _A(Adapter):
        name = "t"; kinds = {"ip"}
        def enrich(self, v, k): return [{"source": "t", "type": "tag", "value": "x"}]
    REGISTRY.clear(); register(_A())
    e = enrich_entity("1.1.1.1", "ip")
    assert e["records"] == [{"source": "t", "type": "tag", "value": "x"}]
    assert enrich_entity("1.1.1.1", "domain")["records"] == []  # kind filter
    return {"ok": True, "sources": e["sources"]}
```

- [ ] **Step 2: Run** — Run: `cd "docs/threat-model/demo" && python -c "import enrichment; print(enrichment.fabric_selftest())"` — Expected: `{'ok': True, 'sources': ['t']}`

- [ ] **Step 3: Commit** — `git add docs/threat-model/demo/enrichment.py && git commit -m "Add pluggable enrichment adapter registry with dedup/merge"`

### Task 3.2: Free adapters — HIBP Pwned Passwords, Hudson Rock, IntelX, CISA KEV, NVD + stubs

**Files:**
- Modify: `docs/threat-model/demo/enrichment.py`

**Interfaces:**
- Consumes: `Adapter`, `register`, `requests` (lazy import).
- Produces: registered adapters `HIBPPasswords` (kinds={"password"}), `HudsonRock` (kinds={"email","domain","username"}), `IntelX` (kinds={"email","domain"}), `CisaKev` (kinds={"cve"}), `Nvd` (kinds={"cve"}); `register_default_fabric()` that registers all + labeled stubs (`Sentinel,Splunk,WildFire,JA3,DarkWeb` → `enabled()==False`).

- [ ] **Step 1: Implement the free adapters** (real free APIs; lazy `requests`; key from env; never log key)

```python
def _get(url, **kw):
    import requests
    return requests.get(url, timeout=kw.pop("timeout", 8), **kw)

@register
class HIBPPasswords(Adapter):
    """k-anonymity range API — never transmits the password, only the SHA1 prefix."""
    name = "hibp-pwned-passwords"; kinds = {"password"}
    def enrich(self, value, kind):
        import hashlib
        h = hashlib.sha1(value.encode()).hexdigest().upper()
        prefix, suffix = h[:5], h[5:]
        r = _get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if r.status_code != 200: return []
        for line in r.text.splitlines():
            suf, _, cnt = line.partition(":")
            if suf == suffix:
                return [{"source": self.name, "type": "pwned_count", "value": int(cnt)}]
        return [{"source": self.name, "type": "pwned_count", "value": 0}]

@register
class HudsonRock(Adapter):
    name = "hudsonrock-infostealer"; kinds = {"email", "domain", "username"}
    _EP = {"email": "search-by-login", "username": "search-by-login", "domain": "search-by-domain"}
    def enrich(self, value, kind):
        ep = self._EP[kind]; param = "domain" if kind == "domain" else "login"
        r = _get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/{ep}",
                 params={param: value})
        if r.status_code != 200: return []
        j = r.json()
        n = j.get("total") or j.get("stealers") and len(j["stealers"]) or 0
        return [{"source": self.name, "type": "infostealer_hits", "value": n, "raw": j}]

@register
class IntelX(Adapter):
    name = "intelx"; kinds = {"email", "domain"}
    def enabled(self): return bool(os.getenv("INTELX_API_KEY"))
    def enrich(self, value, kind):
        key = os.getenv("INTELX_API_KEY")
        r = _get("https://2.intelx.io/intelligent/search",
                 headers={"x-key": key}, params={"term": value, "maxresults": 10})
        if r.status_code != 200: return []
        return [{"source": self.name, "type": "leak_records", "value": value, "raw": r.json()}]

@register
class CisaKev(Adapter):
    name = "cisa-kev"; kinds = {"cve"}
    _URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    def enrich(self, value, kind):
        r = _get(self._URL, timeout=12)
        if r.status_code != 200: return []
        for v in r.json().get("vulnerabilities", []):
            if v.get("cveID", "").upper() == value.upper():
                return [{"source": self.name, "type": "known_exploited", "value": v.get("cveID"),
                         "raw": v}]
        return []

@register
class Nvd(Adapter):
    name = "nvd"; kinds = {"cve"}
    def enrich(self, value, kind):
        r = _get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                 params={"cveId": value})
        if r.status_code != 200: return []
        return [{"source": self.name, "type": "nvd", "value": value, "raw": r.json()}]

# labeled stubs (Slice 3) — visible in the GUI, never run live yet
class _Stub(Adapter):
    def __init__(self, name, kinds): self.name = name; self.kinds = set(kinds)
    def enabled(self): return False
    def enrich(self, v, k): return []

def register_default_fabric():
    for nm, ks in [("microsoft-sentinel", {"ip","host","account"}),
                   ("splunk", {"ip","host","account"}),
                   ("paloalto-wildfire", {"hash","url","domain"}),
                   ("ja3-ja4", {"session","ip"}),
                   ("darkweb-osint", {"email","username","domain"})]:
        register(_Stub(nm, ks))
```

- [ ] **Step 2: Add a network-free selftest** for the registry shape (do not hit live APIs in selftest — assert adapters register & kind routing; live calls are validated manually).

```python
def fabric_v1_selftest():
    REGISTRY.clear()
    # re-register decorated adapters by instantiating classes
    for cls in (HIBPPasswords, HudsonRock, IntelX, CisaKev, Nvd):
        register(cls())
    register_default_fabric()
    names = {a.name for a in REGISTRY}
    assert {"hibp-pwned-passwords","hudsonrock-infostealer","cisa-kev","nvd"} <= names
    assert any(a.name == "splunk" and not a.enabled() for a in REGISTRY)  # stub disabled
    return {"ok": True, "n_adapters": len(REGISTRY)}
```

> NOTE: the `@register` decorator already appends on import, so `REGISTRY.clear()` + manual re-register in the selftest keeps it deterministic. Keep that pattern.

- [ ] **Step 3: Run** — Run: `cd "docs/threat-model/demo" && python -c "import enrichment; print(enrichment.fabric_v1_selftest())"` — Expected: `{'ok': True, 'n_adapters': >=10}`

- [ ] **Step 4: Commit** — `git add docs/threat-model/demo/enrichment.py && git commit -m "Add free enrichment adapters (HIBP/HudsonRock/IntelX/CISA-KEV/NVD) + Slice-3 stubs"`

---

## Phase 4 — Identity Intelligence

### Task 4.1: `identity_intel.py` — exposure, re-exposure, hygiene, predictive

**Files:**
- Create: `docs/threat-model/demo/identity_intel.py`

**Interfaces:**
- Consumes: `live_data.State`, `identities` (classify_entity), `enrichment.enrich_entity`.
- Produces: dataclasses `ReExposure(entity,count,events,survives_restore,first,last)`, `Signal(entity,kind,detail,score)`; functions `re_exposure(state) -> list[ReExposure]`, `session_hijacking(state) -> list[Signal]`, `mfa_bombing(state) -> list[Signal]`, `password_reuse(state) -> list[Signal]`, `persistent_bad_hygiene(state) -> list[Signal]`, `vip_at_risk(state, vips: set[str]) -> list[Signal]`, `predictive(state) -> dict`, `score(state) -> dict`, `summary(state, vips=None) -> dict`; `selftest()`.

- [ ] **Step 1: Write the failing selftest + implementations** (deterministic logic over `State`; no live calls in selftest)

```python
"""Identity Intelligence — re-exposure (incl. survival across IDP/immutable-backup
restore), session hijacking, MFA bombing, password reuse, persistent bad hygiene,
VIP-at-risk, predictive/situational awareness. Operates over live_data.State."""
from __future__ import annotations
from dataclasses import dataclass, field
import identities as ID

@dataclass
class ReExposure:
    entity: str; count: int; events: list = field(default_factory=list)
    survives_restore: bool = False; first=None; last=None

@dataclass
class Signal:
    entity: str; kind: str; detail: str; score: int

def _principals(state):
    """Entities (principals) seen in the graph, keyed 'type:id'."""
    g = state.graph
    return sorted(getattr(g, "nodes", {}) or [])

def re_exposure(state) -> list:
    """Group repeated exposure-bearing events per principal; a principal is
    'survives_restore' when exposure recurs across a restore boundary marker."""
    by_ent = {}
    for ev in state.norm:
        acct = ev.raw.get("account") or ev.raw.get("user_name") or ev.raw.get("user")
        if not acct: continue
        key = f"account:{acct}"
        exposed = bool(ev.malicious_control) or ev.raw.get("exposed") or \
                  ev.source in ("okta", "email", "nhi", "agent")
        if exposed:
            by_ent.setdefault(key, []).append(ev)
    out = []
    for ent, evs in by_ent.items():
        evs = sorted(evs, key=lambda e: e.ts)
        restored = any(e.raw.get("idp_restore") or e.raw.get("backup_restore") for e in evs)
        recurs_after = restored and len([e for e in evs if e.ts]) >= 2
        out.append(ReExposure(entity=ent, count=len(evs), events=evs,
                              survives_restore=recurs_after or len(evs) >= 3,
                              first=evs[0].ts, last=evs[-1].ts))
    return sorted(out, key=lambda r: -r.count)

def session_hijacking(state) -> list:
    sig = []
    seen_ip = {}
    for ev in state.norm:
        acct = ev.raw.get("account") or ev.raw.get("user_name")
        ip = ev.raw.get("source_address") or ev.raw.get("ip")
        if acct and ip:
            prev = seen_ip.get(acct)
            if prev and prev != ip:
                sig.append(Signal(f"account:{acct}", "session_hijacking",
                                  f"auth from new IP {ip} (was {prev})", 70))
            seen_ip[acct] = ip
    return sig

def mfa_bombing(state) -> list:
    from collections import Counter
    c = Counter()
    for ev in state.norm:
        if ev.raw.get("mfa_prompt") or ev.raw.get("event") == "mfa_challenge":
            c[ev.raw.get("account") or ev.raw.get("user_name")] += 1
    return [Signal(f"account:{a}", "mfa_bombing", f"{n} MFA prompts", min(90, 30 + n*10))
            for a, n in c.items() if a and n >= 3]

def password_reuse(state) -> list:
    """Flag accounts whose observed password pattern recurs / is breach-known.
    Live HIBP check is opt-in via enrichment; here we use the recorded flag."""
    out = []
    for ev in state.norm:
        if ev.raw.get("pwned") or ev.raw.get("password_reused"):
            acct = ev.raw.get("account") or ev.raw.get("user_name")
            if acct:
                out.append(Signal(f"account:{acct}", "password_reuse",
                                  "password seen in breach/infostealer corpus", 60))
    return out

def persistent_bad_hygiene(state) -> list:
    rex = {r.entity: r for r in re_exposure(state)}
    return [Signal(e, "persistent_bad_hygiene",
                   f"{r.count} exposures; survives restore={r.survives_restore}",
                   min(95, 50 + r.count*5))
            for e, r in rex.items() if r.count >= 2]

def vip_at_risk(state, vips=None) -> list:
    vips = vips or set()
    out = []
    for k, s in state.scores.items():
        ident = k.split(":", 1)[1] if ":" in k else k
        if ident in vips and s.get("final", 0) >= 50:
            out.append(Signal(k, "vip_at_risk", f"VIP risk {s['final']}", s["final"]))
    return out

def predictive(state) -> dict:
    pred = (state.inv or {}).get("prediction", {})
    return {"predicted_next_targets": pred.get("predicted_next_targets", []),
            "rationale": pred.get("rationale", ""),
            "situational": {"principals": len(_principals(state)),
                            "high_risk": sum(1 for s in state.scores.values() if s.get("final",0) >= 80)}}

def score(state) -> dict:
    """Fuse identity signals into the continuous scores (additive bump, capped 100)."""
    bumps = {}
    for fn in (session_hijacking, mfa_bombing, password_reuse, persistent_bad_hygiene):
        for sig in fn(state):
            bumps[sig.entity] = max(bumps.get(sig.entity, 0), sig.score)
    fused = dict(state.scores)
    for ent, bump in bumps.items():
        cur = fused.get(ent, {"final": 0})
        fused[ent] = {**cur, "final": min(100, max(cur.get("final", 0), bump))}
    return fused

def summary(state, vips=None) -> dict:
    return {"re_exposure": re_exposure(state), "session_hijacking": session_hijacking(state),
            "mfa_bombing": mfa_bombing(state), "password_reuse": password_reuse(state),
            "persistent_bad_hygiene": persistent_bad_hygiene(state),
            "vip_at_risk": vip_at_risk(state, vips), "predictive": predictive(state)}

def selftest():
    from live_data import build_state
    st = build_state(None)
    summ = summary(st, vips=set())
    assert isinstance(summ["re_exposure"], list)
    assert isinstance(score(st), dict)
    return {"ok": True, "re_exposed": len(summ["re_exposure"]),
            "predicted": len(summ["predictive"]["predicted_next_targets"])}

if __name__ == "__main__":
    print(selftest())
```

- [ ] **Step 2: Run to verify it passes** — Run: `cd "docs/threat-model/demo" && python identity_intel.py` — Expected: `{'ok': True, 're_exposed': N, 'predicted': M}` (N may be 0 on the baseline estate — that's fine; assert is about shape).

- [ ] **Step 3: Commit** — `git add docs/threat-model/demo/identity_intel.py && git commit -m "Add identity_intel: re-exposure, session-hijack, MFA-bombing, hygiene, predictive"`

### Task 4.2: Seed identity signals into the synthetic estate

**Files:**
- Modify: `docs/threat-model/demo/data.py`

**Interfaces:**
- Consumes: existing `events()`.
- Produces: a few extra synthetic events carrying `mfa_prompt`, `password_reused`/`pwned`, `idp_restore`, and a second-IP auth so `identity_intel` produces non-empty demo output.

- [ ] **Step 1:** In `data.py`'s event list, add (near the campaign account, e.g. the okta/account events) 3–4 events:
  - two `okta` auths for the same `account` from different `source_address` (session hijack),
  - 4 `okta` `mfa_challenge`/`mfa_prompt` events for that account (MFA bombing),
  - one event with `"password_reused": true` / `"pwned": true`,
  - one event with `"idp_restore": true` followed by another exposure for the same account (survives-restore).
  Match the existing event dict shape exactly (read the file first).

- [ ] **Step 2: Run** — Run: `cd "docs/threat-model/demo" && python identity_intel.py && python run_demo.py >/dev/null && echo OK` — Expected: `{'ok': True, 're_exposed': >=1, ...}` then `OK` (the CLI engine still runs).

- [ ] **Step 3: Commit** — `git add docs/threat-model/demo/data.py && git commit -m "Seed identity-intel demo signals (hijack, MFA bombing, reuse, restore) into estate"`

---

## Phase 5 — Interactive visuals

### Task 5.1: `viz_interactive.py` — pyvis correlation graph + blast radius

**Files:**
- Create: `docs/threat-model/demo/viz_interactive.py`

**Interfaces:**
- Consumes: `brand`, `live_data.State`, lazy `pyvis`.
- Produces: `correlation_graph(state, *, focus=None, height="640px") -> str` (HTML), `blast_radius(state) -> str`, `available() -> bool`; `selftest()`. On missing pyvis, `correlation_graph` returns `viz_svg.entity_graph_svg(...)` instead.

- [ ] **Step 1: Write failing selftest + implementation**

```python
"""Interactive (pyvis/plotly) visuals. JS bundled inline → works offline.
Degrades to viz_svg/viz when libs are absent. Mirrors viz.build_nx_graph's
node/edge selection (viz.py:35)."""
from __future__ import annotations
import brand

def available() -> bool:
    try:
        import pyvis  # noqa: F401
        return True
    except Exception:
        return False

def _nodes_edges(state):
    g = state.graph; iocs = state.iocs
    scores = state.scores
    nodes = set(g.reachable_principals(iocs.keys())) | {k for k in iocs.keys() if k in g.nodes}
    edges = []
    for a in nodes:
        for b in g.adj.get(a, ()):
            if b in nodes and a < b:
                edges.append((a, b))
    return nodes, edges, scores

def correlation_graph(state, *, focus=None, height="640px") -> str:
    if not available():
        import viz_svg
        return viz_svg.entity_graph_svg(state.graph, state.iocs, state.scores)
    from pyvis.network import Network
    net = Network(height=height, width="100%", bgcolor=brand.BG, font_color=brand.INK,
                  notebook=False, cdn_resources="in_line")   # inline JS → offline
    nodes, edges, scores = _nodes_edges(state)
    for k in nodes:
        t = k.split(":", 1)[0]
        risk = scores.get(k, {}).get("final", 0)
        net.add_node(k, label=k.split(":", 1)[1][:18], color=brand.TYPE_COLOR.get(t, brand.MUT),
                     value=10 + risk, title=f"{k}\\nrisk {risk}",
                     borderWidth=3 if (focus and k == focus) else 1)
    for a, b in edges:
        net.add_edge(a, b, color="#33334a")
    net.toggle_physics(True)
    return net.generate_html(notebook=False)

def blast_radius(state) -> str:
    import viz_svg
    return viz_svg.blast_radius_svg((state.inv or {}).get("subagents", {}).get("scoping", {}))

def selftest():
    from live_data import build_state
    st = build_state(None)
    html = correlation_graph(st)
    assert "<" in html and (("vis-network" in html) or ("<svg" in html))
    assert "<svg" in blast_radius(st) or blast_radius(st) == ""
    return {"ok": True, "pyvis": available(), "len": len(html)}

if __name__ == "__main__":
    print(selftest())
```

- [ ] **Step 2: Run** — Run: `cd "docs/threat-model/demo" && python viz_interactive.py` — Expected: `{'ok': True, 'pyvis': True, 'len': >1000}`

- [ ] **Step 3: Commit** — `git add docs/threat-model/demo/viz_interactive.py && git commit -m "Add viz_interactive pyvis correlation graph (inline JS) with SVG fallback"`

### Task 5.2: `viz_interactive` — Plotly panels

**Files:**
- Modify: `docs/threat-model/demo/viz_interactive.py`

**Interfaces:**
- Produces: `risk_panel(state) -> str`, `timeline(state) -> str`, `coverage_by_rule(state) -> str`, `exposure_timeline(state) -> str` — each returns a self-contained `<div>` from `plotly.io.to_html(..., include_plotlyjs="inline", full_html=False)`; degrade to `viz.draw_*` PNG-in-`<img>` if plotly absent.

- [ ] **Step 1: Implement Plotly panels**

```python
def _plotly_ok():
    try:
        import plotly  # noqa: F401
        return True
    except Exception:
        return False

def _fig_html(fig):
    import plotly.io as pio
    return pio.to_html(fig, include_plotlyjs="inline", full_html=False,
                       config={"displaylogo": False})

def risk_panel(state) -> str:
    if not _plotly_ok():
        return "<div>risk panel needs plotly</div>"
    import plotly.graph_objects as go
    items = list(state.scores.items())[:12]
    ys = [k for k, _ in items][::-1]; xs = [s["final"] for _, s in items][::-1]
    colors = [brand.PINK if v >= 80 else (brand.TEAL if v >= 50 else brand.MUT) for v in xs]
    fig = go.Figure(go.Bar(x=xs, y=ys, orientation="h", marker_color=colors))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, plot_bgcolor=brand.BG,
                      title="Continuous entity risk", height=420, margin=dict(l=160))
    return _fig_html(fig)

def timeline(state) -> str:
    if not _plotly_ok(): return "<div>timeline needs plotly</div>"
    import plotly.graph_objects as go
    pts = sorted([e for e in state.norm if e.malicious_control or e.severity in ("high","critical")],
                 key=lambda e: e.ts)[:20]
    if not pts: return "<div>no high-severity events</div>"
    fig = go.Figure(go.Scatter(x=[e.ts for e in pts], y=[e.source for e in pts], mode="markers",
                    marker=dict(size=12, color=brand.PINK)))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, title="Attack-chain timeline",
                      height=360)
    return _fig_html(fig)

def coverage_by_rule(state) -> str:
    if not _plotly_ok(): return "<div>coverage needs plotly</div>"
    import plotly.graph_objects as go
    from collections import Counter
    c = Counter(f.rule for f in state.findings)
    rules = list(c); vals = [c[r] for r in rules]
    fig = go.Figure(go.Bar(x=vals, y=rules, orientation="h", marker_color=brand.TEAL))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG, title="Detection coverage by rule",
                      height=max(300, 30*len(rules)), margin=dict(l=200))
    return _fig_html(fig)

def exposure_timeline(state) -> str:
    if not _plotly_ok(): return "<div>exposure needs plotly</div>"
    import plotly.graph_objects as go
    import identity_intel as II
    rex = II.re_exposure(state)
    if not rex: return "<div>no re-exposure events</div>"
    fig = go.Figure()
    for r in rex[:8]:
        fig.add_trace(go.Scatter(x=[e.ts for e in r.events], y=[r.entity]*len(r.events),
                      mode="markers+lines", name=r.entity.split(":",1)[-1][:16],
                      marker=dict(color=brand.AMBER if r.survives_restore else brand.BLUE)))
    fig.update_layout(template="plotly_dark", paper_bgcolor=brand.BG,
                      title="Identity re-exposure timeline (amber = survives restore)", height=420)
    return _fig_html(fig)
```

- [ ] **Step 2: Extend selftest** — append: `for f in (risk_panel, timeline, coverage_by_rule, exposure_timeline): assert "<" in f(st)`

- [ ] **Step 3: Run** — Run: `cd "docs/threat-model/demo" && python viz_interactive.py` — Expected: `{'ok': True, ...}`

- [ ] **Step 4: Commit** — `git add docs/threat-model/demo/viz_interactive.py && git commit -m "Add Plotly risk/timeline/coverage/exposure panels (inline JS)"`

### Task 5.3: `mitre_layer.py`

**Files:**
- Create: `docs/threat-model/demo/mitre_layer.py`

**Interfaces:**
- Consumes: `live_data.State` (`state.mitre`), `brand`.
- Produces: `build_layer(state, name="Abstract investigation") -> dict`, `write_layer(state, path="mitre_layer.json") -> str`, `matrix_html(state) -> str`; `selftest()`.

- [ ] **Step 1: Implement** (Navigator layer v4.5 schema; coverage→score; observed techniques flagged)

```python
"""ATT&CK Navigator layer.json export + in-notebook matrix. Layer opens in
https://mitre-attack.github.io/attack-navigator/ (the only external link we emit)."""
from __future__ import annotations
import json, brand

def build_layer(state, name="Abstract investigation") -> dict:
    techniques = []
    for t in (state.mitre or []):
        for tech in t.get("techniques", []) or []:
            total = tech.get("total", 0); en = tech.get("enabled", 0)
            techniques.append({"techniqueID": tech.get("id") or tech.get("techniqueID"),
                               "score": int(100*en/total) if total else 0,
                               "color": brand.TEAL if en else "",
                               "comment": f"{en}/{total} rules enabled"})
    return {"name": name, "versions": {"layer": "4.5", "navigator": "4.9.1"},
            "domain": "enterprise-attack", "description": "Abstract live coverage + observed",
            "techniques": techniques,
            "gradient": {"colors": [brand.BG, brand.TEAL], "minValue": 0, "maxValue": 100}}

def write_layer(state, path="mitre_layer.json") -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_layer(state), fh, indent=2)
    return path

def matrix_html(state) -> str:
    import viz_svg
    return viz_svg.mitre_heatstrip_svg(state.mitre or [])

def selftest():
    from live_data import build_state
    layer = build_layer(build_state(None))
    assert layer["versions"]["layer"] == "4.5" and "techniques" in layer
    assert "<" in matrix_html(build_state(None))
    return {"ok": True, "techniques": len(layer["techniques"])}

if __name__ == "__main__":
    print(selftest())
```

- [ ] **Step 2: Run** — Run: `cd "docs/threat-model/demo" && python mitre_layer.py` — Expected: `{'ok': True, 'techniques': N}`

- [ ] **Step 3: Commit** — `git add docs/threat-model/demo/mitre_layer.py && git commit -m "Add mitre_layer ATT&CK Navigator export + matrix html"`

### Task 5.4: `viz_interactive` — diverse diagram suite (way more than bubbles)

**Files:** Modify `docs/threat-model/demo/viz_interactive.py`

**Interfaces (each returns a self-contained `<div>` via `_fig_html`; degrade to a `<div>` notice if plotly absent):**
- `attack_flow_sankey(state)` — Sankey of the kill-chain flow (source → tactic → entity-kind → outcome) weighted by event counts.
- `association_matrix(state)` — entity×entity adjacency heatmap (who-touched-whom), brand colorscale.
- `entity_event_timeline(state, entity=None)` — Plotly timeline/Gantt of events per entity over time.
- `mitre_matrix(state)` — full interactive ATT&CK matrix heatmap (tactic columns × technique cells), coverage-scored — richer than the strip.
- `risk_radar(state, entity)` — scatterpolar of an entity's risk dimensions (exposure / hijack / hygiene / privilege / blast-radius).
- `exposure_sunburst(state)` — sunburst: entity-kind → entity → exposure-source.
- `tactic_treemap(state)` — treemap: tactic → technique → finding count.
- `temporal_heatmap(state)` — activity heatmap (time-bucket × source).

- [ ] **Step 1:** Implement the eight functions with `plotly.graph_objects`/`plotly.express`, `template="plotly_dark"`, `paper_bgcolor=brand.BG`, brand colors; each guarded by `_plotly_ok()`.
- [ ] **Step 2:** Extend `selftest()` — for each fn assert `"<" in fn(st)` (pass a real entity key for radar from `list(st.scores)[0]`).
- [ ] **Step 3:** Run `python viz_interactive.py` → `{'ok': True, ...}`.
- [ ] **Step 4:** Commit — `git commit -m "Add Sankey/matrix/timeline/MITRE-matrix/radar/sunburst/treemap/heatmap visuals"`

### Task 5.5: `viz_interactive` — expressive network + per-entity detail card

**Files:** Modify `docs/threat-model/demo/viz_interactive.py`

**Interfaces:**
- `correlation_graph(state, *, focus=None, layout="force", height="640px")` — upgrade: **shape per kind** (host=box, nhi=diamond, agent=triangle, device=square, session=hexagon, account=dot, VIP=star, ip/domain/hash=icon), **edge relationship labels** (authenticated-from / executed / beaconed-to / owns / assumed-role from graph edge metadata), **layout modes** `force|hierarchical|radial|clustered` (pyvis options), **full-field hover tooltip** (every raw field of the focal entity), click-to-select wired in the console.
- `entity_detail_html(state, entity) -> str` — a full branded card: ALL raw fields for that entity, risk breakdown (base + identity bumps), identity signals, enrichment summary slot, related-entities list with pivot affordances, and an annotation slot.

- [ ] **Step 1:** Implement layout/shape/edge-label upgrades + `entity_detail_html`; keep the SVG fallback when pyvis is absent.
- [ ] **Step 2:** Extend `selftest()` — assert `correlation_graph(st, layout="hierarchical")` returns markup and `entity_detail_html(st, list(st.scores)[0])` contains the entity id.
- [ ] **Step 3:** Run `python viz_interactive.py` → `{'ok': True, ...}`.
- [ ] **Step 4:** Commit — `git commit -m "Add expressive network (shapes/edge-labels/layouts) + per-entity detail card"`

---

## Phase 6 — Operator console (the GUI)

> **Expanded interaction scope (per user):** the Graph tab gets a **view-type selector**
> (Network · Sankey · Association matrix · Timeline · MITRE matrix · Sunburst · Treemap ·
> Temporal heatmap · Risk radar) and a **layout switcher**; a **filters** row (entity-type
> multiselect · risk slider · time window); **drill-down** (search or click → `entity_detail_html`
> in a detail pane with pivot buttons that re-focus the graph + pull enrichment + identity intel);
> and **annotations** (per-entity notes kept on the Console, surfaced in the report).

### Task 6.1: `console.py` — render builders (logic, GUI-free, fully testable)

**Files:**
- Create: `docs/threat-model/demo/console.py`

**Interfaces:**
- Consumes: `live_data`, `identity_intel`, `enrichment`, `viz_interactive`, `mitre_layer`, `brand`.
- Produces: pure builders `overview_html(state) -> str`, `identity_html(state, vips=None) -> str`, `enrichment_html(result: dict) -> str`, `writeback_preview(state) -> dict` (the dry-run payload + a `diff` string, **no** network), `selftest()`. (Widget wiring is Task 6.2 and is import-guarded.)

- [ ] **Step 1: Implement the builders + failing selftest**

```python
"""Operator console. Split into pure HTML/preview builders (testable headless)
and the ipywidgets shell (Task 6.2, import-guarded)."""
from __future__ import annotations
import html, brand

def _badge(state):
    txt = "LIVE tenant" if state.live else "OFFLINE — modeled data"
    col = brand.TEAL if state.live else brand.AMBER
    return f'<span style="background:{col};color:{brand.BG};padding:2px 8px;border-radius:6px;font-weight:700">{txt}</span>'

def overview_html(state) -> str:
    m = state.metrics or {}
    return (f'<div style="font-family:{brand.FONT_STACK};color:{brand.INK}">{_badge(state)} '
            f'<h2 style="color:{brand.PINK}">Investigation overview</h2>'
            f'<p>findings: {len(state.findings)} · insights: {len(state.insights)} · '
            f'detections: {len(state.detections)} · scored entities: {len(state.scores)}</p></div>')

def identity_html(state, vips=None) -> str:
    import identity_intel as II
    s = II.summary(state, vips or set())
    rows = "".join(f"<li>{html.escape(r.entity)} — {r.count}× exposure"
                   f"{' · <b>survives restore</b>' if r.survives_restore else ''}</li>"
                   for r in s["re_exposure"][:10])
    sigs = "".join(f"<li>{html.escape(x.entity)} — {x.kind} ({x.score})</li>"
                   for x in (s["session_hijacking"]+s["mfa_bombing"]+s["password_reuse"])[:10])
    return (f'<div style="font-family:{brand.FONT_STACK};color:{brand.INK}">'
            f'<h3 style="color:{brand.TEAL}">Re-exposure</h3><ul>{rows or "<li>none</li>"}</ul>'
            f'<h3 style="color:{brand.TEAL}">Identity signals</h3><ul>{sigs or "<li>none</li>"}</ul></div>')

def enrichment_html(result: dict) -> str:
    recs = "".join(f"<li>{html.escape(r.get('source',''))}: {html.escape(str(r.get('type','')))} = "
                   f"{html.escape(str(r.get('value','')))}</li>" for r in result.get("records", []))
    return (f'<div style="font-family:{brand.FONT_STACK};color:{brand.INK}">'
            f'<b>{html.escape(result.get("value",""))}</b> ({html.escape(result.get("kind",""))}) '
            f'→ sources: {", ".join(result.get("sources", [])) or "none"}<ul>{recs}</ul></div>')

def writeback_preview(state) -> dict:
    """Dry-run only: build the exact view/insight payload + a human diff. No network."""
    name = "[ABS-DEMO] Investigation — console"
    payload = {"name": name, "query": [{"id": "q1", "depth": 0, "field": "severity", "index": 0,
               "value": "critical", "parentId": None, "fieldType": "String",
               "field_operation": "EQUALS", "subFieldOperation": ""}],
               "fields": ["type", "@timestamp", "severity", "user_name", "message"],
               "order_by": "@timestamp", "order_type": "DESC"}
    diff = f"CREATE view '{name}'  (+{len(payload['fields'])} fields, 1 query clause)"
    return {"action": "create_view", "payload": payload, "diff": diff, "applied": False}

def selftest():
    from live_data import build_state
    st = build_state(None)
    assert "Investigation overview" in overview_html(st)
    assert "Re-exposure" in identity_html(st)
    assert enrichment_html({"value":"1.1.1.1","kind":"ip","sources":["t"],"records":[]})
    wb = writeback_preview(st)
    assert wb["applied"] is False and wb["action"] == "create_view"
    return {"ok": True}

if __name__ == "__main__":
    print(selftest())
```

- [ ] **Step 2: Run** — Run: `cd "docs/threat-model/demo" && python console.py` — Expected: `{'ok': True}`

- [ ] **Step 3: Commit** — `git add docs/threat-model/demo/console.py && git commit -m "Add console render/preview builders (headless-testable, dry-run write-back)"`

### Task 6.2: `console.py` — ipywidgets shell

**Files:**
- Modify: `docs/threat-model/demo/console.py`

**Interfaces:**
- Consumes: the Task 6.1 builders, lazy `ipywidgets`, `IPython.display`.
- Produces: `Console(state, vips=None)` class with `.show()` returning the tabbed widget; tabs Overview/Graph/Insights/Analytics/Identity/Enrichment/Report/Actions; a search box; an Actions tab with **Dry-run → Confirm → Apply** buttons (Apply disabled until a connection is attached via `.attach(connection)`); `launch(connection=None, vips=None)` convenience.

- [ ] **Step 1: Implement the widget shell** (import-guarded so `console.py` still imports headless)

```python
def _widgets():
    import ipywidgets as w
    from IPython.display import HTML, display
    return w, HTML, display

class Console:
    def __init__(self, state, vips=None, connection=None):
        self.state, self.vips, self.connection = state, vips or set(), connection
    def attach(self, connection): self.connection = connection
    def _html_box(self, html_str):
        w, HTML, _ = _widgets()
        return w.HTML(value=html_str)
    def show(self):
        w, HTML, display = _widgets()
        import viz_interactive as VI, mitre_layer as ML, enrichment as EN
        st = self.state
        search = w.Text(placeholder="search entity / IOC / CVE…", description="Find:")
        graph_out = w.Output(); enrich_out = w.Output()
        with graph_out: display(HTML(VI.correlation_graph(st)))
        def on_search(_):
            enrich_out.clear_output()
            val = search.value.strip()
            kind = "cve" if val.lower().startswith("cve-") else (
                   "ip" if val.count(".") == 3 else ("email" if "@" in val else "domain"))
            with enrich_out:
                display(HTML(enrichment_html(EN.enrich_entity(val, kind))))
            graph_out.clear_output()
            with graph_out: display(HTML(VI.correlation_graph(st, focus=val)))
        search.on_submit(on_search)
        # Actions: dry-run → confirm → apply
        dry = w.Button(description="Dry-run write-back", button_style="info")
        confirm = w.Checkbox(value=False, description="I confirm this live mutation")
        apply = w.Button(description="Apply to tenant", button_style="danger", disabled=True)
        act_out = w.Output()
        def on_dry(_):
            act_out.clear_output()
            with act_out:
                wb = writeback_preview(st)
                print(wb["diff"]); print(wb["payload"])
                apply.disabled = not (self.connection and confirm.value)
        def on_confirm(ch): apply.disabled = not (self.connection and ch["new"])
        def on_apply(_):
            with act_out:
                if not self.connection: print("No connection attached — dry-run only."); return
                wb = writeback_preview(st)
                res = self.connection.create_view(wb["payload"])   # real POST
                print("applied:", (res.get("body") or {}).get("id"))
        dry.on_click(on_dry); confirm.observe(on_confirm, "value"); apply.on_click(on_apply)
        actions = w.VBox([dry, confirm, apply, act_out])
        tabs = w.Tab()
        children = [self._html_box(overview_html(st)), graph_out,
                    self._html_box(f"<pre>{len(st.insights)} insights / {len(st.detections)} detections</pre>"),
                    self._html_box(f"<pre>{st.analytics}</pre>"),
                    self._html_box(identity_html(st, self.vips)),
                    w.VBox([search, enrich_out]),
                    self._html_box(ML.matrix_html(st)), actions]
        tabs.children = children
        for i, t in enumerate(["Overview","Graph","Insights","Analytics","Identity","Enrichment","Report","Actions"]):
            tabs.set_title(i, t)
        return w.VBox([w.HTML(f"<h2 style='color:{brand.PINK};font-family:{brand.FONT_STACK}'>Abstract AI-SOC Console</h2>"), tabs])

def launch(connection=None, vips=None):
    from live_data import build_state
    return Console(build_state(connection), vips=vips, connection=connection).show()
```

- [ ] **Step 2: Add a guarded selftest** that asserts the module imports headless and that `Console` instantiates without ipywidgets being *called* (don't call `.show()` headless):

```python
# append to selftest():
from live_data import build_state
c = Console(build_state(None))
assert c.state is not None and c.connection is None
```

- [ ] **Step 3: Run** — Run: `cd "docs/threat-model/demo" && python console.py` — Expected: `{'ok': True}` (no ipywidgets import at module load).

- [ ] **Step 4: Commit** — `git add docs/threat-model/demo/console.py && git commit -m "Add ipywidgets console shell with search + dry-run/confirm/apply write-back"`

---

## Phase 7 — Branded report

### Task 7.1: `report.py` — self-contained branded report embedding interactive panels

**Files:**
- Modify: `docs/threat-model/demo/report.py` (replace `html_report` at lines 102-120; add identity section to `markdown`; keep `--writeback` dry-run-first)

**Interfaces:**
- Consumes: `live_data.build_state`, `viz_interactive`, `mitre_layer`, `identity_intel`, `brand`.
- Produces: `html_report(state) -> str` (self-contained: inline fonts/CSS via `brand`, embedded pyvis graph + plotly panels + identity section + MITRE matrix); `main()` writes `.md` + `.html`; `--writeback` prints the dry-run preview and only POSTs with `--apply`.

- [ ] **Step 1: Rewrite `build()`** to use `live_data.build_state(None)` and rewrite `html_report` to embed `viz_interactive.correlation_graph(state)`, `viz_interactive.risk_panel(state)`, `viz_interactive.exposure_timeline(state)`, `mitre_layer.matrix_html(state)`, and an Identity Intelligence section from `identity_intel.summary(state)`. Header uses `brand.logo_svg("white")` and `brand.FONT_STACK`. **No** `http(s)://` refs (drop the Google-Fonts `<link>`).

- [ ] **Step 2: Make write-back dry-run-first** — in `main()`, on `--writeback` print `console.writeback_preview(state)`; only when `--apply` is also present, connect `AbstractClient` and POST.

- [ ] **Step 3: Add `selftest()`** asserting the HTML is self-contained:

```python
def selftest():
    from live_data import build_state
    h = html_report(build_state(None))
    assert "http://" not in h and "https://" not in h.replace("https://mitre-attack.github.io", "")
    assert "Abstract" in h and ("vis-network" in h or "<svg" in h)
    return {"ok": True, "bytes": len(h)}
```

- [ ] **Step 4: Run** — Run: `cd "docs/threat-model/demo" && python -c "import report; print(report.selftest())" && python report.py` — Expected: `{'ok': True, 'bytes': >5000}` then writes `investigation_report.md` + `.html`.

- [ ] **Step 5: Commit** — `git add docs/threat-model/demo/report.py docs/threat-model/demo/investigation_report.* && git commit -m "Rebuild report.py as self-contained branded report; dry-run-first write-back"`

---

## Phase 8 — Notebook regeneration + end-to-end validation

### Task 8.1: `build_notebook.py` — add the console section + regenerate

**Files:**
- Modify: `docs/threat-model/demo/build_notebook.py`
- Regenerate: `docs/threat-model/demo/soc_notebook.ipynb`

**Interfaces:**
- Consumes: existing notebook-builder helpers in `build_notebook.py` (read first).
- Produces: a new "Visual investigation console" section near the top that does:
  `from live_data import build_state; from console import Console; Console(build_state()).show()`
  plus markdown explaining offline/live + the dry-run write-back, and a cell exporting the report + `mitre_layer.write_layer(build_state())`.

- [ ] **Step 1:** Add cells (follow the file's existing cell-append pattern). First code cell of the section:

```python
# Visual investigation console — offline by default; pass a connected AbstractClient for live.
from live_data import build_state
from console import Console
state = build_state()          # offline synthetic estate; build_state(client) for LIVE
Console(state, vips={"ceo@acme.example", "cfo@acme.example"}).show()
```

- [ ] **Step 2: Regenerate** — Run: `cd "docs/threat-model/demo" && python build_notebook.py` — Expected: writes `soc_notebook.ipynb`, prints cell count.

- [ ] **Step 3: Headless execute** — Run:
```bash
cd "docs/threat-model/demo" && "$HOME/miniforge3/bin/conda" run -n abstract-soc \
  jupyter nbconvert --to notebook --execute --inplace \
  --ExecutePreprocessor.kernel_name=abstract-soc \
  --ExecutePreprocessor.timeout=300 soc_notebook.ipynb && echo EXEC_OK
```
Expected: `EXEC_OK` (notebook runs end-to-end, no exceptions).

- [ ] **Step 4: Commit** — `git add docs/threat-model/demo/build_notebook.py docs/threat-model/demo/soc_notebook.ipynb && git commit -m "Regenerate notebook with the visual investigation console section (validated headless)"`

### Task 8.2: Full-suite green + docs cross-link

**Files:**
- Modify: `docs/threat-model/demo/README.md` (add console + Navigator-layer note to the "show everyone" section)

- [ ] **Step 1: Run every selftest**
```bash
cd "docs/threat-model/demo" && for m in brand viz_svg viz live_data enrichment identity_intel viz_interactive mitre_layer console report; do
  echo "== $m =="; "$HOME/miniforge3/bin/conda" run -n abstract-soc python "$m.py" 2>&1 | tail -1 || exit 1; done
```
Expected: each prints an `{'ok': True, ...}`-style line (enrichment via its `fabric_v1_selftest`).

- [ ] **Step 2:** Add one paragraph + run line to README documenting the console (`Console(build_state()).show()`), the offline/live toggle, dry-run write-back, and `mitre_layer.json` Navigator export.

- [ ] **Step 3: Commit** — `git add docs/threat-model/demo/README.md && git commit -m "Document the investigation console + Navigator layer export in the README"`

---

## Self-review notes (author)
- **Spec coverage:** env/run (P0), brand (P1), live Abstract pull+dedup (P2), enrichment fabric + free feeds + stubs (P3), identity depth incl. survives-restore (P4), pyvis+plotly+MITRE Navigator (P5), total-GUI console + dry-run/confirm/apply (P6), self-contained branded report (P7), notebook regen + headless validation (P8). External SIEM/dark-web connectors + full write surface are explicitly Slices 2–3 (stubs visible now).
- **Live endpoint names** in Task 2.2 are marked to be reconciled against `abstract_client.py` by the implementer (do not invent).
- **Offline-first** everywhere; no test hits a live API or requires a key.
