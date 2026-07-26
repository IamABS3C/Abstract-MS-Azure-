# Abstract × Sentinel — Gaps, Gamechanger & the SE Playbook

*Why a live, in-product, bidirectional competitive tool is a homerun no competitor is running — and the gaps to close to make it undeniable.*

---

## The gamechanger thesis

Every vendor ships a **static** competitive deck. We ship a **living competitive instrument that runs inside the prospect's own Microsoft Sentinel**, reads **their real cost, incidents, and MTTR**, pulls **live Abstract insights, reduction, and tune-at-source data via the API**, and computes the comparison **on their numbers, in the tool they already use**.

Nobody else is doing this. The competitive artifact *is* the product working.

### What makes it unique (and hard to copy)

1. **It lives in the SIEM.** A Content Hub solution — the competitive/TCO workbook, connectors, parser, hunts, automation and playbooks install where the buyer already works. Not a PDF; a deployed experience.
2. **Bidirectional, live API integration.** Two connectors: Abstract → Sentinel (destination) and an **Insights & Detections API sync** (insights, verdicts, tune-at-source filters, pipeline IO metrics, detection effectiveness) so the comparison works **even when Sentinel isn't the destination**.
3. **Measured, not modeled, reduction.** Aggregation/dedupe ratio comes straight from `aggregation_count` (live: ~34:1). Tier-aware TCO prices Analytics ($4.30/GB) vs. data lake ($0.05/GB) — the real cost lever.
4. **Composable SIEM framing.** Per the [manifesto](https://www.abstract.security/manifesto), Sentinel is *one composable component* (Collection · Detection · Retention · AI-SecOps), not a competitor to knock. Disarms the "rip-and-replace" objection.
5. **The tune-at-source loop.** Disposition an incident FP in Sentinel → Abstract adds an upstream filter → fewer GB **and** fewer future incidents. A closed loop only a pipeline can offer.
6. **Integrity by design.** Cited third-party stats (CardinalOps, Vectra, Mandiant, CrowdStrike, ISC2, Tines, IBM), Abstract's own published claims, and positioning are **separately labeled** — so it survives technical scrutiny.
7. **A runnable outbrief.** The comparison notebook regenerates a customer-specific scorecard from their tenant + workspace.

---

## Better together — the one-liner

> **Abstract makes Sentinel cheaper, faster, and higher-fidelity — and keeps you un-locked-in.** Cut volume and cost before ingest, land decision-ready insights, detect in-stream, and route full fidelity to a cheap lake — while Sentinel stays your investigation and compliance home. Augment today; rebalance on your own numbers.

---

## Gaps to close (the homerun checklist)

| # | Gap | Impact | How to close |
| --- | --- | --- | --- |
| 1 | **Live pipeline metrics / detection-effectiveness empty in the demo tenant** | `AbstractPipelineMetrics_CL` / `AbstractDetectionEffectiveness_CL` panels show no data | Point the **API Sync** connector at a production tenant with live pipeline volume; both are already wired to the confirmed endpoints (`/v3/pipelines/metrics/`, `/v2/rules/detection-effectiveness`). |
| 2 | **RunPlaybook automation rules need the Sentinel MI role** | Verdict/Tune playbooks don't auto-run until permissioned | Grant **Microsoft Sentinel Automation Contributor** to the Sentinel MI on the RG, then attach Verdict (on-create) + Tune-at-source (on-update, FP) automation rules. Ships as a documented post-step; the safe tag/prioritize automation rule installs today. |
| 3 | **Abstract API key for the live pullers** | Pullers can't sync without a key | Provide the key as a **securestring / Key Vault reference** at connector deploy. Never in the template. |
| 4 | **True MTTD** | Currently a SIEM detect-lag proxy | With live ingestion, compute event-time → alert-time precisely; the panel is built for it. |
| 5 | **Content Hub certification (verified badge)** | Private install today, not Marketplace-listed | Run Microsoft's `createSolutionV4.ps1` + `arm-ttk` over `solution/` and submit via Partner Center (see `Package/PACKAGING.md`). |
| 6 | **Detection overlap depth** | Coverage shown at technique level | Add a Sentinel-rule ↔ Abstract-detection overlap matrix once both detection catalogs are pulled (Abstract ships 1,153 curated detections). |

---

## The SE POV playbook (how to run it)

1. **Install** the Abstract Content Hub solution into the prospect's Sentinel (or a lab mirror).
2. **Connect** the API Sync connector with the prospect's Abstract trial key → live insights/tuning/metrics flow in.
3. **Open** the *Competitive & TCO Command Center* workbook; set the cost parameters to their real $/GB and daily volume.
4. **Walk** cost → reduction → detections/MITRE → incidents/MTTR/MTTD → AI-SOC → tune-at-source, on *their* data.
5. **Leave behind** the branded HTML brief; **hand over** the notebook for their team to re-run.
6. **Decide** augment / optimize / rebalance from the migration ladder — on real numbers.

*Figures are demo-measured or modeled from parameters (Sentinel list pricing, East US, verified 2026-07); capability claims are grounded in Abstract content + Sentinel product facts. Validate current pricing/product before external use.*
