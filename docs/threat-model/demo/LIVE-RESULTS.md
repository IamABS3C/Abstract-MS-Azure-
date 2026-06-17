# Live integration — proven against a real Abstract tenant

This is the record of wiring the demo to a live Abstract tenant via the documented
REST API (not the read-only MCP). The closed loop **reads** the tenant and **writes back**
real objects.

## What works (verified)

| Capability | Endpoint | Result |
|---|---|---|
| Auth | `Authorization: Bearer <key>` + `x-as-vendor-account-id` | ✅ auto-detected by `connect()` (200) |
| Read views | `GET /v1/streamviewer/views` | ✅ |
| Read field sets | `GET /v1/streamviewer/field-sets` | ✅ |
| **Create field set** | `POST /v1/streamviewer/field-set` | ✅ **200** — entity-centric projection |
| **Create view** | `POST /v1/streamviewer/view` | ✅ **201** — threat-research findings surface |
| Delete (cleanup) | `DELETE /v1/streamviewer/{view,field-set}/{id}`, `/v1/rules/{nanoid}` | ✅ idempotent re-runs |
| Validate rule | `POST /v3/rules/validations` | ✅ `is_valid: true` |
| **Create detection rule** | `POST /v1/rules/` | ✅ **32 real rules** (CREATE_FINDING + CREATE_INSIGHT) |
| Create suppression | `POST /v2/rule-tuning-filters/` | ✅ 2 created |
| Live MITRE coverage | `GET /v3/rules/mitre` | ✅ 318/363 techniques |
| Field analytics | `POST /v1/streamviewer/field-analytics` | ✅ live top-N |
| Enable rules | `PATCH /v1/rules/{nanoid}` (`name`+`is_enabled`+`state`) | ✅ 32/32 enabled |
| **Generate insights** | `POST /v1/insights/` | ✅ **8 real insights** from the model |
| Delete insight | `DELETE /v1/insights/{nanoid}` | ✅ kill switch |

A representative run created field-set + view as `created_by: mherbert@abstract.security`
(IDs rotate each run because the script cleans + recreates). Run it yourself:

```bash
cd docs/threat-model/demo
python3 live_writeback.py            # clean prior demo objects → create + verify
python3 live_writeback.py --cleanup  # remove the demo objects
python3 dashboard.py --mode api      # same write-back, then render dashboard.html (LIVE banner)
```

## What's created on the tenant

- **Field set** `WildFire/PAN Threat Research — Entity Fields (demo)` — 29 fields validated
  against the live 549-value `FieldEnum` (the real Abstract Common Schema): `user_name`,
  `source_address`, `dest_address`, `file.hash.sha256`, `destination.domain`, `dns.question.name`,
  `tls.client.ja3`, `threat.indicator`, `threat.technique_id`, `process.command_line`,
  `email.attachments.file.hash.sha256`, … — the entity model from [../README.md](../README.md) §1,
  in real field names.
- **View** `WildFire / PAN Threat Research (Abstract model demo)` — `type = Finding`, 30-day
  window, bound to the field set. The threat-research surface for hash/domain/IP/user pivots.

Both are clearly `(demo)`-named and reversible. `live_writeback.py` cleans them on each run.

## Detection rules — REAL (resolved)

Rules are the richest write-back (rules **generate findings + insights**), and they now work:

- The Create Rule `query_json` is an **Avro structure** with union type tags
  (`security.abs.rules.avro.state.*`). Rather than reverse-engineer it, [rules_engine.py](rules_engine.py)
  **copies a canonical rule** captured from the tenant (`GET /v1/rules/{nanoid}` →
  `_rule_template.json`) and swaps only the condition list — guaranteeing a valid body.
- `POST /v3/rules/validations` confirms `is_valid: true`; `POST /v1/rules/` (trailing slash —
  no-slash 307s) creates it. Required extras beyond validate: `query_snapshot: []`.
- The template's actions include **CREATE_FINDING + CREATE_INSIGHT**, so an enabled rule
  produces real insights. Rules are created **disabled** (`is_enabled: false`) to avoid tenant
  noise — flip to enable.
- [build_demo.py](build_demo.py) creates **all 32 scenarios as real rules** (verified: 32 created,
  0 failures; creating them raised the tenant's MITRE coverage 331 → 363 techniques).

**Gotcha (handled):** `GET /v3/rules` is eventually-consistent — it intermittently returns an
empty `data` array while `total_count` stays correct (and the `sort` param triggers that path).
`build_demo._list_rules_stable()` retries until the array is populated, so cleanup is reliable.

## Generating data (insights)

Two ways the demo produces visible tenant data:

1. **Enable rules** ([enable_rules.py](enable_rules.py)) — flips all 32 `[ABS-DEMO]` rules to
   `is_enabled:true`, `state:production`. These are **realtime** rules, so they fire on *new*
   incoming events; on a quiet/historical tenant they won't backfill. Kill switch:
   `python3 enable_rules.py --disable`.
2. **Generate insights directly** ([generate_insights.py](generate_insights.py)) — pushes the
   model's findings to `POST /v1/insights/` as **real, visible insights** (8 created; tenant total
   1→9), each with MITRE + severity; the lead carries blast radius, predicted targets, and a
   **live GreyNoise verdict**. This is the reliable "show data now" path. Kill switch:
   `python3 generate_insights.py --cleanup`.
3. **Batch replay** ([replay.py](replay.py)) — authors the 32 scenarios as `action: batch` rules
   (validated `is_valid:true`, created + enabled) that evaluate **historical** data. The engine
   runs them on its batch cycle; the manual force trigger is `POST /v1/rules/refresh-rules` with a
   `cep` type selector — but the exact param name wasn't discoverable via the API (it 400s as
   "all" otherwise). Capture the UI's refresh-rules request to pin it (same method that unlocked
   rule creation). Kill switch: `python3 replay.py --cleanup`.

## Live OSINT (real)

`identities.greynoise_community(ip)` is a **real, unauthenticated GreyNoise community API call**
(e.g. `185.220.101.45` → `classification: malicious, noise: true`). `identities.pivot_urls()`
builds one-click pivots across **24 hacker search engines** (Shodan, Censys, ZoomEye, FOFA,
Criminal IP, VirusTotal, urlscan, crt.sh, IntelligenceX, Dehashed, Hudson Rock, Exploit-DB …),
curated from [awesome-hacker-search-engines](https://github.com/edoardottt/awesome-hacker-search-engines).

## Other API notes

- `POST /v1/streamviewer/timeline` and `/search` require `start_time`, `end_time`
  (not in the future) and `vendor_account_id`; both were flaky (`500`) on this tenant during
  the demo, so the live-read proof uses the list endpoints instead.
- Insights are **not** in the public REST surface (the MCP exposed `/v1/insights/`, but the
  documented API is rules-engine + streamviewer). Write-back of analyst-facing detections is
  therefore via **rules** (→ insights) rather than insights directly.

## Security

- The key lives in **`~/.abstract.env`** (outside the repo, `chmod 600`), loaded at runtime by
  `abstract_client._load_dotenv()`. It is **never** printed, logged, or written into the repo
  (verified: `grep -rn "<key>" .` → no matches).
- This was a **test tenant** key the owner said would be **rotated** — rotate it after the demo.
- `# security: no raw tokens` — the client only sends the key in the `Authorization` header.
