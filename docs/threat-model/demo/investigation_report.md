# Incident Report — Qakbot-style intrusion (model demo)

**Lead finding:** Malware confirmed by 3 independent controls on host:ACME-LT-4471  
**Severity:** critical · **Risk:** 99/100 · **Triage:** true-positive (high confidence)

## Executive summary

A malware verdict corroborated by endpoint execution and C2 beaconing, with an identity authenticating from the same C2 infrastructure (account takeover). Detected in-stream before landing. **8 entities** implicated; **2** predicted next targets.

## Detections (shift-left)

- **[99] verdict-fusion** — Malware confirmed by 3 independent controls on host:ACME-LT-4471  
  _controls agree: EDR, NGFW/WildFire, TI; user=jsmith@acme.com_
- **[96] ato-c2-bridge** — Auth from C2 infrastructure 91.219.236.12 — likely account takeover  
  _principals authenticating from a known C2 IP: account:aws:jsmith, account:okta:jsmith@acme.com, nhi:svc-ci-pipeline_
- **[95] ioc-blast-match** — host:ACME-LT-4471 contacted 5 known-bad IOC(s)  
  _matched: 185.220.101.45, 91.219.236.12, cdn.evil-delivery.com, dca86121cc7427e375fd24fe5871d727a4604532c4f3a567b3c956a3b6b6e0c4, http://cdn.evil-delivery.com/inv/invoice_8841.exe_
- **[87] ioc-blast-match** — identity:jsmith@acme.com contacted 4 known-bad IOC(s)  
  _matched: 185.220.101.45, 91.219.236.12, dca86121cc7427e375fd24fe5871d727a4604532c4f3a567b3c956a3b6b6e0c4, http://cdn.evil-delivery.com/inv/invoice_8841.exe_
- **[82] beaconing** — Beaconing ACME-LT-4471 → 91.219.236.12 (6 sessions, ~60s interval)  
  _jitter=0.00, avg_bytes=492_
- **[79] ioc-blast-match** — account:okta:jsmith@acme.com contacted 3 known-bad IOC(s)  
  _matched: 91.219.236.12, dca86121cc7427e375fd24fe5871d727a4604532c4f3a567b3c956a3b6b6e0c4, http://cdn.evil-delivery.com/inv/invoice_8841.exe_
- **[71] ioc-blast-match** — host:ACME-LT-2210 contacted 2 known-bad IOC(s)  
  _matched: 91.219.236.12, api.telemetry-sync.net_
- **[71] ioc-blast-match** — host:ACME-LT-8802 contacted 2 known-bad IOC(s)  
  _matched: 185.220.101.45, cdn.evil-delivery.com_

## Identity Intelligence

**Continuous re-exposure**
- `account:okta:jsmith@acme.com` — 8× exposure — **survives IDP/backup restore**
- `identity:jsmith@acme.com` — 3× exposure
- `account:aws:jsmith` — 1× exposure
- `identity:mraj@acme.com` — 1× exposure
- `nhi:svc-ci-pipeline` — 1× exposure
- `agent:agent-soc-autobot` — 1× exposure

**Signals**
- `account:okta:jsmith@acme.com` — session_hijacking (75): auth from new IP 91.219.236.12 (was 52.20.10.5) [known-bad IP]
- `account:okta:jsmith@acme.com` — session_hijacking (75): auth from new IP 91.219.236.12 (was 52.20.10.5) [known-bad IP]
- `account:okta:jsmith@acme.com` — mfa_bombing (70): 4 MFA prompts in burst
- `account:okta:jsmith@acme.com` — password_reuse (60): credential seen in breach/infostealer corpus
- `account:okta:jsmith@acme.com` — vip_at_risk (100.0): VIP elevated risk 100.0
- `identity:jsmith@acme.com` — vip_at_risk (100.0): VIP elevated risk 100.0

## Blast radius

- **Real-time:** aws:jsmith, okta:jsmith@acme.com, agent-soc-autobot, ACME-LT-4471, ACME-LT-8802, jsmith@acme.com, svc-ci-pipeline
- **Historical (replay):** ACME-LT-2210

## Prediction

- **Predicted next targets:** ACME-LT-2210, ACME-LT-8802
- _contacted known C2 infrastructure with no local conviction yet — intervene before payload/execution_

## Continuous risk (top entities)

- `account:okta:jsmith@acme.com` — 100.0 (trend +0.0)
- `host:ACME-LT-4471` — 100.0 (trend +0.0)
- `identity:jsmith@acme.com` — 100.0 (trend +0.0)
- `host:ACME-LT-8802` — 68.0 (trend +30.0)
- `host:ACME-LT-2210` — 60.0 (trend +30.0)
- `account:aws:jsmith` — 30.0 (trend +30.0)

## OSINT enrichment

- **ip** `185.220.101.45` → Maltego, SpiderFoot, Criminal IP, GreyNoise, Shodan / Censys, VirusTotal, AbuseIPDB, AlienVault OTX
- **domain** `api.telemetry-sync.net` → Maltego, SpiderFoot, Shodan / Censys, VirusTotal, AlienVault OTX, MISP / OpenCTI, Recorded Future, urlscan.io
- **hash** `dca86121cc7427e375fd24fe5871d727a4604532c4f3a567b3c956a3b6b6e0c4` → SpiderFoot, VirusTotal, AlienVault OTX, MISP / OpenCTI, Recorded Future

## Recommended actions

- disable sessions / force re-auth
- rotate NHI/service tokens
- review agent tool grants

## Efficiency vs. SIEM-first

- SIEM volume cut **99.5%** (5,025 → 25)
- Alert fatigue cut **88.9%** (9 alerts → 1 incident)
> Model demo. Verdict fusion / entity correlation / identity intelligence mirror what Abstract produces; replay, scoring, prediction run in the local engine.