# Incident Report — Qakbot-style intrusion (model demo)

**Lead finding:** [ABS-DEMO] Malware confirmed by 3 independent controls on host:ACME-LT-4471  
**Severity:** critical · **Risk:** 95/100 · **Triage:** true-positive

## Executive summary

A malware verdict corroborated by endpoint execution and C2 beaconing, with an identity authenticating from the same C2 infrastructure (account takeover). Detected in-stream before landing. **7 entities** implicated; **0** predicted next targets.

## Detections (shift-left)

- **[95] insight** — [ABS-DEMO] Malware confirmed by 3 independent controls on host:ACME-LT-4471  
  _controls agree: EDR, NGFW/WildFire, TI; user=jsmith@acme.com  Blast radius: 8 entities across 5 identity kinds; predicted next targets: ACME-LT-2210, ACME-LT-8802. Live GreyNoise(185.220.101.45) = malicious. SIEM volume cut 99.6%, fatigue cut 87.5%. Model demo — see docs/threat-model._
- **[95] insight** — [ABS-DEMO] host:ACME-LT-4471 contacted 5 known-bad IOC(s)  
  _matched: 185.220.101.45, 91.219.236.12, cdn.evil-delivery.com, dca86121cc7427e375fd24fe5871d727a4604532c4f3a567b3c956a3b6b6e0c4, http://cdn.evil-delivery.com/inv/invoice_8841.exe_
- **[80] insight** — [ABS-DEMO] identity:jsmith@acme.com contacted 4 known-bad IOC(s)  
  _matched: 185.220.101.45, 91.219.236.12, dca86121cc7427e375fd24fe5871d727a4604532c4f3a567b3c956a3b6b6e0c4, http://cdn.evil-delivery.com/inv/invoice_8841.exe_
- **[80] insight** — [ABS-DEMO] Beaconing ACME-LT-4471 → 91.219.236.12 (6 sessions, ~60s interval)  
  _jitter=0.00, avg_bytes=492_
- **[55] insight** — [ABS-DEMO] host:ACME-LT-2210 contacted 2 known-bad IOC(s)  
  _matched: 91.219.236.12, api.telemetry-sync.net_
- **[55] insight** — [ABS-DEMO] host:ACME-LT-8802 contacted 2 known-bad IOC(s)  
  _matched: 185.220.101.45, cdn.evil-delivery.com_
- **[95] insight** — [ABS-DEMO] Malware confirmed by 3 independent controls on host:ACME-LT-4471  
  _controls agree: EDR, NGFW/WildFire, TI; user=jsmith@acme.com_
- **[95] insight** — [ABS-DEMO] Malware confirmed by 3 independent controls on host:ACME-LT-4471  
  _controls agree: EDR, NGFW/WildFire, TI; user=jsmith@acme.com_

## Identity Intelligence

**Continuous re-exposure**
- `account:rule:ItxArTYzrdjDRMQKFGKlt5Ijmu89LDbW` — 1× exposure
- `account:rule:pHgixR6IPViGLI8HtaU9rL0KqlQtSbt9` — 1× exposure
- `account:rule:FovCwN-t2ojU5TD0ceac44SqkxQdtJXS` — 1× exposure
- `account:rule:SvJJ8sZScJT5DREbefbeSZ0gnbHS2Qvv` — 1× exposure
- `account:rule:VNqftsmg6IFZErldP5-aLLhosARJyiFh` — 1× exposure

**Signals**
- `account:id:jsmith@acme.com` — vip_at_risk (90): VIP elevated risk 90
- `identity:jsmith@acme.com` — vip_at_risk (90): VIP elevated risk 90

## Blast radius

- **Real-time:** id:jsmith@acme.com, jsmith@acme.com, rule:ItxArTYzrdjDRMQKFGKlt5Ijmu89LDbW, rule:pHgixR6IPViGLI8HtaU9rL0KqlQtSbt9, rule:FovCwN-t2ojU5TD0ceac44SqkxQdtJXS, rule:SvJJ8sZScJT5DREbefbeSZ0gnbHS2Qvv, rule:VNqftsmg6IFZErldP5-aLLhosARJyiFh
- **Historical (replay):** —

## Prediction

- **Predicted next targets:** —
- _entities trending toward high risk (heuristic)_

## Continuous risk (top entities)

- `account:id:jsmith@acme.com` — 90 (trend +0)
- `identity:jsmith@acme.com` — 90 (trend +0)
- `account:rule:ItxArTYzrdjDRMQKFGKlt5Ijmu89LDbW` — 72 (trend +0)
- `account:rule:pHgixR6IPViGLI8HtaU9rL0KqlQtSbt9` — 72 (trend +0)
- `account:rule:FovCwN-t2ojU5TD0ceac44SqkxQdtJXS` — 72 (trend +0)
- `account:rule:SvJJ8sZScJT5DREbefbeSZ0gnbHS2Qvv` — 72 (trend +0)

## OSINT enrichment

- **ip** `91.219.236.12` → Maltego, SpiderFoot, Criminal IP, GreyNoise, Shodan / Censys, VirusTotal, AbuseIPDB, AlienVault OTX
- **domain** `cdn.evil-delivery.com` → Maltego, SpiderFoot, Shodan / Censys, VirusTotal, AlienVault OTX, MISP / OpenCTI, Recorded Future, urlscan.io
- **hash** `dca86121cc7427e375fd24fe5871d727a4604532c4f3a567b3c956a3b6b6e0c4` → SpiderFoot, VirusTotal, AlienVault OTX, MISP / OpenCTI, Recorded Future


## Efficiency vs. SIEM-first

- SIEM volume cut **-76.5%** (34 → 60)
- Alert fatigue cut **0%** (60 alerts → 1 incident)
> Model demo. Verdict fusion / entity correlation / identity intelligence mirror what Abstract produces; replay, scoring, prediction run in the local engine.