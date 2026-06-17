# Sample data catalog — WildFire, PAN, and the mixed evidence estate

> **Representative, not authoritative.** These payloads are illustrative of the shape and
> the high-value fields each source contributes. Field names, verdict codes, and report
> structure vary by PAN-OS / WildFire API / Cortex version and by connector. Validate
> against the live vendor schema before building parsers. The point here is the *model* —
> which entities and signals each source yields and how they normalize to a common schema.

Everything below normalizes to OCSF (the schema Abstract uses) and then to the entity
model in [README.md](README.md). The right-hand "Yields" notes on each sample show which
entities/attributes that source contributes to the graph.

---

## 1. Palo Alto WildFire

### 1.1 Verdict API — `GET /publicapi/get/verdict`

**XML (native):**
```xml
<wildfire>
  <get-verdict-info>
    <sha256>dca86121cc7427e375fd24fe5871d727a4604532c4f3a567b3c956a3b6b6e0c4</sha256>
    <md5>e8a091a84dd2ea7ee429135ff48e9f48</md5>
    <verdict>1</verdict>
  </get-verdict-info>
</wildfire>
```

**Verdict codes:**

| Code | Meaning | Use as |
|---|---|---|
| `0` | Benign | suppress / low weight |
| `1` | Malware | **high-confidence detection trigger** |
| `2` | Grayware | medium weight, context-dependent |
| `4` | Phishing | high weight (esp. with email/URL correlation) |
| `5` | C2 (command & control) | **high weight, pivot to network streams** |
| `-100` | Pending (sample submitted, no verdict yet) | re-poll; hold finding open |
| `-101` | Error | retry/alert ops |
| `-102` | Unknown (no sample record) | submit sample / first-seen |
| `-103` | Invalid hash | input validation |

**Yields:** `FileHash` entity (sha256 canonical, md5 alt-key) + verdict attribute → confidence signal.

### 1.2 Report API — `GET /publicapi/get/report` (representative, trimmed)

```xml
<wildfire>
  <version>2.0</version>
  <file_info>
    <malware>yes</malware>
    <sha256>dca86121cc7427e375fd24fe5871d727a4604532c4f3a567b3c956a3b6b6e0c4</sha256>
    <md5>e8a091a84dd2ea7ee429135ff48e9f48</md5>
    <filetype>PE32 executable</filetype>
    <size>486400</size>
  </file_info>
  <task_info>
    <report>
      <version>2.0</version>
      <platform>100</platform>          <!-- Win10 x64 sandbox -->
      <software>Windows 10 64-bit</software>
      <malware>yes</malware>
      <summary>
        <entry score="5" id="6004" details="Process injection into a remote process"/>
        <entry score="5" id="2103" details="Connects to a known malicious C2 host"/>
        <entry score="4" id="3101" details="Creates a Run key for persistence"/>
        <entry score="3" id="1201" details="Spawns PowerShell with encoded command"/>
      </summary>
      <process_list>
        <process name="invoice_8841.exe" pid="2104">
          <process_activity>
            <Create>
              <process name="powershell.exe" pid="2210"
                       commandline="powershell -enc JABzAD0ATgBlAHcA..."/>
            </Create>
          </process_activity>
        </process>
        <process name="powershell.exe" pid="2210">
          <process_activity>
            <Create>
              <process name="rundll32.exe" pid="2308"
                       commandline="rundll32 %TEMP%\\qbot.dll,DllRegisterServer"/>
            </Create>
          </process_activity>
        </process>
      </process_list>
      <registry>
        <entry action="SetValueKey"
               key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
               value="qbot" data="%TEMP%\\qbot.dll"/>
      </registry>
      <mutex>
        <entry>Global\\m9d8f7a6-qbot</entry>
      </mutex>
      <network>
        <dns>
          <entry query="cdn.evil-delivery.com" type="A" response="185.220.101.45"/>
          <entry query="api.telemetry-sync.net"  type="A" response="91.219.236.12"/>
        </dns>
        <TCP>
          <entry ip="185.220.101.45" port="443" country="RU" ja3="769,47-53-5-10,..."/>
          <entry ip="91.219.236.12"  port="8443" country="NL"/>
        </TCP>
        <url>
          <entry host="cdn.evil-delivery.com" uri="/inv/invoice_8841.exe" method="GET"/>
          <entry host="api.telemetry-sync.net" uri="/gate.php" method="POST"/>
        </url>
      </network>
      <evidence>
        <file>
          <entry name="%TEMP%\\qbot.dll"
                 sha256="b7c4...e21a" action="create"/>
        </file>
      </evidence>
      <!-- Some report versions emit ATT&CK technique tags per behavior entry. -->
      <mitre_attack>
        <technique id="T1059.001" name="PowerShell"/>
        <technique id="T1055"     name="Process Injection"/>
        <technique id="T1547.001" name="Registry Run Keys"/>
        <technique id="T1071.001" name="Web Protocols (C2)"/>
      </mitre_attack>
    </report>
  </task_info>
</wildfire>
```

**Yields (this is the gold):** one detonation produces a whole subgraph —
`FileHash` → `Process`(tree) → `FileHash`(dropped dll) → `Domain` × N → `IP` × N →
`URL` × N → `Certificate`/`JA3` → `MITRE technique` × N → behavioral `score`.
Every one of those IOCs becomes a **live matchlist entry** (see README §5/§6).

### 1.3 WildFire report → normalized IOC bundle (what the pipeline extracts)

```json
{
  "source": "wildfire",
  "sample": { "sha256": "dca8...e0c4", "md5": "e8a0...9f48", "verdict": "malware", "family": "Qakbot" },
  "iocs": {
    "domains":  ["cdn.evil-delivery.com", "api.telemetry-sync.net"],
    "ips":      ["185.220.101.45", "91.219.236.12"],
    "urls":     ["http://cdn.evil-delivery.com/inv/invoice_8841.exe",
                 "http://api.telemetry-sync.net/gate.php"],
    "hashes":   ["b7c4...e21a"],
    "ja3":      ["769,47-53-5-10,..."],
    "mutexes":  ["Global\\m9d8f7a6-qbot"],
    "regkeys":  ["HKCU\\...\\Run\\qbot"]
  },
  "mitre": ["T1059.001", "T1055", "T1547.001", "T1071.001"],
  "behaviors": [{ "id": 6004, "score": 5, "text": "Process injection" }]
}
```

---

## 2. PAN-OS firewall logs (delivered via Strata Logging Service / Cortex, syslog, or Event Hub)

### 2.1 THREAT log — `subtype=wildfire` (the verdict-bearing one)
```json
{
  "type": "THREAT", "subtype": "wildfire",
  "receive_time": "2026-06-16T14:32:08Z", "serial": "007051000123456", "device_name": "fw-edge-01",
  "src": "10.12.4.27", "dst": "185.220.101.45", "natsrc": "203.0.113.10",
  "srcuser": "acme\\jsmith", "rule": "Outbound-Web", "src_zone": "trust", "dst_zone": "untrust",
  "app": "web-browsing", "proto": "tcp", "dport": 443, "direction": "client-to-server",
  "threatid": "Qakbot Downloader(300123)", "thr_category": "wildfire-malware",
  "severity": "critical", "action": "reset-both", "wildfire_verdict": "malicious",
  "misc": "http://cdn.evil-delivery.com/inv/invoice_8841.exe",
  "filedigest": "dca86121cc7427e375fd24fe5871d727a4604532c4f3a567b3c956a3b6b6e0c4",
  "filetype": "PE", "category": "malware", "pcap_id": "884412300000001"
}
```
**Yields:** `User` + `Host`(src) + `IP`(dst) + `URL` + `FileHash` + verdict + action + `Rule`. This is a **pre-correlated** record — user, asset, network, file, and verdict in one row.

### 2.2 TRAFFIC log (sessions, bytes, app — for beaconing/exfil/lateral movement)
```json
{
  "type": "TRAFFIC", "receive_time": "2026-06-16T14:33:11Z", "serial": "007051000123456",
  "src": "10.12.4.27", "dst": "91.219.236.12", "srcuser": "acme\\jsmith",
  "app": "ssl", "proto": "tcp", "dport": 8443, "rule": "Outbound-Web", "action": "allow",
  "bytes_sent": 2048, "bytes_received": 512, "packets": 14, "session_end_reason": "tcp-fin",
  "repeat_count": 1, "start": "2026-06-16T14:33:09Z", "elapsed": 2
}
```
**Yields:** `Host`↔`IP` session edge with bytes/timing → beaconing & exfil analytics.

### 2.3 URL filtering log
```json
{
  "type": "THREAT", "subtype": "url", "receive_time": "2026-06-16T14:32:05Z",
  "src": "10.12.4.27", "srcuser": "acme\\jsmith", "dst": "185.220.101.45",
  "app": "web-browsing", "url": "cdn.evil-delivery.com/inv/invoice_8841.exe",
  "category": "malware", "action": "block-url", "http_method": "GET",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "referer": "https://mail.acme.com/"
}
```
**Yields:** `URL` + `Domain` + `User`/`Host` + user-agent (weak fingerprint).

### 2.4 DNS Security log (often the earliest signal — DGA / NRD / tunneling)
```json
{
  "type": "THREAT", "subtype": "spyware", "threat_category": "dns-malware",
  "receive_time": "2026-06-16T14:31:58Z", "src": "10.12.4.27", "srcuser": "acme\\jsmith",
  "dns_query": "api.telemetry-sync.net", "dns_type": "A", "action": "sinkhole",
  "threatid": "Suspicious DNS Query (generic:api.telemetry-sync.net)", "severity": "high"
}
```
**Yields:** `Domain` + resolution + `User`/`Host` → first-touch pivot for the C2 from §1.2.

### 2.5 Panorama / Strata Logging Service note
Panorama is the management/aggregation plane; **Strata Logging Service** (formerly Cortex
Data Lake) is the cloud log store. Both forward the same THREAT/TRAFFIC/URL/FILE/DATA log
types — Strata typically as JSON over its log-forwarding API, Panorama as syslog/CEF or via
HTTP forwarding. Treat them as **transport for the §2.1–2.4 records**, not new schemas.
Strata adds normalized field names (e.g. `log.panw.fw.threat.name`) — map those to the same
OCSF targets.

---

## 3. Other firewall / network vendors (the vendor-agnostic point)

Normalize once; the same content runs regardless of vendor.

**FortiGate (FortiOS) UTM/virus event:**
```json
{ "type": "utm", "subtype": "virus", "srcip": "10.12.4.27", "dstip": "185.220.101.45",
  "user": "jsmith", "service": "HTTPS", "filename": "invoice_8841.exe",
  "checksum": "e8a091a8", "virus": "W32/Qakbot", "action": "blocked", "level": "warning" }
```

**Zscaler (NSS web log, key fields):**
```json
{ "datetime": "2026-06-16 14:32:05", "login": "jsmith@acme.com", "clientip": "10.12.4.27",
  "url": "cdn.evil-delivery.com/inv/invoice_8841.exe", "urlcategory": "Malware",
  "action": "Blocked", "threatname": "Win32.Downloader.Qakbot", "useragent": "Mozilla/5.0..." }
```

**Check Point / Cisco FTD / Prisma Access:** same conceptual fields (src/dst/user/app/action/
threat/file-hash). Map all to OCSF **Network Activity / HTTP Activity / Detection Finding**.

**Mapping rule of thumb:** every NGFW gives you {who, src host, dst ip/domain/url, app, action,
optional file hash, optional verdict}. Those slot into the *same* entity edges — so a Fortinet
or Zscaler shop gets the identical WildFire-style detections with zero rule rewrites.

---

## 4. Threat intelligence & OSINT

**MISP event (STIX-flavored, trimmed):**
```json
{ "Event": { "info": "Qakbot campaign 2026-06", "threat_level_id": "1",
  "Attribute": [
    { "type": "sha256", "value": "dca8...e0c4", "category": "Payload delivery" },
    { "type": "domain", "value": "cdn.evil-delivery.com" },
    { "type": "ip-dst", "value": "185.220.101.45" } ],
  "Galaxy": [{ "name": "mitre-attack", "value": "T1071.001" }],
  "Tag": [{ "name": "malware:Qakbot" }, { "name": "tlp:amber" }] } }
```

**VirusTotal file report (trimmed):**
```json
{ "data": { "id": "dca8...e0c4", "attributes": {
  "last_analysis_stats": { "malicious": 63, "suspicious": 2, "undetected": 6 },
  "popular_threat_classification": { "suggested_threat_label": "trojan.qakbot/qbot" },
  "crowdsourced_yara_results": [{ "rule_name": "QakBot_payload" }] } } }
```

**GreyNoise / AbuseIPDB (IP reputation):**
```json
{ "ip": "185.220.101.45", "greynoise": { "classification": "malicious", "tags": ["C2"] },
  "abuseipdb": { "abuseConfidenceScore": 100, "countryCode": "RU", "totalReports": 412 } }
```
**Yields:** independent corroboration → raises fused confidence; `Campaign`/`Actor` attribution
edges; this is what the **Abstract Intel Gallery (AIG)** carries as live inputs.

---

## 5. Identity / IdP / ATO signals

**Okta system log (suspicious auth → ATO precursor):**
```json
{ "eventType": "user.session.start", "outcome": { "result": "SUCCESS" },
  "actor": { "alternateId": "jsmith@acme.com" },
  "client": { "ipAddress": "91.219.236.12", "geographicalContext": { "country": "Netherlands" },
              "userAgent": { "rawUserAgent": "Mozilla/5.0..." } },
  "securityContext": { "isProxy": true, "asNumber": 49981 },
  "debugContext": { "debugData": { "threatSuspected": "true", "riskLevel": "HIGH" } } }
```

**Entra ID sign-in (impossible travel / MFA fatigue):**
```json
{ "userPrincipalName": "jsmith@acme.com", "ipAddress": "91.219.236.12",
  "riskLevelDuringSignIn": "high", "riskState": "atRisk",
  "status": { "errorCode": 0 }, "authenticationRequirement": "multiFactorAuthentication",
  "location": { "countryOrRegion": "NL" }, "appDisplayName": "Office365" }
```
**Yields:** `Account`/`Identity` + `IP` (note: **same NL IP `91.219.236.12` as the C2 in §1.2**)
+ risk + geo → the ATO↔malware bridge. ATO patterns: impossible travel, new-ASN/proxy login,
MFA fatigue, dormant-account reactivation, OAuth grant to unknown app.

---

## 6. EDR / XDR

**CrowdStrike detection (trimmed):**
```json
{ "ComputerName": "ACME-LT-4471", "UserName": "jsmith",
  "SHA256HashData": "dca8...e0c4", "FileName": "invoice_8841.exe",
  "CommandLine": "powershell -enc JABzAD0...", "ParentBaseFileName": "invoice_8841.exe",
  "Tactic": "Defense Evasion", "Technique": "T1055", "PatternDispositionDescription": "Process Blocked",
  "DetectName": "Qakbot", "Severity": 8 }
```

**Microsoft Defender XDR alert:**
```json
{ "AlertId": "da637...", "Title": "Qakbot malware detected", "Severity": "High",
  "Category": "Malware", "DeviceName": "ACME-LT-4471", "AccountName": "jsmith",
  "Sha256": "dca8...e0c4", "MitreTechniques": ["T1059.001","T1055"] }
```
**Yields:** `Host`(endpoint) + `User` + `FileHash` + `Process` + technique → the **endpoint
corroboration** of the firewall/WildFire verdict (same sha256 = the controls agree).

---

## 7. Cloud providers

**AWS CloudTrail (suspicious post-ATO action):**
```json
{ "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey",
  "userIdentity": { "type": "IAMUser", "userName": "jsmith" },
  "sourceIPAddress": "91.219.236.12", "awsRegion": "us-east-1",
  "userAgent": "aws-cli/2.x", "eventTime": "2026-06-16T15:01:44Z" }
```

**Azure Activity / Sign-in:** the Entra sign-in (§5) plus resource Activity Log (this repo's
[activitylog template](../../templates/subscription/activitylog.bicep) streams it). GCP: Cloud
Audit Logs `protoPayload` with `authenticationInfo.principalEmail` + `requestMetadata.callerIp`.
**Yields:** `Account` + `IP` + cloud resource → exfil/persistence in cloud, same identity key.

---

## 8. Email security

**Proofpoint / M365 message event (delivery vector):**
```json
{ "messageID": "<abc@acme.com>", "sender": "billing@evil-delivery.com",
  "recipient": ["jsmith@acme.com"], "subject": "Invoice 8841 overdue",
  "attachments": [{ "filename": "invoice_8841.exe", "sha256": "dca8...e0c4" }],
  "verdict": "malicious", "clickedURL": "http://cdn.evil-delivery.com/inv/invoice_8841.exe" }
```
**Yields:** `EmailMessage` → `FileHash` (same sha256) → `URL` → `Account`(recipient). Closes the
loop: **email delivered the file → firewall saw the download → WildFire convicted it → EDR saw
execution → identity shows the ATO from the same C2 IP.** One campaign, six sources, one entity.

---

## 9. SOAR (consumers of the model, not sources)

XSOAR / Splunk SOAR / Tines / Torq / Sentinel Playbooks are **action targets**. The pipeline
emits a finding; the SOAR isolates the host, disables the account, blocks the IOC, opens the
case. The model below produces the *trigger + enriched context object* these playbooks consume.

---

## 10. The unifying layer — one OCSF-normalized event

Every sample above collapses into the same shape (here, the WildFire threat log as OCSF
**Detection Finding** with enrichments). This is what makes the entity model possible:

```json
{
  "class_name": "Detection Finding",
  "time": "2026-06-16T14:32:08Z",
  "severity": "Critical",
  "finding_info": { "title": "WildFire malicious file download", "types": ["Malware"] },
  "malware": [{ "name": "Qakbot", "classification_ids": ["Trojan"] }],
  "evidences": {
    "file": { "name": "invoice_8841.exe", "hashes": [{ "algorithm": "SHA-256", "value": "dca8...e0c4" }] },
    "src_endpoint": { "ip": "10.12.4.27", "hostname": "ACME-LT-4471" },
    "dst_endpoint": { "ip": "185.220.101.45", "location": { "country": "RU" } },
    "url": { "url_string": "http://cdn.evil-delivery.com/inv/invoice_8841.exe" }
  },
  "actor": { "user": { "name": "jsmith", "email_addr": "jsmith@acme.com" } },
  "enrichments": [
    { "provider": "WildFire", "name": "verdict", "value": "malware" },
    { "provider": "AIG/GreyNoise", "name": "dst_reputation", "value": "C2:malicious" },
    { "provider": "Identity", "name": "user_risk", "value": "high" },
    { "provider": "MITRE", "name": "techniques", "value": ["T1059.001","T1055","T1071.001"] }
  ],
  "abstract": { "risk_score": 97, "campaign": "Qakbot-2026-06", "correlated_sources": 6 }
}
```

Continue to [README.md](README.md) for how these become entities, mappings, correlations,
analytics, and agentic workflows.
