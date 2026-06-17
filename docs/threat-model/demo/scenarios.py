"""
The catalog that drives the elaborate live demo — entity-model field sets and a
large use-case/scenario list spanning every major data source. build_demo.py turns
each entry into real Abstract objects (field sets + saved views/searches), plus
suppressions, analytics, and a rule catalog.

All field names are valid members of the live 549-value FieldEnum (Abstract Common
Schema). All objects are prefixed "[ABS-DEMO]" so cleanup is exact.
"""
from __future__ import annotations

MARKER = "[ABS-DEMO]"

# ── Entity-model field sets (mappers / projections) ──────────────────────────
FIELDSETS = {
    "identity": ["type", "@timestamp", "severity", "vendor", "action", "event.outcome",
                 "user_name", "user.email", "user.target.email", "source_address",
                 "source.geo.country_iso_code", "user.roles", "message"],
    "network_firewall": ["type", "@timestamp", "severity", "vendor", "event.dataset", "action",
                         "source_address", "dest_address", "dest_port", "network.protocol",
                         "network.bytes", "destination.domain", "destination.geo.country_iso_code",
                         "message"],
    "cloud": ["type", "@timestamp", "severity", "vendor", "cloud.provider", "cloud.account_id",
              "cloud.region", "action", "event.outcome", "user_name", "source_address", "message"],
    "edr_xdr": ["type", "@timestamp", "severity", "host_name", "user_name", "process.name",
                "process.command_line", "process.parent.name", "file.hash.sha256",
                "threat.technique_id", "message"],
    "email": ["type", "@timestamp", "severity", "email.sender", "email.from", "email.to",
              "email.subject", "email.attachments.file.hash.sha256", "url.original", "message"],
    "dns_web": ["type", "@timestamp", "severity", "user_name", "source_address", "dns.question.name",
                "dns.question.registered_domain", "url.original", "destination.domain",
                "http.request.method", "message"],
    "threat_intel": ["type", "@timestamp", "severity", "threat.indicator", "threat.feed",
                     "threat.framework", "threat.technique_id", "threat.group_name",
                     "source_address", "dest_address", "message"],
    "nhi_agent": ["type", "@timestamp", "severity", "user_name", "service.name", "process.name",
                  "source_address", "cloud.account_id", "action", "message"],
    "wildfire": ["type", "@timestamp", "severity", "vendor", "file.hash.sha256", "file.name",
                 "url.original", "destination.domain", "dest_address", "threat.technique_id",
                 "process.name", "message"],
}


def S(key, title, model, severity, mitre, tags, conditions):
    return {"key": key, "title": title, "model": model, "severity": severity,
            "mitre": mitre, "tags": tags, "conditions": conditions}


# (field, operation, value). Operations kept to widely-valid ones:
# EQUALS, CONTAINS, CONTAINS_WORD, IS_IN_LIST, IS_IN_SUBNET.
SCENARIOS = [
    # ── Identity / ATO ───────────────────────────────────────────────────────
    S("ato-bruteforce", "ATO — Okta brute force", "identity", "high",
      [("T1110", "Brute Force")], ["identity", "ato", "okta"],
      [("vendor", "EQUALS", "okta"), ("event.outcome", "EQUALS", "failure")]),
    S("ato-mfa-fatigue", "ATO — MFA fatigue / push bombing", "identity", "high",
      [("T1621", "MFA Request Generation")], ["identity", "ato", "mfa"],
      [("action", "CONTAINS", "mfa")]),
    S("ato-new-asn", "ATO — login from new/proxy ASN", "identity", "high",
      [("T1078", "Valid Accounts")], ["identity", "ato", "geo"],
      [("action", "CONTAINS_WORD", "login")]),
    S("ato-impossible-travel", "ATO — impossible travel", "identity", "high",
      [("T1078", "Valid Accounts")], ["identity", "ato", "geo"],
      [("action", "CONTAINS_WORD", "session")]),
    S("ato-account-manip", "ATO — account manipulation / MFA factor add", "identity", "critical",
      [("T1098", "Account Manipulation")], ["identity", "persistence"],
      [("action", "CONTAINS", "factor")]),
    S("ato-oauth-grant", "ATO — OAuth grant to unknown app", "identity", "medium",
      [("T1528", "Steal Application Access Token")], ["identity", "oauth", "saas"],
      [("action", "CONTAINS", "oauth")]),

    # ── Cloud (AWS / Azure / GCP) ────────────────────────────────────────────
    S("cloud-accesskey", "Cloud — new access key created", "cloud", "high",
      [("T1098", "Account Manipulation")], ["cloud", "aws", "persistence"],
      [("vendor", "EQUALS", "aws"), ("action", "CONTAINS", "CreateAccessKey")]),
    S("cloud-root-usage", "Cloud — root / privileged account usage", "cloud", "high",
      [("T1078.004", "Cloud Accounts")], ["cloud", "aws", "privilege"],
      [("user_name", "CONTAINS_WORD", "root")]),
    S("cloud-iam-policy", "Cloud — IAM policy change", "cloud", "medium",
      [("T1098", "Account Manipulation")], ["cloud", "aws", "iam"],
      [("action", "CONTAINS", "PutPolicy")]),
    S("cloud-bulk-export", "Cloud — bulk data export / exfil", "cloud", "critical",
      [("T1567", "Exfiltration Over Web Service")], ["cloud", "exfil", "data"],
      [("action", "CONTAINS", "Export")]),
    S("cloud-failed-api", "Cloud — burst of failed API calls", "cloud", "medium",
      [("T1595", "Active Scanning")], ["cloud", "recon"],
      [("vendor", "EQUALS", "aws"), ("event.outcome", "EQUALS", "failure")]),

    # ── Network / Firewall ───────────────────────────────────────────────────
    S("net-c2-beacon", "Network — C2 beaconing", "network_firewall", "high",
      [("T1071.001", "Web Protocols")], ["network", "c2", "firewall"],
      [("network.protocol", "EQUALS", "tcp")]),
    S("net-threat-reset", "Network — threat blocked (reset-both)", "network_firewall", "high",
      [("T1071", "Application Layer Protocol")], ["network", "firewall", "threat"],
      [("event.dataset", "EQUALS", "THREAT")]),
    S("net-exfil-volume", "Network — large outbound transfer", "network_firewall", "high",
      [("T1030", "Data Transfer Size Limits")], ["network", "exfil"],
      [("event.dataset", "EQUALS", "TRAFFIC")]),
    S("net-portscan", "Network — port scan / sweep", "network_firewall", "medium",
      [("T1046", "Network Service Discovery")], ["network", "recon"],
      [("event.dataset", "EQUALS", "TRAFFIC")]),

    # ── DNS / Web ────────────────────────────────────────────────────────────
    S("dns-tunneling", "DNS — tunneling / high-entropy queries", "dns_web", "high",
      [("T1071.004", "DNS")], ["dns", "c2", "exfil"],
      [("dns.question.name", "CONTAINS", ".")]),
    S("dns-nrd", "DNS — newly registered / suspicious domain", "dns_web", "medium",
      [("T1568", "Dynamic Resolution")], ["dns", "c2"],
      [("dns.question.registered_domain", "CONTAINS", ".")]),

    # ── EDR / XDR ────────────────────────────────────────────────────────────
    S("edr-malware-exec", "EDR — malware execution", "edr_xdr", "critical",
      [("T1204", "User Execution")], ["edr", "malware"],
      [("process.name", "CONTAINS", ".exe")]),
    S("edr-lolbin-powershell", "EDR — encoded PowerShell (LOLBin)", "edr_xdr", "high",
      [("T1059.001", "PowerShell")], ["edr", "execution"],
      [("process.command_line", "CONTAINS", "enc")]),
    S("edr-process-injection", "EDR — process injection", "edr_xdr", "high",
      [("T1055", "Process Injection")], ["edr", "defense-evasion"],
      [("process.name", "CONTAINS", "rundll32")]),
    S("edr-cred-dumping", "EDR — credential dumping", "edr_xdr", "critical",
      [("T1003", "OS Credential Dumping")], ["edr", "credential-access"],
      [("process.command_line", "CONTAINS", "lsass")]),

    # ── Email ────────────────────────────────────────────────────────────────
    S("email-malware-attach", "Email — malicious attachment", "email", "high",
      [("T1566.001", "Spearphishing Attachment")], ["email", "phishing"],
      [("email.attachments.file.hash.sha256", "CONTAINS_WORD", "a")]),
    S("email-phish-url", "Email — phishing URL", "email", "high",
      [("T1566.002", "Spearphishing Link")], ["email", "phishing"],
      [("url.original", "CONTAINS", "http")]),

    # ── WildFire / sandbox ───────────────────────────────────────────────────
    S("wf-malicious-verdict", "WildFire — malicious verdict", "wildfire", "critical",
      [("T1204", "User Execution")], ["wildfire", "malware", "verdict"],
      [("file.hash.sha256", "CONTAINS_WORD", "a")]),
    S("wf-c2-ioc", "WildFire — report C2 IOC contact", "wildfire", "high",
      [("T1071.001", "Web Protocols")], ["wildfire", "c2", "ioc"],
      [("destination.domain", "CONTAINS", ".")]),

    # ── Threat intel / OSINT ─────────────────────────────────────────────────
    S("ti-known-bad-ip", "Threat Intel — known-bad IP match", "threat_intel", "high",
      [("T1071", "Application Layer Protocol")], ["threat-intel", "ioc"],
      [("threat.indicator", "CONTAINS_WORD", "a")]),
    S("ti-technique-sighting", "Threat Intel — ATT&CK technique sighting", "threat_intel", "medium",
      [("T1595", "Active Scanning")], ["threat-intel", "mitre"],
      [("threat.technique_id", "CONTAINS", "T1")]),

    # ── Identity exposure / session theft (cookies) ──────────────────────────
    S("exposure-stolen-session", "Identity Exposure — stolen session / cookie reuse", "identity", "high",
      [("T1539", "Steal Web Session Cookie")], ["identity-exposure", "session", "ato"],
      [("action", "CONTAINS_WORD", "session")]),

    # ── NHI / agentic exposure ───────────────────────────────────────────────
    S("nhi-token-new-asn", "NHI — service token used from new ASN", "nhi_agent", "high",
      [("T1078", "Valid Accounts")], ["nhi", "non-human", "cloud"],
      [("service.name", "CONTAINS_WORD", "svc")]),
    S("agent-anomalous-tool", "Agentic — AI agent anomalous tool call / exfil", "nhi_agent", "high",
      [("T1567", "Exfiltration Over Web Service")], ["agentic", "ai", "exfil"],
      [("action", "CONTAINS", "tool")]),

    # ── Supply chain / GenAI ─────────────────────────────────────────────────
    S("supplychain-ci-token", "Supply Chain — CI token harvest + startup mod", "cloud", "critical",
      [("T1195", "Supply Chain Compromise")], ["supply-chain", "ci-cd"],
      [("action", "CONTAINS", "CodeBuild")]),
    S("genai-agent-abuse", "GenAI — agent abuse / permission bypass", "nhi_agent", "critical",
      [("T1562", "Impair Defenses")], ["genai", "ai", "defense-evasion"],
      [("action", "CONTAINS_WORD", "execute")]),
]

# Severities → IS_IN_LIST helper for suppressions / cross-cuts
SUPPRESSIONS = [
    {"title": MARKER + " Suppress known scanner ASN (demo)",
     "note": "example benign-source suppression",
     "conditions": [("source_address", "IS_IN_SUBNET", "10.0.0.0/8")]},
    {"title": MARKER + " Suppress corp VPN egress (demo)",
     "note": "example egress suppression",
     "conditions": [("network.protocol", "EQUALS", "udp")]},
]

# Analytics to pull live (field-analytics top-N + MITRE coverage)
ANALYTICS_FIELDS = ["vendor", "severity", "event.outcome", "source_address", "user_name"]


def view_query_from_conditions(conditions):
    """Convert (field, op, value) tuples → the flat view-query list the API expects."""
    out = []
    for i, (field, op, value) in enumerate(conditions):
        ftype = "Ipv4" if op == "IS_IN_SUBNET" else "String"
        out.append({"id": f"q{i}", "depth": 0, "field": field, "index": i, "value": value,
                    "parentId": None, "fieldType": ftype, "field_operation": op,
                    "subFieldOperation": ""})
    return out


def summary():
    by_model = {}
    for s in SCENARIOS:
        by_model.setdefault(s["model"], 0)
        by_model[s["model"]] += 1
    return {"fieldsets": len(FIELDSETS), "scenarios": len(SCENARIOS),
            "by_model": by_model, "suppressions": len(SUPPRESSIONS),
            "analytics_fields": len(ANALYTICS_FIELDS)}


if __name__ == "__main__":
    import json
    print(json.dumps(summary(), indent=2))
