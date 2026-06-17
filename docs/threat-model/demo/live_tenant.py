"""
Live tenant wiring — what we actually read from the connected Abstract MCP, and
the write-back payloads that are PREPARED but blocked by token scope.

Connection status (observed 2026-06-17 via mcp__abstract-security__*):
  • READ  works  — get_timeline / list_insights / get_insight / list_views / get_view
  • WRITE blocked — create_fieldset → "Missing required permission 'mcp.tools.write'
                     (have: none)". The OAuth key is READ-ONLY.
  • search_events / query_events → 422 on this tenant (raw-search flag / translator).

So the read/ingest half of the loop is live; the write-back half needs either a
write-scoped key or the REST API (per the API spec). The payloads below are built
to the create_* tool schemas and fire as-is the moment write scope is granted.
"""
from __future__ import annotations

# ── Confirmed live reads (counts over ~30 days) ──────────────────────────────
SNAPSHOT = {
    "tenant": "abstract-security (connected MCP)",
    "window": "2026-05-17 → 2026-06-17",
    "total_events_30d": 6_661_287,
    "by_source": {                       # via get_timeline query_string probes
        "vendor:aws": 3_424_719,
        "vendor:okta": 177_282,
        "event.dataset:THREAT (PAN)": 105,
        "event.dataset:TRAFFIC (PAN)": "present (Palo Alto view)",
        "vendor:paloalto": 0,            # PAN is keyed by event.dataset, not vendor
        "wildfire": 0,                    # no WildFire-labeled data in this tenant
    },
    "existing_insights_total": 34,
    "anchor_incident": {                 # real insight l6PqCLQXEq (read live)
        "nanoid": "l6PqCLQXEq",
        "title": "Credential Compromise to Account Takeover — jacques.plante@demo.abstract.security",
        "source_ip": "203.0.113.2",      # 162 events in window
        "verdict": "MALICIOUS",
        "confidence": 97,
        "chain": ["T1110 brute force", "password access", "T1098 MFA mod",
                  "T1078 session", "SAML lateral move", "Salesforce bulk export ~1.05M records"],
        "campaign_correlation": ["EFzi5kCUCu (exfil)", "EdomkUUQ4k (IAB validation)"],
        "historical_repeat": ["CNhyMrTfss", "ZKSJnVwmxk", "GvijSrbUgR", "1BQ9YWV6dz"],
        "agentic_workflows_seen": ["Threat Intelligence (OTX/WHOIS/URLScan/AIG)",
                                   "Event Search", "Insight Correlation"],
    },
    # How the live product already mirrors the model in ../README.md:
    "model_mapping": {
        "verdict-fusion": "insight.verdict.evidence[] (weighted: event_pattern/mitre/threat_intel)",
        "campaign-cluster": "correlated insights + [Insight Correlation Workflow]",
        "replay/retro-hunt": "2-week historical repeat-pattern correlation",
        "AIG enrichment": "[Threat Intelligence Workflow] OTX/WHOIS/URLScan/AIG",
        "agentic sub-agents": "thread_id triage workflows writing comments back to the insight",
        "entity model": "schema fields user_name/source_ipv4/dest_ipv4/file.hash.sha256/url.domain/threat.indicator.value",
    },
}


# ── Write-back payloads (PREPARED — fire once write scope is granted) ─────────
FIELDSET_PAYLOAD = {
    "name": "WildFire/PAN Threat Research — Entity Fields (demo)",
    "fields": ["type", "@timestamp", "vendor", "event.dataset", "user_name", "user_email",
               "host_name", "source_ipv4", "dest_ipv4", "destination.geo.country_iso_code",
               "action", "event.outcome", "file.hash.sha256", "url.domain",
               "threat.indicator.type", "threat.indicator.value", "severity"],
    "share_level": "PRIVATE",
    "tags": ["demo", "wildfire", "threat-research", "entity-model"],
}

VIEW_PAYLOAD = {
    "name": "WildFire / PAN Threat Research (Abstract model demo)",
    "description": "Threat-relevant PAN datasets projected through the entity-centric "
                   "fieldset; the surface for hash/domain/IP/user pivots in the model.",
    "condition": {"operator": "AND",
                  "conditions": [{"field": "event.dataset", "field_type": "String",
                                  "field_operation": "IS_IN_LIST", "value": "THREAT, TRAFFIC",
                                  "case_sensitive": False}],
                  "groups": []},
    "time_range_hours": 720,
    "share_level": "PRIVATE",
    "tags": ["demo", "wildfire", "threat-research"],
    # fieldset_ids: [<id from FIELDSET_PAYLOAD once created>]
}

INSIGHT_PAYLOAD = {
    "payload": {
        "title": "WildFire-style Verdict Fusion + ATO↔C2 Bridge (model demo)",
        "status": "open",
        "severity": "critical",
        "categories": ["detection"],
        "summary": (
            "Model-generated finding (see docs/threat-model). Demonstrates shift-left "
            "verdict fusion: a malware verdict (WildFire/NGFW) corroborated by EDR execution "
            "and a beacon to C2 on the same host, fused into one critical finding — then the "
            "ATO↔C2 bridge: an identity authenticating from the same C2 infrastructure. "
            "Maps onto the live anchor incident l6PqCLQXEq (jacques.plante, 203.0.113.2): "
            "the same evidence-weighted, entity-correlated, campaign-clustered pattern Abstract "
            "Amplify already produces — extended with WildFire report IOCs as a live AIG "
            "matchlist and a predictive 'next target' score. Read-time demo; not a real alert."),
        "mitre_attack_techniques": [
            {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"},
            {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell"},
            {"id": "T1055", "name": "Process Injection"},
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1098", "name": "Account Manipulation"},
            {"id": "T1567", "name": "Exfiltration Over Web Service"},
        ],
    }
}


def main():
    import json
    print("LIVE TENANT SNAPSHOT (read-only key)\n" + "=" * 60)
    print(json.dumps(SNAPSHOT, indent=2))
    print("\nPREPARED WRITE-BACK PAYLOADS (need 'mcp.tools.write' or REST)\n" + "=" * 60)
    print("create_fieldset:", json.dumps(FIELDSET_PAYLOAD))
    print("\ncreate_view:", json.dumps(VIEW_PAYLOAD))
    print("\ncreate_insight:", json.dumps(INSIGHT_PAYLOAD))


if __name__ == "__main__":
    main()
