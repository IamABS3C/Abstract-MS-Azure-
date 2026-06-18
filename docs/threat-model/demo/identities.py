"""
Expanded identity / entity taxonomy + OSINT source registry for investigations.

Covers the full spectrum the modern SOC cares about — human, machine, non-human
(NHI), service principals, AI agents, and stolen sessions/cookies — across every
identity source, plus a pluggable registry of OSINT / threat-intel tools
(Maltego, SpiderFoot, Criminal IP, SpyCloud, …) used during hunts and incidents.

Dep-free. The OSINT adapters are stubs with a clear `# ← plug real API here` seam;
they return shaped, simulated enrichment so the notebook/report run end-to-end.
"""
from __future__ import annotations

# ── Identity taxonomy ────────────────────────────────────────────────────────
# kind → (description, schema key fields, example sources, why it matters)
IDENTITY_TYPES = {
    "human_user":       ("Interactive person", ["user_name", "user.email"],
                         ["Okta", "Entra ID", "Active Directory", "Duo", "Ping"],
                         "ATO, phishing, insider, MFA fatigue"),
    "service_account":  ("Non-interactive app/service login", ["user_name", "service.name"],
                         ["Active Directory", "Okta", "GCP", "Kubernetes"],
                         "over-privileged, rarely rotated, lateral movement"),
    "non_human_identity": ("NHI — tokens/keys/bots not tied to a person",
                         ["service.name", "user_name", "cloud.account_id"],
                         ["AWS IAM", "GitHub", "CI/CD", "secrets managers"],
                         "secret sprawl, token theft, supply-chain"),
    "service_principal": ("Cloud app identity / managed identity",
                         ["cloud.account_id", "user_name"],
                         ["Entra ID", "AWS IAM Role", "GCP Service Account"],
                         "consent abuse, role escalation, persistence"),
    "machine_host":     ("Device / workload / node", ["host_name", "host_address", "host.os.name"],
                         ["EDR", "AKS/EKS", "Defender", "CrowdStrike"],
                         "C2 host, lateral pivot, crypto-mining"),
    "ai_agent":         ("Autonomous AI/agentic identity (MCP, copilots)",
                         ["service.name", "process.name", "user_name"],
                         ["Agent platforms", "MCP servers", "Entra Agent ID"],
                         "prompt injection, tool abuse, agent identity sprawl"),
    "session_cookie":   ("Stolen web session / token (no password)",
                         ["user.email", "user_name", "source_address"],
                         ["Okta", "Entra", "AiTM/Evilginx", "stealer logs"],
                         "MFA bypass via session theft"),
    "api_key":          ("Long-lived programmatic credential",
                         ["service.name", "cloud.account_id"],
                         ["AWS access keys", "API gateways", "SaaS PATs"],
                         "leaked-key abuse, exfil"),
    "workload_identity": ("Federated workload (WIF / OIDC)",
                         ["cloud.account_id", "service.name"],
                         ["GCP WIF", "Azure WI", "GitHub OIDC"],
                         "cross-cloud trust abuse"),
}

# source → identity kinds it emits + its principal key field
IDENTITY_SOURCES = {
    "Okta":            (["human_user", "service_account", "session_cookie"], "user.email"),
    "Entra ID":        (["human_user", "service_principal", "ai_agent", "session_cookie"], "user.email"),
    "Active Directory": (["human_user", "service_account", "machine_host"], "user_name"),
    "AWS IAM":         (["non_human_identity", "service_principal", "api_key"], "user_name"),
    "GCP IAM":         (["service_account", "workload_identity"], "user_name"),
    "Duo / Ping":      (["human_user"], "user.email"),
    "GitHub":          (["non_human_identity", "workload_identity"], "user_name"),
    "Kubernetes":      (["service_account", "workload_identity", "machine_host"], "service.name"),
    "EDR / XDR":       (["machine_host", "human_user"], "host_name"),
    "Agent platform":  (["ai_agent", "non_human_identity"], "service.name"),
}


def classify_entity(ent: dict) -> str:
    """Heuristically map a normalized entity dict → identity kind."""
    t = ent.get("type", ""); name = (ent.get("id") or "").lower()
    if t == "agent" or "agent" in name or "autobot" in name:
        return "ai_agent"
    if t == "nhi" or name.startswith("svc") or "pipeline" in name or "ci" in name:
        return "non_human_identity"
    if t == "host":
        return "machine_host"
    if t == "account":
        return "service_principal" if any(k in name for k in ("aws", "gcp", "azure")) else "human_user"
    if t == "identity":
        return "human_user"
    return "human_user"


# ── OSINT / threat-intel tool registry (pluggable) ───────────────────────────
# name → (category, entity kinds it enriches, what it returns)
OSINT_TOOLS = {
    "Maltego":         ("graph-recon", ["domain", "ip", "email", "person"], "link analysis / transforms"),
    "SpiderFoot":      ("auto-recon", ["domain", "ip", "email", "hash", "name"], "automated OSINT footprint"),
    "Criminal IP":     ("ip-reputation", ["ip"], "malicious/scanner/c2 scoring"),
    "GreyNoise":       ("ip-reputation", ["ip"], "internet-noise vs targeted"),
    "Shodan / Censys": ("attack-surface", ["ip", "domain"], "exposed services/banners"),
    "VirusTotal":      ("multi-rep", ["hash", "domain", "ip", "url"], "AV consensus / relations"),
    "AbuseIPDB":       ("ip-reputation", ["ip"], "abuse confidence score"),
    "AlienVault OTX":  ("intel-feed", ["ip", "domain", "hash"], "community pulses"),
    "MISP / OpenCTI":  ("tip", ["ip", "domain", "hash", "actor"], "curated IOCs + attribution"),
    "Recorded Future": ("intel", ["ip", "domain", "hash", "actor"], "risk scores + intel cards"),
    "urlscan.io":      ("url-recon", ["url", "domain"], "live page + redirects"),
    "SpyCloud":        ("exposure", ["email", "session_cookie"], "breach + stolen-session data"),
    "Hudson Rock":     ("stealer-logs", ["email", "machine_host", "session_cookie"], "infostealer infections"),
    "Have I Been Pwned": ("breach", ["email"], "credential exposure"),
}


# ── Hacker / OSINT search-engine pivot registry ──────────────────────────────
# Curated from github.com/edoardottt/awesome-hacker-search-engines. Each entry gives
# a direct search-URL template so an analyst/agent can one-click pivot on any IOC.
# kind ∈ {ip, domain, url, hash, email, cve, keyword}
SEARCH_ENGINES = {
    # attack surface / servers
    "Shodan":        ("attack-surface", ["ip", "domain"], "https://www.shodan.io/search?query={q}"),
    "Censys":        ("attack-surface", ["ip", "domain"], "https://search.censys.io/search?resource=hosts&q={q}"),
    "ZoomEye":       ("attack-surface", ["ip", "domain"], "https://www.zoomeye.org/searchResult?q={q}"),
    "FOFA":          ("attack-surface", ["ip", "domain"], "https://fofa.info/result?qbase64={b64}"),
    "Netlas":        ("attack-surface", ["ip", "domain"], "https://app.netlas.io/responses/?q={q}"),
    "Onyphe":        ("attack-surface", ["ip", "domain"], "https://www.onyphe.io/search/?query={q}"),
    "Criminal IP":   ("attack-surface", ["ip"], "https://www.criminalip.io/asset/search?query={q}"),
    # threat intel
    "VirusTotal":    ("threat-intel", ["ip", "domain", "hash", "url"], "https://www.virustotal.com/gui/search/{q}"),
    "GreyNoise":     ("threat-intel", ["ip"], "https://viz.greynoise.io/ip/{q}"),
    "Pulsedive":     ("threat-intel", ["ip", "domain", "url"], "https://pulsedive.com/explore/search?keyword={q}"),
    "ThreatMiner":   ("threat-intel", ["ip", "domain", "hash"], "https://www.threatminer.org/host.php?q={q}"),
    "AbuseIPDB":     ("threat-intel", ["ip"], "https://www.abuseipdb.com/check/{q}"),
    "AlienVault OTX": ("threat-intel", ["ip", "domain", "hash"], "https://otx.alienvault.com/indicator/ip/{q}"),
    "urlscan.io":    ("url-recon", ["url", "domain"], "https://urlscan.io/search/#{q}"),
    # certs / dns / domains
    "crt.sh":        ("certificates", ["domain"], "https://crt.sh/?q={q}"),
    "DNSDumpster":   ("dns", ["domain"], "https://dnsdumpster.com/?q={q}"),
    # code
    "GitHub Code":   ("code", ["keyword", "domain", "hash"], "https://github.com/search?q={q}&type=code"),
    "grep.app":      ("code", ["keyword", "domain"], "https://grep.app/search?q={q}"),
    # breach / leaks / email
    "Have I Been Pwned": ("breach", ["email"], "https://haveibeenpwned.com/account/{q}"),
    "Dehashed":      ("breach", ["email", "domain"], "https://dehashed.com/search?query={q}"),
    "IntelligenceX": ("leaks", ["email", "domain", "ip", "url"], "https://intelx.io/?s={q}"),
    "Hudson Rock":   ("stealer-logs", ["email", "domain"], "https://www.hudsonrock.com/search?q={q}"),
    # vulns / exploits
    "NIST NVD":      ("vulnerabilities", ["cve"], "https://nvd.nist.gov/vuln/search/results?query={q}"),
    "Exploit-DB":    ("exploits", ["cve", "keyword"], "https://www.exploit-db.com/search?q={q}"),
}


def pivot_urls(value: str, kind: str) -> dict:
    """One-click pivot URLs across every relevant hacker search engine for an IOC."""
    import base64
    import urllib.parse
    q = urllib.parse.quote(str(value))
    b64 = base64.b64encode(str(value).encode()).decode()
    out = {}
    for name, (cat, kinds, tmpl) in SEARCH_ENGINES.items():
        if kind in kinds:
            out[name] = {"category": cat, "url": tmpl.format(q=q, b64=b64)}
    return out


def greynoise_community(ip: str) -> dict:
    """REAL GreyNoise community lookup. The community endpoint now needs a *free*
    API key — set GREYNOISE_API_KEY and it authenticates; without one it returns a
    clear hint instead of a raw 404 (anonymous access was deprecated)."""
    import os
    import urllib.request
    import urllib.error
    import json as _json
    key = os.environ.get("GREYNOISE_API_KEY")
    headers = {"Accept": "application/json"}
    if key:
        headers["key"] = key
    try:
        req = urllib.request.Request(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
        with urllib.request.urlopen(req, timeout=10) as r:
            d = _json.loads(r.read())
        return {"classification": d.get("classification"), "name": d.get("name"),
                "noise": d.get("noise"), "riot": d.get("riot"),
                "last_seen": d.get("last_seen"), "link": d.get("link"),
                "message": d.get("message"), "authenticated": bool(key)}
    except urllib.error.HTTPError as e:  # noqa: PERF203
        if e.code == 404 and not key:
            return {"note": "GreyNoise community now requires a free API key — set GREYNOISE_API_KEY",
                    "noise": None, "authenticated": False}
        try:  # 404 with a key usually means 'IP not observed' and carries a JSON body
            body = _json.loads(e.read())
            return {"classification": body.get("classification"), "noise": body.get("noise"),
                    "message": body.get("message"), "authenticated": bool(key)}
        except Exception:  # noqa: BLE001
            return {"error": f"HTTP {e.code}", "authenticated": bool(key)}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:120]}


def osint_enrich(value: str, kind: str, tools=None, live=False) -> dict:
    """Enrichment from relevant tools. `live=True` calls real adapters where wired
    (GreyNoise community for IPs); others stay stubbed until keys are added."""
    tools = tools or list(OSINT_TOOLS)
    out = {}
    for name in tools:
        cat, kinds, desc = OSINT_TOOLS[name]
        if kind not in kinds:
            continue
        if live and name == "GreyNoise" and kind == "ip":
            out[name] = {"category": cat, "queried": value, "live": True,
                         "result": greynoise_community(value)}        # ← REAL API
        else:
            out[name] = {"category": cat, "queried": value, "result": f"[stub] {desc}",
                         "wire": f"replace with {name} API call for {kind}={value}"}
    return out


def selftest():
    assert classify_entity({"type": "agent", "id": "agent-soc-autobot"}) == "ai_agent"
    assert classify_entity({"type": "nhi", "id": "svc-ci-pipeline"}) == "non_human_identity"
    assert classify_entity({"type": "host", "id": "ACME-LT-4471"}) == "machine_host"
    assert classify_entity({"type": "account", "id": "aws:jsmith"}) == "service_principal"
    e = osint_enrich("185.220.101.45", "ip", ["Criminal IP", "GreyNoise", "Have I Been Pwned"])
    assert "Criminal IP" in e and "Have I Been Pwned" not in e  # HIBP only does email
    piv = pivot_urls("185.220.101.45", "ip")
    assert "Shodan" in piv and "crt.sh" not in piv  # crt.sh is domain-only
    return {"identity_types": len(IDENTITY_TYPES), "identity_sources": len(IDENTITY_SOURCES),
            "osint_tools": len(OSINT_TOOLS), "search_engines": len(SEARCH_ENGINES),
            "ip_pivots": len(piv), "domain_pivots": len(pivot_urls("evil.com", "domain"))}


if __name__ == "__main__":
    import json
    print(json.dumps(selftest(), indent=2))
