"""
Authenticated OSINT / threat-intel enrichment for the analyst notebook.

A pluggable registry of REAL adapters. Each one is authenticated from an
environment variable (never hard-coded, never printed) and uses only the stdlib
(urllib) so the module runs anywhere. Adapters whose key is absent are *skipped*
(no network call), so the notebook runs hermetically offline and lights up the
moment keys are present.

    export VT_API_KEY=...            # VirusTotal v3
    export ABUSEIPDB_API_KEY=...     # AbuseIPDB v2
    export SHODAN_API_KEY=...        # Shodan
    export GREYNOISE_API_KEY=...     # GreyNoise (enterprise context; community is keyless)
    export OTX_API_KEY=...           # AlienVault OTX
    export URLSCAN_API_KEY=...       # urlscan.io
    export HIBP_API_KEY=...          # Have I Been Pwned
    export CENSYS_API_ID=...  CENSYS_API_SECRET=...   # Censys (basic auth)

    python3 enrichment.py 185.220.101.45        # auto-detect kind, run available adapters
    python3 enrichment.py evil.com domain

Security: keys are read from the environment and sent only to their own provider
over TLS. They are never returned, logged, or written to disk. See ~/.abstract.env
for how the Abstract key is kept out of the repo — same discipline here.
"""
from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

# reuse the keyless pivots + community GreyNoise already curated in identities.py
import identities as ID

DEFAULT_TIMEOUT = 12


# ── indicator typing ─────────────────────────────────────────────────────────
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)


def detect_kind(indicator: str) -> str:
    s = (indicator or "").strip()
    if "/" in s and _IPV4.match(s.split("/")[0]) and s.count("/") == 1:
        return "cidr"
    if _IPV4.match(s):
        return "ip"
    if _CVE.match(s):
        return "cve"
    if _HASH.match(s):
        return "hash"
    if "@" in s and "." in s.split("@")[-1]:
        return "email"
    if s.lower().startswith(("http://", "https://")):
        return "url"
    if s.upper().startswith("AS") and s[2:].isdigit():
        return "asn"
    if _DOMAIN.match(s):
        return "domain"
    return "keyword"


# ── HTTP helper (stdlib) ─────────────────────────────────────────────────────
def _get(url: str, headers: dict = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    req = urllib.request.Request(url, headers=headers or {"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            txt = r.read().decode()
            return {"ok": True, "status": r.status,
                    "data": json.loads(txt) if txt.strip().startswith(("{", "[")) else txt}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": e.read().decode()[:300]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:200]}


# ── authenticated adapters (each returns a compact, shaped summary) ──────────────
def _virustotal(value, kind):
    key = os.environ.get("VT_API_KEY")
    if not key:
        return {"skipped": "no VT_API_KEY"}
    path = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}.get(kind)
    if not path:
        return {"skipped": f"VirusTotal does not take {kind}"}
    ident = base64.urlsafe_b64encode(value.encode()).decode().strip("=") if kind == "url" else value
    r = _get(f"https://www.virustotal.com/api/v3/{path}/{ident}", {"x-apikey": key, "Accept": "application/json"})
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    stats = (((r.get("data") or {}).get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
    return {"malicious": stats.get("malicious"), "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless"), "undetected": stats.get("undetected")}


def _abuseipdb(value, kind):
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return {"skipped": "no ABUSEIPDB_API_KEY"}
    if kind != "ip":
        return {"skipped": "AbuseIPDB is IP-only"}
    q = urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90})
    r = _get(f"https://api.abuseipdb.com/api/v2/check?{q}", {"Key": key, "Accept": "application/json"})
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = (r.get("data") or {}).get("data") or {}
    return {"abuse_confidence": d.get("abuseConfidenceScore"), "country": d.get("countryCode"),
            "isp": d.get("isp"), "total_reports": d.get("totalReports"), "tor": d.get("isTor")}


def _shodan(value, kind):
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return {"skipped": "no SHODAN_API_KEY"}
    if kind != "ip":
        return {"skipped": "Shodan host lookup is IP-only"}
    r = _get(f"https://api.shodan.io/shodan/host/{value}?key={key}")
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    return {"org": d.get("org"), "os": d.get("os"), "ports": d.get("ports"),
            "hostnames": d.get("hostnames"), "tags": d.get("tags")}


def _greynoise(value, kind):
    if kind != "ip":
        return {"skipped": "GreyNoise is IP-only"}
    # community endpoint (free API key via GREYNOISE_API_KEY); identities.py handles
    # the key header + a clear hint when no key is set.
    return ID.greynoise_community(value)


def _otx(value, kind):
    key = os.environ.get("OTX_API_KEY")
    if not key:
        return {"skipped": "no OTX_API_KEY"}
    section = {"ip": "IPv4", "domain": "domain", "hash": "file"}.get(kind)
    if not section:
        return {"skipped": f"OTX does not take {kind}"}
    base = {"ip": "IPv4", "domain": "domain", "hash": "file"}[kind]
    r = _get(f"https://otx.alienvault.com/api/v1/indicators/{base}/{value}/general",
             {"X-OTX-API-KEY": key, "Accept": "application/json"})
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    pulses = (d.get("pulse_info") or {}).get("count")
    return {"pulses": pulses, "reputation": d.get("reputation"),
            "country": d.get("country_name"), "asn": d.get("asn")}


def _urlscan(value, kind):
    key = os.environ.get("URLSCAN_API_KEY")
    if not key:
        return {"skipped": "no URLSCAN_API_KEY"}
    if kind not in ("domain", "url", "ip"):
        return {"skipped": f"urlscan does not take {kind}"}
    q = urllib.parse.quote(f"page.domain:{value}" if kind == "domain" else f'"{value}"')
    r = _get(f"https://urlscan.io/api/v1/search/?q={q}", {"API-Key": key, "Accept": "application/json"})
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    return {"total_results": d.get("total"),
            "recent": [x.get("page", {}).get("url") for x in (d.get("results") or [])[:3]]}


def _censys(value, kind):
    cid, secret = os.environ.get("CENSYS_API_ID"), os.environ.get("CENSYS_API_SECRET")
    if not (cid and secret):
        return {"skipped": "no CENSYS_API_ID/CENSYS_API_SECRET"}
    if kind != "ip":
        return {"skipped": "Censys host view is IP-only"}
    tok = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    r = _get(f"https://search.censys.io/api/v2/hosts/{value}",
             {"Authorization": f"Basic {tok}", "Accept": "application/json"})
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    res = ((r.get("data") or {}).get("result") or {})
    return {"services": [s.get("service_name") for s in (res.get("services") or [])][:10],
            "asn": (res.get("autonomous_system") or {}).get("name"),
            "country": (res.get("location") or {}).get("country")}


def _hibp(value, kind):
    key = os.environ.get("HIBP_API_KEY")
    if not key:
        return {"skipped": "no HIBP_API_KEY"}
    if kind != "email":
        return {"skipped": "HIBP is email-only"}
    r = _get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(value)}",
             {"hibp-api-key": key, "user-agent": "abstract-soc-notebook", "Accept": "application/json"})
    if r.get("status") == 404:
        return {"breaches": 0}
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    return {"breaches": len(r.get("data") or []),
            "names": [b.get("Name") for b in (r.get("data") or [])][:8]}


# name → (categories, supported kinds, env var(s), adapter)
ENRICHERS = {
    "VirusTotal": ("multi-rep", ["ip", "domain", "hash", "url"], ["VT_API_KEY"], _virustotal),
    "AbuseIPDB":  ("ip-reputation", ["ip"], ["ABUSEIPDB_API_KEY"], _abuseipdb),
    "Shodan":     ("attack-surface", ["ip"], ["SHODAN_API_KEY"], _shodan),
    "GreyNoise":  ("ip-reputation", ["ip"], ["GREYNOISE_API_KEY"], _greynoise),  # keyless community fallback
    "AlienVault OTX": ("intel-feed", ["ip", "domain", "hash"], ["OTX_API_KEY"], _otx),
    "urlscan.io": ("url-recon", ["domain", "url", "ip"], ["URLSCAN_API_KEY"], _urlscan),
    "Censys":     ("attack-surface", ["ip"], ["CENSYS_API_ID", "CENSYS_API_SECRET"], _censys),
    "Have I Been Pwned": ("breach", ["email"], ["HIBP_API_KEY"], _hibp),
}


def available() -> dict:
    """Which adapters are key-configured (booleans only — never the key value).
    GreyNoise is always available via its keyless community endpoint."""
    out = {}
    for name, (_cat, _kinds, envs, _fn) in ENRICHERS.items():
        out[name] = all(os.environ.get(e) for e in envs) or (name == "GreyNoise")
    return out


def enrich(indicator: str, kind: str = None, only=None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run every adapter that supports this indicator kind AND is configured.
    Returns {tool: {category, result|skipped|error}}. Adapters without a key are
    skipped with no network call. Includes keyless pivot deep-links."""
    kind = kind or detect_kind(indicator)
    selected = only or list(ENRICHERS)
    results = {"indicator": indicator, "kind": kind, "tools": {}}
    for name in selected:
        if name not in ENRICHERS:
            continue
        cat, kinds, envs, fn = ENRICHERS[name]
        if kind not in kinds:
            continue
        has_key = all(os.environ.get(e) for e in envs) or name == "GreyNoise"
        if not has_key:
            results["tools"][name] = {"category": cat, "skipped": "no key (" + "/".join(envs) + ")"}
            continue
        results["tools"][name] = {"category": cat, "result": fn(indicator, kind)}
    # keyless one-click pivots (always present)
    results["pivots"] = ID.pivot_urls(indicator, kind if kind in
                                      ("ip", "domain", "url", "hash", "email", "cve") else "keyword")
    return results


def selftest() -> dict:
    assert detect_kind("8.8.8.8") == "ip"
    assert detect_kind("evil.com") == "domain"
    assert detect_kind("a" * 64) == "hash"
    assert detect_kind("user@acme.com") == "email"
    assert detect_kind("CVE-2024-3094") == "cve"
    assert detect_kind("10.0.0.0/8") == "cidr"
    e = enrich("185.220.101.45", "ip")           # offline: adapters skip, pivots present
    assert e["kind"] == "ip" and e["pivots"]
    return {"adapters": len(ENRICHERS), "available_now": sum(available().values()),
            "tools_for_ip": len(e["tools"]), "ip_pivots": len(e["pivots"])}


if __name__ == "__main__":
    import sys
    ind = sys.argv[1] if len(sys.argv) > 1 else "185.220.101.45"
    knd = sys.argv[2] if len(sys.argv) > 2 else None
    print("configured adapters:", json.dumps(available()))
    print(json.dumps(enrich(ind, knd), indent=2)[:2000])
