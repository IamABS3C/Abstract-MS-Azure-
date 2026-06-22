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


# ── free / free-tier adapters (Slice 1 fabric) ───────────────────────────────────
def _hibp_passwords(value, kind):
    """HIBP Pwned Passwords k-anonymity range API. Sends ONLY the SHA-1 prefix —
    the password itself is never transmitted."""
    if kind != "password":
        return {"skipped": "HIBP Pwned Passwords is password-only"}
    import hashlib
    h = hashlib.sha1(value.encode("utf-8")).hexdigest().upper()
    prefix, suffix = h[:5], h[5:]
    r = _get(f"https://api.pwnedpasswords.com/range/{prefix}")
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    data = r.get("data") or ""
    for line in (data.splitlines() if isinstance(data, str) else []):
        suf, _, cnt = line.partition(":")
        if suf.strip().upper() == suffix:
            return {"pwned_count": int((cnt.strip() or "0"))}
    return {"pwned_count": 0}


def _hudsonrock(value, kind):
    """Hudson Rock Cavalier — free infostealer-log exposure check (email/domain/username)."""
    if kind not in ("email", "domain", "username"):
        return {"skipped": "Hudson Rock takes email/domain/username"}
    if kind == "domain":
        url = ("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?"
               + urllib.parse.urlencode({"domain": value}))
    else:
        url = ("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?"
               + urllib.parse.urlencode({"login": value}))
    r = _get(url)
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    if not isinstance(d, dict):
        return {"error": "unexpected response"}
    hits = (d.get("total") or len(d.get("stealers", []) or [])
            or (d.get("total_corporate_services", 0) or 0) + (d.get("total_user_services", 0) or 0))
    return {"infostealer_hits": hits, "message": d.get("message")}


def _intelx(value, kind):
    key = os.environ.get("INTELX_API_KEY")
    if not key:
        return {"skipped": "no INTELX_API_KEY"}
    if kind not in ("email", "domain"):
        return {"skipped": "IntelX search takes email/domain"}
    r = _get("https://2.intelx.io/intelligent/search?"
             + urllib.parse.urlencode({"term": value, "maxresults": 10, "media": 0}),
             {"x-key": key, "Accept": "application/json"})
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    return {"search_id": d.get("id"), "status": d.get("status")}


def _cisa_kev(value, kind):
    if kind != "cve":
        return {"skipped": "CISA KEV is CVE-only"}
    r = _get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
             timeout=15)
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    for v in (d.get("vulnerabilities") or []):
        if str(v.get("cveID", "")).upper() == value.upper():
            return {"known_exploited": True, "vendor": v.get("vendorProject"),
                    "product": v.get("product"), "dateAdded": v.get("dateAdded"),
                    "dueDate": v.get("dueDate")}
    return {"known_exploited": False}


def _nvd(value, kind):
    if kind != "cve":
        return {"skipped": "NVD lookup is CVE-only"}
    r = _get("https://services.nvd.nist.gov/rest/json/cves/2.0?"
             + urllib.parse.urlencode({"cveId": value}), {"Accept": "application/json"})
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    vulns = ((r.get("data") or {}).get("vulnerabilities") or [])
    if not vulns:
        return {"found": False}
    cve = vulns[0].get("cve") or {}
    metrics = cve.get("metrics") or {}
    cvss = None
    for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(mk):
            cvss = ((metrics[mk][0] or {}).get("cvssData") or {}).get("baseScore")
            break
    desc = ""
    for dd in (cve.get("descriptions") or []):
        if dd.get("lang") == "en":
            desc = (dd.get("value") or "")[:200]
            break
    return {"cvss": cvss, "description": desc}


def _post(url, data=None, headers=None, timeout=DEFAULT_TIMEOUT):
    """POST helper (form bytes or pre-encoded JSON bytes)."""
    body = data if isinstance(data, (bytes, type(None))) else urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers=headers or {"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            txt = r.read().decode()
            return {"ok": True, "status": r.status,
                    "data": json.loads(txt) if txt.strip().startswith(("{", "[")) else txt}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": e.read().decode()[:300]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:200]}


# ── more free / free-tier feeds: gov · vuln · exposure · malware · predictive ──────
def _epss(value, kind):
    """FIRST EPSS — probability a CVE will be exploited in the wild (predictive)."""
    if kind != "cve":
        return {"skipped": "EPSS is CVE-only"}
    r = _get(f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(value)}")
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    rows = ((r.get("data") or {}).get("data") or [])
    if not rows:
        return {"found": False}
    d = rows[0]
    return {"epss": round(float(d.get("epss", 0) or 0), 5),
            "percentile": round(float(d.get("percentile", 0) or 0), 5)}


def _internetdb(value, kind):
    """Shodan InternetDB — keyless ports / CVEs / CPEs / hostnames for an IP."""
    if kind != "ip":
        return {"skipped": "InternetDB is IP-only"}
    r = _get(f"https://internetdb.shodan.io/{value}")
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    return {"ports": d.get("ports"), "vulns": d.get("vulns"),
            "cpes": d.get("cpes"), "hostnames": d.get("hostnames"), "tags": d.get("tags")}


def _crtsh(value, kind):
    if kind != "domain":
        return {"skipped": "crt.sh is domain-only"}
    r = _get(f"https://crt.sh/?q={urllib.parse.quote(value)}&output=json")
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    rows = r.get("data") or []
    names = sorted({n.strip() for row in rows for n in str(row.get("name_value", "")).split("\n") if n.strip()})
    return {"certs": len(rows), "subdomains": names[:25]}


def _rdap(value, kind):
    if kind not in ("ip", "domain"):
        return {"skipped": "RDAP takes ip/domain"}
    path = "ip" if kind == "ip" else "domain"
    r = _get(f"https://rdap.org/{path}/{urllib.parse.quote(value)}")
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    org = ""
    for e in (d.get("entities") or []):
        for v in ((e.get("vcardArray") or [None, []])[1] or []):
            if v and v[0] == "fn":
                org = v[3]
                break
        if org:
            break
    return {"handle": d.get("handle"), "name": d.get("name") or d.get("ldhName"),
            "org": org, "country": d.get("country")}


def _ipwhois(value, kind):
    if kind != "ip":
        return {"skipped": "ipwho.is is IP-only"}
    r = _get(f"https://ipwho.is/{value}")
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    conn = d.get("connection") or {}
    return {"country": d.get("country"), "city": d.get("city"),
            "asn": conn.get("asn"), "org": conn.get("org") or conn.get("isp")}


def _leakcheck_public(value, kind):
    if kind != "email":
        return {"skipped": "LeakCheck public is email-only"}
    r = _get(f"https://leakcheck.io/api/public?check={urllib.parse.quote(value)}")
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    return {"found": d.get("found"), "breach_sources": len(d.get("sources") or []),
            "fields": d.get("fields")}


def _ransomware_live(value, kind):
    if kind != "domain":
        return {"skipped": "ransomware.live is domain-only"}
    r = _get(f"https://api.ransomware.live/v2/searchvictims/{urllib.parse.quote(value)}")
    if not r.get("ok"):
        return {"found": False, "note": r.get("status")}
    d = r.get("data")
    rows = d if isinstance(d, list) else (d.get("victims") if isinstance(d, dict) else [])
    rows = rows or []
    return {"victims_found": len(rows),
            "groups": sorted({(v.get("group_name") or v.get("group")) for v in rows
                              if isinstance(v, dict)} - {None})[:5]}


def _urlhaus(value, kind):
    if kind not in ("url", "domain", "ip", "host"):
        return {"skipped": "URLhaus takes url/domain/ip"}
    if kind == "url":
        r = _post("https://urlhaus-api.abuse.ch/v1/url/", {"url": value})
    else:
        r = _post("https://urlhaus-api.abuse.ch/v1/host/", {"host": value})
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    return {"status": d.get("query_status"), "threat": d.get("threat"),
            "url_count": d.get("url_count"),
            "urls": [u.get("url") for u in (d.get("urls") or [])[:3]]}


def _malwarebazaar(value, kind):
    if kind != "hash":
        return {"skipped": "MalwareBazaar is hash-only"}
    hdr = {"Accept": "application/json"}
    key = os.environ.get("MALWAREBAZAAR_API_KEY") or os.environ.get("ABUSE_CH_API_KEY")
    if key:
        hdr["Auth-Key"] = key
    r = _post("https://mb-api.abuse.ch/api/v1/", {"query": "get_info", "hash": value}, headers=hdr)
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    if d.get("query_status") != "ok":
        return {"found": False, "status": d.get("query_status")}
    item = (d.get("data") or [{}])[0]
    return {"file_type": item.get("file_type"), "signature": item.get("signature"),
            "tags": item.get("tags")}


def _threatfox(value, kind):
    key = os.environ.get("THREATFOX_API_KEY") or os.environ.get("ABUSE_CH_API_KEY")
    if not key:
        return {"skipped": "no THREATFOX_API_KEY (free from abuse.ch)"}
    if kind not in ("ip", "domain", "url", "hash"):
        return {"skipped": "ThreatFox takes ip/domain/url/hash"}
    body = json.dumps({"query": "search_ioc", "search_term": value}).encode()
    r = _post("https://threatfox-api.abuse.ch/api/v1/", data=body,
              headers={"Auth-Key": key, "Content-Type": "application/json", "Accept": "application/json"})
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    rows = d.get("data") if isinstance(d.get("data"), list) else []
    return {"status": d.get("query_status"), "iocs": len(rows),
            "malware": sorted({x.get("malware_printable") for x in rows
                               if isinstance(x, dict)} - {None})[:5]}


def _pulsedive(value, kind):
    key = os.environ.get("PULSEDIVE_API_KEY")
    if not key:
        return {"skipped": "no PULSEDIVE_API_KEY (free signup)"}
    if kind not in ("ip", "domain", "url"):
        return {"skipped": "Pulsedive takes ip/domain/url"}
    r = _get(f"https://pulsedive.com/api/explore.php?q={urllib.parse.quote(value)}"
             f"&limit=1&pretty=0&key={key}")
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    res = ((r.get("data") or {}).get("results") or [])
    d = res[0] if res else {}
    return {"risk": d.get("risk"), "threats": d.get("threats")}


def _wildfire(value, kind):
    """Palo Alto WildFire file verdict (XML API) — key-gated."""
    key = os.environ.get("WILDFIRE_API_KEY")
    if not key:
        return {"skipped": "no WILDFIRE_API_KEY"}
    if kind != "hash":
        return {"skipped": "WildFire verdict is hash-only"}
    r = _post("https://wildfire.paloaltonetworks.com/publicapi/get/verdict",
              {"apikey": key, "hash": value}, headers={"Accept": "*/*"})
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    txt = r.get("data") if isinstance(r.get("data"), str) else json.dumps(r.get("data"))
    m = re.search(r"<verdict>(-?\d+)</verdict>", txt or "")
    codes = {"0": "benign", "1": "malware", "2": "grayware",
             "-100": "pending", "-101": "error", "-102": "not found"}
    return {"verdict": codes.get(m.group(1) if m else None, "unknown")}


_FEODO_CACHE = {"ips": None}


def _feodo(value, kind):
    """abuse.ch Feodo Tracker — keyless botnet C2 IP blocklist (Dridex/Emotet/QakBot/…)."""
    if kind != "ip":
        return {"skipped": "Feodo Tracker is IP-only"}
    if _FEODO_CACHE["ips"] is None:
        r = _get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=15)
        rows = r.get("data") if isinstance(r.get("data"), list) else []
        _FEODO_CACHE["ips"] = {str(x.get("ip_address")): x for x in rows if isinstance(x, dict)}
    if not _FEODO_CACHE["ips"]:
        return {"error": "feed unavailable"}
    hit = _FEODO_CACHE["ips"].get(value)
    return {"feodo_c2": bool(hit),
            **({"malware": hit.get("malware"), "first_seen": hit.get("first_seen"),
                "port": hit.get("port")} if hit else {})}


def _circl_cve(value, kind):
    """CIRCL cve-search — keyless CVE intel (CVSS, summary)."""
    if kind != "cve":
        return {"skipped": "CIRCL cve-search is CVE-only"}
    r = _get(f"https://cve.circl.lu/api/cve/{value}")
    if not r.get("ok"):
        return {"error": r.get("error") or r.get("status")}
    d = r.get("data") or {}
    if not isinstance(d, dict) or not d:
        return {"found": False}
    out = {"cvss": d.get("cvss"), "summary": (d.get("summary") or "")[:200],
           "references": len(d.get("references") or [])}
    return out if (out["cvss"] or out["summary"]) else {"found": False}


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
    # free / free-tier (keyless adapters auto-enable: all([]) is True)
    "HIBP Passwords": ("breach", ["password"], [], _hibp_passwords),
    "Hudson Rock": ("infostealer", ["email", "domain", "username"], [], _hudsonrock),
    "Intelligence X": ("leak-search", ["email", "domain"], ["INTELX_API_KEY"], _intelx),
    "CISA KEV": ("vuln-exploited", ["cve"], [], _cisa_kev),
    "NVD": ("vuln", ["cve"], [], _nvd),
    # gov / vuln / exposure / malware / predictive (keyless unless noted)
    "EPSS": ("exploit-prediction", ["cve"], [], _epss),
    "Shodan InternetDB": ("attack-surface", ["ip"], [], _internetdb),
    "crt.sh": ("cert-transparency", ["domain"], [], _crtsh),
    "RDAP": ("registration", ["ip", "domain"], [], _rdap),
    "ipwho.is": ("geo-asn", ["ip"], [], _ipwhois),
    "LeakCheck (public)": ("breach", ["email"], [], _leakcheck_public),
    "Ransomware.live": ("ransomware", ["domain"], [], _ransomware_live),
    "URLhaus": ("malware-url", ["url", "domain", "ip"], [], _urlhaus),
    "MalwareBazaar": ("malware", ["hash"], [], _malwarebazaar),
    "ThreatFox": ("intel-feed", ["ip", "domain", "url", "hash"], ["THREATFOX_API_KEY"], _threatfox),
    "Pulsedive": ("multi-rep", ["ip", "domain", "url"], ["PULSEDIVE_API_KEY"], _pulsedive),
    "Palo Alto WildFire": ("malware", ["hash"], ["WILDFIRE_API_KEY"], _wildfire),
    "abuse.ch Feodo": ("botnet-c2", ["ip"], [], _feodo),
    "CIRCL cve-search": ("vuln", ["cve"], [], _circl_cve),
}

# Non-API pivots — surfaced as keyless deep-links / local compute (no scraping).
# SIEM/MCP lookups (Sentinel · Splunk · Elastic · MCP) live in integrations.py.
# name → (category, kinds, note)
STUBS = {
    "JA3/JA4 fingerprints": ("network-fp", ["session", "ip"], "TLS fingerprint pivot (local compute)"),
    "Dark-web / forums / HUMINT": ("osint-humint", ["email", "username", "domain"],
                                   "keyless pivot deep-links; scraping gated by ToS"),
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


def _reshape(e: dict) -> dict:
    """Flatten enrich()'s tool results into deduped provenance records:
    {value, kind, records:[{source,type,value}], by_source, sources, pivots}."""
    records, by_source = [], {}
    for name, info in (e.get("tools") or {}).items():
        res = info.get("result")
        if not isinstance(res, dict) or "skipped" in res or "error" in res:
            continue
        recs = [{"source": name, "type": k, "value": v} for k, v in res.items() if v is not None]
        if recs:
            by_source[name] = recs
            records.extend(recs)
    seen, deduped = set(), []
    for r in records:
        k = (r["source"], r["type"], str(r["value"]))
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)
    return {"value": e.get("indicator"), "kind": e.get("kind"), "records": deduped,
            "by_source": by_source, "sources": list(by_source), "pivots": e.get("pivots", [])}


def enrich_entity(value: str, kind: str = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Fan out across every enabled adapter that supports `kind`, dedup/merge into
    provenance records. Failures are isolated per adapter (see enrich())."""
    kind = kind or detect_kind(value)
    return _reshape(enrich(value, kind, timeout=timeout))


def selftest() -> dict:
    assert detect_kind("8.8.8.8") == "ip"
    assert detect_kind("evil.com") == "domain"
    assert detect_kind("a" * 64) == "hash"
    assert detect_kind("user@acme.com") == "email"
    assert detect_kind("CVE-2024-3094") == "cve"
    assert detect_kind("10.0.0.0/8") == "cidr"
    e = enrich("185.220.101.45", "ip")           # offline: adapters skip, pivots present
    assert e["kind"] == "ip" and e["pivots"]
    # fabric: free adapters registered + reshaping (all network-free)
    assert {"HIBP Passwords", "Hudson Rock", "CISA KEV", "NVD"} <= set(ENRICHERS)
    assert {"EPSS", "Shodan InternetDB", "crt.sh", "RDAP", "URLhaus", "MalwareBazaar",
            "Ransomware.live", "ipwho.is", "LeakCheck (public)", "abuse.ch Feodo",
            "CIRCL cve-search"} <= set(ENRICHERS)
    assert ENRICHERS["EPSS"][0] == "exploit-prediction"  # predictive feed wired
    assert "Intelligence X" in ENRICHERS and ENRICHERS["Intelligence X"][2] == ["INTELX_API_KEY"]
    assert STUBS
    ee = enrich_entity("AS13335", "asn")          # no adapter supports asn → no network call
    assert set(ee) >= {"value", "kind", "records", "by_source", "sources"} and ee["records"] == []
    sample = {"indicator": "x", "kind": "ip",
              "tools": {"T": {"category": "c", "result": {"a": 1, "b": None}}}, "pivots": []}
    assert _reshape(sample)["records"] == [{"source": "T", "type": "a", "value": 1}]
    return {"ok": True, "adapters": len(ENRICHERS), "available_now": sum(available().values()),
            "stubs": len(STUBS), "tools_for_ip": len(e["tools"]), "ip_pivots": len(e["pivots"])}


if __name__ == "__main__":
    import sys
    ind = sys.argv[1] if len(sys.argv) > 1 else "185.220.101.45"
    knd = sys.argv[2] if len(sys.argv) > 2 else None
    print("configured adapters:", json.dumps(available()))
    print(json.dumps(enrich(ind, knd), indent=2)[:2000])
