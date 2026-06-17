#!/usr/bin/env python3
"""
OSINT pivots for incident investigation.

Given an indicator (IP, CIDR, domain, hash, email, username, URL, ASN, CVE),
return curated deep-links into hacker/OSINT search engines distilled from
github.com/edoardottt/awesome-hacker-search-engines (see search_engines.json).

Pure-link enrichment: no API keys, no outbound calls — just the right pivots for
an analyst or an agent. Engines that also offer keyed APIs are tagged in the
registry; wire those in separately if you want automated enrichment.

CLI:
    python osint_pivots.py 8.8.8.8
    python osint_pivots.py evil.example.com
    python osint_pivots.py CVE-2024-3094
    python osint_pivots.py --type username jdoe

Reused by the Abstract MCP server (tool: osint_pivots) and the Copilot agent.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse

_REGISTRY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "search_engines.json")

_PATTERNS = [
    ("cve", re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)),
    ("asn", re.compile(r"^AS\d+$", re.I)),
    ("cidr", re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")),
    ("ip", re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")),
    ("hash", re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")),
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
    ("url", re.compile(r"^https?://", re.I)),
    ("domain", re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")),
]


def detect_type(indicator: str) -> str:
    s = indicator.strip()
    for t, rx in _PATTERNS:
        if rx.search(s):
            return t
    return "username"


def _load():
    with open(_REGISTRY) as fh:
        return json.load(fh)


def _fill(template: str, indicator: str, itype: str) -> str:
    enc = urllib.parse.quote(indicator, safe="")
    # ASN as bare number where the template implies it; keep "AS" prefix for bgp.he.net etc.
    return (template
            .replace("{ip}", enc).replace("{cidr}", enc).replace("{domain}", enc)
            .replace("{hash}", enc).replace("{email}", enc).replace("{username}", enc)
            .replace("{url}", enc).replace("{asn}", enc).replace("{cve}", enc.upper())
            .replace("{query}", enc))


def pivots(indicator: str, itype: str | None = None) -> dict:
    """Return {indicator, type, count, pivots:[{name,category,url,auth,tags}]}."""
    itype = itype or detect_type(indicator)
    reg = _load()
    out = []
    for e in reg["engines"]:
        if itype in e["indicator_types"]:
            out.append({
                "name": e["name"], "category": e["category"],
                "url": _fill(e["url"], indicator, itype),
                "auth": e.get("auth", "none"), "tags": e.get("tags", []),
            })
    return {"indicator": indicator, "type": itype, "count": len(out), "pivots": out,
            "attribution": reg["attribution"]["url"]}


def main(argv=None):
    p = argparse.ArgumentParser(description="OSINT pivot links for an indicator")
    p.add_argument("indicator")
    p.add_argument("--type", choices=[t for t, _ in _PATTERNS] + ["username", "query"], help="override auto-detection")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    res = pivots(a.indicator, a.type)
    if a.json:
        print(json.dumps(res, indent=2)); return
    print(f"{res['indicator']}  (type: {res['type']})  — {res['count']} pivots")
    cat = None
    for piv in res["pivots"]:
        if piv["category"] != cat:
            cat = piv["category"]; print(f"\n  {cat}")
        key = "" if piv["auth"] in ("none", "manual") else f"  [{piv['auth']}]"
        print(f"    {piv['name']:<22} {piv['url']}{key}")


if __name__ == "__main__":
    main()
