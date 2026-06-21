"""External-search & corroboration deep-links — one click from any selected entity/IOC/actor
to the wider web: search engines, APT / ransomware / infostealer actor databases, code &
social, news & advisories, and dark-web indexes (clearnet front-ends — ToS-safe deep-links,
no scraping). Pairs with the keyed enrichment fabric (enrichment.py) and SIEM/MCP lookups
(integrations.py) so an investigation corroborates Abstract findings against public sources:
articles, disclosures, remediations, related incidents.

Every value is a URL template with `{q}`; the entity value is URL-encoded. Nothing here makes
a network call — these are links the analyst opens. IOC-typed pivots reuse the 24-engine
registry in identities.py."""
from __future__ import annotations
import urllib.parse

try:
    import identities as ID
except Exception:   # noqa: BLE001
    ID = None


def _q(s):
    return urllib.parse.quote_plus(str(s))


# category → [(name, url-template-with {q})]
_TEMPLATES = {
    "search": [
        ("Google", "https://www.google.com/search?q={q}"),
        ("Bing", "https://www.bing.com/search?q={q}"),
        ("DuckDuckGo", "https://duckduckgo.com/?q={q}"),
        ("Brave", "https://search.brave.com/search?q={q}"),
        ("Yandex", "https://yandex.com/search/?text={q}"),
    ],
    "threat_actor": [
        ("MITRE ATT&CK Groups", "https://www.google.com/search?q=site:attack.mitre.org+groups+{q}"),
        ("Malpedia", "https://www.google.com/search?q=site:malpedia.caad.fkie.fraunhofer.de+{q}"),
        ("ETDA APT cards", "https://apt.etda.or.th/cgi-bin/aptsearch.cgi?q={q}"),
        ("ORKL reports", "https://orkl.eu/search?query={q}"),
        ("MISP galaxy", "https://github.com/MISP/misp-galaxy/search?q={q}"),
        ("ThreatFox tag", "https://threatfox.abuse.ch/browse/tag/{q}/"),
    ],
    "ransomware_infostealer": [
        ("Ransomware.live", "https://www.ransomware.live/#/search?q={q}"),
        ("ransomwatch", "https://github.com/joshhighet/ransomwatch"),
        ("Hudson Rock", "https://www.hudsonrock.com/search?domain={q}"),
        ("MalwareBazaar", "https://bazaar.abuse.ch/browse.php?search={q}"),
        ("VX-Underground", "https://www.google.com/search?q=site:vx-underground.org+{q}"),
    ],
    "code_social": [
        ("GitHub code", "https://github.com/search?q={q}&type=code"),
        ("GitHub repos", "https://github.com/search?q={q}&type=repositories"),
        ("Reddit", "https://www.reddit.com/search/?q={q}"),
        ("X / Twitter", "https://twitter.com/search?q={q}"),
        ("infosec.exchange", "https://infosec.exchange/search?q={q}"),
        ("LinkedIn", "https://www.linkedin.com/search/results/all/?keywords={q}"),
    ],
    "news_advisory": [
        ("Google News", "https://news.google.com/search?q={q}"),
        ("CISA advisories", "https://www.cisa.gov/news-events/cybersecurity-advisories?search_api_fulltext={q}"),
        ("The DFIR Report", "https://thedfirreport.com/?s={q}"),
        ("BleepingComputer", "https://www.bleepingcomputer.com/search/?q={q}"),
        ("KrebsOnSecurity", "https://krebsonsecurity.com/?s={q}"),
        ("Remediation / advisory", "https://www.google.com/search?q={q}+remediation+mitigation+advisory"),
    ],
    "darkweb_index": [
        ("Ahmia (Tor index)", "https://ahmia.fi/search/?q={q}"),
        ("Intelligence X", "https://intelx.io/?s={q}"),
        ("Leak/forum mentions", "https://www.google.com/search?q={q}+breach+OR+leak+OR+forum+OR+marketplace"),
    ],
}


def _expand(categories, q):
    enc = _q(q)
    return {cat: [{"name": n, "url": tpl.format(q=enc)} for n, tpl in _TEMPLATES[cat]]
            for cat in categories}


def actor_pivots(name) -> dict:
    """For an APT / ransomware / infostealer / bad-actor group name."""
    return _expand(["search", "threat_actor", "ransomware_infostealer", "news_advisory",
                    "code_social", "darkweb_index"], name)


def ioc_pivots(value, kind="keyword") -> dict:
    """IOC deep-links: the keyless 24-engine registry (identities.py) + search/news."""
    out = _expand(["search", "news_advisory", "darkweb_index"], value)
    if ID is not None:
        try:
            reg = ID.pivot_urls(value, kind if kind in
                                ("ip", "domain", "url", "hash", "email", "cve") else "keyword")
            out["intel"] = [{"name": n, "url": (d.get("url") if isinstance(d, dict) else d)}
                            for n, d in list(reg.items())]
        except Exception:   # noqa: BLE001
            pass
    return out


def corroboration(query) -> list:
    """Public articles / disclosures / remediations to corroborate a finding."""
    enc = _q(query)
    return [{"name": n, "url": tpl.format(q=enc)} for n, tpl in _TEMPLATES["news_advisory"]]


def entity_pivots(entity, kind=None) -> dict:
    """Dispatch for a selected entity. `entity` may be a graph key ('account:okta:jsmith@…'),
    a bare value, or an actor name. IOC kinds get IOC intel; everything also gets web/actor/
    social/news/dark-web reach so any selection corroborates against the wider internet."""
    ident = entity.split(":", 1)[1] if isinstance(entity, str) and ":" in entity else entity
    et = entity.split(":", 1)[0] if isinstance(entity, str) and ":" in entity else ""
    kind = kind or {"ip": "ip", "domain": "domain", "hash": "hash", "url": "url"}.get(et)
    if kind in ("ip", "domain", "hash", "url", "email", "cve"):
        piv = ioc_pivots(ident, kind)
        piv.update(_expand(["threat_actor", "code_social"], ident))
        return piv
    # principals / accounts / hosts / unknown names → full actor + web reach
    return actor_pivots(ident)


def flatten(pivots: dict) -> list:
    out = []
    for cat, items in pivots.items():
        for it in items:
            out.append({"category": cat, **it})
    return out


def selftest():
    a = actor_pivots("LockBit")
    assert "threat_actor" in a and a["search"][0]["url"].startswith("https://")
    assert any("attack.mitre.org" in x["url"] for x in a["threat_actor"])
    i = ioc_pivots("185.220.101.45", "ip")
    assert "search" in i and ("intel" in i or ID is None)
    e = entity_pivots("account:okta:jsmith@acme.com")
    assert e and flatten(e)
    e2 = entity_pivots("ip:91.219.236.12")
    assert "darkweb_index" in e2
    assert corroboration("Qakbot")[0]["url"].startswith("https://")
    cats = set(a) | set(i)
    return {"ok": True, "categories": sorted(cats), "actor_links": len(flatten(a)),
            "ioc_links": len(flatten(i))}


if __name__ == "__main__":
    print(selftest())
