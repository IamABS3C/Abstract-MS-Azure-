"""Keyless, zero-config external research that RETURNS results (not just links).

An extension layer for the Abstract console: web search, Wikipedia, page fetch/scrape, and a
consolidated entity/actor research brief — all with NO API keys, NO signup, stdlib only. Uses
official keyless endpoints (DuckDuckGo Instant Answer API, Wikipedia REST) plus a DuckDuckGo
HTML fallback for organic results, and generic readable-text extraction for any fetched page.

Pairs with: enrichment.py (keyless intel: EPSS/CISA-KEV/NVD/URLhaus/MalwareBazaar/HudsonRock/…)
and osint_pivots.py (one-click deep-links). This module is the "actually fetch & return the
content" complement. It never replaces Abstract — it adds outside context to an investigation."""
from __future__ import annotations

import html as _html
import json
import re
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (compatible; AbstractAISOC/1.0; +research)"
TIMEOUT = 12


def _get(url, headers=None, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers={**{"User-Agent": UA, "Accept": "*/*"}, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"ok": True, "status": r.status, "ctype": r.headers.get_content_type(),
                    "text": r.read(2_000_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": e.read(400).decode("utf-8", "replace")}
    except Exception as e:   # noqa: BLE001
        return {"ok": False, "error": str(e)[:200]}


def _try_json(s):
    try:
        return json.loads(s)
    except Exception:   # noqa: BLE001
        return None


def _strip_html(h: str) -> str:
    h = re.sub(r"(?is)<(script|style|noscript|svg|head|nav|footer)\b.*?</\1>", " ", h)
    h = re.sub(r"(?s)<!--.*?-->", " ", h)
    text = _html.unescape(re.sub(r"(?s)<[^>]+>", " ", h))
    return re.sub(r"\s+", " ", text).strip()


def _ddg_unwrap(href: str) -> str:
    m = re.search(r"uddg=([^&]+)", href)
    return urllib.parse.unquote(m.group(1)) if m else href


def _flatten_related(topics):
    out = []
    for t in topics or []:
        if isinstance(t, dict) and "Topics" in t:
            out += _flatten_related(t["Topics"])
        elif isinstance(t, dict) and t.get("Text"):
            out.append({"title": t["Text"][:80], "snippet": t["Text"], "url": t.get("FirstURL", "")})
    return out


def _ddg_html(query, n):
    # Robust across DDG markup changes: grab the organic-result redirect links (/l/?uddg=…)
    # from the lite endpoint first, then the html endpoint.
    for url in ("https://lite.duckduckgo.com/lite/?" + urllib.parse.urlencode({"q": query}),
                "https://html.duckduckgo.com/html/?" + urllib.parse.urlencode({"q": query})):
        r = _get(url)
        if not r.get("ok"):
            continue
        out, seen = [], set()
        for m in re.finditer(r'(?is)<a[^>]+href="([^"]*uddg=[^"]+)"[^>]*>(.*?)</a>', r["text"]):
            u, t = _ddg_unwrap(m.group(1)), _strip_html(m.group(2))
            if not t or u in seen:
                continue
            seen.add(u)
            out.append({"title": t, "snippet": "", "url": u})
            if len(out) >= n:
                break
        if out:
            return out
    return []


def web_search(query: str, n: int = 6) -> list:
    """Keyless web search → real results [{title, snippet, url}]. DuckDuckGo Instant Answer
    API (official) first, then DuckDuckGo HTML organic results as fallback."""
    out = []
    r = _get("https://api.duckduckgo.com/?" + urllib.parse.urlencode(
        {"q": query, "format": "json", "no_html": "1", "no_redirect": "1", "t": "abstract-aisoc"}))
    if r.get("ok"):
        d = _try_json(r["text"]) or {}
        if d.get("AbstractText"):
            out.append({"title": d.get("Heading") or query, "snippet": d["AbstractText"],
                        "url": d.get("AbstractURL", "")})
        out += _flatten_related(d.get("RelatedTopics"))
    if len(out) < n:
        have = {x["url"] for x in out}
        out += [x for x in _ddg_html(query, n) if x["url"] not in have]
    return out[:n]


def wikipedia(query: str) -> dict:
    """Keyless Wikipedia summary (opensearch → REST summary)."""
    r = _get("https://en.wikipedia.org/w/api.php?" + urllib.parse.urlencode(
        {"action": "opensearch", "search": query, "limit": 1, "format": "json"}))
    d = _try_json(r.get("text", "")) if r.get("ok") else None
    title = d[1][0] if (d and len(d) > 1 and d[1]) else query
    s = _get("https://en.wikipedia.org/api/rest_v1/page/summary/"
             + urllib.parse.quote(title.replace(" ", "_")))
    if not s.get("ok"):
        return {"ok": False, "title": title}
    sd = _try_json(s["text"]) or {}
    # relevance guard: opensearch fuzzy-matches (e.g. "Qakbot"→"Qaboos"); reject weak matches
    toks = [t for t in re.split(r"\W+", query.lower()) if len(t) > 3]
    blob = (sd.get("title", "") + " " + sd.get("extract", "")).lower()
    if toks and not any(t in blob for t in toks):
        return {"ok": False, "title": sd.get("title", title),
                "note": f"no close Wikipedia match for '{query}'"}
    return {"ok": True, "title": sd.get("title", title), "extract": sd.get("extract", ""),
            "url": ((sd.get("content_urls") or {}).get("desktop") or {}).get("page", "")}


def fetch_text(url: str, max_chars: int = 4000) -> dict:
    """Fetch a URL and return readable text (scrape any page) or parsed JSON."""
    r = _get(url)
    if not r.get("ok"):
        return {"url": url, "ok": False, "error": r.get("error") or r.get("status")}
    body = r["text"]
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
    title = _html.unescape(m.group(1)).strip() if m else ""
    if "json" in (r.get("ctype") or ""):
        return {"url": url, "ok": True, "title": title, "json": _try_json(body)}
    return {"url": url, "ok": True, "title": title, "text": _strip_html(body)[:max_chars]}


def research_entity(value: str, kind: str = None) -> dict:
    """Consolidated keyless research brief for an indicator / actor / keyword:
    web-search hits + a Wikipedia summary. Callers add Abstract + intel context."""
    return {"value": value, "web": web_search(value, 5), "wikipedia": wikipedia(value)}


def capabilities() -> dict:
    """Advertise the keyless sources (no key / no signup)."""
    return {"web_search": "DuckDuckGo Instant Answer API + HTML fallback (keyless)",
            "wikipedia": "Wikipedia REST summary (keyless)",
            "fetch_text": "generic page fetch + readable-text extraction (scrape)"}


def selftest():
    # pure, network-free shape checks (live calls are exercised on use)
    assert _strip_html("<b>hi</b><script>x()</script>there") == "hi there"
    assert _strip_html("<p>a&amp;b</p>") == "a&b"
    assert _ddg_unwrap("//duckduckgo.com/l/?uddg=https%3A%2F%2Fa.com%2Fx&rut=1") == "https://a.com/x"
    assert _try_json('{"a":1}') == {"a": 1} and _try_json("nope") is None
    rel = _flatten_related([{"Text": "x", "FirstURL": "u"},
                            {"Topics": [{"Text": "y", "FirstURL": "v"}]}])
    assert len(rel) == 2 and rel[1]["title"] == "y"
    return {"ok": True, "sources": list(capabilities())}


if __name__ == "__main__":
    import sys
    if "--live" in sys.argv:        # manual live smoke test
        print(json.dumps(research_entity(sys.argv[-1] if sys.argv[-1] != "--live" else "Qakbot"), indent=2)[:1500])
    else:
        print(selftest())
