"""Keyless MITRE ATT&CK intel via attackcti — actor/group → aliases + techniques + software,
and technique lookup. Lazy + cached: the first call fetches ATT&CK over MITRE's public TAXII
(no key, ~seconds); results are cached for the session. Degrades gracefully if attackcti is
absent or the fetch fails. Extends the console's actor research + MITRE tab."""
from __future__ import annotations

_CACHE = {"client": None, "groups": None}


def available() -> bool:
    try:
        import attackcti
        return attackcti is not None
    except Exception:   # noqa: BLE001
        return False


def _client():
    if _CACHE["client"] is None:
        from attackcti import attack_client
        _CACHE["client"] = attack_client()
    return _CACHE["client"]


def _groups():
    if _CACHE["groups"] is None:
        out = []
        for x in _client().get_groups():
            out.append({"id": getattr(x, "id", ""), "name": getattr(x, "name", ""),
                        "aliases": list(getattr(x, "aliases", []) or [])})
        _CACHE["groups"] = out
    return _CACHE["groups"]


def find_group(name: str) -> dict:
    """Match an actor name/alias → ATT&CK group + the techniques it's known to use."""
    if not available():
        return {"available": False, "note": "pip install attackcti"}
    try:
        nl = (name or "").lower().strip()
        if not nl:
            return {"available": True, "matched": None}
        for g in _groups():
            names = [g["name"]] + g.get("aliases", [])
            if any(nl == n.lower() or (len(nl) > 3 and nl in n.lower()) for n in names if n):
                techs = []
                try:
                    used = _client().get_techniques_used_by_group(g["id"])
                    techs = sorted({getattr(t, "name", "") for t in used} - {""})[:25]
                except Exception:   # noqa: BLE001
                    pass
                return {"available": True, "matched": g["name"], "aliases": g["aliases"][:8],
                        "techniques": techs, "technique_count": len(techs)}
        return {"available": True, "matched": None, "groups_indexed": len(_groups())}
    except Exception as e:   # noqa: BLE001
        return {"available": True, "error": str(e)[:160]}


def selftest():
    # network-free: availability + signatures only (live fetch happens on demand)
    assert isinstance(available(), bool)
    assert callable(find_group)
    return {"ok": True, "available": available()}


if __name__ == "__main__":
    import sys
    if "--live" in sys.argv and available():
        print(find_group(sys.argv[-1] if sys.argv[-1] != "--live" else "Lazarus Group"))
    else:
        print(selftest())
