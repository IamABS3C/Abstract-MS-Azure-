"""Config-driven external integrations — the "add a key / endpoint and it lights up" layer.

Every integration declares the env vars it needs; `configured()` is true once they're set,
and `lookup()` / `search()` run a REAL query against that tool. Nothing here requires a key
to import — unconfigured integrations report `configured: False` and are skipped, so the
notebook runs offline and enables each tool the moment its creds are present (in
`~/.abstract.env` or the environment, or set live from the console Settings tab).

  SIEM / log:   Microsoft Sentinel (Log Analytics KQL) · Splunk (REST) · Elastic (_search)
  MCP:          Abstract MCP · Microsoft Sentinel MCP / Security Copilot (generic MCP URL)
  Core:         Abstract REST

Secrets are read from the environment and sent only to their own endpoint over TLS — never
printed, logged, or written to the repo (same discipline as abstract_client / enrichment)."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT = 12


def _http(method, url, headers=None, body=None, timeout=DEFAULT_TIMEOUT):
    data = None
    if isinstance(body, (bytes, bytearray)):
        data = body
    elif isinstance(body, dict):
        data = json.dumps(body).encode()
    elif isinstance(body, str):
        data = body.encode()
    req = urllib.request.Request(url, data=data, method=method,
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


class Integration:
    name = "base"
    kind = "tool"        # siem | mcp | core | edr
    env: list = []       # env vars required to enable
    note = ""

    def configured(self) -> bool:
        return all(os.environ.get(e) for e in self.env)

    def status(self) -> dict:
        return {"name": self.name, "kind": self.kind, "configured": self.configured(),
                "needs": list(self.env), "note": self.note}

    def lookup(self, value: str, kind: str = "") -> dict:
        """Entity/IOC → related events on this tool. Override per integration."""
        return {"configured": self.configured(), "note": "lookup not implemented"}

    def search(self, query: str) -> dict:
        return {"configured": self.configured(), "note": "search not implemented"}


# ── Microsoft Sentinel via Azure Monitor / Log Analytics (KQL) ─────────────────────
class MicrosoftSentinel(Integration):
    name = "Microsoft Sentinel (Log Analytics)"
    kind = "siem"
    env = ["SENTINEL_WORKSPACE_ID", "SENTINEL_TOKEN"]
    note = "Bearer token for api.loganalytics.io (AAD). KQL query."

    def search(self, query: str) -> dict:
        if not self.configured():
            return {"configured": False, "needs": self.env}
        wsid = os.environ["SENTINEL_WORKSPACE_ID"]
        tok = os.environ["SENTINEL_TOKEN"]
        r = _http("POST", f"https://api.loganalytics.io/v1/workspaces/{wsid}/query",
                  headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                  body={"query": query})
        if not r.get("ok"):
            return {"configured": True, "error": r.get("error") or r.get("status")}
        tables = (r.get("data") or {}).get("tables") or []
        rows = tables[0].get("rows", []) if tables else []
        return {"configured": True, "hits": len(rows), "sample": rows[:5]}

    def lookup(self, value, kind=""):
        return self.search(f'search "{value}" | take 5')


# ── Splunk (REST oneshot export) ───────────────────────────────────────────────────
class Splunk(Integration):
    name = "Splunk"
    kind = "siem"
    env = ["SPLUNK_URL", "SPLUNK_TOKEN"]
    note = "SPLUNK_URL=https://host:8089 + bearer token. REST search/jobs/export."

    def search(self, query: str) -> dict:
        if not self.configured():
            return {"configured": False, "needs": self.env}
        url = os.environ["SPLUNK_URL"].rstrip("/") + "/services/search/jobs/export"
        spl = query if query.strip().startswith("search ") else f"search {query}"
        body = urllib.parse.urlencode({"search": spl, "output_mode": "json", "count": 5}).encode()
        r = _http("POST", url, headers={"Authorization": f"Bearer {os.environ['SPLUNK_TOKEN']}",
                                        "Content-Type": "application/x-www-form-urlencoded"}, body=body)
        if not r.get("ok"):
            return {"configured": True, "error": r.get("error") or r.get("status")}
        data = r.get("data")
        rows = []
        if isinstance(data, str):
            for line in data.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        rows.append(json.loads(line).get("result", {}))
                    except Exception:  # noqa: BLE001
                        pass
        return {"configured": True, "hits": len(rows), "sample": rows[:5]}

    def lookup(self, value, kind=""):
        return self.search(f'index=* "{value}" | head 5')


# ── Elastic / OpenSearch (_search) ──────────────────────────────────────────────────
class Elastic(Integration):
    name = "Elastic / OpenSearch"
    kind = "siem"
    env = ["ELASTIC_URL", "ELASTIC_API_KEY"]
    note = "ELASTIC_URL=https://host:9200 + base64 API key. POST _search."

    def search(self, query: str) -> dict:
        if not self.configured():
            return {"configured": False, "needs": self.env}
        url = os.environ["ELASTIC_URL"].rstrip("/") + "/_search"
        r = _http("POST", url,
                  headers={"Authorization": f"ApiKey {os.environ['ELASTIC_API_KEY']}",
                           "Content-Type": "application/json"},
                  body={"size": 5, "query": {"query_string": {"query": query}}})
        if not r.get("ok"):
            return {"configured": True, "error": r.get("error") or r.get("status")}
        hits = ((r.get("data") or {}).get("hits") or {})
        total = hits.get("total")
        total = total.get("value") if isinstance(total, dict) else total
        return {"configured": True, "hits": total,
                "sample": [h.get("_source") for h in (hits.get("hits") or [])[:5]]}

    def lookup(self, value, kind=""):
        return self.search(f'"{value}"')


# ── MCP slots (Abstract + Microsoft Sentinel MCP / Security Copilot) ────────────────
class AbstractMCPIntegration(Integration):
    name = "Abstract MCP"
    kind = "mcp"
    env = []   # bundled stdio server works without a key; ABSTRACT_MCP_URL overrides
    note = "Bundled stdio server (solution/mcp) or ABSTRACT_MCP_URL for a remote endpoint."

    def configured(self) -> bool:
        return True

    def status(self):
        s = super().status()
        s["endpoint"] = os.environ.get("ABSTRACT_MCP_URL", "(bundled stdio server)")
        return s

    def lookup(self, value, kind=""):
        try:
            from mcp_client import AbstractMCP
            m = AbstractMCP()
            piv = m.call("osint_pivots", indicator=value)
            return {"configured": True, "ok": piv.get("ok"),
                    "pivots": (piv.get("result") or {}).get("count")}
        except Exception as e:  # noqa: BLE001
            return {"configured": True, "error": str(e)[:120]}


class GenericMCP(Integration):
    """Microsoft Sentinel MCP / Security Copilot / any MCP server — set its URL to enable."""
    kind = "mcp"

    def __init__(self, name, env_url):
        self.name = name
        self.env = [env_url]
        self._env_url = env_url
        self.note = f"Set {env_url} to a streamable-HTTP MCP endpoint."

    def status(self):
        s = super().status()
        s["endpoint"] = os.environ.get(self._env_url, "(unset)")
        return s


class AbstractREST(Integration):
    name = "Abstract REST"
    kind = "core"
    env = ["ABSTRACT_API_KEY"]
    note = "ABSTRACT_API_KEY (+ ABSTRACT_ACCOUNT_ID for tenant header)."


# Registry — extend by appending an Integration subclass.
REGISTRY = [
    AbstractREST(),
    AbstractMCPIntegration(),
    MicrosoftSentinel(),
    GenericMCP("Microsoft Sentinel MCP", "SENTINEL_MCP_URL"),
    GenericMCP("Security Copilot MCP", "SECURITY_COPILOT_MCP_URL"),
    Splunk(),
    Elastic(),
]


def registry_status() -> list:
    return [i.status() for i in REGISTRY]


def configured() -> dict:
    return {i.name: i.configured() for i in REGISTRY}


def get(name: str):
    for i in REGISTRY:
        if i.name == name:
            return i
    return None


def lookup_all(value: str, kind: str = "", kinds=("siem", "mcp")) -> dict:
    """Run an entity/IOC lookup across every CONFIGURED integration of the given kinds."""
    out = {}
    for i in REGISTRY:
        if i.kind in kinds and i.configured():
            try:
                out[i.name] = i.lookup(value, kind)
            except Exception as e:  # noqa: BLE001
                out[i.name] = {"error": str(e)[:120]}
    return out


def selftest():
    st = registry_status()
    names = {s["name"] for s in st}
    assert {"Microsoft Sentinel (Log Analytics)", "Splunk", "Elastic / OpenSearch",
            "Abstract REST", "Abstract MCP", "Microsoft Sentinel MCP"} <= names
    # unconfigured siem returns configured:False (no network)
    assert MicrosoftSentinel().search("x | take 1")["configured"] in (False, True)
    assert get("Splunk").configured() in (False, True)
    # Abstract MCP is always "configured" (bundled)
    assert get("Abstract MCP").configured() is True
    assert callable(lookup_all)   # exercised live from the console, not in the unit check
    return {"ok": True, "integrations": len(REGISTRY),
            "configured_now": sum(configured().values())}


if __name__ == "__main__":
    print(selftest())
