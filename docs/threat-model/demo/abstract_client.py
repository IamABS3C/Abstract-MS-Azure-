"""
Abstract adapter — live REST + offline simulation behind one interface.

Endpoints + auth confirmed from the Abstract API reference
(docs.abstractsecurity.app/docs/api-reference) and exercised against a live test
tenant (see LIVE-RESULTS.md):
  • Base   https://api.abstractsecurity.app
  • Tenant header  x-as-vendor-account-id
  • streamviewer:  POST /v1/streamviewer/{search,timeline,view,field-set,translate}
                   GET  /v1/streamviewer/{views,field-sets,view/{id},field-set/{id}}
                   POST /v2/streamviewer/raw-search           (Elasticsearch DSL)
  • insights:      GET/POST /v1/insights/   GET/PATCH/DELETE /v1/insights/{nanoid}
                   POST /v1/insights/{nanoid}/comments
                   GET/POST/DELETE /v1/insights/{nanoid}/verdict
  • rules-engine:  GET/POST /v1/rules   GET /v3/rules/mitre   (rules generate insights)

Auth scheme for a provisioned API key isn't stated in the docs, so connect()
auto-detects (Bearer → x-api-key → raw Authorization) with a read probe.

The key is read from ~/.abstract.env (outside the repo) or the environment, and
is never printed, logged, or written into the repo.  # security: no raw tokens.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
import urllib.parse


def _load_dotenv():
    candidates = [
        os.path.expanduser("~/.abstract.env"),
        os.path.expanduser("~/.abstract/credentials"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
    ]
    for path in candidates:
        if not os.path.exists(path):
            continue
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        break


_load_dotenv()

ABSTRACT_API_BASE = os.environ.get("ABSTRACT_API_BASE", "https://api.abstractsecurity.app")
# accept either name for the tenant id (the SDK/MCP use VENDOR_ACCOUNT_ID)
ABSTRACT_ACCOUNT_ID = (os.environ.get("ABSTRACT_ACCOUNT_ID")
                       or os.environ.get("ABSTRACT_VENDOR_ACCOUNT_ID", ""))

EP = {
    "search":         "/v1/streamviewer/search",
    "raw_search":     "/v2/streamviewer/raw-search",
    "timeline":       "/v1/streamviewer/timeline",
    "translate":      "/v1/streamviewer/translate",
    "views":          "/v1/streamviewer/views",
    "view":           "/v1/streamviewer/view",
    "fieldsets":      "/v1/streamviewer/field-sets",
    "fieldset":       "/v1/streamviewer/field-set",
    "rules":          "/v1/rules",
    "mitre":          "/v3/rules/mitre",
    "insights":       "/v1/insights/",
}


class AbstractClient:
    def __init__(self, mode: str = "offline"):
        self.mode = "api" if mode in ("api", "live") else "offline"
        self.key = os.environ.get("ABSTRACT_API_KEY", "")
        self.scheme = None
        self.sent = {"fieldsets": 0, "views": 0, "rules": 0, "insights": 0}
        if self.mode == "api" and not self.key:
            raise RuntimeError("mode=api needs ABSTRACT_API_KEY (e.g. in ~/.abstract.env)")

    # ── transport ────────────────────────────────────────────────────────────
    def _headers(self, scheme: str) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if ABSTRACT_ACCOUNT_ID:
            h["x-as-vendor-account-id"] = ABSTRACT_ACCOUNT_ID
        if scheme == "bearer":
            h["Authorization"] = f"Bearer {self.key}"
        elif scheme == "x-api-key":
            h["x-api-key"] = self.key
        elif scheme == "raw":
            h["Authorization"] = self.key
        return h

    def _req(self, method: str, path: str, body: dict = None, scheme: str = None) -> dict:
        if self.mode != "api":
            return {"ok": True, "simulated": True}
        scheme = scheme or self.scheme or "bearer"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(ABSTRACT_API_BASE + path, data=data, method=method,
                                     headers=self._headers(scheme))
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                txt = r.read().decode()
                return {"ok": True, "status": r.status,
                        "body": json.loads(txt) if txt.strip().startswith(("{", "[")) else txt}
        except urllib.error.HTTPError as e:
            return {"ok": False, "status": e.code, "error": e.read().decode()[:500]}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    # thin generic verbs (so a notebook/agent can hit any documented endpoint)
    def get(self, path, scheme=None):          return self._req("GET", path, scheme=scheme)
    def post(self, path, body, scheme=None):   return self._req("POST", path, body, scheme=scheme)
    def patch(self, path, body, scheme=None):  return self._req("PATCH", path, body, scheme=scheme)
    def put(self, path, body, scheme=None):    return self._req("PUT", path, body, scheme=scheme)
    def delete(self, path, scheme=None):       return self._req("DELETE", path, scheme=scheme)

    # ── connectivity + auth auto-detect (read-only probe) ────────────────────────
    def connect(self) -> dict:
        if self.mode != "api":
            self.scheme = "offline"; return {"ok": True, "scheme": "offline"}
        for scheme in ("bearer", "x-api-key", "raw"):
            r = self._req("GET", EP["views"], scheme=scheme)
            if r.get("ok"):
                self.scheme = scheme
                return {"ok": True, "scheme": scheme, "status": r.get("status")}
            if r.get("status") == 403:  # authenticated but unauthorized → scheme is right
                self.scheme = scheme
                return {"ok": True, "scheme": scheme, "status": 403, "note": "authn ok, authz limited"}
        return {"ok": False, "error": "no auth scheme worked", "last": r}

    def whoami(self) -> dict:
        """Best-effort identity probe (endpoint varies by deployment)."""
        for path in ("/v1/users/me", "/v1/me", "/v1/auth/me"):
            r = self._req("GET", path)
            if r.get("ok"):
                return r
        return {"ok": False, "note": "no /me endpoint; auth verified via connect()"}

    # ── streamviewer: search / query / timeline / translate ──────────────────────
    def search(self, condition: dict = None, query_string: str = "", size: int = 50,
               start: str = "2026-05-16T00:00:00Z", end: str = "2026-06-16T23:59:59Z") -> dict:
        body = {"start_time": start, "end_time": end, "size": size,
                "vendor_account_id": ABSTRACT_ACCOUNT_ID}
        if condition:
            body["condition"] = condition
        if query_string:
            body["query_string"] = query_string
        return self._req("POST", EP["search"], body)

    def raw_search(self, query: dict, aggs: dict = None, size: int = 10,
                   start: str = "2026-05-16T00:00:00Z", end: str = "2026-06-16T23:59:59Z",
                   sort: list = None) -> dict:
        """Elasticsearch DSL search — what the views-beta UI calls under the hood."""
        body = {"start_time": start, "end_time": end, "query": query, "size": size}
        if aggs:
            body["aggs"] = aggs
        if sort:
            body["sort"] = sort
        return self._req("POST", EP["raw_search"], body)

    def translate(self, natural_language: str) -> dict:
        """NL → Abstract ConditionGroup (does not execute). The API field is `query`."""
        return self._req("POST", EP["translate"], {"query": natural_language,
                                                    "vendor_account_id": ABSTRACT_ACCOUNT_ID})

    def timeline(self, query_string="", start="2026-05-16T00:00:00Z",
                 end="2026-06-16T23:59:59Z", chunks=6):
        body = {"start_time": start, "end_time": end,
                "vendor_account_id": ABSTRACT_ACCOUNT_ID, "chunks": chunks}
        if query_string:
            body["query_string"] = query_string
        return self._req("POST", EP["timeline"], body)

    # ── views ────────────────────────────────────────────────────────────────
    def list_views(self):           return self._req("GET", EP["views"] + "?page_size=500")
    def get_view(self, vid):        return self._req("GET", EP["view"] + "/" + vid)
    def create_view(self, payload: dict) -> dict:
        self.sent["views"] += 1
        if self.mode == "offline":
            print("[offline] view:", payload.get("name")); return {"ok": True, "simulated": True}
        return self._req("POST", EP["view"], payload)
    def update_view(self, vid, payload):  return self._req("PATCH", EP["view"] + "/" + vid, payload)
    def delete_view(self, vid):     return self._req("DELETE", EP["view"] + "/" + vid)

    # ── field sets ─────────────────────────────────────────────────────────────
    def list_fieldsets(self):       return self._req("GET", EP["fieldsets"] + "?page_size=500")
    def get_fieldset(self, fid):    return self._req("GET", EP["fieldset"] + "/" + fid)
    def create_fieldset(self, payload: dict) -> dict:
        self.sent["fieldsets"] += 1
        if self.mode == "offline":
            print("[offline] field-set:", payload.get("name")); return {"ok": True, "simulated": True}
        return self._req("POST", EP["fieldset"], payload)
    def update_fieldset(self, fid, payload): return self._req("PATCH", EP["fieldset"] + "/" + fid, payload)
    def delete_fieldset(self, fid): return self._req("DELETE", EP["fieldset"] + "/" + fid)

    # ── rules + MITRE ──────────────────────────────────────────────────────────
    def list_rules(self):           return self._req("GET", EP["rules"])
    def get_rule(self, rid):        return self._req("GET", EP["rules"] + "/" + str(rid))
    def create_rule(self, payload: dict) -> dict:
        self.sent["rules"] += 1
        if self.mode == "offline":
            print("[offline] rule:", payload.get("name")); return {"ok": True, "simulated": True}
        return self._req("POST", EP["rules"], payload)
    def update_rule(self, rid, payload): return self._req("PATCH", EP["rules"] + "/" + str(rid), payload)
    def mitre(self):                return self._req("GET", EP["mitre"])

    # ── insights (alerts / cases) ────────────────────────────────────────────────
    def list_insights(self, page_size: int = 50, **filters) -> dict:
        qs = {"page_size": page_size}
        qs.update({k: v for k, v in filters.items() if v is not None})
        return self._req("GET", EP["insights"] + "?" + urllib.parse.urlencode(qs))

    def get_insight(self, nanoid):  return self._req("GET", EP["insights"] + nanoid)
    def create_insight(self, payload: dict) -> dict:
        self.sent["insights"] += 1
        if self.mode == "offline":
            print("[offline] insight:", payload.get("title")); return {"ok": True, "simulated": True}
        return self._req("POST", EP["insights"], payload)
    def update_insight(self, nanoid, payload): return self._req("PATCH", EP["insights"] + nanoid, payload)
    def delete_insight(self, nanoid):          return self._req("DELETE", EP["insights"] + nanoid)
    def add_insight_comment(self, nanoid, text): return self._req(
        "POST", EP["insights"] + nanoid + "/comments", {"comment": text})
    def get_insight_verdict(self, nanoid):     return self._req("GET", EP["insights"] + nanoid + "/verdict")
    def set_insight_verdict(self, nanoid, verdict, **extra):
        return self._req("POST", EP["insights"] + nanoid + "/verdict", {"verdict": verdict, **extra})
    def insight_findings(self, nanoid):        return self._req("GET", EP["insights"] + nanoid + "/findings")
    def insight_resources(self, nanoid):       return self._req("GET", EP["insights"] + nanoid + "/resources")


if __name__ == "__main__":
    import sys
    c = AbstractClient("api" if "--api" in sys.argv else "offline")
    print("connect:", json.dumps(c.connect()))
    if "--api" in sys.argv:
        print("views:", len((c.list_views().get("body", {}) or {}).get("views", [])))
        print("insights total:",
              (c.list_insights(page_size=1).get("body", {}) or {}).get("metadata", {}).get("total_count"))
