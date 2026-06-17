"""
Abstract adapter — live REST + offline simulation behind one interface.

Endpoints + auth confirmed from the Abstract API reference
(docs.abstractsecurity.app/docs/api-reference):
  • Base   https://api.abstractsecurity.app
  • Tenant header  x-as-vendor-account-id
  • streamviewer:  POST /v1/streamviewer/{search,timeline,view,field-set,translate}
                   GET  /v1/streamviewer/{views,field-sets,view/{id},field-set/{id}}
  • rules-engine:  POST /v1/rules   GET /v1/rules   (rules generate insights)

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
ABSTRACT_ACCOUNT_ID = os.environ.get("ABSTRACT_ACCOUNT_ID", "")

EP = {
    "search":         "/v1/streamviewer/search",
    "timeline":       "/v1/streamviewer/timeline",
    "translate":      "/v1/streamviewer/translate",
    "views":          "/v1/streamviewer/views",
    "view":           "/v1/streamviewer/view",
    "fieldsets":      "/v1/streamviewer/field-sets",
    "fieldset":       "/v1/streamviewer/field-set",
    "rules":          "/v1/rules",
}


class AbstractClient:
    def __init__(self, mode: str = "offline"):
        self.mode = "api" if mode in ("api", "live") else "offline"
        self.key = os.environ.get("ABSTRACT_API_KEY", "")
        self.scheme = None
        self.sent = {"fieldsets": 0, "views": 0, "rules": 0}
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

    # ── reads ────────────────────────────────────────────────────────────────
    def list_views(self):     return self._req("GET", EP["views"] + "?page_size=500")
    def list_fieldsets(self): return self._req("GET", EP["fieldsets"] + "?page_size=500")
    def list_rules(self):     return self._req("GET", EP["rules"])
    def timeline(self, query_string="", start="2026-05-16T00:00:00Z",
                 end="2026-06-16T23:59:59Z", chunks=6):
        body = {"start_time": start, "end_time": end,
                "vendor_account_id": ABSTRACT_ACCOUNT_ID, "chunks": chunks}
        if query_string:
            body["query_string"] = query_string
        return self._req("POST", EP["timeline"], body)

    # ── deletes (for idempotent demo runs / cleanup) ────────────────────────────
    def delete_view(self, vid):     return self._req("DELETE", EP["view"] + "/" + vid)
    def delete_fieldset(self, fid): return self._req("DELETE", EP["fieldset"] + "/" + fid)

    # ── writes ───────────────────────────────────────────────────────────────
    def create_fieldset(self, payload: dict) -> dict:
        self.sent["fieldsets"] += 1
        if self.mode == "offline":
            print("[offline] field-set:", payload.get("name")); return {"ok": True, "simulated": True}
        return self._req("POST", EP["fieldset"], payload)

    def create_view(self, payload: dict) -> dict:
        self.sent["views"] += 1
        if self.mode == "offline":
            print("[offline] view:", payload.get("name")); return {"ok": True, "simulated": True}
        return self._req("POST", EP["view"], payload)

    def create_rule(self, payload: dict) -> dict:
        self.sent["rules"] += 1
        if self.mode == "offline":
            print("[offline] rule:", payload.get("name")); return {"ok": True, "simulated": True}
        return self._req("POST", EP["rules"], payload)


if __name__ == "__main__":
    import sys
    c = AbstractClient("api" if "--api" in sys.argv else "offline")
    print("connect:", json.dumps(c.connect()))
