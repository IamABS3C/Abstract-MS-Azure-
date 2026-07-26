"""Local backend for the interactive dashboard — makes every action LIVE (no Jupyter kernel).

  python3 server.py [--port 8765] [--live]      # or:  ./run.sh --serve
  → http://127.0.0.1:8765

Serves console.html (built fresh from the current State) and a small JSON API the app's
buttons call: connect to Abstract, enrich, cross-reference SIEM/MCP, dry-run/apply authoring,
and AI summarize/triage. Pure stdlib (http.server) — no new dependencies. Binds localhost only;
API keys are set process-local via /api/connect and never logged or written to disk.

This is the same engine the notebook console uses; the browser app is now a first-class,
fully-wired client of it."""
from __future__ import annotations

import json
import os
import sys
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import live_data
import enrichment as EN
import integrations as IN
import abstract_authoring as AA
import ai_agents as AI
import console_app

STATE = {"s": None, "conn": None}


def rebuild():
    STATE["s"] = live_data.build_state(STATE["conn"])
    return STATE["s"]


def _connect_from_env():
    try:
        from abstract_client import AbstractClient
        c = AbstractClient("api")
        if c.connect().get("ok"):
            STATE["conn"] = c
    except Exception:   # noqa: BLE001
        pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):   # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html", "/console.html"):
            self._send(200, console_app.build_app(STATE["s"], backend=True),
                       "text/html; charset=utf-8")
        elif path == "/api/health":
            self._send(200, {"ok": True, "live": STATE["s"].live, "source": STATE["s"].source})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0) or 0)
        try:
            body = json.loads(self.rfile.read(ln) or b"{}")
        except Exception:   # noqa: BLE001
            body = {}
        try:
            self._send(200, self._route(self.path.split("?", 1)[0], body))
        except Exception as e:   # noqa: BLE001 — never 500 the UI; surface the message
            self._send(200, {"error": str(e)[:240]})

    def _route(self, path, b):
        if path == "/api/connect":
            for var, val in (("ABSTRACT_API_KEY", b.get("key")),
                             ("ABSTRACT_ACCOUNT_ID", b.get("account")),
                             ("ABSTRACT_API_BASE", b.get("base"))):
                if val:
                    os.environ[var] = val          # process-local; never logged
            from abstract_client import AbstractClient
            c = AbstractClient("api")
            conn = c.connect()
            if conn.get("ok"):
                STATE["conn"] = c
                rebuild()
            return {"ok": bool(conn.get("ok")), "scheme": conn.get("scheme"),
                    "live": STATE["s"].live, "source": STATE["s"].source,
                    "note": conn.get("note")}
        if path == "/api/offline":
            STATE["conn"] = None
            rebuild()
            return {"ok": True, "source": STATE["s"].source}
        if path == "/api/setenv":              # set any integration/AI/enrichment key
            name = (b.get("name") or "").strip()
            if name:
                os.environ[name] = b.get("value", "")
            return {"ok": bool(name), "set": name}
        if path == "/api/enrich":
            v = b.get("value", "")
            k = b.get("kind") or EN.detect_kind(v)
            return EN.enrich_entity(v, k)
        if path == "/api/xref":
            v = b.get("value", "")
            k = b.get("kind") or EN.detect_kind(v)
            return {"results": IN.lookup_all(v, k)}
        if path == "/api/author":
            a = AA.build(b.get("kind", "Saved view"), state=STATE["s"])
            if b.get("apply"):
                if not STATE["conn"]:
                    return {"diff": a["diff"], "applied": {"applied": False,
                            "note": "not connected — connect in Settings first"}}
                return {"diff": a["diff"], "applied": AA.apply(STATE["conn"], a)}
            return {"diff": a["diff"], "payload": a["payload"],
                    "live_capable": a["live_capable"], "applied": False}
        if path == "/api/ai":
            fn = AI.triage if b.get("action") == "triage" else AI.summarize_investigation
            return fn(STATE["s"], provider=b.get("provider"))
        if path == "/api/review":
            return AA.review(STATE["conn"], state=STATE["s"])
        if path == "/api/state":
            return console_app._data(STATE["s"])
        return {"error": "unknown route: " + path}


def main():
    port = 8765
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    if "--live" in sys.argv:
        _connect_from_env()
    rebuild()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Abstract AI-SOC console (live backend) → http://127.0.0.1:{port}   (Ctrl-C to stop)")
    print(f"  state: {STATE['s'].source}  ·  connect a tenant from the Settings tab")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


def selftest():
    """Exercise the routes in-process (no socket) against an offline State."""
    rebuild()
    h = Handler.__new__(Handler)        # bypass socket init; call _route directly
    assert "error" not in h._route("/api/offline", {})
    au = h._route("/api/author", {"kind": "Saved view"})
    assert au["applied"] is False and au["live_capable"] is True
    st = h._route("/api/state", {})
    assert "entities" in st and st["kpis"]
    page = console_app.build_app(STATE["s"], backend=True)
    assert "const BACKEND = true" in page and "/api/enrich" in page
    return {"ok": True, "routes": ["connect", "offline", "setenv", "enrich", "xref",
                                   "author", "ai", "review", "state"], "source": STATE["s"].source}


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        print(selftest())
    else:
        main()
