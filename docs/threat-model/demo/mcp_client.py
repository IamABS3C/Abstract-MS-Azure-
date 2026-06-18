"""
Connect the notebook to the Abstract Security MCP server.

The same Abstract API, reached over the Model Context Protocol — the way Claude /
Copilot / agents consume it. This helper drives an MCP session from plain Python
(notebook or script): list the server's tools and call them.

Server resolution (first that applies):
  1. ABSTRACT_MCP_URL   — a remote MCP endpoint  (https://…/mcp  or  …/sse)
  2. ABSTRACT_MCP_CMD   — a shell command that speaks MCP over stdio
  3. default            — the bundled stdio server, solution/mcp/abstract_mcp_server.py,
                          launched with THIS interpreter (so it shares the venv)

Auth/tenant for the bundled server come from the environment, same as everywhere:
    export ABSTRACT_API_KEY=...   ABSTRACT_VENDOR_ACCOUNT_ID=...

Degrades gracefully: if the `mcp` SDK isn't installed, or no server can be
reached, every method returns a status dict explaining how to enable it — it
never raises into the notebook. Listing tools needs no Abstract key (FastMCP
returns tool definitions); only *calling* an authenticated tool needs one.

    python3 mcp_client.py             # connect to the bundled server, list tools
    python3 mcp_client.py search abstract_search_events hours=24 size=5
"""
from __future__ import annotations

import asyncio
import os
import shlex
import sys

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    _MCP_OK = True
except Exception as _e:  # noqa: BLE001
    _MCP_OK = False
    _MCP_ERR = str(_e)


def _bundled_server() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "..", "solution", "mcp",
                                          "abstract_mcp_server.py"))


def _run(coro, timeout: float = 45.0):
    """Run an async coroutine whether or not an event loop is already running
    (notebooks run one). Falls back to a worker thread when a loop is live."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(asyncio.wait_for(coro, timeout))
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(1) as ex:
        return ex.submit(lambda: asyncio.run(asyncio.wait_for(coro, timeout))).result()


def _content_to_text(result) -> str:
    parts = []
    for c in getattr(result, "content", []) or []:
        parts.append(getattr(c, "text", "") or "")
    return "\n".join(p for p in parts if p)


class AbstractMCP:
    def __init__(self, server: str = None):
        self.url = os.environ.get("ABSTRACT_MCP_URL")
        self.cmd = server or os.environ.get("ABSTRACT_MCP_CMD")
        self.bundled = _bundled_server()
        self.transport = "url" if self.url else ("cmd" if self.cmd else "stdio")

    # ── transport plumbing ───────────────────────────────────────────────────
    def _server_params(self):
        if self.cmd:
            argv = shlex.split(self.cmd)
            return StdioServerParameters(command=argv[0], args=argv[1:], env=os.environ.copy())
        # bundled server, launched with the current interpreter
        return StdioServerParameters(command=sys.executable, args=[self.bundled], env=os.environ.copy())

    async def _session(self, fn):
        if self.url:
            from mcp.client.streamable_http import streamablehttp_client
            ctx = streamablehttp_client(self.url)
            async with ctx as (read, write, *_):
                async with ClientSession(read, write) as s:
                    await s.initialize()
                    return await fn(s)
        async with stdio_client(self._server_params()) as (read, write):
            async with ClientSession(read, write) as s:
                await s.initialize()
                return await fn(s)

    # ── public API ───────────────────────────────────────────────────────────
    def status(self) -> dict:
        if not _MCP_OK:
            return {"ready": False, "reason": f"mcp SDK not installed ({_MCP_ERR}); pip install 'mcp'"}
        if self.url:
            return {"ready": True, "transport": "streamable-http", "target": self.url}
        if self.cmd:
            return {"ready": True, "transport": "stdio", "target": self.cmd}
        if not os.path.exists(self.bundled):
            return {"ready": False, "reason": f"bundled server not found at {self.bundled}; "
                    "set ABSTRACT_MCP_URL or ABSTRACT_MCP_CMD"}
        # report a repo-relative path (avoid leaking absolute home paths into outputs)
        try:
            target = os.path.relpath(self.bundled)
        except Exception:  # noqa: BLE001
            target = os.path.basename(self.bundled)
        return {"ready": True, "transport": "stdio", "target": target}

    def list_tools(self) -> list:
        if not self.status().get("ready"):
            return [{"error": self.status().get("reason")}]
        try:
            async def fn(s):
                res = await s.list_tools()
                return [{"name": t.name, "description": (t.description or "").strip().split("\n")[0],
                         "input_schema": getattr(t, "inputSchema", None)} for t in res.tools]
            return _run(self._session(fn))
        except Exception as e:  # noqa: BLE001
            return [{"error": str(e)[:200]}]

    def call(self, tool: str, **arguments) -> dict:
        if not self.status().get("ready"):
            return {"ok": False, "error": self.status().get("reason")}
        try:
            async def fn(s):
                res = await s.call_tool(tool, arguments=arguments or {})
                return res
            res = _run(self._session(fn))
            txt = _content_to_text(res)
            data = None
            if txt:
                import json
                try:
                    data = json.loads(txt)
                except Exception:  # noqa: BLE001
                    data = txt
            return {"ok": not getattr(res, "isError", False), "tool": tool, "result": data}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "tool": tool, "error": str(e)[:300]}


def selftest() -> dict:
    m = AbstractMCP()
    st = m.status()
    out = {"status": st}
    if st.get("ready"):
        tools = m.list_tools()
        out["tools"] = [t.get("name") for t in tools if "name" in t]
        out["tool_count"] = len(out["tools"])
    return out


if __name__ == "__main__":
    import json
    m = AbstractMCP()
    if len(sys.argv) > 2 and sys.argv[1] == "search":
        tool = sys.argv[2]
        kwargs = dict(kv.split("=", 1) for kv in sys.argv[3:] if "=" in kv)
        for k, v in list(kwargs.items()):
            if v.isdigit():
                kwargs[k] = int(v)
        print(json.dumps(m.call(tool, **kwargs), indent=2, default=str)[:2000])
    else:
        print(json.dumps(selftest(), indent=2, default=str))
