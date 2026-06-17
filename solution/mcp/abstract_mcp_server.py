#!/usr/bin/env python3
"""
Abstract Security MCP server.

Exposes the Abstract Security API as Model Context Protocol tools so any MCP
client (Claude Desktop / Code, Copilot, custom agents) can use the Abstract
pipeline as a *source* — search normalized events, inspect the ACS schema,
list agentic workflows, and fetch/run verdicts — alongside other MCP sources.

Auth + tenant come from the environment (never hard-code the key):
    export ABSTRACT_API_KEY=<key>
    export ABSTRACT_VENDOR_ACCOUNT_ID=<id>
    export ABSTRACT_BASE_URL=https://api.abstractsecurity.app   # optional

Run (stdio):
    pip install "mcp[cli]"
    python solution/mcp/abstract_mcp_server.py

Register (Claude Desktop / Code) — see solution/mcp/README.md for the JSON.
The server reuses the same AbstractClient as the SDK and the Logic App / Copilot
plugins, so behavior is identical across all of them.
"""
from __future__ import annotations

import os
import sys

# Reuse the canonical client from ../scripts/abstract_api.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from abstract_api import AbstractClient, AbstractError  # noqa: E402

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - helpful message if SDK missing
    print('The MCP SDK is required:  pip install "mcp[cli]"', file=sys.stderr)
    raise

mcp = FastMCP("abstract-security")


def _client() -> AbstractClient:
    return AbstractClient()


@mcp.tool()
def abstract_verify() -> dict:
    """Verify connectivity/auth; returns the current user, org and permission count."""
    d = _client().verify()
    return {
        "user": d.get("email"),
        "organization": (d.get("current_organization") or {}).get("name"),
        "permissions": len(d.get("permissions", [])),
    }


@mcp.tool()
def abstract_acs_fields(grep: str = "", limit: int = 100) -> list:
    """List Abstract Common Schema (ACS) fields and types. Optionally filter by substring."""
    rows = _client().acs_fields()
    if grep:
        rows = [r for r in rows if grep.lower() in str(r.get("field", "")).lower()]
    return [{"field": r["field"], "type": r["data_type"]} for r in rows[:limit]]


@mcp.tool()
def abstract_search_events(hours: int = 24, size: int = 25, username: str = "", src_ip: str = "") -> dict:
    """Search normalized Abstract events over the last `hours`. Optionally scope by username or source IP."""
    condition = None
    conds = []
    if username:
        conds.append({"field": "user_name", "field_type": "String", "operation": "CONTAINS", "value": username})
    if src_ip:
        conds.append({"field": "source_ipv4", "field_type": "Ipv4", "operation": "EQUALS", "value": src_ip})
    if conds:
        condition = {"operator": "and", "conditions": conds}
    res = _client().search_events(hours=hours, size=size, condition=condition)
    return {"count": len(res.get("events", [])), "events": res.get("events", []), "metadata": res.get("metadata", {})}


@mcp.tool()
def abstract_list_workflows() -> list:
    """List Abstract ASTRO/ASE agentic workflows (e.g. Verdict, IP Threat Intelligence) and their enabled state."""
    d = _client().list_workflows()
    return [{"name": w.get("workflow_name"), "enabled": w.get("enabled"), "trigger": w.get("event_type")} for w in d.get("workflows", [])]


@mcp.tool()
def abstract_get_insight_verdict(insight_id: str) -> dict:
    """Fetch the stored agentic verdict for an Abstract insight id."""
    return _client().get_insight_verdict(insight_id)


@mcp.tool()
def abstract_run_verdict(insight_id: str) -> dict:
    """Run Abstract's agentic Verdict workflow for an insight and wait for the result (may take minutes)."""
    return _client().run_verdict(insight_id)


if __name__ == "__main__":
    try:
        mcp.run()
    except AbstractError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
