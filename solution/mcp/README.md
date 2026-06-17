# Abstract Security MCP server

Exposes the Abstract Security API as **Model Context Protocol** tools so any MCP
client — Claude Desktop/Code, Copilot, or a custom agent — can use the Abstract
pipeline as a source alongside your other MCP sources (Sentinel, GitHub, etc.).

## Tools

| Tool | Maps to | Use |
| --- | --- | --- |
| `abstract_verify` | `GET /v2/auth/` | connectivity / who am I |
| `abstract_acs_fields` | `GET /v1/acs/fields` | explore the Abstract Common Schema (473 fields) |
| `abstract_search_events` | `POST /v1/streamviewer/search` | search normalized events (scope by user / src IP) |
| `abstract_list_workflows` | `GET /v1/ase/workflows` | list agentic workflows (Verdict, IP Threat Intel…) |
| `abstract_get_insight_verdict` | `GET /v1/insights/{id}/verdict` | fetch a stored verdict |
| `abstract_run_verdict` | `POST /v1/ase/workflows/verdict` | run the agentic Verdict workflow |

## Run

```bash
pip install "mcp[cli]"
export ABSTRACT_API_KEY=<key>            # never commit this
export ABSTRACT_VENDOR_ACCOUNT_ID=<id>
python solution/mcp/abstract_mcp_server.py     # stdio
```

## Register with Claude Code / Desktop

`claude mcp add abstract-security -- python /abs/path/solution/mcp/abstract_mcp_server.py`
or add to your MCP config (key supplied via env, **not** in the file):

```json
{
  "mcpServers": {
    "abstract-security": {
      "command": "python",
      "args": ["/abs/path/solution/mcp/abstract_mcp_server.py"],
      "env": {
        "ABSTRACT_API_KEY": "${ABSTRACT_API_KEY}",
        "ABSTRACT_VENDOR_ACCOUNT_ID": "12jW5BDyQR",
        "ABSTRACT_BASE_URL": "https://api.abstractsecurity.app"
      }
    }
  }
}
```

The server reuses the same `AbstractClient` as `solution/scripts/abstract_api.py`,
the Logic App playbooks, and the Copilot plugin — one client, consistent behavior
everywhere. Read-only tools are safe to expose broadly; `abstract_run_verdict`
triggers an agentic workflow, so gate it in autonomous setups.
