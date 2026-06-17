# OSINT pivots

Curated investigation deep-links distilled from
[awesome-hacker-search-engines](https://github.com/edoardottt/awesome-hacker-search-engines)
(by edoardottt — credit + license per that repo). Turns an indicator into the
right set of hacker/OSINT search-engine links for an analyst or an agent.

- `search_engines.json` — the registry (engine, category, indicator types, URL
  template, auth requirement, tags).
- `osint_pivots.py` — auto-detects the indicator type and fills the templates.

**Pure-link enrichment**: no API keys and no outbound calls — it just builds the
pivots. Engines that also offer keyed APIs (VirusTotal, GreyNoise, Shodan, IntelX,
DeHashed…) are tagged `auth: free|login` in the registry; wire those into a keyed
enricher separately if you want automated lookups.

## Use it

```bash
python solution/osint/osint_pivots.py 203.0.113.66
python solution/osint/osint_pivots.py evil.example.com --json
python solution/osint/osint_pivots.py CVE-2024-3094
python solution/osint/osint_pivots.py --type username jdoe
```

Supported indicator types (auto-detected): `ip`, `cidr`, `domain`, `hash`
(md5/sha1/sha256), `email`, `url`, `asn` (e.g. `AS15169`), `cve`, and
`username`/`query` fallback.

## Where it plugs in

- **MCP** — the Abstract MCP server exposes it as the `osint_pivots` tool, so
  Claude / Copilot / any MCP client can pivot on an IOC mid-investigation
  alongside the Abstract API tools.
- **Copilot agent** — `solution/copilot/abstract-agent.yaml` instructs the
  triage agent to gather pivots for each external IOC and cite the best ones.
- **Playbooks / notebook** — `osint_pivots.pivots(indicator)` returns structured
  links you can drop into an incident comment or the threat-model demo's report.

## Extending

Add engines to `search_engines.json` (the full awesome-hacker-search-engines list
has hundreds across servers, code search, vulnerabilities, credentials, social,
crypto, IoT, etc.). Keep URL templates using the `{ip}/{domain}/{hash}/{email}/
{username}/{url}/{asn}/{cve}/{query}` tokens so the filler picks them up.
