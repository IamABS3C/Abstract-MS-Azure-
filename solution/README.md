<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../solutions/brand/abstract-logo-white.png">
    <img src="../solutions/brand/abstract-logo-black.png" alt="Abstract Security" height="44">
  </picture>
</p>

<h1 align="center">Microsoft Sentinel content pack</h1>

<p align="center">
  <a href="#whats-in-it">Contents</a> ·
  <a href="#install">Install</a> ·
  <a href="#what-it-changes-in-your-workspace">What it changes</a> ·
  <a href="#secrets">Secrets</a> ·
  <a href="../README.md">Back to the overview</a>
</p>

Optional Microsoft Sentinel content for data the
[Sentinel Destination](../solutions/docs/sentinel-destination-assurance.md) delivers:
- a connector tile, a parser, analytics rules, hunting queries and workbooks, all over the
  Abstract table `AbstractEventLogs_CL`;
- playbooks and a Security Copilot plugin that call the Abstract API from Sentinel.

The destination does **not** need this pack. It is a separate install. It is **lab and
proof-of-concept content**, not a certified Content Hub solution; see
[`Package/PACKAGING.md`](Package/PACKAGING.md) for the certification path.

---

## What's in it

| Folder | Contents |
| --- | --- |
| `Package/` | `mainTemplate.json` installs the whole pack in one deployment; `createUiDefinition.json` is its wizard |
| `connector/` | The "Abstract Security" connector tile (display only), plus two Logic App pull connectors |
| `parsers/` | `ASim_AbstractEvent`, a function that projects Abstract fields onto ASIM-style names |
| `analytics/` | Two scheduled rules: high or critical Abstract events; repeated failures followed by success |
| `hunting/` | Rare or newly seen products; identities with high cumulative risk |
| `workbooks/` | Pipeline overview; value and ROI; cost and TCO comparison |
| `playbooks/` | Enrich an incident from Abstract; Abstract Verdict; tune at source on a false positive |
| `copilot/` | Security Copilot API plugin, KQL skills and a triage agent |
| `mcp/`, `osint/` | An MCP server for the Abstract API, and IOC investigation links |
| `scripts/` | `abstract_api.py` (API client) and `seed_sentinel.py` (lab data seeder) |
| `schema/` | The ACS field catalog and the portal sample `all_fields.json` for the destination's table |

---

## Install

Deploy the Sentinel Destination first, so the Abstract table exists. Then:

```bash
az deployment group create -g <workspace-rg> \
  --template-file solution/Package/mainTemplate.json \
  --parameters workspace=<workspace> keyVaultSecretUri=<https://<vault>.vault.azure.net/secrets/abstract-api-key>
```

Or deploy `mainTemplate.json` from the portal ("Deploy a custom template") with
`createUiDefinition.json`.

After installing:
1. Review each analytics rule and automation rule, then enable the ones you want. They
   install **disabled**.
2. Give each playbook's managed identity **Key Vault Secrets User** on the vault that holds
   the Abstract API key (`keyVaultSecretUri`).
3. Give each playbook's managed identity **Microsoft Sentinel Responder** on the workspace.

---

## What it changes in your workspace

It only adds its own items; it never edits or deletes yours.

| Item | Count | Installed state |
| --- | --- | --- |
| Analytics rules | 2 | Disabled |
| Automation rules | 3 | Disabled, and scoped to this pack's two rules by rule ID, so they never act on other incidents |
| Saved searches (the `ASim_AbstractEvent` function and three hunting queries) | 4 | Available |
| Workbooks | 3 | Available |
| Logic App playbooks and their API connections | 3 | Deployed; they do nothing until an automation rule runs them |
| Connector tiles | 2 | Display only; they create no tables or DCRs |

**What the playbooks do:**
- The Verdict playbook adds a comment and, for a malicious verdict, raises the incident's
  severity to High. It never changes the incident's status.
- Tune-at-source creates an Abstract rule-tuning filter when an incident is closed as a
  false positive.

**Updates:** items have fixed IDs. Reinstalling or updating the pack restores its own
items to the shipped state, including disabled. Tune copies of the rules, not the
originals.

**Legacy API:** the two pull connectors in `connector/` write through the Azure Monitor HTTP
Data Collector API with the workspace key. Microsoft has retired that API in favour of the
Logs Ingestion API, so treat them as legacy.

---

## Lab data

`scripts/seed_sentinel.py` sends sample ACS events to the Abstract table through the Logs
Ingestion API, so the content has data to show.

```bash
python3 solution/scripts/seed_sentinel.py --sample 50 --dry-run      # preview, no credentials
export AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=…
export ABSTRACT_DCE_URL=… ABSTRACT_DCR_IMMUTABLE_ID=…
python3 solution/scripts/seed_sentinel.py --file events.json
```

> [!WARNING]
> **Lab workspaces only.** Seeded rows cannot be told apart from real ones. They reach this
> pack's rules and, if the destination writes ASIM tables, every ASIM rule in the workspace.

---

## Secrets

The Abstract API key is never written into these files.
- **Playbooks** read it at run time from Key Vault through their managed identity
  (`keyVaultSecretUri`).
- **Security Copilot** stores it as a credential setting.
- **The scripts** read `ABSTRACT_API_KEY`, `ABSTRACT_VENDOR_ACCOUNT_ID` and
  `ABSTRACT_BASE_URL` from the environment.

```bash
export ABSTRACT_API_KEY=<key>            # never commit it
export ABSTRACT_VENDOR_ACCOUNT_ID=<vendor-account-id>
python3 solution/scripts/abstract_api.py verify
```
