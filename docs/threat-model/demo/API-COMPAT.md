# Abstract API - compatibility report

Generated from the live `/openapi.json` (OpenAPI 3.1.0, API Abstract v0.0.2) on 2026-06-23.

**27/27** endpoints the demo uses are present with the expected method. Auth: bearer token + `x-as-vendor-account-id` tenant header.

| status | method | path | used for | spec methods |
|---|---|---|---|---|
| OK | GET | `/v1/streamviewer/views` | list_views | GET |
| OK | POST | `/v1/streamviewer/view` | create_view | POST |
| OK | PATCH | `/v1/streamviewer/view/{id}` | update_view | DELETE,GET,PATCH |
| OK | DELETE | `/v1/streamviewer/view/{id}` | delete_view | DELETE,GET,PATCH |
| OK | GET | `/v1/streamviewer/field-sets` | list_fieldsets | GET |
| OK | POST | `/v1/streamviewer/field-set` | create_fieldset | POST |
| OK | POST | `/v1/streamviewer/search` | search (GetEvents) | POST |
| OK | POST | `/v1/streamviewer/translate` | translate | POST |
| OK | POST | `/v1/streamviewer/timeline` | timeline | POST |
| OK | POST | `/v1/streamviewer/field-analytics` | field analytics | POST |
| OK | POST | `/v2/streamviewer/raw-search` | raw_search (tenant-gated) | POST |
| OK | GET | `/v2/rules/` | list_rules | GET |
| OK | POST | `/v1/rules/` | create_rule | GET,POST |
| OK | GET | `/v3/rules/` | rules v3 | GET |
| OK | POST | `/v3/rules/validations` | rule validate | POST |
| OK | DELETE | `/v1/rules/{rule_id}` | delete rule | DELETE,GET,PATCH |
| OK | GET | `/v3/rules/mitre` | mitre coverage | GET |
| OK | GET | `/v2/rules/mitre` | mitre v2 | GET |
| OK | GET | `/v1/insights/` | list_insights | GET,POST |
| OK | POST | `/v1/insights/` | create_insight | GET,POST |
| OK | PATCH | `/v1/insights/{insight_id}` | update_insight | DELETE,GET,PATCH |
| OK | DELETE | `/v1/insights/{insight_id}` | delete_insight | DELETE,GET,PATCH |
| OK | POST | `/v1/insights/comments` | add comment (CommentCreate) | POST |
| OK | POST | `/v1/insights/{insight_id}/verdict` | set verdict | DELETE,GET,POST |
| OK | GET | `/v2/rule-tuning-filters/` | list suppressions | GET,POST |
| OK | POST | `/v2/rule-tuning-filters/` | create suppression | GET,POST |
| OK | DELETE | `/v2/rule-tuning-filters/{filter_id}` | delete suppression | DELETE,PATCH |

## Notes
- `search` (`GetEvents`): requires non-empty `selected_fields` (`['*']` = all), `page_size`, `storage_type`, a non-future time window, and a typed `condition` (each field's `field_type` comes from the tenant field schema).
- `/v2/streamviewer/raw-search` is in the spec but returns *endpoint not enabled* on this tenant.
- Rules: list via `GET /v2/rules/` (or `/v3/rules/`); `GET /v1/rules` (no trailing slash) 500s. Create via `POST /v1/rules/` + validate via `POST /v3/rules/validations`.
- Full spec exposes 300 paths; this report covers the surface the demo integrates with.
