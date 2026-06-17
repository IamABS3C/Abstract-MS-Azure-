#!/usr/bin/env python3
"""
Abstract Security API client + CLI (reference SDK for the Sentinel bundle).

Auth + tenant are read from the environment (NEVER hard-code the key):

    export ABSTRACT_API_KEY=<your-api-key>
    export ABSTRACT_BASE_URL=https://api.abstractsecurity.app     # optional, this is the default
    export ABSTRACT_VENDOR_ACCOUNT_ID=<your-vendor-account-id>

The key is sent as a Bearer token; the vendor account id rides in the
`x-as-vendor-account-id` header (Abstract is multi-tenant). Both are required
on most endpoints. See docs.abstractsecurity.app -> API Reference.

This module is the canonical example the Logic App playbooks and the Security
Copilot plugin mirror. Standard library only (urllib) so it runs anywhere.

CLI:
    python abstract_api.py verify
    python abstract_api.py fields [--grep ip] [--limit 50]
    python abstract_api.py search --hours 24 --size 5
    python abstract_api.py workflows
    python abstract_api.py verdict --insight <insight_id>
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import time
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "https://api.abstractsecurity.app"


class AbstractError(RuntimeError):
    """Raised on a non-2xx response, carrying status + body for triage."""

    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:500]}")
        self.status = status
        self.body = body


class AbstractClient:
    def __init__(self, api_key=None, vendor_account_id=None, base_url=None, timeout=60):
        self.api_key = api_key or os.environ.get("ABSTRACT_API_KEY")
        self.vendor_account_id = vendor_account_id or os.environ.get("ABSTRACT_VENDOR_ACCOUNT_ID")
        self.base_url = (base_url or os.environ.get("ABSTRACT_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        if not self.api_key:
            raise SystemExit("ABSTRACT_API_KEY is not set (export it; do not hard-code it).")

    # -- low-level ----------------------------------------------------------
    def _request(self, method, path, body=None, vendor=True):
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}
        if vendor and self.vendor_account_id:
            headers["x-as-vendor-account-id"] = self.vendor_account_id
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise AbstractError(e.code, e.read().decode("utf-8", "replace")) from None

    # -- endpoints used by the bundle --------------------------------------
    def verify(self):
        """GET /v2/auth/ -> current user + permissions (connectivity check)."""
        return self._request("GET", "/v2/auth/")

    def health(self):
        return self._request("GET", "/health-check/")

    def acs_fields(self):
        """GET /v1/acs/fields -> the Abstract Common Schema field catalog."""
        return self._request("GET", "/v1/acs/fields")

    def search_events(self, hours=24, size=30, condition=None, selected_fields=None):
        """POST /v1/streamviewer/search -> events for incident enrichment."""
        end = _dt.datetime.now(_dt.timezone.utc)
        start = end - _dt.timedelta(hours=hours)
        body = {
            "vendor_account_id": self.vendor_account_id,
            "page_size": size,
            "selected_fields": selected_fields or ["id", "@timestamp", "message", "severity", "product", "vendor"],
            "start_time": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end_time": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if condition:
            body["condition"] = condition
        return self._request("POST", "/v1/streamviewer/search", body)

    def list_workflows(self):
        """GET /v1/ase/workflows -> ASTRO/ASE agentic workflows (Verdict, etc.)."""
        return self._request("GET", "/v1/ase/workflows")

    def run_verdict(self, insight_id, poll=True, interval=10, max_wait=300):
        """POST /v1/ase/workflows/verdict (async) then poll for the verdict."""
        started = self._request("POST", "/v1/ase/workflows/verdict", {"insight_id": insight_id})
        task_id = started.get("task_id")
        if not poll or not task_id:
            return started
        waited = 0
        while waited < max_wait:
            res = self._request("GET", f"/v1/ase/workflows/verdict/{task_id}")
            if res.get("verdict") or res.get("status") in ("COMPLETED", "FAILED"):
                return res
            time.sleep(interval)
            waited += interval
        return {"status": "TIMEOUT", "task_id": task_id}

    def get_insight_verdict(self, insight_id):
        """GET /v1/insights/{id}/verdict -> stored verdict for an insight."""
        return self._request("GET", f"/v1/insights/{insight_id}/verdict")


# --- CLI -------------------------------------------------------------------
def _print(obj):
    print(json.dumps(obj, indent=2)[:8000])


def main(argv=None):
    p = argparse.ArgumentParser(description="Abstract Security API client")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verify")
    f = sub.add_parser("fields"); f.add_argument("--grep"); f.add_argument("--limit", type=int, default=40)
    s = sub.add_parser("search"); s.add_argument("--hours", type=int, default=24); s.add_argument("--size", type=int, default=5)
    sub.add_parser("workflows")
    v = sub.add_parser("verdict"); v.add_argument("--insight", required=True)
    args = p.parse_args(argv)
    c = AbstractClient()

    if args.cmd == "verify":
        d = c.verify()
        org = (d.get("current_organization") or {}).get("name")
        print(f"OK  user={d.get('email')}  org={org}  permissions={len(d.get('permissions', []))}")
    elif args.cmd == "fields":
        rows = c.acs_fields()
        if args.grep:
            rows = [r for r in rows if args.grep.lower() in str(r.get("field", "")).lower()]
        print(f"{len(rows)} fields")
        for r in rows[: args.limit]:
            print(f"  {r['field']:<40} {r['data_type']}")
    elif args.cmd == "search":
        _print(c.search_events(hours=args.hours, size=args.size))
    elif args.cmd == "workflows":
        _print(c.list_workflows())
    elif args.cmd == "verdict":
        _print(c.run_verdict(args.insight))


if __name__ == "__main__":
    try:
        main()
    except AbstractError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
