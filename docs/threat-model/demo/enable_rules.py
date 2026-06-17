"""
Enable + apply all [ABS-DEMO] detection rules so they evaluate the live stream and
generate findings/insights. Rules group by rule.id, so expect ~1 grouped insight
per firing rule (not thousands). Monitors the insight count after enabling.

  python3 enable_rules.py            # enable all + refresh + monitor
  python3 enable_rules.py --disable  # turn them all back off (kill switch)
"""
from __future__ import annotations

import json
import sys
import time

from abstract_client import AbstractClient
import build_demo as B
import scenarios as S


def insights_total(c):
    b = c._req("GET", "/v1/insights/?page_size=1").get("body", {}) or {}
    return (b.get("metadata") or {}).get("total_count")


def set_enabled(c, on: bool):
    rules = [r for r in B._list_rules_stable(c) if S.MARKER in (r.get("name") or "")]
    ok = 0
    for r in rules:
        body = {"name": r["name"], "is_enabled": on, "state": "production"}
        rr = c._req("PATCH", f"/v1/rules/{r['nanoid']}", body)
        if rr.get("ok"):
            ok += 1
        else:
            print(f"  PATCH {r['nanoid']} -> {rr.get('status')} {(rr.get('error') or '')[:120]}")
    return ok, len(rules)


def refresh(c):
    for path in ("/v1/rules/refresh-rules", "/v1/rules/refresh-rules/"):
        r = c._req("POST", path, {})
        if r.get("status") != 307:
            return r.get("status")
    return r.get("status")


def main():
    c = AbstractClient("api")
    print("connect:", c.connect().get("scheme"))
    if "--disable" in sys.argv:
        ok, n = set_enabled(c, False)
        print(f"disabled {ok}/{n}; refresh {refresh(c)}")
        return
    before = insights_total(c)
    ok, n = set_enabled(c, True)
    print(f"enabled {ok}/{n} rules | refresh status {refresh(c)} | insights before={before}")
    for i in range(8):
        time.sleep(20)
        print(f"  +{(i+1)*20}s  insights={insights_total(c)}")
    print("done — disable any time with: python3 enable_rules.py --disable")


if __name__ == "__main__":
    main()
