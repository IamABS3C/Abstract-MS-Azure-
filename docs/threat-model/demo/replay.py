"""
Batch replay — author the scenarios as `action: batch` detection rules (which
evaluate HISTORICAL data) and trigger the engine to run them, generating findings
+ grouped insights from the tenant's real events.

  python3 replay.py            # (re)create [ABS-DEMO] rules as batch + enabled
  python3 replay.py --fire     # ALSO trigger refresh (engine evaluates them) + monitor
  python3 replay.py --cleanup  # remove [ABS-DEMO] rules

⚠️  --fire calls POST /v1/rules/refresh-rules {"type":"cep"}, which refreshes ALL
   conditional (cep) rules in the tenant — not only ours. Existing rules are realtime
   so they won't backfill; only the new batch rules evaluate history. Kill switches:
   `python3 replay.py --cleanup` and `python3 generate_insights.py --cleanup`.
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


def main():
    c = AbstractClient("api")
    print("connect:", c.connect().get("scheme"))

    # always start clean for [ABS-DEMO] rules
    removed = 0
    for r in B._list_rules_stable(c):
        if S.MARKER in (r.get("name") or "") and r.get("nanoid"):
            c._req("DELETE", f"/v1/rules/{r['nanoid']}"); removed += 1
    print("removed prior demo rules:", removed)
    if "--cleanup" in sys.argv:
        return

    print("creating batch rules (historical evaluation), enabled:")
    made, failed = B.build_rules(c, action="batch", enabled=True)
    print(f"  {len(made)} batch rules created (failed {len(failed)})")

    if "--fire" not in sys.argv:
        print("\nNOT fired. To trigger evaluation (refreshes ALL cep rules tenant-wide):")
        print("  python3 replay.py --fire")
        return

    before = insights_total(c)
    print(f"\ninsights before: {before}")
    print("firing refresh-rules (trying known param shapes for type=cep) …")
    fired = False
    for path, body in [("/v1/rules/refresh-rules", {"category": "cep"}),
                       ("/v1/rules/refresh-rules", {"engine": "cep"}),
                       ("/v1/rules/refresh-rules?category=cep", {}),
                       ("/v1/rules/refresh-rules", {"type": "cep"})]:
        r = c._req("POST", path, body)
        if r.get("status") not in (400, 404, 422):
            print("  fired via", path, body, "->", r.get("status")); fired = True; break
    if not fired:
        # The exact refresh param wasn't discoverable via the API; the rules are batch +
        # enabled and run on the engine's batch cycle. To force it, capture the UI's
        # refresh-rules request (browser network tab) — same way the rule-create body was found.
        print("  refresh param not discovered — batch rules will run on the engine's batch cycle.")
        print("  guaranteed real-data path meanwhile: python3 generate_insights.py")
        return
    for i in range(6):
        time.sleep(20)
        print(f"  +{(i+1)*20}s insights={insights_total(c)}")
    print("done. kill: python3 replay.py --cleanup ; python3 generate_insights.py --cleanup")


if __name__ == "__main__":
    main()
