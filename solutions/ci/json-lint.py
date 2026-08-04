#!/usr/bin/env python3
"""
Parse every JSON file in the repo, tolerating // line comments.

Lives as a file rather than inline in the workflow because an inline heredoc inside
a YAML block scalar is fragile: any line that dedents to column 0 silently breaks
the whole workflow file.

ARM parameter files legitimately carry // comments (the portal and az CLI both
accept them), so a naive json.load would report false failures on files that are
perfectly valid.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SKIP_PARTS = {".git", ".venv", "node_modules", "__pycache__", ".ipynb_checkpoints"}


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    failures: list[tuple[Path, str]] = []
    checked = 0

    for path in sorted(root.rglob("*.json")):
        if SKIP_PARTS & set(path.parts):
            continue
        checked += 1
        try:
            raw = path.read_text(encoding="utf-8")
            json.loads(re.sub(r"^\s*//.*$", "", raw, flags=re.M))
            print(f"ok   : {path.relative_to(root)}")
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"FAIL : {path.relative_to(root)}: {e}")
            failures.append((path, str(e)))

    print(f"\n{checked} JSON file(s) checked, {len(failures)} failure(s)")
    if failures:
        print("\n::error::Invalid JSON committed:")
        for path, msg in failures:
            print(f"  {path.relative_to(root)}: {msg}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
