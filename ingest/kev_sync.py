#!/usr/bin/env python3
"""Adopt new public KEV rows newer than the engagement watermark.

Reads advisory metadata only. Does not fetch exploit write-ups.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ROOT = Path(__file__).resolve().parents[1]
WATCH = ROOT / "data" / "watchlist.json"


def main() -> int:
    watermark = sys.argv[1] if len(sys.argv) > 1 else "2026-09-20"
    with urllib.request.urlopen(FEED, timeout=40) as resp:
        data = json.load(resp)
    rows = [
        {
            "cve": v.get("cveID"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "name": v.get("vulnerabilityName"),
            "added": v.get("dateAdded"),
            "due": v.get("dueDate"),
        }
        for v in data.get("vulnerabilities", [])
        if (v.get("dateAdded") or "") >= watermark
    ]
    WATCH.parent.mkdir(exist_ok=True)
    payload = {"watermark": watermark, "pending_analyst_review": rows[:40], "adopted": []}
    if WATCH.exists():
        payload["adopted"] = json.loads(WATCH.read_text()).get("adopted", [])
    WATCH.write_text(json.dumps(payload, indent=2))
    print(f"pending={len(rows)} watermark={watermark} wrote={WATCH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
