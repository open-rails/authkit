#!/usr/bin/env python3
"""Reject missing, duplicate, skipped or failed named critical journeys."""
import json
from pathlib import Path
import re
import sys

expected = json.loads(Path("critical/scenarios.json").read_text())
events = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.startswith("{")]
bad = [e for e in events if e.get("Action") in {"fail", "build-fail", "skip"}]
if bad:
    raise SystemExit(f"Unqualified critical suite: {bad}")
observed = {}
for event in events:
    if event.get("Action") != "pass":
        continue
    # Only the independently named scenario, not a successful nested branch.
    match = re.fullmatch(r"[^/]+/(AK-J\d+-C\d+)_[^/]+", event.get("Test", ""))
    if match:
        scenario = match[1]
        if scenario in observed:
            raise SystemExit(f"Duplicate scenario pass: {scenario}")
        observed[scenario] = event["Test"]
missing, unexpected = set(expected) - observed.keys(), observed.keys() - set(expected)
if missing or unexpected:
    raise SystemExit(f"Missing scenarios: {sorted(missing)}; unexpected: {sorted(unexpected)}")
print(f"Qualified {len(observed)} named Go critical scenarios; zero skips. Browser/TS qualification is separate.")
