"""Check a brotli-cve-check JSON report against expectations.

Usage: python3 -I assert.py REPORT.json EXPECTATION...
EXPECTATION is "ID|TEXT|STATUS": some finding with that ID whose component or path
contains TEXT must have STATUS. Exit status 1 lists every unmet expectation.
"""
import json
import sys


def main() -> int:
    report = json.load(open(sys.argv[1], encoding="utf-8"))
    failures = []
    for spec in sys.argv[2:]:
        check_id, text, status = spec.split("|")
        matches = [
            f for f in report["findings"]
            if f["id"] == check_id and (text in f["path"] or text == f["component"])
        ]
        if not any(f["status"] == status for f in matches):
            got = sorted({f["status"] for f in matches}) or ["no finding"]
            failures.append(f"{spec}: got {', '.join(got)}")
    for line in failures:
        print("FAIL", line)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
