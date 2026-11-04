"""Check a brotli-cve-check JSON report against expectations.

Usage: python3 -I assert.py REPORT.json EXPECTATION...
EXPECTATION is one of:
  "ID|TEXT|STATUS"   some finding with that ID whose component or path contains TEXT must have
                     STATUS; with STATUS "-", no such finding may exist
  "info:ID|TEXT"     some information line with that ID must contain TEXT
  "skipped:SCOPE|TEXT"  some "Not scanned" entry with that scope must have a reason containing TEXT
Exit status 1 lists every unmet expectation.
"""
import json
import sys


def check(report: dict, spec: str) -> str:
    """Return "" when SPEC holds, otherwise what was found instead."""
    if spec.startswith("info:"):
        check_id, text = spec[len("info:"):].split("|", 1)
        lines = [i["text"] for i in report["info"] if i["id"] == check_id]
        return "" if any(text in t for t in lines) else f"got {lines or ['no information']}"
    if spec.startswith("skipped:"):
        scope, text = spec[len("skipped:"):].split("|", 1)
        reasons = [s["reason"] for s in report["skipped"] if s["scope"] == scope]
        return "" if any(text in r for r in reasons) else f"got {reasons or ['no entry']}"
    check_id, text, status = spec.split("|")
    matches = [
        f for f in report["findings"]
        if f["id"] == check_id and (text in f["path"] or text == f["component"])
    ]
    if status == "-":
        return "" if not matches else f"got {sorted({f['status'] for f in matches})}"
    if any(f["status"] == status for f in matches):
        return ""
    got = sorted({f["status"] for f in matches}) or ["no finding"]
    return f"got {', '.join(got)}"


def main() -> int:
    report = json.load(open(sys.argv[1], encoding="utf-8"))
    failures = []
    for spec in sys.argv[2:]:
        got = check(report, spec)
        if got:
            failures.append(f"{spec}: {got}")
    for line in failures:
        print("FAIL", line)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
