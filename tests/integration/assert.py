"""Check a brotli-cve-check JSON report against expectations.

Usage: python3 -I assert.py REPORT.json EXPECTATION...
       python3 -I assert.py --summary REPORT.json
--summary prints what decides the exit status: the counts by status and the "Not scanned"
entries of kind "failed" (run.sh shows it when an exit status is not the expected one).
EXPECTATION is one of:
  "ID|TEXT|STATUS"   some finding with that ID whose component or path contains TEXT must have
                     STATUS; with STATUS "-", no such finding may exist
  "info:ID|TEXT"     some information line with that ID must contain TEXT
  "skipped:SCOPE|TEXT"  some "Not scanned" entry with that scope must have a reason containing TEXT
  "skipped:SCOPE|TEXT|KIND"  ... and that entry's kind must be KIND ("chosen" or "failed")
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
        scope, text, *kind = spec[len("skipped:"):].split("|", 2)
        entries = [s for s in report["skipped"] if s["scope"] == scope]
        if any(text in s["reason"] and (not kind or s["kind"] == kind[0]) for s in entries):
            return ""
        got = [f"{s['kind']}: {s['reason']}" if kind else s["reason"] for s in entries]
        return f"got {got or ['no entry']}"
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


def summary(report: dict) -> list:
    """The lines of --summary."""
    counts = [f"{k} {v}" for k, v in report["summary"]["by_status"].items() if v]
    failed = [f"{s['scope']}: {s['reason']}" for s in report["skipped"] if s["kind"] == "failed"]
    lines = [f"exit_code {report['exit_code']}; {', '.join(counts) or 'no findings'}"]
    return lines + ([f"failed {f}" for f in failed] or ["failed: none"])


def main() -> int:
    if sys.argv[1] == "--summary":
        for line in summary(json.load(open(sys.argv[2], encoding="utf-8"))):
            print("     report:", line)
        return 0
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
