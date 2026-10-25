#!/usr/bin/env bats
# Whole-program behaviour: options, output formats, exit codes, read-only guarantee.

load test_helper

BIN="$REPO_ROOT/bin/brotli-cve-check"

setup() {
  T="$BATS_TEST_TMPDIR/tree"
  mkdir -p "$T/srv" "$T/proc"
  printf 'btime 1761400000\n' >"$T/proc/stat"
  printf 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu 24.04 LTS"\n' >"$T/os-release"
  # A small, fully controlled host: no homes, fake /proc, one root.
  export BCC_PROC_ROOT="$T/proc" BCC_OS_RELEASE="$T/os-release" BCC_HOME_DIRS="$T/nohome" BCC_MOUNTINFO=/dev/null
  ARGS=(--roots "$T/srv" --no-exec --timeout 30)
}

@test "--help and --version exit 0" {
  run "$BIN" --help
  [ "$status" -eq 0 ]
  [[ $output == *"--inspect-containers"* ]]
  run "$BIN" --version
  [ "$status" -eq 0 ]
  [[ $output == "brotli-cve-check "* ]]
}

@test "an unknown option is an error of the tool (exit 3)" {
  run "$BIN" --deeep
  [ "$status" -eq 3 ]
  [[ $output == *"unknown option: --deeep"* ]]
}

@test "bad values are rejected, not guessed" {
  run "$BIN" --lang fr
  [ "$status" -eq 3 ]
  run "$BIN" --timeout 0
  [ "$status" -eq 3 ]
  run "$BIN" --roots relative/path
  [ "$status" -eq 3 ]
  run "$BIN" --output
  [ "$status" -eq 3 ]
}

@test "--output never overwrites an existing file" {
  : >"$T/existing"
  run "$BIN" "${ARGS[@]}" --output "$T/existing"
  [ "$status" -eq 3 ]
  [ ! -s "$T/existing" ]
}

@test "--output writes the same report as stdout" {
  run "$BIN" "${ARGS[@]}" --json --output "$T/out.json"
  [ -s "$T/out.json" ]
  [ "$output" = "$(cat "$T/out.json")" ]
}

@test "JSON output parses and carries the documented fields" {
  command -v python3 >/dev/null || skip "python3 not available to parse JSON"
  run "$BIN" "${ARGS[@]}" --json
  printf '%s' "$output" >"$T/out.json"
  python3 -I - "$T/out.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
for k in ("tool_version", "data_snapshot_date", "host", "scanned_roots", "skipped", "findings", "summary", "exit_code"):
    assert k in d, k
assert d["host"]["package_series"] == "ubuntu:noble"
assert set(d["summary"]) >= {"needs_update", "needs_restart", "needs_review", "by_status"}
assert any(s["scope"] == "C09 --deep" for s in d["skipped"])
EOF
}

@test "text output ends with the four-line summary and the intrusion disclaimer" {
  run "$BIN" "${ARGS[@]}"
  [[ $output == *"Needs update:"* ]]
  [[ $output == *"Needs restart:"* ]]
  [[ $output == *"Needs human review:"* ]]
  [[ $output == *"Not scanned:"* ]]
  [[ ${lines[${#lines[@]} - 1]} == "This tool does not check for intrusion."* ]]
}

@test "the word SAFE never appears; the best result names the unscanned ranges" {
  run "$BIN" "${ARGS[@]}" --data "$REPO_ROOT/data/advisories.tsv"
  [[ $output != *SAFE* ]]
  if [ "$status" -eq 0 ]; then
    [[ $output == *"No known vulnerable component was found in the scanned ranges"* ]]
  fi
}

@test "--lang ja prints Japanese" {
  run "$BIN" "${ARGS[@]}" --lang ja
  [[ $output == *"このツールは侵入の有無を調べません。"* ]]
  [[ $output == *"更新が必要なもの:"* ]]
}

@test "exit 1 when something is VULNERABLE" {
  mkdir -p "$T/srv/venv/lib/python3.12/site-packages/Brotli-1.2.0.dist-info"
  printf 'Name: Brotli\nVersion: 1.2.0\n' >"$T/srv/venv/lib/python3.12/site-packages/Brotli-1.2.0.dist-info/METADATA"
  run "$BIN" "${ARGS[@]}"
  [ "$status" -eq 1 ]
  [[ $output == *"[VULNERABLE] C06 | Brotli |"* ]]
}

@test "control characters in a path are shown as ? in the text report" {
  d="$T/srv/x"$'\033'"[31mred"
  mkdir -p "$d/Brotli-1.2.0.dist-info"
  printf 'Name: Brotli\nVersion: 1.2.0\n' >"$d/Brotli-1.2.0.dist-info/METADATA"
  run "$BIN" "${ARGS[@]}"
  [[ $output != *$'\033'* ]]
  [[ $output == *"x?[31mred"* ]]
}

@test "stale data (30 days or more) is warned about" {
  BCC_TODAY=2026-12-15 run "$BIN" "${ARGS[@]}"
  [[ $output == *"WARNING: the advisory data is 50 days old"* ]]
}

@test "the scan is read-only: nothing under the roots changes" {
  mkdir -p "$T/srv/venv/lib/python3.12/site-packages/Brotli-1.2.0.dist-info" "$T/srv/app/node_modules/axios"
  printf 'Name: Brotli\nVersion: 1.2.0\n' >"$T/srv/venv/lib/python3.12/site-packages/Brotli-1.2.0.dist-info/METADATA"
  printf '{"version": "1.7.9"}\n' >"$T/srv/app/node_modules/axios/package.json"
  before=$(find "$T/srv" -printf '%p %s %T@ %m\n' | sort)
  run "$BIN" --roots "$T/srv" --deep --projects --timeout 30
  after=$(find "$T/srv" -printf '%p %s %T@ %m\n' | sort)
  [ "$before" = "$after" ]
}

@test "a root named with --roots that does not exist is listed as not scanned" {
  run "$BIN" --roots "$T/srv,$T/nope" --no-exec
  [[ $output == *"[SKIPPED] $T/nope | does not exist"* ]]
}
