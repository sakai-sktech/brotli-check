#!/usr/bin/env bats
# Whole-program behaviour: options, output formats, exit codes, read-only guarantee.

load test_helper

bats_require_minimum_version 1.5.0

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

@test "--output refuses a dangling symlink (it would be followed)" {
  ln -s "$T/somewhere-else" "$T/out.txt"
  run "$BIN" "${ARGS[@]}" --output "$T/out.txt"
  [ "$status" -eq 3 ]
  [ ! -e "$T/somewhere-else" ]
}

@test "--output refuses a directory others can modify without the sticky bit" {
  mkdir -p "$T/open"
  chmod 777 "$T/open"
  run "$BIN" "${ARGS[@]}" --output "$T/open/out.txt"
  [ "$status" -eq 3 ]
  [ ! -e "$T/open/out.txt" ]
}

@test "--output through a symlinked directory writes into the resolved directory" {
  mkdir -p "$T/real"
  ln -s "$T/real" "$T/link"
  run "$BIN" "${ARGS[@]}" --output "$T/link/r.txt"
  [ -s "$T/real/r.txt" ]
}

@test "--output leaves exactly one new file (no temporary file behind)" {
  mkdir -p "$T/o"
  run "$BIN" "${ARGS[@]}" --output "$T/o/report.txt"
  [ -s "$T/o/report.txt" ]
  [ "$(find "$T/o" -mindepth 1 | wc -l)" -eq 1 ]
}

@test "--output writes the same report as stdout" {
  run --separate-stderr "$BIN" "${ARGS[@]}" --json --output "$T/out.json"
  [ -s "$T/out.json" ]
  [ "$output" = "$(cat "$T/out.json")" ]
}

@test "a scan prints nothing on stderr (no stray tool errors on the terminal)" {
  run --separate-stderr "$BIN" "${ARGS[@]}" --json
  [ -z "$stderr" ] || { printf 'stderr was:\n%s\n' "$stderr"; return 1; }
}

@test "JSON output parses and carries the documented fields" {
  command -v python3 >/dev/null || skip "python3 not available to parse JSON"
  run --separate-stderr "$BIN" "${ARGS[@]}" --json
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
  run "$BIN" --roots "$T/srv" --deep --projects --timeout 30 --no-exec
  after=$(find "$T/srv" -printf '%p %s %T@ %m\n' | sort)
  [ "$before" = "$after" ]
}

@test "system tools never come from the caller's PATH (a planted stat or timeout is not run)" {
  mkdir -p "$T/evil"
  for t in stat timeout grep od readelf; do
    printf '#!/bin/sh\n: >"%s/ran-%s"\nexit 1\n' "$T" "$t" >"$T/evil/$t"
    chmod +x "$T/evil/$t"
  done
  PATH="$T/evil:$PATH" run "$BIN" "${ARGS[@]}"
  [ "$status" -ne 3 ]
  [ -z "$(find "$T" -maxdepth 1 -name 'ran-*')" ]
}

@test "a root named with --roots that does not exist is listed as not scanned" {
  run "$BIN" --roots "$T/srv,$T/nope" --no-exec
  [[ $output == *"[SKIPPED] $T/nope | does not exist"* ]]
}

@test "--data: a FIFO is refused at once (never opened); others' write access is warned about" {
  mkfifo "$T/fifo.tsv"
  SECONDS=0
  run timeout 30 "$BIN" "${ARGS[@]}" --data "$T/fifo.tsv"
  [ "$status" -eq 3 ]
  ((SECONDS < 20))
  cp "$REPO_ROOT/data/advisories.tsv" "$T/data.tsv"
  chmod 644 "$T/data.tsv"
  run "$BIN" "${ARGS[@]}" --data "$T/data.tsv"
  [[ $output != *"can change the advisory data"* ]]
  chmod 666 "$T/data.tsv"
  run "$BIN" "${ARGS[@]}" --data "$T/data.tsv"
  [[ $output == *"WARNING: users other than root (or you) can change the advisory data $T/data.tsv"* ]]
  command -v python3 >/dev/null || return 0
  run --separate-stderr "$BIN" "${ARGS[@]}" --data "$T/data.tsv" --json
  printf '%s' "$output" | python3 -I -c 'import json,sys; assert json.load(sys.stdin)["data_writable_by_others"] is True'
}

@test "consent: with programs to run and no terminal, the tool lists them and asks for --yes or --no-exec" {
  mkdir -p "$T/srv/tools/bin"
  printf '\177ELF\002\001\001\000' >"$T/srv/tools/bin/bun"
  chmod +x "$T/srv/tools/bin/bun"
  run "$BIN" --roots "$T/srv" --timeout 30 </dev/null
  [ "$status" -eq 3 ]
  [[ $output == *"$T/srv/tools/bin/bun --version"* ]]
  [[ $output == *"--yes (run them) or --no-exec"* ]]
  run "$BIN" --roots "$T/srv" --timeout 30 --no-exec </dev/null
  [ "$status" -ne 3 ]
  [[ $output == *"[NOT RUN] $T/srv/tools/bin/bun --version (--no-exec)"* ]]
}

@test "consent: --yes runs the listed programs and the report says what ran (JSON too)" {
  command -v cc >/dev/null || skip "no C compiler"
  mkdir -p "$T/srv/tools/bin"
  printf '#include <stdio.h>\nint main(void){puts("1.4.4");return 0;}\n' >"$T/stub.c"
  cc -o "$T/srv/tools/bin/bun" "$T/stub.c"
  run "$BIN" --roots "$T/srv" --timeout 30 --yes </dev/null
  [[ $output == *"[RUN] $T/srv/tools/bin/bun --version -> 1.4.4 (exit status 0)"* ]]
  [[ $output == *"[FIXED] C05 | bun | $T/srv/tools/bin/bun | 1.4.4"* ]]
  command -v python3 >/dev/null || return 0
  run --separate-stderr "$BIN" --roots "$T/srv" --timeout 30 --yes --json </dev/null
  printf '%s' "$output" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
e = [x for x in d["execution"] if x["path"].endswith("/srv/tools/bin/bun")]
assert e and e[0]["ran"] is True and e[0]["output"].strip() == "1.4.4" and e[0]["facts"], e'
}

@test "consent: at a terminal the user chooses by number" {
  command -v script >/dev/null || skip "script (util-linux) is needed for a terminal"
  command -v cc >/dev/null || skip "no C compiler"
  mkdir -p "$T/srv/a/bin" "$T/srv/b/bin"
  printf '#include <stdio.h>\nint main(void){puts("1.4.4");return 0;}\n' >"$T/stub.c"
  cc -o "$T/srv/a/bin/bun" "$T/stub.c"
  cp "$T/srv/a/bin/bun" "$T/srv/b/bin/bun"
  # The host's own programs are listed too: find b's number first (no terminal: list, stop).
  run "$BIN" --roots "$T/srv" --timeout 30 </dev/null
  n=$(sed -n 's|^ *\([0-9]*\)\. '"$T"'/srv/b/bin/bun --version.*|\1|p' <<<"$output")
  [ -n "$n" ]
  printf '%s\n' "$n" | script -qec "$BIN --roots $T/srv --timeout 30 --lang en" /dev/null >"$T/out.txt" 2>&1 || true
  grep -q "Run them?" "$T/out.txt"
  grep -q "\[RUN\] $T/srv/b/bin/bun --version" "$T/out.txt"
  grep -q "\[NOT RUN\] $T/srv/a/bin/bun --version (not chosen)" "$T/out.txt"
}

@test "a found path with control characters, a newline and a tab: shown as ?, and what runs is what was listed" {
  command -v cc >/dev/null || skip "no C compiler"
  p="$T/srv/x"$'\033'"[2J"$'\n'"y"
  mkdir -p "$p"$'\t'"z/bin"
  printf '#include <stdio.h>\nint main(void){puts("1.4.4");return 0;}\n' >"$T/stub.c"
  cc -o "$p"$'\t'"z/bin/bun" "$T/stub.c"
  # What splitting the entry at the tab would have run instead.
  printf '#!/bin/sh\necho 9.9.9\n' >"$p"
  chmod +x "$p"
  shown="$T/srv/x?[2J?y?z/bin/bun"
  run --separate-stderr "$BIN" --roots "$T/srv" --timeout 30 </dev/null
  [ "$status" -eq 3 ]
  [[ $stderr != *$'\033'* ]]
  [[ $stderr == *". $shown --version  (C05 bun)"* ]]
  run --separate-stderr "$BIN" --roots "$T/srv" --timeout 30 --yes </dev/null
  [[ $output != *$'\033'* ]]
  [[ $output == *"[RUN] $shown --version -> 1.4.4 (exit status 0)"* ]]
  [[ $output == *"[FIXED] C05 | bun | $shown | 1.4.4"* ]]
}
