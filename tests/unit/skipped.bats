#!/usr/bin/env bats
# Ranges not scanned come in two kinds (issue #10, docs/design.md 10.26): left out by how the
# tool was run ("chosen", not counted in the exit status) and could not be scanned although the
# run set out to ("failed": exit status 2 when no finding makes it 1). The first two tests are
# the reproduction of the issue, moved here from the review's reproduction.

load test_helper

bats_require_minimum_version 1.5.0

setup() {
  load_libs
  setup_fakebin
  T="$BATS_TEST_TMPDIR/t"
  mkdir -p "$T"
  BCC_DEEP=0 BCC_PROJECTS=0 BCC_CONTAINERS=0 BCC_INSPECT_CONTAINERS=0 BCC_EXPOSURE=0
  BCC_DATA_LABEL=test BCC_UID=1000 BCC_ROOTS=(/opt)
}

teardown() {
  # Let bats remove what a test locked.
  chmod -R u+rwx "$T" 2>/dev/null || true
}

# The skipped ranges as "kind|scope" lines.
kinds() {
  local f
  for f in ${BCC_SKIPPED[@]+"${BCC_SKIPPED[@]}"}; do
    bcc_split_tab "$f"
    printf '%s|%s\n' "${BCC_F[2]}" "${BCC_F[0]}"
  done
}
# The text report as the tool prints it.
report() {
  bcc_summarize
  BCC_EXIT=$(bcc_exit_code)
  bcc_render_text
}
# The JSON report.
report_json() {
  bcc_summarize
  BCC_EXIT=$(bcc_exit_code)
  bcc_render_json
}
not_root() { [ "$(id -u)" -ne 0 ] || skip "root can read what is locked here"; }

@test "#10 only ranges left out by the options, not root and --exclude: exit 0, and the summary says none could not be scanned" {
  BCC_EXCLUDES=("$T/cache")
  bcc_note_disabled
  run kinds
  [[ $output == *"chosen|C09 --deep"* ]]
  [[ $output == *"chosen|C07 --projects"* ]]
  [[ $output == *"chosen|C14 --containers"* ]]
  [[ $output == *"chosen|C15 --exposure"* ]]
  [[ $output == *"chosen|$T/cache"* ]]
  [[ $output == *"chosen|root"* ]]
  [[ $output != *"failed|"* ]]
  [ "$(bcc_exit_code)" -eq 0 ]
  run report
  [[ $output == *"== Not scanned =="$'\n'"[SKIPPED] C09 --deep | "* ]]
  [[ $output != *"[FAILED]"* ]]
  [[ $output != *"== Could not be scanned =="* ]]
  [[ $output == *"Could not be scanned: none"$'\n'"Not scanned: C09 --deep, C07 --projects, C14 --containers, C15 --exposure, $T/cache, root"* ]]
  [[ $output == *"No known vulnerable component was found in the scanned ranges"* ]]
}

@test "#10 dpkg-query fails: C01 could not be scanned, exit 2, and the summary does not say nothing was found" {
  printf '#!/bin/sh\nexit 2\n' >"$FAKEBIN/dpkg-query"
  chmod +x "$FAKEBIN/dpkg-query"
  BCC_DEB_SERIES=ubuntu:noble
  bcc_check_c01
  [ "${#BCC_FINDINGS[@]}" -eq 0 ]
  [ "$(kinds)" = "failed|C01" ]
  [ "$(bcc_exit_code)" -eq 2 ]
  bcc_note_disabled
  run report
  [[ $output == *$'\n'"== Could not be scanned =="$'\n'"[FAILED] C01 | dpkg-query failed (status 2): the package database could not be read"$'\n\n'"== Not scanned =="$'\n'"[SKIPPED] C09 --deep | "* ]]
  [[ $output == *$'\n'"Needs update: 0"$'\n'"Needs restart: 0"$'\n'"Needs human review: 0"$'\n'"Could not be scanned: C01"$'\n'"Not scanned: C09 --deep, "* ]]
  [[ $output != *"No known vulnerable component"* ]]
  # The reasons are written in the language of the run.
  bcc_init_findings
  BCC_LANG=ja
  bcc_check_c01
  bcc_note_disabled
  run report
  [[ $output == *$'\n'"== 走査できなかった範囲 =="$'\n'"[FAILED] C01 | dpkg-query が失敗した（終了状態 2）。パッケージのデータベースを読めなかった"* ]]
  [[ $output == *$'\n'"人の確認が必要なもの: 0 件"$'\n'"走査できなかった範囲: C01"$'\n'"走査しなかった範囲: C09 --deep, "* ]]
  [[ $output != *"見つかりませんでした"* ]]
}

@test "#10 JSON: every skipped entry carries its kind, and the exit code counts the failed one" {
  bcc_skip chosen "C09 --deep" "$(bcc_msg skip_opt_deep)"
  bcc_skip failed C01 "$(bcc_msg skip_dpkg_failed 2)"
  run report_json
  [[ $output == *'"skipped":[{"scope":"C09 --deep","reason":"generic search of ELF files for bundled decoders (use --deep)","kind":"chosen"},{"scope":"C01","reason":"dpkg-query failed (status 2): the package database could not be read","kind":"failed"}]'* ]]
  [[ $output == *'"exit_code":2,'* ]]
}

@test "#10 a line that makes exit 1 keeps it next to a range that could not be scanned" {
  bcc_skip failed C01 "$(bcc_msg skip_dpkg_failed 2)"
  bcc_add_finding C06 VULNERABLE Brotli /opt/venv 1.2.0 r n "" ""
  [ "$(bcc_exit_code)" -eq 1 ]
  bcc_init_findings
  bcc_skip failed C01 "$(bcc_msg skip_dpkg_failed 2)"
  bcc_add_finding C06 UNKNOWN Brotli /opt/venv 1.2.1 r n "" ""
  [ "$(bcc_exit_code)" -eq 2 ]
}

@test "#10 a needed program that is missing: dpkg (not Debian/Ubuntu) and ss for --exposure could not be scanned" {
  bcc_have() { [[ $1 != dpkg-query && $1 != ss ]] && command -v -- "$1" >/dev/null 2>&1; }
  bcc_check_c01
  bcc_check_c15
  [ "$(kinds)" = "failed|C01"$'\n'"failed|C15" ]
  [[ ${BCC_SKIPPED[*]} == *"dpkg is not available (not Debian/Ubuntu)"* ]]
  [ "$(bcc_exit_code)" -eq 2 ]
}

@test "#10 commands that fail could not be scanned: dpkg-query for C02, snap list, flatpak list, ss" {
  for c in dpkg-query snap flatpak ss; do
    printf '#!/bin/sh\nexit 2\n' >"$FAKEBIN/$c"
    chmod +x "$FAKEBIN/$c"
  done
  bcc_check_c02
  bcc_check_c12
  bcc_check_c15
  # (The host's own flatpak runtimes may add lines of their own.)
  run kinds
  [[ $output == "failed|C02"$'\n'"failed|C12 snap"$'\n'"failed|C12 flatpak"$'\n'* ]]
  [[ $output == *$'\n'"failed|C15" ]]
}

@test "#10 a time limit, a file not read to the end and files over the size limit could not be scanned" {
  bcc_find_status 124 "C06 (search)"
  bcc_note_incomplete "$T/libbrotlidec.so.1.2.1"
  BCC_MAX_ELF_MB=1
  mkdir -p "$T/srv/bin"
  truncate -s 2M "$T/srv/bin/huge"
  chmod +x "$T/srv/bin/huge"
  BCC_ROOTS=("$T/srv")
  bcc_check_c09_deep
  [ "$(kinds)" = "failed|C06 (search)"$'\n'"failed|$T/libbrotlidec.so.1.2.1"$'\n'"failed|C09 --deep (size)" ]
}

@test "#10 what this user could not read is left out by not being root; what root could not read could not be scanned" {
  not_root
  BCC_IS_ROOT=0
  [ "$(bcc_denied_kind)" = chosen ]
  BCC_IS_ROOT=1
  [ "$(bcc_denied_kind)" = failed ]
  # A home, a search root, processes, directories under a root, files for --deep.
  mkdir -p "$T/home/bob" "$T/locked" "$T/proc/200" "$T/srv/closed" "$T/srv/lib"
  printf '7f00-7f01 r-xp 0 08:01 1 /usr/lib/x.so\n' >"$T/proc/200/maps"
  : >"$T/srv/lib/libx.so"
  chmod 000 "$T/home/bob" "$T/locked" "$T/proc/200/maps" "$T/srv/closed" "$T/srv/lib/libx.so"
  BCC_HOME_DIRS="$T/home/bob" BCC_PROC_ROOT="$T/proc" BCC_ROOTS_RAW="$T/locked"
  for root in 0 1; do
    bcc_init_findings
    BCC_IS_ROOT=$root
    bcc_init_homes
    BCC_ROOTS=("$T/locked")
    bcc_check_roots
    bcc_check_c03
    BCC_ROOTS=("$T/srv")
    bcc_find_each true "$T/srv" -- -name nothing
    bcc_find_status $? "C06 (search)"
    bcc_check_c09_deep
    kind=chosen
    ((root)) && kind=failed
    run kinds
    [ "$output" = "$kind|$T/home/bob"$'\n'"$kind|$T/locked"$'\n'"$kind|C03 $T/proc"$'\n'"$kind|C06 (search) (find)"$'\n'"$kind|C09 --deep (find)"$'\n'"$kind|C09 --deep (unreadable)" ]
  done
  # The words follow: root is not told to run as root.
  [[ ${BCC_SKIPPED[*]} == *"C03 $T/proc"$'\t'"processes that could not be read even as root: 1"$'\t'failed* ]]
  bcc_init_findings
  BCC_IS_ROOT=0
  bcc_check_c03
  [[ ${BCC_SKIPPED[*]} == *"C03 $T/proc"$'\t'"processes that could not be read: 1 (other users; run as root)"$'\t'chosen* ]]
}

@test "#10 directories find could not read for another reason than permission could not be scanned" {
  BCC_IS_ROOT=0
  BCC_FIND_ERRORS=2 BCC_FIND_DENIED=2 BCC_FIND_ERROR_EXAMPLE=/srv/a
  bcc_find_status 0 a
  BCC_FIND_ERRORS=2 BCC_FIND_DENIED=1
  bcc_find_status 0 b
  [ "$(kinds)" = "chosen|a (find)"$'\n'"failed|b (find)" ]
  # What find says is counted by kind.
  printf '#!/bin/sh\necho "find: '"'"'/srv/x'"'"': Permission denied" >&2\necho "find: '"'"'/srv/y'"'"': Input/output error" >&2\nexit 1\n' >"$FAKEBIN/find"
  chmod +x "$FAKEBIN/find"
  mkdir -p "$T/srv"
  bcc_find_each true "$T/srv" -- -name nothing
  [ "$BCC_FIND_ERRORS" -eq 2 ]
  [ "$BCC_FIND_DENIED" -eq 1 ]
}

@test "#10 other users' sockets are left out by not being root" {
  printf '#!/bin/sh\nprintf "LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*\\n"\n' >"$FAKEBIN/ss"
  chmod +x "$FAKEBIN/ss"
  BCC_IS_ROOT=0
  bcc_check_c15
  [ "$(kinds)" = "chosen|C15" ]
}

@test "#10 a place named on the command line that is not there could not be scanned; a missing default root is not listed" {
  BCC_ROOTS_RAW="$T/nope" BCC_ROOTS=("$T/nope")
  bcc_check_roots
  [ "$(kinds)" = "failed|$T/nope" ]
  [[ ${BCC_SKIPPED[*]} == *"$T/nope"$'\t'"does not exist"$'\t'failed* ]]
  bcc_init_findings
  BCC_ROOTS_RAW=$BCC_DEFAULT_ROOTS BCC_ROOTS=("$T/nope")
  bcc_check_roots
  [ "${#BCC_SKIPPED[@]}" -eq 0 ]
}

@test "#10 --envoy-config: a name that is not a file could not be scanned; a file this user may not read is left out by not being root" {
  BCC_C10_CANDS=() BCC_C10_DONE=1
  BCC_ENVOY_CONFIG="$T/nope.yaml"
  bcc_check_c10
  mkdir -p "$T/conf.d"
  BCC_ENVOY_CONFIG="$T/conf.d"
  bcc_check_c10
  run kinds
  [ "$output" = "failed|$T/nope.yaml"$'\n'"failed|$T/conf.d" ]
  [[ ${BCC_SKIPPED[*]} == *"$T/conf.d"$'\t'"not a regular file"$'\t'failed* ]]
  not_root
  bcc_init_findings
  printf 'x\n' >"$T/envoy.yaml"
  chmod 000 "$T/envoy.yaml"
  BCC_ENVOY_CONFIG="$T/envoy.yaml" BCC_IS_ROOT=0
  bcc_check_c10
  [ "$(kinds)" = "chosen|$T/envoy.yaml" ]
}

@test "#10 programs not run (--no-exec, or not chosen) are left out by choice" {
  make_fake_elf "$T/a/bun"
  bcc_plan_add "$T/a/bun" --version "C05 bun"
  BCC_NO_EXEC=1
  bcc_note_exec
  bcc_init_findings
  bcc_plan_add "$T/a/bun" --version "C05 bun"
  BCC_NO_EXEC=0
  bcc_note_exec
  [ "$(kinds)" = "chosen|exec" ]
  BCC_NO_EXEC=1
  bcc_note_exec
  [ "$(kinds)" = "chosen|exec"$'\n'"chosen|--no-exec" ]
}

@test "#10 a scope is listed once for each kind (first reason wins within a kind)" {
  bcc_skip chosen X a
  bcc_skip failed X b
  bcc_skip chosen X c
  bcc_skip failed X d
  [ "${#BCC_SKIPPED[@]}" -eq 2 ]
  [ "${BCC_SKIPPED[0]}" = "X"$'\t'"a"$'\t'"chosen" ]
  [ "${BCC_SKIPPED[1]}" = "X"$'\t'"b"$'\t'"failed" ]
  [ "$(bcc_count_skipped failed)" -eq 1 ]
}

@test "#10 a kind other than chosen or failed is an internal error" {
  run bcc_skip skipped X a
  [ "$status" -eq 3 ]
  [[ $output == *"internal error: unknown kind of skipped range 'skipped'"* ]]
  run bcc_skip X a
  [ "$status" -eq 3 ]
}

@test "#10 every call of bcc_skip in lib/ names its kind" {
  local calls bad
  calls=$(grep -h 'bcc_skip ' "$REPO_ROOT"/lib/*.sh | grep -Ev '^[[:space:]]*#')
  # (One line holds two calls.)
  [ "$(grep -o 'bcc_skip ' <<<"$calls" | wc -l)" -ge 46 ]
  # shellcheck disable=SC2016  # the pattern matches a literal "$(bcc_denied_kind)" and "$kind"
  bad=$(grep -o 'bcc_skip [^ ]*' <<<"$calls" | grep -Ev '^bcc_skip (chosen|failed|"\$\(bcc_denied_kind\)"|"\$kind")$' || true)
  [ -z "$bad" ] || { printf 'calls without a kind:\n%s\n' "$bad"; return 1; }
}

@test "#10 --help: exit status 2 includes a range that could not be scanned (en, ja)" {
  run "$REPO_ROOT/bin/brotli-cve-check" --help
  [ "$status" -eq 0 ]
  [[ $output == *"0 does not mean everything was looked at"* ]]
  [[ $output == *"LIKELY_*, UNKNOWN) or a range could not be scanned"* ]]
  [[ $output == *'read "skipped" (with its "kind") and "options" in --json too.'* ]]
  run "$REPO_ROOT/bin/brotli-cve-check" --lang ja --help
  [ "$status" -eq 0 ]
  [[ $output == *"全部を見たという意味"* ]]
  [[ $output == *"LIKELY_*・UNKNOWN）か、"$'\n'"走査できなかった範囲がある"* ]]
  [[ $output == *"--json の skipped（kind も）と options もあわせて見る。"* ]]
}
