#!/usr/bin/env bats
# Regressions for the Codex adversarial review, round 4 (2026-10-26): execution of found
# programs, trusted tools, --output, dpkg ownership, decoder markers, pre-releases, bounded
# reads, failures and excluded ranges in "Not scanned", container Node.js discovery.
# shellcheck disable=SC2317  # stand-ins for library functions are called by the code under test

load test_helper

setup() {
  load_libs
  setup_fakebin
  T="$BATS_TEST_TMPDIR/tree"
  mkdir -p "$T"
}

# A directory under the repository (owned by the test user, not world-writable like /tmp).
safe_dir() {
  SAFE="$REPO_ROOT/tests/tmp/$BATS_TEST_NUMBER-$$"
  mkdir -p "$SAFE"
  chmod 755 "$REPO_ROOT/tests/tmp" "$SAFE"
}

# Is FACT, exactly, among BCC_FACTS? (Facts may hold newlines.)
has_fact() {
  local f
  for f in ${BCC_FACTS[@]+"${BCC_FACTS[@]}"}; do [[ $f == "$1" ]] && return 0; done
  return 1
}

# The dependency-walk records of FILE, one "kind<TAB>a<TAB>b" line each (for assertions).
walk_records() {
  local s c i
  read -r s c <<<"${BCC_DEPWALK_CACHE[$1]}"
  for ((i = s; i < s + c; i++)); do
    printf '%s\t%s\t%s\n' "${BCC_WALK_K[i]}" "${BCC_WALK_A[i]}" "${BCC_WALK_B[i]}"
  done
}

# --- 1: as root, found programs are not run by default; loaded code is checked too -------

@test "consent: --no-exec runs nothing, --yes runs everything listed (as root too)" {
  make_fake_elf "$T/a/bun"
  make_fake_elf "$T/b/bun"
  BCC_IS_ROOT=1
  bcc_plan_add "$T/a/bun" --version "C05 bun"
  bcc_plan_add "$T/b/bun" --version "C05 bun"
  BCC_NO_EXEC=1
  bcc_exec_consent
  [ "${#BCC_PLAN_OK[@]}" -eq 0 ]
  BCC_NO_EXEC=0 BCC_YES=1
  bcc_exec_consent
  [ "${#BCC_PLAN_OK[@]}" -eq 2 ]
}

@test "consent: without a terminal and without --yes or --no-exec, the tool lists and stops" {
  make_fake_elf "$T/a/bun"
  bcc_plan_add "$T/a/bun" --version "C05 bun"
  run bcc_exec_consent </dev/null
  [ "$status" -eq 3 ]
  [[ $output == *"$T/a/bun --version"* ]]
  [[ $output == *"--yes (run them) or --no-exec"* ]]
  # Nothing to run: nothing to ask.
  BCC_PLAN=()
  run bcc_exec_consent </dev/null
  [ "$status" -eq 0 ]
}

@test "consent: --no-exec and --yes together are an error; answers are parsed strictly" {
  run bcc_parse_args --no-exec --yes
  [ "$status" -eq 3 ]
  [[ $output == *"cannot be used together"* ]]
  [ "$(bcc_parse_choice "1,3" 3 | paste -sd, -)" = 1,3 ]
  [ "$(bcc_parse_choice "2-3" 3 | paste -sd, -)" = 2,3 ]
  [ "$(bcc_parse_choice "Y" 2 | paste -sd, -)" = 1,2 ]
  [ -z "$(bcc_parse_choice "" 2)" ]
  [ -z "$(bcc_parse_choice "n" 2)" ]
  run bcc_parse_choice "4" 3
  [ "$status" -eq 1 ]
  run bcc_parse_choice "1;rm" 3
  [ "$status" -eq 1 ]
}

@test "facts: a RUNPATH directory others can write is named before asking" {
  command -v cc >/dev/null || skip "no C compiler"
  command -v readelf >/dev/null || skip "readelf not available"
  mkdir -p "$T/bin" "$T/open"
  chmod 777 "$T/open"
  printf '#include <stdio.h>\nint main(void){puts("v24.22.1");return 0;}\n' >"$T/stub.c"
  cc -Wl,-rpath,"$T/open" -o "$T/bin/rpath" "$T/stub.c"
  bcc_ldcache_load
  bcc_exec_facts "$T/bin/rpath"
  [[ " ${BCC_FACTS[*]} " == *"$T/open can be written by anyone"* ]]
}

@test "facts: without readelf the facts say the libraries were not examined" {
  make_fake_elf "$T/prog"
  bcc_have() { [[ $1 != readelf ]] && command -v -- "$1" >/dev/null 2>&1; }
  bcc_exec_facts "$T/prog"
  [[ " ${BCC_FACTS[*]} " == *"the libraries it loads were not examined"* ]]
}

# --- 2: system tools never come from the caller's PATH -----------------------------------

@test "trusted tools: PATH is fixed to system directories; the caller's PATH is only searched" {
  printf '#!/bin/sh\necho fake\n' >"$FAKEBIN/readelf"
  chmod +x "$FAKEBIN/readelf"
  local before=$PATH
  bcc_init_path
  [[ $PATH == /usr/sbin:/usr/bin:/sbin:/bin* ]]
  [[ $PATH != *"$FAKEBIN"* ]]
  [ "$BCC_USER_PATH" = "$before" ]
  run bcc_path_dirs
  [[ $output == *"$FAKEBIN"* ]]
}

# --- 3: --output never links into a directory planted at the name ------------------------

@test "--output: a directory planted at the name makes the write fail; nothing lands inside" {
  mkdir -p "$T/out" "$T/out/report.txt"
  run bcc_write_output "$T/out" report.txt "the report"
  [ "$status" -eq 1 ]
  [ -z "$(ls -A "$T/out/report.txt")" ]
  [ "$(find "$T/out" -mindepth 1 -maxdepth 1 | wc -l)" -eq 1 ] # no temporary file left
}

# --- 4: only packages that C01 judged are left to C01 -----------------------------------

@test "dpkg: a libbrotlidec owned by a vendor's package is judged, one owned by libbrotli1 is not" {
  # bcc_dpkg_owner never asks about /tmp; stand in for dpkg here.
  bcc_dpkg_owner() {
    case $1 in
      */vendor/*) echo vendor-agent ;;
      */system/*) echo libbrotli1:amd64 ;;
      *) return 1 ;;
    esac
  }
  BCC_C01_JUDGED[libbrotli1]=1
  for d in vendor system; do
    mkdir -p "$T/$d/lib"
    tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$T/$d/lib/libbrotlidec.so.1.2.0"
  done
  BCC_IDX_LIB=("$T/vendor/lib/libbrotlidec.so.1.2.0" "$T/system/lib/libbrotlidec.so.1.2.0")
  bcc_check_c09_libs
  run findings_brief
  [[ $output == *"VULNERABLE|C09|libbrotlidec (shared)|$T/vendor/lib/libbrotlidec.so.1.2.0|1.2.0"* ]]
  [[ $output != *"$T/system/"* ]]
  [ -n "${BCC_JUDGED[$T/system/lib/libbrotlidec.so.1.2.0]:-}" ] # so --deep skips it too
}

@test "dpkg: Brotli in a vendor's packaged Python is judged by its version, with the package named" {
  bcc_dpkg_owner() { case $1 in */embedded/*) echo vendor-agent ;; *) return 1 ;; esac; }
  site="$T/opt/vendor/embedded/lib/python3.12/site-packages"
  mkdir -p "$site/Brotli-1.1.0.dist-info"
  printf 'Name: Brotli\nVersion: 1.1.0\n' >"$site/Brotli-1.1.0.dist-info/METADATA"
  BCC_IDX_PY=("$site/Brotli-1.1.0.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"VULNERABLE|C06|Brotli|$site/Brotli-1.1.0.dist-info|1.1.0"* ]]
  [[ ${BCC_FINDINGS[*]} == *"belongs to the package vendor-agent"* ]]
  [[ ${BCC_INFO[*]:-} != *"C01 judges it"* ]]
}

@test "dpkg: python3-brotli is left to C01 only when C01 judged it" {
  bcc_dpkg_owner() { echo python3-brotli; }
  site="$T/usr/lib/python3/dist-packages"
  mkdir -p "$site/Brotli-1.1.0.egg-info"
  printf 'Name: Brotli\nVersion: 1.1.0\n' >"$site/Brotli-1.1.0.egg-info/PKG-INFO"
  BCC_IDX_PY=("$site/Brotli-1.1.0.egg-info")
  BCC_IDX_CONDA=()
  BCC_C01_JUDGED[python3-brotli]=1
  bcc_check_c06
  [ "${#BCC_FINDINGS[@]}" -eq 0 ]
  [[ ${BCC_INFO[*]} == *"C01 judges it"* ]]
}

# --- 5: absent markers are not proof; several copies are not all fixed --------------------

@test "C11: no markers in a hand-built server is UNKNOWN; from a package it is NOT_APPLICABLE" {
  command -v readelf >/dev/null || skip "readelf not available"
  BCC_NO_EXEC=1
  mkdir -p "$T/custom" "$T/pkg"
  cp /bin/true "$T/custom/nginx"
  cp /bin/true "$T/pkg/nginx"
  bcc_dpkg_owner() { case $1 in */pkg/*) echo nginx-core ;; *) return 1 ;; esac; }
  bcc_c11_file nginx "$T/custom/nginx"
  bcc_c11_file nginx "$T/pkg/nginx"
  run findings_brief
  [[ $output == *"UNKNOWN|C11|nginx|$T/custom/nginx|"* ]]
  [[ $output == *"NOT_APPLICABLE|C11|nginx|$T/pkg/nginx|"* ]]
  [[ ${BCC_FINDINGS[*]} == *"From the package nginx-core"* ]]
}

@test "C11: a Go server without the cgo binding is NOT_APPLICABLE; with it, UNKNOWN" {
  command -v readelf >/dev/null || skip "readelf not available"
  BCC_NO_EXEC=1
  mkdir -p "$T/go" "$T/cgo"
  cp /bin/true "$T/go/caddy"
  printf '\377 Go buildinf:\010\000' >>"$T/go/caddy"
  cp "$T/go/caddy" "$T/cgo/caddy"
  printf 'dep\tgithub.com/google/brotli/go/cbrotli\tv1.1.0\000' >>"$T/cgo/caddy"
  bcc_c11_file caddy "$T/go/caddy"
  bcc_c11_file caddy "$T/cgo/caddy"
  run findings_brief
  [[ $output == *"NOT_APPLICABLE|C11|caddy|$T/go/caddy|"* ]]
  [[ $output == *"UNKNOWN|C11|caddy|$T/cgo/caddy|"* ]]
}

@test "C08: a curl that was not run and shows no markers is UNKNOWN, not NOT_APPLICABLE" {
  command -v readelf >/dev/null || skip "readelf not available"
  BCC_NO_EXEC=1
  mkdir -p "$T/bin"
  cp /bin/true "$T/bin/curl"
  bcc_c08_entry "$T/bin/curl"
  run findings_brief
  [[ $output == "UNKNOWN|C08|curl|$T/bin/curl|"* ]]
}

@test "strings: a fixed copy next to another copy of Brotli is not LIKELY_FIXED" {
  make_fake_elf "$T/two" "$FIXTURES/c09/static-1.2.1-O2-p2-strip.txt"
  printf '%s\000junk\000%s\000' "$BCC_BROTLI_DICT_HEAD" "$BCC_BROTLI_DICT_HEAD" >>"$T/two"
  make_fake_elf "$T/one" "$FIXTURES/c09/static-1.2.1-O2-p2-strip.txt"
  printf '%s\000' "$BCC_BROTLI_DICT_HEAD" >>"$T/one"
  run bcc_brotli_heuristic "$T/two"
  [[ $output == MULTIPLE_COPIES$'\t'17$'\t'1$'\t'2* ]]
  run bcc_brotli_heuristic "$T/one"
  [[ $output == LIKELY_FIXED$'\t'17$'\t'1$'\t'1* ]]
  bcc_report_by_strings C09 two "$T/two" "" "prefix"
  [[ ${BCC_FINDINGS[0]} == C09$'\t'UNKNOWN$'\t'two* ]]
  # A version from a path that says "fixed" does not vouch for every copy either.
  bcc_judge node 22 semver 22.23.4
  bcc_crosscheck_fixed "$T/two"
  [ "$BCC_J_STATUS" = UNKNOWN ]
}

# --- 6: pre-releases are not the release ------------------------------------------------

@test "pre-release of the fixed version is UNKNOWN; before it VULNERABLE, after it FIXED" {
  bcc_judge bun '*' semver 1.4.4-rc.1
  [ "$BCC_J_STATUS" = UNKNOWN ]
  [[ $BCC_J_REASON == "Pre-release 1.4.4-rc.1 of the fixed version 1.4.4"* ]]
  bcc_judge bun '*' semver 1.4.3-rc.1
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_judge bun '*' semver 1.4.5-canary.20261020
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge node 22 semver 22.23.4-pre
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_judge pypi:brotli '*' pep440 1.2.1rc1
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_judge pypi:brotli '*' pep440 1.2.1.post1
  [ "$BCC_J_STATUS" = FIXED ]
}

@test "pre-release: Firefox Nightly and Beta of the fixed version are UNKNOWN" {
  bcc_browser_judge firefox "150.0a1"
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_browser_judge firefox "150.0b3"
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_browser_judge firefox "150.0~b3+build1"
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_browser_judge firefox "151.0a1"
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_browser_judge firefox "149.0b9"
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_browser_judge firefox "150.0-1" # a snap revision, not a pre-release
  [ "$BCC_J_STATUS" = FIXED ]
}

@test "pre-release: version strings keep their suffix" {
  [ "$(bcc_semver_parse v26.0.0-nightly20261020abc)" = 26.0.0-nightly20261020abc ]
  [ "$(bcc_semver_parse 1.4.4+5e5e7c60)" = 1.4.4 ]
  [ "$(bcc_version_from_dirname node-v22.23.4-linux-x64)" = 22.23.4 ]
  [ "$(bcc_version_from_dirname node-v24.0.0-rc.1-linux-x64-musl)" = 24.0.0-rc.1 ]
  [ "$(bcc_version_from_dirname v22.23.4)" = 22.23.4 ]
  [ "$(bcc_version_from_dirname 1.4.4-rc.1)" = 1.4.4-rc.1 ]
  run bcc_version_from_dirname node24_alpine
  [ "$status" -eq 1 ]
}

@test "pre-release: Bun and Node.js from paths and headers" {
  BCC_NO_EXEC=1
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  make_fake_elf "$T/home/u/.local/share/mise/installs/bun/1.4.4-rc.1/bin/bun"
  BCC_HOMES=("$T/home/u")
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c05
  make_fake_elf "$T/opt/node-v22.23.4-linux-x64/bin/node"
  mkdir -p "$T/opt/node-v22.23.4-linux-x64/include/node"
  printf '#define NODE_MAJOR_VERSION 22\n#define NODE_MINOR_VERSION 23\n#define NODE_PATCH_VERSION 4\n#define NODE_VERSION_IS_RELEASE 0\n' \
    >"$T/opt/node-v22.23.4-linux-x64/include/node/node_version.h"
  BCC_IDX_NODE=("$T/opt/node-v22.23.4-linux-x64/bin/node")
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"UNKNOWN|C05|bun|$T/home/u/.local/share/mise/installs/bun/1.4.4-rc.1/bin/bun|1.4.4-rc.1"* ]]
  [[ $output == *"UNKNOWN|C04|node|$T/opt/node-v22.23.4-linux-x64/bin/node|22.23.4-pre"* ]]
}

@test "pre-release: a Node.js release candidate in a container is UNKNOWN" {
  cat >"$FAKEBIN/docker" <<'EOF'
#!/bin/sh
printf 'OS\tdebian\ttrixie\t\nNODE\t/usr/local/bin/node\tv22.23.4-rc.1\nEND\n'
EOF
  chmod +x "$FAKEBIN/docker"
  bcc_c14_inspect docker 0123abcd web img:1
  run findings_brief
  [[ $output == *"UNKNOWN|C14|node|container web (img:1) /usr/local/bin/node|22.23.4-rc.1"* ]]
}

# --- 7: reads of found files are bounded and cannot block -------------------------------

@test "reads: a FIFO is never opened (header, ELF check, strings)" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/n/bin/node"
  mkdir -p "$T/n/include/node"
  mkfifo "$T/n/include/node/node_version.h" "$T/fifo"
  SECONDS=0
  run bcc_node_version "$T/n/bin/node"
  [ "$status" -eq 1 ]
  run bcc_is_elf "$T/fifo"
  [ "$status" -eq 1 ]
  run bcc_brotli_scan "$T/fifo"
  [[ $output == *$'\t'unreadable ]]
  run bcc_read_file "$T/fifo" 10
  [ "$status" -eq 1 ]
  ((SECONDS < 5))
}

@test "reads: distinct error names are counted only up to 64 (no unbounded memory, no sort)" {
  for i in $(seq 1 200); do printf '_ERROR_FORMAT_X%d\000' "$i"; done >"$T/many"
  run bcc_brotli_scan "$T/many"
  [[ $output == 64$'\t'* ]]
}

@test "reads: a file above the size limit is INCOMPLETE, not judged by part of its strings" {
  BCC_MAX_ELF_MB=1
  make_fake_elf "$T/big" "$FIXTURES/c09/static-1.2.0-O2-p2-strip.txt"
  truncate -s 2M "$T/big"
  run bcc_brotli_heuristic "$T/big"
  [[ $output == INCOMPLETE$'\t'*$'\t'partial ]]
}

# --- 8: failures are reported, never turned into "nothing found" ------------------------

@test "C01: a failing dpkg-query is not reported as 'none installed'" {
  printf '#!/bin/sh\nexit 2\n' >"$FAKEBIN/dpkg-query"
  chmod +x "$FAKEBIN/dpkg-query"
  BCC_DEB_SERIES=ubuntu:noble
  bcc_check_c01
  [[ ${BCC_INFO[*]:-} != *"None of"* ]]
  [[ ${BCC_SKIPPED[*]} == C01$'\t'"dpkg-query failed (status 2)"* ]]
}

@test "find: directories that could not be read are listed as not scanned" {
  [ "$(id -u)" -ne 0 ] || skip "root reads every directory"
  mkdir -p "$T/srv/locked" "$T/srv/open"
  chmod 000 "$T/srv/locked"
  bcc_find_each true "$T/srv" -- -name nothing
  bcc_find_status $? "roots"
  chmod 755 "$T/srv/locked"
  [ "$BCC_FIND_ERRORS" -eq 1 ]
  [[ ${BCC_SKIPPED[*]} == *"roots (find)"$'\t'"1 directories could not be read (e.g. $T/srv/locked)"* ]]
}

# --- 9: excluded ranges are listed; local disks mounted below the roots are searched -----

@test "mounts: a local disk below a root is searched, a tmpfs is listed as not scanned" {
  mkdir -p "$T/srv/data/app" "$T/srv/scratch"
  : >"$T/srv/data/app/marker"
  printf '36 25 8:17 / %s rw,relatime shared:1 - ext4 /dev/sdb1 rw\n37 25 0:40 / %s rw shared:2 - tmpfs tmpfs rw\n' \
    "$T/srv/data" "$T/srv/scratch" >"$T/mountinfo"
  BCC_MOUNTINFO="$T/mountinfo"
  bcc_init_remote_mounts
  run bcc_mounts_below "$T/srv"
  [[ $output == *"ext4"$'\t'"$T/srv/data"* ]]
  # These are not real mounts, so look at what find is asked to walk.
  printf '#!/bin/sh\nprintf "%%s\\n" "$@" >"%s/find-args"\n' "$T" >"$FAKEBIN/find"
  chmod +x "$FAKEBIN/find"
  bcc_find_each true "$T/srv" -- -name marker
  grep -qx -- "$T/srv/data" "$T/find-args"
  run grep -qx -- "$T/srv/scratch" "$T/find-args"
  [ "$status" -eq 1 ]
  [[ ${BCC_SKIPPED[*]} == *"$T/srv/scratch"$'\t'"tmpfs file systems mounted below the search roots (1;"* ]]
}

@test "--exclude paths are listed as not scanned" {
  BCC_EXCLUDES=("$T/srv/cache")
  bcc_note_disabled
  [[ ${BCC_SKIPPED[*]} == *"$T/srv/cache"$'\t'"excluded with --exclude"* ]]
}

@test "--deep: files above the size limit are listed as not scanned" {
  BCC_MAX_ELF_MB=1
  mkdir -p "$T/srv/bin"
  truncate -s 2M "$T/srv/bin/huge"
  chmod +x "$T/srv/bin/huge"
  BCC_ROOTS=("$T/srv")
  bcc_check_c09_deep
  [[ ${BCC_SKIPPED[*]} == *"C09 --deep (size)"$'\t'"1 files larger than 1 MiB were not searched (e.g. $T/srv/bin/huge)"* ]]
}

# --- 10: Node.js in containers is found by the shells containers have -------------------

@test "C14: the probe finds node with dash (no 'command -v -a'), once per real file" {
  command -v dash >/dev/null || skip "dash not available"
  mkdir -p "$T/c/bin" "$T/c/alt"
  printf '#!/bin/sh\necho v22.23.4\n' >"$T/c/bin/node"
  chmod +x "$T/c/bin/node"
  ln -s "$T/c/bin/node" "$T/c/alt/nodejs"
  run env PATH="$T/c/bin:$T/c/alt:/usr/bin:/bin" dash -c "$BCC_C14_PROBE"
  [[ $output == *"NODE"$'\t'"$T/c/bin/node"$'\t'"v22.23.4"* ]]
  [[ $output != *"$T/c/alt/nodejs"* ]]
  [[ ${lines[${#lines[@]} - 1]} == END ]]
}

@test "C14: a probe that stops before its end is listed as not scanned" {
  cat >"$FAKEBIN/docker" <<'EOF'
#!/bin/sh
printf 'OS\tdebian\ttrixie\t\n'
EOF
  chmod +x "$FAKEBIN/docker"
  bcc_c14_inspect docker 0123abcd web img:1
  [[ ${BCC_SKIPPED[*]} == *"container web"$'\t'"the read-only check inside the container stopped before its end"* ]]
}

# --- Codex review, round 5 (2026-10-26) --------------------------------------------------

@test "round 5: a symlink in a directory others can write is named, even as an ancestor" {
  mkdir -p "$T/real/lib" "$T/open" "$T/mine"
  chmod 755 "$T/real" "$T/real/lib" "$T/mine"
  chmod 777 "$T/open"
  ln -s "$T/real" "$T/open/current"
  ln -s "$T/real" "$T/mine/current"
  BCC_FACTS=()
  bcc_path_facts "$T/open/current/lib"
  [[ " ${BCC_FACTS[*]} " == *"$T/open can be written by anyone"* ]]
  BCC_FACTS=()
  bcc_path_facts "$T/mine/current/lib"
  [[ " ${BCC_FACTS[*]} " != *"$T/mine"*"anyone"* ]]
  [[ " ${BCC_FACTS[*]} " != *"$T/real"*"anyone"* ]]
}

@test "round 5: an empty RUNPATH entry is named; chosen programs run from /" {
  command -v cc >/dev/null || skip "no C compiler"
  command -v readelf >/dev/null || skip "readelf not available"
  mkdir -p "$T/bin"
  printf '#include <stdio.h>\n#include <unistd.h>\nint main(void){char b[4096];puts(getcwd(b,sizeof b));return 0;}\n' >"$T/cwd.c"
  cc -Wl,-rpath,':/nonexistent' -o "$T/bin/empty" "$T/cwd.c"
  cc -Wl,-rpath,'/usr/lib:' -o "$T/bin/trailing" "$T/cwd.c"
  cc -o "$T/bin/plain" "$T/cwd.c"
  bcc_ldcache_load
  bcc_exec_facts "$T/bin/empty"
  [[ " ${BCC_FACTS[*]} " == *"empty library search entry"* ]]
  bcc_exec_facts "$T/bin/trailing" # "read -a" would drop a trailing empty entry
  [[ " ${BCC_FACTS[*]} " == *"empty library search entry"* ]]
  bcc_plan_add "$T/bin/plain" --version test
  BCC_PLAN_OK["$T/bin/plain"$'\t'--version]=1
  cd "$T"
  bcc_exec_run
  cd /
  run bcc_probe "$T/bin/plain" --version
  [ "$output" = / ]
}

@test "round 5: a file name saying fixed is not FIXED when the file cannot be read to the end" {
  BCC_MAX_ELF_MB=1
  mkdir -p "$T/opt/app"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.1-nostrip.txt" >"$T/opt/app/libbrotlidec.so.1.2.1"
  truncate -s 2M "$T/opt/app/libbrotlidec.so.1.2.1"
  BCC_IDX_LIB=("$T/opt/app/libbrotlidec.so.1.2.1")
  bcc_check_c09_libs
  run findings_brief
  [[ $output == "UNKNOWN|C09|libbrotlidec (shared)|$T/opt/app/libbrotlidec.so.1.2.1|1.2.1"* ]]
  [[ ${BCC_SKIPPED[*]} == *"$T/opt/app/libbrotlidec.so.1.2.1"$'\t'"could not be read to the end"* ]]
}

@test "round 5: C11 does not take a partly read file for one without markers" {
  command -v readelf >/dev/null || skip "readelf not available"
  BCC_NO_EXEC=1 BCC_MAX_ELF_MB=1
  mkdir -p "$T/pkg"
  cp /bin/true "$T/pkg/nginx"
  truncate -s 2M "$T/pkg/nginx"
  bcc_dpkg_owner() { echo nginx-core; }
  bcc_c11_file nginx "$T/pkg/nginx"
  run findings_brief
  [[ $output == "UNKNOWN|C11|nginx|$T/pkg/nginx|"* ]]
}

@test "round 5: an empty conda-meta/ next to a library does not hide it; a reported environment does" {
  mkdir -p "$T/srv/app/lib" "$T/srv/app/conda-meta" "$T/srv/env/lib" "$T/srv/env/conda-meta"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$T/srv/app/lib/libbrotlidec.so.1.2.0"
  cp "$T/srv/app/lib/libbrotlidec.so.1.2.0" "$T/srv/env/lib/libbrotlidec.so.1.2.0"
  printf '{}\n' >"$T/srv/env/conda-meta/libbrotlidec-1.2.0-h0_0.json"
  BCC_IDX_PY=()
  BCC_IDX_CONDA=("$T/srv/env/conda-meta/libbrotlidec-1.2.0-h0_0.json")
  bcc_check_c06
  BCC_IDX_LIB=("$T/srv/app/lib/libbrotlidec.so.1.2.0" "$T/srv/env/lib/libbrotlidec.so.1.2.0")
  bcc_check_c09_libs
  run findings_brief
  [[ $output == *"VULNERABLE|C09|libbrotlidec (shared)|$T/srv/app/lib/libbrotlidec.so.1.2.0|1.2.0"* ]]
  [[ $output == *"VULNERABLE|C06|conda:libbrotlidec|$T/srv/env/conda-meta/"* ]]
  [[ $output != *"|C09|libbrotlidec (shared)|$T/srv/env/"* ]]
}

@test "round 5: a program loading a libbrotlidec that C01 did not judge gets that copy judged" {
  bcc_dpkg_owner() { case $1 in */system/*) echo libbrotli1:amd64 ;; *) return 1 ;; esac; }
  BCC_C01_JUDGED[libbrotli1]=1
  mkdir -p "$T/vendor/lib" "$T/system/lib"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$T/vendor/lib/libbrotlidec.so.1.2.0"
  cp "$T/vendor/lib/libbrotlidec.so.1.2.0" "$T/system/lib/libbrotlidec.so.1.2.0"
  bcc_report_linked_lib C08 curl /usr/local/bin/curl "$T/vendor/lib/libbrotlidec.so.1.2.0" readelf
  bcc_report_linked_lib C08 curl /usr/bin/curl "$T/system/lib/libbrotlidec.so.1.2.0" readelf
  bcc_report_linked_lib C08 curl /opt/x/bin/curl "$T/nowhere/libbrotlidec.so.1" readelf
  run findings_brief
  [[ $output == *"VULNERABLE|C09|libbrotlidec (shared)|$T/vendor/lib/libbrotlidec.so.1.2.0|1.2.0"* ]]
  [[ $output != *"$T/system/"* ]]
  [[ $output == *"UNKNOWN|C08|curl|/opt/x/bin/curl|"* ]]
  [[ ${BCC_INFO[*]} == *"/usr/local/bin/curl (curl) loads a libbrotlidec that C01 did not judge"* ]]
  [[ ${BCC_INFO[*]} == *"/usr/bin/curl (curl) loads the OS libbrotlidec"* ]]
}

@test "round 5: a Chromium version with a Debian-style pre-release suffix is not the release" {
  bcc_browser_judge chromium "148.0.7778.0~rc1"
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_browser_judge chromium "148.0.7778.96"
  [ "$BCC_J_STATUS" = FIXED ]
}

@test "round 5: --deep search errors and a failing dpkg-query in a container are listed as not scanned" {
  printf '#!/bin/sh\nprintf "__BCC_GREP_ERR\\000"\n' >"$FAKEBIN/xargs"
  chmod +x "$FAKEBIN/xargs"
  make_fake_elf "$T/srv/bin/prog"
  BCC_ROOTS=("$T/srv")
  bcc_check_c09_deep
  [[ ${BCC_SKIPPED[*]} == *"C09 --deep (search)"$'\t'"some files could not be searched"* ]]
  cat >"$FAKEBIN/docker" <<'EOS'
#!/bin/sh
printf 'OS\tdebian\ttrixie\t\nPKGRC\t2\nEND\n'
EOS
  chmod +x "$FAKEBIN/docker"
  bcc_c14_inspect docker 0123abcd web img:1
  [[ ${BCC_SKIPPED[*]} == *"container web (dpkg)"$'\t'"dpkg-query failed inside the container (status 2)"* ]]
}

@test "round 5: a search root that is a symlink is walked at its target, and said so" {
  mkdir -p "$T/data/srv/app"
  : >"$T/data/srv/app/marker"
  ln -s "$T/data/srv" "$T/srv"
  found=()
  collect() { found+=("$1"); }
  bcc_find_each collect "$T/srv" -- -name marker
  [[ " ${found[*]} " == *" $T/data/srv/app/marker "* ]]
  BCC_ROOTS=("$T/srv")
  BCC_ROOTS_RAW="$T/srv" BCC_DEFAULT_ROOTS=/opt
  bcc_check_roots
  [[ ${BCC_INFO[*]} == *"Search root $T/srv is a symbolic link; searched its target $T/data/srv"* ]]
}

# --- Codex review, round 6 (2026-10-27) --------------------------------------------------

@test "round 6: a RUNPATH entry that is a dangling symlink in a writable directory is named" {
  command -v cc >/dev/null || skip "no C compiler"
  command -v readelf >/dev/null || skip "readelf not available"
  mkdir -p "$T/bin" "$T/open"
  chmod 777 "$T/open"
  ln -s "$T/open/later" "$T/open/libdir"
  printf 'int main(void){return 0;}\n' >"$T/m.c"
  cc -Wl,-rpath,"$T/open/libdir" -o "$T/bin/prog" "$T/m.c"
  bcc_ldcache_load
  bcc_exec_facts "$T/bin/prog"
  [[ " ${BCC_FACTS[*]} " == *"$T/open can be written by anyone"* ]]
}

@test "round 6: libraries are looked up through the RPATH inherited from the executable" {
  command -v cc >/dev/null || skip "no C compiler"
  command -v readelf >/dev/null || skip "readelf not available"
  mkdir -p "$T/app/lib" "$T/app/bin"
  printf 'int x(void){return 1;}\n' >"$T/x.c"
  printf 'int x(void);\nint a(void){return x();}\n' >"$T/a.c"
  printf 'int a(void);\nint main(void){return a();}\n' >"$T/m.c"
  cc -shared -fPIC -o "$T/app/lib/libX.so" "$T/x.c"
  cc -shared -fPIC -o "$T/app/lib/libA.so" "$T/a.c" -L"$T/app/lib" -lX
  # DT_RPATH (not RUNPATH) on the executable; libA.so has no search path of its own.
  cc -o "$T/app/bin/prog" "$T/m.c" -L"$T/app/lib" -lA -Wl,--disable-new-dtags,-rpath,"$T/app/lib"
  readelf -d "$T/app/lib/libA.so" | grep -qE 'RPATH|RUNPATH' && skip "toolchain added a search path to libA.so"
  bcc_ldcache_load
  bcc_dep_walk_prefetch "$T/app/bin/prog"
  grep -qxF "N"$'\t'"libX.so"$'\t'"$T/app/lib/libX.so" <<<"$(walk_records "$T/app/bin/prog")"
}

@test "round 6: the end of a read is never taken from the file's own bytes" {
  # Old versions carried a status mark in the data stream; a file could forge it.
  make_fake_elf "$T/forged" "$FIXTURES/c09/shared-1.2.1-nostrip.txt"
  printf '__BCC_READ_RC=0\000' >>"$T/forged"
  run bcc_brotli_scan "$T/forged"
  [[ $output == *$'\t'complete ]]
  # A failing grep (memory exhausted, read error) makes the read partial.
  printf '#!/bin/sh\ncat >/dev/null\nexit 2\n' >"$FAKEBIN/grep"
  chmod +x "$FAKEBIN/grep"
  run bcc_brotli_scan "$T/forged"
  [[ $output == *$'\t'partial ]]
}

@test "round 6: Firefox's application.ini and a flatpak runtime's file name are confirmed by strings" {
  mkdir -p "$T/firefox" "$T/flatpak/runtime/org.x.Platform/x86_64/24/active/files/lib"
  make_fake_elf "$T/firefox/firefox"
  printf '[App]\nVersion=151.0\n' >"$T/firefox/application.ini"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$T/firefox/libxul.so"
  BCC_C13_CANDS=("$T/firefox/firefox") BCC_C13_KINDS=(firefox) BCC_C13_DONE=1
  bcc_check_c13
  run findings_brief
  [[ $output == *"UNKNOWN|C13|firefox|$T/firefox/firefox|151.0"* ]]
  lib="$T/flatpak/runtime/org.x.Platform/x86_64/24/active/files/lib/libbrotlidec.so.1.2.1"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$lib"
  bcc_c12_runtime_lib "$lib"
  run findings_brief
  [[ $output == *"UNKNOWN|C12|"*"|$lib|1.2.1"* ]]
}

@test "round 6: a conda record saying fixed is confirmed against the environment's library" {
  mkdir -p "$T/env/conda-meta" "$T/env/lib"
  printf '{}\n' >"$T/env/conda-meta/libbrotlidec-1.2.1-h0_0.json"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$T/env/lib/libbrotlidec.so.1.2.1"
  BCC_IDX_PY=() BCC_IDX_CONDA=("$T/env/conda-meta/libbrotlidec-1.2.1-h0_0.json")
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|conda:libbrotlidec|"* ]]
}

@test "round 6: a libbrotlidec loaded under a name its file does not have is still judged" {
  mkdir -p "$T/vendor/lib"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$T/vendor/lib/decoder.bin"
  ln -s decoder.bin "$T/vendor/lib/libbrotlidec.so.1"
  bcc_report_linked_lib C08 curl /opt/x/bin/curl "$T/vendor/lib/libbrotlidec.so.1" readelf
  run findings_brief
  [[ $output == *"LIKELY_VULNERABLE|C09|libbrotlidec (shared)|$T/vendor/lib/decoder.bin|"* ]]
}

@test "round 6: a file that loads libbrotlidec and carries its own decoder gets that copy judged" {
  command -v cc >/dev/null || skip "no C compiler"
  command -v readelf >/dev/null || skip "readelf not available"
  lib=""
  for x in /usr/lib/x86_64-linux-gnu/libbrotlidec.so.1 /usr/lib/aarch64-linux-gnu/libbrotlidec.so.1; do
    [ -e "$x" ] && { lib=$x; break; }
  done
  [ -n "$lib" ] || skip "no system libbrotlidec to link against"
  mkdir -p "$T/srv/bin"
  printf 'int main(void){return 0;}\n' >"$T/m.c"
  # --no-as-needed: the linker would otherwise drop the (unused) libbrotlidec from NEEDED.
  cc -o "$T/srv/bin/both" "$T/m.c" -Wl,--no-as-needed "$lib"
  readelf -d "$T/srv/bin/both" | grep -q 'libbrotlidec' || skip "could not make a program that needs libbrotlidec"
  tr '\n' '\0' <"$FIXTURES/c09/static-1.2.0-O2-p2-strip.txt" >>"$T/srv/bin/both"
  printf 'BrotliDecoderDecompressStream\0' >>"$T/srv/bin/both"
  BCC_ROOTS=("$T/srv")
  bcc_check_c09_deep
  run findings_brief
  [[ $output == *"LIKELY_VULNERABLE|C09|both (own copy)|$T/srv/bin/both|"* ]]
}

@test "round 6: a candidate found by its name is kept when it is a symlink to another name" {
  mkdir -p "$T/opt/vendor/bin"
  make_fake_elf "$T/opt/vendor/bin/node-22.0.0"
  ln -s node-22.0.0 "$T/opt/vendor/bin/node"
  bcc_collect0 < <(printf 'G%s\0' "$T/opt/*/bin/node" | PATH=/usr/bin:/bin bcc_candidates 'node|nodejs')
  [ "${BCC_LIST[0]}" = "$T/opt/vendor/bin/node-22.0.0" ]
}

@test "round 6: a link to a program of another name (a mise or volta shim) is not the runtime" {
  mkdir -p "$T/bin" "$T/shims"
  make_fake_elf "$T/bin/mise"
  ln -s ../bin/mise "$T/shims/node"
  bcc_collect0 < <(printf 'G%s\0' "$T/shims/node" | PATH=/usr/bin:/bin bcc_candidates 'node|nodejs')
  [ "${#BCC_LIST[@]}" -eq 0 ]
}

@test "round 6: a path with a newline in it stays one path" {
  d="$T/x"$'\n'"y/bin"
  mkdir -p "$d"
  make_fake_elf "$d/bun"
  bcc_collect0 < <(bcc_index_list "$d/bun" | PATH=/usr/bin:/bin bcc_candidates bun)
  [ "${#BCC_LIST[@]}" -eq 1 ]
  [ "${BCC_LIST[0]}" = "$d/bun" ]
}

@test "round 6: Brotli under a container's dist-packages without python3-brotli is judged" {
  cat >"$FAKEBIN/docker" <<'EOS'
#!/bin/sh
printf 'OS\tdebian\ttrixie\t\nPKGRC\t1\nPY\t/usr/lib/python3/dist-packages/Brotli-1.1.0.dist-info/METADATA\tBrotli\t1.1.0\nEND\n'
EOS
  chmod +x "$FAKEBIN/docker"
  bcc_c14_inspect docker 0123abcd web img:1
  run findings_brief
  [[ $output == *"VULNERABLE|C14|Brotli|container web (img:1) /usr/lib/python3/dist-packages/Brotli-1.1.0.dist-info|1.1.0"* ]]
}

@test "round 6: a Python package of the distribution in a container is left to its PKG line" {
  cat >"$FAKEBIN/docker" <<'EOS'
#!/bin/sh
printf 'OS\tdebian\ttrixie\t\nPKG\tii \tpython3-brotli\t1.1.0-2+deb13u1\tbrotli\t1.1.0-2+deb13u1\nPKGRC\t0\nPY\t/usr/lib/python3/dist-packages/Brotli-1.1.0.egg-info/METADATA\tBrotli\t1.1.0\nEND\n'
EOS
  chmod +x "$FAKEBIN/docker"
  bcc_c14_inspect docker 0123abcd web img:1
  run findings_brief
  [[ $output != *"|C14|Brotli|"* ]]
}

@test "round 6: an Envoy configuration read only in part is not reported as free of Brotli" {
  printf 'static_resources: {}\n' >"$T/envoy.yaml"
  truncate -s 65M "$T/envoy.yaml"
  BCC_ENVOY_CONFIG="$T/envoy.yaml"
  BCC_C10_CANDS=() BCC_C10_DONE=1
  bcc_check_c10
  [[ ${BCC_INFO[*]} != *"No Brotli decompressor in"* ]]
  [[ ${BCC_SKIPPED[*]} == *"$T/envoy.yaml"$'\t'"could not be read to the end"* ]]
}

@test "round 6: snap list and ss failures are listed as not scanned" {
  printf '#!/bin/sh\nexit 1\n' >"$FAKEBIN/snap"
  printf '#!/bin/sh\nexit 1\n' >"$FAKEBIN/ss"
  chmod +x "$FAKEBIN/snap" "$FAKEBIN/ss"
  bcc_have() { [[ $1 != flatpak ]] && command -v -- "$1" >/dev/null 2>&1; }
  bcc_check_c12
  bcc_check_c15
  [[ ${BCC_SKIPPED[*]} == *"C12 snap"$'\t'"snap list failed (status 1)"* ]]
  [[ ${BCC_SKIPPED[*]} == *"C15"$'\t'"ss failed (status 1)"* ]]
}

@test "round 6: Electron snaps are found through /snap/NAME/current, which is a symlink" {
  mkdir -p "$T/snap/app/42/opt"
  : >"$T/snap/app/42/opt/resources.pak"
  ln -s 42 "$T/snap/app/current"
  bcc_is_electron_tree "$T/snap/app/current"
}

@test "round 6: an incomplete read of a library is listed even when its name says vulnerable" {
  BCC_MAX_ELF_MB=1
  mkdir -p "$T/opt/app"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$T/opt/app/libbrotlidec.so.1.2.0"
  truncate -s 2M "$T/opt/app/libbrotlidec.so.1.2.0"
  BCC_IDX_LIB=("$T/opt/app/libbrotlidec.so.1.2.0")
  bcc_check_c09_libs
  [[ ${BCC_SKIPPED[*]} == *"$T/opt/app/libbrotlidec.so.1.2.0"$'\t'"could not be read to the end"* ]]
}

# --- Automatic security review after round 6 (2026-10-27) ---------------------------------
# The list of programs to run is the screen the user decides on, so what it shows must be
# what is there, and what runs must be what it showed - whatever bytes a found path holds.

@test "review 10/27: control characters in a found path never reach the terminal in the consent list" {
  d="$T/esc"$'\033'"]0;title"$'\a'$'\033'"[2J"$'\xc2\x9b'"31m/bin"
  make_fake_elf "$d/bun"
  bcc_plan_add "$d/bun" --version "C05 bun"
  run bcc_exec_consent </dev/null
  [ "$status" -eq 3 ]
  [[ $output != *$'\033'* && $output != *$'\a'* && $output != *$'\xc2\x9b'* ]]
  [[ $output == *" 1. $T/esc?]0;title??[2J?31m/bin/bun --version  (C05 bun)"* ]]
}

@test "review 10/27: a newline in a path leaves every fact whole, on one line in the text, exact in JSON" {
  n="$T/a"$'\n'"b"
  mkdir -p "$n/open/bin" "$n/open/sub"
  chmod 777 "$n/open" "$n/open/sub"
  make_fake_elf "$n/open/bin/bun"
  BCC_FACTS=()
  bcc_path_facts "$n/open/bin/bun"
  [ "${#BCC_FACTS[@]}" -eq 1 ]
  [ "${BCC_FACTS[0]}" = "$n/open can be written by anyone" ]
  # A fact with a newline in it does not hide the ones after it.
  BCC_FACTS=()
  bcc_path_facts "$n/open/sub"
  [ "${#BCC_FACTS[@]}" -eq 2 ]
  [ "${BCC_FACTS[1]}" = "$n/open/sub can be written by anyone" ]
  bcc_plan_add "$n/open/bin/bun" --version "C05 bun"
  BCC_NO_EXEC=1
  run bcc_render_exec_text
  [[ $output == *"[NOT RUN] $T/a?b/open/bin/bun --version (--no-exec)"* ]]
  [[ $output == *$'\n'"    - $T/a?b/open can be written by anyone"* ]]
  run bcc_render_exec_json
  [[ $output == *"\"path\":\"$T/a\\nb/open/bin/bun\""* ]]
  [[ $output == *"\"$T/a\\nb/open can be written by anyone\""* ]]
}

@test "review 10/27: libraries searched through \$ORIGIN under a path with a newline are examined there" {
  command -v cc >/dev/null || skip "no C compiler"
  command -v readelf >/dev/null || skip "readelf not available"
  n="$T/x"$'\n'"y"
  mkdir -p "$n/bin" "$n/lib"
  chmod 777 "$n/lib"
  printf 'int main(void){return 0;}\n' >"$T/m.c"
  # shellcheck disable=SC2016  # $ORIGIN is for the linker
  cc -Wl,-rpath,'$ORIGIN/../lib' -o "$n/bin/prog" "$T/m.c"
  bcc_ldcache_load
  bcc_exec_facts "$n/bin/prog"
  has_fact "$n/lib can be written by anyone"
}

@test "review 10/27: what runs is the program listed, even with a tab in its path" {
  d="$T/evil"$'\t'"dir/bin"
  mkdir -p "$d"
  printf '#!/bin/sh\necho "listed $*"\n' >"$d/bun"
  # What splitting the entry at its first tab would have run instead.
  printf '#!/bin/sh\necho "split $*"\n' >"$T/evil"
  chmod +x "$d/bun" "$T/evil"
  bcc_plan_add "$d/bun" --version "C05 bun"
  run bcc_print_plan
  [[ $output == *" 1. $T/evil?dir/bin/bun --version  (C05 bun)"* ]]
  BCC_YES=1
  bcc_exec_consent
  bcc_exec_run
  run bcc_probe "$d/bun" --version
  [ "$output" = "listed --version" ]
}

@test "review 10/27: a symlink is followed to its exact target; a chain too long to follow is said so" {
  w="$T/w"$'\n'
  mkdir -p "$w"
  chmod 777 "$w"
  ln -s "$w" "$T/l"
  BCC_FACTS=()
  bcc_path_facts "$T/l"
  has_fact "$w can be written by anyone"
  # The kernel gives up after 40 links; the walk does too, and says so.
  ln -s loop2 "$T/loop1"
  ln -s loop1 "$T/loop2"
  BCC_FACTS=()
  bcc_path_facts "$T/loop1/x"
  [[ ${BCC_FACTS[*]} == *"$T/loop1: symbolic links were not followed further"* ]]
}

@test "review 10/27: library lookups under different search paths are kept apart" {
  command -v cc >/dev/null || skip "no C compiler"
  command -v readelf >/dev/null || skip "readelf not available"
  # One directory whose name holds ":" (reached through $ORIGIN), and two directories
  # that a RUNPATH lists with ":" - joined, both read the same.
  one="$T/a:$T/b"
  mkdir -p "$one" "$T/b"
  printf 'int q(void){return 0;}\n' >"$T/q.c"
  printf 'int q(void);\nint main(void){return q();}\n' >"$T/m.c"
  cc -shared -fPIC -o "$T/b/libq.so" "$T/q.c"
  cp "$T/b/libq.so" "$one/libq.so"
  # shellcheck disable=SC2016  # $ORIGIN is for the linker
  cc -o "$one/p1" "$T/m.c" -L"$T/b" -lq -Wl,-rpath,'$ORIGIN'
  cc -o "$T/p2" "$T/m.c" -L"$T/b" -lq -Wl,-rpath,"$T/a:$T/b"
  bcc_ldcache_load
  bcc_dep_walk_prefetch "$one/p1"
  bcc_dep_walk_prefetch "$T/p2"
  grep -qxF "N"$'\t'"libq.so"$'\t'"$one/libq.so" <<<"$(walk_records "$one/p1")"
  grep -qxF "N"$'\t'"libq.so"$'\t'"$T/b/libq.so" <<<"$(walk_records "$T/p2")"
}

@test "review 10/27: a [ or * in a library directory is part of its name, not a pattern" {
  d="$T/app [1]/lib"
  mkdir -p "$d/glibc-hwcaps/x86-64-v3" "$T/app 1/lib/glibc-hwcaps/x86-64-v3"
  : >"$d/glibc-hwcaps/x86-64-v3/libq.so"
  : >"$T/app 1/lib/glibc-hwcaps/x86-64-v3/libq.so"
  [ "$(bcc_dep_find libq.so "$d")" = "$d/glibc-hwcaps/x86-64-v3/libq.so" ]
  command -v cc >/dev/null || skip "no C compiler"
  command -v readelf >/dev/null || skip "readelf not available"
  chmod 777 "$d/glibc-hwcaps/x86-64-v3"
  printf 'int main(void){return 0;}\n' >"$T/m.c"
  cc -Wl,-rpath,"$d" -o "$T/prog" "$T/m.c"
  bcc_ldcache_load
  bcc_exec_facts "$T/prog"
  has_fact "$d/glibc-hwcaps/x86-64-v3 can be written by anyone"
}

# --- Mutation tests of 2026-10-27: gaps they showed (docs/2026-10-26_test-record_codex-round4-5.html 13) ---

@test "mutation 10/27: a chosen program runs with an empty environment, stdin closed, its output capped" {
  mkdir -p "$T/bin"
  cat >"$T/bin/probe" <<'EOS'
#!/bin/sh
echo "env=${NODE_OPTIONS:-none}"
if read -r line; then echo "stdin=$line"; else echo "stdin=closed"; fi
head -c 100000 /dev/zero | tr '\0' x
EOS
  chmod +x "$T/bin/probe"
  bcc_plan_add "$T/bin/probe" --version test
  BCC_YES=1
  bcc_exec_consent
  NODE_OPTIONS=--require=/tmp/evil.js bcc_exec_run <<<"typed by the user"
  out=${BCC_PROBE_OUT["$T/bin/probe"$'\t'--version]}
  [[ $out == "env=none"$'\n'"stdin=closed"$'\n'x* ]]
  [ "${#out}" -le 65536 ]
}

@test "mutation 10/27: the plan leaves out what its verdict does not need, and asks for the rest" {
  # Candidates and their linkage stand in for the host; what is asked follows design 10.11.
  bcc_c04_candidates() { BCC_C04_CANDS=("$T/pkg/node-linked" "$T/pkg/node-static" "$T/own/node"); }
  bcc_c05_candidates() { BCC_C05_CANDS=(); }
  bcc_c08_candidates() { BCC_C08_CANDS=("$T/curl-linked" "$T/curl-static"); }
  bcc_c10_candidates() { BCC_C10_CANDS=(); }
  bcc_c13_candidates() { BCC_C13_CANDS=("$T/pkg/firefox" "$T/own/firefox"); BCC_C13_KINDS=(firefox firefox); }
  bcc_dpkg_owner() {
    case $1 in "$T/pkg/"*) BCC_DPKG_CACHE[$1]=pkg; printf 'pkg\n' ;; *) BCC_DPKG_CACHE[$1]=""; return 1 ;; esac
  }
  bcc_link_prefetch() { case $1 in *-linked) BCC_LINK_RC[$1]=0 ;; *) BCC_LINK_RC[$1]=1 ;; esac; }
  bcc_exec_facts() { BCC_FACTS=(fact); }
  bcc_build_exec_plan
  plan=$(printf '%s\n' "${BCC_PLAN[@]}" | cut -f1 | sort | paste -sd' ' -)
  [ "$plan" = "$T/curl-static $T/own/firefox $T/own/node $T/pkg/node-static" ]
}

@test "mutation 10/27: programs listed but not run are listed as not scanned, with the reason" {
  make_fake_elf "$T/a/bun"
  bcc_plan_add "$T/a/bun" --version "C05 bun"
  BCC_NO_EXEC=1
  bcc_note_exec
  [[ ${BCC_SKIPPED[*]} == *"--no-exec"$'\t'"found programs were not run"* ]]
  BCC_SKIPPED=()
  declare -gA BCC_SKIP_KEYS=()
  BCC_NO_EXEC=0
  bcc_note_exec
  [[ ${BCC_SKIPPED[*]} == *"exec"$'\t'"1 programs listed to read their versions were not chosen"* ]]
  # What ran is not listed.
  BCC_SKIPPED=()
  declare -gA BCC_SKIP_KEYS=()
  BCC_PROBE_RC["$T/a/bun"$'\t'--version]=0
  bcc_note_exec
  [ "${#BCC_SKIPPED[@]}" -eq 0 ]
}

# A stat that reports another owner (uid 4242, gid 4243, mode 775) for the paths listed in
# FAKE_STAT_OTHERS, as only root could make such files; the real stat for anything else.
fake_stat_others() {
  cat >"$FAKEBIN/stat" <<'EOS'
#!/bin/bash
args=("$@") fmt="" path=""
while (($#)); do case $1 in -c) fmt=$2; shift 2 ;; --) path=$2; break ;; *) shift ;; esac; done
for p in $FAKE_STAT_OTHERS; do
  if [[ $path == "$p" ]]; then
    case $fmt in '%u %g %a') echo "4242 4243 775" ;; '%u') echo 4242 ;; *) exec /usr/bin/stat "${args[@]}" ;; esac
    exit 0
  fi
done
exec /usr/bin/stat "${args[@]}"
EOS
  chmod +x "$FAKEBIN/stat"
}

@test "mutation 10/27: another owner, a group that can write, the owner of a link, a missing name are facts" {
  fake_stat_others
  mkdir -p "$T/theirs" "$T/real"
  ln -s "$T/real" "$T/link"
  export FAKE_STAT_OTHERS="$T/theirs $T/link"
  BCC_FACTS=()
  bcc_path_facts "$T/theirs/prog"
  has_fact "$T/theirs belongs to uid 4242"
  has_fact "$T/theirs can be written by group gid 4243"
  has_fact "$T/theirs/prog does not exist (whoever can write in the directory above could create it)"
  BCC_FACTS=()
  bcc_path_facts "$T/link/x"
  has_fact "$T/link belongs to uid 4242"
}

@test "mutation 10/27: the loader, each library loaded, relative entries and readelf failures are facts" {
  command -v cc >/dev/null || skip "no C compiler"
  command -v readelf >/dev/null || skip "readelf not available"
  mkdir -p "$T/open" "$T/lib" "$T/bin"
  chmod 777 "$T/open"
  printf 'int q(void){return 0;}\n' >"$T/q.c"
  printf 'int q(void);\nint main(void){return q();}\n' >"$T/m.c"
  cc -shared -fPIC -o "$T/lib/libq.so" "$T/q.c"
  chmod 666 "$T/lib/libq.so"
  # The library file itself can be changed by anyone (its directory cannot); the loader is
  # named in a directory anyone can write; one search entry is relative.
  cc -o "$T/bin/prog" "$T/m.c" -L"$T/lib" -lq -Wl,-rpath,"$T/lib:lib" -Wl,--dynamic-linker="$T/open/ld.so"
  make_fake_elf "$T/bin/fake"
  bcc_ldcache_load
  bcc_exec_facts "$T/bin/prog"
  has_fact "$T/lib/libq.so can be written by anyone"
  has_fact "$T/open/ld.so does not exist (whoever can write in the directory above could create it)"
  has_fact "$T/bin/prog: lib has a relative library search entry (looked up from the working directory; the tool runs programs from /)"
  bcc_exec_facts "$T/bin/fake"
  has_fact "readelf could not read $T/bin/fake; what it loads was not examined"
}

@test "mutation 10/27: /etc/ld.so.preload and what it names are examined" {
  mkdir -p "$T/etc" "$T/open"
  chmod 777 "$T/open"
  printf '%s\n' "$T/open/libhook.so" >"$T/etc/ld.so.preload"
  chmod 666 "$T/etc/ld.so.preload"
  make_fake_elf "$T/prog"
  BCC_LD_PRELOAD_FILE="$T/etc/ld.so.preload"
  bcc_exec_facts "$T/prog"
  has_fact "$T/etc/ld.so.preload can be written by anyone"
  has_fact "$T/open/libhook.so does not exist (whoever can write in the directory above could create it)"
}

# A readelf that pretends: "-d FILE" prints FILE.dyn (the dynamic section, written by dyn
# below), "-l" prints nothing. For search paths a compiler will not produce (RPATH and RUNPATH
# on one object).
fake_readelf() {
  cat >"$FAKEBIN/readelf" <<'EOS'
#!/bin/bash
f=${!#}
case $1 in -d) [[ -f $f.dyn ]] && cat -- "$f.dyn" || exit 1 ;; *) exit 0 ;; esac
EOS
  chmod +x "$FAKEBIN/readelf"
}

# dyn FILE [NEEDED=x] [RPATH=x] [RUNPATH=x] ...: create FILE and its pretended dynamic section.
dyn() {
  local f=$1 kv
  shift
  mkdir -p "$(dirname "$f")"
  : >"$f"
  : >"$f.dyn"
  for kv in "$@"; do
    case $kv in
      NEEDED=*) printf ' 0x0000000000000001 (NEEDED)             Shared library: [%s]\n' "${kv#*=}" ;;
      RPATH=*) printf ' 0x000000000000000f (RPATH)              Library rpath: [%s]\n' "${kv#*=}" ;;
      RUNPATH=*) printf ' 0x000000000000001d (RUNPATH)            Library runpath: [%s]\n' "${kv#*=}" ;;
    esac >>"$f.dyn"
  done
}

@test "mutation 10/27: a RUNPATH hides the same object's RPATH and the RPATH it would inherit" {
  fake_readelf
  # prog has both; glibc ignores its RPATH, so libA's need (libB) is not looked up in r1.
  dyn "$T/bin/prog" NEEDED=libA.so RPATH="$T/r1" RUNPATH="$T/r2"
  dyn "$T/r2/libA.so" NEEDED=libB.so
  dyn "$T/r1/libB.so"
  bcc_dep_walk_prefetch "$T/bin/prog"
  recs=$(walk_records "$T/bin/prog")
  grep -qxF "N"$'\t'"libA.so"$'\t'"$T/r2/libA.so" <<<"$recs"
  grep -qxF "N"$'\t'"libB.so"$'\t' <<<"$recs"
  [[ $recs != *"$T/r1"* ]]
  # A library with a RUNPATH does not use the RPATH of the program that loads it.
  dyn "$T/bin/prog2" NEEDED=libC.so RPATH="$T/r3"
  dyn "$T/r3/libC.so" NEEDED=libD.so RUNPATH="$T/r4"
  dyn "$T/r3/libD.so"
  bcc_dep_walk_prefetch "$T/bin/prog2"
  grep -qxF "N"$'\t'"libD.so"$'\t' <<<"$(walk_records "$T/bin/prog2")"
}

@test "mutation 10/27: a chain of libraries deeper than the walk follows is said so" {
  fake_readelf
  local i
  dyn "$T/bin/prog" NEEDED=lib0.so RPATH="$T/lib"
  for i in 0 1 2 3 4 5 6 7 8 9; do dyn "$T/lib/lib$i.so" NEEDED="lib$((i + 1)).so"; done
  bcc_exec_facts "$T/bin/prog"
  has_fact "the libraries were followed only 8 levels deep"
}

@test "mutation 10/27: a search path inherited through \$ORIGIN keeps a \":\" in a directory name" {
  fake_readelf
  # prog sits under "x:y"; its RPATH $ORIGIN/../lib is that directory, which libA inherits.
  # shellcheck disable=SC2016  # $ORIGIN is for the (pretended) loader
  dyn "$T/x:y/bin/prog" NEEDED=libA.so RPATH='$ORIGIN/../lib'
  dyn "$T/x:y/lib/libA.so" NEEDED=libB.so
  dyn "$T/x:y/lib/libB.so"
  bcc_dep_walk_prefetch "$T/x:y/bin/prog"
  grep -qxF "N"$'\t'"libB.so"$'\t'"$T/x:y/bin/../lib/libB.so" <<<"$(walk_records "$T/x:y/bin/prog")"
}

@test "mutation 10/27: RPATH and NEEDED values with [ or ] are read whole" {
  fake_readelf
  dyn "$T/bin/prog" NEEDED='lib[1].so' RPATH="$T/app [1]/lib"
  dyn "$T/app [1]/lib/lib[1].so"
  bcc_dep_walk_prefetch "$T/bin/prog"
  recs=$(walk_records "$T/bin/prog")
  grep -qxF "D"$'\t'"$T/app [1]/lib"$'\t' <<<"$recs"
  grep -qxF "N"$'\t'"lib[1].so"$'\t'"$T/app [1]/lib/lib[1].so" <<<"$recs"
}
