#!/usr/bin/env bats
# Detection items with fake programs, a fake /proc and fake installation trees.

load test_helper

setup() {
  load_libs
  setup_fakebin
  T="$BATS_TEST_TMPDIR/tree"
  mkdir -p "$T"
}

# Fake dpkg-query: -W prints FAKE_DPKG_LINES (already formatted), -S owns nothing.
fake_dpkg_query() {
  cat >"$FAKEBIN/dpkg-query" <<'EOF'
#!/bin/sh
case "$1" in
  -W) printf '%b' "$FAKE_DPKG_LINES" ;;
  -S) exit 1 ;;
esac
EOF
  chmod +x "$FAKEBIN/dpkg-query"
}

# --- C01 -----------------------------------------------------------------------

@test "C01: Ubuntu noble packages are judged against USN-8956-1; python3-brotli gets its own finding" {
  command -v dpkg >/dev/null || skip "dpkg not available"
  fake_dpkg_query
  export FAKE_DPKG_LINES='ii \tlibbrotli1:amd64\t1.1.0-2ubuntu0.1\tbrotli\t1.1.0-2ubuntu0.1\nii \tpython3-brotli\t1.1.0-2build2\tbrotli\t1.1.0-2build2\n'
  BCC_DEB_SERIES=ubuntu:noble
  bcc_check_c01
  run findings_brief
  [[ $output == *"FIXED|C01|libbrotli1|"* ]]
  [[ $output == *"VULNERABLE|C01|python3-brotli|"* ]]
}

@test "C01: Debian trixie judges the source version (binNMU suffix on the binary is ignored)" {
  command -v dpkg >/dev/null || skip "dpkg not available"
  fake_dpkg_query
  export FAKE_DPKG_LINES='ii \tlibbrotli1:amd64\t1.1.0-2+deb13u1+b1\tbrotli\t1.1.0-2+deb13u1\nii \tpython3-brotli\t1.1.0-2\tbrotli\t1.1.0-2\n'
  BCC_DEB_SERIES=debian:trixie
  bcc_check_c01
  run findings_brief
  [[ $output == *"FIXED|C01|libbrotli1|"* ]]
  [[ $output == *"VULNERABLE|C01|python3-brotli|"* ]]
}

@test "C01: removed packages (rc) are not judged" {
  fake_dpkg_query
  export FAKE_DPKG_LINES='rc \tlibbrotli1:amd64\t1.1.0-2\tbrotli\t1.1.0-2\n'
  BCC_DEB_SERIES=debian:trixie
  bcc_check_c01
  [ "${#BCC_FINDINGS[@]}" -eq 0 ]
}

@test "C01: an unknown distribution is UNKNOWN, not guessed" {
  fake_dpkg_query
  export FAKE_DPKG_LINES='ii \tlibbrotli1\t1.1.0-1\tbrotli\t1.1.0-1\n'
  BCC_DEB_SERIES=""
  BCC_OS_ID=somedistro
  bcc_check_c01
  run findings_brief
  [[ $output == "UNKNOWN|C01|libbrotli1|"* ]]
}

@test "host: derivatives map to the archive they follow (UBUNTU_CODENAME)" {
  printf 'ID=linuxmint\nVERSION_CODENAME=xia\nUBUNTU_CODENAME=noble\nPRETTY_NAME="Linux Mint 22"\n' >"$T/os-release"
  BCC_OS_RELEASE="$T/os-release"
  bcc_init_host
  [ "$BCC_DEB_SERIES" = ubuntu:noble ]
}

# --- C02 -----------------------------------------------------------------------

@test "C02: dependents of libbrotli1 are information, not findings" {
  fake_dpkg_query
  export FAKE_DPKG_LINES='ii \tlibcurl4t64:amd64\tlibbrotli1 (>= 0.6.0), libc6\nii \tbrotli\tlibbrotli1 (= 1.1.0-2)\nii \tlibfoo\tlibbrotli1-extra\n'
  bcc_check_c02
  [ "${#BCC_FINDINGS[@]}" -eq 0 ]
  [[ ${BCC_INFO[0]} == *"libcurl4t64"* ]]
  [[ ${BCC_INFO[0]} != *"libfoo"* ]]
  [[ ${BCC_INFO[0]} != *"brotli,"* ]]
}

# --- C03 -----------------------------------------------------------------------

fake_proc() {
  P="$BATS_TEST_TMPDIR/proc"
  mkdir -p "$P/100" "$P/200" "$P/300"
  printf 'btime 1761400000\n' >"$P/stat"
  printf '7f00-7f10 r-xp 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.1.0 (deleted)\n' >"$P/100/maps"
  printf '7f00-7f10 r-xp 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.1.0\n' >"$P/200/maps"
  printf '7f00-7f10 r-xp 00000000 08:01 99 /usr/lib/python3/dist-packages/_brotli.cpython-312-x86_64-linux-gnu.so (deleted)\n' >"$P/300/maps"
  printf '100 (nginx) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5000 0\n' >"$P/100/stat"
  ln -s /usr/sbin/nginx "$P/100/exe"
  BCC_PROC_ROOT=$P
}

@test "C03: a deleted libbrotlidec or _brotli*.so mapping needs a restart; a live one does not" {
  fake_proc
  bcc_check_c03
  run findings_brief
  [[ $output == *"RESTART_REQUIRED|C03|pid 100|/usr/sbin/nginx|"* ]]
  [[ $output == *"RESTART_REQUIRED|C03|pid 300|"* ]]
  [[ $output != *"pid 200"* ]]
}

@test "C03: command lines are not shown unless --show-cmdline" {
  fake_proc
  printf 'nginx\0-g\0secret-token\0' >"$P/100/cmdline"
  bcc_check_c03
  [[ ${BCC_FINDINGS[*]} != *secret-token* ]]
  bcc_init_findings
  BCC_SHOW_CMDLINE=1
  bcc_check_c03
  [[ ${BCC_FINDINGS[*]} == *secret-token* ]]
}

@test "C03: unreadable maps are counted as not scanned" {
  [ "$(id -u)" -ne 0 ] || skip "root can read everything"
  fake_proc
  chmod 000 "$P/200/maps"
  bcc_check_c03
  [[ ${BCC_SKIPPED[*]} == *"processes that could not be read: 1"* ]]
}

# --- C04 / C05 -------------------------------------------------------------------

@test "C04: --no-exec takes the version from include/node/node_version.h" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/home/u/.nvm/versions/node/v22.23.3/bin/node"
  mkdir -p "$T/home/u/.nvm/versions/node/v22.23.3/include/node"
  printf '#define NODE_MAJOR_VERSION 22\n#define NODE_MINOR_VERSION 23\n#define NODE_PATCH_VERSION 3\n' \
    >"$T/home/u/.nvm/versions/node/v22.23.3/include/node/node_version.h"
  BCC_HOMES=("$T/home/u")
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"VULNERABLE|C04|node|$T/home/u/.nvm/versions/node/v22.23.3/bin/node|22.23.3"* ]]
  [[ ${BCC_FINDINGS[*]} == *"version via header"* ]]
}

@test "C04: --no-exec without a header falls back to the version in the path (confirmed by strings)" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/home/u/.local/share/mise/installs/node/24.22.1/bin/node" "$FIXTURES/c09/node-v24.22.1.txt"
  BCC_HOMES=("$T/home/u")
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"FIXED|C04|node|$T/home/u/.local/share/mise/installs/node/24.22.1/bin/node|24.22.1"* ]]
}

@test "C04: a version from the path that the file's strings cannot confirm is UNKNOWN, saying so" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/home/u/.local/share/mise/installs/node/24.22.1/bin/node"
  BCC_HOMES=("$T/home/u")
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"UNKNOWN|C04|node|$T/home/u/.local/share/mise/installs/node/24.22.1/bin/node|24.22.1"* ]]
  [[ ${BCC_FINDINGS[*]} == *"Not confirmed by the file"* ]]
}

@test "C04: an end-of-life line is VULNERABLE with the 'move to a supported line' advice" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/opt/node-v20.19.4-linux-x64/bin/node"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_IDX_NODE=("$T/opt/node-v20.19.4-linux-x64/bin/node")
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"VULNERABLE|C04|node|$T/opt/node-v20.19.4-linux-x64/bin/node|20.19.4"* ]]
  [[ ${BCC_FINDINGS[*]} == *"move to Node.js 22.23.4"* ]]
}

@test "C04: unknown version falls back to the C09 strings (fixed Node.js strings)" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/opt/runner/node24_alpine/bin/node" "$FIXTURES/c09/node-v22.23.4.txt"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_IDX_NODE=("$T/opt/runner/node24_alpine/bin/node")
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"LIKELY_FIXED|C04|node|$T/opt/runner/node24_alpine/bin/node|"* ]]
}

@test "C04: a node process whose executable was replaced needs a restart" {
  BCC_NO_EXEC=1
  P="$BATS_TEST_TMPDIR/proc"
  mkdir -p "$P/4242"
  ln -s "/opt/app/bin/node (deleted)" "$P/4242/exe"
  BCC_PROC_ROOT=$P
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"RESTART_REQUIRED|C04|pid 4242|/opt/app/bin/node|"* ]]
}

@test "C04: shims and scripts named node are not judged" {
  BCC_NO_EXEC=1
  mkdir -p "$T/shims"
  printf '#!/bin/sh\nexec mise x -- node "$@"\n' >"$T/shims/node"
  chmod +x "$T/shims/node"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  PATH="$T/shims:$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  [[ ${BCC_FINDINGS[*]:-} != *"$T/shims/node"* ]]
}

# A real ELF program with no Brotli in it, for links whose libraries must be followed.
plain_elf() {
  mkdir -p "$(dirname "$1")"
  cp /bin/true "$1"
  readelf -d "$1" >/dev/null 2>&1 || skip "readelf cannot read /bin/true"
}

@test "C04: a link to a program of another name is not run, and the report names it (#19)" {
  command -v readelf >/dev/null || skip "readelf not available"
  BCC_NO_EXEC=1
  plain_elf "$T/bin/mise"
  mkdir -p "$T/shims"
  ln -s ../bin/mise "$T/shims/node"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_USER_PATH="$T/shims"
  bcc_build_exec_plan
  [[ ${BCC_PLAN[*]:-} != *"$T/bin/mise"* ]]
  bcc_check_c04
  [[ ${BCC_FINDINGS[*]:-} != *"$T/bin/mise"* ]]
  [[ ${BCC_INFO[*]} == *"$T/shims/node is a link to $T/bin/mise, a program of another name"*"not judged as node"*"does not load libbrotlidec"* ]]
}

@test "C04: a link of another name to a file with a Brotli decoder is judged by its strings, not run (#19)" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/opt/app/runtime/app-runtime" "$FIXTURES/c09/node-v22.23.4.txt"
  mkdir -p "$T/opt/app/bin"
  ln -s ../runtime/app-runtime "$T/opt/app/bin/node"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_IDX_NODE=("$T/opt/app/bin/node")
  BCC_USER_PATH="$T/empty"
  bcc_build_exec_plan
  [[ ${BCC_PLAN[*]:-} != *"$T/opt/app/runtime/app-runtime"* ]]
  bcc_check_c04
  run findings_brief
  [[ $output == *"LIKELY_FIXED|C04|app-runtime|$T/opt/app/runtime/app-runtime|"* ]]
  [[ ${BCC_FINDINGS[*]} == *"Found as $T/opt/app/bin/node, a link to this program of another name: it was not run"* ]]
  # --deep does not report the same file again.
  BCC_ROOTS=("$T/opt")
  bcc_check_c09_deep
  run findings_brief
  [ "$(grep -c '|C09|.*app-runtime' <<<"$output")" -eq 0 ]
}

@test "C04: a second link to a file already judged points to it (#19)" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/opt/app/runtime/app-runtime" "$FIXTURES/c09/node-v22.23.4.txt"
  mkdir -p "$T/opt/app/bin" "$T/opt/app/sbin"
  ln -s ../runtime/app-runtime "$T/opt/app/bin/node"
  ln -s ../runtime/app-runtime "$T/opt/app/sbin/node"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_IDX_NODE=("$T/opt/app/bin/node" "$T/opt/app/sbin/node")
  BCC_USER_PATH="$T/empty"
  bcc_check_c04
  run findings_brief
  [ "$(grep -c "|$T/opt/app/runtime/app-runtime|" <<<"$output")" -eq 1 ]
  [[ ${BCC_INFO[*]} == *"$T/opt/app/sbin/node is a link to $T/opt/app/runtime/app-runtime, a program of another name: it was not run"* ]]
}

@test "C04: a link of another name to a file not read to its end is listed as not scanned (#19)" {
  BCC_NO_EXEC=1
  BCC_MAX_ELF_MB=1
  make_fake_elf "$T/bin/big"
  head -c 2097152 /dev/zero >>"$T/bin/big"
  # Its libraries cannot be followed either; what was not read comes first.
  cat >"$FAKEBIN/readelf" <<'EOF'
#!/bin/sh
exit 1
EOF
  chmod +x "$FAKEBIN/readelf"
  mkdir -p "$T/shims"
  ln -s ../bin/big "$T/shims/node"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_USER_PATH="$T/shims"
  bcc_check_c04
  [[ ${BCC_FINDINGS[*]:-} != *"$T/bin/big"* ]]
  [[ ${BCC_SKIPPED[*]} == *"$T/shims/node"$'\t'"a link to $T/bin/big, a program of another name: that file could not be read to the end"* ]]
}

@test "C04: a link of another name whose libraries could not be followed is listed as not scanned (#19)" {
  BCC_NO_EXEC=1
  # Not a real ELF: readelf cannot read it, so whether it loads libbrotlidec stays open.
  make_fake_elf "$T/bin/mise"
  mkdir -p "$T/shims"
  ln -s ../bin/mise "$T/shims/node"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_USER_PATH="$T/shims"
  bcc_check_c04
  [[ ${BCC_FINDINGS[*]:-} != *"$T/bin/mise"* ]]
  [[ ${BCC_SKIPPED[*]} == *"$T/shims/node"$'\t'"a link to $T/bin/mise, a program of another name: that file carries no Brotli decoder, but whether it loads libbrotlidec could not be followed to the end"* ]]
}

@test "C04: a link of another name to a file that loads libbrotlidec is judged by that library (#19)" {
  command -v cc >/dev/null || skip "no C compiler"
  command -v readelf >/dev/null || skip "readelf not available"
  lib=""
  for x in /usr/lib/x86_64-linux-gnu/libbrotlidec.so.1 /usr/lib/aarch64-linux-gnu/libbrotlidec.so.1; do
    [ -e "$x" ] && { lib=$x; break; }
  done
  [ -n "$lib" ] || skip "no system libbrotlidec to link against"
  BCC_NO_EXEC=1
  mkdir -p "$T/opt/app/bin" "$T/shims"
  printf 'int main(void){return 0;}\n' >"$T/m.c"
  cc -o "$T/opt/app/bin/runner" "$T/m.c" -Wl,--no-as-needed "$lib"
  readelf -d "$T/opt/app/bin/runner" | grep -q 'libbrotlidec' || skip "could not make a program that needs libbrotlidec"
  ln -s ../opt/app/bin/runner "$T/shims/node"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_USER_PATH="$T/shims"
  bcc_check_c04
  [[ ${BCC_INFO[*]} == *"$T/shims/node is a link to $T/opt/app/bin/runner, a program of another name: it was not run"* ]]
  [[ ${BCC_INFO[*]} == *"$T/opt/app/bin/runner (runner) loads "*"libbrotlidec"* ]]
}

@test "C05: a bun that is a link to a program of another name is named in the report (#19)" {
  command -v readelf >/dev/null || skip "readelf not available"
  BCC_NO_EXEC=1
  plain_elf "$T/bin/mise"
  mkdir -p "$T/shims"
  ln -s ../bin/mise "$T/shims/bun"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_USER_PATH="$T/shims"
  bcc_check_c05
  [[ ${BCC_FINDINGS[*]:-} != *"$T/bin/mise"* ]]
  [[ ${BCC_INFO[*]} == *"$T/shims/bun is a link to $T/bin/mise, a program of another name"*"not judged as bun"* ]]
  [[ $'\n'"$(printf '%s\n' "${BCC_INFO[@]}")" == *$'\n'"C05"$'\t'"$T/shims/bun is a link"* ]]
}

@test "C04: a node chosen to run gives its version through --version" {
  command -v cc >/dev/null || skip "no C compiler to build a stand-in node"
  mkdir -p "$T/n/bin"
  printf '#include <stdio.h>\nint main(void){puts("v24.22.0");return 0;}\n' >"$T/stub.c"
  cc -o "$T/n/bin/node" "$T/stub.c"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_IDX_NODE=("$T/n/bin/node")
  bcc_plan_add "$T/n/bin/node" --version "C04 node"
  BCC_PLAN_OK["$T/n/bin/node"$'\t'--version]=1
  bcc_exec_run
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"VULNERABLE|C04|node|$T/n/bin/node|24.22.0"* ]]
  [[ ${BCC_FINDINGS[*]} == *"version via exec"* ]]
}

@test "C04: a program under a world-writable directory is named so, and is not run without consent" {
  command -v cc >/dev/null || skip "no C compiler"
  mkdir -p "$T/opt/n/bin"
  printf '#include <stdio.h>\nint main(void){puts("v24.22.1");return 0;}\n' >"$T/stub.c"
  cc -o "$T/opt/n/bin/node" "$T/stub.c"
  chmod 777 "$T/opt"
  bcc_exec_facts "$T/opt/n/bin/node"
  [[ " ${BCC_FACTS[*]} " == *"$T/opt can be written by anyone"* ]]
  bcc_plan_add "$T/opt/n/bin/node" --version "C04 node"
  bcc_exec_run
  run bcc_probe "$T/opt/n/bin/node" --version
  [ "$status" -eq 125 ]
  [ -z "$output" ]
}

@test "exec safety: a directory writable only by your own private group is fine" {
  SAFE="$REPO_ROOT/tests/tmp/$BATS_TEST_NUMBER-$$"
  mkdir -p "$SAFE/d"
  chmod 755 "$REPO_ROOT/tests/tmp" "$SAFE"
  chmod 775 "$SAFE/d"
  cp /bin/true "$SAFE/d/prog"
  bcc_group_is_private "$(id -u)" "$(stat -c %g "$SAFE/d")" || { rm -rf "$SAFE"; skip "primary group is shared"; }
  run bcc_safe_to_exec "$SAFE/d/prog"
  rm -rf "$SAFE"
  [ "$status" -eq 0 ]
}

@test "exec safety: as root, a program owned by an ordinary user is never run" {
  [ "$(id -u)" -ne 0 ] || skip "needs a non-root test user"
  SAFE="$REPO_ROOT/tests/tmp/$BATS_TEST_NUMBER-$$"
  mkdir -p "$SAFE"
  chmod 755 "$REPO_ROOT/tests/tmp" "$SAFE"
  cp /bin/true "$SAFE/prog"
  run bcc_safe_to_exec "$SAFE/prog"
  [ "$status" -eq 0 ]
  run bcc_safe_to_exec "$SAFE/prog" 0
  rm -rf "$SAFE"
  [ "$status" -eq 1 ]
}

@test "exec safety: a path through a symlink is refused (checked path = executed path)" {
  SAFE="$REPO_ROOT/tests/tmp/$BATS_TEST_NUMBER-$$"
  mkdir -p "$SAFE"
  chmod 755 "$REPO_ROOT/tests/tmp" "$SAFE"
  cp /bin/true "$SAFE/real"
  ln -s "$SAFE/real" "$SAFE/link"
  run bcc_safe_to_exec "$SAFE/link"
  rm -rf "$SAFE"
  [ "$status" -eq 1 ]
}

@test "C05: Bun 1.0.20 is before the advisory's range: UNKNOWN, with the same advice to update" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/home/u/.local/share/mise/installs/bun/1.0.20/bin/bun"
  BCC_HOMES=("$T/home/u")
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c05
  run findings_brief
  [[ $output == *"UNKNOWN|C05|bun|$T/home/u/.local/share/mise/installs/bun/1.0.20/bin/bun|1.0.20"* ]]
  [[ ${BCC_FINDINGS[*]} == *"GHSA-663w-cv8g-jj2p"* ]]
  [[ ${BCC_FINDINGS[*]} == *"Update to 1.4.4 or later."* ]]
  # The data's note mentions "bun build --compile" too: look for the words of the next step.
  [[ ${BCC_FINDINGS[*]} == *"keep the Bun they were built with"* ]]
}

@test "C05: Bun 1.4.3 is VULNERABLE and the advice mentions compiled executables" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/home/u/.local/share/mise/installs/bun/1.4.3/bin/bun"
  BCC_HOMES=("$T/home/u")
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c05
  run findings_brief
  [[ $output == *"VULNERABLE|C05|bun|$T/home/u/.local/share/mise/installs/bun/1.4.3/bin/bun|1.4.3"* ]]
  [[ ${BCC_FINDINGS[*]} == *"bun build --compile"* ]]
}

# --- C06 / C07 -------------------------------------------------------------------

make_dist_info() { # site name version
  mkdir -p "$1/$2-$3.dist-info"
  printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\n' "$2" "$3" >"$1/$2-$3.dist-info/METADATA"
}

@test "C06: PyPI Brotli 1.2.0 is VULNERABLE, brotlicffi 1.2.1.0 is FIXED, and HTTP clients are EXPOSURE" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" Brotli 1.2.0
  make_dist_info "$T/srv/venv2/lib/python3.12/site-packages" brotlicffi 1.2.1.0
  make_fake_elf "$T/srv/venv2/lib/python3.12/site-packages/brotlicffi/_brotlicffi.abi3.so" "$FIXTURES/c09/pypi-brotlicffi-1.2.1.0.txt"
  make_dist_info "$site" urllib3 2.2.0
  make_dist_info "$site" aiohttp 3.9.0
  BCC_IDX_PY=("$site/Brotli-1.2.0.dist-info" "$T/srv/venv2/lib/python3.12/site-packages/brotlicffi-1.2.1.0.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"VULNERABLE|C06|Brotli|$site/Brotli-1.2.0.dist-info|1.2.0"* ]]
  [[ $output == *"FIXED|C06|brotlicffi|"* ]]
  [[ $output == *"EXPOSURE|C06|python-http-clients|$site|"* ]]
  [[ ${BCC_FINDINGS[*]} == *"aiohttp.web servers"* ]]
}

@test "C06: an egg-info file (not directory) is read too" {
  site="$T/usr/local/lib/python3.12/dist-packages"
  mkdir -p "$site"
  printf 'Name: Brotli\nVersion: 1.0.9\n' >"$site/Brotli-1.0.9.egg-info"
  BCC_IDX_PY=("$site/Brotli-1.0.9.egg-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  [[ ${BCC_FINDINGS[0]} == *VULNERABLE* ]]
}

@test "C06: PyPI Brotli before the range is UNKNOWN for that reason, and gets the pip command" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" Brotli 1.0.1
  BCC_IDX_PY=("$site/Brotli-1.0.1.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|Brotli|$site/Brotli-1.0.1.dist-info|1.0.1"* ]]
  [[ ${BCC_FINDINGS[*]} == *"GHSA-9v8h-qqgm-4m35"* ]]
  [[ ${BCC_FINDINGS[*]} == *'pip install -U "brotli>=1.2.1"'* ]]
  # It is not the missing-module case: there the version is at or above the fix.
  [[ ${BCC_FINDINGS[*]} != *"no extension module"* ]]
}

@test "C06: PyPI Brotli before the range in a vendor's package is sent to that package, not pip" {
  site="$T/opt/agent/lib/python3.12/site-packages"
  make_dist_info "$site" Brotli 1.0.1
  bcc_dpkg_owner() { printf 'vendor-agent'; }
  bcc_covered_by_c01() { return 1; }
  BCC_IDX_PY=("$site/Brotli-1.0.1.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|Brotli|$site/Brotli-1.0.1.dist-info|1.0.1"* ]]
  [[ ${BCC_FINDINGS[*]} == *"belongs to the package vendor-agent"* ]]
  [[ ${BCC_FINDINGS[*]} != *"pip install"* ]]
}

@test "C06: conda libbrotlidec before the range is UNKNOWN, and gets the conda command" {
  mkdir -p "$T/opt/conda/conda-meta"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.0.2-h0_0.json"
  BCC_IDX_PY=()
  BCC_IDX_CONDA=("$T/opt/conda/conda-meta/libbrotlidec-1.0.2-h0_0.json")
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|conda:libbrotlidec|"*"|1.0.2"* ]]
  [[ ${BCC_FINDINGS[*]} == *"conda update -p"* ]]
}

@test "C06: conda libbrotlidec is judged by its series" {
  mkdir -p "$T/opt/conda/conda-meta"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.1.1-hb9d3cd8_0.json"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.0.9-h166bdaf_9.json"
  make_fake_elf "$T/opt/conda/lib/libbrotlidec.so.1.1.1" "$FIXTURES/c09/shared-1.2.1-nostrip.txt"
  BCC_IDX_PY=()
  BCC_IDX_CONDA=("$T/opt/conda/conda-meta/libbrotlidec-1.1.1-hb9d3cd8_0.json" "$T/opt/conda/conda-meta/libbrotlidec-1.0.9-h166bdaf_9.json")
  bcc_check_c06
  run findings_brief
  [[ $output == *"FIXED|C06|conda:libbrotlidec|"*"|1.1.1"* ]]
  [[ $output == *"VULNERABLE|C06|conda:libbrotlidec|"*"|1.0.9"* ]]
}

@test "index: package-manager caches are not reported" {
  mkdir -p "$T/home/u/.cache/uv/archive-v0/x/playwright/driver"
  make_fake_elf "$T/home/u/.cache/uv/archive-v0/x/playwright/driver/node"
  make_dist_info "$T/home/u/.cache/uv/archive-v0/y" brotli 1.2.0
  # The index also covers system Python and /usr/lib, which may hold caches of their own (a CI
  # runner image did): count what the test tree adds, not the host's total.
  BCC_ROOTS=()
  bcc_build_index
  base=$BCC_IDX_CACHED
  BCC_ROOTS=("$T/home")
  bcc_build_index
  [[ " ${BCC_IDX_NODE[*]:-} ${BCC_IDX_PY[*]:-} " != *"$T"* ]]
  [ $((BCC_IDX_CACHED - base)) -eq 2 ]
}

@test "C07: inbound and outbound decoding packages are exposure hints" {
  nm="$T/srv/app/node_modules"
  mkdir -p "$nm/body-parser" "$nm/express" "$nm/axios"
  printf '{ "name": "body-parser", "version": "2.2.0" }\n' >"$nm/body-parser/package.json"
  printf '{ "name": "express", "version": "4.21.2" }\n' >"$nm/express/package.json"
  printf '{ "name": "axios", "version": "1.7.9" }\n' >"$nm/axios/package.json"
  BCC_ROOTS=("$T/srv")
  bcc_check_c07
  [ "${#BCC_FINDINGS[@]}" -eq 1 ]
  [[ ${BCC_FINDINGS[0]} == *"body-parser@2.2.0"* ]]
  [[ ${BCC_FINDINGS[0]} != *"express@4"* ]]
  [[ ${BCC_FINDINGS[0]} == *"axios@1.7.9"* ]]
}

# --- C09 libraries by name ---------------------------------------------------------

@test "C09: libbrotlidec named 1.2.1 with fixed strings is FIXED" {
  f="$T/opt/app/lib/libbrotlidec.so.1.2.1"
  mkdir -p "${f%/*}"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.1-nostrip.txt" >"$f"
  BCC_IDX_LIB=("$f")
  bcc_check_c09_libs
  [[ ${BCC_FINDINGS[0]} == C09$'\t'FIXED* ]]
}

@test "C09: libbrotlidec before the range is UNKNOWN, and says what to replace it with" {
  local v
  for v in 1.0.2 0.6.0; do
    f="$T/opt/app-$v/lib/libbrotlidec.so.$v"
    mkdir -p "${f%/*}"
    tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$f"
    BCC_IDX_LIB=("$f")
    bcc_init_findings
    bcc_check_c09_libs
    [[ ${BCC_FINDINGS[0]} == C09$'\t'UNKNOWN* ]]
    [[ ${BCC_FINDINGS[0]} == *"GHSA-9v8h-qqgm-4m35"* ]]
    [[ ${BCC_FINDINGS[0]} == *"with Brotli 1.0.10 or later"* ]]
  done
}

@test "C09: file name and strings disagree -> UNKNOWN (possibly a patched build)" {
  f="$T/opt/app/lib/libbrotlidec.so.1.2.0"
  mkdir -p "${f%/*}"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.1-nostrip.txt" >"$f"
  BCC_IDX_LIB=("$f")
  bcc_check_c09_libs
  [[ ${BCC_FINDINGS[0]} == C09$'\t'UNKNOWN* ]]
}

@test "C09: no version in the name -> judged by strings" {
  f="$T/opt/app/pillow.libs/libbrotlidec-ba690955.so.1"
  mkdir -p "${f%/*}"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$f"
  BCC_IDX_LIB=("$f")
  bcc_check_c09_libs
  [[ ${BCC_FINDINGS[0]} == C09$'\t'LIKELY_VULNERABLE* ]]
}

@test "C09 --deep: a bundled decoder in an unknown ELF file is reported; a dynamic user is not" {
  command -v readelf >/dev/null || skip "readelf not available"
  make_fake_elf "$T/srv/app/bin/server" "$FIXTURES/c09/static-1.2.0-O2-p2-nostrip.txt"
  printf 'BrotliDecoderDecompressStream\0' >>"$T/srv/app/bin/server"
  BCC_ROOTS=("$T/srv")
  bcc_check_c09_deep
  run findings_brief
  [[ $output == *"LIKELY_VULNERABLE|C09|server|$T/srv/app/bin/server|"* ]]
}

@test "C09 --deep: the extension module of a Brotli that C06 judged is not reported twice" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" Brotli 1.2.0
  make_fake_elf "$site/_brotli.cpython-312-x86_64-linux-gnu.so" "$FIXTURES/c09/pypi-Brotli-1.2.0.txt"
  printf 'BrotliDecoderDecompressStream\0' >>"$site/_brotli.cpython-312-x86_64-linux-gnu.so"
  BCC_IDX_PY=("$site/Brotli-1.2.0.dist-info")
  BCC_IDX_CONDA=()
  BCC_ROOTS=("$T/srv")
  bcc_check_c06
  bcc_check_c09_deep
  run findings_brief
  [[ $output == *"VULNERABLE|C06|Brotli|"* ]]
  [[ $output != *"|C09|"* ]]
}

# --- Codex review regressions (2026-10-26) --------------------------------------------

@test "lookup keeps the caller's BCC_F (judging must not clobber parsed fields)" {
  bcc_split_tab $'NODE\t/usr/local/bin/node\tv22.23.3'
  bcc_judge node 22 semver 22.23.3
  [ "${BCC_F[1]}" = /usr/local/bin/node ]
}

@test "C14: two node copies in one container are both reported (no dedup collision)" {
  cat >"$FAKEBIN/docker" <<'EOF'
#!/bin/sh
printf 'OS\tdebian\ttrixie\t\nNODE\t/opt/a/bin/node\tv22.23.4\nNODE\t/opt/b/bin/node\tv22.23.3\n'
EOF
  chmod +x "$FAKEBIN/docker"
  bcc_c14_inspect docker 0123abcd web img:1
  run findings_brief
  [[ $output == *"FIXED|C14|node|container web (img:1) /opt/a/bin/node|22.23.4"* ]]
  [[ $output == *"VULNERABLE|C14|node|container web (img:1) /opt/b/bin/node|22.23.3"* ]]
}

@test "linkage that cannot be followed is undetermined (2), never 'not linked'" {
  command -v readelf >/dev/null || skip "readelf not available"
  BCC_NO_EXEC=1
  make_fake_elf "$T/broken"
  run bcc_links_brotlidec "$T/broken"
  [ "$status" -eq 2 ]
}

@test "C04: a path saying 22.23.4 over an unfixed decoder is UNKNOWN, not FIXED" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/opt/node-v22.23.4-linux-x64/bin/node" "$FIXTURES/c09/node-v22.23.3.txt"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_IDX_NODE=("$T/opt/node-v22.23.4-linux-x64/bin/node")
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"UNKNOWN|C04|node|$T/opt/node-v22.23.4-linux-x64/bin/node|22.23.4"* ]]
}

@test "C06: metadata saying 1.2.1 over an unfixed _brotli module is UNKNOWN, not FIXED" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" Brotli 1.2.1
  tr '\n' '\0' <"$FIXTURES/c09/pypi-Brotli-1.2.0.txt" >"$site/_brotli.cpython-312-x86_64-linux-gnu.so"
  BCC_IDX_PY=("$site/Brotli-1.2.1.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|Brotli|"* ]]
  [[ $output != *"FIXED|C06|Brotli|"* ]]
}

# One finding's reason and next step, for assertions on the wording.
finding_reason() { bcc_split_tab "${BCC_FINDINGS[0]}"; printf '%s' "${BCC_F[5]}"; }
finding_next() { bcc_split_tab "${BCC_FINDINGS[0]}"; printf '%s' "${BCC_F[6]}"; }

@test "C06: Brotli metadata saying 1.2.1 with no extension module is UNKNOWN, and says so" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" Brotli 1.2.1
  BCC_IDX_PY=("$site/Brotli-1.2.1.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [ "$output" = "UNKNOWN|C06|Brotli|$site/Brotli-1.2.1.dist-info|1.2.1" ]
  [[ $(finding_reason) == *"the metadata says version 1.2.1, but no extension module was found to compare (_brotli.*so)"* ]]
  [[ $(finding_next) == *"reinstall the package"* ]]
}

@test "C06: brotlicffi metadata saying 1.2.1.0 with no extension module is UNKNOWN, and says so" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" brotlicffi 1.2.1.0
  BCC_IDX_PY=("$site/brotlicffi-1.2.1.0.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [ "$output" = "UNKNOWN|C06|brotlicffi|$site/brotlicffi-1.2.1.0.dist-info|1.2.1.0" ]
  [[ $(finding_reason) == *"no extension module was found to compare (brotlicffi/_brotlicffi*.so)"* ]]
}

@test "C06: an extension module that is a dangling symlink is not a file to compare" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" Brotli 1.2.1
  ln -s nowhere.so "$site/_brotli.cpython-312-x86_64-linux-gnu.so"
  BCC_IDX_PY=("$site/Brotli-1.2.1.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|Brotli|"* ]]
  [[ $(finding_reason) == *"no extension module was found"* ]]
}

@test "C06: another package's module in the same site confirms nothing" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" brotlicffi 1.2.1.0
  make_fake_elf "$site/_brotli.cpython-312-x86_64-linux-gnu.so" "$FIXTURES/c09/pypi-Brotli-1.2.1.txt"
  BCC_IDX_PY=("$site/brotlicffi-1.2.1.0.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|brotlicffi|"* ]]
  [[ $(finding_reason) == *"no extension module was found"* ]]
}

@test "C06: another package's unfixed module does not cast doubt on a confirmed one" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" brotlicffi 1.2.1.0
  make_fake_elf "$site/brotlicffi/_brotlicffi.abi3.so" "$FIXTURES/c09/pypi-brotlicffi-1.2.1.0.txt"
  make_fake_elf "$site/_brotli.cpython-312-x86_64-linux-gnu.so" "$FIXTURES/c09/pypi-Brotli-1.2.0.txt"
  BCC_IDX_PY=("$site/brotlicffi-1.2.1.0.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"FIXED|C06|brotlicffi|"* ]]
}

@test "C09 --deep: a module of a package C06 did not judge in that site is still looked at" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" brotlicffi 1.2.1.0
  make_fake_elf "$site/brotlicffi/_brotlicffi.abi3.so" "$FIXTURES/c09/pypi-brotlicffi-1.2.1.0.txt"
  make_fake_elf "$site/_brotli.cpython-312-x86_64-linux-gnu.so" "$FIXTURES/c09/pypi-Brotli-1.2.0.txt"
  printf 'BrotliDecoderDecompressStream\0' >>"$site/_brotli.cpython-312-x86_64-linux-gnu.so"
  BCC_IDX_PY=("$site/brotlicffi-1.2.1.0.dist-info")
  BCC_IDX_CONDA=()
  BCC_ROOTS=("$T/srv")
  bcc_check_c06
  bcc_check_c09_deep
  run findings_brief
  [[ $output == *"LIKELY_VULNERABLE|C09|"*"_brotli.cpython-312-x86_64-linux-gnu.so"* ]]
  [[ $output != *"|C09|"*"_brotlicffi.abi3.so"* ]]
}

@test "C06: Brotli and brotlicffi metadata with their fixed modules stay FIXED" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" Brotli 1.2.1
  make_dist_info "$site" brotlicffi 1.2.1.0
  make_fake_elf "$site/_brotli.cpython-312-x86_64-linux-gnu.so" "$FIXTURES/c09/pypi-Brotli-1.2.1.txt"
  make_fake_elf "$site/brotlicffi/_brotlicffi.abi3.so" "$FIXTURES/c09/pypi-brotlicffi-1.2.1.0.txt"
  BCC_IDX_PY=("$site/Brotli-1.2.1.dist-info" "$site/brotlicffi-1.2.1.0.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"FIXED|C06|Brotli|$site/Brotli-1.2.1.dist-info|1.2.1"* ]]
  [[ $output == *"FIXED|C06|brotlicffi|$site/brotlicffi-1.2.1.0.dist-info|1.2.1.0"* ]]
}

@test "C06: a site path holding glob characters is taken literally" {
  site="$T/srv/ve[n]v/lib/python3.12/site-packages"
  make_dist_info "$site" Brotli 1.2.1
  make_fake_elf "$site/_brotli.cpython-312-x86_64-linux-gnu.so" "$FIXTURES/c09/pypi-Brotli-1.2.1.txt"
  BCC_IDX_PY=("$site/Brotli-1.2.1.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"FIXED|C06|Brotli|"* ]]
}

@test "C06: Brotli metadata below the fix with no extension module stays VULNERABLE" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" Brotli 1.2.0
  BCC_IDX_PY=("$site/Brotli-1.2.0.dist-info")
  BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"VULNERABLE|C06|Brotli|"* ]]
  [[ $(finding_reason) != *"no extension module"* ]]
  [[ $(finding_next) == *"pip install -U"* ]]
}

@test "C06: a conda record saying 1.2.1 with no lib/ is UNKNOWN, and says so" {
  mkdir -p "$T/opt/conda/conda-meta"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json"
  BCC_IDX_PY=()
  BCC_IDX_CONDA=("$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json")
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|conda:libbrotlidec|"*"|1.2.1"* ]]
  [[ $(finding_reason) == *"the conda record says version 1.2.1, but no shared library was found to compare (lib/libbrotlidec.so.*, not counting symbolic links)"* ]]
  [[ $(finding_next) == *"reinstall the package"* ]]
}

@test "C06: a conda record with only a dangling symlink in lib/ is UNKNOWN, and says so" {
  mkdir -p "$T/opt/conda/conda-meta" "$T/opt/conda/lib"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json"
  ln -s libbrotlidec.so.1.2.1 "$T/opt/conda/lib/libbrotlidec.so.1"
  BCC_IDX_PY=()
  BCC_IDX_CONDA=("$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json")
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|conda:libbrotlidec|"*"|1.2.1"* ]]
  [[ $(finding_reason) == *"no shared library was found to compare"* ]]
}

@test "C06: a conda record with only a symlink to a real library outside the glob is UNKNOWN" {
  mkdir -p "$T/opt/conda/conda-meta" "$T/opt/conda/lib"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json"
  make_fake_elf "$T/opt/conda/pkgs/libbrotlidec.so.1.2.1" "$FIXTURES/c09/shared-1.2.1-nostrip.txt"
  ln -s ../pkgs/libbrotlidec.so.1.2.1 "$T/opt/conda/lib/libbrotlidec.so.1"
  BCC_IDX_PY=()
  BCC_IDX_CONDA=("$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json")
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|conda:libbrotlidec|"*"|1.2.1"* ]]
}

@test "C06: a conda record with an unfixed library stays UNKNOWN, for that reason" {
  mkdir -p "$T/opt/conda/conda-meta"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json"
  make_fake_elf "$T/opt/conda/lib/libbrotlidec.so.1.2.1" "$FIXTURES/c09/shared-1.2.0-nostrip.txt"
  BCC_IDX_PY=()
  BCC_IDX_CONDA=("$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json")
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|conda:libbrotlidec|"*"|1.2.1"* ]]
  [[ $(finding_reason) == *"lacks the fix's error name"* ]]
  [[ $(finding_reason) != *"no shared library"* ]]
}

@test "C06: a conda record with a fixed library and its symlink stays FIXED" {
  mkdir -p "$T/opt/conda/conda-meta"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json"
  make_fake_elf "$T/opt/conda/lib/libbrotlidec.so.1.2.1" "$FIXTURES/c09/shared-1.2.1-nostrip.txt"
  ln -s libbrotlidec.so.1.2.1 "$T/opt/conda/lib/libbrotlidec.so.1"
  BCC_IDX_PY=()
  BCC_IDX_CONDA=("$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json")
  bcc_check_c06
  run findings_brief
  [[ $output == *"FIXED|C06|conda:libbrotlidec|"*"|1.2.1"* ]]
}

@test "C06: a conda environment path holding glob characters is taken literally" {
  mkdir -p "$T/opt/con[d]a/conda-meta"
  : >"$T/opt/con[d]a/conda-meta/libbrotlidec-1.2.1-h0_0.json"
  make_fake_elf "$T/opt/con[d]a/lib/libbrotlidec.so.1.2.1" "$FIXTURES/c09/shared-1.2.1-nostrip.txt"
  BCC_IDX_PY=()
  BCC_IDX_CONDA=("$T/opt/con[d]a/conda-meta/libbrotlidec-1.2.1-h0_0.json")
  bcc_check_c06
  run findings_brief
  [[ $output == *"FIXED|C06|conda:libbrotlidec|"*"|1.2.1"* ]]
}

@test "C06: a conda record below the fix with no lib/ stays VULNERABLE" {
  mkdir -p "$T/opt/conda/conda-meta"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.2.0-h0_0.json"
  BCC_IDX_PY=()
  BCC_IDX_CONDA=("$T/opt/conda/conda-meta/libbrotlidec-1.2.0-h0_0.json")
  bcc_check_c06
  run findings_brief
  [[ $output == *"VULNERABLE|C06|conda:libbrotlidec|"*"|1.2.0"* ]]
  [[ $(finding_next) == *"conda update"* ]]
}

@test "C14: Python metadata saying 1.2.1 inside a container is UNKNOWN, and says so" {
  cat >"$FAKEBIN/docker" <<'EOF'
#!/bin/sh
printf 'OS\tdebian\ttrixie\t\nPKGRC\t1\nPY\t/usr/local/lib/python3.12/site-packages/Brotli-1.2.1.dist-info/METADATA\tBrotli\t1.2.1\nEND\n'
EOF
  chmod +x "$FAKEBIN/docker"
  bcc_c14_inspect docker 0123abcd web img:1
  run findings_brief
  [ "$output" = "UNKNOWN|C14|Brotli|container web (img:1) /usr/local/lib/python3.12/site-packages/Brotli-1.2.1.dist-info|1.2.1" ]
  [[ $(finding_reason) == *"the metadata inside the container says version 1.2.1; the check inside containers does not compare the strings"* ]]
  [[ $(finding_next) == *"Ask the vendor or maintainer"* ]]
}

@test "C14: Python metadata below the fix inside a container stays VULNERABLE, with its next step" {
  cat >"$FAKEBIN/docker" <<'EOF'
#!/bin/sh
printf 'OS\tdebian\ttrixie\t\nPKGRC\t1\nPY\t/usr/local/lib/python3.12/site-packages/brotlicffi-1.2.0.2.dist-info/METADATA\tbrotlicffi\t1.2.0.2\nEND\n'
EOF
  chmod +x "$FAKEBIN/docker"
  bcc_c14_inspect docker 0123abcd web img:1
  run findings_brief
  [[ $output == *"VULNERABLE|C14|brotlicffi|"* ]]
  [[ $(finding_next) == *"rebuild the image"* ]]
}

@test "the reasons for a missing file are in Japanese too" {
  BCC_LANG=ja
  site="$T/srv/venv/lib/python3.12/site-packages"
  make_dist_info "$site" Brotli 1.2.1
  mkdir -p "$T/opt/conda/conda-meta"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json"
  BCC_IDX_PY=("$site/Brotli-1.2.1.dist-info")
  BCC_IDX_CONDA=("$T/opt/conda/conda-meta/libbrotlidec-1.2.1-h0_0.json")
  bcc_check_c06
  [[ ${BCC_FINDINGS[*]} == *"メタデータの版は 1.2.1 だが、照合する拡張モジュールが見つからなかった"* ]]
  [[ ${BCC_FINDINGS[*]} == *"conda の記録の版は 1.2.1 だが、照合する共有ライブラリが見つからなかった"* ]]
}

# --- C10 / C13 ----------------------------------------------------------------------

@test "C10: Envoy 1.35 is VULNERABLE, says why, and names lines to move to" {
  # bcc_probe is the only way to the version; what it runs is covered by the exec tests.
  bcc_probe() { printf '%s\n' "envoy  version: 0123456789abcdef0123456789abcdef01234567/1.35.0/Clean/RELEASE/BoringSSL"; }
  BCC_C10_CANDS=("$T/envoy") BCC_C10_DONE=1
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c10
  run findings_brief
  [[ $output == *"VULNERABLE|C10|envoy|$T/envoy|1.35.0"* ]]
  [[ ${BCC_FINDINGS[*]} == *"affected range"* ]]
  [[ ${BCC_FINDINGS[*]} == *"move to Envoy 1.36.12"* ]]
  [[ ${BCC_FINDINGS[*]} != *"Update to - or later"* ]]
}

@test "C10: an Envoy configuration with a Brotli decompressor is EXPOSURE" {
  printf 'name: envoy.filters.http.decompressor\ntyped_config:\n  decompressor_library:\n    name: envoy.compression.brotli.decompressor\n' >"$T/envoy.yaml"
  BCC_ENVOY_CONFIG="$T/envoy.yaml"
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c10
  run findings_brief
  [[ $output == *"EXPOSURE|C10|envoy-config|$T/envoy.yaml|"* ]]
}

@test "C13: Chromium needs a four-part version; 148 before branch 7778 is UNKNOWN" {
  bcc_browser_judge chromium "148.0.7728.2"
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_browser_judge chromium "148.0.7778.96"
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_browser_judge chromium "147.0.7727.116"
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_browser_judge chromium "070714.619358"
  [ "$BCC_J_STATUS" = UNKNOWN ]
}

@test "C13: Firefox and Firefox ESR use their own thresholds" {
  bcc_browser_judge firefox "150.0.1"
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_browser_judge firefox "149.0"
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_browser_judge firefox "140.10.0esr"
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_browser_judge firefox "140.9.0esr"
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_browser_judge firefox "153.0esr"
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_browser_judge firefox "153.6.0esr"
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_browser_judge firefox "115.35.0esr"
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_browser_judge firefox "115.34.0esr"
  [ "$BCC_J_STATUS" = VULNERABLE ]
}
