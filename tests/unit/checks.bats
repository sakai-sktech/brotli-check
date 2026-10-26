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

@test "C01: Ubuntu noble packages are NO_FIX_AVAILABLE; python3-brotli gets its own finding" {
  fake_dpkg_query
  export FAKE_DPKG_LINES='ii \tlibbrotli1:amd64\t1.1.0-2build2\tbrotli\t1.1.0-2build2\nii \tpython3-brotli\t1.1.0-2build2\tbrotli\t1.1.0-2build2\n'
  BCC_DEB_SERIES=ubuntu:noble
  bcc_check_c01
  run findings_brief
  [[ $output == *"NO_FIX_AVAILABLE|C01|libbrotli1|"* ]]
  [[ $output == *"NO_FIX_AVAILABLE|C01|python3-brotli|"* ]]
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

@test "C04: --no-exec without a header falls back to the version in the path" {
  BCC_NO_EXEC=1
  make_fake_elf "$T/home/u/.local/share/mise/installs/node/24.22.1/bin/node"
  BCC_HOMES=("$T/home/u")
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"FIXED|C04|node|$T/home/u/.local/share/mise/installs/node/24.22.1/bin/node|24.22.1"* ]]
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

@test "C04: a real node --version is used when the file is safe to run" {
  command -v cc >/dev/null || skip "no C compiler to build a stand-in node"
  # Under the repository (owned by the test user), not under /tmp (world-writable).
  SAFE="$REPO_ROOT/tests/tmp/$BATS_TEST_NUMBER-$$"
  mkdir -p "$SAFE/n/bin"
  chmod 755 "$REPO_ROOT/tests/tmp" "$SAFE" "$SAFE/n" "$SAFE/n/bin"
  printf '#include <stdio.h>\nint main(void){puts("v24.22.0");return 0;}\n' >"$SAFE/stub.c"
  cc -o "$SAFE/n/bin/node" "$SAFE/stub.c"
  bcc_safe_to_exec "$SAFE/n/bin/node" >/dev/null || { rm -rf "$SAFE"; skip "repository path is writable by others"; }
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
  BCC_IDX_NODE=("$SAFE/n/bin/node")
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  rm -rf "$SAFE"
  [[ $output == *"VULNERABLE|C04|node|$SAFE/n/bin/node|24.22.0"* ]]
  [[ ${BCC_FINDINGS[*]} == *"version via exec"* ]]
}

@test "C04: a program under a world-writable directory is never run" {
  command -v cc >/dev/null || skip "no C compiler"
  mkdir -p "$T/opt/n/bin"
  printf '#include <stdio.h>\nint main(void){puts("v24.22.1");return 0;}\n' >"$T/stub.c"
  cc -o "$T/opt/n/bin/node" "$T/stub.c"
  chmod 777 "$T/opt"
  run bcc_probe "$T/opt/n/bin/node" --version
  [ "$status" -eq 126 ]
  [ -z "$output" ]
  run bcc_safe_to_exec "$T/opt/n/bin/node"
  [ "$status" -eq 1 ]
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

@test "C06: conda libbrotlidec is judged by its series" {
  mkdir -p "$T/opt/conda/conda-meta"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.1.1-hb9d3cd8_0.json"
  : >"$T/opt/conda/conda-meta/libbrotlidec-1.0.9-h166bdaf_9.json"
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
  BCC_ROOTS=("$T/home")
  bcc_build_index
  # The index also covers system Python and /usr/lib; only the test tree matters here.
  [[ " ${BCC_IDX_NODE[*]:-} ${BCC_IDX_PY[*]:-} " != *"$T"* ]]
  [ "$BCC_IDX_CACHED" -eq 2 ]
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

# --- C10 / C13 ----------------------------------------------------------------------

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
}
