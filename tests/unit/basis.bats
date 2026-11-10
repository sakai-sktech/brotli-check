#!/usr/bin/env bats
# Issue #9: a FIXED line says where its version came from (docs/design.md 10.25) - the package,
# a program's output, or a file whose decoder strings confirmed the fix, with what those strings
# do not show - and its next step is for that line only. Every path that can give FIXED is here.
# shellcheck disable=SC2317  # stand-ins for library functions are called by the code under test

load test_helper

setup() {
  load_libs
  setup_fakebin
  T="$BATS_TEST_TMPDIR/tree"
  mkdir -p "$T"
  BCC_PROC_ROOT="$BATS_TEST_TMPDIR/emptyproc"
  mkdir -p "$BCC_PROC_ROOT"
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

# Reason and next step of the finding whose component is COMPONENT (the first one).
reason_of() {
  local f
  for f in "${BCC_FINDINGS[@]}"; do
    bcc_split_tab "$f"
    [[ ${BCC_F[2]} == "$1" ]] && { printf '%s' "${BCC_F[5]}"; return 0; }
  done
  return 1
}
next_of() {
  local f
  for f in "${BCC_FINDINGS[@]}"; do
    bcc_split_tab "$f"
    [[ ${BCC_F[2]} == "$1" ]] && { printf '%s' "${BCC_F[6]}"; return 0; }
  done
  return 1
}

FOUND_THIS='Found: the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH) among the decoder strings of this file.'
UNSEEN='Not determined: whether all decoder code in the file is fixed (the linker merges equal strings, so an unfixed copy sharing them would not show).'
NEXT_FIXED='No update needed for this line (other lines, and the ranges not scanned or that could not be scanned, are separate).'

# --- the distribution's packages ------------------------------------------------------

@test "#9 C01: a fixed package rests on the distribution package version; the next step keeps the restart" {
  command -v dpkg >/dev/null || skip "dpkg not available"
  fake_dpkg_query
  export FAKE_DPKG_LINES='ii \tlibbrotli1:amd64\t1.1.0-2ubuntu0.1\tbrotli\t1.1.0-2ubuntu0.1\n'
  BCC_DEB_SERIES=ubuntu:noble
  bcc_check_c01
  [ "$(reason_of libbrotli1)" = "At or above the fixed version 1.1.0-2ubuntu0.1 (the distribution package version)." ]
  [ "$(next_of libbrotli1)" = "$NEXT_FIXED If it was updated recently, restart the services that use it (C03)." ]
}

@test "#9 C01: the same in Japanese" {
  command -v dpkg >/dev/null || skip "dpkg not available"
  BCC_LANG=ja
  fake_dpkg_query
  export FAKE_DPKG_LINES='ii \tlibbrotli1:amd64\t1.1.0-2ubuntu0.1\tbrotli\t1.1.0-2ubuntu0.1\n'
  BCC_DEB_SERIES=ubuntu:noble
  bcc_check_c01
  [ "$(reason_of libbrotli1)" = "修正版 1.1.0-2ubuntu0.1 以上です（配布元パッケージの版）。" ]
  [ "$(next_of libbrotli1)" = "この行については更新は不要（ほかの行と、走査しなかった範囲・走査できなかった範囲は別）。 最近更新したなら、使っているサービスを再起動する（C03）。" ]
}

# --- a program's output ---------------------------------------------------------------

@test "#9 C04: a version from node --version says so, and claims nothing about strings" {
  make_fake_elf "$T/opt/node/bin/node"
  bcc_probe() { printf 'v24.22.1\n'; }
  BCC_C04_CANDS=("$T/opt/node/bin/node") BCC_C04_DONE=1
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"FIXED|C04|node|$T/opt/node/bin/node|24.22.1"* ]]
  [ "$(reason_of node)" = "At or above the fixed version 24.22.1 (output of node --version)." ]
  [ "$(next_of node)" = "$NEXT_FIXED" ]
}

@test "#9 C05: a version from bun --version says so" {
  make_fake_elf "$T/opt/bun/bin/bun"
  bcc_probe() { printf '1.4.4\n'; }
  BCC_C05_CANDS=("$T/opt/bun/bin/bun") BCC_C05_DONE=1
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c05
  [ "$(reason_of bun)" = "At or above the fixed version 1.4.4 (output of bun --version)." ]
  [[ $(next_of bun) == "$NEXT_FIXED" ]]
}

@test "#9 C10: a version from envoy --version says so; the decompressor sentence stays" {
  bcc_probe() { printf '%s\n' "envoy  version: 0123456789abcdef0123456789abcdef01234567/1.38.6/Clean/RELEASE/BoringSSL"; }
  BCC_C10_CANDS=("$T/envoy") BCC_C10_DONE=1
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c10
  [ "$(reason_of envoy)" = "At or above the fixed version 1.38.6 (output of envoy --version). Envoy decodes Brotli only where a Brotli decompressor filter is configured." ]
  [ "$(next_of envoy)" = "$NEXT_FIXED" ]
}

@test "#9 C13: a version from chrome --version says so" {
  make_fake_elf "$T/opt/google/chrome/chrome"
  bcc_probe() { printf 'Google Chrome 148.0.7778.96\n'; }
  BCC_C13_CANDS=("$T/opt/google/chrome/chrome") BCC_C13_KINDS=(chromium) BCC_C13_DONE=1
  bcc_check_c13
  [[ $(reason_of chrome) == "At or above the fixed version 148.0.7778.0 (output of chrome --version). (Basis: analysis of the source tree, not a vendor advisory.)" ]]
  [ "$(next_of chrome)" = "$NEXT_FIXED" ]
}

# --- the records of other package managers --------------------------------------------

@test "#9 C13: a browser's version from its package says which package dpkg recorded" {
  make_fake_elf "$T/usr/lib/chromium/chromium"
  bcc_probe() { return 1; }
  bcc_dpkg_owner() { printf 'chromium\n'; }
  printf '#!/bin/sh\nprintf "148.0.7778.96-1~deb13u1"\n' >"$FAKEBIN/dpkg-query"
  chmod +x "$FAKEBIN/dpkg-query"
  BCC_C13_CANDS=("$T/usr/lib/chromium/chromium") BCC_C13_KINDS=(chromium) BCC_C13_DONE=1
  bcc_check_c13
  [[ $(reason_of chromium) == "At or above the fixed version 148.0.7778.0 (the version dpkg records for the package chromium). "* ]]
}

@test "#9 C12: snaps say their version is snap list's, and FIXED needs nothing for that line" {
  printf '#!/bin/sh\nprintf "Name Version Rev Tracking Publisher Notes\\nnode 24.22.1 9 24/stable iojs classic\\nfirefox 150.0-1 7 latest/stable mozilla -\\n"\n' >"$FAKEBIN/snap"
  chmod +x "$FAKEBIN/snap"
  bcc_have() { [[ $1 != flatpak ]] && command -v -- "$1" >/dev/null 2>&1; }
  bcc_check_c12
  [ "$(reason_of snap:node)" = "At or above the fixed version 24.22.1 (the version snap list gives)." ]
  [ "$(next_of snap:node)" = "$NEXT_FIXED" ]
  [[ $(reason_of snap:firefox) == "At or above the fixed version 150.0 (the version snap list gives). "* ]]
  [ "$(next_of snap:firefox)" = "$NEXT_FIXED" ]
}

@test "#9 C12: a fixed flatpak browser says flatpak list, and its next step is no longer flatpak update" {
  printf '#!/bin/sh\nprintf "org.chromium.Chromium\\t148.0.7778.96\\tsystem\\n"\n' >"$FAKEBIN/flatpak"
  chmod +x "$FAKEBIN/flatpak"
  bcc_have() { [[ $1 != snap ]] && command -v -- "$1" >/dev/null 2>&1; }
  bcc_c12_runtime_libs() { :; }
  bcc_check_c12
  [[ $(reason_of flatpak:org.chromium.Chromium) == "At or above the fixed version 148.0.7778.0 (the version flatpak list gives). "* ]]
  [ "$(next_of flatpak:org.chromium.Chromium)" = "$NEXT_FIXED" ]
}

@test "#9 C12: an unfixed flatpak browser still gets the browser update" {
  printf '#!/bin/sh\nprintf "org.mozilla.firefox\\t149.0\\tsystem\\n"\n' >"$FAKEBIN/flatpak"
  chmod +x "$FAKEBIN/flatpak"
  bcc_have() { [[ $1 != snap ]] && command -v -- "$1" >/dev/null 2>&1; }
  bcc_c12_runtime_libs() { :; }
  bcc_check_c12
  run findings_brief
  [[ $output == *"VULNERABLE|C12|flatpak:org.mozilla.firefox|"* ]]
  [ "$(next_of flatpak:org.mozilla.firefox)" = "Update the browser to the latest version." ]
}

# --- a file, confirmed by its strings -------------------------------------------------

@test "#9 C04: a version from the directory name, confirmed by the strings, says both and what is not known" {
  make_fake_elf "$T/home/u/.local/share/mise/installs/node/24.22.1/bin/node" "$FIXTURES/c09/node-v24.22.1.txt"
  BCC_NO_EXEC=1
  BCC_C04_CANDS=("$T/home/u/.local/share/mise/installs/node/24.22.1/bin/node") BCC_C04_DONE=1
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"FIXED|C04|node|"*"/24.22.1/bin/node|24.22.1"* ]]
  [ "$(reason_of node)" = "At or above the fixed version 24.22.1 (version from the directory name). $FOUND_THIS $UNSEEN" ]
  [ "$(next_of node)" = "$NEXT_FIXED" ]
}

@test "#9 C04: the same in Japanese" {
  BCC_LANG=ja BCC_NO_EXEC=1
  make_fake_elf "$T/home/u/.local/share/mise/installs/node/24.22.1/bin/node" "$FIXTURES/c09/node-v24.22.1.txt"
  BCC_C04_CANDS=("$T/home/u/.local/share/mise/installs/node/24.22.1/bin/node") BCC_C04_DONE=1
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  [ "$(reason_of node)" = "修正版 24.22.1 以上です（版はディレクトリ名から）。 分かったこと: このファイルのデコーダーの文字列に、修正で追加されたエラー名（_ERROR_FORMAT_BLOCK_SWITCH）がある。 分からないこと: ファイルの中のデコーダーがすべて修正済みかどうか（同じ文字列はリンカーが 1 つにまとめるため、それを共有する未修正のコピーは見えない）。" ]
  [ "$(next_of node)" = "この行については更新は不要（ほかの行と、走査しなかった範囲・走査できなかった範囲は別）。" ]
}

@test "#9 C04: a version from node_version.h says it came from the header" {
  make_fake_elf "$T/opt/nodejs/bin/node" "$FIXTURES/c09/node-v24.22.1.txt"
  mkdir -p "$T/opt/nodejs/include/node"
  printf '#define NODE_MAJOR_VERSION 24\n#define NODE_MINOR_VERSION 22\n#define NODE_PATCH_VERSION 1\n#define NODE_VERSION_IS_RELEASE 1\n' \
    >"$T/opt/nodejs/include/node/node_version.h"
  BCC_NO_EXEC=1
  BCC_C04_CANDS=("$T/opt/nodejs/bin/node") BCC_C04_DONE=1
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  [ "$(reason_of node)" = "At or above the fixed version 24.22.1 (version from the header file include/node/node_version.h). $FOUND_THIS $UNSEEN" ]
}

@test "#9 C04: when the strings disagree the line is UNKNOWN, still saying where the version came from" {
  make_fake_elf "$T/home/u/.nvm/versions/node/v24.22.1/bin/node" "$FIXTURES/c09/node-v24.22.0.txt"
  BCC_NO_EXEC=1
  BCC_C04_CANDS=("$T/home/u/.nvm/versions/node/v24.22.1/bin/node") BCC_C04_DONE=1
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c04
  run findings_brief
  [[ $output == *"UNKNOWN|C04|node|"* ]]
  [[ $(reason_of node) == "At or above the fixed version 24.22.1 (version from the directory name). But the decoder in the file lacks"* ]]
  [[ $(reason_of node) != *"Found:"* && $(reason_of node) != *"Not determined:"* ]]
}

@test "#9 C05: a version from the directory name is confirmed by the strings" {
  make_fake_elf "$T/home/u/.local/share/mise/installs/bun/1.4.4/bin/bun" "$FIXTURES/c09/shared-1.2.1-nostrip.txt"
  bcc_probe() { return 1; }
  BCC_C05_CANDS=("$T/home/u/.local/share/mise/installs/bun/1.4.4/bin/bun") BCC_C05_DONE=1
  PATH="$FAKEBIN:/usr/bin:/bin" bcc_check_c05
  [ "$(reason_of bun)" = "At or above the fixed version 1.4.4 (version from the directory name). $FOUND_THIS $UNSEEN" ]
}

@test "#9 C06: PyPI metadata confirmed by the extension module names that module" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  mkdir -p "$site/Brotli-1.2.1.dist-info"
  printf 'Metadata-Version: 2.1\nName: Brotli\nVersion: 1.2.1\n' >"$site/Brotli-1.2.1.dist-info/METADATA"
  tr '\n' '\0' <"$FIXTURES/c09/pypi-Brotli-1.2.1.txt" >"$site/_brotli.cpython-312-x86_64-linux-gnu.so"
  BCC_IDX_PY=("$site/Brotli-1.2.1.dist-info") BCC_IDX_CONDA=()
  bcc_check_c06
  [ "$(reason_of Brotli)" = "At or above the fixed version 1.2.1 (version from the package metadata). Found: the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH) among the decoder strings of $site/_brotli.cpython-312-x86_64-linux-gnu.so. $UNSEEN" ]
  [ "$(next_of Brotli)" = "$NEXT_FIXED" ]
}

@test "#9 C06: the same in Japanese" {
  BCC_LANG=ja
  site="$T/srv/venv/lib/python3.12/site-packages"
  mkdir -p "$site/Brotli-1.2.1.dist-info"
  printf 'Metadata-Version: 2.1\nName: Brotli\nVersion: 1.2.1\n' >"$site/Brotli-1.2.1.dist-info/METADATA"
  tr '\n' '\0' <"$FIXTURES/c09/pypi-Brotli-1.2.1.txt" >"$site/_brotli.cpython-312-x86_64-linux-gnu.so"
  BCC_IDX_PY=("$site/Brotli-1.2.1.dist-info") BCC_IDX_CONDA=()
  bcc_check_c06
  [ "$(reason_of Brotli)" = "修正版 1.2.1 以上です（版はパッケージのメタデータから）。 分かったこと: $site/_brotli.cpython-312-x86_64-linux-gnu.so のデコーダーの文字列に、修正で追加されたエラー名（_ERROR_FORMAT_BLOCK_SWITCH）がある。 分からないこと: ファイルの中のデコーダーがすべて修正済みかどうか（同じ文字列はリンカーが 1 つにまとめるため、それを共有する未修正のコピーは見えない）。" ]
}

@test "#9 C06: two confirmed extension modules give one sentence of each kind" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  mkdir -p "$site/Brotli-1.2.1.dist-info"
  printf 'Metadata-Version: 2.1\nName: Brotli\nVersion: 1.2.1\n' >"$site/Brotli-1.2.1.dist-info/METADATA"
  tr '\n' '\0' <"$FIXTURES/c09/pypi-Brotli-1.2.1.txt" >"$site/_brotli.cpython-311-x86_64-linux-gnu.so"
  tr '\n' '\0' <"$FIXTURES/c09/pypi-Brotli-1.2.1.txt" >"$site/_brotli.cpython-312-x86_64-linux-gnu.so"
  BCC_IDX_PY=("$site/Brotli-1.2.1.dist-info") BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"FIXED|C06|Brotli|"* ]]
  [ "$(reason_of Brotli)" = "At or above the fixed version 1.2.1 (version from the package metadata). Found: the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH) among the decoder strings of $site/_brotli.cpython-311-x86_64-linux-gnu.so, $site/_brotli.cpython-312-x86_64-linux-gnu.so. $UNSEEN" ]
}

@test "#9 C06: a confirmed module, then an unfixed one: UNKNOWN keeps what was found and drops what FIXED would not know" {
  site="$T/srv/venv/lib/python3.12/site-packages"
  mkdir -p "$site/Brotli-1.2.1.dist-info"
  printf 'Metadata-Version: 2.1\nName: Brotli\nVersion: 1.2.1\n' >"$site/Brotli-1.2.1.dist-info/METADATA"
  tr '\n' '\0' <"$FIXTURES/c09/pypi-Brotli-1.2.1.txt" >"$site/_brotli.cpython-311-x86_64-linux-gnu.so"
  tr '\n' '\0' <"$FIXTURES/c09/pypi-Brotli-1.2.0.txt" >"$site/_brotli.cpython-312-x86_64-linux-gnu.so"
  BCC_IDX_PY=("$site/Brotli-1.2.1.dist-info") BCC_IDX_CONDA=()
  bcc_check_c06
  run findings_brief
  [[ $output == *"UNKNOWN|C06|Brotli|"* ]]
  [[ $(reason_of Brotli) == *"among the decoder strings of $site/_brotli.cpython-311-x86_64-linux-gnu.so. But the decoder in the file lacks"* ]]
  [[ $(reason_of Brotli) != *"Not determined:"* ]]
}

@test "#9 C06: a conda record confirmed by its library names the library" {
  mkdir -p "$T/env/conda-meta" "$T/env/lib"
  : >"$T/env/conda-meta/libbrotlidec-1.2.1-h0_0.json"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.1-nostrip.txt" >"$T/env/lib/libbrotlidec.so.1.2.1"
  BCC_IDX_PY=() BCC_IDX_CONDA=("$T/env/conda-meta/libbrotlidec-1.2.1-h0_0.json")
  bcc_check_c06
  [ "$(reason_of conda:libbrotlidec)" = "At or above the fixed version 1.2.1 (version from the conda record). Found: the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH) among the decoder strings of $T/env/lib/libbrotlidec.so.1.2.1. $UNSEEN" ]
}

@test "#9 C09: a library's file name confirmed by its strings" {
  mkdir -p "$T/opt/app/lib"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.1-nostrip.txt" >"$T/opt/app/lib/libbrotlidec.so.1.2.1"
  BCC_IDX_LIB=("$T/opt/app/lib/libbrotlidec.so.1.2.1")
  bcc_check_c09_libs
  [ "$(reason_of 'libbrotlidec (shared)')" = "At or above the fixed version 1.2.1 (version from the file name). $FOUND_THIS $UNSEEN" ]
  [ "$(next_of 'libbrotlidec (shared)')" = "$NEXT_FIXED" ]
}

@test "#9 C12: a flatpak runtime's library is confirmed by its strings, and needs nothing for that line" {
  lib="$T/flatpak/runtime/org.x.Platform/x86_64/24/active/files/lib/libbrotlidec.so.1.2.1"
  mkdir -p "${lib%/*}"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.1-nostrip.txt" >"$lib"
  bcc_c12_runtime_lib "$lib"
  run findings_brief
  [[ $output == *"FIXED|C12|"*"|$lib|1.2.1"* ]]
  bcc_split_tab "${BCC_FINDINGS[0]}"
  [ "${BCC_F[5]}" = "At or above the fixed version 1.2.1 (version from the file name). $FOUND_THIS $UNSEEN" ]
  [ "${BCC_F[6]}" = "$NEXT_FIXED" ]
}

@test "#9 C13: Firefox's application.ini confirmed by libxul.so names libxul.so" {
  mkdir -p "$T/firefox"
  make_fake_elf "$T/firefox/firefox"
  bcc_probe() { return 1; }
  printf '[App]\nVersion=151.0\n' >"$T/firefox/application.ini"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.1-nostrip.txt" >"$T/firefox/libxul.so"
  BCC_C13_CANDS=("$T/firefox/firefox") BCC_C13_KINDS=(firefox) BCC_C13_DONE=1
  bcc_check_c13
  [ "$(reason_of firefox)" = "At or above the fixed version 150.0 (version from application.ini). (Basis: analysis of the source tree, not a vendor advisory.) Found: the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH) among the decoder strings of $T/firefox/libxul.so. $UNSEEN" ]
}

# --- inside containers ----------------------------------------------------------------

@test "#9 C14: a fixed package and Node.js inside a container say so, and need no rebuild for that line" {
  cat >"$FAKEBIN/docker" <<'EOF'
#!/bin/sh
printf 'OS\tubuntu\tnoble\t\nPKG\tii \tlibbrotli1:amd64\t1.1.0-2ubuntu0.1\tbrotli\t1.1.0-2ubuntu0.1\nPKGRC\t0\nNODE\t/usr/local/bin/node\tv24.22.1\nEND\n'
EOF
  chmod +x "$FAKEBIN/docker"
  bcc_c14_inspect docker 0123abcd web img:1
  [ "$(reason_of libbrotli1)" = "At or above the fixed version 1.1.0-2ubuntu0.1 (the distribution package version inside the container)." ]
  [ "$(next_of libbrotli1)" = "$NEXT_FIXED" ]
  [[ $(reason_of node) == "At or above the fixed version 24.22.1 (output of node --version inside the container). "* ]]
  [ "$(next_of node)" = "$NEXT_FIXED" ]
}

@test "#9 C14: an unfixed package inside a container still says to rebuild the image" {
  cat >"$FAKEBIN/docker" <<'EOF'
#!/bin/sh
printf 'OS\tubuntu\tnoble\t\nPKG\tii \tlibbrotli1:amd64\t1.1.0-2build2\tbrotli\t1.1.0-2build2\nPKGRC\t0\nEND\n'
EOF
  chmod +x "$FAKEBIN/docker"
  bcc_c14_inspect docker 0123abcd web img:1
  run findings_brief
  [[ $output == *"VULNERABLE|C14|libbrotli1|"* ]]
  [[ $(next_of libbrotli1) == *"rebuild the image"* ]]
}

@test "#9 C14: Python metadata inside a container with no module listed stays UNKNOWN, saying where its version came from" {
  cat >"$FAKEBIN/docker" <<'EOF'
#!/bin/sh
printf 'OS\tdebian\ttrixie\t\nPKGRC\t1\nPY\t/usr/local/lib/python3.12/site-packages/brotli-1.2.1.dist-info/METADATA\tBrotli\t1.2.1\nEND\n'
EOF
  chmod +x "$FAKEBIN/docker"
  bcc_c14_inspect docker 0123abcd web img:1
  run findings_brief
  [[ $output == *"UNKNOWN|C14|Brotli|"* ]]
  [[ $(reason_of Brotli) == "At or above the fixed version 1.2.1 (version from the package metadata inside the container). Not confirmed by a file:"* ]]
}

# --- the rest ---------------------------------------------------------------------------

@test "#9 the strings estimate (LIKELY_FIXED) reads as before the split of its message" {
  make_fake_elf "$T/opt/app/bin/app" "$FIXTURES/c09/node-v24.22.1.txt"
  bcc_report_by_strings C09 app "$T/opt/app/bin/app" "" "Carries its own copy."
  [ "$(reason_of app)" = "Carries its own copy. Found: the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH) among its decoder strings; copies of the Brotli dictionary: 0. $UNSEEN" ]
}

@test "#9 rows the data cannot decide say why in the reason, not in the evidence" {
  bcc_judge node 10 semver 10.1.0 "$(bcc_msg b_exec node)"
  [ "$BCC_J_STATUS" = UNKNOWN ]
  [ "$BCC_J_REASON" = "Cannot be judged from the data: some versions or builds of this line do not contain Brotli, and the data does not tell which." ]
  bcc_judge envoy 1.17 semver 1.17.4 "$(bcc_msg b_exec envoy)"
  [ "$BCC_J_STATUS" = UNKNOWN ]
  [[ $BCC_J_REASON != *evidence* ]]
  BCC_LANG=ja
  bcc_judge node 10 semver 10.1.0 "$(bcc_msg b_exec node)"
  [ "$BCC_J_REASON" = "既知データからは判定できません。この系列には Brotli を含まない版やビルドがあり、どれが含むかを既知データは区別していません。" ]
}

@test "#9 no message points the reader to the evidence any more" {
  run bash -c "grep -nE 'see evidence|evidence を参照' '$REPO_ROOT/lib/i18n.sh'"
  [ "$status" -eq 1 ]
}

@test "#9 every call of bcc_judge in lib/ says where its version came from" {
  # A call without a BASIS would give a FIXED that does not say what it rests on. Each call
  # passes a b_* message, or a variable named basis that holds one.
  local calls missing
  calls=$(grep -nE '^[[:space:]]*bcc_(browser_)?judge ' "$REPO_ROOT"/lib/*.sh)
  [ "$(grep -c . <<<"$calls")" -ge 17 ]
  # shellcheck disable=SC2016  # the pattern matches a literal "$(bcc_msg ...)" and "$basis"
  missing=$(grep -vE '"\$\(bcc_msg b_[a-z_]+( "[^"]*")?\)"$|"\$basis"$' <<<"$calls" || true)
  [ -z "$missing" ]
}
