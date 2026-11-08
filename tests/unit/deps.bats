#!/usr/bin/env bats
# Dependency walk as ld.so does it (issue #18, docs/design.md 10.28): every libbrotlidec a
# program loads is judged, a library name already loaded is not looked up again, and
# glibc-hwcaps subdirectories are tried in the loader's own order.
# shellcheck disable=SC2317  # stand-ins for library functions are called by the code under test

load test_helper

setup() {
  load_libs
  setup_fakebin
  T="$BATS_TEST_TMPDIR/tree"
  mkdir -p "$T"
}

# --- The two cases of the issue --------------------------------------------------------

@test "#18: a program that loads the OS libbrotlidec and a private one gets both judged" {
  fake_readelf
  bcc_dpkg_owner() { case $1 in "$T"/system/*) echo libbrotli1:amd64 ;; *) return 1 ;; esac; }
  BCC_C01_JUDGED[libbrotli1]=1
  BCC_LDCACHE_LOADED=1
  BCC_LDCACHE="libbrotlidec.so.1"$'\t'"libc6,x86-64"$'\t'"$T/system/lib/libbrotlidec.so.1"
  dyn "$T/system/lib/libbrotlidec.so.1"
  dyn "$T/app/lib/libbrotlidec_private.so.1"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$T/app/lib/libbrotlidec_private.so.1"
  dyn "$T/app/bin/curl" NEEDED=libbrotlidec.so.1 NEEDED=libbrotlidec_private.so.1 RUNPATH="$T/app/lib"
  bcc_c08_entry "$T/app/bin/curl"
  run findings_brief
  [[ $output == *"LIKELY_VULNERABLE|C09|libbrotlidec (shared)|$T/app/lib/libbrotlidec_private.so.1|"* ]]
  [[ ${BCC_INFO[*]} == *"$T/app/bin/curl (curl) loads the OS libbrotlidec ($T/system/lib/libbrotlidec.so.1"* ]]
  [[ ${BCC_INFO[*]} == *"$T/app/bin/curl (curl) loads a libbrotlidec that C01 did not judge ($T/app/lib/libbrotlidec_private.so.1"* ]]
}

@test "#18: glibc-hwcaps subdirectories are tried in the loader's order, not by name" {
  fake_readelf
  # The loader searches x86-64-v3, then x86-64-v2; not x86-64-v4 (the CPU lacks it).
  pin_hwcaps x86-64-v3 x86-64-v2
  dyn "$T/app/bin/prog" NEEDED=libq.so.1 RUNPATH="$T/app/lib"
  dyn "$T/app/lib/libq.so.1"
  for v in x86-64-v2 x86-64-v3 x86-64-v4; do dyn "$T/app/lib/glibc-hwcaps/$v/libq.so.1"; done
  bcc_dep_walk_prefetch "$T/app/bin/prog"
  recs=$(walk_records "$T/app/bin/prog")
  grep -qxF "N"$'\t'"libq.so.1"$'\t'"$T/app/lib/glibc-hwcaps/x86-64-v3/libq.so.1" <<<"$recs"
  [[ $recs != *"/x86-64-v2/"* && $recs != *"/x86-64-v4/"* ]]
}

# --- Every libbrotlidec, each once ------------------------------------------------------

@test "#18: two names for one libbrotlidec file, or one name needed twice, are one library" {
  fake_readelf
  dyn "$T/app/lib/libbrotlidec.so.1.2.0"
  ln -s libbrotlidec.so.1.2.0 "$T/app/lib/libbrotlidec.so.1"
  ln -s libbrotlidec.so.1.2.0 "$T/app/lib/libbrotlidec.so"
  dyn "$T/app/lib/libz.so.1" NEEDED=libbrotlidec.so.1
  dyn "$T/app/bin/prog" NEEDED=libbrotlidec.so.1 NEEDED=libbrotlidec.so NEEDED=libz.so.1 RUNPATH="$T/app/lib"
  bcc_links_brotlidec "$T/app/bin/prog"
  [ "${#BCC_LINKS[@]}" -eq 1 ]
  [ "${BCC_LINKS[0]}" = "$T/app/lib/libbrotlidec.so.1" ]
  [ -z "${BCC_LINKS_AMBIG[0]}" ]
}

@test "#18: a libbrotlidec that is not found is listed with the ones that are" {
  fake_readelf
  dyn "$T/app/lib/libbrotlidec_a.so.1"
  dyn "$T/app/bin/prog" NEEDED=libbrotlidec_a.so.1 NEEDED=libbrotlidec_b.so.1 RUNPATH="$T/app/lib"
  BCC_LDCACHE_LOADED=1 BCC_LDCACHE="" BCC_LIB_DIRS=("$T/none")
  bcc_links_brotlidec "$T/app/bin/prog"
  [ "${BCC_LINKS[*]}" = "$T/app/lib/libbrotlidec_a.so.1 libbrotlidec_b.so.1 (not found)" ]
}

@test "#18: a name already loaded is not looked up again, as ld.so does (breadth first)" {
  fake_readelf
  # prog finds libq.so.1 in /a; libx, with its own RUNPATH /b, needs it too: ld.so uses the
  # one already loaded (measured on Ubuntu 22.04 and 24.04).
  dyn "$T/a/libq.so.1"
  dyn "$T/b/libq.so.1"
  dyn "$T/a/libx.so.1" NEEDED=libq.so.1 RUNPATH="$T/b"
  dyn "$T/bin/prog" NEEDED=libq.so.1 NEEDED=libx.so.1 RPATH="$T/a"
  bcc_dep_walk_prefetch "$T/bin/prog"
  recs=$(walk_records "$T/bin/prog")
  grep -qxF "N"$'\t'"libq.so.1"$'\t'"$T/a/libq.so.1" <<<"$recs"
  [[ $recs != *"$T/b/libq.so.1"* ]]
  # The same through a SONAME: prog loads libqpriv.so.1, whose SONAME is libq.so.1.
  dyn "$T/c/libqpriv.so.1" SONAME=libq.so.1
  dyn "$T/c/libx.so.1" NEEDED=libq.so.1 RUNPATH="$T/b"
  dyn "$T/bin/prog2" NEEDED=libqpriv.so.1 NEEDED=libx.so.1 RPATH="$T/c"
  bcc_dep_walk_prefetch "$T/bin/prog2"
  recs=$(walk_records "$T/bin/prog2")
  [[ $recs != *"$T/b/libq.so.1"* ]]
  grep -qxF "N"$'\t'"libx.so.1"$'\t'"$T/c/libx.so.1" <<<"$recs"
}

@test "#18: --deep: every private libbrotlidec of a program is judged, the OS one adds nothing" {
  fake_readelf
  bcc_dpkg_owner() { case $1 in "$T"/system/*) echo libbrotli1:amd64 ;; *) return 1 ;; esac; }
  BCC_C01_JUDGED[libbrotli1]=1
  BCC_LDCACHE_LOADED=1
  BCC_LDCACHE="libbrotlidec.so.1"$'\t'"libc6,x86-64"$'\t'"$T/system/lib/libbrotlidec.so.1"
  dyn "$T/system/lib/libbrotlidec.so.1"
  for n in a b; do
    dyn "$T/opt/lib/libbrotlidec_$n.so.1"
    tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$T/opt/lib/libbrotlidec_$n.so.1"
  done
  dyn "$T/opt/bin/worker" NEEDED=libbrotlidec.so.1 NEEDED=libbrotlidec_a.so.1 NEEDED=libbrotlidec_b.so.1 RUNPATH="$T/opt/lib"
  bcc_c09_linked_decoder "$T/opt/bin/worker"
  run findings_brief
  [[ $output == *"C09|libbrotlidec (shared)|$T/opt/lib/libbrotlidec_a.so.1|"* ]]
  [[ $output == *"C09|libbrotlidec (shared)|$T/opt/lib/libbrotlidec_b.so.1|"* ]]
  [[ ${BCC_INFO[*]} != *"OS libbrotlidec"* ]]
}

@test "#18: what this run said about every library a program loads holds for the program" {
  # (A process still running a deleted copy of the program takes its next step from these.)
  fake_readelf
  dyn "$T/opt/lib/libbrotlidec_a.so.1"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.1-nostrip.txt" >"$T/opt/lib/libbrotlidec_a.so.1"
  dyn "$T/opt/lib/libbrotlidec_b.so.1"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$T/opt/lib/libbrotlidec_b.so.1"
  dyn "$T/opt/bin/curl" NEEDED=libbrotlidec_a.so.1 NEEDED=libbrotlidec_b.so.1 RUNPATH="$T/opt/lib"
  bcc_c08_entry "$T/opt/bin/curl"
  [[ ${BCC_DISK_JUDGED[$T/opt/bin/curl]} == *$'\t'LIKELY_FIXED$'\n'* ]]
  [[ ${BCC_DISK_JUDGED[$T/opt/bin/curl]} == *$'\t'LIKELY_VULNERABLE$'\n'* ]]
}

# --- glibc-hwcaps: the loader's order, the ld.so cache, the default directories --------

@test "#18: the ld.so cache's glibc-hwcaps entries are taken in the loader's order" {
  # ldconfig -p as on Ubuntu 22.04 and 24.04: hwcaps entries first, in name order.
  cat >"$FAKEBIN/ldconfig" <<EOS
#!/bin/sh
printf '3 libs found in cache \`/etc/ld.so.cache'"'"'\n'
printf '\tlibq.so.1 (libc6,x86-64, hwcap: "x86-64-v2") => $T/c/glibc-hwcaps/x86-64-v2/libq.so.1\n'
printf '\tlibq.so.1 (libc6,x86-64, hwcap: "x86-64-v3") => $T/c/glibc-hwcaps/x86-64-v3/libq.so.1\n'
printf '\tlibq.so.1 (libc6,x86-64) => $T/c/libq.so.1\n'
printf '\tlibr.so.1 (libc6,x86-64, hwcap: 0x0000000000000002) => $T/c/tls/libr.so.1\n'
printf '\tlibr.so.1 (libc6,x86-64) => $T/c/libr.so.1\n'
EOS
  chmod +x "$FAKEBIN/ldconfig"
  bcc_ldcache_load
  bcc_dep_find known libq.so.1
  [ "${BCC_FOUND[*]}" = "$T/c/glibc-hwcaps/x86-64-v3/libq.so.1" ]
  pin_hwcaps x86-64-v2
  bcc_dep_find known libq.so.1
  [ "${BCC_FOUND[*]}" = "$T/c/glibc-hwcaps/x86-64-v2/libq.so.1" ]
  pin_hwcaps
  bcc_dep_find known libq.so.1
  [ "${BCC_FOUND[*]}" = "$T/c/libq.so.1" ]
  # An entry of the older hwcaps scheme is not taken (docs/limitations.md).
  bcc_dep_find known libr.so.1
  [ "${BCC_FOUND[*]}" = "$T/c/libr.so.1" ]
  # With the order unknown, each could be the one: all are candidates.
  unpin_hwcaps
  bcc_dep_find unknown libq.so.1
  [ "${#BCC_FOUND[@]}" -eq 3 ]
}

@test "#18: the default directories' glibc-hwcaps subdirectories are tried too" {
  BCC_LDCACHE_LOADED=1 BCC_LDCACHE=""
  BCC_LIB_DIRS=("$T/lib" "$T/usr/lib")
  mkdir -p "$T/lib/glibc-hwcaps/x86-64-v3" "$T/usr/lib"
  : >"$T/lib/glibc-hwcaps/x86-64-v3/libq.so.1"
  : >"$T/usr/lib/libq.so.1"
  bcc_dep_find known libq.so.1
  [ "${BCC_FOUND[*]}" = "$T/lib/glibc-hwcaps/x86-64-v3/libq.so.1" ]
  # A level the loader does not search, and a name it does not know, are not tried.
  pin_hwcaps x86-64-v2
  mkdir -p "$T/lib/glibc-hwcaps/foo"
  : >"$T/lib/glibc-hwcaps/foo/libq.so.1"
  bcc_dep_find known libq.so.1
  [ "${BCC_FOUND[*]}" = "$T/usr/lib/libq.so.1" ]
}

@test "#18: with the order unknown, every copy is judged and the report says which could not be told" {
  fake_readelf
  unpin_hwcaps
  for v in x86-64-v2 x86-64-v3; do
    dyn "$T/app/lib/glibc-hwcaps/$v/libbrotlidec.so.1"
    tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.0-nostrip.txt" >"$T/app/lib/glibc-hwcaps/$v/libbrotlidec.so.1"
  done
  dyn "$T/app/lib/libbrotlidec.so.1"
  tr '\n' '\0' <"$FIXTURES/c09/shared-1.2.1-nostrip.txt" >"$T/app/lib/libbrotlidec.so.1"
  dyn "$T/app/bin/curl" NEEDED=libbrotlidec.so.1 RUNPATH="$T/app/lib"
  bcc_dep_walk_prefetch "$T/app/bin/curl"
  recs=$(walk_records "$T/app/bin/curl")
  grep -qxF "X"$'\t'"hwcaps"$'\t'"libbrotlidec.so.1" <<<"$recs"
  [ "$(grep -c "^N"$'\t'"libbrotlidec.so.1"$'\t' <<<"$recs")" -eq 3 ]
  bcc_c08_entry "$T/app/bin/curl"
  run findings_brief
  [[ $output == *"LIKELY_VULNERABLE|C09|libbrotlidec (shared)|$T/app/lib/glibc-hwcaps/x86-64-v2/libbrotlidec.so.1|"* ]]
  [[ $output == *"LIKELY_VULNERABLE|C09|libbrotlidec (shared)|$T/app/lib/glibc-hwcaps/x86-64-v3/libbrotlidec.so.1|"* ]]
  [[ $output == *"LIKELY_FIXED|C09|libbrotlidec (shared)|$T/app/lib/libbrotlidec.so.1|"* ]]
  [[ ${BCC_INFO[*]} == *"($T/app/lib/libbrotlidec.so.1, found by readelf)"*"Which copy of libbrotlidec.so.1 it loads could not be told"* ]]
  bcc_exec_facts "$T/app/bin/curl"
  [[ " ${BCC_FACTS[*]} " == *"which copy of the library libbrotlidec.so.1 is loaded could not be told"* ]]
}

@test "#18: with the order unknown, copies that are one file are one, and nothing is said" {
  fake_readelf
  unpin_hwcaps
  dyn "$T/app/lib/libbrotlidec.so.1"
  mkdir -p "$T/app/lib/glibc-hwcaps/x86-64-v3"
  ln -s ../../libbrotlidec.so.1 "$T/app/lib/glibc-hwcaps/x86-64-v3/libbrotlidec.so.1"
  dyn "$T/app/bin/prog" NEEDED=libbrotlidec.so.1 RUNPATH="$T/app/lib"
  bcc_dep_walk_prefetch "$T/app/bin/prog"
  recs=$(walk_records "$T/app/bin/prog")
  [ "$(grep -c "^N"$'\t'"libbrotlidec.so.1"$'\t' <<<"$recs")" -eq 1 ]
  [[ $recs != *hwcaps$'\t'libbrotlidec.so.1* ]]
  bcc_links_brotlidec "$T/app/bin/prog"
  [ "${#BCC_LINKS[@]}" -eq 1 ]
  [ -z "${BCC_LINKS_AMBIG[0]}" ]
}

@test "#18: a program naming another loader in PT_INTERP does not get the system loader's order" {
  fake_readelf
  dyn "$T/app/lib/glibc-hwcaps/x86-64-v3/libq.so.1"
  dyn "$T/app/lib/libq.so.1"
  dyn "$T/app/bin/own" NEEDED=libq.so.1 RUNPATH="$T/app/lib"
  printf '%s' "$T/app/lib/ld-linux-x86-64.so.2" >"$T/app/bin/own.interp"
  : >"$T/app/lib/ld-linux-x86-64.so.2"
  bcc_dep_walk_prefetch "$T/app/bin/own"
  [ "${BCC_DEPWALK_HWC[$T/app/bin/own]}" = unknown ]
  grep -qxF "X"$'\t'"hwcaps"$'\t'"libq.so.1" <<<"$(walk_records "$T/app/bin/own")"
  # One that names the system's loader does.
  dyn "$T/app/bin/sys" NEEDED=libq.so.1 RUNPATH="$T/app/lib"
  printf '%s' "$BCC_HWCAPS_LOADER" >"$T/app/bin/sys.interp"
  bcc_dep_walk_prefetch "$T/app/bin/sys"
  [ "${BCC_DEPWALK_HWC[$T/app/bin/sys]}" = known ]
  grep -qxF "N"$'\t'"libq.so.1"$'\t'"$T/app/lib/glibc-hwcaps/x86-64-v3/libq.so.1" <<<"$(walk_records "$T/app/bin/sys")"
}

@test "#18: the facts name only the glibc-hwcaps subdirectories the loader searches" {
  fake_readelf
  pin_hwcaps x86-64-v3 x86-64-v2
  mkdir -p "$T/app/lib/glibc-hwcaps/x86-64-v3" "$T/app/lib/glibc-hwcaps/x86-64-v4"
  chmod 777 "$T/app/lib/glibc-hwcaps/x86-64-v3" "$T/app/lib/glibc-hwcaps/x86-64-v4"
  dyn "$T/app/bin/prog" RUNPATH="$T/app/lib"
  bcc_exec_facts "$T/app/bin/prog"
  [[ " ${BCC_FACTS[*]} " == *"$T/app/lib/glibc-hwcaps/x86-64-v3 can be written by anyone"* ]]
  [[ " ${BCC_FACTS[*]} " != *"$T/app/lib/glibc-hwcaps/x86-64-v4 can be written by anyone"* ]]
  # With the order unknown, every one there.
  bcc_init_findings
  unpin_hwcaps
  bcc_exec_facts "$T/app/bin/prog"
  [[ " ${BCC_FACTS[*]} " == *"$T/app/lib/glibc-hwcaps/x86-64-v4 can be written by anyone"* ]]
}

# --- Asking the loader -------------------------------------------------------------------

@test "#18: ld.so --help: only subdirectories marked searched are taken, in its order" {
  # Ubuntu 22.04 (glibc 2.35), with the legacy section after it.
  bcc_hwcaps_parse $'Shared library search path:\n  /lib/x86_64-linux-gnu (system search path)\n\nSubdirectories of glibc-hwcaps directories, in priority order:\n  x86-64-v4 (supported, searched)\n  x86-64-v3 (supported, searched)\n  x86-64-v2 (supported, searched)\n\nLegacy HWCAP subdirectories under library search path directories:\n  haswell (AT_PLATFORM; supported, searched)\n  tls (supported, searched)'
  [ "${BCC_HWCAPS[*]}" = "x86-64-v4 x86-64-v3 x86-64-v2" ]
  # A level the CPU lacks (GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX512F on Ubuntu 24.04) and
  # masked ones (dl-usage.c) are not searched.
  bcc_hwcaps_parse $'Subdirectories of glibc-hwcaps directories, in priority order:\n  x86-64-v4\n  x86-64-v3 (supported, searched)\n  x86-64-v2 (supported, masked)\n  z9 (masked)\n'
  [ "${BCC_HWCAPS[*]}" = "x86-64-v3" ]
  bcc_hwcaps_parse $'\nNo subdirectories of glibc-hwcaps directories are searched.\n'
  [ "${#BCC_HWCAPS[@]}" -eq 0 ]
  run bcc_hwcaps_parse $'Usage: ld.so [OPTION]... EXECUTABLE-FILE [ARGS-FOR-PROGRAM...]\n'
  [ "$status" -eq 1 ]
}

@test "#18: the loader is asked from / with an empty environment, only when it knows --help" {
  mkdir -p "$T/l"
  cat >"$T/l/ld.so" <<EOS
#!/bin/sh
# --glibc-hwcaps-mask
{ pwd; env | grep -c .; } >"$T/l/ran"
printf 'Subdirectories of glibc-hwcaps directories, in priority order:\n  x86-64-v3 (supported, searched)\n'
EOS
  chmod +x "$T/l/ld.so"
  bcc_safe_to_exec() { printf '%s\n' "$1"; }
  BCC_HWCAPS_LOADED="" BCC_SYS_LOADERS="$T/l/ld.so"
  export SOME_TUNABLE=1
  bcc_hwcaps_load
  [ "$BCC_HWCAPS_LOADER" = "$T/l/ld.so" ]
  [ "${BCC_HWCAPS[*]}" = x86-64-v3 ]
  [ "$(sed -n 1p "$T/l/ran")" = / ]
  [ "$(sed -n 2p "$T/l/ran")" -le 3 ]
  # One whose file does not name the option (glibc before 2.33) is not run.
  rm "$T/l/ran"
  sed -i '/--glibc-hwcaps-mask/d' "$T/l/ld.so"
  BCC_HWCAPS_LOADED=""
  bcc_hwcaps_load
  [ -z "$BCC_HWCAPS_LOADER" ]
  [ ! -e "$T/l/ran" ]
  # Nor one that others can change.
  printf '# --glibc-hwcaps-mask\n' >>"$T/l/ld.so"
  bcc_safe_to_exec() { return 1; }
  BCC_HWCAPS_LOADED=""
  bcc_hwcaps_load
  [ -z "$BCC_HWCAPS_LOADER" ]
  [ ! -e "$T/l/ran" ]
}

@test "#18: this host's loader answers (when it is glibc 2.33 or later)" {
  local l=/lib64/ld-linux-x86-64.so.2
  [ -e "$l" ] || skip "not an x86_64 glibc host"
  grep -aqF -e --glibc-hwcaps-mask "$(readlink -f "$l")" || skip "glibc before 2.33"
  BCC_HWCAPS_LOADED="" BCC_SYS_LOADERS=$l
  bcc_hwcaps_load
  [ "$BCC_HWCAPS_LOADER" = "$(readlink -f "$l")" ]
  for h in ${BCC_HWCAPS[@]+"${BCC_HWCAPS[@]}"}; do [[ $h == x86-64-v[234] ]]; done
}

@test "#18: no caller takes bcc_links_brotlidec's answer from its output" {
  # The libraries come back in BCC_LINKS (paths may hold a newline); a caller in $(...) would
  # see nothing, and one in a pipe would lose them.
  run grep -nE '\$\( *bcc_links_brotlidec|`bcc_links_brotlidec|bcc_links_brotlidec[^|;&]*\|[^|]' "$REPO_ROOT"/lib/*.sh "$REPO_ROOT"/bin/brotli-cve-check
  [ "$status" -eq 1 ]
}
