# shellcheck shell=bash
# Shared setup for the bats unit tests. Libraries are sourced into the test shell;
# external programs are replaced by fakes placed first on PATH.

REPO_ROOT=$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)
FIXTURES="$REPO_ROOT/tests/fixtures"

load_libs() {
  local f
  for f in "$REPO_ROOT"/lib/*.sh; do
    # shellcheck source=/dev/null
    . "$f"
  done
  # The tool runs with pipefail (bin/brotli-cve-check); test under the same rules.
  set -o pipefail
  BCC_LANG=en
  BCC_NO_EXEC=0
  BCC_YES=0
  BCC_SHOW_CMDLINE=0
  BCC_TIMEOUT=20
  BCC_PROBE_TIMEOUT=5
  BCC_MAX_ELF_MB=64
  BCC_INCLUDE_REMOTE=0
  BCC_EXCLUDES=()
  BCC_REMOTE_MOUNTS=()
  BCC_HOMES=()
  BCC_ROOTS=()
  BCC_IS_ROOT=0
  BCC_DEB_SERIES=""
  BCC_ENVOY_CONFIG=""
  bcc_init_findings
  bcc_load_data test <"$REPO_ROOT/data/advisories.tsv"
  # The loader's glibc-hwcaps order depends on the CPU: tests pin one (pin_hwcaps).
  pin_hwcaps x86-64-v4 x86-64-v3 x86-64-v2
}

# As if the system's loader had answered "ld.so --help" with these glibc-hwcaps
# subdirectories searched, highest priority first (none: it searches none). The loader is
# this host's, so that programs a test compiles name it as theirs.
pin_hwcaps() {
  local l
  BCC_HWCAPS_LOADED=1
  BCC_HWCAPS_LOADER=/nonexistent/ld.so
  for l in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux-aarch64.so.1; do
    [[ -e $l ]] && { BCC_HWCAPS_LOADER=$(readlink -f -- "$l"); break; }
  done
  BCC_HWCAPS=("$@")
}

# As if the loader could not be asked: the order of glibc-hwcaps subdirectories is unknown.
unpin_hwcaps() {
  BCC_HWCAPS_LOADED=1
  BCC_HWCAPS_LOADER=""
  BCC_HWCAPS=()
}

# A readelf that pretends: "-d FILE" prints FILE.dyn (the dynamic section, written by dyn
# below), "-l FILE" the loader named in FILE.interp (nothing without one). For search paths a
# compiler will not produce (RPATH and RUNPATH on one object).
fake_readelf() {
  cat >"$FAKEBIN/readelf" <<'EOS'
#!/bin/bash
f=${!#}
case $1 in
  -d) [[ -f $f.dyn ]] && cat -- "$f.dyn" || exit 1 ;;
  -l) [[ ! -f $f.interp ]] || printf '      [Requesting program interpreter: %s]\n' "$(cat -- "$f.interp")" ;;
esac
exit 0
EOS
  chmod +x "$FAKEBIN/readelf"
}

# dyn FILE [NEEDED=x] [RPATH=x] [RUNPATH=x] [SONAME=x] ...: create FILE and its pretended
# dynamic section.
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
      SONAME=*) printf ' 0x000000000000000e (SONAME)             Library soname: [%s]\n' "${kv#*=}" ;;
    esac >>"$f.dyn"
  done
}

# The dependency-walk records of FILE, one "kind<TAB>a<TAB>b" line each (for assertions).
walk_records() {
  local s c i
  read -r s c <<<"${BCC_DEPWALK_CACHE[$1]}"
  for ((i = s; i < s + c; i++)); do
    printf '%s\t%s\t%s\n' "${BCC_WALK_K[i]}" "${BCC_WALK_A[i]}" "${BCC_WALK_B[i]}"
  done
}

# Directory for fake programs, first on PATH.
setup_fakebin() {
  FAKEBIN="$BATS_TEST_TMPDIR/fakebin"
  mkdir -p "$FAKEBIN"
  PATH="$FAKEBIN:$PATH"
}

# A file that passes the ELF magic check but is not a runnable program.
make_fake_elf() {
  mkdir -p "$(dirname "$1")"
  printf '\177ELF\002\001\001\000' >"$1"
  if [[ -n ${2:-} ]]; then
    tr '\n' '\0' <"$2" >>"$1"
  fi
  chmod +x "$1"
}

# Findings as "STATUS|ID|component|path|version" lines, for easy assertions.
findings_brief() {
  local f
  for f in ${BCC_FINDINGS[@]+"${BCC_FINDINGS[@]}"}; do
    bcc_split_tab "$f"
    printf '%s|%s|%s|%s|%s\n' "${BCC_F[1]}" "${BCC_F[0]}" "${BCC_F[2]}" "${BCC_F[3]}" "${BCC_F[4]}"
  done
}
