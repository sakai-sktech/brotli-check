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
  BCC_LANG=en
  BCC_NO_EXEC=0
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
