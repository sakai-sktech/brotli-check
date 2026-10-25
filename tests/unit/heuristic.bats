#!/usr/bin/env bats
# C09 string heuristic against the verified fixtures (tests/fixtures/c09/README.md).
# Each fixture is the list of "_ERROR_*" strings extracted from a real build or binary;
# the heuristic reads files the same way (runs of printable bytes), so the lists work as input.

load test_helper

setup() {
  load_libs
  C09="$FIXTURES/c09"
}

status_of() {
  bcc_brotli_heuristic "$1" | cut -f1
}

@test "every fixed build is LIKELY_FIXED (shared, static -O2, static LTO p2, strip or not)" {
  local f
  for f in "$C09"/shared-1.2.1-*.txt "$C09"/static-1.2.1-O2-*.txt "$C09"/static-1.2.1-LTO-p2-*.txt; do
    [ "$(status_of "$f")" = LIKELY_FIXED ] || { echo "not fixed: $f"; return 1; }
  done
}

@test "every unfixed build is LIKELY_VULNERABLE" {
  local f
  for f in "$C09"/shared-1.2.0-*.txt "$C09"/static-1.2.0-O2-*.txt "$C09"/static-1.2.0-LTO-p2-*.txt; do
    [ "$(status_of "$f")" = LIKELY_VULNERABLE ] || { echo "not vulnerable: $f"; return 1; }
  done
}

@test "LTO + gc-sections without BrotliDecoderErrorString is undecidable (VENDORED_COPY)" {
  local f
  for f in "$C09"/static-1.2.0-LTO-p1-*.txt "$C09"/static-1.2.1-LTO-p1-*.txt; do
    [ "$(status_of "$f")" = VENDORED_COPY ] || { echo "decided: $f"; return 1; }
  done
}

@test "official Node.js binaries: 22.23.3 / 24.22.0 unfixed, 22.23.4 / 24.22.1 fixed" {
  [ "$(status_of "$C09/node-v22.23.3.txt")" = LIKELY_VULNERABLE ]
  [ "$(status_of "$C09/node-v24.22.0.txt")" = LIKELY_VULNERABLE ]
  [ "$(status_of "$C09/node-v22.23.4.txt")" = LIKELY_FIXED ]
  [ "$(status_of "$C09/node-v24.22.1.txt")" = LIKELY_FIXED ]
}

@test "PyPI wheels: Brotli 1.2.1 and brotlicffi 1.2.1.0 fixed, earlier ones not" {
  [ "$(status_of "$C09/pypi-Brotli-1.2.1.txt")" = LIKELY_FIXED ]
  [ "$(status_of "$C09/pypi-brotlicffi-1.2.1.0.txt")" = LIKELY_FIXED ]
  [ "$(status_of "$C09/pypi-Brotli-1.2.0.txt")" = LIKELY_VULNERABLE ]
  [ "$(status_of "$C09/pypi-brotlicffi-1.2.0.2.txt")" = LIKELY_VULNERABLE ]
}

@test "a longer name that merely contains _ERROR_FORMAT_BLOCK_SWITCH does not count" {
  # Node.js keeps BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH in its own table.
  f="$BATS_TEST_TMPDIR/node-like"
  { cat "$C09/node-v22.23.3.txt"; printf 'BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH\n'; } | tr '\n' '\0' >"$f"
  [ "$(status_of "$f")" = LIKELY_VULNERABLE ]
}

@test "a few stray names are not enough to decide" {
  f="$BATS_TEST_TMPDIR/stray"
  printf '_ERROR_FORMAT_DISTANCE\0_ERROR_FORMAT_PADDING_1\0' >"$f"
  [ "$(status_of "$f")" = VENDORED_COPY ]
}
