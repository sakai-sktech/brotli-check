#!/usr/bin/env bats

load test_helper

setup() {
  load_libs
}

write_data() {
  DATA="$BATS_TEST_TMPDIR/data.tsv"
  printf '%s\n' "$@" | sed 's/|/\t/g' >"$DATA"
}

@test "the shipped data file loads and has a snapshot date" {
  [ "$BCC_DATA_SNAPSHOT" = 2026-10-27 ]
  [ "${#BCC_DATA_ROWS[@]}" -gt 20 ]
}

@test "lookup: an exact branch wins over a range row" {
  bcc_data_lookup node 22
  [ "$BCC_D_FIXED" = 22.23.4 ]
  [ "$BCC_D_STATUS" = fixed ]
}

@test "lookup: end-of-life Node.js lines are derived, with the reason in the note" {
  bcc_data_lookup node 20
  [ "$BCC_D_STATUS" = derived ]
  [[ $BCC_D_NOTE == *"end-of-life versions are always affected"* ]]
  bcc_data_lookup node 25
  [ "$BCC_D_STATUS" = derived ]
}

@test "lookup: very old Node.js lines are unknown (may predate bundled Brotli)" {
  bcc_data_lookup node 8
  [ "$BCC_D_STATUS" = unknown ]
}

@test "lookup: a future Node.js line has no data" {
  run bcc_data_lookup node 27
  [ "$status" -eq 1 ]
}

@test "judge: below the fixed version is VULNERABLE, at or above is FIXED" {
  bcc_judge node 22 semver 22.23.3
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_judge node 22 semver 22.23.4
  [ "$BCC_J_STATUS" = FIXED ]
}

@test "judge: Ubuntu is fixed by USN-8956-1 (source version compared)" {
  command -v dpkg >/dev/null || skip "dpkg not available"
  bcc_judge deb-src:brotli ubuntu:noble deb 1.1.0-2build2
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_judge deb-src:brotli ubuntu:noble deb 1.1.0-2ubuntu0.1
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge deb-src:brotli ubuntu:jammy deb 1.0.9-2ubuntu0.1
  [ "$BCC_J_STATUS" = FIXED ]
}

@test "judge: a distributor without a fix gives NO_FIX_AVAILABLE (no_fix row)" {
  write_data '# snapshot: 2026-10-26' 'deb-src:brotli|ubuntu:noble|-|no_fix|https://x|2026-10-26|'
  bcc_load_data test-data <"$DATA"
  bcc_judge deb-src:brotli ubuntu:noble deb 1.1.0-2build2
  [ "$BCC_J_STATUS" = NO_FIX_AVAILABLE ]
}

@test "judge: Debian sid has 1.2.0-4.1; forky waits for it (unreleased)" {
  command -v dpkg >/dev/null || skip "dpkg not available"
  bcc_judge deb-src:brotli debian:sid deb 1.2.0-4
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_judge deb-src:brotli debian:sid deb 1.2.0-4.1
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge deb-src:brotli debian:forky deb 1.2.0-4
  [ "$BCC_J_STATUS" = NO_FIX_AVAILABLE ]
  bcc_judge deb-src:brotli debian:forky deb 1.2.0-4.1
  [ "$BCC_J_STATUS" = FIXED ]
}

@test "judge: Envoy 1.38.6 and 1.37.8 are FIXED (advisory and tags agree)" {
  bcc_judge envoy 1.38 semver 1.38.6
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge envoy 1.37 semver 1.37.8
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge envoy 1.38 semver 1.38.5
  [ "$BCC_J_STATUS" = VULNERABLE ]
}

@test "judge: PyPI brotlicffi 1.2.1.0 is FIXED, 1.2.0.2 is VULNERABLE" {
  bcc_judge pypi:brotlicffi '*' pep440 1.2.1.0
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge pypi:brotlicffi '*' pep440 1.2.0.2
  [ "$BCC_J_STATUS" = VULNERABLE ]
}

@test "judge: analysis-based rows say so in the reason" {
  bcc_judge firefox '*' semver 149.0
  [ "$BCC_J_STATUS" = VULNERABLE ]
  [[ $BCC_J_REASON == *"not a vendor advisory"* ]]
}

@test "data: a row with 6 columns is rejected" {
  write_data '# snapshot: 2026-10-26' 'node|22|22.23.4|fixed|https://x|2026-10-26'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
  [[ $output == *"7 tab-separated columns"* ]]
}

@test "data: an unknown status is rejected" {
  write_data '# snapshot: 2026-10-26' 'node|22|22.23.4|maybe|https://x|2026-10-26|'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
  [[ $output == *"unknown status"* ]]
}

@test "data: a source that is not https is rejected" {
  write_data '# snapshot: 2026-10-26' 'node|22|22.23.4|fixed|http://x|2026-10-26|'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
}

@test "data: a missing snapshot line is rejected" {
  write_data 'node|22|22.23.4|fixed|https://x|2026-10-26|'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
  [[ $output == *"snapshot"* ]]
}

@test "data: age is computed against today" {
  write_data '# snapshot: 2026-10-26' 'node|22|22.23.4|fixed|https://x|2026-10-26|'
  BCC_TODAY=2026-12-01
  bcc_load_data test-data <"$DATA"
  [ "$BCC_DATA_AGE_DAYS" -eq 36 ]
}
