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
  [ "$BCC_DATA_SNAPSHOT" = 2026-11-02 ]
  [ "${#BCC_DATA_ROWS[@]}" -gt 20 ]
}

@test "lookup: an exact branch wins over a range row" {
  bcc_data_lookup node 22
  [ "$BCC_D_FIXED" = 22.23.4 ]
  [ "$BCC_D_STATUS" = fixed ]
}

@test "lookup: end-of-life Node.js lines are derived, with the reason in the note" {
  bcc_data_lookup node 20
  [ "$BCC_D_STATUS" = derived_eol ]
  [[ $BCC_D_NOTE == *"end-of-life versions are always affected"* ]]
  bcc_data_lookup node 25
  [ "$BCC_D_STATUS" = derived_eol ]
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
  write_data '# snapshot: 2026-10-26' 'deb-src:brotli|ubuntu:noble|-|no_fix|-|https://x|2026-10-26|'
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

# --- The advisory's affected range (issue #2) ---

@test "range: the versions on each side of the lower bound (Bun, Brotli)" {
  bcc_judge bun '*' semver 1.0.20
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_judge bun '*' semver 1.0.21
  [ "$BCC_J_STATUS" = VULNERABLE ]
  [ "$BCC_J_REASON" = "Below the fixed version 1.4.4." ]
  bcc_judge brotli 1.0 semver 1.0.2
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_judge brotli 1.0 semver 1.0.3
  [ "$BCC_J_STATUS" = VULNERABLE ]
  [ "$BCC_J_REASON" = "Below the fixed version 1.0.10." ]
}

@test "range: at or above the fix is still FIXED, and a row without a range is unchanged" {
  bcc_judge bun '*' semver 1.4.4
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge brotli 1.0 semver 1.0.10
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge brotli 1.1 semver 1.1.0
  [ "$BCC_J_STATUS" = VULNERABLE ]
  [ "$BCC_J_OUT_OF_RANGE" -eq 0 ]
}

@test "range: outside it the reason names the advisory and the range, and advises an update" {
  bcc_judge bun '*' semver 1.0.20
  [[ $BCC_J_REASON == *"GHSA-663w-cv8g-jj2p"*"1.0.21 to 1.4.3"* ]]
  [[ $BCC_J_REASON == *"does not say whether"* ]]
  [[ $BCC_J_REASON == *"update is recommended"* ]]
  [ "$BCC_J_NEXT" = "Update to 1.4.4 or later." ]
  BCC_LANG=ja
  bcc_judge bun '*' semver 1.0.20
  [ "$BCC_J_REASON" = "告知（GHSA-663w-cv8g-jj2p）の影響範囲 1.0.21〜1.4.3 の外です。この CVE の影響を受けるかは告知からは分かりません。古い版なので更新を勧めます。" ]
  bcc_judge brotli 1.0 semver 1.0.2
  [[ $BCC_J_REASON == *"GHSA-9v8h-qqgm-4m35"*"1.0.3〜1.2.0"* ]]
}

@test "range: Brotli 0.x has no fix of its own, and is sent to a real version" {
  local v
  for v in 0.6.0 0.5.2; do
    bcc_judge brotli "${v%.*}" semver "$v"
    [ "$BCC_J_STATUS" = UNKNOWN ]
    [[ $BCC_J_REASON == *"GHSA-9v8h-qqgm-4m35"*"1.0.3 to 1.2.0"* ]]
    [ "$BCC_J_FIXED" = 1.0.10 ]
    [ "$BCC_J_NEXT" = "Update to 1.0.10 or later." ]
  done
}

@test "range: PyPI follows the GHSA's lower bound, since PYSEC disagrees below it" {
  bcc_judge pypi:brotli '*' pep440 1.0.1
  [ "$BCC_J_STATUS" = UNKNOWN ]
  [[ $BCC_J_REASON == *"1.0.3 to 1.2.0"* ]]
  bcc_judge pypi:brotli '*' pep440 1.0.4
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_judge pypi:brotlicffi '*' pep440 0.8.0
  [ "$BCC_J_STATUS" = UNKNOWN ]
  [[ $BCC_J_REASON == *"1.0.3 to 1.2.0.2"* ]]
  [[ $BCC_J_EVIDENCE == *"PYSEC"*"GHSA-9v8h-qqgm-4m35"* ]]
  bcc_judge pypi:brotlicffi '*' pep440 1.0.9.2
  [ "$BCC_J_STATUS" = VULNERABLE ]
}

@test "range: a pre-release of the fix stays a pre-release; of the lower bound, it is before the range" {
  bcc_judge bun '*' semver 1.4.4-rc1
  [ "$BCC_J_STATUS" = UNKNOWN ]
  [[ $BCC_J_REASON == *"Pre-release"* ]]
  [ "$BCC_J_OUT_OF_RANGE" -eq 0 ]
  bcc_judge bun '*' semver 1.0.21-canary.1
  [ "$BCC_J_STATUS" = UNKNOWN ]
  [ "$BCC_J_OUT_OF_RANGE" -eq 1 ]
}

@test "range: bcc_judge_advises_update follows the last judgement" {
  bcc_judge bun '*' semver 1.0.20
  bcc_judge_advises_update
  bcc_judge bun '*' semver 1.4.4
  run bcc_judge_advises_update
  [ "$status" -ne 0 ]
  bcc_judge bun '*' semver 1.4.3
  bcc_judge_advises_update
}

@test "derived: Node.js and Envoy stay VULNERABLE and the reason itself gives the ground" {
  bcc_judge node 20 semver 20.19.0
  [ "$BCC_J_STATUS" = VULNERABLE ]
  [[ $BCC_J_REASON == *"end-of-life versions are always affected"* ]]
  [[ $BCC_J_REASON != *evidence* ]]
  bcc_judge envoy 1.35 semver 1.35.0
  [ "$BCC_J_STATUS" = VULNERABLE ]
  [[ $BCC_J_REASON == *"bundled"*"affected range"* ]]
  [[ $BCC_J_REASON != *evidence* ]]
  BCC_LANG=ja
  bcc_judge node 20 semver 20.19.0
  [[ $BCC_J_REASON == *"サポートが終わった版を常に影響あり"* ]]
  [[ $BCC_J_REASON != *evidence* ]]
  bcc_judge envoy 1.35 semver 1.35.0
  [[ $BCC_J_REASON == *"同梱の Brotli が影響範囲の版"* ]]
  [[ $BCC_J_REASON != *evidence* ]]
}

@test "data: Envoy before Brotli support is UNKNOWN; from 1.18 on it is VULNERABLE" {
  bcc_load_data shipped-data <"$REPO_ROOT/data/advisories.tsv"
  bcc_judge envoy 1.17 semver 1.17.4
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_judge envoy 1.9 semver 1.9.1
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_judge envoy 1.18 semver 1.18.0
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_judge envoy 1.35 semver 1.35.13
  [ "$BCC_J_STATUS" = VULNERABLE ]
}

@test "data: Ubuntu's ESM releases are judged by USN-8956-2" {
  bcc_load_data shipped-data <"$REPO_ROOT/data/advisories.tsv"
  bcc_judge deb-src:brotli ubuntu:focal deb 1.0.7-6ubuntu0.1+esm1
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge deb-src:brotli ubuntu:focal deb 1.0.7-6ubuntu0.1
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_judge deb-src:brotli ubuntu:bionic deb 1.0.3-1ubuntu1.3+esm1
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge deb-src:brotli ubuntu:bionic deb 1.0.3-1ubuntu1.3
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_judge deb-src:brotli ubuntu:xenial deb 1.0.3-1ubuntu1~16.04.2+esm1
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge deb-src:brotli ubuntu:xenial deb 1.0.3-1ubuntu1~16.04.2
  [ "$BCC_J_STATUS" = VULNERABLE ]
}

@test "text report: outside the range is visible without evidence, and adds to exit code 2 only" {
  BCC_LANG=ja BCC_DATA_LABEL=test BCC_ROOTS=(/opt)
  bcc_judge bun '*' semver 1.0.20
  bcc_add_finding C05 "$BCC_J_STATUS" bun /opt/bun/bin/bun 1.0.20 "$BCC_J_REASON" "$BCC_J_NEXT" "$BCC_J_EVIDENCE" ""
  bcc_judge brotli 0.6 semver 0.6.0
  bcc_add_finding C09 "$BCC_J_STATUS" libbrotlidec /opt/x/libbrotlidec.so.0.6.0 0.6.0 "$BCC_J_REASON" "$BCC_J_NEXT" "$BCC_J_EVIDENCE" ""
  [ "$(bcc_exit_code)" -eq 2 ]
  run bcc_render_text
  [[ $output == *"[UNKNOWN] C05 | bun | /opt/bun/bin/bun | 1.0.20 | 告知（GHSA-663w-cv8g-jj2p）の影響範囲 1.0.21〜1.4.3 の外です。"*"| 1.4.4 以上に更新する。"* ]]
  [[ $output == *"[UNKNOWN] C09 | libbrotlidec | /opt/x/libbrotlidec.so.0.6.0 | 0.6.0 | 告知（GHSA-9v8h-qqgm-4m35）の影響範囲 1.0.3〜1.2.0 の外です。"*"| 1.0.10 以上に更新する。"* ]]
}

@test "text report: the ground of a derived VULNERABLE is in the line" {
  BCC_LANG=ja BCC_DATA_LABEL=test BCC_ROOTS=(/opt)
  bcc_judge node 20 semver 20.19.0
  bcc_add_finding C04 "$BCC_J_STATUS" node /opt/node/bin/node 20.19.0 "$BCC_J_REASON" "-" "$BCC_J_EVIDENCE" ""
  [ "$(bcc_exit_code)" -eq 1 ]
  run bcc_render_text
  [[ $output == *"[VULNERABLE] C04 | node | /opt/node/bin/node | 20.19.0 | 提供元の告知は、サポートが終わった版を常に影響ありとしています。"* ]]
}

@test "data: a range is read from the file, and only applies below its first version" {
  write_data '# snapshot: 2026-10-26' 'foo|*|2.0.0|fixed|ADV-1:1.5.0:1.9.9|https://x|2026-10-26|'
  bcc_load_data test-data <"$DATA"
  bcc_judge foo '*' semver 1.4.9
  [ "$BCC_J_STATUS" = UNKNOWN ]
  [[ $BCC_J_REASON == *"ADV-1"*"1.5.0 to 1.9.9"* ]]
  bcc_judge foo '*' semver 1.5.0
  [ "$BCC_J_STATUS" = VULNERABLE ]
}

@test "data: a badly written, misplaced or reversed range is rejected" {
  local row st
  for row in 'foo|*|2.0.0|fixed||https://x|2026-10-26|' \
    'foo|*|2.0.0|fixed|1.5.0|https://x|2026-10-26|' \
    'foo|*|2.0.0|fixed|ADV-1:1.5.0|https://x|2026-10-26|' \
    'foo|*|2.0.0|fixed|ADV-1:x:1.9.9|https://x|2026-10-26|'; do
    write_data '# snapshot: 2026-10-26' "$row"
    run bcc_load_data test-data <"$DATA"
    [ "$status" -eq 3 ]
    [[ $output == *"ADVISORY:FIRST:LAST"* ]]
  done
  for st in no_fix unreleased derived_eol derived_bundled derived_before_range analysis unknown; do
    write_data '# snapshot: 2026-10-26' "foo|*|2.0.0|$st|ADV-1:1.5.0:1.9.9|https://x|2026-10-26|"
    run bcc_load_data test-data <"$DATA"
    [ "$status" -eq 3 ]
    [[ $output == *"only be given on a fixed row"* ]]
  done
  write_data '# snapshot: 2026-10-26' 'foo|*|2.0.0|fixed|ADV-1:2.0.0:2.5.0|https://x|2026-10-26|'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
  [[ $output == *"below fixed"* ]]
  write_data '# snapshot: 2026-10-26' 'foo|*|2.0.0|fixed|ADV-1:1.9.9:1.5.0|https://x|2026-10-26|'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
  [[ $output == *"not above LAST"* ]]
  # A component too long for arithmetic does not wrap around into a valid order.
  write_data '# snapshot: 2026-10-26' 'foo|*|1.2.1|fixed|ADV-1:18446744073709551617.2.0:1.2.0|https://x|2026-10-26|'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
}

@test "data: the old status name derived is rejected" {
  write_data '# snapshot: 2026-10-26' 'foo|*|-|derived|-|https://x|2026-10-26|'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
  [[ $output == *"unknown status"* ]]
}

@test "data: a row with 7 columns is rejected" {
  write_data '# snapshot: 2026-10-26' 'node|22|22.23.4|fixed|https://x|2026-10-26|'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
  [[ $output == *"8 tab-separated columns"* ]]
}

@test "data: an unknown status is rejected" {
  write_data '# snapshot: 2026-10-26' 'node|22|22.23.4|maybe|-|https://x|2026-10-26|'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
  [[ $output == *"unknown status"* ]]
}

@test "data: a source that is not https is rejected" {
  write_data '# snapshot: 2026-10-26' 'node|22|22.23.4|fixed|-|http://x|2026-10-26|'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
}

@test "data: a missing snapshot line is rejected" {
  write_data 'node|22|22.23.4|fixed|-|https://x|2026-10-26|'
  run bcc_load_data test-data <"$DATA"
  [ "$status" -eq 3 ]
  [[ $output == *"snapshot"* ]]
}

@test "data: age is computed against today" {
  write_data '# snapshot: 2026-10-26' 'node|22|22.23.4|fixed|-|https://x|2026-10-26|'
  BCC_TODAY=2026-12-01
  bcc_load_data test-data <"$DATA"
  [ "$BCC_DATA_AGE_DAYS" -eq 36 ]
}
