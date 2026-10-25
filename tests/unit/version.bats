#!/usr/bin/env bats

load test_helper

setup() {
  load_libs
}

@test "semver: numeric fields, not string order" {
  [ "$(bcc_semver_cmp 22.9.0 22.23.4)" = -1 ]
  [ "$(bcc_semver_cmp 22.23.4 22.23.4)" = 0 ]
  [ "$(bcc_semver_cmp v26.12.1 26.12.0)" = 1 ]
  [ "$(bcc_semver_cmp 1.40 1.40.0)" = 0 ]
}

@test "semver: a pre-release sorts before the release" {
  [ "$(bcc_semver_cmp 1.4.4-canary.1 1.4.4)" = -1 ]
  [ "$(bcc_semver_cmp 1.4.4 1.4.4-canary.1)" = 1 ]
}

@test "semver: unparsable input is reported, not guessed" {
  [ "$(bcc_semver_cmp abc 1.0.0)" = "?" ]
  run bcc_version_ge semver abc 1.0.0
  [ "$status" -eq 2 ]
}

@test "pep440: 1.2.1 and 1.2.1.0 are equal (Brotli vs brotlicffi numbering)" {
  [ "$(bcc_pep440_cmp 1.2.1 1.2.1.0)" = 0 ]
  bcc_version_ge pep440 1.2.1 1.2.1.0
  bcc_version_ge pep440 1.2.1.0 1.2.1
}

@test "pep440: pre-releases, dev and post releases" {
  [ "$(bcc_pep440_cmp 1.2.1rc1 1.2.1)" = -1 ]
  [ "$(bcc_pep440_cmp 1.2.1.dev3 1.2.1rc1)" = -1 ]
  [ "$(bcc_pep440_cmp 1.2.1.post1 1.2.1)" = 1 ]
  [ "$(bcc_pep440_cmp 1.2.0.2 1.2.1.0)" = -1 ]
  [ "$(bcc_pep440_cmp 1.2.1+local 1.2.1)" = 0 ]
}

@test "deb: dpkg --compare-versions decides, including +debNuM and ~" {
  command -v dpkg >/dev/null || skip "dpkg not available"
  bcc_version_ge deb 1.1.0-2+deb13u1 1.1.0-2+deb13u1
  run bcc_version_ge deb 1.1.0-2 1.1.0-2+deb13u1
  [ "$status" -eq 1 ]
  run bcc_version_ge deb 1.2.0-4 1.2.0-4.1
  [ "$status" -eq 1 ]
  bcc_version_ge deb 1.2.0-4.1 1.2.0-4.1
}

@test "version from output: a log line before the version is not taken (Chrome)" {
  out=$'[1026/070739.474907:WARNING:chrome/app/chrome_main_linux.cc:84] Read channel stable\nGoogle Chrome 149.0.7827.53 '
  v=$(bcc_version_from_output "$out" 'Chrom[a-z]* ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)')
  [ "$v" = 149.0.7827.53 ]
}

@test "version from output: no matching line means no version" {
  run bcc_version_from_output "Segmentation fault" '^v([0-9]+\.[0-9]+\.[0-9]+)'
  [ "$status" -eq 1 ]
  [ -z "$output" ]
}
