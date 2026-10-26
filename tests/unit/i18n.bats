#!/usr/bin/env bats
# The message catalog is complete in both languages and covers every key in the code.

load test_helper

setup() {
  load_libs
}

@test "every English key has a Japanese message and vice versa" {
  local k missing=""
  for k in "${!BCC_MSG_EN[@]}"; do [[ -n ${BCC_MSG_JA[$k]:-} ]] || missing+=" ja:$k"; done
  for k in "${!BCC_MSG_JA[@]}"; do [[ -n ${BCC_MSG_EN[$k]:-} ]] || missing+=" en:$k"; done
  [ -z "$missing" ] || { echo "missing:$missing"; return 1; }
}

@test "every key used by the code exists in the catalog" {
  local k missing=""
  while IFS= read -r k; do
    [[ -n ${BCC_MSG_EN[$k]:-} ]] || missing+=" $k"
  done < <(grep -ohE 'bcc_msg "?[a-z][a-z0-9_]*' "$REPO_ROOT"/lib/*.sh | sed -E 's/bcc_msg "?//' | grep -v '_$' | sort -u)
  for k in C01 C02 C03 C04 C05 C06 C07 C08 C09 C10 C11 C12 C13 C14 C15; do
    [[ -n ${BCC_MSG_EN[title_$k]:-} ]] || missing+=" title_$k"
  done
  [ -z "$missing" ] || { echo "missing:$missing"; return 1; }
}

@test "both languages take the same number of arguments for each key" {
  local k en ja bad=""
  for k in "${!BCC_MSG_EN[@]}"; do
    en=$(grep -o '%s' <<<"${BCC_MSG_EN[$k]}" | wc -l || true)
    ja=$(grep -o '%s' <<<"${BCC_MSG_JA[$k]}" | wc -l || true)
    [ "$en" -eq "$ja" ] || bad+=" $k($en/$ja)"
  done
  [ -z "$bad" ] || { echo "mismatch:$bad"; return 1; }
}

@test "no message calls a result SAFE or 安全 as a verdict" {
  local k
  for k in "${!BCC_MSG_EN[@]}"; do
    [[ ${BCC_MSG_EN[$k]} != *SAFE* ]] || { echo "$k"; return 1; }
  done
  for k in "${!BCC_MSG_JA[@]}"; do
    [[ ${BCC_MSG_JA[$k]} != *"安全です"* ]] || { echo "$k"; return 1; }
  done
}
