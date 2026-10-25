# shellcheck shell=bash
# findings.sh - collect findings, information lines and skipped scopes; summarize; exit code.
#
# A finding is one array element with tab-separated fields:
#   id status component path version reason next_step evidence confidence

BCC_STATUSES="VULNERABLE FIXED NO_FIX_AVAILABLE RESTART_REQUIRED VENDORED_COPY LIKELY_FIXED LIKELY_VULNERABLE EXPOSURE NOT_APPLICABLE UNKNOWN SKIPPED"

bcc_init_findings() {
  BCC_FINDINGS=()
  BCC_INFO=()
  BCC_SKIPPED=()
  declare -gA BCC_FINDING_KEYS=()
  declare -gA BCC_SKIP_KEYS=()
  declare -gA BCC_DPKG_CACHE=()
  declare -gA BCC_PRIVGRP_CACHE=()
}

# Split a tab-separated record into the global array BCC_F, keeping empty fields
# (IFS=$'\t' read would merge consecutive tabs).
bcc_split_tab() {
  local rest=$1
  BCC_F=()
  while [[ $rest == *$'\t'* ]]; do
    BCC_F+=("${rest%%$'\t'*}")
    rest=${rest#*$'\t'}
  done
  BCC_F+=("$rest")
}

# Fields must not carry tabs or newlines.
bcc_clean_field() {
  local s=$1
  s=${s//$'\t'/ }
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  printf '%s' "$s"
}

# bcc_add_finding ID STATUS COMPONENT PATH VERSION REASON NEXT [EVIDENCE] [CONFIDENCE]
bcc_add_finding() {
  local id=$1 status=$2 component=$3 path=$4 version=$5 reason=$6 next=$7
  local evidence=${8:-} confidence=${9:-}
  case " $BCC_STATUSES " in
    *" $status "*) ;;
    *) bcc_die "internal error: unknown status '$status'" ;;
  esac
  local key="$id|$component|$path"
  [[ -z ${BCC_FINDING_KEYS[$key]:-} ]] || return 0
  BCC_FINDING_KEYS[$key]=1
  local f
  f="$(bcc_clean_field "$id")"$'\t'"$status"$'\t'"$(bcc_clean_field "$component")"$'\t'"$(bcc_clean_field "$path")"
  f+=$'\t'"$(bcc_clean_field "$version")"$'\t'"$(bcc_clean_field "$reason")"$'\t'"$(bcc_clean_field "$next")"
  f+=$'\t'"$(bcc_clean_field "$evidence")"$'\t'"$(bcc_clean_field "$confidence")"
  BCC_FINDINGS+=("$f")
}

# bcc_add_info ID TEXT  - context that is not a finding (does not affect counts or exit code).
bcc_add_info() {
  BCC_INFO+=("$(bcc_clean_field "$1")"$'\t'"$(bcc_clean_field "$2")")
}

# bcc_skip SCOPE REASON - a range that was not scanned (first reason per scope wins).
bcc_skip() {
  local key=$1
  [[ -z ${BCC_SKIP_KEYS[$key]:-} ]] || return 0
  BCC_SKIP_KEYS[$key]=1
  BCC_SKIPPED+=("$(bcc_clean_field "$1")"$'\t'"$(bcc_clean_field "$2")")
}

bcc_count_status() {
  local want=$1 f n=0
  for f in ${BCC_FINDINGS[@]+"${BCC_FINDINGS[@]}"}; do
    bcc_split_tab "$f"
    [[ ${BCC_F[1]} == "$want" ]] && n=$((n + 1))
  done
  printf '%d' "$n"
}

# Summary for non-specialists (docs/json-schema.md "summary").
bcc_summarize() {
  BCC_SUM_UPDATE=$(($(bcc_count_status VULNERABLE) + $(bcc_count_status LIKELY_VULNERABLE)))
  BCC_SUM_RESTART=$(bcc_count_status RESTART_REQUIRED)
  BCC_SUM_REVIEW=$(($(bcc_count_status NO_FIX_AVAILABLE) + $(bcc_count_status VENDORED_COPY) + $(bcc_count_status UNKNOWN) + $(bcc_count_status LIKELY_FIXED)))
}

# 0: none of VULNERABLE/RESTART_REQUIRED/NO_FIX_AVAILABLE (not proof of safety)
# 1: VULNERABLE or RESTART_REQUIRED present
# 2: otherwise NO_FIX_AVAILABLE, VENDORED_COPY, LIKELY_*, or UNKNOWN present
bcc_exit_code() {
  if (($(bcc_count_status VULNERABLE) + $(bcc_count_status RESTART_REQUIRED) > 0)); then
    printf 1
  elif (($(bcc_count_status NO_FIX_AVAILABLE) + $(bcc_count_status VENDORED_COPY) + $(bcc_count_status UNKNOWN) + $(bcc_count_status LIKELY_VULNERABLE) + $(bcc_count_status LIKELY_FIXED) > 0)); then
    printf 2
  else
    printf 0
  fi
}
