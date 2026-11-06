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
  declare -gA BCC_JUDGED=()
  declare -gA BCC_C01_JUDGED=() BCC_C01_STATUS=()
  # What this run said about the file now at a path (bcc_note_disk), for the processes that
  # still run a deleted file at that path (C03-C05, bcc_restart_advice).
  declare -gA BCC_DISK_JUDGED=()
  # Links to a program of another name that bcc_candidates did not take, per check.
  BCC_OTHER_ID=() BCC_OTHER_FOUND=() BCC_OTHER_REAL=()
  declare -gA BCC_OTHER_KEYS=()
  # Filled by C06, read by C09; declared here so that every entry point has them as
  # associative arrays (an undeclared one would evaluate a path key arithmetically).
  declare -gA BCC_C06_SITES=() BCC_C06_CONDA_FILES=()
  # Execution plan, consent and results (lib/exec.sh); caches for facts and linkage.
  BCC_PLAN=()
  declare -gA BCC_PLAN_BIN=() BCC_PLAN_ARG=() BCC_PLAN_PURPOSE=() BCC_PLAN_FACTS=() BCC_PLAN_OK=()
  declare -gA BCC_PROBE_OUT=() BCC_PROBE_RC=()
  declare -gA BCC_UNAME_CACHE=() BCC_PATHFACTS_CACHE=() BCC_DEPWALK_CACHE=() BCC_DEPWALK_RC=()
  declare -gA BCC_LINK_CACHE=() BCC_LINK_RC=() BCC_DYN_CACHE=() BCC_FIND_CACHE=()
  # Facts and dependency-walk records are kept in arrays, never joined with a separator (a
  # path may hold any byte but NUL); the caches above hold ranges "start count" of them.
  BCC_FACT_POOL=() BCC_WALK_K=() BCC_WALK_A=() BCC_WALK_B=()
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

# Fields must not carry tabs or newlines. They are shown as "?", as control characters are
# in the text report and in the list of programs to run: one path reads the same everywhere,
# and a space would make it look like another path.
bcc_clean_field() {
  local s=$1
  s=${s//$'\t'/?}
  s=${s//$'\n'/?}
  s=${s//$'\r'/?}
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
  # A finding about a file is what this run says about that file on disk. A restart and an
  # exposure hint say nothing about the file's decoder.
  case $status in RESTART_REQUIRED | EXPOSURE) ;; *) [[ $path != /* ]] || bcc_note_disk "$path" "$id" "$component" "$status" ;; esac
}

# bcc_note_disk PATH ID COMPONENT STATUS - this run judged the file now at PATH (directly, or
# through what it loads, or by the package or record it belongs to) as STATUS in finding ID.
bcc_note_disk() {
  local line
  line="$(bcc_clean_field "$2")"$'\t'"$(bcc_clean_field "$3")"$'\t'"$4"
  case $'\n'"${BCC_DISK_JUDGED[$1]:-}" in *$'\n'"$line"$'\n'*) return 0 ;; esac
  BCC_DISK_JUDGED[$1]+="$line"$'\n'
}

# bcc_add_info ID TEXT  - context that is not a finding (does not affect counts or exit code).
bcc_add_info() {
  BCC_INFO+=("$(bcc_clean_field "$1")"$'\t'"$(bcc_clean_field "$2")")
}

# bcc_skip KIND SCOPE REASON - a range that was not scanned (first reason per kind and scope
# wins). Stored as "scope<TAB>reason<TAB>kind". KIND is one of (issue #10, docs/design.md 10.26):
#   chosen  left out by how the tool was run: an option not given (or given: --exclude,
#           --no-exec), programs not chosen to run, not running as root (and what this user
#           therefore could not read), file systems the walk does not enter unless asked, what
#           an option only counts (stopped containers, images), an optional tool (readelf)
#   failed  the run set out to look at it and could not: a command failed or is missing, a
#           time limit, a file not read to the end or over the size limit, what root could not
#           read, a place named on the command line that is not there, a container not looked
#           inside although --inspect-containers asked for it
# A failed range makes the exit status 2 when no finding makes it 1 (bcc_exit_code).
bcc_skip() {
  local kind=$1 key="$1|$2"
  case $kind in
    chosen | failed) ;;
    *) bcc_die "internal error: unknown kind of skipped range '$kind'" ;;
  esac
  [[ -z ${BCC_SKIP_KEYS[$key]:-} ]] || return 0
  BCC_SKIP_KEYS[$key]=1
  BCC_SKIPPED+=("$(bcc_clean_field "$2")"$'\t'"$(bcc_clean_field "$3")"$'\t'"$kind")
}

# The kind of a range this user could not read for lack of permission: not running as root is
# the runner's choice (the "root" entry says so), while what root cannot read is a failure.
bcc_denied_kind() {
  if ((BCC_IS_ROOT)); then printf failed; else printf chosen; fi
}

# Number of skipped ranges of KIND.
bcc_count_skipped() {
  local want=$1 f n=0
  for f in ${BCC_SKIPPED[@]+"${BCC_SKIPPED[@]}"}; do
    [[ ${f##*$'\t'} == "$want" ]] && n=$((n + 1))
  done
  printf '%d' "$n"
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

# 0: none of the below (not proof of safety: ranges left out by choice are not counted)
# 1: VULNERABLE or RESTART_REQUIRED present
# 2: otherwise NO_FIX_AVAILABLE, VENDORED_COPY, LIKELY_*, or UNKNOWN present, or a range that
#    could not be scanned (a skipped range of kind "failed")
bcc_exit_code() {
  if (($(bcc_count_status VULNERABLE) + $(bcc_count_status RESTART_REQUIRED) > 0)); then
    printf 1
  elif (($(bcc_count_status NO_FIX_AVAILABLE) + $(bcc_count_status VENDORED_COPY) + $(bcc_count_status UNKNOWN) + $(bcc_count_status LIKELY_VULNERABLE) + $(bcc_count_status LIKELY_FIXED) + $(bcc_count_skipped failed) > 0)); then
    printf 2
  else
    printf 0
  fi
}
