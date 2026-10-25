# shellcheck shell=bash
# main.sh - command line, orchestration, output, exit code.

BCC_VERSION="0.1.0"
BCC_CVE="CVE-2026-111497"
BCC_DEFAULT_ROOTS="/opt,/usr/local,/srv,/var/www,/home,/root"

bcc_usage() {
  bcc_msg usage "$BCC_VERSION" "$BCC_DEFAULT_ROOTS"
}

# Split "a,b,c" into lines, dropping empty items and trailing slashes.
bcc_split_list() {
  local item
  local -a items=()
  IFS=, read -r -a items <<<"$1"
  for item in ${items[@]+"${items[@]}"}; do
    [[ -n $item ]] || continue
    [[ $item == / ]] || item=${item%/}
    printf '%s\n' "$item"
  done
}

bcc_parse_args() {
  BCC_ROOTS_RAW=$BCC_DEFAULT_ROOTS
  BCC_EXCLUDE_RAW=""
  BCC_DEEP=0 BCC_PROJECTS=0 BCC_CONTAINERS=0 BCC_INSPECT_CONTAINERS=0 BCC_EXPOSURE=0
  BCC_NO_EXEC=0 BCC_SHOW_CMDLINE=0 BCC_JSON=0 BCC_INCLUDE_REMOTE=0
  BCC_OUTPUT="" BCC_DATA_FILE="" BCC_ENVOY_CONFIG="" BCC_LANG=en
  BCC_TIMEOUT=120 BCC_MAX_ELF_MB=512
  local opt val
  while (($#)); do
    opt=$1
    val=""
    if [[ $opt == --*=* ]]; then
      val=${opt#*=}
      opt=${opt%%=*}
      set -- "$opt" "$val" "${@:2}"
    fi
    case $opt in
      --roots | --exclude | --envoy-config | --output | --data | --lang | --timeout)
        (($# >= 2)) || bcc_die "$(bcc_msg err_needs_value "$opt")"
        val=$2
        shift 2
        ;;
      *) shift ;;
    esac
    case $opt in
      --roots) BCC_ROOTS_RAW=$val ;;
      --exclude) BCC_EXCLUDE_RAW=$val ;;
      --deep) BCC_DEEP=1 ;;
      --projects) BCC_PROJECTS=1 ;;
      --containers) BCC_CONTAINERS=1 ;;
      --inspect-containers) BCC_CONTAINERS=1 BCC_INSPECT_CONTAINERS=1 ;;
      --exposure) BCC_EXPOSURE=1 ;;
      --envoy-config) BCC_ENVOY_CONFIG=$val ;;
      --no-exec) BCC_NO_EXEC=1 ;;
      --show-cmdline) BCC_SHOW_CMDLINE=1 ;;
      --json) BCC_JSON=1 ;;
      --output) BCC_OUTPUT=$val ;;
      --data) BCC_DATA_FILE=$val ;;
      --lang)
        case $val in
          ja | en) BCC_LANG=$val ;;
          *) bcc_die "$(bcc_msg err_bad_lang "$val")" ;;
        esac
        ;;
      --timeout)
        [[ $val =~ ^[1-9][0-9]*$ ]] || bcc_die "$(bcc_msg err_bad_timeout "$val")"
        BCC_TIMEOUT=$val
        ;;
      --include-remote) BCC_INCLUDE_REMOTE=1 ;;
      --version)
        printf 'brotli-cve-check %s (%s)\n' "$BCC_VERSION" "$BCC_CVE"
        exit 0
        ;;
      -h | --help)
        bcc_usage
        exit 0
        ;;
      *) bcc_die "$(bcc_msg err_unknown_option "$opt")" ;;
    esac
  done
  # The language is known only after parsing; an earlier error message used English.
  BCC_PROBE_TIMEOUT=$((BCC_TIMEOUT < 10 ? BCC_TIMEOUT : 10))
  mapfile -t BCC_ROOTS < <(bcc_split_list "$BCC_ROOTS_RAW")
  mapfile -t BCC_EXCLUDES < <(bcc_split_list "$BCC_EXCLUDE_RAW")
  local r
  for r in ${BCC_ROOTS[@]+"${BCC_ROOTS[@]}"}; do
    [[ $r == /* ]] || bcc_die "$(bcc_msg err_relative "$r")"
  done
  for r in ${BCC_EXCLUDES[@]+"${BCC_EXCLUDES[@]}"}; do
    [[ $r == /* ]] || bcc_die "$(bcc_msg err_relative "$r")"
  done
  if [[ -n $BCC_OUTPUT && -e $BCC_OUTPUT ]]; then
    bcc_die "$(bcc_msg err_output_exists "$BCC_OUTPUT")"
  fi
}

# Roots that do not exist or cannot be read are reported, not silently dropped.
bcc_check_roots() {
  local r
  local -a ok=()
  for r in ${BCC_ROOTS[@]+"${BCC_ROOTS[@]}"}; do
    if [[ ! -e $r ]]; then
      continue
    elif [[ ! -r $r || ! -x $r ]]; then
      bcc_skip "$r" "$(bcc_msg skip_unreadable)"
    else
      ok+=("$r")
    fi
  done
  BCC_ROOTS=(${ok[@]+"${ok[@]}"})
}

bcc_load_data_source() {
  if [[ -n $BCC_DATA_FILE ]]; then
    [[ -r $BCC_DATA_FILE ]] || bcc_die "$(bcc_msg err_data_unreadable "$BCC_DATA_FILE")"
    bcc_load_data "$BCC_DATA_FILE" <"$BCC_DATA_FILE"
    BCC_DATA_LABEL=$BCC_DATA_FILE
  elif declare -F bcc_embedded_data >/dev/null; then
    bcc_load_data embedded < <(bcc_embedded_data)
    BCC_DATA_LABEL=embedded
  elif [[ -n ${BCC_DEFAULT_DATA:-} && -r $BCC_DEFAULT_DATA ]]; then
    bcc_load_data "$BCC_DEFAULT_DATA" <"$BCC_DEFAULT_DATA"
    BCC_DATA_LABEL=$BCC_DEFAULT_DATA
  else
    bcc_die "$(bcc_msg err_data_unreadable "${BCC_DEFAULT_DATA:-data/advisories.tsv}")"
  fi
}

# Ranges that were not scanned because an option was not given.
bcc_note_disabled() {
  ((BCC_DEEP)) || bcc_skip "C09 --deep" "$(bcc_msg skip_opt_deep)"
  ((BCC_PROJECTS)) || bcc_skip "C07 --projects" "$(bcc_msg skip_opt_projects)"
  ((BCC_CONTAINERS)) || bcc_skip "C14 --containers" "$(bcc_msg skip_opt_containers)"
  ((BCC_EXPOSURE)) || bcc_skip "C15 --exposure" "$(bcc_msg skip_opt_exposure)"
  ((BCC_NO_EXEC)) && bcc_skip "--no-exec" "$(bcc_msg skip_opt_noexec)"
  if ((!BCC_IS_ROOT)); then
    bcc_skip "root" "$(bcc_msg skip_not_root)"
  fi
  bcc_have readelf || bcc_skip "binutils" "$(bcc_msg skip_no_binutils)"
  return 0
}

bcc_run_checks() {
  declare -gA BCC_JUDGED=()
  bcc_build_index
  bcc_check_c01
  bcc_check_c02
  bcc_check_c03
  bcc_check_c04
  bcc_check_c05
  bcc_check_c06
  ((BCC_PROJECTS)) && bcc_check_c07
  bcc_check_c08
  bcc_check_c09_libs
  ((BCC_DEEP)) && bcc_check_c09_deep
  bcc_check_c10
  bcc_check_c11
  bcc_check_c12
  bcc_check_c13
  ((BCC_CONTAINERS)) && bcc_check_c14
  ((BCC_EXPOSURE)) && bcc_check_c15
  return 0
}

bcc_main() {
  if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 2))); then
    printf 'brotli-cve-check: bash 4.2 or later is required\n' >&2
    exit 3
  fi
  BCC_LANG=en
  bcc_parse_args "$@"
  local t
  for t in find grep sed awk sort od tr timeout readlink date; do
    bcc_have "$t" || bcc_die "$(bcc_msg err_missing_tool "$t")"
  done
  bcc_init_findings
  bcc_load_data_source
  bcc_init_host
  bcc_init_homes
  bcc_init_remote_mounts
  bcc_check_roots
  bcc_note_disabled
  bcc_run_checks
  bcc_summarize
  BCC_EXIT=$(bcc_exit_code)
  local report
  if ((BCC_JSON)); then
    report=$(bcc_render_json)
  else
    report=$(bcc_render_text)
  fi
  printf '%s\n' "$report"
  if [[ -n $BCC_OUTPUT ]]; then
    (set -o noclobber && printf '%s\n' "$report" >"$BCC_OUTPUT") || bcc_die "$(bcc_msg err_output_write "$BCC_OUTPUT")"
  fi
  exit "$BCC_EXIT"
}
