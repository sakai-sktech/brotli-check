# shellcheck shell=bash
# data.sh - load data/advisories.tsv (read-only) and judge a version against it.

BCC_DATA_STATUSES="fixed no_fix unreleased derived analysis unknown"

# bcc_load_data LABEL < data   (LABEL names the source in error messages)
bcc_load_data() {
  local label=$1 line n=0 tabs
  BCC_DATA_ROWS=()
  BCC_DATA_SNAPSHOT=""
  while IFS= read -r line || [[ -n $line ]]; do
    n=$((n + 1))
    line=${line%$'\r'}
    if [[ $line == '# snapshot: '* ]]; then
      BCC_DATA_SNAPSHOT=${line#'# snapshot: '}
      continue
    fi
    [[ -z $line || $line == '#'* ]] && continue
    tabs=${line//[!$'\t']/}
    ((${#tabs} == 6)) || bcc_die "$(bcc_msg err_data_line "$label" "$n" "$(bcc_msg err_data_columns)")"
    bcc_split_tab "$line"
    [[ -n ${BCC_F[0]} && -n ${BCC_F[1]} && -n ${BCC_F[2]} ]] ||
      bcc_die "$(bcc_msg err_data_line "$label" "$n" "$(bcc_msg err_data_empty)")"
    case " $BCC_DATA_STATUSES " in
      *" ${BCC_F[3]} "*) ;;
      *) bcc_die "$(bcc_msg err_data_line "$label" "$n" "$(bcc_msg err_data_status "${BCC_F[3]}")")" ;;
    esac
    [[ ${BCC_F[4]} == https://* ]] ||
      bcc_die "$(bcc_msg err_data_line "$label" "$n" "$(bcc_msg err_data_url)")"
    [[ ${BCC_F[5]} =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] ||
      bcc_die "$(bcc_msg err_data_line "$label" "$n" "$(bcc_msg err_data_date)")"
    BCC_DATA_ROWS+=("$line")
  done
  [[ $BCC_DATA_SNAPSHOT =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] ||
    bcc_die "$(bcc_msg err_data_snapshot "$label")"
  ((${#BCC_DATA_ROWS[@]})) || bcc_die "$(bcc_msg err_data_line "$label" "$n" "$(bcc_msg err_data_norows)")"
  BCC_DATA_AGE_DAYS=$((($(bcc_today_epoch) - $(date -u -d "$BCC_DATA_SNAPSHOT" +%s)) / 86400))
}

# bcc_data_lookup COMPONENT SERIES
# Exact branch rows first; then "*" and "<=X" rows in file order.
# Sets BCC_D_BRANCH BCC_D_FIXED BCC_D_STATUS BCC_D_URL BCC_D_RETRIEVED BCC_D_NOTE.
bcc_data_lookup() {
  local comp=$1 series=$2 row pass br c
  for pass in exact other; do
    for row in "${BCC_DATA_ROWS[@]}"; do
      bcc_split_tab "$row"
      [[ ${BCC_F[0]} == "$comp" ]] || continue
      br=${BCC_F[1]}
      if [[ $pass == exact ]]; then
        [[ $br == "$series" ]] || continue
      elif [[ $br == '*' ]]; then
        :
      elif [[ $br == '<='* && -n $series ]]; then
        c=$(bcc_semver_cmp "$series" "${br#<=}")
        [[ $c == -1 || $c == 0 ]] || continue
      else
        continue
      fi
      BCC_D_BRANCH=$br
      BCC_D_FIXED=${BCC_F[2]}
      BCC_D_STATUS=${BCC_F[3]}
      BCC_D_URL=${BCC_F[4]}
      BCC_D_RETRIEVED=${BCC_F[5]}
      BCC_D_NOTE=${BCC_F[6]}
      return 0
    done
  done
  return 1
}

# bcc_judge COMPONENT SERIES KIND VERSION
# Sets BCC_J_STATUS (FIXED | VULNERABLE | NO_FIX_AVAILABLE | UNKNOWN), BCC_J_REASON,
# BCC_J_NEXT (empty: caller decides), BCC_J_EVIDENCE, BCC_J_FIXED.
bcc_judge() {
  local comp=$1 series=$2 kind=$3 ver=$4 rc=0
  BCC_J_STATUS=UNKNOWN
  BCC_J_REASON=""
  BCC_J_NEXT=""
  BCC_J_EVIDENCE=""
  BCC_J_FIXED=""
  if ! bcc_data_lookup "$comp" "$series"; then
    BCC_J_REASON=$(bcc_msg r_no_data "$comp" "${series:-?}")
    BCC_J_NEXT=$(bcc_msg n_check_vendor)
    return
  fi
  BCC_J_FIXED=$BCC_D_FIXED
  BCC_J_EVIDENCE="data: $comp $BCC_D_BRANCH; $BCC_D_URL ($BCC_D_RETRIEVED)"
  case $BCC_D_STATUS in
    fixed | analysis | unreleased)
      rc=0
      bcc_version_ge "$kind" "$ver" "$BCC_D_FIXED" || rc=$?
      if ((rc == 0)); then
        BCC_J_STATUS=FIXED
        BCC_J_REASON=$(bcc_msg r_fixed_ge "$BCC_D_FIXED")
      elif ((rc == 1)) && [[ $BCC_D_STATUS == unreleased ]]; then
        BCC_J_STATUS=NO_FIX_AVAILABLE
        BCC_J_REASON=$(bcc_msg r_unreleased "$BCC_D_FIXED")
        BCC_J_NEXT=$(bcc_msg n_wait_vendor)
      elif ((rc == 1)); then
        BCC_J_STATUS=VULNERABLE
        BCC_J_REASON=$(bcc_msg r_below_fixed "$BCC_D_FIXED")
      else
        BCC_J_STATUS=UNKNOWN
        BCC_J_REASON=$(bcc_msg r_version_unparsable "$ver")
        BCC_J_NEXT=$(bcc_msg n_check_vendor)
      fi
      ;;
    no_fix)
      BCC_J_STATUS=NO_FIX_AVAILABLE
      BCC_J_REASON=$(bcc_msg r_no_fix)
      BCC_J_NEXT=$(bcc_msg n_wait_vendor)
      ;;
    derived)
      BCC_J_STATUS=VULNERABLE
      BCC_J_REASON=$(bcc_msg r_derived)
      ;;
    unknown)
      BCC_J_STATUS=UNKNOWN
      BCC_J_REASON=$(bcc_msg r_data_unknown)
      BCC_J_NEXT=$(bcc_msg n_check_vendor)
      ;;
  esac
  [[ $BCC_D_STATUS == analysis ]] && BCC_J_REASON+=" $(bcc_msg r_analysis_basis)"
  [[ -n $BCC_D_NOTE ]] && BCC_J_EVIDENCE+="; $BCC_D_NOTE"
  return 0
}
