# shellcheck shell=bash
# C01 OS packages, C02 packages using the OS libbrotli (information), C03 processes needing a restart.

BCC_C01_PACKAGES="libbrotli1 brotli libbrotli-dev python3-brotli"

# C01: compare the *source* package version with the distributor's fixed version, so
# binNMU suffixes (+b2) on binary packages do not matter. python3-brotli is compiled
# statically from the brotli source, so it gets its own finding.
bcc_check_c01() {
  BCC_C01_LIB_STATUS=""
  if ! bcc_have dpkg-query; then
    bcc_skip C01 "$(bcc_msg skip_no_dpkg)"
    return
  fi
  local line st pkg ver src srcver next any=0
  # shellcheck disable=SC2016  # dpkg-query format, not shell expansion
  local fmt='${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n'
  # shellcheck disable=SC2086  # package list is a fixed word list
  while IFS= read -r line; do
    bcc_split_tab "$line"
    st=${BCC_F[0]}
    pkg=${BCC_F[1]:-}
    ver=${BCC_F[2]:-}
    src=${BCC_F[3]:-}
    srcver=${BCC_F[4]:-}
    [[ $st == [ih]i* ]] || continue
    any=1
    [[ -n $src ]] || src=${pkg%%:*}
    [[ -n $srcver ]] || srcver=$ver
    if [[ -z $BCC_DEB_SERIES ]]; then
      BCC_J_STATUS=UNKNOWN
      BCC_J_REASON=$(bcc_msg r_unknown_series "${BCC_OS_ID:-?}")
      BCC_J_NEXT=$(bcc_msg n_check_vendor)
      BCC_J_EVIDENCE=""
    else
      bcc_judge "deb-src:$src" "$BCC_DEB_SERIES" deb "$srcver"
    fi
    next=$BCC_J_NEXT
    case $BCC_J_STATUS in
      VULNERABLE) next=$(bcc_msg n_update_pkg "$(printf '%q' "${pkg%%:*}")" "$BCC_J_FIXED") ;;
      FIXED) next=$(bcc_msg n_restart_after_update) ;;
    esac
    bcc_add_finding C01 "$BCC_J_STATUS" "${pkg%%:*}" "dpkg ($BCC_DEB_SERIES)" "$ver" "$BCC_J_REASON" "$next" \
      "source $src $srcver; $BCC_J_EVIDENCE" ""
    [[ ${pkg%%:*} == libbrotli1 && -z $BCC_C01_LIB_STATUS ]] && BCC_C01_LIB_STATUS=$BCC_J_STATUS
  done < <(bcc_sys dpkg-query -W -f "$fmt" $BCC_C01_PACKAGES)
  ((any)) || bcc_add_info C01 "$(bcc_msg i_c01_none)"
}

# C02: installed packages that depend on libbrotli1 are fixed by C01's update plus a restart.
bcc_check_c02() {
  bcc_have dpkg-query || return 0
  local line name re='(^|[ ,|])libbrotli1([ :(,]|$)'
  local -a deps=()
  # shellcheck disable=SC2016
  local fmt='${db:Status-Abbrev}\t${binary:Package}\t${Depends}, ${Pre-Depends}\n'
  while IFS= read -r line; do
    bcc_split_tab "$line"
    [[ ${BCC_F[0]} == [ih]i* ]] || continue
    name=${BCC_F[1]%%:*}
    case " $BCC_C01_PACKAGES " in *" $name "*) continue ;; esac
    [[ ${BCC_F[2]:-} =~ $re ]] || continue
    deps+=("$name")
  done < <(bcc_sys dpkg-query -W -f "$fmt")
  ((${#deps[@]})) || return 0
  local list
  list=$(printf '%s\n' "${deps[@]}" | sort -u | paste -sd, - | sed 's/,/, /g')
  bcc_add_info C02 "$(bcc_msg i_c02_dependents "$(printf '%s\n' "${deps[@]}" | sort -u | grep -c .)" "$list")"
}

# C03: a process that still maps a deleted libbrotlidec (or python3-brotli's _brotli*.so)
# keeps running the old code after an update.
bcc_check_c03() {
  local proc=${BCC_PROC_ROOT:-/proc} d pid maps hit exe unreadable=0
  for d in "$proc"/[0-9]*; do
    [[ -d $d ]] || continue
    pid=${d##*/}
    if ! maps=$(cat -- "$d/maps" 2>/dev/null); then
      [[ -e $d/maps ]] && unreadable=$((unreadable + 1))
      continue
    fi
    [[ -n $maps ]] || continue
    hit=$(grep -E '/(libbrotlidec[^/]*\.so[^/]*|_brotli[^/]*\.so) \(deleted\)$' <<<"$maps" |
      sed -E 's/^([^ ]+ +){5}//' | sort -u | head -n 3 | paste -sd, - | sed 's/,/, /g' || true)
    [[ -n $hit ]] || continue
    exe=$(readlink -- "$d/exe" 2>/dev/null) || exe="?"
    bcc_add_finding C03 RESTART_REQUIRED "pid $pid" "$exe" "" "$(bcc_msg r_c03_deleted_lib "$hit")" \
      "$(bcc_msg n_restart)" "$(bcc_proc_evidence "$d")" ""
  done
  ((unreadable == 0)) || bcc_skip "C03 $proc" "$(bcc_msg skip_proc_unreadable "$unreadable")"
}
