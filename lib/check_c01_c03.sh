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
  local line st pkg ver src srcver next any=0 out rc=0
  # shellcheck disable=SC2016  # dpkg-query format, not shell expansion
  local fmt='${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n'
  # Status 1 only means that some of the packages are not installed; 2 and above (and a
  # timeout) mean the database could not be read: then nothing may be said about them.
  # shellcheck disable=SC2086  # package list is a fixed word list
  out=$(bcc_sys dpkg-query -W -f "$fmt" $BCC_C01_PACKAGES) || rc=$?
  if ((rc > 1)); then
    bcc_skip C01 "$(bcc_msg skip_dpkg_failed "$rc")"
    return
  fi
  while IFS= read -r line; do
    [[ -n $line ]] || continue
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
    BCC_C01_JUDGED[${pkg%%:*}]=1
    # The files of this package are judged by this finding (bcc_c01_notes). A package of two
    # architectures has one version (Multi-Arch: same), so the first status stands.
    [[ -n ${BCC_C01_STATUS[${pkg%%:*}]:-} ]] || BCC_C01_STATUS[${pkg%%:*}]=$BCC_J_STATUS
    [[ ${pkg%%:*} == libbrotli1 && -z $BCC_C01_LIB_STATUS ]] && BCC_C01_LIB_STATUS=$BCC_J_STATUS
  done <<<"$out"
  ((any)) || bcc_add_info C01 "$(bcc_msg i_c01_none)"
}

# C02: installed packages that depend on libbrotli1 are fixed by C01's update plus a restart.
bcc_check_c02() {
  bcc_have dpkg-query || return 0
  local line name re='(^|[ ,|])libbrotli1([ :(,]|$)' out rc=0
  local -a deps=()
  # shellcheck disable=SC2016
  local fmt='${db:Status-Abbrev}\t${binary:Package}\t${Depends}, ${Pre-Depends}\n'
  out=$(bcc_sys dpkg-query -W -f "$fmt") || rc=$?
  if ((rc > 1)); then
    bcc_skip C02 "$(bcc_msg skip_dpkg_failed "$rc")"
    return 0
  fi
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    bcc_split_tab "$line"
    [[ ${BCC_F[0]} == [ih]i* ]] || continue
    name=${BCC_F[1]%%:*}
    case " $BCC_C01_PACKAGES " in *" $name "*) continue ;; esac
    [[ ${BCC_F[2]:-} =~ $re ]] || continue
    deps+=("$name")
  done <<<"$out"
  ((${#deps[@]})) || return 0
  local list
  list=$(printf '%s\n' "${deps[@]}" | sort -u | paste -sd, - | sed 's/,/, /g')
  bcc_add_info C02 "$(bcc_msg i_c02_dependents "$(printf '%s\n' "${deps[@]}" | sort -u | grep -c .)" "$list")"
}

# --- Processes that still run a deleted file (C03, and C04/C05 for executables) -------
# The kernel shows that a file a process runs was deleted; it does not say whether the file
# now at that path (if any) is fixed. That is what the other checks of this run judged, so the
# next step is taken from them (issue #5). The deleted file itself is not read: whatever the
# old code was, a process running it is restarted once the disk is fixed.

# Owners of PATH that C01 judged, into BCC_C01_NOTES as bcc_note_disk lines (C01, package,
# status). Called in the caller's shell, not in $(...): dpkg is then asked once per path
# (BCC_DPKG_CACHE), not once per process that maps it.
bcc_c01_notes() {
  local owner p
  BCC_C01_NOTES=""
  bcc_dpkg_owner "$1" >/dev/null || return 0 # (fills BCC_DPKG_CACHE: the next call reads it)
  owner=$(bcc_dpkg_owner "$1") || return 0
  for p in ${owner//,/ }; do
    p=${p%%:*}
    [[ -z ${BCC_C01_STATUS[$p]:-} ]] || BCC_C01_NOTES+="C01"$'\t'"$p"$'\t'"${BCC_C01_STATUS[$p]}"$'\n'
  done
  return 0
}

# FILE loads the libraries LIB...: what this run said about them holds for FILE as well.
bcc_note_loaded() {
  local file=$1 lib line
  shift
  for lib in "$@"; do
    bcc_c01_notes "$lib"
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      bcc_split_tab "$line"
      bcc_note_disk "$file" "${BCC_F[0]}" "${BCC_F[1]}" "${BCC_F[2]}"
    done <<<"${BCC_DISK_JUDGED[$lib]:-}$BCC_C01_NOTES"
  done
}

# Does the process at DIR (/proc/<pid>) see the files this tool sees? One in another mount
# namespace (a container, a snap, a flatpak) names its files by the same paths, but they are
# other files. 0: the same namespace; 1: another one; 2: could not be read.
bcc_same_mntns() {
  local mine theirs
  mine=$(readlink -- "${BCC_PROC_ROOT:-/proc}/self/ns/mnt" 2>/dev/null) || return 2
  theirs=$(readlink -- "$1/ns/mnt" 2>/dev/null) || return 2
  [[ -n $mine && -n $theirs ]] || return 2
  [[ $mine == "$theirs" ]] || return 1
}

# The file now at PATH, as this run judged it. Sets BCC_DS_TEXT (a sentence for the reason),
# BCC_DS_CAT (restart: every judgment is FIXED; update: one says the file on disk is not fixed
# either; check: anything else, no judgment, no file) and BCC_DS_REFS (for update: the
# findings whose next step comes first).
bcc_disk_state() {
  local path=$1 real notes line seen="" list="" fixed=0 other=0
  BCC_DS_REFS=""
  BCC_DS_CAT=check
  if [[ ! -e $path ]]; then
    BCC_DS_TEXT=$(bcc_msg r_disk_none)
    return 0
  fi
  bcc_c01_notes "$path"
  notes="${BCC_DISK_JUDGED[$path]:-}$BCC_C01_NOTES"
  real=$(bcc_realpath "$path") || real=""
  if [[ -n $real && $real != "$path" ]]; then
    bcc_c01_notes "$real"
    notes+="${BCC_DISK_JUDGED[$real]:-}$BCC_C01_NOTES"
  fi
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    case $seen in *$'\n'"$line"$'\n'*) continue ;; esac
    seen+=$'\n'"$line"$'\n'
    bcc_split_tab "$line"
    list+="${list:+, }${BCC_F[0]} ${BCC_F[1]}: ${BCC_F[2]}"
    case ${BCC_F[2]} in
      VULNERABLE | NO_FIX_AVAILABLE | LIKELY_VULNERABLE) BCC_DS_REFS+="${BCC_DS_REFS:+, }${BCC_F[0]} ${BCC_F[1]}" ;;
      FIXED) fixed=1 ;;
      *) other=1 ;;
    esac
  done <<<"$notes"
  if [[ -z $list ]]; then
    BCC_DS_TEXT=$(bcc_msg r_disk_unjudged)
    return 0
  fi
  BCC_DS_TEXT=$(bcc_msg r_disk_judged "$list")
  if [[ -n $BCC_DS_REFS ]]; then
    BCC_DS_CAT=update
  elif ((fixed && !other)); then
    BCC_DS_CAT=restart
  fi
  return 0
}

# For a process at DIR that still runs the deleted files PATH...: sets BCC_RA_REASON (what is
# at those paths now) and BCC_RA_NEXT (restart; update first; or check the disk first).
bcc_restart_advice() {
  local dir=$1 path cat=restart refs="" rc=0
  shift
  BCC_RA_REASON=""
  bcc_same_mntns "$dir" || rc=$?
  if ((rc == 1)); then
    BCC_RA_REASON=$(bcc_msg r_disk_other_ns)
  elif ((rc != 0)); then
    BCC_RA_REASON=$(bcc_msg r_disk_ns_unknown)
  fi
  if ((rc != 0)); then
    BCC_RA_NEXT=$(bcc_msg n_restart_check_first)
    return 0
  fi
  for path in "$@"; do
    bcc_disk_state "$path"
    if (($# > 1)); then
      BCC_RA_REASON+="${BCC_RA_REASON:+ }$path: $BCC_DS_TEXT"
    else
      BCC_RA_REASON=$BCC_DS_TEXT
    fi
    case $BCC_DS_CAT in
      update)
        cat=update
        case ", $refs, " in *", $BCC_DS_REFS, "*) ;; *) refs+="${refs:+, }$BCC_DS_REFS" ;; esac
        ;;
      check) [[ $cat == update ]] || cat=check ;;
    esac
  done
  case $cat in
    restart) BCC_RA_NEXT=$(bcc_msg n_restart) ;;
    update) BCC_RA_NEXT=$(bcc_msg n_restart_update_first "$refs") ;;
    *) BCC_RA_NEXT=$(bcc_msg n_restart_check_first) ;;
  esac
}

# C03: a process that still maps a deleted libbrotlidec (or python3-brotli's _brotli*.so)
# keeps running the old code. Run after the checks that judge the files on disk (C01, C06,
# C09, ...: bcc_run_checks), whose findings say what a restart would load.
bcc_check_c03() {
  local proc=${BCC_PROC_ROOT:-/proc} d pid maps lines hit exe p unreadable=0
  local -a paths
  for d in "$proc"/[0-9]*; do
    [[ -d $d ]] || continue
    pid=${d##*/}
    if ! maps=$(cat -- "$d/maps" 2>/dev/null); then
      [[ -e $d/maps ]] && unreadable=$((unreadable + 1))
      continue
    fi
    [[ -n $maps ]] || continue
    lines=$(grep -E '/(libbrotlidec[^/]*\.so[^/]*|_brotli[^/]*\.so) \(deleted\)$' <<<"$maps" |
      sed -E 's/^([^ ]+ +){5}//' | sort -u || true)
    [[ -n $lines ]] || continue
    hit=$(head -n 3 <<<"$lines" | paste -sd, - | sed 's/,/, /g')
    paths=()
    while IFS= read -r p; do paths+=("${p%" (deleted)"}"); done <<<"$lines"
    exe=$(readlink -- "$d/exe" 2>/dev/null) || exe="?"
    bcc_restart_advice "$d" "${paths[@]}"
    bcc_add_finding C03 RESTART_REQUIRED "pid $pid" "$exe" "" "$(bcc_msg r_c03_deleted_lib "$hit") $BCC_RA_REASON" \
      "$BCC_RA_NEXT" "$(bcc_proc_evidence "$d")" ""
  done
  ((unreadable == 0)) || bcc_skip "C03 $proc" "$(bcc_msg skip_proc_unreadable "$unreadable")"
}
