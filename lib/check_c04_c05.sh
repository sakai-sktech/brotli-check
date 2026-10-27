# shellcheck shell=bash
# C04 Node.js, C05 Bun. Both bundle Brotli statically (official builds), so the
# runtime's own version decides. process.versions.brotli is never used: fixed
# Node.js 22.23.4 still reports "1.1.0" (data/advisories.tsv, node 22).

bcc_node_patterns() {
  local h
  printf '%s\n' /usr/bin/node /usr/bin/nodejs /usr/local/bin/node '/opt/*/bin/node' '/opt/*/*/bin/node' \
    '/usr/local/n/versions/node/*/bin/node' '/snap/node/current/bin/node'
  for h in ${BCC_HOMES[@]+"${BCC_HOMES[@]}"}; do
    printf '%s\n' "$h/.nvm/versions/node/*/bin/node" "$h/.volta/tools/image/node/*/bin/node" \
      "$h/.fnm/node-versions/*/installation/bin/node" "$h/.local/share/fnm/node-versions/*/installation/bin/node" \
      "$h/.asdf/installs/nodejs/*/bin/node" "$h/.local/share/mise/installs/node/*/bin/node" \
      "$h/n/versions/node/*/bin/node" "$h/.local/bin/node"
  done
}

# Prints "VERSION<TAB>METHOD" (METHOD: exec | header | path). Pre-release suffixes are kept
# (v24.0.0-rc.1, v26.0.0-nightly...; a header of a non-release build gives X.Y.Z-pre).
bcc_node_version() {
  local bin=$1 out v hdr text ma mi pa rel re
  if out=$(bcc_probe "$bin" --version) && v=$(bcc_version_from_output "$out" '^(v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)[[:space:]]*$'); then
    printf '%s\texec\n' "$(bcc_semver_parse "$v")"
    return 0
  fi
  # Official tarballs ship include/node/node_version.h next to bin/.
  hdr="$(dirname -- "$(dirname -- "$bin")")/include/node/node_version.h"
  if text=$(bcc_read_file "$hdr" 65536); then
    ma=$(sed -n 's/^#define NODE_MAJOR_VERSION \([0-9][0-9]*\).*/\1/p' <<<"$text" | head -n 1)
    mi=$(sed -n 's/^#define NODE_MINOR_VERSION \([0-9][0-9]*\).*/\1/p' <<<"$text" | head -n 1)
    pa=$(sed -n 's/^#define NODE_PATCH_VERSION \([0-9][0-9]*\).*/\1/p' <<<"$text" | head -n 1)
    rel=$(sed -n 's/^#define NODE_VERSION_IS_RELEASE \([0-9][0-9]*\).*/\1/p' <<<"$text" | head -n 1)
    if [[ -n $ma && -n $mi && -n $pa ]]; then
      printf '%s.%s.%s%s\theader\n' "$ma" "$mi" "$pa" "$([[ $rel == 0 ]] && printf -- -pre)"
      return 0
    fi
  fi
  # Version managers keep one directory per version: .../v22.17.1/bin/node, .../node-v22.17.1-linux-x64/bin/node
  re='/([^/]+)/(installation/)?bin/[^/]+$'
  [[ $bin =~ $re ]] && v=$(bcc_version_from_dirname "${BASH_REMATCH[1]}") && { printf '%s\tpath\n' "$v"; return 0; }
  return 1
}

# Running processes per executable: fills BCC_PROC_EXE[pid]=path and reports deleted
# executables of the given names as RESTART_REQUIRED. Usage: bcc_scan_proc_exes ID NAME...
bcc_scan_proc_exes() {
  local id=$1 d pid exe base n match
  shift
  declare -gA BCC_PROC_EXE=()
  local proc=${BCC_PROC_ROOT:-/proc}
  for d in "$proc"/[0-9]*; do
    exe=$(readlink -- "$d/exe" 2>/dev/null) || continue
    pid=${d##*/}
    base=${exe##*/}
    match=0
    for n in "$@"; do [[ ${base%" (deleted)"} == "$n" ]] && match=1; done
    ((match)) || continue
    if [[ $exe == *" (deleted)" ]]; then
      bcc_add_finding "$id" RESTART_REQUIRED "pid $pid" "${exe%" (deleted)"}" "" "$(bcc_msg r_exe_deleted)" \
        "$(bcc_msg n_restart)" "$(bcc_proc_evidence "$d")" ""
    else
      BCC_PROC_EXE[$pid]=$exe
    fi
  done
}

# PIDs (space separated) running PATH, from BCC_PROC_EXE.
bcc_pids_of() {
  local pid out=""
  for pid in "${!BCC_PROC_EXE[@]}"; do
    [[ ${BCC_PROC_EXE[$pid]} == "$1" ]] && out+="$pid "
  done
  printf '%s' "${out% }"
}

# Report a binary that bundles Brotli statically but whose version is unknown, or whose
# version number may not reflect a distributor's backport: use the C09 string heuristic.
# Usage: bcc_report_by_strings ID COMPONENT PATH VERSION REASON-PREFIX
bcc_report_by_strings() {
  local id=$1 comp=$2 path=$3 ver=$4 prefix=$5 res status count dicts
  res=$(bcc_brotli_heuristic "$path")
  bcc_split_tab "$res"
  status=${BCC_F[0]}
  count=${BCC_F[1]}
  dicts=${BCC_F[3]:-0}
  case $status in
    LIKELY_FIXED)
      bcc_add_finding "$id" LIKELY_FIXED "$comp" "$path" "$ver" "$prefix $(bcc_msg r_heur_fixed "$dicts")" \
        "$(bcc_msg n_confirm_vendor)" "$(bcc_msg e_heur "$count" yes)" "$(bcc_msg conf_heur)"
      ;;
    LIKELY_VULNERABLE)
      bcc_add_finding "$id" LIKELY_VULNERABLE "$comp" "$path" "$ver" "$prefix $(bcc_msg r_heur_vuln)" \
        "$(bcc_msg n_update_product)" "$(bcc_msg e_heur "$count" no)" "$(bcc_msg conf_heur)"
      ;;
    MULTIPLE_COPIES)
      bcc_add_finding "$id" UNKNOWN "$comp" "$path" "$ver" "$prefix $(bcc_msg r_heur_multiple)" \
        "$(bcc_msg n_check_vendor)" "$(bcc_msg e_heur "$count" yes); $(bcc_msg e_dicts "$dicts")" ""
      ;;
    INCOMPLETE)
      bcc_add_finding "$id" UNKNOWN "$comp" "$path" "$ver" "$prefix $(bcc_msg r_heur_incomplete "$BCC_MAX_ELF_MB")" \
        "$(bcc_msg n_check_vendor)" "" ""
      bcc_note_incomplete "$path"
      ;;
    *)
      bcc_add_finding "$id" VENDORED_COPY "$comp" "$path" "$ver" "$prefix $(bcc_msg r_heur_none)" \
        "$(bcc_msg n_check_vendor)" "$(bcc_msg e_heur "$count" no)" ""
      ;;
  esac
}

# The node executables C04 judges (and bcc_build_exec_plan asks about): the known places,
# the index, and the executables of running node processes. Computed once (BCC_C04_CANDS).
bcc_c04_candidates() {
  [[ -z ${BCC_C04_DONE:-} ]] || return 0
  local exe c known
  bcc_collect0 < <({ bcc_node_patterns | bcc_glob_records; bcc_index_list ${BCC_IDX_NODE[@]+"${BCC_IDX_NODE[@]}"}; } | bcc_candidates 'node|nodejs')
  BCC_C04_CANDS=(${BCC_LIST[@]+"${BCC_LIST[@]}"})
  # Running node executables outside the searched places are judged too.
  while IFS= read -r -d '' exe; do
    known=0
    for c in ${BCC_C04_CANDS[@]+"${BCC_C04_CANDS[@]}"}; do [[ $c == "$exe" ]] && known=1; done
    ((known)) || { bcc_is_elf "$exe" && BCC_C04_CANDS+=("$exe"); }
  done < <(bcc_running_exes node nodejs)
  BCC_C04_DONE=1
}

bcc_check_c04() {
  local bin owner link rc libpath method ver vm major pids next
  bcc_c04_candidates
  bcc_scan_proc_exes C04 node nodejs
  for bin in ${BCC_C04_CANDS[@]+"${BCC_C04_CANDS[@]}"}; do
    BCC_JUDGED[$bin]=1
    pids=$(bcc_pids_of "$bin")
    if owner=$(bcc_dpkg_owner "$bin"); then
      rc=0
      link=$(bcc_links_brotlidec "$bin") || rc=$?
      if ((rc == 0)); then
        bcc_split_tab "$link"
        libpath=${BCC_F[0]}
        method=${BCC_F[1]}
        bcc_report_linked_lib C04 "$owner" "$bin" "$libpath" "$method"
        bcc_report_own_copy C04 "node ($owner)" "$bin"
        continue
      elif ((rc == 1)); then
        vm=$(bcc_node_version "$bin") || vm=""
        bcc_split_tab "$vm"
        bcc_report_by_strings C04 "node ($owner)" "$bin" "${BCC_F[0]:-}" "$(bcc_msg r_distro_static)"
        continue
      fi
      bcc_add_finding C04 UNKNOWN node "$bin" "" "$(bcc_msg r_link_undetermined)" "$(bcc_msg n_install_binutils)" "" ""
      continue
    fi
    if ! vm=$(bcc_node_version "$bin"); then
      bcc_report_by_strings C04 node "$bin" "" "$(bcc_msg r_version_unknown)"
      continue
    fi
    bcc_split_tab "$vm"
    ver=${BCC_F[0]}
    method=${BCC_F[1]}
    major=${ver%%.*}
    bcc_judge node "$major" semver "$ver"
    [[ $method == exec ]] || bcc_crosscheck_fixed "$bin"
    next=$BCC_J_NEXT
    if [[ $BCC_J_STATUS == VULNERABLE ]]; then
      if [[ $BCC_D_STATUS == derived ]]; then
        next=$(bcc_msg n_node_move_line)
      else
        next=$(bcc_msg n_update_runtime "$BCC_J_FIXED")
      fi
      [[ -n $pids ]] && next+=" $(bcc_msg n_restart_pids "$pids")"
    fi
    bcc_add_finding C04 "$BCC_J_STATUS" node "$bin" "$ver" "$BCC_J_REASON" "$next" \
      "$(bcc_msg e_version_method "$method")${pids:+; pids $pids}; $BCC_J_EVIDENCE" ""
  done
}

bcc_bun_patterns() {
  local h
  printf '%s\n' /usr/local/bin/bun /usr/bin/bun '/opt/*/bin/bun'
  for h in ${BCC_HOMES[@]+"${BCC_HOMES[@]}"}; do
    printf '%s\n' "$h/.bun/bin/bun" "$h/.local/share/mise/installs/bun/*/bin/bun" "$h/.asdf/installs/bun/*/bin/bun"
  done
}

bcc_c05_candidates() {
  [[ -z ${BCC_C05_DONE:-} ]] || return 0
  bcc_collect0 < <({ bcc_bun_patterns | bcc_glob_records; bcc_index_list ${BCC_IDX_BUN[@]+"${BCC_IDX_BUN[@]}"}; } | bcc_candidates bun)
  BCC_C05_CANDS=(${BCC_LIST[@]+"${BCC_LIST[@]}"})
  BCC_C05_DONE=1
}

bcc_check_c05() {
  local bin out ver method pids next re='/([^/]+)/bin/bun$'
  bcc_c05_candidates
  bcc_scan_proc_exes C05 bun
  for bin in ${BCC_C05_CANDS[@]+"${BCC_C05_CANDS[@]}"}; do
    BCC_JUDGED[$bin]=1
    pids=$(bcc_pids_of "$bin")
    ver=""
    # The whole version, pre-release included (1.4.4-rc.1 is not 1.4.4).
    if out=$(bcc_probe "$bin" --version) && ver=$(bcc_version_from_output "$out" '^([0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)*)[[:space:]]*$') &&
      ver=$(bcc_semver_parse "$ver"); then
      method="exec"
    else
      ver=""
    fi
    if [[ -z $ver && $bin =~ $re ]] && ver=$(bcc_version_from_dirname "${BASH_REMATCH[1]}"); then
      method=path
    fi
    if [[ -z $ver ]]; then
      bcc_report_by_strings C05 bun "$bin" "" "$(bcc_msg r_version_unknown)"
      continue
    fi
    bcc_judge bun '*' semver "$ver"
    [[ $method == exec ]] || bcc_crosscheck_fixed "$bin"
    next=$BCC_J_NEXT
    if [[ $BCC_J_STATUS == VULNERABLE ]]; then
      next=$(bcc_msg n_update_runtime "$BCC_J_FIXED")
      [[ -n $pids ]] && next+=" $(bcc_msg n_restart_pids "$pids")"
      next+=" $(bcc_msg n_bun_compiled)"
    fi
    bcc_add_finding C05 "$BCC_J_STATUS" bun "$bin" "$ver" "$BCC_J_REASON" "$next" \
      "$(bcc_msg e_version_method "$method")${pids:+; pids $pids}; $BCC_J_EVIDENCE" ""
  done
}
