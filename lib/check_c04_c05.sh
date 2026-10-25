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

# Prints "VERSION<TAB>METHOD" (METHOD: exec | header | path).
bcc_node_version() {
  local bin=$1 out v hdr ma mi pa re
  if out=$(bcc_probe "$bin" --version) && v=$(bcc_version_from_output "$out" '^v([0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*$'); then
    printf '%s\texec\n' "$v"
    return 0
  fi
  # Official tarballs ship include/node/node_version.h next to bin/.
  hdr="$(dirname -- "$(dirname -- "$bin")")/include/node/node_version.h"
  if [[ -r $hdr ]]; then
    ma=$(sed -n 's/^#define NODE_MAJOR_VERSION \([0-9][0-9]*\).*/\1/p' "$hdr" | head -n 1)
    mi=$(sed -n 's/^#define NODE_MINOR_VERSION \([0-9][0-9]*\).*/\1/p' "$hdr" | head -n 1)
    pa=$(sed -n 's/^#define NODE_PATCH_VERSION \([0-9][0-9]*\).*/\1/p' "$hdr" | head -n 1)
    [[ -n $ma && -n $mi && -n $pa ]] && { printf '%s.%s.%s\theader\n' "$ma" "$mi" "$pa"; return 0; }
  fi
  # Version managers keep one directory per version: .../v22.17.1/bin/node, .../node-v22.17.1-linux-x64/bin/node
  re='/(node-)?v?([0-9]+\.[0-9]+\.[0-9]+)[^/]*/(installation/)?bin/[^/]+$'
  [[ $bin =~ $re ]] && { printf '%s\tpath\n' "${BASH_REMATCH[2]}"; return 0; }
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
  local id=$1 comp=$2 path=$3 ver=$4 prefix=$5 res status count
  res=$(bcc_brotli_heuristic "$path")
  bcc_split_tab "$res"
  status=${BCC_F[0]}
  count=${BCC_F[1]}
  case $status in
    LIKELY_FIXED)
      bcc_add_finding "$id" LIKELY_FIXED "$comp" "$path" "$ver" "$prefix $(bcc_msg r_heur_fixed)" \
        "$(bcc_msg n_confirm_vendor)" "$(bcc_msg e_heur "$count" yes)" "$(bcc_msg conf_heur)"
      ;;
    LIKELY_VULNERABLE)
      bcc_add_finding "$id" LIKELY_VULNERABLE "$comp" "$path" "$ver" "$prefix $(bcc_msg r_heur_vuln)" \
        "$(bcc_msg n_update_product)" "$(bcc_msg e_heur "$count" no)" "$(bcc_msg conf_heur)"
      ;;
    *)
      bcc_add_finding "$id" VENDORED_COPY "$comp" "$path" "$ver" "$prefix $(bcc_msg r_heur_none)" \
        "$(bcc_msg n_check_vendor)" "$(bcc_msg e_heur "$count" no)" ""
      ;;
  esac
}

bcc_check_c04() {
  local bin owner link rc libpath method ver vm major pids next
  local -a cands=()
  mapfile -t cands < <({ bcc_node_patterns; bcc_index_list ${BCC_IDX_NODE[@]+"${BCC_IDX_NODE[@]}"}; } | bcc_candidates 'node|nodejs')
  bcc_scan_proc_exes C04 node nodejs
  # Running node executables outside the searched places are judged too.
  local pid exe c known
  for pid in "${!BCC_PROC_EXE[@]}"; do
    exe=${BCC_PROC_EXE[$pid]}
    known=0
    for c in ${cands[@]+"${cands[@]}"}; do [[ $c == "$exe" ]] && known=1; done
    ((known)) || { bcc_is_elf "$exe" && cands+=("$exe"); }
  done
  for bin in ${cands[@]+"${cands[@]}"}; do
    BCC_JUDGED[$bin]=1
    pids=$(bcc_pids_of "$bin")
    if owner=$(bcc_dpkg_owner "$bin"); then
      link=$(bcc_links_brotlidec "$bin")
      rc=$?
      if ((rc == 0)); then
        bcc_split_tab "$link"
        libpath=${BCC_F[0]}
        method=${BCC_F[1]}
        bcc_add_info C04 "$(bcc_msg i_uses_os_lib "$bin" "$owner" "$libpath" "$method")"
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

bcc_check_c05() {
  local bin out ver method pids next re='/v?([0-9]+\.[0-9]+\.[0-9]+)[^/]*/bin/bun$'
  local -a cands=()
  mapfile -t cands < <({ bcc_bun_patterns; bcc_index_list ${BCC_IDX_BUN[@]+"${BCC_IDX_BUN[@]}"}; } | bcc_candidates bun)
  bcc_scan_proc_exes C05 bun
  for bin in ${cands[@]+"${cands[@]}"}; do
    BCC_JUDGED[$bin]=1
    pids=$(bcc_pids_of "$bin")
    ver=""
    if out=$(bcc_probe "$bin" --version) && ver=$(bcc_version_from_output "$out" '^([0-9]+\.[0-9]+\.[0-9]+)([-+][0-9A-Za-z.]+)?[[:space:]]*$'); then
      method=exec
    else
      ver=""
    fi
    if [[ -z $ver && $bin =~ $re ]]; then
      ver=${BASH_REMATCH[1]}
      method=path
    fi
    if [[ -z $ver ]]; then
      bcc_report_by_strings C05 bun "$bin" "" "$(bcc_msg r_version_unknown)"
      continue
    fi
    bcc_judge bun '*' semver "$ver"
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
