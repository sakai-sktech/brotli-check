# shellcheck shell=bash
# C08 curl, C09 vendored copies of the Brotli decoder.

bcc_check_c08() {
  local bin out has_br="" link rc libpath method
  local -a cands=()
  mapfile -t cands < <(printf '%s\n' /usr/bin/curl /usr/local/bin/curl '/opt/*/bin/curl' | bcc_candidates curl)
  for bin in ${cands[@]+"${cands[@]}"}; do
    BCC_JUDGED[$bin]=1
    bcc_note_exec_safety "$bin"
    has_br=""
    if out=$(bcc_probe "$bin" -V); then
      if grep -i '^Features:' <<<"$out" | grep -qiw brotli; then has_br=1; else has_br=0; fi
    fi
    rc=0
    link=$(bcc_links_brotlidec "$bin") || rc=$?
    if ((rc == 0)); then
      bcc_split_tab "$link"
      libpath=${BCC_F[0]}
      method=${BCC_F[1]}
      bcc_add_info C08 "$(bcc_msg i_uses_os_lib "$bin" curl "$libpath" "$method") $(bcc_msg i_c08_compressed)"
    elif ((rc == 1)); then
      if [[ $has_br == 1 ]] || { [[ -z $has_br ]] && bcc_has_brotli_decoder_marker "$bin"; }; then
        bcc_report_by_strings C08 curl "$bin" "" "$(bcc_msg r_c08_static)"
      else
        bcc_add_finding C08 NOT_APPLICABLE curl "$bin" "" "$(bcc_msg r_c08_no_brotli)" "$(bcc_msg n_none)" "" ""
      fi
    else
      bcc_add_finding C08 UNKNOWN curl "$bin" "" "$(bcc_msg r_link_undetermined)" "$(bcc_msg n_install_binutils)" "" ""
    fi
  done
}

# Owned by a package built from the brotli source (judged by C01)?
bcc_owned_by_brotli_source() {
  local owner p
  owner=$(bcc_dpkg_owner "$1") || return 1
  for p in ${owner//,/ }; do
    case " $BCC_C01_PACKAGES " in *" ${p%%:*} "*) return 0 ;; esac
  done
  return 1
}

# Shared/static libbrotlidec outside dpkg (built from source, conda, bundled in /opt):
# found by file name on every run, judged by the version in the file name and by strings.
bcc_c09_lib_entry() {
  local f=$1 base ver="" series res hstatus count kind=shared
  base=${f##*/}
  [[ $base == *.so* || $base == *.a ]] || return 0
  [[ $base == *.a ]] && kind=static
  # conda environments are reported by C06 (conda-meta) already.
  [[ -d $(dirname -- "$(dirname -- "$f")")/conda-meta ]] && return 0
  bcc_dpkg_owner "$f" >/dev/null && return 0
  [[ $base =~ \.so\.([0-9]+\.[0-9]+\.[0-9]+)$ ]] && ver=${BASH_REMATCH[1]}
  res=$(bcc_brotli_heuristic "$f")
  bcc_split_tab "$res"
  hstatus=${BCC_F[0]}
  count=${BCC_F[1]}
  BCC_JUDGED[$f]=1
  if [[ -z $ver ]]; then
    bcc_report_by_strings C09 "libbrotlidec ($kind)" "$f" "" "$(bcc_msg r_c09_lib_noversion)"
    return 0
  fi
  series=${ver%.*}
  bcc_judge brotli "$series" semver "$ver"
  if [[ ($BCC_J_STATUS == FIXED && $hstatus == LIKELY_VULNERABLE) || ($BCC_J_STATUS == VULNERABLE && $hstatus == LIKELY_FIXED) ]]; then
    bcc_add_finding C09 UNKNOWN "libbrotlidec ($kind)" "$f" "$ver" "$(bcc_msg r_c09_conflict "$BCC_J_STATUS" "$hstatus")" \
      "$(bcc_msg n_check_vendor)" "$(bcc_msg e_heur "$count" "$([[ $hstatus == LIKELY_FIXED ]] && echo yes || echo no)"); $BCC_J_EVIDENCE" ""
    return 0
  fi
  local next=$BCC_J_NEXT
  [[ $BCC_J_STATUS == VULNERABLE ]] && next=$(bcc_msg n_update_lib "$f" "$BCC_J_FIXED")
  bcc_add_finding C09 "$BCC_J_STATUS" "libbrotlidec ($kind)" "$f" "$ver" "$BCC_J_REASON" "$next" \
    "$(bcc_msg e_heur "$count" "$([[ $hstatus == LIKELY_FIXED ]] && echo yes || echo no)"); $BCC_J_EVIDENCE" ""
}

bcc_check_c09_libs() {
  local f
  for f in ${BCC_IDX_LIB[@]+"${BCC_IDX_LIB[@]}"}; do
    bcc_c09_lib_entry "$f"
  done
}

bcc_c09_collect() {
  BCC_C09_FILES+=("$1")
}

# --deep: any ELF under --roots that carries the decoder but does not load libbrotlidec.
bcc_check_c09_deep() {
  BCC_C09_FILES=()
  bcc_find_each bcc_c09_collect ${BCC_ROOTS[@]+"${BCC_ROOTS[@]}"} -- \
    -type f -size "-$((BCC_MAX_ELF_MB * 1024))k" \( -perm -u=x -o -name '*.so' -o -name '*.so.*' -o -name '*.node' \)
  bcc_find_status $? "C09 --deep"
  ((${#BCC_C09_FILES[@]})) || return 0
  local f needed
  while IFS= read -r -d '' f; do
    [[ -z ${BCC_JUDGED[$f]:-} ]] || continue
    bcc_is_pkg_cache "$f" && continue
    bcc_is_elf "$f" || continue
    [[ ${f##*/} == libbrotlidec* ]] && continue
    # A program that links libbrotlidec dynamically names the decoder symbols in .dynstr; not a copy.
    needed=$(bcc_elf_needed "$f" 2>/dev/null || true)
    grep -q '^libbrotlidec' <<<"$needed" && continue
    bcc_owned_by_brotli_source "$f" && continue
    BCC_JUDGED[$f]=1
    bcc_report_by_strings C09 "${f##*/}" "$f" "" "$(bcc_msg r_c09_vendored)"
  done < <(printf '%s\0' "${BCC_C09_FILES[@]}" |
    timeout -k 2 "$BCC_TIMEOUT" xargs -0 -r env LC_ALL=C grep -l -Z -a -E \
      'BrotliDecoderDecompressStream|BrotliDecoderCreateInstance|_ERROR_FORMAT_EXUBERANT_NIBBLE' -- 2>/dev/null)
}
