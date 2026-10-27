# shellcheck shell=bash
# C08 curl, C09 vendored copies of the Brotli decoder.

bcc_c08_candidates() {
  [[ -z ${BCC_C08_DONE:-} ]] || return 0
  bcc_collect0 < <(printf '%s\n' /usr/bin/curl /usr/local/bin/curl '/opt/*/bin/curl' | bcc_glob_records | bcc_candidates curl)
  BCC_C08_CANDS=(${BCC_LIST[@]+"${BCC_LIST[@]}"})
  BCC_C08_DONE=1
}

bcc_check_c08() {
  local bin
  bcc_c08_candidates
  for bin in ${BCC_C08_CANDS[@]+"${BCC_C08_CANDS[@]}"}; do
    bcc_c08_entry "$bin"
  done
}

bcc_c08_entry() {
  local bin=$1 out has_br="" link rc=0 libpath method
  BCC_JUDGED[$bin]=1
  if out=$(bcc_probe "$bin" -V); then
    if grep -i '^Features:' <<<"$out" | grep -qiw brotli; then has_br=1; else has_br=0; fi
  fi
  link=$(bcc_links_brotlidec "$bin") || rc=$?
  if ((rc == 0)); then
    bcc_split_tab "$link"
    libpath=${BCC_F[0]}
    method=${BCC_F[1]}
    bcc_report_linked_lib C08 curl "$bin" "$libpath" "$method" "$(bcc_msg i_c08_compressed)"
    bcc_report_own_copy C08 curl "$bin"
  elif ((rc == 1)); then
    # NOT_APPLICABLE needs curl's own word (-V lists no brotli). A static curl names no
    # decoder symbols and does not use BrotliDecoderErrorString, so without -V the
    # absence of markers proves nothing.
    if [[ $has_br == 1 ]] || { [[ -z $has_br ]] && bcc_has_brotli_decoder_marker "$bin"; }; then
      bcc_report_by_strings C08 curl "$bin" "" "$(bcc_msg r_c08_static)"
    elif [[ $has_br == 0 ]]; then
      bcc_add_finding C08 NOT_APPLICABLE curl "$bin" "" "$(bcc_msg r_c08_no_brotli)" "$(bcc_msg n_none)" "" ""
    else
      bcc_add_finding C08 UNKNOWN curl "$bin" "" "$(bcc_msg r_c08_not_run)" "$(bcc_msg n_c08_check_features)" "" ""
    fi
  else
    bcc_add_finding C08 UNKNOWN curl "$bin" "" "$(bcc_msg r_link_undetermined)" "$(bcc_msg n_install_binutils)" "" ""
  fi
}

# Is PATH covered by a C01 finding? Only when its dpkg owner is one of the packages C01
# actually judged on this run (libbrotli1, brotli, libbrotli-dev, python3-brotli). Any other
# owner (a vendor's .deb bundling its own Brotli under /opt) is judged like an unpackaged file.
bcc_covered_by_c01() {
  local owner p
  owner=$(bcc_dpkg_owner "$1") || return 1
  for p in ${owner//,/ }; do
    [[ -n ${BCC_C01_JUDGED[${p%%:*}]:-} ]] && return 0
  done
  return 1
}

# A program that loads libbrotlidec (bcc_links_brotlidec) is covered by C01 only when that
# very library is one C01 judged. Any other copy - a private libbrotlidec reached through
# RUNPATH, possibly outside the search roots - is judged here like C09's libraries, and one
# that could not be found is UNKNOWN (Codex review round 5).
# Usage: bcc_report_linked_lib ID PRODUCT FILE LIBPATH METHOD [MORE-INFO]
bcc_report_linked_lib() {
  local id=$1 prod=$2 file=$3 lib=$4 method=$5 more=${6:-} real
  real=$(bcc_realpath "$lib") || real=""
  if [[ -z $real || ! -f $real ]]; then
    bcc_add_finding "$id" UNKNOWN "$prod" "$file" "" "$(bcc_msg r_linked_lib_missing "$lib")" "$(bcc_msg n_check_vendor)" "" ""
    return 0
  fi
  if bcc_covered_by_c01 "$real" || bcc_covered_by_c01 "$lib"; then
    bcc_add_info "$id" "$(bcc_msg i_uses_os_lib "$file" "$prod" "$lib" "$method")${more:+ $more}"
    return 0
  fi
  bcc_add_info "$id" "$(bcc_msg i_uses_private_lib "$file" "$prod" "$real" "$method")${more:+ $more}"
  # Judged under the name it is loaded by (libbrotlidec.so.1 -> decoder.bin is still one).
  [[ -n ${BCC_JUDGED[$real]:-} ]] || bcc_c09_lib_entry "$real" "${lib##*/}"
}

# A file that loads libbrotlidec can also carry a decoder of its own (with local symbols).
# Its own decoder error names - which a program that only calls libbrotlidec does not have -
# show it; that copy is then judged by its strings as well.
# Usage: bcc_report_own_copy ID PRODUCT FILE
bcc_report_own_copy() {
  local res
  res=$(bcc_brotli_heuristic "$3")
  bcc_split_tab "$res"
  ((${BCC_F[1]:-0} >= BCC_MIN_ERROR_NAMES)) || return 0
  bcc_report_by_strings "$1" "$2 (own copy)" "$3" "" "$(bcc_msg r_own_copy)"
}

# Shared/static libbrotlidec not covered by C01 (built from source, bundled in /opt, a
# vendor's package): found by file name on every run, judged by the version in the file
# name and by strings. Marked as judged either way, so --deep does not report it again.
# Usage: bcc_c09_lib_entry FILE [NAME]  (NAME: the name it is loaded by, when the file's own
# name is not libbrotlidec*: a symlink target)
bcc_c09_lib_entry() {
  local f=$1 base ver="" series res hstatus count kind=shared
  base=${2:-${f##*/}}
  [[ $base == *.so* || $base == *.a ]] || return 0
  [[ $base == *.a ]] && kind=static
  BCC_JUDGED[$f]=1
  # A conda environment's libbrotlidec is reported by C06 from its conda-meta record; only
  # when C06 did report one for this environment (an empty or unrelated conda-meta/ next to
  # a library proves nothing).
  [[ -n ${BCC_C06_CONDA_ENVS[$(dirname -- "$(dirname -- "$f")")]:-} ]] && return 0
  bcc_covered_by_c01 "$f" && return 0
  [[ $base =~ \.so\.([0-9]+\.[0-9]+\.[0-9]+)$ ]] && ver=${BASH_REMATCH[1]}
  res=$(bcc_brotli_heuristic "$f")
  bcc_split_tab "$res"
  hstatus=${BCC_F[0]}
  count=${BCC_F[1]}
  [[ $hstatus == INCOMPLETE ]] && bcc_note_incomplete "$f"
  if [[ -z $ver ]]; then
    bcc_report_by_strings C09 "libbrotlidec ($kind)" "$f" "" "$(bcc_msg r_c09_lib_noversion)"
    return 0
  fi
  series=${ver%.*}
  bcc_judge brotli "$series" semver "$ver"
  # A file name saying "fixed" needs the strings to confirm it (bcc_crosscheck_fixed: one
  # copy, the fix's error name); an outright disagreement is reported as such below.
  [[ $BCC_J_STATUS == FIXED && $hstatus != LIKELY_VULNERABLE ]] && bcc_crosscheck_fixed "$f"
  if [[ ($BCC_J_STATUS == FIXED && $hstatus == LIKELY_VULNERABLE) ||
    ($BCC_J_STATUS == VULNERABLE && $hstatus == LIKELY_FIXED) ]]; then
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

# The extension module of a PyPI Brotli/brotlicffi that C06 already judged by its metadata.
bcc_c09_judged_by_c06() {
  local f=$1 site
  case $f in
    */_brotli*.so) site=${f%/*} ;;
    */brotlicffi/*.so) site=${f%/brotlicffi/*} ;;
    *) return 1 ;;
  esac
  [[ -n ${BCC_C06_SITES[$site]:-} ]]
}

# Files above the size limit come back from find as "__BCC_BIG=<path>" records (paths from
# find always start with "/"); unreadable ones are counted instead of handed to grep.
bcc_c09_collect() {
  local f=$1
  if [[ $f == __BCC_BIG=* ]]; then
    BCC_C09_BIG=$((BCC_C09_BIG + 1))
    [[ -n $BCC_C09_BIG_EXAMPLE ]] || BCC_C09_BIG_EXAMPLE=${f#__BCC_BIG=}
  elif [[ -r $f ]]; then
    BCC_C09_FILES+=("$f")
  else
    BCC_C09_UNREADABLE=$((BCC_C09_UNREADABLE + 1))
  fi
}

# --deep: any ELF under --roots that carries the decoder but does not load libbrotlidec.
bcc_check_c09_deep() {
  BCC_C09_FILES=()
  BCC_C09_BIG=0 BCC_C09_BIG_EXAMPLE="" BCC_C09_UNREADABLE=0
  bcc_find_each bcc_c09_collect ${BCC_ROOTS[@]+"${BCC_ROOTS[@]}"} -- \
    -type f \( -perm -u=x -o -name '*.so' -o -name '*.so.*' -o -name '*.node' \) \
    \( -size "-$((BCC_MAX_ELF_MB * 1024))k" -o \( -printf '__BCC_BIG=%p\0' -false \) \)
  bcc_find_status $? "C09 --deep"
  ((BCC_C09_BIG == 0)) || bcc_skip "C09 --deep (size)" "$(bcc_msg skip_c09_big "$BCC_C09_BIG" "$BCC_MAX_ELF_MB" "$BCC_C09_BIG_EXAMPLE")"
  ((BCC_C09_UNREADABLE == 0)) || bcc_skip "C09 --deep (unreadable)" "$(bcc_msg skip_c09_unreadable "$BCC_C09_UNREADABLE")"
  ((${#BCC_C09_FILES[@]})) || return 0
  local f needed rc=0 errs=0
  while IFS= read -r -d '' f; do
    case $f in
      __BCC_GREP_RC=*)
        rc=${f#__BCC_GREP_RC=}
        continue
        ;;
      __BCC_GREP_ERR)
        errs=$((errs + 1))
        continue
        ;;
    esac
    [[ -z ${BCC_JUDGED[$f]:-} ]] || continue
    bcc_is_pkg_cache "$f" && continue
    bcc_c09_judged_by_c06 "$f" && continue
    bcc_is_elf "$f" || continue
    # A program that links libbrotlidec dynamically names the decoder symbols in .dynstr; that
    # alone is not a copy. Its own decoder error names are (bcc_report_own_copy).
    needed=$(bcc_elf_needed "$f" 2>/dev/null || true)
    if grep -q '^libbrotlidec' <<<"$needed"; then
      BCC_JUDGED[$f]=1
      bcc_report_own_copy C09 "${f##*/}" "$f"
      continue
    fi
    bcc_covered_by_c01 "$f" && continue
    BCC_JUDGED[$f]=1
    bcc_report_by_strings C09 "${f##*/}" "$f" "" "$(bcc_msg r_c09_vendored)"
  done < <(
    # grep exits 1 for "no match" and 2 for an error; xargs would fold both into 123, so
    # each batch reports an error itself (__BCC_GREP_ERR) and exits 0.
    # shellcheck disable=SC2016  # expanded by sh, per batch
    printf '%s\0' "${BCC_C09_FILES[@]}" |
      timeout -k 2 "$BCC_TIMEOUT" xargs -0 -r sh -c 'LC_ALL=C grep -l -Z -a -E "$0" -- "$@" 2>/dev/null
        [ "$?" -le 1 ] || printf "__BCC_GREP_ERR\0"' \
        'BrotliDecoderDecompressStream|BrotliDecoderCreateInstance|_ERROR_FORMAT_EXUBERANT_NIBBLE'
    printf '__BCC_GREP_RC=%d\0' "$?"
  )
  if ((rc == 124 || rc == 137)); then
    bcc_skip "C09 --deep (search)" "$(bcc_msg skip_timeout "$BCC_TIMEOUT")"
  elif ((rc != 0 || errs > 0)); then
    bcc_skip "C09 --deep (search)" "$(bcc_msg skip_c09_grep_errors)"
  fi
  return 0
}
