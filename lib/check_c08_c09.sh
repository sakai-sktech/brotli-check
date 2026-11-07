# shellcheck shell=bash
# C08 curl, C09 vendored copies of the Brotli decoder.

bcc_c08_candidates() {
  [[ -z ${BCC_C08_DONE:-} ]] || return 0
  bcc_candidates C08 curl < <(printf '%s\n' /usr/bin/curl /usr/local/bin/curl '/opt/*/bin/curl' | bcc_glob_records)
  BCC_C08_CANDS=(${BCC_LIST[@]+"${BCC_LIST[@]}"})
  BCC_C08_DONE=1
}

bcc_check_c08() {
  local bin
  bcc_c08_candidates
  for bin in ${BCC_C08_CANDS[@]+"${BCC_C08_CANDS[@]}"}; do
    bcc_c08_entry "$bin"
  done
  bcc_report_other_names C08
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
  # What this run says about the library holds for the file that loads it (bcc_note_loaded).
  if bcc_covered_by_c01 "$real" || bcc_covered_by_c01 "$lib"; then
    bcc_add_info "$id" "$(bcc_msg i_uses_os_lib "$file" "$prod" "$lib" "$method")${more:+ $more}"
    bcc_note_loaded "$file" "$real" "$lib"
    return 0
  fi
  bcc_add_info "$id" "$(bcc_msg i_uses_private_lib "$file" "$prod" "$real" "$method")${more:+ $more}"
  # Judged under the name it is loaded by (libbrotlidec.so.1 -> decoder.bin is still one).
  [[ -n ${BCC_JUDGED[$real]:-} ]] || bcc_c09_lib_entry "$real" "${lib##*/}"
  bcc_note_loaded "$file" "$real"
}

# A file that loads libbrotlidec can also carry a decoder of its own (with local symbols).
# Its own decoder error names - which a program that only calls libbrotlidec does not have -
# show it; that copy is then judged by its strings as well.
# Usage: bcc_report_own_copy ID PRODUCT FILE
bcc_report_own_copy() {
  local res
  res=$(bcc_brotli_heuristic "$3")
  bcc_split_tab "$res"
  if ((${BCC_F[1]:-0} < BCC_MIN_ERROR_NAMES)); then
    # Too few names so far is no answer when the file was not read to its end.
    [[ ${BCC_F[0]} != INCOMPLETE ]] || bcc_note_incomplete "$3"
    return 0
  fi
  bcc_report_by_strings "$1" "$2 (own copy)" "$3" "" "$(bcc_msg r_own_copy)"
}

# The links bcc_candidates did not take for ID, because they point to a program of another
# name (docs/design.md 10.23). The file is not run and no version is read for it - a version
# manager's shim would answer for itself - but what it carries is looked at, as --deep does:
# a file that loads libbrotlidec is judged by that library, one with decoder markers by its
# strings. One with neither is information, and one where that could not be told (not read
# to its end, its libraries not followed) is listed as not scanned. Every link shows.
# Usage: bcc_report_other_names ID
bcc_report_other_names() {
  local id=$1 i found real comp link rc res
  for i in ${BCC_OTHER_ID[@]+"${!BCC_OTHER_ID[@]}"}; do
    [[ ${BCC_OTHER_ID[i]} == "$id" ]] || continue
    found=${BCC_OTHER_FOUND[i]}
    real=${BCC_OTHER_REAL[i]}
    comp=${real##*/}
    # Judged already (through another link, or by --deep): its lines are there.
    if [[ -n ${BCC_JUDGED[$real]:-} ]]; then
      bcc_add_info "$id" "$(bcc_msg i_other_name_judged "$found" "$real")"
      continue
    fi
    bcc_link_prefetch "$real"
    rc=0
    link=$(bcc_links_brotlidec "$real") || rc=$?
    if ((rc == 0)); then
      BCC_JUDGED[$real]=1
      bcc_add_info "$id" "$(bcc_msg i_other_name_judged "$found" "$real")"
      bcc_split_tab "$link"
      bcc_report_linked_lib "$id" "$comp" "$real" "${BCC_F[0]}" "${BCC_F[1]}"
      bcc_report_own_copy "$id" "$comp" "$real"
      continue
    fi
    res=$(bcc_brotli_scan "$real")
    bcc_split_tab "$res"
    if [[ ${BCC_F[3]} == 1 ]]; then
      BCC_JUDGED[$real]=1
      bcc_report_by_strings "$id" "$comp" "$real" "" "$(bcc_msg r_other_name "$found")"
    elif [[ ${BCC_F[6]} != complete ]]; then
      bcc_skip failed "$found" "$(bcc_msg skip_other_name_incomplete "$real" "$BCC_MAX_ELF_MB")"
    elif ((rc != 1)); then
      bcc_skip failed "$found" "$(bcc_msg skip_other_name_links "$real")"
    else
      bcc_add_info "$id" "$(bcc_msg i_other_name "$found" "$real" "${found##*/}")"
    fi
  done
  return 0
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
  # A conda environment's libbrotlidec is reported by C06 from its conda-meta record; only the
  # files C06 compared with such a record (an empty or unrelated conda-meta/ next to a library
  # proves nothing, and neither does a record about another file in the same lib/).
  [[ -n ${BCC_C06_CONDA_FILES[$f]:-} ]] && return 0
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
  bcc_judge brotli "$series" semver "$ver" "$(bcc_msg b_filename)"
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
  bcc_judge_advises_update && next=$(bcc_msg n_update_lib "$f" "$BCC_J_FIXED")
  bcc_add_finding C09 "$BCC_J_STATUS" "libbrotlidec ($kind)" "$f" "$ver" "$BCC_J_REASON" "$next" \
    "$(bcc_msg e_heur "$count" "$([[ $hstatus == LIKELY_FIXED ]] && echo yes || echo no)"); $BCC_J_EVIDENCE" ""
}

bcc_check_c09_libs() {
  local f
  for f in ${BCC_IDX_LIB[@]+"${BCC_IDX_LIB[@]}"}; do
    bcc_c09_lib_entry "$f"
  done
}

# --- .NET (docs/design.md 10.27) ---------------------------------------------------------
# .NET builds Google's C decoder into its System.IO.Compression native library
# (libSystem.IO.Compression.Native.so; System.IO.Compression.Native.so before .NET 5) and does
# not load libbrotlidec, so updating the OS's libbrotli does not reach it. Each copy found by
# name is judged by .NET's own version:
#   - a file of Ubuntu's .NET source packages (dotnet6, dotnet8, ...) by the package's version,
#     against Ubuntu's fixed version, as C01 judges libbrotli1;
#   - any other (Microsoft's archives and packages, the copy a self-contained application
#     carries) by the build stamp in the file, against Microsoft's fixed version. Its strings
#     cannot always tell: .NET 8's library carries no decoder error names (measured on
#     Microsoft's 8.0.32 and 8.0.33 and Ubuntu's 8.0.33), .NET 9's and 10's do.

# The .NET version stamped into FILE by the build, "@(#)Version 8.0.3326.52219 @Commit: <sha>".
# Arcade's file version encodes the release: FILE_MINOR = MINOR * 100 + PATCH / 100 and
# FILE_PATCH = (PATCH % 100) * 100 + yy (dotnet/arcade Documentation/Versioning.md), so this
# is 8.0.33. .NET Core 2.x and 3.x stamp corefx's version (4.6.x, 4.700.x), which is not
# .NET's: only major versions from 5 count. A release and its previews share a stamp (11.0.0).
# Prints "VERSION<TAB>STAMP<TAB>COMMIT"; status 1 when there is none.
bcc_dotnet_stamp() {
  local f=$1 line a b c re='^@\(#\)Version ([0-9]{1,4})\.([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,9})( @Commit: ([0-9a-f]{7,64}))?'
  # grep stops at the first stamp; tr then writes to a closed pipe, and where SIGPIPE is
  # ignored (as on GitHub's runners) it says so on stderr: that is expected, not an error.
  line=$(bcc_read_file "$f" $((BCC_MAX_ELF_MB * 1024 * 1024)) | LC_ALL=C tr -c '[:print:]' '\n' 2>/dev/null | (
    ulimit -v 262144 2>/dev/null
    LC_ALL=C grep -a -m 1 -E '^@\(#\)Version [0-9]' 2>/dev/null
  )) || true
  [[ $line =~ $re ]] || return 1
  a=$((10#${BASH_REMATCH[1]}))
  b=$((10#${BASH_REMATCH[2]}))
  c=$((10#${BASH_REMATCH[3]}))
  ((a >= 5)) || return 1
  printf '%d.%d.%d\t%d.%d.%d.%s\t%s\n' "$a" $((b / 100)) $(((b % 100) * 100 + c / 100)) \
    "$a" "$b" "$c" "$((10#${BASH_REMATCH[4]}))" "${BASH_REMATCH[6]}"
}

# The version in DIR/.version (second line; the first is the commit), which every shared
# runtime of Microsoft's and Ubuntu's has and a self-contained application does not.
bcc_dotnet_version_file() {
  local text v
  text=$(bcc_read_file "$1/.version" 4096) || return 1
  v=$(sed -n '2{s/[[:space:]]*$//;p;q}' <<<"$text")
  v=$(bcc_semver_parse "$v") || return 1
  [[ -n $v ]] && printf '%s\n' "$v"
}

bcc_check_c09_dotnet() {
  local f
  for f in ${BCC_IDX_DOTNET[@]+"${BCC_IDX_DOTNET[@]}"}; do
    [[ -z ${BCC_JUDGED[$f]:-} ]] || continue
    bcc_c09_dotnet_entry "$f"
  done
}

# Usage: bcc_c09_dotnet_entry FILE
bcc_c09_dotnet_entry() {
  local f=$1 dir=${1%/*} res owner="" pkg="" line ver src srcver comp=dotnet shared=0 next
  local stamp="" sver="" snum="" commit="" vfile="" basis series heur hcount hbs ev pkgver=""
  BCC_JUDGED[$f]=1
  res=$(bcc_brotli_scan "$f")
  bcc_split_tab "$res"
  if [[ ${BCC_F[3]} != 1 ]]; then
    # .NET Core before 2.1 has no Brotli. Absence counts only when the file was read to its end.
    if [[ ${BCC_F[6]} == complete ]]; then
      bcc_add_info C09 "$(bcc_msg i_dotnet_no_decoder "$f")"
    else
      bcc_note_incomplete "$f"
    fi
    return 0
  fi
  # A shared runtime: <root>/shared/Microsoft.NETCore.App/<version>/. Anything else is a copy an
  # application carries (self-contained), which an update of the installed .NET does not change.
  [[ ${dir%/*} == */shared/Microsoft.NETCore.App ]] && shared=1
  ((shared)) || comp="dotnet (self-contained)"
  if owner=$(bcc_dpkg_owner "$f"); then
    pkg=${owner%%,*}
    pkg=${pkg%%:*}
    comp="dotnet ($pkg)"
    # shellcheck disable=SC2016  # dpkg-query format
    line=$(bcc_sys dpkg-query -W -f '${Version}\t${source:Package}\t${source:Version}\n' "$pkg" | head -n 1) || true
    bcc_split_tab "$line"
    pkgver=${BCC_F[0]:-}
    src=${BCC_F[1]:-}
    srcver=${BCC_F[2]:-}
    if [[ $src =~ ^dotnet[0-9]+$ && -n $srcver ]]; then
      bcc_c09_dotnet_package "$f" "$comp" "$pkg" "$pkgver" "$src" "$srcver"
      return 0
    fi
  fi
  # Microsoft's builds and anything else: the stamp, with a shared runtime's .version for a
  # pre-release's label (an application's directory may hold a .version file of its own).
  if stamp=$(bcc_dotnet_stamp "$f"); then
    bcc_split_tab "$stamp"
    sver=${BCC_F[0]}
    snum=${BCC_F[1]}
    commit=${BCC_F[2]}
  fi
  if ((shared)); then vfile=$(bcc_dotnet_version_file "$dir") || vfile=""; fi
  ev="${pkg:+package $pkg${pkgver:+ $pkgver}; }${snum:+stamp $snum${commit:+ (commit $commit)}; }${vfile:+.version $vfile; }"
  if [[ -n $sver && -n $vfile && ${vfile%%-*} != "$sver" ]]; then
    bcc_add_finding C09 UNKNOWN "$comp" "$f" "$sver" "$(bcc_msg r_dotnet_conflict "$sver" "$snum" "$vfile")" \
      "$(bcc_msg n_check_vendor)" "${ev%; }" ""
    return 0
  fi
  if [[ -n $sver ]]; then
    ver=${vfile:-$sver}
    basis=$(bcc_msg b_dotnet_stamp "$snum")
  elif [[ -n $vfile ]]; then
    ver=$vfile
    basis=$(bcc_msg b_dotnet_version_file)
  else
    bcc_report_by_strings C09 "$comp" "$f" "" "$(bcc_msg r_dotnet_no_version)"
    return 0
  fi
  series=${ver%%-*}
  series=${series%.*}
  bcc_judge dotnet "$series" semver "$ver" "$basis"
  bcc_split_tab "$(bcc_brotli_heuristic "$f")"
  heur=${BCC_F[0]} hcount=${BCC_F[1]} hbs=${BCC_F[2]}
  if [[ $BCC_J_STATUS == FIXED && -n $sver && -z $vfile && $BCC_J_FIXED == "$sver"-* ]]; then
    # The stamp of X.Y.0 is also that of its previews, and the fix came in one of them.
    BCC_J_STATUS=UNKNOWN
    BCC_J_REASON=$(bcc_msg r_dotnet_preview "$sver" "$BCC_J_FIXED")
    BCC_J_NEXT=$(bcc_msg n_check_vendor)
  elif [[ $BCC_J_STATUS == FIXED && -n $sver && $heur == VENDORED_COPY ]]; then
    # The stamp is written into this very file by its build: it stands where the strings cannot
    # tell (requester's decision, 2026-11-07), and the reason says what they leave open.
    BCC_J_REASON+=" $(bcc_msg r_dotnet_unseen)"
  elif [[ $BCC_J_STATUS == FIXED ]]; then
    bcc_crosscheck_fixed "$f"
  elif [[ $BCC_J_STATUS == VULNERABLE && $heur == LIKELY_FIXED ]]; then
    BCC_J_STATUS=UNKNOWN
    BCC_J_REASON=$(bcc_msg r_dotnet_strings_fixed "$ver")
    BCC_J_NEXT=$(bcc_msg n_check_vendor)
  fi
  next=$BCC_J_NEXT
  if bcc_judge_advises_update; then
    if ((!shared)) && [[ $BCC_J_FIXED == - ]]; then
      next=$(bcc_msg n_dotnet_app_line)
    elif ((!shared)); then
      next=$(bcc_msg n_dotnet_app "$BCC_J_FIXED")
    elif [[ $BCC_J_FIXED == - ]]; then
      next=$(bcc_msg n_dotnet_move_line)
    else
      next=$(bcc_msg n_dotnet_update "$BCC_J_FIXED")
    fi
  fi
  bcc_add_finding C09 "$BCC_J_STATUS" "$comp" "$f" "$ver" "$BCC_J_REASON" "$next" \
    "$ev$(bcc_msg e_heur "$hcount" "$( ((hbs)) && echo yes || echo no)"); $BCC_J_EVIDENCE" ""
}

# A file of one of Ubuntu's .NET source packages: the package's source version against
# Ubuntu's fixed version (the stamp is upstream's release, which says nothing of a backport).
# Usage: bcc_c09_dotnet_package FILE COMPONENT PACKAGE VERSION SOURCE SOURCE-VERSION
bcc_c09_dotnet_package() {
  local f=$1 comp=$2 pkg=$3 ver=$4 src=$5 srcver=$6 next
  if [[ -z $BCC_DEB_SERIES ]]; then
    bcc_add_finding C09 UNKNOWN "$comp" "$f" "$ver" "$(bcc_msg r_unknown_series "${BCC_OS_ID:-?}")" \
      "$(bcc_msg n_check_vendor)" "source $src $srcver" ""
    return 0
  fi
  bcc_judge "deb-src:$src" "$BCC_DEB_SERIES" deb "$srcver" "$(bcc_msg b_deb)"
  next=$BCC_J_NEXT
  case $BCC_J_STATUS in
    VULNERABLE)
      if [[ $BCC_J_FIXED == - ]]; then
        next=$(bcc_msg n_dotnet_move_line)
      else
        next=$(bcc_msg n_dotnet_update_pkg "$(printf '%q' "$pkg")" "$src" "$BCC_J_FIXED")
      fi
      ;;
    NO_FIX_AVAILABLE) next=$(bcc_msg n_dotnet_move_line) ;;
    FIXED) next+=" $(bcc_msg n_restart_after_update)" ;;
  esac
  bcc_add_finding C09 "$BCC_J_STATUS" "$comp" "$f" "$ver" "$BCC_J_REASON" "$next" "source $src $srcver; $BCC_J_EVIDENCE" ""
}

# The extension module of a PyPI Brotli/brotlicffi that C06 already judged by its metadata:
# the same files C06 compares, and only for the package C06 judged in that site.
bcc_c09_judged_by_c06() {
  local f=$1 key
  case $f in
    */_brotli.*so) key=brotli:${f%/*} ;;
    */brotlicffi/_brotlicffi*.so) key=brotlicffi:${f%/brotlicffi/*} ;;
    *) return 1 ;;
  esac
  [[ -n ${BCC_C06_SITES[$key]:-} ]]
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

# --deep: the library a program loads, when it is not one C01 judged. Its file need not be under
# the roots, nor look like a library there (libbrotlidec.so.1 -> decoder.bin). A program that
# loads the OS's library says nothing new, and there can be many of them, so nothing is added.
bcc_c09_linked_decoder() {
  local f=$1 link rc=0 lib method real
  link=$(bcc_links_brotlidec "$f") || rc=$?
  if ((rc != 0)); then
    bcc_add_finding C09 UNKNOWN "${f##*/}" "$f" "" "$(bcc_msg r_link_undetermined)" "$(bcc_msg n_install_binutils)" "" ""
    return 0
  fi
  bcc_split_tab "$link"
  lib=${BCC_F[0]}
  method=${BCC_F[1]}
  real=$(bcc_realpath "$lib") || real=""
  [[ -n $real && -f $real ]] && { bcc_covered_by_c01 "$real" || bcc_covered_by_c01 "$lib"; } && return 0
  bcc_report_linked_lib C09 "${f##*/}" "$f" "$lib" "$method"
}

# --deep: any ELF under --roots that carries the decoder but does not load libbrotlidec.
bcc_check_c09_deep() {
  BCC_C09_FILES=()
  BCC_C09_BIG=0 BCC_C09_BIG_EXAMPLE="" BCC_C09_UNREADABLE=0
  bcc_find_each bcc_c09_collect ${BCC_ROOTS[@]+"${BCC_ROOTS[@]}"} -- \
    -type f \( -perm -u=x -o -name '*.so' -o -name '*.so.*' -o -name '*.node' \) \
    \( -size "-$((BCC_MAX_ELF_MB * 1024))k" -o \( -printf '__BCC_BIG=%p\0' -false \) \)
  bcc_find_status $? "C09 --deep"
  # No option takes a file over the size limit in: a person has to look at it (failed).
  ((BCC_C09_BIG == 0)) || bcc_skip failed "C09 --deep (size)" "$(bcc_msg skip_c09_big "$BCC_C09_BIG" "$BCC_MAX_ELF_MB" "$BCC_C09_BIG_EXAMPLE")"
  ((BCC_C09_UNREADABLE == 0)) || bcc_skip "$(bcc_denied_kind)" "C09 --deep (unreadable)" "$(bcc_msg skip_c09_unreadable "$BCC_C09_UNREADABLE")"
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
    if bcc_needed_has_brotlidec "$needed"; then
      BCC_JUDGED[$f]=1
      bcc_c09_linked_decoder "$f"
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
    bcc_skip failed "C09 --deep (search)" "$(bcc_msg skip_timeout "$BCC_TIMEOUT")"
  elif ((rc != 0 || errs > 0)); then
    bcc_skip failed "C09 --deep (search)" "$(bcc_msg skip_c09_grep_errors)"
  fi
  return 0
}
