# shellcheck shell=bash
# elf.sh - ELF detection, transitive libbrotlidec linkage, Brotli decoder string markers.

bcc_is_elf() {
  [[ $(bcc_read_file "$1" 4 | od -An -tx1 2>/dev/null | tr -d ' \n') == 7f454c46 ]]
}

# NEEDED entries of an ELF file. Status 1 when readelf fails on it, 2 when readelf is not
# available. (Captured first so the status does not depend on pipefail.)
bcc_elf_needed() {
  local out
  bcc_have readelf || return 2
  out=$(bcc_sys readelf -d -- "$1") || return 1
  sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p' <<<"$out"
}

# Cache of "soname<TAB>arch<TAB>path" from ldconfig -p (system query, not a found program),
# loaded once in the main shell (bcc_run_checks) so that subshells inherit it. Never piped
# into a reader that may stop early: on hosts with many libraries the cache exceeds the
# pipe buffer and the writer would print "write error: Broken pipe" (seen on CI).
bcc_ldcache_load() {
  [[ -z ${BCC_LDCACHE_LOADED:-} ]] || return 0
  BCC_LDCACHE=""
  local ldc
  for ldc in ldconfig /sbin/ldconfig /usr/sbin/ldconfig; do
    if bcc_have "$ldc"; then
      BCC_LDCACHE=$(bcc_sys "$ldc" -p | sed -n 's/^[[:space:]]*\([^ ]*\) (\([^)]*\)) => \(.*\)$/\1\t\2\t\3/p' || true)
      break
    fi
  done
  BCC_LDCACHE_LOADED=1
}

# Resolve a soname from the ld.so cache, then the default directories (the RPATH/RUNPATH
# part of the search is bcc_dep_find's). Usage: bcc_elf_resolve SONAME
bcc_elf_resolve() {
  local name=$1 d hit
  bcc_ldcache_load
  hit=$(awk -F'\t' -v n="$name" '$1 == n && $2 ~ /x86-64|64bit|AArch64|aarch64/ { print $3; exit }' <<<"$BCC_LDCACHE")
  [[ -z $hit ]] && hit=$(awk -F'\t' -v n="$name" '$1 == n { print $3; exit }' <<<"$BCC_LDCACHE")
  [[ -n $hit ]] && { printf '%s\n' "$hit"; return 0; }
  for d in /lib64 /usr/lib64 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu /lib /usr/lib; do
    [[ -e $d/$name ]] && { printf '%s\n' "$d/$name"; return 0; }
  done
  return 1
}

# A version taken from a path, a header file, package metadata or a file name (not from the
# program itself) is only as good as whoever named the directory or wrote the file. Such a
# version yields FIXED only when the decoder FILE contains confirms it: the fix's error name,
# in a single copy of Brotli. Anything else leaves the fix unconfirmed and the result is
# UNKNOWN, saying what was found and what was not: strings without the fix's name, more than
# one copy, no error names at all, or a file that could not be read to the end (also listed
# as not scanned). Acts on BCC_J_* from bcc_judge, in the main shell.
# Usage: bcc_crosscheck_fixed FILE
bcc_crosscheck_fixed() {
  local f=$1 res
  [[ $BCC_J_STATUS == FIXED ]] || return 0
  res=$(bcc_brotli_heuristic "$f")
  case ${res%%$'\t'*} in
    LIKELY_FIXED) return 0 ;;
    LIKELY_VULNERABLE) BCC_J_REASON=$(bcc_msg r_crosscheck_conflict "$BCC_J_REASON") ;;
    MULTIPLE_COPIES) BCC_J_REASON="$BCC_J_REASON $(bcc_msg r_heur_multiple)" ;;
    INCOMPLETE)
      BCC_J_REASON="$BCC_J_REASON $(bcc_msg r_crosscheck_incomplete "$BCC_MAX_ELF_MB")"
      bcc_note_incomplete "$f"
      ;;
    *) BCC_J_REASON="$BCC_J_REASON $(bcc_msg r_crosscheck_unconfirmed)" ;;
  esac
  BCC_J_STATUS=UNKNOWN
  BCC_J_NEXT=$(bcc_msg n_check_vendor)
  return 0
}

# A file whose strings could not be read to the end is listed as not scanned (once).
bcc_note_incomplete() {
  bcc_skip "$1" "$(bcc_msg skip_incomplete "$BCC_MAX_ELF_MB")"
}

# Split one RPATH or RUNPATH value of OBJECT into BCC_DIRS ($ORIGIN expanded). Problems are
# recorded in BCC_DIR_ISSUES as "kind<TAB>object": an empty entry (":/x", "/x:", "/x::/y" -
# ld.so reads it as the working directory), a relative one, or a token this walk does not
# expand ($LIB, $PLATFORM). Such entries are not searched here.
bcc_dep_dirs() {
  local value=$1 obj=$2 origin=${2%/*} d
  local -a parts=()
  BCC_DIRS=()
  BCC_DIR_ISSUES=()
  [[ -n $value ]] || return 0
  [[ $value != :* && $value != *: && $value != *::* ]] || BCC_DIR_ISSUES+=("empty"$'\t'"$obj")
  IFS=: read -r -a parts <<<"$value"
  for d in ${parts[@]+"${parts[@]}"}; do
    [[ -n $d ]] || continue
    # shellcheck disable=SC2016  # the literal token $ORIGIN is replaced
    d=${d//'$ORIGIN'/$origin}
    # shellcheck disable=SC2016
    d=${d//'${ORIGIN}'/$origin}
    if [[ $d == *'$'* ]]; then
      BCC_DIR_ISSUES+=("token"$'\t'"$obj: $d")
    elif [[ $d != /* ]]; then
      BCC_DIR_ISSUES+=("relative"$'\t'"$obj: $d")
    else
      BCC_DIRS+=("$d")
    fi
  done
}

# Find SONAME in the directories given (glibc-hwcaps subdirectories first, as ld.so tries
# them), then in the ld.so cache and the default directories. Prints the path.
bcc_dep_find() {
  local name=$1 d h
  shift
  for d in "$@"; do
    bcc_glob "$d/glibc-hwcaps/*/$name"
    for h in ${BCC_GLOB[@]+"${BCC_GLOB[@]}"}; do printf '%s\n' "$h"; return 0; done
    [[ -e $d/$name ]] && { printf '%s\n' "$d/$name"; return 0; }
  done
  bcc_elf_resolve "$name"
}

# The libraries FILE would load, looked up the way glibc's ld.so does: for each object, the
# DT_RPATH of the object that needs the library and then of the objects that loaded it, up
# to the executable - unless the needing object has a DT_RUNPATH, which also hides its own
# DT_RPATH - then that object's DT_RUNPATH, the ld.so cache, the default directories.
# (LD_LIBRARY_PATH does not apply: programs run with an empty environment.) Records,
# tab-separated, one per line:
#   I  path            the loader named by PT_INTERP
#   D  dir             a directory listed in some RPATH/RUNPATH
#   N  soname  path    a needed library and where it resolved ("" when not found)
#   X  kind  detail    something not followed: empty/relative/token (search entries, see
#                      bcc_dep_dirs), missing (soname), readelf (failed on file), depth
# The records go to BCC_WALK_OUT; status 2 when readelf is not available. Run in the main shell, it keeps
# each object's dynamic section (BCC_DYN_CACHE) and each lookup (BCC_FIND_CACHE), so that
# libraries shared by many programs are read once.
bcc_dep_walk_uncached() {
  local file=$1 out="" interp dyn needed rpath runpath cur inh so path d depth i fkey
  local -A seen=()
  local -a q=("$file") qi=("") nq=() nqi=() own_rp=() own_run=() search=() inh_a=()
  bcc_have readelf || return 2
  if interp=$(bcc_sys readelf -l -- "$file"); then
    interp=$(sed -n 's/.*\[Requesting program interpreter: \(.*\)\]$/\1/p' <<<"$interp" | head -n 1)
    [[ -z $interp ]] || out+="I"$'\t'"$interp"$'\n'
  fi
  for ((depth = 0; depth < 8 && ${#q[@]}; depth++)); do
    nq=() nqi=()
    for i in "${!q[@]}"; do
      cur=${q[i]} inh=${qi[i]}
      [[ -z ${seen[$cur]:-} ]] || continue
      seen[$cur]=1
      if [[ -z ${BCC_DYN_CACHE[$cur]+x} ]]; then
        if dyn=$(bcc_sys readelf -d -- "$cur"); then BCC_DYN_CACHE[$cur]=$dyn; else BCC_DYN_CACHE[$cur]=$'\001'; fi
      fi
      dyn=${BCC_DYN_CACHE[$cur]}
      if [[ $dyn == $'\001' ]]; then
        out+="X"$'\t'"readelf"$'\t'"$cur"$'\n'
        continue
      fi
      needed=$(sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p' <<<"$dyn")
      rpath=$(sed -n 's/.*(RPATH).*\[\(.*\)\].*/\1/p' <<<"$dyn" | head -n 1)
      runpath=$(sed -n 's/.*(RUNPATH).*\[\(.*\)\].*/\1/p' <<<"$dyn" | head -n 1)
      # glibc ignores DT_RPATH when the same object has DT_RUNPATH.
      [[ -n $runpath ]] && rpath=""
      bcc_dep_dirs "$rpath" "$cur"
      own_rp=(${BCC_DIRS[@]+"${BCC_DIRS[@]}"})
      for d in ${BCC_DIR_ISSUES[@]+"${BCC_DIR_ISSUES[@]}"}; do out+="X"$'\t'"$d"$'\n'; done
      bcc_dep_dirs "$runpath" "$cur"
      own_run=(${BCC_DIRS[@]+"${BCC_DIRS[@]}"})
      for d in ${BCC_DIR_ISSUES[@]+"${BCC_DIR_ISSUES[@]}"}; do out+="X"$'\t'"$d"$'\n'; done
      for d in ${own_rp[@]+"${own_rp[@]}"} ${own_run[@]+"${own_run[@]}"}; do out+="D"$'\t'"$d"$'\n'; done
      inh_a=()
      [[ -n $inh ]] && IFS=: read -r -a inh_a <<<"$inh"
      if [[ -n $runpath ]]; then
        search=(${own_run[@]+"${own_run[@]}"})
      else
        search=(${own_rp[@]+"${own_rp[@]}"} ${inh_a[@]+"${inh_a[@]}"})
      fi
      while IFS= read -r so; do
        [[ -n $so ]] || continue
        if [[ $so == */* ]]; then
          path=$so
          [[ -e $path ]] || path=""
        else
          fkey="$so"$'\t'"$(IFS=:; printf '%s' "${search[*]:-}")"
          if [[ -z ${BCC_FIND_CACHE[$fkey]+x} ]]; then
            BCC_FIND_CACHE[$fkey]=$(bcc_dep_find "$so" ${search[@]+"${search[@]}"}) || BCC_FIND_CACHE[$fkey]=""
          fi
          path=${BCC_FIND_CACHE[$fkey]}
        fi
        out+="N"$'\t'"$so"$'\t'"$path"$'\n'
        if [[ -z $path ]]; then
          out+="X"$'\t'"missing"$'\t'"$so"$'\n'
          continue
        fi
        if [[ -z ${BCC_FIND_CACHE[real:$path]+x} ]]; then
          BCC_FIND_CACHE[real:$path]=$(bcc_realpath "$path") || BCC_FIND_CACHE[real:$path]=""
        fi
        path=${BCC_FIND_CACHE[real:$path]}
        [[ -n $path ]] || continue
        [[ -n ${seen[$path]:-} ]] && continue
        nq+=("$path")
        # What this library needs is looked up in its own RPATH, then in ours, upward.
        local -a chain=(${own_rp[@]+"${own_rp[@]}"} ${inh_a[@]+"${inh_a[@]}"})
        nqi+=("$(IFS=:; printf '%s' "${chain[*]:-}")")
      done <<<"$needed"
    done
    q=(${nq[@]+"${nq[@]}"})
    qi=(${nqi[@]+"${nqi[@]}"})
  done
  ((${#q[@]} == 0)) || out+="X"$'\t'"depth"$'\t'"$file"$'\n'
  BCC_WALK_OUT=$out
}

# bcc_dep_walk_uncached once per file, kept in the main shell (BCC_DEPWALK_CACHE and _RC) so
# that later callers - often in a subshell - reuse it.
bcc_dep_walk_prefetch() {
  local rc=0
  [[ -z ${BCC_DEPWALK_RC[$1]+x} ]] || return 0
  BCC_WALK_OUT=""
  bcc_dep_walk_uncached "$1" || rc=$?
  BCC_DEPWALK_CACHE[$1]=$BCC_WALK_OUT
  BCC_DEPWALK_RC[$1]=$rc
}

# Does FILE load libbrotlidec, directly or through other libraries? Prints the resolved
# libbrotlidec path and the method (readelf). Status: 0 linked, 1 not linked (static copy or
# no Brotli), 2 undetermined. Anything that could not be followed to the end (no readelf, a
# readelf failure, a library not found, the depth limit) is 2, never 1: "not linked" leads
# to NOT_APPLICABLE. The file is only read: ldd, which hands the file to the loader, is not
# used.
bcc_links_brotlidec_uncached() {
  local file=$1 walk rc lib
  bcc_dep_walk_prefetch "$file"
  walk=${BCC_DEPWALK_CACHE[$file]}
  rc=${BCC_DEPWALK_RC[$file]}
  ((rc == 0)) || return 2
  lib=$(awk -F'\t' '$1 == "N" && $2 ~ /^libbrotlidec/ { print ($3 == "" ? $2 " (not found)" : $3); exit }' <<<"$walk")
  if [[ -n $lib ]]; then
    printf '%s\treadelf\n' "$lib"
    return 0
  fi
  if grep -qE $'^X\t(missing|readelf|depth)\t' <<<"$walk"; then
    return 2
  fi
  return 1
}

bcc_link_prefetch() {
  local rc=0 out
  [[ -z ${BCC_LINK_RC[$1]+x} ]] || return 0
  bcc_dep_walk_prefetch "$1"
  out=$(bcc_links_brotlidec_uncached "$1") || rc=$?
  BCC_LINK_CACHE[$1]=$out
  BCC_LINK_RC[$1]=$rc
}

bcc_links_brotlidec() {
  if [[ -z ${BCC_LINK_RC[$1]+x} ]]; then
    bcc_links_brotlidec_uncached "$1"
    return
  fi
  [[ -z ${BCC_LINK_CACHE[$1]} ]] || printf '%s\n' "${BCC_LINK_CACHE[$1]}"
  return "${BCC_LINK_RC[$1]}"
}

# One bounded read of FILE (bcc_read_file, at most the --deep size limit) for Brotli's
# strings, taken as runs of printable bytes like strings(1). Prints one record:
#   names<TAB>block_switch<TAB>dicts<TAB>marker<TAB>go<TAB>cbrotli<TAB>read
#   names         distinct "_ERROR_FORMAT_*" strings (whole strings only: Node.js also carries
#                 "BROTLI_DECODER_ERROR_FORMAT_*" in its own table); counting stops at 64
#   block_switch  1 when _ERROR_FORMAT_BLOCK_SWITCH (added by the fix) is among them
#   dicts         copies of Brotli's built-in dictionary: every copy of Brotli carries one
#                 (libbrotlicommon and Node.js: 1), so 2 or more means more than one copy
#   marker        1 when decoder symbol names or error names are present
#   go, cbrotli   1 for a Go program (build info) / one that names the cgo Brotli binding
#   read          complete | partial (cut at the size limit, timed out, or a line too long
#                 for the memory limit) | unreadable
# No sort and bounded memory: the strings of a hostile file cannot fill a disk or RAM. A file
# that is one huge printable run would make grep hold it as one line, so grep and awk run
# under a 256 MiB address-space limit. Whether the file was read to the end is decided from
# the exit status of every stage (the reader, tr, grep and awk), never from anything in the
# file's own bytes: a status mark carried in the data stream could be forged by the file
# (Codex review round 6). (tr -s or fold would cap lines too, but cost 7x the time.)
BCC_BROTLI_DICT_HEAD=timedownlifeleftbackcodedatashowonlysitecity
bcc_brotli_scan() {
  local f=$1 max=$((BCC_MAX_ELF_MB * 1024 * 1024)) size cut=0 res counts
  local -a sts=()
  if [[ ! -f $f || ! -r $f ]]; then
    printf '0\t0\t0\t0\t0\t0\tunreadable\n'
    return
  fi
  size=$(stat -L -c %s -- "$f" 2>/dev/null) || size=0
  [[ $size =~ ^[0-9]+$ ]] && ((size > max)) && cut=1
  res=$(
    bcc_read_file "$f" "$max" | LC_ALL=C tr -c '[:print:]' '\n' | (
      ulimit -v 262144 2>/dev/null
      LC_ALL=C grep -a -E "^_ERROR_FORMAT_[A-Z0-9_]+\$|_ERROR_FORMAT_EXUBERANT_NIBBLE|BrotliDecoderDecompressStream|BrotliDecoderCreateInstance|$BCC_BROTLI_DICT_HEAD|^ Go buildinf:|github\\.com/google/brotli/go/cbrotli" 2>/dev/null |
        LC_ALL=C awk -v dict="$BCC_BROTLI_DICT_HEAD" '
          /^_ERROR_FORMAT_[A-Z0-9_]+$/ {
            if (!($0 in seen) && n < 64) { seen[$0] = 1; n++ }
            if ($0 == "_ERROR_FORMAT_BLOCK_SWITCH") bs = 1
          }
          /_ERROR_FORMAT_EXUBERANT_NIBBLE|BrotliDecoderDecompressStream|BrotliDecoderCreateInstance/ { mk = 1 }
          index($0, dict) { d++ }
          /^ Go buildinf:/ { go = 1 }
          /github\.com\/google\/brotli\/go\/cbrotli/ { cb = 1 }
          END { printf "%d\t%d\t%d\t%d\t%d\t%d\n", n, bs, d, mk, go, cb }' 2>/dev/null
      # grep: 0 = lines found, 1 = none (both fine), 2 = error (e.g. memory exhausted).
      pst=("${PIPESTATUS[@]}")
      if ((pst[0] <= 1 && pst[1] == 0)); then exit 0; else exit 1; fi
    )
    printf '\t%s\n' "${PIPESTATUS[*]}"
  )
  # res: the counts line (missing if awk died), a newline, then a tab and the three statuses.
  counts=""
  [[ $res == *$'\n'* ]] && counts=${res%%$'\n'*}
  read -r -a sts <<<"${res##*$'\t'}"
  local re='^[0-9]+'$'\t''[0-9]+'$'\t''[0-9]+'$'\t''[0-9]+'$'\t''[0-9]+'$'\t''[0-9]+$'
  if [[ ! $counts =~ $re ]]; then
    counts=$'0\t0\t0\t0\t0\t0'
    sts=(1)
  fi
  if ((cut == 0 && ${#sts[@]} == 3 && sts[0] == 0 && sts[1] == 0 && sts[2] == 0)); then
    printf '%s\tcomplete\n' "$counts"
  else
    printf '%s\tpartial\n' "$counts"
  fi
}

# Does FILE look like it contains a Brotli decoder? (symbol names or decoder error names)
bcc_has_brotli_decoder_marker() {
  local res
  res=$(bcc_brotli_scan "$1")
  bcc_split_tab "$res"
  [[ ${BCC_F[3]} == 1 ]]
}

# C09 heuristic, verified on builds of 1.2.0/1.2.1 and official binaries
# (tests/fixtures/c09/README.md). Prints: STATUS<TAB>count<TAB>has_block_switch<TAB>dicts<TAB>read
#   LIKELY_FIXED       _ERROR_FORMAT_BLOCK_SWITCH present, one copy of Brotli
#   LIKELY_VULNERABLE  other _ERROR_FORMAT_* present, BLOCK_SWITCH absent
#   MULTIPLE_COPIES    BLOCK_SWITCH present, but the file holds more than one copy of Brotli:
#                      the linker merges equal strings, so one fixed copy hides an old one
#   INCOMPLETE         the file could not be read to the end (size limit, timeout)
#   VENDORED_COPY      fewer than BCC_MIN_ERROR_NAMES names (BrotliDecoderErrorString removed
#                      by the linker, or only a fragment): undecidable
# Every verified build carried 16 names (unfixed) or 17 (fixed), or none at all.
BCC_MIN_ERROR_NAMES=8
bcc_brotli_heuristic() {
  local res count bs dicts read status
  res=$(bcc_brotli_scan "$1")
  bcc_split_tab "$res"
  count=${BCC_F[0]} bs=${BCC_F[1]} dicts=${BCC_F[2]} read=${BCC_F[6]}
  if [[ $read != complete ]]; then
    status=INCOMPLETE
  elif ((count < BCC_MIN_ERROR_NAMES)); then
    status=VENDORED_COPY
    bs=0
  elif ((bs && dicts > 1)); then
    status=MULTIPLE_COPIES
  elif ((bs)); then
    status=LIKELY_FIXED
  else
    status=LIKELY_VULNERABLE
  fi
  printf '%s\t%d\t%d\t%d\t%s\n' "$status" "$count" "$bs" "$dicts" "$read"
}
