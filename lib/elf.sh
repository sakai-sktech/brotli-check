# shellcheck shell=bash
# elf.sh - ELF detection, transitive libbrotlidec linkage, Brotli decoder string markers.

bcc_is_elf() {
  [[ $(od -An -tx1 -N4 -- "$1" 2>/dev/null | tr -d ' \n') == 7f454c46 ]]
}

# NEEDED entries of an ELF file. Status 1 when readelf fails on it, 2 when readelf is not
# available. (Captured first so the status does not depend on pipefail.)
bcc_elf_needed() {
  local out
  bcc_have readelf || return 2
  out=$(bcc_sys readelf -d -- "$1") || return 1
  sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p' <<<"$out"
}

# RUNPATH/RPATH directories of an ELF file, with $ORIGIN expanded.
bcc_elf_runpath() {
  local file=$1 origin p
  bcc_have readelf || return 2
  origin=$(dirname -- "$file")
  bcc_sys readelf -d -- "$file" | sed -n 's/.*(R\(UN\)\{0,1\}PATH).*\[\(.*\)\].*/\2/p' | tr ':' '\n' |
    while IFS= read -r p; do
      # shellcheck disable=SC2016  # the literal token $ORIGIN is replaced
      p=${p//'$ORIGIN'/$origin}
      # shellcheck disable=SC2016
      p=${p//'${ORIGIN}'/$origin}
      [[ -n $p ]] && printf '%s\n' "$p"
    done
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

# Resolve a soname the way ld.so would, approximately: RUNPATH, ld cache, default dirs.
# Usage: bcc_elf_resolve SONAME RUNPATH-DIR...
bcc_elf_resolve() {
  local name=$1 d hit
  shift
  for d in "$@"; do
    [[ -e $d/$name ]] && { printf '%s\n' "$d/$name"; return 0; }
  done
  bcc_ldcache_load
  hit=$(awk -F'\t' -v n="$name" '$1 == n && $2 ~ /x86-64|64bit|AArch64|aarch64/ { print $3; exit }' <<<"$BCC_LDCACHE")
  [[ -z $hit ]] && hit=$(awk -F'\t' -v n="$name" '$1 == n { print $3; exit }' <<<"$BCC_LDCACHE")
  [[ -n $hit ]] && { printf '%s\n' "$hit"; return 0; }
  for d in /lib64 /usr/lib64 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu /lib /usr/lib; do
    [[ -e $d/$name ]] && { printf '%s\n' "$d/$name"; return 0; }
  done
  return 1
}

# A version taken from a path, a header file or package metadata (not from the program
# itself) is only as good as whoever named the directory or wrote the file. Before such a
# version yields FIXED, look at the decoder that FILE actually contains: if its strings
# lack the fix's error name, report UNKNOWN instead. Acts on BCC_J_* from bcc_judge.
# Usage: bcc_crosscheck_fixed FILE
bcc_crosscheck_fixed() {
  local f=$1 res
  [[ $BCC_J_STATUS == FIXED && -f $f && -r $f ]] || return 0
  res=$(bcc_brotli_heuristic "$f")
  if [[ ${res%%$'\t'*} == LIKELY_VULNERABLE ]]; then
    BCC_J_STATUS=UNKNOWN
    BCC_J_REASON=$(bcc_msg r_crosscheck_conflict "$BCC_J_REASON")
    BCC_J_NEXT=$(bcc_msg n_check_vendor)
  fi
  return 0
}

# Does FILE load libbrotlidec, directly or through other libraries?
# Prints the resolved libbrotlidec path and the method (ldd | readelf).
# Status: 0 linked, 1 not linked (static copy or no Brotli), 2 undetermined. Anything that
# could not be followed to the end (readelf failure, unresolvable dependency, depth limit,
# "not found" in ldd) is 2, never 1: "not linked" leads to NOT_APPLICABLE.
bcc_links_brotlidec() {
  local file=$1 out lib safe
  if ((!BCC_NO_EXEC)) && bcc_have ldd && safe=$(bcc_safe_to_exec "$file"); then
    # glibc's ldd asks the system dynamic loader to list dependencies (--list); the
    # file's own code does not run. ldd(1) still warns against untrusted files, so
    # files others could modify go to the readelf walk below.
    out=$(bcc_sys ldd -- "$safe")
    if [[ $out == *"not a dynamic executable"* || $out == *"statically linked"* ]]; then
      return 1
    fi
    lib=$(sed -n 's/^[[:space:]]*libbrotlidec[^ ]* => \(.*\)$/\1/p' <<<"$out" | head -n 1)
    if [[ -n $lib ]]; then
      lib=${lib% (0x*}
      printf '%s\tldd\n' "$lib"
      return 0
    fi
    if [[ -n $out && $out != *"=> not found"* ]]; then
      return 1
    fi
  fi
  bcc_have readelf || return 2
  # Breadth-first walk over NEEDED entries (depth-limited).
  local -A seen=()
  local -a queue=("$file") next_queue=()
  local depth cur so path needed incomplete=0
  local -a rp=()
  for ((depth = 0; depth < 8 && ${#queue[@]}; depth++)); do
    next_queue=()
    for cur in "${queue[@]}"; do
      [[ -z ${seen[$cur]:-} ]] || continue
      seen[$cur]=1
      if ! needed=$(bcc_elf_needed "$cur"); then
        incomplete=1
        continue
      fi
      mapfile -t rp < <(bcc_elf_runpath "$cur")
      while IFS= read -r so; do
        [[ -n $so ]] || continue
        path=$(bcc_elf_resolve "$so" ${rp[@]+"${rp[@]}"}) || path=""
        if [[ $so == libbrotlidec* ]]; then
          printf '%s\treadelf\n' "${path:-$so (not found)}"
          return 0
        fi
        if [[ -z $path ]]; then
          incomplete=1
          continue
        fi
        next_queue+=("$path")
      done <<<"$needed"
    done
    queue=(${next_queue[@]+"${next_queue[@]}"})
  done
  ((${#queue[@]} == 0)) || incomplete=1
  ((incomplete)) && return 2
  return 1
}

# Decoder error-name strings ("_ERROR_FORMAT_*") found in FILE, one per line, sorted.
# Strings are taken as runs of printable bytes, like strings(1); only whole strings
# that start with _ERROR_FORMAT_ count (Node.js also carries
# "BROTLI_DECODER_ERROR_FORMAT_*" names in its own table).
bcc_brotli_error_names() {
  # 2>/dev/null first: redirections apply left to right, and an unreadable file must not
  # print "Permission denied" on the terminal.
  LC_ALL=C tr -c '[:print:]' '\n' 2>/dev/null <"$1" | LC_ALL=C grep -E '^_ERROR_FORMAT_[A-Z0-9_]+$' | sort -u
}

# Does FILE look like it contains a Brotli decoder? (symbol names or decoder error names)
bcc_has_brotli_decoder_marker() {
  LC_ALL=C grep -a -q -E 'BrotliDecoderDecompressStream|BrotliDecoderCreateInstance|_ERROR_FORMAT_EXUBERANT_NIBBLE' -- "$1" 2>/dev/null
}

# C09 heuristic, verified on builds of 1.2.0/1.2.1 and official binaries
# (tests/fixtures/c09/README.md). Prints: STATUS<TAB>count<TAB>has_block_switch
#   LIKELY_FIXED       _ERROR_FORMAT_BLOCK_SWITCH present
#   LIKELY_VULNERABLE  other _ERROR_FORMAT_* present, BLOCK_SWITCH absent
#   VENDORED_COPY      fewer than BCC_MIN_ERROR_NAMES names (BrotliDecoderErrorString removed
#                      by the linker, or only a fragment): undecidable
# Every verified build carried 16 names (unfixed) or 17 (fixed), or none at all.
BCC_MIN_ERROR_NAMES=8
bcc_brotli_heuristic() {
  local names count=0 bs=0
  names=$(bcc_brotli_error_names "$1")
  [[ -n $names ]] && count=$(grep -c . <<<"$names")
  if ((count < BCC_MIN_ERROR_NAMES)); then
    printf 'VENDORED_COPY\t%d\t0\n' "$count"
    return
  fi
  grep -qxF '_ERROR_FORMAT_BLOCK_SWITCH' <<<"$names" && bs=1
  if ((bs)); then
    printf 'LIKELY_FIXED\t%d\t1\n' "$count"
  else
    printf 'LIKELY_VULNERABLE\t%d\t0\n' "$count"
  fi
}
