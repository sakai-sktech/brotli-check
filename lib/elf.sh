# shellcheck shell=bash
# elf.sh - ELF detection, transitive libbrotlidec linkage, Brotli decoder string markers.

bcc_is_elf() {
  [[ $(od -An -tx1 -N4 -- "$1" 2>/dev/null | tr -d ' \n') == 7f454c46 ]]
}

# NEEDED entries of an ELF file. Status 2 when readelf is not available.
bcc_elf_needed() {
  bcc_have readelf || return 2
  bcc_sys readelf -d -- "$1" | sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p'
}

# RUNPATH/RPATH directories of an ELF file, with $ORIGIN expanded.
bcc_elf_runpath() {
  local file=$1 origin p
  bcc_have readelf || return 2
  origin=$(dirname -- "$file")
  bcc_sys readelf -d -- "$file" | sed -n 's/.*(R\(UN\)\{0,1\}PATH).*\[\(.*\)\].*/\2/p' | tr ':' '\n' |
    while IFS= read -r p; do
      p=${p//'$ORIGIN'/$origin}
      p=${p//'${ORIGIN}'/$origin}
      [[ -n $p ]] && printf '%s\n' "$p"
    done
}

# Cache of "soname<TAB>path" from ldconfig -p (system query, not a found program).
bcc_ldcache() {
  if [[ -z ${BCC_LDCACHE_LOADED:-} ]]; then
    BCC_LDCACHE=""
    local ldc
    for ldc in ldconfig /sbin/ldconfig /usr/sbin/ldconfig; do
      if bcc_have "$ldc"; then
        BCC_LDCACHE=$(bcc_sys "$ldc" -p | sed -n 's/^[[:space:]]*\([^ ]*\) (\([^)]*\)) => \(.*\)$/\1\t\2\t\3/p')
        break
      fi
    done
    BCC_LDCACHE_LOADED=1
  fi
  printf '%s\n' "$BCC_LDCACHE"
}

# Resolve a soname the way ld.so would, approximately: RUNPATH, ld cache, default dirs.
# Usage: bcc_elf_resolve SONAME RUNPATH-DIR...
bcc_elf_resolve() {
  local name=$1 d hit
  shift
  for d in "$@"; do
    [[ -e $d/$name ]] && { printf '%s\n' "$d/$name"; return 0; }
  done
  hit=$(bcc_ldcache | awk -F'\t' -v n="$name" '$1 == n && $2 ~ /x86-64|64bit|AArch64|aarch64/ { print $3; exit }')
  [[ -z $hit ]] && hit=$(bcc_ldcache | awk -F'\t' -v n="$name" '$1 == n { print $3; exit }')
  [[ -n $hit ]] && { printf '%s\n' "$hit"; return 0; }
  for d in /lib64 /usr/lib64 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu /lib /usr/lib; do
    [[ -e $d/$name ]] && { printf '%s\n' "$d/$name"; return 0; }
  done
  return 1
}

# Does FILE load libbrotlidec, directly or through other libraries?
# Prints the resolved libbrotlidec path and the method (ldd | readelf).
# Status: 0 linked, 1 not linked (static copy or no Brotli), 2 undetermined.
bcc_links_brotlidec() {
  local file=$1 out lib
  if ((!BCC_NO_EXEC)) && bcc_have ldd; then
    # glibc's ldd asks the system dynamic loader to list dependencies (--list);
    # the file's own code does not run.
    out=$(bcc_sys ldd -- "$file")
    if [[ $out == *"not a dynamic executable"* || $out == *"statically linked"* ]]; then
      return 1
    fi
    lib=$(sed -n 's/^[[:space:]]*libbrotlidec[^ ]* => \([^ ]*\) .*/\1/p' <<<"$out" | head -n 1)
    if [[ -n $lib ]]; then
      printf '%s\tldd\n' "$lib"
      return 0
    fi
    [[ -n $out ]] && return 1
  fi
  bcc_have readelf || return 2
  # Breadth-first walk over NEEDED entries (depth-limited).
  local -A seen=()
  local -a queue=("$file") next=()
  local depth cur so path
  local -a rp=()
  for ((depth = 0; depth < 8 && ${#queue[@]}; depth++)); do
    next=()
    for cur in "${queue[@]}"; do
      [[ -z ${seen[$cur]:-} ]] || continue
      seen[$cur]=1
      mapfile -t rp < <(bcc_elf_runpath "$cur")
      while IFS= read -r so; do
        [[ -n $so ]] || continue
        path=$(bcc_elf_resolve "$so" ${rp[@]+"${rp[@]}"}) || continue
        if [[ $so == libbrotlidec* ]]; then
          printf '%s\treadelf\n' "$path"
          return 0
        fi
        next+=("$path")
      done < <(bcc_elf_needed "$cur")
    done
    queue=(${next[@]+"${next[@]}"})
  done
  return 1
}

# Decoder error-name strings ("_ERROR_FORMAT_*") found in FILE, one per line, sorted.
# Strings are taken as runs of printable bytes, like strings(1); only whole strings
# that start with _ERROR_FORMAT_ count (Node.js also carries
# "BROTLI_DECODER_ERROR_FORMAT_*" names in its own table).
bcc_brotli_error_names() {
  LC_ALL=C tr -c '[:print:]' '\n' <"$1" 2>/dev/null | LC_ALL=C grep -E '^_ERROR_FORMAT_[A-Z0-9_]+$' | sort -u
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
