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
  sed -n 's/^[^[]*(NEEDED)[^[]*\[\(.*\)\]$/\1/p' <<<"$out"
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

# The system's loader, per architecture. Only it is asked for its glibc-hwcaps order (below),
# and that order is used only for programs that name it in PT_INTERP and for libraries (which
# name none: this host's programs load them). Another loader may search otherwise.
BCC_SYS_LOADERS="/lib64/ld-linux-x86-64.so.2 /lib/ld-linux-aarch64.so.1"

# The glibc-hwcaps subdirectories the system's loader searches, highest priority first, as the
# loader itself says ("ld.so --help", glibc 2.33 and later; docs/design.md 10.28): it picks the
# highest level the CPU supports, so the order cannot be read from the names. Asked once per run
# in the main shell (bcc_run_checks), from "/" with an empty environment (GLIBC_TUNABLES can
# mask levels), and only of a loader that no one but root can change and whose file names
# --glibc-hwcaps-mask (added in 2.33, with --help): an older one takes "--help" for a program to
# load. Sets BCC_HWCAPS_LOADER (its real path; empty when it could not be asked) and BCC_HWCAPS
# (empty when it searches none).
bcc_hwcaps_load() {
  [[ -z ${BCC_HWCAPS_LOADED:-} ]] || return 0
  local l real n out
  BCC_HWCAPS_LOADED=1
  BCC_HWCAPS_LOADER=""
  BCC_HWCAPS=()
  for l in $BCC_SYS_LOADERS; do
    real=$(bcc_realpath "$l") || continue
    [[ -f $real ]] || continue
    bcc_safe_to_exec "$real" 0 >/dev/null || continue
    n=$(bcc_read_file "$real" 16777216 | LC_ALL=C grep -a -c -F -e --glibc-hwcaps-mask) || n=0
    [[ $n =~ ^[1-9][0-9]*$ ]] || continue
    out=$(cd / && bcc_sys env -i "$real" --help) || continue
    bcc_hwcaps_parse "$out" || continue
    BCC_HWCAPS_LOADER=$real
    return 0
  done
  BCC_HWCAPS=()
  return 0
}

# The glibc-hwcaps part of "ld.so --help" into BCC_HWCAPS: the names under "Subdirectories of
# glibc-hwcaps directories, in priority order:" marked "(supported, searched)", in that order. A
# name without the mark (masked, or a level the CPU lacks) is not searched. "No subdirectories of
# glibc-hwcaps directories are searched." leaves it empty. Status 1 when the text says neither.
bcc_hwcaps_parse() {
  local line in=0 said=0 re='^  ([A-Za-z0-9_-]+) \(supported, searched\)$'
  BCC_HWCAPS=()
  while IFS= read -r line; do
    if ((in)); then
      [[ -n $line ]] || break
      if [[ $line =~ $re ]]; then BCC_HWCAPS+=("${BASH_REMATCH[1]}"); fi
      continue
    fi
    case $line in
      'Subdirectories of glibc-hwcaps directories, in priority order:') in=1 said=1 ;;
      'No subdirectories of glibc-hwcaps directories are searched.') said=1 ;;
    esac
  done <<<"$1"
  ((said))
}

# Is the glibc-hwcaps order known for an object whose PT_INTERP is INTERP (empty: none)?
bcc_hwcaps_known_for() {
  local real
  [[ -n ${BCC_HWCAPS_LOADER:-} ]] || return 1
  [[ -n $1 ]] || return 0
  real=$(bcc_realpath "$1") || return 1
  [[ $real == "$BCC_HWCAPS_LOADER" ]]
}

# The glibc-hwcaps subdirectories of DIR that ld.so tries before DIR itself, into BCC_GLOB. With
# the order known (MODE known): those the loader searches, highest priority first. Otherwise
# every one there, in name order (which of them it tries is not known). Only what is there (a
# dangling link counts: its target may be created). DIR is taken literally: a "[" or "*" in a
# found path is part of a name, not a pattern.
# Usage: bcc_hwcaps_dirs DIR MODE
bcc_hwcaps_dirs() {
  local d=$1/glibc-hwcaps had=0 h
  BCC_GLOB=()
  if [[ ${2:-} == known ]]; then
    for h in ${BCC_HWCAPS[@]+"${BCC_HWCAPS[@]}"}; do
      if [[ -e $d/$h || -L $d/$h ]]; then BCC_GLOB+=("$d/$h"); fi
    done
    return 0
  fi
  shopt -q nullglob && had=1
  shopt -s nullglob
  BCC_GLOB=("$d"/*)
  ((had)) || shopt -u nullglob
  return 0
}

# Look for NAME in DIR as ld.so does - its glibc-hwcaps subdirectories (bcc_hwcaps_dirs), then
# DIR itself - appending what is found to BCC_FOUND. Status 0 when the search ends here: always
# at a copy in DIR itself; at one in a subdirectory only when the order is known (otherwise the
# loader may skip it, and the search goes on).
# Usage: bcc_dep_find_in MODE NAME DIR
bcc_dep_find_in() {
  local h
  bcc_hwcaps_dirs "$3" "$1"
  for h in ${BCC_GLOB[@]+"${BCC_GLOB[@]}"}; do
    [[ -e $h/$2 ]] || continue
    BCC_FOUND+=("$h/$2")
    [[ $1 != known ]] || return 0
  done
  [[ -e $3/$2 ]] || return 1
  BCC_FOUND+=("$3/$2")
}

# The default directories ld.so searches after its cache (tests stand in for them).
BCC_LIB_DIRS=(/lib64 /usr/lib64 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu /lib /usr/lib)

# The ld.so cache, then the default directories (the RPATH/RUNPATH part of the search is
# bcc_dep_find's), appending to BCC_FOUND. For one name the cache may hold entries for
# glibc-hwcaps subdirectories ('hwcap: "x86-64-v3"'; ldconfig lists them first, in name order)
# and one for the plain file: ld.so takes the entry of the highest priority it searches, else the
# plain one. Entries of the older hwcaps scheme ("hwcap: 0x..."; glibc before 2.37) are not
# taken (docs/limitations.md). 64-bit entries are preferred. Status 0 when the search ended at
# a file, as for bcc_dep_find_in.
# Usage: bcc_elf_resolve MODE SONAME
bcc_elf_resolve() {
  local mode=$1 name=$2 d hits sel line arch path i bi=-1 best="" plain="" re='hwcap: "([^"]+)"'
  bcc_ldcache_load
  hits=$(awk -F'\t' -v n="$name" '$1 == n { print $2 "\t" $3 }' <<<"$BCC_LDCACHE")
  sel=$(awk -F'\t' '$1 ~ /x86-64|64bit|AArch64|aarch64/' <<<"$hits")
  [[ -n $sel ]] || sel=$hits
  while IFS= read -r line; do
    [[ $line == *$'\t'* ]] || continue
    arch=${line%%$'\t'*} path=${line#*$'\t'}
    if [[ $arch =~ $re ]]; then
      if [[ $mode != known ]]; then
        BCC_FOUND+=("$path")
        continue
      fi
      for i in ${BCC_HWCAPS[@]+"${!BCC_HWCAPS[@]}"}; do
        if [[ ${BCC_HWCAPS[i]} == "${BASH_REMATCH[1]}" ]] && ((bi < 0 || i < bi)); then
          bi=$i best=$path
        fi
      done
    elif [[ $arch != *hwcap:* && -z $plain ]]; then
      plain=$path
    fi
  done <<<"$sel"
  [[ -z $best ]] || { BCC_FOUND+=("$best"); return 0; }
  [[ -z $plain ]] || { BCC_FOUND+=("$plain"); return 0; }
  for d in "${BCC_LIB_DIRS[@]}"; do
    bcc_dep_find_in "$mode" "$name" "$d" && return 0
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
# A FIXED that stands says what the strings showed and what they do not (docs/design.md 10.25),
# as a LIKELY_FIXED line does: the reason is rebuilt from bcc_judge's (BCC_J_BASE) with every
# file confirmed so far (BCC_J_CONFIRMED), so several files still give one sentence of each kind.
# NAMED: the file is not the one on the finding's line (an extension module, a library), so the
# reason names it.
# Usage: bcc_crosscheck_fixed FILE [NAMED]
bcc_crosscheck_fixed() {
  local label=""
  [[ $BCC_J_STATUS == FIXED ]] || return 0
  [[ -z ${2:-} ]] || label=$1
  bcc_crosscheck_apply "$(bcc_brotli_heuristic "$1")" "$1" "$label"
}

# The same rule for strings already judged (a bcc_brotli_classify line), however the file was
# read: a file inside a container comes through its engine (C14, docs/design.md 10.29). SCOPE
# is what "Could not be scanned" lists when the file could not be read to the end; LABEL names
# the file in the reason (empty: the file on the finding's line). RES "UNREADABLE": the file
# could not be read at all; the caller lists it, with why.
# Usage: bcc_crosscheck_apply RES SCOPE LABEL
bcc_crosscheck_apply() {
  local res=$1 scope=$2 label=$3 files="" c
  [[ $BCC_J_STATUS == FIXED ]] || return 0
  [[ -n ${BCC_J_BASE:-} ]] || BCC_J_BASE=$BCC_J_REASON
  # (An empty entry: the file on the finding's line.)
  if [[ ${res%%$'\t'*} == LIKELY_FIXED ]]; then BCC_J_CONFIRMED+=("$label"); fi
  for c in ${BCC_J_CONFIRMED[@]+"${BCC_J_CONFIRMED[@]}"}; do [[ -z $c ]] || files+="${files:+, }$c"; done
  BCC_J_REASON=$BCC_J_BASE
  if [[ -n $files ]]; then
    BCC_J_REASON+=" $(bcc_msg r_crosscheck_fixed "$files")"
  elif ((${#BCC_J_CONFIRMED[@]})); then
    BCC_J_REASON+=" $(bcc_msg r_crosscheck_fixed_self)"
  fi
  case ${res%%$'\t'*} in
    LIKELY_FIXED)
      BCC_J_REASON+=" $(bcc_msg r_fixed_unseen)"
      return 0
      ;;
    LIKELY_VULNERABLE) BCC_J_REASON=$(bcc_msg r_crosscheck_conflict "$BCC_J_REASON") ;;
    MULTIPLE_COPIES) BCC_J_REASON="$BCC_J_REASON $(bcc_msg r_heur_multiple)" ;;
    INCOMPLETE)
      BCC_J_REASON="$BCC_J_REASON $(bcc_msg r_crosscheck_incomplete "$BCC_MAX_ELF_MB")"
      bcc_note_incomplete "$scope"
      ;;
    UNREADABLE) BCC_J_REASON="$BCC_J_REASON $(bcc_msg r_crosscheck_unreadable "$label")" ;;
    *) BCC_J_REASON="$BCC_J_REASON $(bcc_msg r_crosscheck_unconfirmed)" ;;
  esac
  BCC_J_STATUS=UNKNOWN
  BCC_J_NEXT=$(bcc_msg n_check_vendor)
  return 0
}

# The same rule when there is no file to look at: a "fixed" version stays unconfirmed, so the
# result is UNKNOWN. Acts on BCC_J_* from bcc_judge, in the main shell.
# Usage: bcc_crosscheck_no_file REASON NEXT
bcc_crosscheck_no_file() {
  [[ $BCC_J_STATUS == FIXED ]] || return 0
  BCC_J_REASON="$BCC_J_REASON $1"
  BCC_J_STATUS=UNKNOWN
  BCC_J_NEXT=$2
  return 0
}

# A file whose strings could not be read to the end is listed as not scanned (once), for
# failure: it was to be judged.
bcc_note_incomplete() {
  bcc_skip failed "$1" "$(bcc_msg skip_incomplete "$BCC_MAX_ELF_MB")"
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

# Where ld.so finds SONAME, into BCC_FOUND: in each directory given, its glibc-hwcaps
# subdirectories and then the directory itself (bcc_dep_find_in), then the ld.so cache and the
# default directories (bcc_elf_resolve). With the order known (MODE known) that is the one file
# found. Otherwise a copy in a glibc-hwcaps subdirectory may or may not be the one taken, so
# the search goes on to the first copy outside them, and BCC_FOUND holds every candidate in
# search order: more than one means that which is loaded could not be told. Status 1 (none)
# when not found. In the calling shell: paths may hold any byte, so they are not printed.
# Usage: bcc_dep_find MODE SONAME DIR...
bcc_dep_find() {
  local mode=$1 name=$2 d
  shift 2
  BCC_FOUND=()
  for d in "$@"; do
    bcc_dep_find_in "$mode" "$name" "$d" && return 0
  done
  bcc_elf_resolve "$mode" "$name" || ((${#BCC_FOUND[@]}))
}

# The dynamic section of OBJECT (readelf -d), once, into BCC_DYN_CACHE[OBJECT] ($'\001' when
# readelf failed on it).
bcc_dyn_load() {
  local dyn
  [[ -z ${BCC_DYN_CACHE[$1]+x} ]] || return 0
  if dyn=$(bcc_sys readelf -d -- "$1"); then BCC_DYN_CACHE[$1]=$dyn; else BCC_DYN_CACHE[$1]=$'\001'; fi
}

# One record of a dependency walk, appended to BCC_WALK_K/_A/_B (see bcc_dep_walk_uncached).
bcc_walk_rec() {
  BCC_WALK_K+=("$1")
  BCC_WALK_A+=("$2")
  BCC_WALK_B+=("${3:-}")
}

# The libraries FILE would load, looked up the way glibc's ld.so does: for each object, the
# DT_RPATH of the object that needs the library and then of the objects that loaded it, up
# to the executable - unless the needing object has a DT_RUNPATH, which also hides its own
# DT_RPATH - then that object's DT_RUNPATH, the ld.so cache, the default directories.
# (LD_LIBRARY_PATH does not apply: programs run with an empty environment.) In each of those
# directories ld.so tries the glibc-hwcaps subdirectories first, in its loader's order of
# priority when that is known (bcc_hwcaps_load; otherwise every copy there is a candidate,
# bcc_dep_find). A name is loaded once: a needed name that an object already loaded was
# loaded by, or that is such an object's SONAME, is that object and is not looked up again
# (ld.so loads breadth-first, as this walk goes). Records, each a kind and up to two fields:
#   I  path            the loader named by PT_INTERP
#   D  dir             a directory listed in some RPATH/RUNPATH
#   N  soname  path    a needed library and where it resolved ("" when not found); a name
#                      with several candidates has one N record for each
#   X  kind  detail    something not followed: empty/relative/token (search entries, see
#                      bcc_dep_dirs), missing (soname), readelf (failed on file), depth;
#                      hwcaps (soname): which of its N records ld.so loads could not be told
# The records are appended to the arrays BCC_WALK_K/_A/_B, never joined into lines: the
# fields hold paths, and a path (or $ORIGIN) may hold a newline or a tab. Status 2 when
# readelf is not available. Run in the main shell, it keeps each object's dynamic section
# (BCC_DYN_CACHE) and each lookup (BCC_FIND_CACHE, a range of BCC_FIND_POOL), so that
# libraries shared by many programs are read once. BCC_DEPWALK_HWC[FILE] says whether the
# glibc-hwcaps order was known for FILE ("known" or "unknown").
bcc_dep_walk_uncached() {
  local file=$1 interp dyn needed rpath runpath cur inh so path d depth i fkey hs hc hwc fs fc real sn
  local -A seen=() named=() same=()
  # The search path each queued object inherits is a range "start count" of chains.
  local -a q=("$file") qi=("0 0") nq=() nqi=() own_rp=() own_run=() search=() inh_a=() chains=() cands=() reals=()
  bcc_have readelf || return 2
  bcc_hwcaps_load
  interp=""
  if interp=$(bcc_sys readelf -l -- "$file"); then
    interp=$(sed -n 's/.*\[Requesting program interpreter: \(.*\)\]$/\1/p' <<<"$interp" | head -n 1)
    [[ -z $interp ]] || bcc_walk_rec I "$interp"
  else
    interp=""
  fi
  hwc=unknown
  bcc_hwcaps_known_for "$interp" && hwc=known
  BCC_DEPWALK_HWC[$file]=$hwc
  for ((depth = 0; depth < 8 && ${#q[@]}; depth++)); do
    nq=() nqi=()
    for i in "${!q[@]}"; do
      cur=${q[i]} inh=${qi[i]}
      [[ -z ${seen[$cur]:-} ]] || continue
      seen[$cur]=1
      bcc_dyn_load "$cur"
      dyn=${BCC_DYN_CACHE[$cur]}
      if [[ $dyn == $'\001' ]]; then
        bcc_walk_rec X readelf "$cur"
        continue
      fi
      # "(TAG)  Library runpath: [VALUE]": the value runs from the first "[" to the "]"
      # that ends the line, since a directory may have "[" or "]" in its name.
      needed=$(sed -n 's/^[^[]*(NEEDED)[^[]*\[\(.*\)\]$/\1/p' <<<"$dyn")
      rpath=$(sed -n 's/^[^[]*(RPATH)[^[]*\[\(.*\)\]$/\1/p' <<<"$dyn" | head -n 1)
      runpath=$(sed -n 's/^[^[]*(RUNPATH)[^[]*\[\(.*\)\]$/\1/p' <<<"$dyn" | head -n 1)
      # glibc ignores DT_RPATH when the same object has DT_RUNPATH.
      [[ -n $runpath ]] && rpath=""
      bcc_dep_dirs "$rpath" "$cur"
      own_rp=(${BCC_DIRS[@]+"${BCC_DIRS[@]}"})
      # (An issue is "kind<TAB>detail"; the kind has no tab, the detail may.)
      for d in ${BCC_DIR_ISSUES[@]+"${BCC_DIR_ISSUES[@]}"}; do bcc_walk_rec X "${d%%$'\t'*}" "${d#*$'\t'}"; done
      bcc_dep_dirs "$runpath" "$cur"
      own_run=(${BCC_DIRS[@]+"${BCC_DIRS[@]}"})
      for d in ${BCC_DIR_ISSUES[@]+"${BCC_DIR_ISSUES[@]}"}; do bcc_walk_rec X "${d%%$'\t'*}" "${d#*$'\t'}"; done
      for d in ${own_rp[@]+"${own_rp[@]}"} ${own_run[@]+"${own_run[@]}"}; do bcc_walk_rec D "$d"; done
      inh_a=()
      read -r hs hc <<<"$inh"
      ((hc == 0)) || inh_a=("${chains[@]:hs:hc}")
      if [[ -n $runpath ]]; then
        search=(${own_run[@]+"${own_run[@]}"})
      else
        search=(${own_rp[@]+"${own_rp[@]}"} ${inh_a[@]+"${inh_a[@]}"})
      fi
      while IFS= read -r so; do
        [[ -n $so ]] || continue
        # Already loaded under this name (or as this SONAME): ld.so uses that object.
        [[ -z ${named[$so]:-} ]] || continue
        BCC_FOUND=()
        if [[ $so == */* ]]; then
          [[ ! -e $so ]] || BCC_FOUND=("$so")
        else
          # Each part with its length: no two different searches share a key (a directory
          # reached through $ORIGIN may hold ":" or any other separator).
          fkey="$hwc ${#so}:$so"
          for d in ${search[@]+"${search[@]}"}; do fkey+=" ${#d}:$d"; done
          if [[ -z ${BCC_FIND_CACHE[$fkey]+x} ]]; then
            bcc_dep_find "$hwc" "$so" ${search[@]+"${search[@]}"} || true
            BCC_FIND_CACHE[$fkey]="${#BCC_FIND_POOL[@]} ${#BCC_FOUND[@]}"
            BCC_FIND_POOL+=(${BCC_FOUND[@]+"${BCC_FOUND[@]}"})
          fi
          read -r fs fc <<<"${BCC_FIND_CACHE[$fkey]}"
          BCC_FOUND=()
          ((fc == 0)) || BCC_FOUND=("${BCC_FIND_POOL[@]:fs:fc}")
        fi
        if ((${#BCC_FOUND[@]} == 0)); then
          bcc_walk_rec N "$so" ""
          bcc_walk_rec X missing "$so"
          continue
        fi
        named[$so]=1
        # Candidates that are one file (a link, /lib and /usr/lib) count once.
        cands=() reals=() same=()
        for path in "${BCC_FOUND[@]}"; do
          if [[ -z ${BCC_FIND_CACHE[real:$path]+x} ]]; then
            BCC_FIND_CACHE[real:$path]=$(bcc_realpath "$path") || BCC_FIND_CACHE[real:$path]=""
          fi
          real=${BCC_FIND_CACHE[real:$path]}
          if [[ -n $real ]]; then
            [[ -z ${same[$real]:-} ]] || continue
            same[$real]=1
          fi
          cands+=("$path")
          reals+=("$real")
        done
        for path in "${cands[@]}"; do bcc_walk_rec N "$so" "$path"; done
        ((${#cands[@]} == 1)) || bcc_walk_rec X hwcaps "$so"
        for real in "${reals[@]}"; do
          [[ -n $real ]] || continue
          # The names it is loaded by include its SONAME (read now: ld.so maps it now).
          bcc_dyn_load "$real"
          sn=$(sed -n 's/^[^[]*(SONAME)[^[]*\[\(.*\)\]$/\1/p' <<<"${BCC_DYN_CACHE[$real]}" | head -n 1)
          [[ -z $sn ]] || named[$sn]=1
          [[ -z ${seen[$real]:-} ]] || continue
          nq+=("$real")
          # What this library needs is looked up in its own RPATH, then in ours, upward.
          local -a chain=(${own_rp[@]+"${own_rp[@]}"} ${inh_a[@]+"${inh_a[@]}"})
          nqi+=("${#chains[@]} ${#chain[@]}")
          chains+=(${chain[@]+"${chain[@]}"})
        done
      done <<<"$needed"
    done
    q=(${nq[@]+"${nq[@]}"})
    qi=(${nqi[@]+"${nqi[@]}"})
  done
  ((${#q[@]} == 0)) || bcc_walk_rec X depth "$file"
  return 0
}

# bcc_dep_walk_uncached once per file, kept in the main shell so that later callers - often
# in a subshell - reuse it: BCC_DEPWALK_CACHE holds the range "start count" of its records
# in BCC_WALK_K/_A/_B, BCC_DEPWALK_RC its status.
bcc_dep_walk_prefetch() {
  local rc=0 start=${#BCC_WALK_K[@]}
  [[ -z ${BCC_DEPWALK_RC[$1]+x} ]] || return 0
  bcc_dep_walk_uncached "$1" || rc=$?
  BCC_DEPWALK_CACHE[$1]="$start $((${#BCC_WALK_K[@]} - start))"
  BCC_DEPWALK_RC[$1]=$rc
}

# bcc_needed_has_brotlidec TEXT: does this list of NEEDED entries (one per line) name
# libbrotlidec? An entry may be a path (a library linked without a SONAME).
bcc_needed_has_brotlidec() {
  grep -Eq '(^|/)libbrotlidec[^/]*$' <<<"$1"
}

# Does FILE load libbrotlidec, directly or through other libraries? Every libbrotlidec it
# loads, in the order ld.so loads them (a program may load several, under different names;
# docs/design.md 10.28), one entry per file, into BCC_LINKS: the path as resolved, or
# "NAME (not found)". BCC_LINKS_AMBIG has, for each, the library name when the file is one of
# several copies the loader may pick (glibc-hwcaps, order unknown: bcc_dep_find), else "".
# Status: 0 linked, 1 not linked (static copy or no Brotli), 2 undetermined. When none was
# found, anything that could not be followed to the end (no readelf, a readelf failure, a
# library not found, the depth limit) is 2, never 1: "not linked" leads to NOT_APPLICABLE. The
# file is only read: ldd, which hands the file to the loader, is not used.
bcc_links_brotlidec_uncached() {
  local file=$1 rc s c i so p real key open=0
  local -A amb=() got=()
  BCC_LINKS=() BCC_LINKS_AMBIG=()
  bcc_dep_walk_prefetch "$file"
  rc=${BCC_DEPWALK_RC[$file]}
  ((rc == 0)) || return 2
  read -r s c <<<"${BCC_DEPWALK_CACHE[$file]}"
  for ((i = s; i < s + c; i++)); do
    [[ ${BCC_WALK_K[i]} != X || ${BCC_WALK_A[i]} != hwcaps ]] || amb[${BCC_WALK_B[i]}]=1
  done
  for ((i = s; i < s + c; i++)); do
    case ${BCC_WALK_K[i]} in
      N)
        so=${BCC_WALK_A[i]} p=${BCC_WALK_B[i]}
        # A NEEDED entry may be a path (a library linked without a SONAME).
        [[ ${so##*/} == libbrotlidec* ]] || continue
        if [[ -z $p ]]; then
          key="name:$so" p="$so (not found)"
        else
          real=${BCC_FIND_CACHE[real:$p]-}
          [[ -n $real ]] || real=$(bcc_realpath "$p") || real=""
          key="file:${real:-$p}"
        fi
        [[ -z ${got[$key]:-} ]] || continue
        got[$key]=1
        BCC_LINKS+=("$p")
        BCC_LINKS_AMBIG+=("${amb[$so]:+$so}")
        ;;
      X)
        case ${BCC_WALK_A[i]} in missing | readelf | depth) open=1 ;; esac
        ;;
    esac
  done
  ((${#BCC_LINKS[@]} == 0)) || return 0
  ((open)) && return 2
  return 1
}

# bcc_links_brotlidec_uncached once per file, kept in the main shell: BCC_LINK_CACHE holds the
# range "start count" of its entries in BCC_LINK_P (BCC_LINKS) and BCC_LINK_S
# (BCC_LINKS_AMBIG), BCC_LINK_RC its status.
bcc_link_prefetch() {
  local rc=0
  [[ -z ${BCC_LINK_RC[$1]+x} ]] || return 0
  bcc_links_brotlidec_uncached "$1" || rc=$?
  BCC_LINK_CACHE[$1]="${#BCC_LINK_P[@]} ${#BCC_LINKS[@]}"
  BCC_LINK_P+=(${BCC_LINKS[@]+"${BCC_LINKS[@]}"})
  BCC_LINK_S+=(${BCC_LINKS_AMBIG[@]+"${BCC_LINKS_AMBIG[@]}"})
  BCC_LINK_RC[$1]=$rc
}

# Usage: bcc_links_brotlidec FILE - in the calling shell, not in $(...): the libraries come back
# in BCC_LINKS and BCC_LINKS_AMBIG (see bcc_links_brotlidec_uncached), never printed (a path
# may hold any byte but NUL). Callers report them with bcc_report_linked_libs.
bcc_links_brotlidec() {
  local s c
  bcc_link_prefetch "$1"
  BCC_LINKS=() BCC_LINKS_AMBIG=()
  read -r s c <<<"${BCC_LINK_CACHE[$1]}"
  if ((c)); then
    BCC_LINKS=("${BCC_LINK_P[@]:s:c}")
    BCC_LINKS_AMBIG=("${BCC_LINK_S[@]:s:c}")
  fi
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
  local f=$1 max=$((BCC_MAX_ELF_MB * 1024 * 1024)) size cut=0
  if [[ ! -f $f || ! -r $f ]]; then
    printf '0\t0\t0\t0\t0\t0\tunreadable\n'
    return
  fi
  size=$(stat -L -c %s -- "$f" 2>/dev/null) || size=0
  [[ $size =~ ^[0-9]+$ ]] && ((size > max)) && cut=1
  bcc_brotli_scan_stream "$cut" bcc_read_file "$f" "$max"
  printf '%s\n' "$BCC_SCAN"
}

# The scan of bcc_brotli_scan over the bytes READER prints, so that a file not on this host's
# disk can be read under the same limits: a container's file comes through its engine (C14,
# docs/design.md 10.29), never through a temporary file. READER reads at most the size limit
# under its own time limit; CUT is 1 when the file is known to be larger than the limit. Sets
# BCC_SCAN (the record of bcc_brotli_scan) and BCC_SCAN_RC (READER's exit status; empty when
# not known). As above, "complete" comes from the exit status of every stage, never from the
# bytes read. In the calling shell.
# Usage: bcc_brotli_scan_stream CUT READER [ARG...]
bcc_brotli_scan_stream() {
  local cut=$1 res counts
  local -a sts=()
  shift
  res=$(
    "$@" | LC_ALL=C tr -c '[:print:]' '\n' | (
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
  BCC_SCAN_RC=""
  if ((${#sts[@]} == 3)) && [[ ${sts[0]} =~ ^[0-9]+$ ]]; then BCC_SCAN_RC=${sts[0]}; fi
  local re='^[0-9]+'$'\t''[0-9]+'$'\t''[0-9]+'$'\t''[0-9]+'$'\t''[0-9]+'$'\t''[0-9]+$'
  if [[ ! $counts =~ $re ]]; then
    counts=$'0\t0\t0\t0\t0\t0'
    sts=(1)
  fi
  if ((cut == 0 && ${#sts[@]} == 3 && sts[0] == 0 && sts[1] == 0 && sts[2] == 0)); then
    BCC_SCAN="$counts"$'\t'complete
  else
    BCC_SCAN="$counts"$'\t'partial
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
  bcc_brotli_classify "$(bcc_brotli_scan "$1")"
}

# The same, from a record of bcc_brotli_scan (or of bcc_brotli_scan_stream, for a file read
# some other way).
# Usage: bcc_brotli_classify RECORD
bcc_brotli_classify() {
  local count bs dicts read status
  bcc_split_tab "$1"
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
