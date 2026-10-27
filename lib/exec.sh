# shellcheck shell=bash
# exec.sh - running programs the scan found, with the user's consent (docs/design.md 10.11).
#
# Reading a version from the program itself is the most direct evidence, so the tool asks to
# run found programs with one version argument. Nothing found is run without consent:
#   1. the checks name the programs whose version they need (bcc_build_exec_plan);
#   2. each comes with facts: who owns it, and who besides root (or you) could change it,
#      the directories above it, or the libraries it would load (bcc_exec_facts);
#   3. the user chooses at a terminal - all, none, or by number - or says so in advance with
#      --yes or --no-exec; without a terminal and without either, the tool stops and asks for
#      one (bcc_exec_consent);
#   4. only the chosen programs run, from "/", with an empty environment and a time limit
#      (bcc_exec_run), and the report lists what ran, what did not, and the facts.
# The tool reports the facts; deciding what to run is the user's. (Earlier versions decided
# by themselves which programs were "safe" to run, and hid that decision in the results.)

BCC_PROBE_ARGS="--version -V"

# Fill the global array BCC_LIST from NUL-terminated records on stdin (paths may contain
# newlines; bash 4.2 has no "mapfile -d").
bcc_collect0() {
  local x
  BCC_LIST=()
  while IFS= read -r -d '' x; do BCC_LIST+=("$x"); done
}

# Expand the glob PATTERN into the array BCC_GLOB: no word splitting, no match = no entry.
bcc_glob() {
  local IFS='' had=0
  shopt -q nullglob && had=1
  shopt -s nullglob
  # shellcheck disable=SC2206  # the expansion is the point; IFS is empty, so nothing splits
  BCC_GLOB=($1)
  ((had)) || shopt -u nullglob
  return 0
}

# The glibc-hwcaps subdirectories of DIR (ld.so tries them first), into BCC_GLOB. DIR is
# taken literally: a "[" or "*" in a found path is part of a name, not a pattern.
bcc_hwcaps_dirs() {
  local had=0
  shopt -q nullglob && had=1
  shopt -s nullglob
  BCC_GLOB=("$1"/glibc-hwcaps/*)
  ((had)) || shopt -u nullglob
  return 0
}

# Split PATH at "/" into BCC_PARTS, dropping empty components. A name may hold any byte but
# "/" and NUL ("IFS=/ read" would stop at a newline).
bcc_path_parts() {
  local rest=$1
  BCC_PARTS=()
  while [[ $rest == */* ]]; do
    [[ -z ${rest%%/*} ]] || BCC_PARTS+=("${rest%%/*}")
    rest=${rest#*/}
  done
  [[ -z $rest ]] || BCC_PARTS+=("$rest")
}

# Name of a user or group id, for the facts (cached; the id itself when unknown).
bcc_user_name() {
  if [[ -z ${BCC_UNAME_CACHE[u$1]+x} ]]; then
    local n
    n=$(getent passwd "$1" 2>/dev/null | cut -d: -f1) || n=""
    BCC_UNAME_CACHE[u$1]=${n:-uid $1}
  fi
  BCC_NAME=${BCC_UNAME_CACHE[u$1]}
}
bcc_group_name() {
  if [[ -z ${BCC_UNAME_CACHE[g$1]+x} ]]; then
    local n
    n=$(getent group "$1" 2>/dev/null | cut -d: -f1) || n=""
    BCC_UNAME_CACHE[g$1]=${n:-gid $1}
  fi
  BCC_NAME=${BCC_UNAME_CACHE[g$1]}
}

# Who besides root (or you) could change PATH, as the kernel would resolve it: the path is
# walked one component at a time from "/", following symlinks where they are, and every
# directory looked up in and the final file are examined. Appends facts to BCC_FACTS:
# another owner, a group that can write, or anyone who can write (a sticky directory such
# as /tmp counts through the owners of what is in it). Cached per path (main shell), as a
# range of BCC_FACT_POOL: facts name paths, which may hold newlines or any separator.
bcc_path_facts() {
  local key=$1 cur=/ c t l n=0 uid s cnt
  local -a comps=() found=()
  if [[ -z ${BCC_PATHFACTS_CACHE[$key]+x} ]]; then
    bcc_path_parts "${1#/}"
    comps=(${BCC_PARTS[@]+"${BCC_PARTS[@]}"})
    while :; do
      bcc_node_facts "$cur" dir
      found+=(${BCC_NODE_FACTS[@]+"${BCC_NODE_FACTS[@]}"})
      ((${#comps[@]})) || break
      c=${comps[0]}
      comps=("${comps[@]:1}")
      case $c in
        .) continue ;;
        ..)
          cur=${cur%/*}
          [[ -n $cur ]] || cur=/
          continue
          ;;
      esac
      t=${cur%/}/$c
      if [[ -L $t ]]; then
        # The link itself: in a sticky directory such as /tmp its owner can replace it.
        uid=$(stat -c %u -- "$t" 2>/dev/null) || uid=0
        if [[ $uid =~ ^[0-9]+$ ]] && ((uid != 0 && uid != EUID)); then
          bcc_user_name "$uid"
          found+=("$(bcc_msg f_owner "$t" "$BCC_NAME")")
        fi
        # The kernel gives up after 40 links (ELOOP); so does this walk, and says so.
        # (The "x" keeps a target that ends in a newline: $(...) drops trailing ones.)
        if ((++n > 40)) || ! l=$(readlink -- "$t" && printf x); then
          found+=("$(bcc_msg f_link_stop "$t")")
          break
        fi
        l=${l%x}
        t=${l%$'\n'}
        bcc_path_parts "${t#/}"
        [[ $t == /* ]] && cur=/
        comps=(${BCC_PARTS[@]+"${BCC_PARTS[@]}"} ${comps[@]+"${comps[@]}"})
        continue
      fi
      if [[ ! -e $t ]]; then
        # Whoever can write in the last existing directory (above) could create it.
        found+=("$(bcc_msg f_missing "$t")")
        break
      fi
      if ((${#comps[@]})); then
        cur=$t
      else
        bcc_node_facts "$t" file
        found+=(${BCC_NODE_FACTS[@]+"${BCC_NODE_FACTS[@]}"})
        break
      fi
    done
    BCC_PATHFACTS_CACHE[$key]="${#BCC_FACT_POOL[@]} ${#found[@]}"
    BCC_FACT_POOL+=(${found[@]+"${found[@]}"})
  fi
  read -r s cnt <<<"${BCC_PATHFACTS_CACHE[$key]}"
  ((cnt == 0)) || BCC_FACTS+=("${BCC_FACT_POOL[@]:s:cnt}")
  return 0
}

# Facts about one existing file or directory P (no symlink in it), into BCC_NODE_FACTS.
bcc_node_facts() {
  local p=$1 kind=$2 uid gid mode
  BCC_NODE_FACTS=()
  read -r uid gid mode < <(stat -L -c '%u %g %a' -- "$p" 2>/dev/null) || return 0
  [[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && $mode =~ ^[0-7]+$ ]] || return 0
  if ((uid != 0 && uid != EUID)); then
    bcc_user_name "$uid"
    BCC_NODE_FACTS+=("$(bcc_msg f_owner "$p" "$BCC_NAME")")
  fi
  if (((8#$mode & 8#020) != 0)) && ! { ((EUID != 0 && uid == EUID)) && bcc_group_is_private "$uid" "$gid"; }; then
    # (In a sticky directory, group members can add entries but not replace others'.)
    if [[ $kind == file ]] || (((8#$mode & 8#1000) == 0)); then
      bcc_group_name "$gid"
      BCC_NODE_FACTS+=("$(bcc_msg f_group_write "$p" "$BCC_NAME")")
    fi
  fi
  if (((8#$mode & 8#002) != 0)) && { [[ $kind == file ]] || (((8#$mode & 8#1000) == 0)); }; then
    BCC_NODE_FACTS+=("$(bcc_msg f_world_write "$p")")
  fi
  return 0
}

# The facts for running FILE: about FILE itself, the loader it names, every library it would
# load (bcc_dep_walk), every directory those are searched in (a missing one through its
# nearest existing parent; the glibc-hwcaps subdirectories ld.so tries first), and
# /etc/ld.so.preload. Fills BCC_FACTS (deduplicated); when nothing was found, one fact says
# that only root (or you) can change them.
bcc_exec_facts() {
  local file=$1 rc=0 s c i kind a b p sub
  local -a paths=("$file") pre=()
  local -A seen=()
  BCC_FACTS=()
  bcc_dep_walk_prefetch "$file"
  rc=${BCC_DEPWALK_RC[$file]}
  if ((rc == 2)); then
    BCC_FACTS+=("$(bcc_msg f_no_readelf)")
  fi
  read -r s c <<<"${BCC_DEPWALK_CACHE[$file]}"
  for ((i = s; i < s + c; i++)); do
    kind=${BCC_WALK_K[i]} a=${BCC_WALK_A[i]} b=${BCC_WALK_B[i]}
    case $kind in
      I) paths+=("$a") ;;
      N) [[ -n $b ]] && paths+=("$b") ;;
      D)
        p=$a
        while [[ ! -e $p && ! -L $p ]]; do
          p=${p%/*}
          [[ -n $p ]] || p=/
        done
        paths+=("$p")
        bcc_hwcaps_dirs "$a"
        for sub in ${BCC_GLOB[@]+"${BCC_GLOB[@]}"}; do paths+=("$sub"); done
        ;;
      X)
        case $a in
          empty) BCC_FACTS+=("$(bcc_msg f_rp_empty "$b")") ;;
          relative) BCC_FACTS+=("$(bcc_msg f_rp_relative "$b")") ;;
          token) BCC_FACTS+=("$(bcc_msg f_rp_token "$b")") ;;
          missing) BCC_FACTS+=("$(bcc_msg f_lib_missing "$b")") ;;
          readelf) BCC_FACTS+=("$(bcc_msg f_readelf_failed "$b")") ;;
          depth) BCC_FACTS+=("$(bcc_msg f_depth)") ;;
        esac
        ;;
    esac
  done
  if [[ -e /etc/ld.so.preload ]]; then
    paths+=(/etc/ld.so.preload)
    read -r -a pre <<<"$(bcc_read_file /etc/ld.so.preload 65536 | tr ':\n' '  ')"
    for p in ${pre[@]+"${pre[@]}"}; do paths+=("$p"); done
  fi
  for p in "${paths[@]}"; do
    [[ -n $p && -z ${seen[$p]:-} ]] || continue
    seen[$p]=1
    bcc_path_facts "$p"
  done
  # Deduplicate, keeping the order.
  local -A once=()
  local -a out=()
  for p in ${BCC_FACTS[@]+"${BCC_FACTS[@]}"}; do
    [[ -z ${once[$p]:-} ]] || continue
    once[$p]=1
    out+=("$p")
  done
  if ((${#out[@]} == 0)); then
    if ((EUID == 0)); then out=("$(bcc_msg f_only_root)"); else out=("$(bcc_msg f_only_root_you)"); fi
  fi
  BCC_FACTS=("${out[@]}")
}

# Ask to run BIN with ARG for the check PURPOSE (once per BIN and ARG). The key only
# identifies the entry and is never split: a path may hold a tab, so what runs is taken from
# BCC_PLAN_BIN and BCC_PLAN_ARG. The facts are a range of BCC_FACT_POOL (bcc_plan_facts).
bcc_plan_add() {
  local bin=$1 arg=$2 purpose=$3 key
  case " $BCC_PROBE_ARGS " in *" $arg "*) ;; *) bcc_die "internal error: probe argument not allowed: $arg" ;; esac
  key=$bin$'\t'$arg
  [[ -z ${BCC_PLAN_PURPOSE[$key]+x} ]] || return 0
  BCC_PLAN+=("$key")
  BCC_PLAN_BIN[$key]=$bin
  BCC_PLAN_ARG[$key]=$arg
  BCC_PLAN_PURPOSE[$key]=$purpose
  bcc_exec_facts "$bin"
  BCC_PLAN_FACTS[$key]="${#BCC_FACT_POOL[@]} ${#BCC_FACTS[@]}"
  BCC_FACT_POOL+=("${BCC_FACTS[@]}")
}

# The facts of the plan entry KEY, into BCC_PF.
bcc_plan_facts() {
  local s c
  BCC_PF=()
  read -r s c <<<"${BCC_PLAN_FACTS[$1]:-0 0}"
  ((c == 0)) || BCC_PF=("${BCC_FACT_POOL[@]:s:c}")
  return 0
}

# The programs whose version a check would read by running them. Programs whose verdict does
# not depend on it are not asked for: a packaged node or curl that loads the OS libbrotlidec
# (C01 judges it) and a packaged browser (the package version is used).
bcc_build_exec_plan() {
  local bin i rc
  BCC_PLAN=()
  declare -gA BCC_PLAN_BIN=() BCC_PLAN_ARG=() BCC_PLAN_PURPOSE=() BCC_PLAN_FACTS=() BCC_PLAN_OK=() BCC_PROBE_OUT=() BCC_PROBE_RC=()
  bcc_c04_candidates
  for bin in ${BCC_C04_CANDS[@]+"${BCC_C04_CANDS[@]}"}; do
    bcc_dpkg_owner "$bin" >/dev/null
    if [[ -n ${BCC_DPKG_CACHE[$bin]:-} ]]; then
      bcc_link_prefetch "$bin"
      rc=${BCC_LINK_RC[$bin]}
      ((rc == 1)) || continue
    fi
    bcc_plan_add "$bin" --version "C04 node"
  done
  bcc_c05_candidates
  for bin in ${BCC_C05_CANDS[@]+"${BCC_C05_CANDS[@]}"}; do
    bcc_plan_add "$bin" --version "C05 bun"
  done
  bcc_c08_candidates
  for bin in ${BCC_C08_CANDS[@]+"${BCC_C08_CANDS[@]}"}; do
    bcc_link_prefetch "$bin"
    ((${BCC_LINK_RC[$bin]} == 1)) || continue
    bcc_plan_add "$bin" -V "C08 curl"
  done
  bcc_c10_candidates
  for bin in ${BCC_C10_CANDS[@]+"${BCC_C10_CANDS[@]}"}; do
    bcc_plan_add "$bin" --version "C10 envoy"
  done
  bcc_c13_candidates
  for i in ${BCC_C13_CANDS[@]+"${!BCC_C13_CANDS[@]}"}; do
    bin=${BCC_C13_CANDS[i]}
    bcc_dpkg_owner "$bin" >/dev/null && continue
    bcc_plan_add "$bin" --version "C13 ${BCC_C13_KINDS[i]}"
  done
  return 0
}

# The plan, numbered, with its facts (for the question, on stderr). Paths come from the
# scanned host and this is the screen the user decides on: each value is kept on its line
# (bcc_line_safe) and control characters are shown as "?" (bcc_text_safe), as in the report.
bcc_print_plan() {
  local i=0 key f
  {
    bcc_msg x_plan_head
    printf '\n\n'
    for key in "${BCC_PLAN[@]}"; do
      i=$((i + 1))
      printf ' %2d. %s %s  (%s)\n' "$i" "$(bcc_line_safe "${BCC_PLAN_BIN[$key]}")" "${BCC_PLAN_ARG[$key]}" \
        "${BCC_PLAN_PURPOSE[$key]}"
      bcc_plan_facts "$key"
      for f in ${BCC_PF[@]+"${BCC_PF[@]}"}; do
        printf '       - %s\n' "$(bcc_line_safe "$f")"
      done
    done
    printf '\n'
  } | bcc_text_safe
}

# Parse an answer: y/yes (all), n/no/empty (none), or numbers and ranges ("1,3", "2-4 6").
# Prints the chosen numbers, one per line; status 1 when the answer is not understood.
bcc_parse_choice() {
  local ans=$1 n=$2 tok a b i
  ans=$(tr '[:upper:]' '[:lower:]' <<<"$ans")
  ans=${ans//,/ }
  case $ans in
    y | yes | all | "全部" | "はい") for ((i = 1; i <= n; i++)); do printf '%d\n' "$i"; done; return 0 ;;
    '' | n | no | none | "いいえ") return 0 ;;
  esac
  for tok in $ans; do
    if [[ $tok =~ ^([0-9]+)-([0-9]+)$ ]]; then
      a=$((10#${BASH_REMATCH[1]})) b=$((10#${BASH_REMATCH[2]}))
    elif [[ $tok =~ ^[0-9]+$ ]]; then
      a=$((10#$tok)) b=$a
    else
      return 1
    fi
    ((a >= 1 && b <= n && a <= b)) || return 1
    for ((i = a; i <= b; i++)); do printf '%d\n' "$i"; done
  done
  return 0
}

# Consent: --no-exec runs nothing, --yes runs all; otherwise ask at the terminal, and without
# one stop and ask for --yes or --no-exec (exit 3). Fills BCC_PLAN_OK.
bcc_exec_consent() {
  local key ans chosen i tries=0
  ((${#BCC_PLAN[@]})) || return 0
  ((BCC_NO_EXEC)) && return 0
  if ((BCC_YES)); then
    for key in "${BCC_PLAN[@]}"; do BCC_PLAN_OK[$key]=1; done
    return 0
  fi
  if [[ ! -t 0 || ! -t 2 ]]; then
    bcc_print_plan >&2
    bcc_die "$(bcc_msg err_need_consent)"
  fi
  bcc_print_plan >&2
  while :; do
    bcc_msg x_prompt >&2
    IFS= read -r ans || ans=""
    if chosen=$(bcc_parse_choice "$ans" "${#BCC_PLAN[@]}"); then
      break
    fi
    tries=$((tries + 1))
    if ((tries >= 3)); then
      chosen=""
      break
    fi
    bcc_msg x_prompt_invalid "${#BCC_PLAN[@]}" >&2
    printf '\n' >&2
  done
  for i in $chosen; do BCC_PLAN_OK[${BCC_PLAN[i - 1]}]=1; done
  return 0
}

# Run the chosen programs, each with its one argument: from "/" (no library or file is looked
# up in your working directory), with an empty environment (NODE_OPTIONS and the like have no
# effect), stdin closed, a time limit, and at most 64 KiB of output kept.
bcc_exec_run() {
  local key bin arg out rc
  for key in ${BCC_PLAN[@]+"${BCC_PLAN[@]}"}; do
    [[ -n ${BCC_PLAN_OK[$key]:-} ]] || continue
    bin=${BCC_PLAN_BIN[$key]}
    arg=${BCC_PLAN_ARG[$key]}
    rc=0
    out=$( (cd / && timeout -k 2 "$BCC_PROBE_TIMEOUT" env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C "$bin" "$arg" </dev/null 2>&1) | head -c 65536) || rc=$?
    BCC_PROBE_OUT[$key]=$out
    BCC_PROBE_RC[$key]=$rc
  done
  return 0
}

# A check asks for the output of BIN ARG. Status: that of the run, 125 when it was not run
# (not asked for, not chosen, or --no-exec).
bcc_probe() {
  local key=$1$'\t'$2
  [[ -n ${BCC_PROBE_RC[$key]+x} ]] || return 125
  printf '%s' "${BCC_PROBE_OUT[$key]}"
  return "${BCC_PROBE_RC[$key]}"
}

# For the report: programs that were asked for but not run are a range not scanned exactly.
bcc_note_exec() {
  local key n=0
  for key in ${BCC_PLAN[@]+"${BCC_PLAN[@]}"}; do
    [[ -n ${BCC_PROBE_RC[$key]+x} ]] || n=$((n + 1))
  done
  ((n == 0)) && return 0
  if ((BCC_NO_EXEC)); then
    bcc_skip "--no-exec" "$(bcc_msg skip_opt_noexec)"
  else
    bcc_skip "exec" "$(bcc_msg skip_exec_declined "$n")"
  fi
}
