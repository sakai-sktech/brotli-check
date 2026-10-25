# shellcheck shell=bash
# version.sh - version comparison.
#   Debian versions: dpkg --compare-versions (C01, C14).
#   semver-like (Node.js, Bun, Envoy, Brotli, browsers): numeric dot fields; a pre-release sorts first.
#   PEP 440 subset (PyPI): trailing zeros ignored (1.2.1 == 1.2.1.0); dev < pre < final < post;
#   local versions (+...) ignored.
# Comparison functions print -1, 0, 1, or "?" when a version cannot be parsed.

# Prints the first "N.N[.N...]" found in a string, or nothing.
bcc_version_extract() {
  local re='([0-9]+(\.[0-9]+)+)'
  [[ $1 =~ $re ]] && printf '%s' "${BASH_REMATCH[1]}"
}

# Version from the first line of OUTPUT that matches REGEX (an ERE whose first group is
# the version). Programs may print log lines before the version (Chrome prints a
# "[1026/070739.474907:WARNING:...]" line), so a bare number is never taken.
bcc_version_from_output() {
  local out=$1 re=$2 line
  while IFS= read -r line; do
    if [[ $line =~ $re ]]; then
      printf '%s' "${BASH_REMATCH[1]}"
      return 0
    fi
  done <<<"$out"
  return 1
}

# Compare dot-separated numeric lists (missing fields count as 0).
bcc_numcmp() {
  local -a a=() b=()
  local i n x y
  IFS=. read -r -a a <<<"$1"
  IFS=. read -r -a b <<<"$2"
  n=${#a[@]}
  ((${#b[@]} > n)) && n=${#b[@]}
  for ((i = 0; i < n; i++)); do
    x=${a[i]:-0}
    y=${b[i]:-0}
    x=${x//[!0-9]/}
    y=${y//[!0-9]/}
    x=$((10#${x:-0}))
    y=$((10#${y:-0}))
    if ((x < y)); then
      printf -- -1
      return
    elif ((x > y)); then
      printf 1
      return
    fi
  done
  printf 0
}

bcc_semver_cmp() {
  local re='^v?([0-9]+(\.[0-9]+)*)(-([0-9A-Za-z.-]+))?' ra pa rb pb c
  [[ $1 =~ $re ]] || { printf '?'; return; }
  ra=${BASH_REMATCH[1]}
  pa=${BASH_REMATCH[4]}
  [[ $2 =~ $re ]] || { printf '?'; return; }
  rb=${BASH_REMATCH[1]}
  pb=${BASH_REMATCH[4]}
  c=$(bcc_numcmp "$ra" "$rb")
  if [[ $c != 0 ]]; then
    printf '%s' "$c"
  elif [[ -n $pa && -z $pb ]]; then
    printf -- -1
  elif [[ -z $pa && -n $pb ]]; then
    printf 1
  else
    printf 0
  fi
}

bcc_pep440_suffix_rank() {
  case $1 in
    '') printf 2 ;;
    *dev*) printf 0 ;;
    *post* | *rev* | -[0-9]* | .r[0-9]* | r[0-9]*) printf 3 ;;
    *) printf 1 ;; # a, b, rc, c, alpha, beta, pre, preview
  esac
}

bcc_pep440_cmp() {
  local re='^([0-9]+(\.[0-9]+)*)(.*)$' a b ra sa rb sb c ka kb
  a=$(tr '[:upper:]' '[:lower:]' <<<"$1")
  b=$(tr '[:upper:]' '[:lower:]' <<<"$2")
  a=${a#v}
  b=${b#v}
  a=${a%%+*}
  b=${b%%+*}
  [[ $a =~ $re ]] || { printf '?'; return; }
  ra=${BASH_REMATCH[1]}
  sa=${BASH_REMATCH[3]}
  [[ $b =~ $re ]] || { printf '?'; return; }
  rb=${BASH_REMATCH[1]}
  sb=${BASH_REMATCH[3]}
  c=$(bcc_numcmp "$ra" "$rb")
  if [[ $c != 0 ]]; then
    printf '%s' "$c"
    return
  fi
  ka=$(bcc_pep440_suffix_rank "$sa")
  kb=$(bcc_pep440_suffix_rank "$sb")
  if ((ka < kb)); then
    printf -- -1
  elif ((ka > kb)); then
    printf 1
  else
    printf 0
  fi
}

# bcc_version_ge KIND A B  (KIND: deb | semver | pep440)
# Status: 0 when A >= B, 1 when A < B, 2 when the comparison is not possible.
bcc_version_ge() {
  local kind=$1 a=$2 b=$3 c
  case $kind in
    deb)
      bcc_have dpkg || return 2
      dpkg --validate-version "$a" >/dev/null 2>&1 || return 2
      if dpkg --compare-versions "$a" ge "$b" 2>/dev/null; then return 0; else return 1; fi
      ;;
    semver) c=$(bcc_semver_cmp "$a" "$b") ;;
    pep440) c=$(bcc_pep440_cmp "$a" "$b") ;;
    *) bcc_die "internal error: unknown version kind '$kind'" ;;
  esac
  case $c in
    '?') return 2 ;;
    -1) return 1 ;;
    *) return 0 ;;
  esac
}
