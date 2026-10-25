# shellcheck shell=bash
# index.sh - one walk over the search roots collects everything that is found by name:
# Python metadata, conda records, libbrotlidec files, and node/bun/envoy executables.
# Checks then read the index instead of walking the file system again.

# Package-manager caches hold unpacked downloads, not installed software.
bcc_is_pkg_cache() {
  case $1 in
    */.cache/uv/* | */.cache/pip/* | */.cache/pypoetry/* | */.npm/_cacache/* | */.cache/yarn/*) return 0 ;;
  esac
  return 1
}

bcc_index_entry() {
  local p=$1 base=${1##*/}
  [[ -z ${BCC_IDX_SEEN[$p]:-} ]] || return 0
  BCC_IDX_SEEN[$p]=1
  if bcc_is_pkg_cache "$p"; then
    BCC_IDX_CACHED=$((BCC_IDX_CACHED + 1))
    return 0
  fi
  case $base in
    [Bb][Rr][Oo][Tt][Ll][Ii]-*.dist-info | [Bb][Rr][Oo][Tt][Ll][Ii]-*.egg-info | \
      [Bb][Rr][Oo][Tt][Ll][Ii][Cc][Ff][Ff][Ii]-*.dist-info | [Bb][Rr][Oo][Tt][Ll][Ii][Cc][Ff][Ff][Ii]-*.egg-info)
      BCC_IDX_PY+=("$p")
      ;;
    libbrotlidec-[0-9]*.json) BCC_IDX_CONDA+=("$p") ;;
    libbrotlidec*) BCC_IDX_LIB+=("$p") ;;
    node | nodejs) BCC_IDX_NODE+=("$p") ;;
    bun) BCC_IDX_BUN+=("$p") ;;
    envoy) BCC_IDX_ENVOY+=("$p") ;;
  esac
}

bcc_build_index() {
  BCC_IDX_PY=() BCC_IDX_CONDA=() BCC_IDX_LIB=() BCC_IDX_NODE=() BCC_IDX_BUN=() BCC_IDX_ENVOY=()
  BCC_IDX_CACHED=0
  declare -gA BCC_IDX_SEEN=()
  local d
  local -a extra=()
  mapfile -t extra < <(bcc_python_dirs)
  for d in /usr/lib /usr/lib64 /lib64; do [[ -d $d && ! -L $d ]] && extra+=("$d"); done
  bcc_find_each bcc_index_entry ${BCC_ROOTS[@]+"${BCC_ROOTS[@]}"} ${extra[@]+"${extra[@]}"} -- \
    \( -iname 'brotli-*.dist-info' -o -iname 'brotli-*.egg-info' -o -iname 'brotlicffi-*.dist-info' \
    -o -iname 'brotlicffi-*.egg-info' \
    -o \( -path '*/conda-meta/*' -name 'libbrotlidec-[0-9]*.json' \) \
    -o \( -type f \( -name 'libbrotlidec*.so*' -o -name 'libbrotlidec*.a' \) \) \
    -o \( -type f -perm -u=x \( -name node -o -name nodejs -o -name bun -o -name envoy \) \) \)
  bcc_find_status $? "$(IFS=,; printf '%s' "${BCC_ROOTS[*]:-}")"
  ((BCC_IDX_CACHED == 0)) || bcc_add_info C09 "$(bcc_msg i_pkg_cached "$BCC_IDX_CACHED")"
  return 0
}

# Print the given paths with glob characters escaped, so that bcc_candidates
# (which expands patterns) takes them literally. Usage: bcc_index_list PATH...
bcc_index_list() {
  local p
  for p in "$@"; do
    p=${p//\\/\\\\}
    p=${p//\*/\\*}
    p=${p//\?/\\?}
    p=${p//\[/\\[}
    printf '%s\n' "$p"
  done
}
