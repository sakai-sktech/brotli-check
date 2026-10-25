# shellcheck shell=bash
# C06 Python packages from PyPI (Brotli, brotlicffi) and conda's libbrotlidec,
# C07 Node.js project exposure hints (--projects).

# Directories searched in addition to --roots (system interpreters, per-user tools).
bcc_python_dirs() {
  local h d
  for d in /usr/lib/python3 /usr/lib/python3.* /usr/local/lib/python3.*; do
    [[ -d $d ]] && printf '%s\n' "$d"
  done
  for h in ${BCC_HOMES[@]+"${BCC_HOMES[@]}"}; do
    for d in "$h/.local/lib" "$h/.local/share/mise/installs/python" "$h/.pyenv/versions" \
      "$h/.local/share/uv" "$h/.local/pipx" "$h/.local/share/pipx" "$h/.conda" "$h/miniconda3" \
      "$h/anaconda3" "$h/miniforge3" "$h/.virtualenvs"; do
      [[ -d $d ]] && printf '%s\n' "$d"
    done
  done
}

# Name and Version from a METADATA / PKG-INFO file. Prints "name<TAB>version".
bcc_py_metadata() {
  local f=$1 name ver
  name=$(sed -n 's/^Name: *//p' "$f" | head -n 1 | tr -d '\r')
  ver=$(sed -n 's/^Version: *//p' "$f" | head -n 1 | tr -d '\r')
  [[ -n $name && -n $ver ]] || return 1
  printf '%s\t%s\n' "$name" "$ver"
}

BCC_C06_SEEN_SITES=""

bcc_c06_entry() {
  local p=$1 meta site name ver comp lname owner
  if [[ -d $p ]]; then
    meta=$p/METADATA
    [[ -f $meta ]] || meta=$p/PKG-INFO
  else
    meta=$p # an .egg-info file
  fi
  [[ -f $meta ]] || return 0
  local nv
  nv=$(bcc_py_metadata "$meta") || return 0
  bcc_split_tab "$nv"
  name=${BCC_F[0]}
  ver=${BCC_F[1]}
  lname=$(tr '[:upper:]' '[:lower:]' <<<"$name")
  case $lname in
    brotli) comp=pypi:brotli ;;
    brotlicffi) comp=pypi:brotlicffi ;;
    *) return 0 ;;
  esac
  site=$(dirname -- "$p")
  # Distribution packages (python3-brotli) report the upstream version (1.1.0) even
  # after the distributor's fix; C01 judges them by the package version instead.
  if owner=$(bcc_dpkg_owner "$p"); then
    bcc_add_info C06 "$(bcc_msg i_c06_dpkg "$p" "$owner")"
    bcc_c06_exposure "$site"
    return 0
  fi
  bcc_judge "$comp" '*' pep440 "$ver"
  local next=$BCC_J_NEXT
  [[ $BCC_J_STATUS == VULNERABLE ]] && next=$(bcc_msg n_pip_upgrade "$(printf '%q' "$site")" "$lname" "$BCC_J_FIXED")
  bcc_add_finding C06 "$BCC_J_STATUS" "$name" "$p" "$ver" "$BCC_J_REASON" "$next" "$BCC_J_EVIDENCE" ""
  bcc_c06_exposure "$site"
}

# HTTP libraries in the same environment decode Brotli automatically once Brotli is importable.
bcc_c06_exposure() {
  local site=$1 lib f
  local -a found=()
  case $BCC_C06_SEEN_SITES in *"|$site|"*) return 0 ;; esac
  BCC_C06_SEEN_SITES+="|$site|"
  for lib in urllib3 requests httpx aiohttp scrapy; do
    for f in "$site"/"$lib"-*.dist-info "$site"/"$lib"-*.egg-info; do
      [[ -e $f ]] && { found+=("$lib"); break; }
    done
  done
  ((${#found[@]})) || return 0
  local reason
  reason=$(bcc_msg r_c06_exposure "$(IFS=,; printf '%s' "${found[*]}" | sed 's/,/, /g')")
  case " ${found[*]} " in *" aiohttp "*) reason+=" $(bcc_msg r_c06_aiohttp)" ;; esac
  bcc_add_finding C06 EXPOSURE "python-http-clients" "$site" "" "$reason" "$(bcc_msg n_exposure_hint)" "" ""
}

# conda environments: libbrotlidec as a shared library in <env>/lib, judged by its version.
bcc_c06_conda() {
  local f=$1 base ver series
  [[ $f == */conda-meta/* ]] || return 0
  base=${f##*/}
  [[ $base =~ ^libbrotlidec-([0-9]+\.[0-9]+\.[0-9]+)- ]] || return 0
  ver=${BASH_REMATCH[1]}
  series=${ver%.*}
  bcc_judge brotli "$series" semver "$ver"
  local next=$BCC_J_NEXT
  [[ $BCC_J_STATUS == VULNERABLE ]] && next=$(bcc_msg n_conda_update "$(printf '%q' "$(dirname -- "$(dirname -- "$f")")")")
  bcc_add_finding C06 "$BCC_J_STATUS" "conda:libbrotlidec" "$f" "$ver" "$BCC_J_REASON" "$next" "$BCC_J_EVIDENCE" ""
}

bcc_check_c06() {
  local p
  for p in ${BCC_IDX_PY[@]+"${BCC_IDX_PY[@]}"}; do bcc_c06_entry "$p"; done
  for p in ${BCC_IDX_CONDA[@]+"${BCC_IDX_CONDA[@]}"}; do bcc_c06_conda "$p"; done
}

# C07 (--projects): which installed npm packages would hand attacker data to the decoder.
BCC_C07_INBOUND="body-parser express @fastify/compress koa-body co-body inflation"
BCC_C07_OUTBOUND="undici axios got node-fetch"

# The first "version" key of a package.json (top-level in practice; also works when minified).
bcc_pkg_version() {
  grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$1" 2>/dev/null | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/'
}

bcc_c07_entry() {
  local nm=$1 pkg ver major
  local -a inbound=() outbound=()
  for pkg in $BCC_C07_INBOUND; do
    [[ -f $nm/$pkg/package.json ]] || continue
    ver=$(bcc_pkg_version "$nm/$pkg/package.json")
    major=${ver%%.*}
    case $pkg in
      body-parser) [[ $major == 2 ]] || continue ;;
      express) [[ $major == 5 ]] || continue ;;
    esac
    inbound+=("$pkg@${ver:-?}")
  done
  for pkg in $BCC_C07_OUTBOUND; do
    [[ -f $nm/$pkg/package.json ]] || continue
    outbound+=("$pkg@$(bcc_pkg_version "$nm/$pkg/package.json")")
  done
  ((${#inbound[@]} + ${#outbound[@]})) || return 0
  local reason=""
  ((${#inbound[@]})) && reason+="$(bcc_msg r_c07_inbound "${inbound[*]}") "
  ((${#outbound[@]})) && reason+="$(bcc_msg r_c07_outbound "${outbound[*]}")"
  bcc_add_finding C07 EXPOSURE "npm-project" "$(dirname -- "$nm")" "" "$reason" "$(bcc_msg n_c07)" "" ""
}

bcc_check_c07() {
  # -prune keeps nested node_modules out; npm hoists the packages that matter.
  bcc_find_each bcc_c07_entry ${BCC_ROOTS[@]+"${BCC_ROOTS[@]}"} -- -type d -name node_modules -prune
  bcc_find_status $? "C07"
}
