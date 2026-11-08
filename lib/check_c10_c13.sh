# shellcheck shell=bash
# C10 Envoy, C11 compression-only servers (information), C12 snap/flatpak, C13 browsers.

bcc_c10_candidates() {
  [[ -z ${BCC_C10_DONE:-} ]] || return 0
  local h
  local -a pats=(/usr/local/bin/envoy /usr/bin/envoy '/opt/*/bin/envoy')
  for h in ${BCC_HOMES[@]+"${BCC_HOMES[@]}"}; do pats+=("$h/.func-e/versions/*/bin/envoy"); done
  bcc_candidates C10 envoy < <(printf '%s\n' "${pats[@]}" | bcc_glob_records; bcc_index_list ${BCC_IDX_ENVOY[@]+"${BCC_IDX_ENVOY[@]}"})
  BCC_C10_CANDS=(${BCC_LIST[@]+"${BCC_LIST[@]}"})
  BCC_C10_DONE=1
}

bcc_check_c10() {
  local bin out ver series next
  bcc_c10_candidates
  for bin in ${BCC_C10_CANDS[@]+"${BCC_C10_CANDS[@]}"}; do
    BCC_JUDGED[$bin]=1
    ver=""
    # "envoy  version: <sha>/1.38.6/Clean/RELEASE/BoringSSL"
    out=$(bcc_probe "$bin" --version) && ver=$(bcc_version_from_output "$out" 'version: [0-9a-f]+/([0-9]+\.[0-9]+\.[0-9]+)/') || ver=""
    if [[ -z $ver ]]; then
      bcc_report_by_strings C10 envoy "$bin" "" "$(bcc_msg r_version_unknown)"
      continue
    fi
    series=$(cut -d. -f1-2 <<<"$ver")
    bcc_judge envoy "$series" semver "$ver" "$(bcc_msg b_exec "${bin##*/}")"
    next=$BCC_J_NEXT
    if [[ $BCC_J_STATUS == VULNERABLE ]]; then
      if [[ $BCC_J_FIXED == - ]]; then
        next=$(bcc_msg n_envoy_move_line)
      else
        next=$(bcc_msg n_update_runtime "$BCC_J_FIXED")
      fi
    fi
    bcc_add_finding C10 "$BCC_J_STATUS" envoy "$bin" "$ver" "$BCC_J_REASON $(bcc_msg r_c10_decompressor)" "$next" "$BCC_J_EVIDENCE" ""
  done
  bcc_report_other_names C10
  if [[ -n $BCC_ENVOY_CONFIG ]]; then
    # Named on the command line: a name that is not a file is a failure (a mistyped name must
    # not pass as a clean run); a file this user may not read, the choice of not being root.
    if [[ ! -e $BCC_ENVOY_CONFIG ]]; then
      bcc_skip failed "$BCC_ENVOY_CONFIG" "$(bcc_msg skip_missing)"
    elif [[ ! -f $BCC_ENVOY_CONFIG ]]; then
      bcc_skip failed "$BCC_ENVOY_CONFIG" "$(bcc_msg skip_not_file)"
    elif [[ ! -r $BCC_ENVOY_CONFIG ]]; then
      bcc_skip "$(bcc_denied_kind)" "$BCC_ENVOY_CONFIG" "$(bcc_msg skip_unreadable)"
    else
      local conf rc=0 size
      conf=$(bcc_read_file "$BCC_ENVOY_CONFIG" 67108864) || rc=$?
      size=$(stat -L -c %s -- "$BCC_ENVOY_CONFIG" 2>/dev/null) || size=0
      if grep -qE 'envoy\.compression\.brotli\.decompressor|compression\.brotli\.decompressor\.v3' <<<"$conf"; then
        bcc_add_finding C10 EXPOSURE envoy-config "$BCC_ENVOY_CONFIG" "" "$(bcc_msg r_c10_config_br)" "$(bcc_msg n_exposure_hint)" "" ""
      elif ((rc != 0)) || [[ ! $size =~ ^[0-9]+$ ]] || ((size > 67108864)); then
        # Not found in what was read, but not all of it was read: no claim of absence.
        bcc_skip failed "$BCC_ENVOY_CONFIG" "$(bcc_msg skip_incomplete 64)"
      else
        bcc_add_info C10 "$(bcc_msg i_c10_config_none "$BCC_ENVOY_CONFIG")"
      fi
    fi
  fi
  bcc_add_info C10 "$(bcc_msg i_c10_istio)"
}

# C11: decide from the files, not from the product name: a module or binary either
# carries decoder code, loads libbrotlidec, or neither. "Neither" rests on the absence of
# markers, and a stripped static copy without BrotliDecoderErrorString has none, so it is
# NOT_APPLICABLE only where something else speaks for the build: a distribution package whose
# sources were read (bcc_c11_package_status), or a Go program that does not name the cgo binding
# (Go's Brotli is a separate implementation). Any other package, or anything built by hand, is
# UNKNOWN (docs/design.md 10.9.5 and 10.17).

# Binary packages from the source packages nginx, libnginx-mod-http-brotli, apache2 and haproxy,
# whose sources in Debian 12, 13 and Ubuntu 22.04, 24.04, 26.04 hold no Brotli decoder.
BCC_C11_CHECKED_PACKAGES=" nginx nginx-core nginx-full nginx-light nginx-extras libnginx-mod-http-brotli-filter libnginx-mod-http-brotli-static apache2-bin haproxy "
# A distribution's version: upstream, then only the revision forms Debian and Ubuntu use
# (1.22.1-9+deb12u10, 2.4.68-1~deb12u1, 1.24.0-2ubuntu7.19, 1.0.0~rc-5build1, 2.8.30-0ubuntu0.24.04.1,
# with ~bpo12+1, +esm1, ~22.04.1). A suffix of anyone else's (+acme1, ~noble, +deb.sury.org+1) fails,
# and so does vendor text in the upstream part (1.26.3~acme1-1, 1.26.3acme-1).
BCC_C11_DISTRO_VERSION='^([0-9]+:)?[0-9]+(\.[0-9]+)*(~(rc|alpha|beta|pre|dev)[0-9]*)?(\+(dfsg|ds)[0-9]*)?-[0-9]+(\.[0-9]+)*((build|ubuntu)[0-9]+(\.[0-9]+)*)*([~+](deb[0-9]+u[0-9]+|bpo[0-9]+\+[0-9]+|esm[0-9]+|[0-9][0-9]\.[0-9][0-9](\.[0-9]+)*))*$'

# Does OWNER (bcc_dpkg_owner's words) speak for FILE? Status: 0 a checked distribution package and
# the file as it installed it; 1 not such a package; 2 the file differs from what it installed;
# 3 the comparison failed. dpkg records are not a security boundary (root could write anything):
# this keeps an honest in-house or third-party build from being taken for the distribution's.
# dpkg --verify exits 0 with differences too; they are lines ending in the path.
bcc_c11_package_status() {
  local owner=$1 f=$2 pkg ver maint out sums
  while IFS= read -r pkg; do
    case $BCC_C11_CHECKED_PACKAGES in
      *" ${pkg%%:*} "*) ;;
      *) return 1 ;;
    esac
    # shellcheck disable=SC2016  # dpkg-query format
    IFS=$'\t' read -r ver maint < <(bcc_sys dpkg-query -W -f '${Version}\t${Maintainer}\n' "$pkg") || return 1
    [[ $ver =~ $BCC_C11_DISTRO_VERSION ]] || return 1
    case $maint in
      *'<ubuntu-devel-discuss@lists.ubuntu.com>' | *'@lists.debian.org>' | *'@alioth-lists.debian.net>' | *'@lists.alioth.debian.org>' | *'@tracker.debian.org>') ;;
      *) return 1 ;;
    esac
    out=$(bcc_sys dpkg --verify "$pkg") || return 3
    [[ $'\n'$out$'\n' != *" $f"$'\n'* ]] || return 2
    # dpkg --verify is silent about a file it has no checksum for, so its silence counts only
    # when the package does record one for this file.
    sums=$(bcc_sys dpkg-query --control-show "$pkg" md5sums) || return 4
    [[ $'\n'$sums$'\n' == *"  ${f#/}"$'\n'* ]] || return 4
  done <<<"${owner//, /$'\n'}"
  return 0
}

bcc_c11_file() {
  local prod=$1 f=$2 rc res owner pkg_st detail reason next
  BCC_JUDGED[$f]=1
  res=$(bcc_brotli_scan "$f")
  bcc_split_tab "$res"
  if [[ ${BCC_F[3]} == 1 ]] && ! bcc_needed_has_brotlidec "$(bcc_elf_needed "$f" 2>/dev/null)"; then
    bcc_report_by_strings C11 "$prod" "$f" "" "$(bcc_msg r_c09_vendored)"
    return
  fi
  local go=${BCC_F[4]} cbrotli=${BCC_F[5]} read_st=${BCC_F[6]}
  rc=0
  bcc_links_brotlidec "$f" || rc=$?
  if ((rc == 0)); then
    bcc_report_linked_libs C11 "$prod" "$f"
    bcc_report_own_copy C11 "$prod" "$f"
  elif [[ $read_st != complete ]]; then
    # No markers were seen, but not all of the file was read: absence is not shown.
    bcc_add_finding C11 UNKNOWN "$prod" "$f" "" "$(bcc_msg r_heur_incomplete "$BCC_MAX_ELF_MB")" "$(bcc_msg n_check_vendor)" "" ""
    bcc_note_incomplete "$f"
  elif ((rc == 1)); then
    pkg_st=1
    if owner=$(bcc_dpkg_owner "$f"); then
      pkg_st=0
      bcc_c11_package_status "$owner" "$f" || pkg_st=$?
    else
      owner=""
    fi
    if [[ -n $owner ]] && ((pkg_st == 0)); then
      bcc_add_finding C11 NOT_APPLICABLE "$prod" "$f" "" "$(bcc_msg r_c11_no_decoder_pkg "$owner")" "$(bcc_msg n_c11_other)" "" ""
    elif [[ $go == 1 && $cbrotli != 1 ]]; then
      bcc_add_finding C11 NOT_APPLICABLE "$prod" "$f" "" "$(bcc_msg r_c11_go)" "$(bcc_msg n_c11_other)" "" ""
    elif [[ -n $owner ]]; then
      # What the decision rested on, for the reader (a "diversion by ..." owner has none).
      # shellcheck disable=SC2016  # dpkg-query format
      detail=$(bcc_sys dpkg-query -W -f '${Version}, ${Maintainer}' "${owner%%,*}") || detail=""
      [[ -z $detail ]] || owner+=" ($detail)"
      next=$(bcc_msg n_c11_package)
      case $pkg_st in
        2)
          reason=$(bcc_msg r_c11_pkg_changed "$owner")
          next=$(bcc_msg n_c11_custom)
          ;;
        3) reason=$(bcc_msg r_c11_pkg_not_compared "$owner") ;;
        4) reason=$(bcc_msg r_c11_pkg_no_sum "$owner") ;;
        *) reason=$(bcc_msg r_c11_pkg_unchecked "$owner") ;;
      esac
      bcc_add_finding C11 UNKNOWN "$prod" "$f" "" "$reason" "$next" "" ""
    else
      bcc_add_finding C11 UNKNOWN "$prod" "$f" "" "$(bcc_msg r_c11_no_marker_custom)" "$(bcc_msg n_c11_custom)" "" ""
    fi
  else
    bcc_add_finding C11 UNKNOWN "$prod" "$f" "" "$(bcc_msg r_link_undetermined)" "$(bcc_msg n_install_binutils)" "" ""
  fi
}

bcc_check_c11() {
  local prod names bin m
  local -a cands=()
  for prod in nginx apache2:apache2/httpd haproxy traefik caddy; do
    names=${prod#*:}
    prod=${prod%%:*}
    names=${names//\//|}
    bcc_candidates C11 "$names" < <(printf '%s\n' "/usr/sbin/${names%%|*}" "/usr/local/sbin/${names%%|*}" "/usr/local/bin/${names%%|*}" | bcc_glob_records)
    cands=(${BCC_LIST[@]+"${BCC_LIST[@]}"})
    for bin in ${cands[@]+"${cands[@]}"}; do
      bcc_c11_file "$prod" "$bin"
    done
  done
  bcc_report_other_names C11
  for m in /usr/lib/nginx/modules/*brotli*.so /usr/lib/apache2/modules/mod_brotli.so /usr/lib64/httpd/modules/mod_brotli.so; do
    [[ -f $m ]] && bcc_c11_file "${m##*/}" "$m"
  done
}

# Electron/Chromium-based application trees bundle their own Brotli.
bcc_is_electron_tree() {
  local dir
  # /snap/NAME/current is a symlink, and find -P does not descend into a starting point that is one.
  dir=$(bcc_realpath "$1") || return 1
  [[ -d $dir ]] || return 1
  find -P "$dir" -maxdepth 4 \( -name 'resources.pak' -o -name 'app.asar' -o -name 'chrome_100_percent.pak' -o -name 'libnode.so' \) -print -quit 2>/dev/null | grep -q .
}

bcc_check_c12() {
  local line name ver rest series
  local out rc
  if bcc_have snap; then
    rc=0
    out=$(bcc_sys snap list) || rc=$?
    # (With no snaps installed, snap list says so on stderr and exits 0.)
    ((rc == 0)) || bcc_skip failed "C12 snap" "$(bcc_msg skip_cmd_failed "snap list" "$rc")"
    while IFS= read -r line; do
      read -r name ver rest <<<"$line"
      [[ -n $name && $name != Name ]] || continue
      case $name in
        node)
          series=${ver%%.*}
          bcc_judge node "${series#v}" semver "$ver" "$(bcc_msg b_snap)"
          bcc_add_finding C12 "$BCC_J_STATUS" "snap:node" "/snap/node" "$ver" "$BCC_J_REASON" \
            "$([[ $BCC_J_STATUS == VULNERABLE ]] && bcc_msg n_snap_refresh node || printf '%s' "$BCC_J_NEXT")" "$BCC_J_EVIDENCE" ""
          ;;
        chromium | firefox)
          bcc_browser_judge "$name" "$ver" "$(bcc_msg b_snap)"
          bcc_add_finding C12 "$BCC_J_STATUS" "snap:$name" "/snap/$name" "$ver" "$BCC_J_REASON" \
            "$([[ $BCC_J_STATUS == VULNERABLE ]] && bcc_msg n_snap_refresh "$name" || printf '%s' "$BCC_J_NEXT")" "$BCC_J_EVIDENCE" ""
          ;;
        *)
          if bcc_is_electron_tree "/snap/$name/current"; then
            bcc_add_finding C12 VENDORED_COPY "snap:$name" "/snap/$name" "$ver" "$(bcc_msg r_c12_electron)" \
              "$(bcc_msg n_snap_refresh "$name") $(bcc_msg n_check_vendor)" "" ""
          fi
          ;;
      esac
    done <<<"$out"
  fi
  if bcc_have flatpak; then
    local id dir inst
    rc=0
    out=$(bcc_sys flatpak list --app --columns=application,version,installation) || rc=$?
    ((rc == 0)) || bcc_skip failed "C12 flatpak" "$(bcc_msg skip_cmd_failed "flatpak list" "$rc")"
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      bcc_split_tab "$line"
      id=${BCC_F[0]}
      ver=${BCC_F[1]:-}
      inst=${BCC_F[2]:-}
      [[ -n $id ]] || continue
      case $id in
        org.chromium.Chromium | com.google.Chrome) bcc_browser_judge chromium "$ver" "$(bcc_msg b_flatpak)" ;;
        org.mozilla.firefox) bcc_browser_judge firefox "$ver" "$(bcc_msg b_flatpak)" ;;
        *)
          dir=/var/lib/flatpak/app/$id/current/active/files
          [[ $inst == user ]] && dir=""
          if [[ -n $dir ]] && bcc_is_electron_tree "$dir"; then
            BCC_J_STATUS=VENDORED_COPY
            BCC_J_REASON=$(bcc_msg r_c12_electron)
            BCC_J_NEXT=$(bcc_msg n_check_vendor)
            BCC_J_EVIDENCE=""
          else
            continue
          fi
          ;;
      esac
      bcc_add_finding C12 "$BCC_J_STATUS" "flatpak:$id" "$inst" "$ver" "$BCC_J_REASON" "${BCC_J_NEXT:-$(bcc_msg n_flatpak_update)}" "$BCC_J_EVIDENCE" ""
    done < <(tr -s ' ' <<<"$out" | sed 's/\t\{1,\}/\t/g')
    # Runtimes (org.freedesktop.Platform, org.gnome.Platform, ...) ship their own libbrotlidec.
    local f
    while IFS= read -r -d '' f; do
      bcc_c12_runtime_lib "$f"
    done < <(bcc_c12_runtime_libs /var/lib/flatpak/runtime)
  fi
}

# The same names as the index (a real libbrotlidec.so is a copy too), but not the debug symbols
# of a .Debug runtime, which hold no decoder.
bcc_c12_runtime_libs() {
  find -P "$1" -maxdepth 8 -type f \( -name 'libbrotlidec*.so*' -o -name 'libbrotlidec*.a' \) ! -name '*.debug' -print0 2>/dev/null
}

bcc_c12_runtime_lib() {
  local f=$1 ver series rt
  rt=${f#/var/lib/flatpak/runtime/}
  rt=${rt%%/*}
  if [[ ! ${f##*/} =~ \.so\.([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    # A real file named libbrotlidec.so.1 is still a copy; only the strings can speak for it.
    bcc_report_by_strings C12 "flatpak-runtime:$rt" "$f" "" "$(bcc_msg r_c09_lib_noversion)"
    return 0
  fi
  ver=${BASH_REMATCH[1]}
  series=${ver%.*}
  bcc_judge brotli "$series" semver "$ver" "$(bcc_msg b_filename)"
  bcc_crosscheck_fixed "$f"
  bcc_add_finding C12 "$BCC_J_STATUS" "flatpak-runtime:$rt" "$f" "$ver" "$BCC_J_REASON" \
    "$(bcc_judge_advises_update && bcc_msg n_flatpak_update || printf '%s' "$BCC_J_NEXT")" "$BCC_J_EVIDENCE" ""
}

# bcc_browser_judge chromium|firefox VERSION BASIS  (sets BCC_J_*; BASIS as for bcc_judge)
# Firefox ESR is recognized by "esr" in the version string. Firefox Nightly and Beta
# (150.0a1, 150.0b3, Debian's 150.0~b3) are pre-releases: 150.0a1 is not 150.0. Chromium
# numbers its channels with plain four-part versions; a Debian-style "~" suffix
# (148.0.7778.0~rc1) is a pre-release all the same.
bcc_browser_judge() {
  local kind=$1 raw=$2 basis=${3:-} ver major build rest
  ver=$(bcc_version_extract "$raw")
  if [[ -z $ver ]]; then
    BCC_J_STATUS=UNKNOWN
    BCC_J_REASON=$(bcc_msg r_version_unparsable "$raw")
    BCC_J_NEXT=$(bcc_msg n_check_vendor)
    BCC_J_EVIDENCE=""
    return
  fi
  major=${ver%%.*}
  case $kind in
    chromium)
      if [[ ! $ver =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        BCC_J_STATUS=UNKNOWN
        BCC_J_REASON=$(bcc_msg r_version_unparsable "$raw")
        BCC_J_NEXT=$(bcc_msg n_check_vendor)
        BCC_J_EVIDENCE=""
        return
      fi
      rest=${raw#*"$ver"}
      if [[ $rest =~ ^~([0-9A-Za-z.]+) ]]; then
        bcc_judge chromium '*' semver "$ver-${BASH_REMATCH[1]}" "$basis"
      else
        bcc_judge chromium '*' semver "$ver" "$basis"
      fi
      # 148 builds before branch 7778 predate the Brotli roll.
      build=$(cut -d. -f3 <<<"$ver")
      if [[ $major == 148 && -n $build ]] && ((build < 7778)); then
        BCC_J_STATUS=UNKNOWN
        BCC_J_REASON=$(bcc_msg r_c13_148_early)
        BCC_J_NEXT=$(bcc_msg n_update_browser)
      fi
      ;;
    firefox)
      rest=${raw#*"$ver"}
      if [[ $rest =~ ^([ab][0-9]+) || $rest =~ ^~([0-9A-Za-z.]+) ]]; then
        ver+="-${BASH_REMATCH[1]}"
      fi
      if [[ $raw == *esr* ]]; then
        bcc_judge firefox-esr "$major" semver "$ver" "$basis"
      else
        bcc_judge firefox '*' semver "$ver" "$basis"
      fi
      ;;
  esac
  [[ $BCC_J_STATUS == VULNERABLE ]] && BCC_J_NEXT=$(bcc_msg n_update_browser)
  return 0
}

# Browser executables (BCC_C13_CANDS, with their kind in BCC_C13_KINDS). Computed once.
bcc_c13_candidates() {
  [[ -z ${BCC_C13_DONE:-} ]] || return 0
  local spec kind names x
  BCC_C13_CANDS=() BCC_C13_KINDS=()
  for spec in \
    "chromium:chromium|chromium-browser:/usr/lib/chromium/chromium /usr/lib/chromium-browser/chromium-browser" \
    "chromium:chrome:/opt/google/chrome/chrome" \
    "firefox:firefox|firefox-esr:/usr/lib/firefox/firefox /usr/lib/firefox-esr/firefox-esr /opt/firefox/firefox"; do
    kind=${spec%%:*}
    names=${spec#*:}
    names=${names%%:*}
    bcc_candidates C13 "$names" < <(tr ' ' '\n' <<<"${spec##*:}" | bcc_glob_records)
    for x in ${BCC_LIST[@]+"${BCC_LIST[@]}"}; do
      BCC_C13_CANDS+=("$x")
      BCC_C13_KINDS+=("$kind")
    done
  done
  BCC_C13_DONE=1
}

bcc_check_c13() {
  local i kind bin out ver owner ini method basis
  bcc_c13_candidates
  for i in ${BCC_C13_CANDS[@]+"${!BCC_C13_CANDS[@]}"}; do
      bin=${BCC_C13_CANDS[i]}
      kind=${BCC_C13_KINDS[i]}
      BCC_JUDGED[$bin]=1
      ver="" method=exec owner=""
      if out=$(bcc_probe "$bin" --version); then
        if [[ $kind == chromium ]]; then
          ver=$(bcc_version_from_output "$out" 'Chrom[a-z]* ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(~[0-9A-Za-z.]+)?)') || ver=""
        else
          ver=$(bcc_version_from_output "$out" 'Firefox ([0-9]+\.[0-9]+(\.[0-9]+)*([ab][0-9]+|esr)?)') || ver=""
        fi
      fi
      if [[ -z $ver && $kind == firefox ]] && ini=$(bcc_read_file "$(dirname -- "$bin")/application.ini" 65536); then
        ver=$(sed -n 's/^Version=//p' <<<"$ini" | head -n 1 | tr -d '\r')
        [[ -n $ver && $bin == *esr* ]] && ver+="esr"
        method=ini
      fi
      # Without running it, a packaged browser's version is the package version.
      if [[ -z $ver ]] && owner=$(bcc_dpkg_owner "$bin"); then
        # shellcheck disable=SC2016  # dpkg-query format
        ver=$(bcc_sys dpkg-query -W -f '${Version}' "${owner%%,*}")
        ver=${ver%%-*}
        method=package
      fi
      if [[ -z $(bcc_version_extract "$ver") ]]; then
        bcc_report_by_strings C13 "${bin##*/}" "$bin" "" "$(bcc_msg r_version_unknown)"
        continue
      fi
      basis=$(bcc_method_basis "$method" "$bin" "${owner%%,*}")
      bcc_browser_judge "$kind" "$ver" "$basis"
      # application.ini is a file next to the browser: its version is confirmed against the
      # decoder (Firefox carries it in libxul.so).
      if [[ $method == ini ]]; then
        if [[ -f $(dirname -- "$bin")/libxul.so ]]; then
          bcc_crosscheck_fixed "$(dirname -- "$bin")/libxul.so" named
        else
          bcc_crosscheck_fixed "$bin"
        fi
      fi
      bcc_add_finding C13 "$BCC_J_STATUS" "${bin##*/}" "$bin" "$ver" "$BCC_J_REASON" "$BCC_J_NEXT" \
        "$(bcc_msg e_version_method "$method"); $BCC_J_EVIDENCE" ""
  done
  bcc_report_other_names C13
  bcc_add_info C13 "$(bcc_msg i_c13_electron)"
}
