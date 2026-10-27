# shellcheck shell=bash
# C10 Envoy, C11 compression-only servers (information), C12 snap/flatpak, C13 browsers.

bcc_c10_candidates() {
  [[ -z ${BCC_C10_DONE:-} ]] || return 0
  local h
  local -a pats=(/usr/local/bin/envoy /usr/bin/envoy '/opt/*/bin/envoy')
  for h in ${BCC_HOMES[@]+"${BCC_HOMES[@]}"}; do pats+=("$h/.func-e/versions/*/bin/envoy"); done
  bcc_collect0 < <({ printf '%s\n' "${pats[@]}" | bcc_glob_records; bcc_index_list ${BCC_IDX_ENVOY[@]+"${BCC_IDX_ENVOY[@]}"}; } | bcc_candidates envoy)
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
    bcc_judge envoy "$series" semver "$ver"
    next=$BCC_J_NEXT
    [[ $BCC_J_STATUS == VULNERABLE ]] && next=$(bcc_msg n_update_runtime "$BCC_J_FIXED")
    bcc_add_finding C10 "$BCC_J_STATUS" envoy "$bin" "$ver" "$BCC_J_REASON $(bcc_msg r_c10_decompressor)" "$next" "$BCC_J_EVIDENCE" ""
  done
  if [[ -n $BCC_ENVOY_CONFIG ]]; then
    if [[ ! -f $BCC_ENVOY_CONFIG || ! -r $BCC_ENVOY_CONFIG ]]; then
      bcc_skip "$BCC_ENVOY_CONFIG" "$(bcc_msg skip_unreadable)"
    else
      local conf rc=0 size
      conf=$(bcc_read_file "$BCC_ENVOY_CONFIG" 67108864) || rc=$?
      size=$(stat -L -c %s -- "$BCC_ENVOY_CONFIG" 2>/dev/null) || size=0
      if grep -qE 'envoy\.compression\.brotli\.decompressor|compression\.brotli\.decompressor\.v3' <<<"$conf"; then
        bcc_add_finding C10 EXPOSURE envoy-config "$BCC_ENVOY_CONFIG" "" "$(bcc_msg r_c10_config_br)" "$(bcc_msg n_exposure_hint)" "" ""
      elif ((rc != 0)) || [[ ! $size =~ ^[0-9]+$ ]] || ((size > 67108864)); then
        # Not found in what was read, but not all of it was read: no claim of absence.
        bcc_skip "$BCC_ENVOY_CONFIG" "$(bcc_msg skip_incomplete 64)"
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
# NOT_APPLICABLE only where the build is known: a file from a package (whose build is
# public), or a Go program that does not name the cgo binding (Go's Brotli is a separate
# implementation). Anything else built by hand is UNKNOWN (docs/design.md, Codex round 4).
bcc_c11_file() {
  local prod=$1 f=$2 link rc res owner
  BCC_JUDGED[$f]=1
  res=$(bcc_brotli_scan "$f")
  bcc_split_tab "$res"
  if [[ ${BCC_F[3]} == 1 ]] && ! bcc_elf_needed "$f" 2>/dev/null | grep -q '^libbrotlidec'; then
    bcc_report_by_strings C11 "$prod" "$f" "" "$(bcc_msg r_c09_vendored)"
    return
  fi
  local go=${BCC_F[4]} cbrotli=${BCC_F[5]} read_st=${BCC_F[6]}
  rc=0
  link=$(bcc_links_brotlidec "$f") || rc=$?
  if ((rc == 0)); then
    bcc_split_tab "$link"
    bcc_report_linked_lib C11 "$prod" "$f" "${BCC_F[0]}" "${BCC_F[1]}"
  elif [[ $read_st != complete ]]; then
    # No markers were seen, but not all of the file was read: absence is not shown.
    bcc_add_finding C11 UNKNOWN "$prod" "$f" "" "$(bcc_msg r_heur_incomplete "$BCC_MAX_ELF_MB")" "$(bcc_msg n_check_vendor)" "" ""
    bcc_note_incomplete "$f"
  elif ((rc == 1)); then
    if owner=$(bcc_dpkg_owner "$f"); then
      bcc_add_finding C11 NOT_APPLICABLE "$prod" "$f" "" "$(bcc_msg r_c11_no_decoder_pkg "$owner")" "$(bcc_msg n_c11_other)" "" ""
    elif [[ $go == 1 && $cbrotli != 1 ]]; then
      bcc_add_finding C11 NOT_APPLICABLE "$prod" "$f" "" "$(bcc_msg r_c11_go)" "$(bcc_msg n_c11_other)" "" ""
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
    bcc_collect0 < <(printf '%s\n' "/usr/sbin/${names%%|*}" "/usr/local/sbin/${names%%|*}" "/usr/local/bin/${names%%|*}" | bcc_glob_records | bcc_candidates "$names")
    cands=(${BCC_LIST[@]+"${BCC_LIST[@]}"})
    for bin in ${cands[@]+"${cands[@]}"}; do
      bcc_c11_file "$prod" "$bin"
    done
  done
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
    ((rc == 0)) || bcc_skip "C12 snap" "$(bcc_msg skip_cmd_failed "snap list" "$rc")"
    while IFS= read -r line; do
      read -r name ver rest <<<"$line"
      [[ -n $name && $name != Name ]] || continue
      case $name in
        node)
          series=${ver%%.*}
          bcc_judge node "${series#v}" semver "$ver"
          bcc_add_finding C12 "$BCC_J_STATUS" "snap:node" "/snap/node" "$ver" "$BCC_J_REASON" \
            "$([[ $BCC_J_STATUS == VULNERABLE ]] && bcc_msg n_snap_refresh node || printf '%s' "$BCC_J_NEXT")" "$BCC_J_EVIDENCE" ""
          ;;
        chromium | firefox)
          bcc_browser_judge "$name" "$ver"
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
    ((rc == 0)) || bcc_skip "C12 flatpak" "$(bcc_msg skip_cmd_failed "flatpak list" "$rc")"
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      bcc_split_tab "$line"
      id=${BCC_F[0]}
      ver=${BCC_F[1]:-}
      inst=${BCC_F[2]:-}
      [[ -n $id ]] || continue
      case $id in
        org.chromium.Chromium | com.google.Chrome) bcc_browser_judge chromium "$ver" ;;
        org.mozilla.firefox) bcc_browser_judge firefox "$ver" ;;
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
    done < <(find -P /var/lib/flatpak/runtime -maxdepth 8 -type f -name 'libbrotlidec.so.*' -print0 2>/dev/null)
  fi
}

bcc_c12_runtime_lib() {
  local f=$1 ver series rt
  [[ ${f##*/} =~ \.so\.([0-9]+\.[0-9]+\.[0-9]+)$ ]] || return 0
  ver=${BASH_REMATCH[1]}
  series=${ver%.*}
  rt=${f#/var/lib/flatpak/runtime/}
  rt=${rt%%/*}
  bcc_judge brotli "$series" semver "$ver"
  bcc_crosscheck_fixed "$f"
  bcc_add_finding C12 "$BCC_J_STATUS" "flatpak-runtime:$rt" "$f" "$ver" "$BCC_J_REASON" \
    "$([[ $BCC_J_STATUS == VULNERABLE ]] && bcc_msg n_flatpak_update || printf '%s' "$BCC_J_NEXT")" "$BCC_J_EVIDENCE" ""
}

# bcc_browser_judge chromium|firefox VERSION  (sets BCC_J_*)
# Firefox ESR is recognized by "esr" in the version string. Firefox Nightly and Beta
# (150.0a1, 150.0b3, Debian's 150.0~b3) are pre-releases: 150.0a1 is not 150.0. Chromium
# numbers its channels with plain four-part versions; a Debian-style "~" suffix
# (148.0.7778.0~rc1) is a pre-release all the same.
bcc_browser_judge() {
  local kind=$1 raw=$2 ver major build rest
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
        bcc_judge chromium '*' semver "$ver-${BASH_REMATCH[1]}"
      else
        bcc_judge chromium '*' semver "$ver"
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
        bcc_judge firefox-esr "$major" semver "$ver"
      else
        bcc_judge firefox '*' semver "$ver"
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
    bcc_collect0 < <(tr ' ' '\n' <<<"${spec##*:}" | bcc_glob_records | bcc_candidates "$names")
    for x in ${BCC_LIST[@]+"${BCC_LIST[@]}"}; do
      BCC_C13_CANDS+=("$x")
      BCC_C13_KINDS+=("$kind")
    done
  done
  BCC_C13_DONE=1
}

bcc_check_c13() {
  local i kind bin out ver owner ini method
  bcc_c13_candidates
  for i in ${BCC_C13_CANDS[@]+"${!BCC_C13_CANDS[@]}"}; do
      bin=${BCC_C13_CANDS[i]}
      kind=${BCC_C13_KINDS[i]}
      BCC_JUDGED[$bin]=1
      ver="" method=exec
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
      bcc_browser_judge "$kind" "$ver"
      # application.ini is a file next to the browser: its version is confirmed against the
      # decoder (Firefox carries it in libxul.so).
      if [[ $method == ini ]]; then
        if [[ -f $(dirname -- "$bin")/libxul.so ]]; then
          bcc_crosscheck_fixed "$(dirname -- "$bin")/libxul.so"
        else
          bcc_crosscheck_fixed "$bin"
        fi
      fi
      bcc_add_finding C13 "$BCC_J_STATUS" "${bin##*/}" "$bin" "$ver" "$BCC_J_REASON" "$BCC_J_NEXT" \
        "$(bcc_msg e_version_method "$method"); $BCC_J_EVIDENCE" ""
  done
  bcc_add_info C13 "$(bcc_msg i_c13_electron)"
}
