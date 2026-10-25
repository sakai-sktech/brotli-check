# shellcheck shell=bash
# C10 Envoy, C11 compression-only servers (information), C12 snap/flatpak, C13 browsers.

bcc_check_c10() {
  local bin out ver series next h
  local -a cands=() pats=(/usr/local/bin/envoy /usr/bin/envoy '/opt/*/bin/envoy')
  for h in ${BCC_HOMES[@]+"${BCC_HOMES[@]}"}; do pats+=("$h/.func-e/versions/*/bin/envoy"); done
  mapfile -t cands < <({ printf '%s\n' "${pats[@]}"; bcc_index_list ${BCC_IDX_ENVOY[@]+"${BCC_IDX_ENVOY[@]}"}; } | bcc_candidates envoy)
  for bin in ${cands[@]+"${cands[@]}"}; do
    BCC_JUDGED[$bin]=1
    bcc_note_exec_safety "$bin"
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
    if [[ ! -r $BCC_ENVOY_CONFIG ]]; then
      bcc_skip "$BCC_ENVOY_CONFIG" "$(bcc_msg skip_unreadable)"
    elif grep -qE 'envoy\.compression\.brotli\.decompressor|compression\.brotli\.decompressor\.v3' -- "$BCC_ENVOY_CONFIG"; then
      bcc_add_finding C10 EXPOSURE envoy-config "$BCC_ENVOY_CONFIG" "" "$(bcc_msg r_c10_config_br)" "$(bcc_msg n_exposure_hint)" "" ""
    else
      bcc_add_info C10 "$(bcc_msg i_c10_config_none "$BCC_ENVOY_CONFIG")"
    fi
  fi
  bcc_add_info C10 "$(bcc_msg i_c10_istio)"
}

# C11: decide from the files, not from the product name: a module or binary either
# carries decoder code, loads libbrotlidec, or neither.
bcc_c11_file() {
  local prod=$1 f=$2 link rc
  BCC_JUDGED[$f]=1
  if bcc_has_brotli_decoder_marker "$f" && ! bcc_elf_needed "$f" 2>/dev/null | grep -q '^libbrotlidec'; then
    bcc_report_by_strings C11 "$prod" "$f" "" "$(bcc_msg r_c09_vendored)"
    return
  fi
  rc=0
  link=$(bcc_links_brotlidec "$f") || rc=$?
  if ((rc == 0)); then
    bcc_split_tab "$link"
    bcc_add_info C11 "$(bcc_msg i_uses_os_lib "$f" "$prod" "${BCC_F[0]}" "${BCC_F[1]}")"
  elif ((rc == 1)); then
    bcc_add_finding C11 NOT_APPLICABLE "$prod" "$f" "" "$(bcc_msg r_c11_no_decoder)" "$(bcc_msg n_c11_other)" "" ""
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
    mapfile -t cands < <(printf '%s\n' "/usr/sbin/${names%%|*}" "/usr/local/sbin/${names%%|*}" "/usr/local/bin/${names%%|*}" | bcc_candidates "$names")
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
  local dir=$1
  [[ -d $dir ]] || return 1
  find -P "$dir" -maxdepth 4 \( -name 'resources.pak' -o -name 'app.asar' -o -name 'chrome_100_percent.pak' -o -name 'libnode.so' \) -print -quit 2>/dev/null | grep -q .
}

bcc_check_c12() {
  local line name ver rest series
  if bcc_have snap; then
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
    done < <(bcc_sys snap list)
  fi
  if bcc_have flatpak; then
    local id dir inst
    while IFS= read -r line; do
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
    done < <(bcc_sys flatpak list --app --columns=application,version,installation | tr -s ' ' | sed 's/\t\{1,\}/\t/g')
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
  bcc_add_finding C12 "$BCC_J_STATUS" "flatpak-runtime:$rt" "$f" "$ver" "$BCC_J_REASON" \
    "$([[ $BCC_J_STATUS == VULNERABLE ]] && bcc_msg n_flatpak_update || printf '%s' "$BCC_J_NEXT")" "$BCC_J_EVIDENCE" ""
}

# bcc_browser_judge chromium|firefox VERSION  (sets BCC_J_*)
# Firefox ESR is recognized by "esr" in the version string.
bcc_browser_judge() {
  local kind=$1 raw=$2 ver major build
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
      bcc_judge chromium '*' semver "$ver"
      # 148 builds before branch 7778 predate the Brotli roll.
      build=$(cut -d. -f3 <<<"$ver")
      if [[ $major == 148 && -n $build ]] && ((build < 7778)); then
        BCC_J_STATUS=UNKNOWN
        BCC_J_REASON=$(bcc_msg r_c13_148_early)
        BCC_J_NEXT=$(bcc_msg n_update_browser)
      fi
      ;;
    firefox)
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

bcc_check_c13() {
  local spec kind names bin out ver owner
  local -a cands=()
  for spec in \
    "chromium:chromium|chromium-browser:/usr/lib/chromium/chromium /usr/lib/chromium-browser/chromium-browser" \
    "chromium:chrome:/opt/google/chrome/chrome" \
    "firefox:firefox|firefox-esr:/usr/lib/firefox/firefox /usr/lib/firefox-esr/firefox-esr /opt/firefox/firefox"; do
    kind=${spec%%:*}
    names=${spec#*:}
    names=${names%%:*}
    mapfile -t cands < <(tr ' ' '\n' <<<"${spec##*:}" | bcc_candidates "$names")
    for bin in ${cands[@]+"${cands[@]}"}; do
      BCC_JUDGED[$bin]=1
      bcc_note_exec_safety "$bin"
    bcc_note_exec_safety "$bin"
      ver=""
      if out=$(bcc_probe "$bin" --version); then
        if [[ $kind == chromium ]]; then
          ver=$(bcc_version_from_output "$out" 'Chrom[a-z]* ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)') || ver=""
        else
          ver=$(bcc_version_from_output "$out" 'Firefox ([0-9]+\.[0-9]+(\.[0-9]+)*(esr)?)') || ver=""
        fi
      fi
      if [[ -z $ver && $kind == firefox && -r $(dirname -- "$bin")/application.ini ]]; then
        ver=$(sed -n 's/^Version=//p' "$(dirname -- "$bin")/application.ini" | head -n 1)
        [[ -n $ver && $bin == *esr* ]] && ver+="esr"
      fi
      # Without running it, a packaged browser's version is the package version.
      if [[ -z $ver ]] && owner=$(bcc_dpkg_owner "$bin"); then
        # shellcheck disable=SC2016  # dpkg-query format
        ver=$(bcc_sys dpkg-query -W -f '${Version}' "${owner%%,*}")
        ver=${ver%%-*}
      fi
      if [[ -z $(bcc_version_extract "$ver") ]]; then
        bcc_report_by_strings C13 "${bin##*/}" "$bin" "" "$(bcc_msg r_version_unknown)"
        continue
      fi
      bcc_browser_judge "$kind" "$ver"
      bcc_add_finding C13 "$BCC_J_STATUS" "${bin##*/}" "$bin" "$(bcc_version_extract "$ver")" "$BCC_J_REASON" "$BCC_J_NEXT" "$BCC_J_EVIDENCE" ""
    done
  done
  bcc_add_info C13 "$(bcc_msg i_c13_electron)"
}
