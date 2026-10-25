# shellcheck shell=bash
# output.sh - human-readable report and JSON (schema: docs/json-schema.md).

BCC_CHECK_IDS="C01 C02 C03 C04 C05 C06 C07 C08 C09 C10 C11 C12 C13 C14 C15"

bcc_host_line() {
  local who
  if ((BCC_IS_ROOT)); then who=$(bcc_msg h_root); else who=$(bcc_msg h_not_root "$BCC_UID"); fi
  bcc_msg h_host "${BCC_OS_PRETTY:-${BCC_OS_ID:-?}}" "${BCC_DEB_SERIES:--}" "${BCC_KERNEL:-?}" "$who"
}

bcc_options_summary() {
  local -a o=()
  ((BCC_DEEP)) && o+=(--deep)
  ((BCC_PROJECTS)) && o+=(--projects)
  ((BCC_INSPECT_CONTAINERS)) && o+=(--inspect-containers)
  ((BCC_CONTAINERS && !BCC_INSPECT_CONTAINERS)) && o+=(--containers)
  ((BCC_EXPOSURE)) && o+=(--exposure)
  ((BCC_NO_EXEC)) && o+=(--no-exec)
  ((BCC_INCLUDE_REMOTE)) && o+=(--include-remote)
  [[ -n $BCC_ENVOY_CONFIG ]] && o+=("--envoy-config $BCC_ENVOY_CONFIG")
  if ((${#o[@]})); then printf '%s' "${o[*]}"; else printf -- '-'; fi
}

bcc_render_text() {
  local id f printed
  bcc_msg h_title "$BCC_VERSION" "$BCC_CVE"
  printf '\n'
  bcc_host_line
  printf '\n'
  bcc_msg h_data "$BCC_DATA_SNAPSHOT" "$BCC_DATA_AGE_DAYS" "$BCC_DATA_LABEL"
  printf '\n'
  if ((BCC_DATA_AGE_DAYS >= 30)); then
    bcc_msg w_data_stale "$BCC_DATA_AGE_DAYS"
    printf '\n'
  fi
  bcc_msg h_roots "$(IFS=,; printf '%s' "${BCC_ROOTS[*]:-}")" "$(bcc_options_summary)"
  printf '\n'
  for id in $BCC_CHECK_IDS; do
    printed=0
    for f in ${BCC_FINDINGS[@]+"${BCC_FINDINGS[@]}"}; do
      bcc_split_tab "$f"
      [[ ${BCC_F[0]} == "$id" ]] || continue
      if ((!printed)); then
        printf '\n== %s %s ==\n' "$id" "$(bcc_msg "title_$id")"
        printed=1
      fi
      printf '[%s] %s | %s | %s | %s | %s | %s\n' "${BCC_F[1]}" "${BCC_F[0]}" "${BCC_F[2]}" "${BCC_F[3]:--}" \
        "${BCC_F[4]:--}" "${BCC_F[5]:--}" "${BCC_F[6]:--}"
    done
  done
  if ((${#BCC_INFO[@]})); then
    printf '\n== %s ==\n' "$(bcc_msg title_info)"
    for f in "${BCC_INFO[@]}"; do
      bcc_split_tab "$f"
      printf '[INFO] %s | %s\n' "${BCC_F[0]}" "${BCC_F[1]}"
    done
  fi
  if ((${#BCC_SKIPPED[@]})); then
    printf '\n== %s ==\n' "$(bcc_msg title_skipped)"
    for f in "${BCC_SKIPPED[@]}"; do
      bcc_split_tab "$f"
      printf '[SKIPPED] %s | %s\n' "${BCC_F[0]}" "${BCC_F[1]}"
    done
  fi
  printf '\n== %s ==\n' "$(bcc_msg title_summary)"
  bcc_msg s_update "$BCC_SUM_UPDATE"
  printf '\n'
  bcc_msg s_restart "$BCC_SUM_RESTART"
  printf '\n'
  bcc_msg s_review "$BCC_SUM_REVIEW"
  printf '\n'
  bcc_msg s_skipped "$(bcc_skipped_scopes)"
  printf '\n'
  if ((BCC_EXIT == 0)); then
    bcc_msg s_clean
    printf '\n'
  fi
  bcc_msg s_disclaimer
  printf '\n'
}

bcc_skipped_scopes() {
  local f
  local -a s=()
  for f in ${BCC_SKIPPED[@]+"${BCC_SKIPPED[@]}"}; do
    bcc_split_tab "$f"
    s+=("${BCC_F[0]}")
  done
  if ((${#s[@]})); then
    printf '%s\n' "${s[@]}" | awk '!seen[$0]++' | paste -sd, - | sed 's/,/, /g'
  else
    bcc_msg s_skipped_none
  fi
}

# JSON string escaping (RFC 8259): quote, backslash, control characters.
bcc_json_str() {
  local s=$1 out="" c i code
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  if [[ $s == *[$'\x01'-$'\x1f']* ]]; then
    for ((i = 0; i < ${#s}; i++)); do
      c=${s:i:1}
      if [[ $c == [$'\x01'-$'\x1f'] ]]; then
        printf -v code '%d' "'$c"
        printf -v c '\\u%04x' "$code"
      fi
      out+=$c
    done
    s=$out
  fi
  printf '"%s"' "$s"
}

bcc_json_array_of_strings() {
  local first=1 v
  printf '['
  for v in "$@"; do
    ((first)) || printf ','
    first=0
    bcc_json_str "$v"
  done
  printf ']'
}

bcc_render_json() {
  local f first st
  printf '{'
  printf '"tool":"brotli-cve-check","tool_version":%s,"cve":%s,' "$(bcc_json_str "$BCC_VERSION")" "$(bcc_json_str "$BCC_CVE")"
  printf '"data_snapshot_date":%s,"data_age_days":%d,"data_stale":%s,"data_source":%s,' \
    "$(bcc_json_str "$BCC_DATA_SNAPSHOT")" "$BCC_DATA_AGE_DAYS" "$( ((BCC_DATA_AGE_DAYS >= 30)) && echo true || echo false)" \
    "$(bcc_json_str "$BCC_DATA_LABEL")"
  printf '"host":{"os_id":%s,"os_version_id":%s,"os_codename":%s,"os_pretty_name":%s,"package_series":%s,"kernel":%s,"uid":%d,"is_root":%s},' \
    "$(bcc_json_str "${BCC_OS_ID:-}")" "$(bcc_json_str "${BCC_OS_VERSION_ID:-}")" "$(bcc_json_str "${BCC_OS_CODENAME:-}")" \
    "$(bcc_json_str "${BCC_OS_PRETTY:-}")" "$(bcc_json_str "${BCC_DEB_SERIES:-}")" "$(bcc_json_str "${BCC_KERNEL:-}")" \
    "$BCC_UID" "$( ((BCC_IS_ROOT)) && echo true || echo false)"
  printf '"options":{"deep":%s,"projects":%s,"containers":%s,"inspect_containers":%s,"exposure":%s,"no_exec":%s,"include_remote":%s,"lang":%s},' \
    "$(bcc_json_bool "$BCC_DEEP")" "$(bcc_json_bool "$BCC_PROJECTS")" "$(bcc_json_bool "$BCC_CONTAINERS")" \
    "$(bcc_json_bool "$BCC_INSPECT_CONTAINERS")" "$(bcc_json_bool "$BCC_EXPOSURE")" "$(bcc_json_bool "$BCC_NO_EXEC")" \
    "$(bcc_json_bool "$BCC_INCLUDE_REMOTE")" "$(bcc_json_str "$BCC_LANG")"
  printf '"scanned_roots":%s,' "$(bcc_json_array_of_strings ${BCC_ROOTS[@]+"${BCC_ROOTS[@]}"})"
  printf '"skipped":['
  first=1
  for f in ${BCC_SKIPPED[@]+"${BCC_SKIPPED[@]}"}; do
    bcc_split_tab "$f"
    ((first)) || printf ','
    first=0
    printf '{"scope":%s,"reason":%s}' "$(bcc_json_str "${BCC_F[0]}")" "$(bcc_json_str "${BCC_F[1]:-}")"
  done
  printf '],"findings":['
  first=1
  for f in ${BCC_FINDINGS[@]+"${BCC_FINDINGS[@]}"}; do
    bcc_split_tab "$f"
    ((first)) || printf ','
    first=0
    printf '{"id":%s,"status":%s,"component":%s,"path":%s,"version":%s,"reason":%s,"next_step":%s,"evidence":%s,"confidence":%s}' \
      "$(bcc_json_str "${BCC_F[0]}")" "$(bcc_json_str "${BCC_F[1]}")" "$(bcc_json_str "${BCC_F[2]:-}")" \
      "$(bcc_json_str "${BCC_F[3]:-}")" "$(bcc_json_str "${BCC_F[4]:-}")" "$(bcc_json_str "${BCC_F[5]:-}")" \
      "$(bcc_json_str "${BCC_F[6]:-}")" "$(bcc_json_str "${BCC_F[7]:-}")" "$(bcc_json_str "${BCC_F[8]:-}")"
  done
  printf '],"info":['
  first=1
  for f in ${BCC_INFO[@]+"${BCC_INFO[@]}"}; do
    bcc_split_tab "$f"
    ((first)) || printf ','
    first=0
    printf '{"id":%s,"text":%s}' "$(bcc_json_str "${BCC_F[0]}")" "$(bcc_json_str "${BCC_F[1]:-}")"
  done
  printf '],"summary":{"needs_update":%d,"needs_restart":%d,"needs_review":%d,"by_status":{' \
    "$BCC_SUM_UPDATE" "$BCC_SUM_RESTART" "$BCC_SUM_REVIEW"
  first=1
  for st in $BCC_STATUSES; do
    ((first)) || printf ','
    first=0
    printf '%s:%d' "$(bcc_json_str "$st")" "$(bcc_count_status "$st")"
  done
  printf '}},"exit_code":%d,"disclaimer":%s}' "$BCC_EXIT" "$(bcc_json_str "$(bcc_msg s_disclaimer)")"
  printf '\n'
}

bcc_json_bool() {
  if (($1)); then printf true; else printf false; fi
}
