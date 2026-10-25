# shellcheck shell=bash
# C14 containers (--containers, --inspect-containers), C15 listening sockets (--exposure).

# Fixed, read-only script run inside a container with --inspect-containers.
# It prints tagged lines only; nothing is installed, written, or started.
# shellcheck disable=SC2016  # expanded inside the container, not here
BCC_C14_PROBE='
. /etc/os-release 2>/dev/null
echo "OS	${ID:-}	${VERSION_CODENAME:-}	${UBUNTU_CODENAME:-}"
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f "PKG	\${db:Status-Abbrev}	\${binary:Package}	\${Version}	\${source:Package}	\${source:Version}\n" libbrotli1 python3-brotli 2>/dev/null
fi
for n in $(command -v -a node nodejs 2>/dev/null | sort -u); do echo "NODE	$n	$("$n" --version 2>/dev/null)"; done
for d in /usr/lib/python3/dist-packages /usr/local/lib/python3*/site-packages /usr/lib/python3*/site-packages /opt/*/lib/python3*/site-packages; do
  for m in "$d"/[Bb]rotli-*.dist-info/METADATA "$d"/brotlicffi-*.dist-info/METADATA; do
    [ -f "$m" ] && echo "PY	$m	$(sed -n "s/^Name: *//p" "$m" | head -n 1)	$(sed -n "s/^Version: *//p" "$m" | head -n 1)"
  done
done
'

bcc_check_c14() {
  local engine="" e line id image name
  for e in docker podman; do
    bcc_have "$e" && { engine=$e; break; }
  done
  if [[ -z $engine ]]; then
    bcc_skip C14 "$(bcc_msg skip_no_engine)"
    return
  fi
  local ps
  if ! ps=$(timeout -k 2 "$BCC_TIMEOUT" env LC_ALL=C "$engine" ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}' </dev/null 2>/dev/null); then
    bcc_skip "C14 $engine" "$(bcc_msg skip_engine_denied "$engine")"
    return
  fi
  local nimages
  nimages=$(bcc_sys "$engine" images -q | sort -u | grep -c . || true)
  bcc_add_info C14 "$(bcc_msg i_c14_inventory "$engine" "$(grep -c . <<<"$ps" || true)" "$nimages")"
  bcc_add_info C14 "$(bcc_msg i_c14_rebuild)"
  [[ -n $ps ]] || return 0
  if ((!BCC_INSPECT_CONTAINERS)); then
    while IFS= read -r line; do
      bcc_split_tab "$line"
      bcc_add_info C14 "$(bcc_msg i_c14_not_inspected "${BCC_F[2]:-}" "${BCC_F[1]:-}")"
    done <<<"$ps"
    bcc_skip C14 "$(bcc_msg skip_c14_inside)"
    return
  fi
  if ((BCC_NO_EXEC)); then
    bcc_skip C14 "$(bcc_msg skip_c14_noexec)"
    return
  fi
  while IFS= read -r line; do
    bcc_split_tab "$line"
    id=${BCC_F[0]}
    image=${BCC_F[1]:-}
    name=${BCC_F[2]:-$id}
    [[ $id =~ ^[0-9a-f]+$ ]] || continue
    bcc_c14_inspect "$engine" "$id" "$name" "$image"
  done <<<"$ps"
}

bcc_c14_inspect() {
  local engine=$1 id=$2 name=$3 image=$4 out line series="" where
  if ! out=$(timeout -k 2 "$BCC_TIMEOUT" "$engine" exec "$id" sh -c "$BCC_C14_PROBE" </dev/null 2>/dev/null); then
    bcc_skip "container $name" "$(bcc_msg skip_c14_exec_failed)"
    return
  fi
  where="container $name ($image)"
  while IFS= read -r line; do
    bcc_split_tab "$line"
    case ${BCC_F[0]} in
      OS)
        case ${BCC_F[1]:-} in
          ubuntu | debian) series="${BCC_F[1]}:${BCC_F[2]:-}" ;;
          *) [[ -n ${BCC_F[3]:-} ]] && series="ubuntu:${BCC_F[3]}" ;;
        esac
        [[ -n $series ]] || bcc_add_info C14 "$(bcc_msg i_c14_unsupported_os "$name" "${BCC_F[1]:-?}")"
        ;;
      PKG)
        [[ ${BCC_F[1]:-} == [ih]i* && -n $series ]] || continue
        local pkg=${BCC_F[2]%%:*} ver=${BCC_F[3]} src=${BCC_F[4]:-brotli} srcver=${BCC_F[5]:-${BCC_F[3]}}
        bcc_judge "deb-src:$src" "$series" deb "$srcver"
        bcc_add_finding C14 "$BCC_J_STATUS" "$pkg" "$where" "$ver" "$BCC_J_REASON" "$(bcc_msg n_rebuild_image)" "$BCC_J_EVIDENCE" ""
        ;;
      NODE)
        local nver
        nver=$(bcc_version_extract "${BCC_F[2]:-}")
        if [[ -z $nver ]]; then
          bcc_add_finding C14 UNKNOWN node "$where ${BCC_F[1]}" "" "$(bcc_msg r_version_unknown)" "$(bcc_msg n_check_vendor)" "" ""
          continue
        fi
        bcc_judge node "${nver%%.*}" semver "$nver"
        bcc_add_finding C14 "$BCC_J_STATUS" node "$where ${BCC_F[1]}" "$nver" "$BCC_J_REASON $(bcc_msg r_c14_node_vs_os)" \
          "$(bcc_msg n_rebuild_image)" "$BCC_J_EVIDENCE" ""
        ;;
      PY)
        local lname
        lname=$(tr '[:upper:]' '[:lower:]' <<<"${BCC_F[2]:-}")
        [[ $lname == brotli || $lname == brotlicffi ]] || continue
        [[ ${BCC_F[1]} == /usr/lib/python3/dist-packages/* ]] && continue # distribution package: PKG line
        bcc_judge "pypi:$lname" '*' pep440 "${BCC_F[3]:-}"
        bcc_add_finding C14 "$BCC_J_STATUS" "${BCC_F[2]}" "$where ${BCC_F[1]%/*}" "${BCC_F[3]:-}" "$BCC_J_REASON" "$(bcc_msg n_rebuild_image)" "$BCC_J_EVIDENCE" ""
        ;;
    esac
  done <<<"$out"
}

# C15: who listens beyond loopback? Only a hint for prioritizing.
bcc_check_c15() {
  if ! bcc_have ss; then
    bcc_skip C15 "$(bcc_msg skip_no_ss)"
    return
  fi
  local line local_addr procinfo pname pid any_hidden=0
  while IFS= read -r line; do
    read -r _ _ _ local_addr _ procinfo <<<"$line"
    [[ -n $local_addr ]] || continue
    case $local_addr in
      127.* | '[::1]':* | ::1:* | '[::ffff:127.'*) continue ;;
    esac
    if [[ -z $procinfo ]]; then
      any_hidden=1
      continue
    fi
    [[ $procinfo =~ \(\(\"([^\"]+)\",pid=([0-9]+) ]] || continue
    pname=${BASH_REMATCH[1]}
    pid=${BASH_REMATCH[2]}
    case $pname in
      node | nodejs | bun | envoy | python | python3 | python3.* | uvicorn | gunicorn) ;;
      *) continue ;;
    esac
    bcc_add_finding C15 EXPOSURE "$pname (pid $pid)" "$local_addr" "" "$(bcc_msg r_c15_listen)" "$(bcc_msg n_c15)" "" ""
  done < <(bcc_sys ss -ltnpH)
  ((any_hidden == 0 || BCC_IS_ROOT)) || bcc_skip C15 "$(bcc_msg skip_c15_hidden)"
}
