# shellcheck shell=bash
# C14 containers (--containers, --inspect-containers), C15 listening sockets (--exposure).

# Fixed script run inside a container with --inspect-containers, only through a unix socket
# on this host (bcc_c14_connection). It prints tagged lines only and installs or writes
# nothing; the only programs it starts besides its readers are node/nodejs --version, which
# run as the container's own programs do. os-release is read with sed, never sourced (it is
# a file the image's author controls).
# POSIX sh only: /bin/sh is dash (Debian/Ubuntu) or busybox, and neither knows
# "command -v -a", so node/nodejs are looked up in each PATH directory by hand.
# The END line tells a complete run from one that stopped early.
# shellcheck disable=SC2016  # expanded inside the container, not here
BCC_C14_PROBE='
osr() { sed -n "s/^$1=//p" /etc/os-release 2>/dev/null | head -n 1 | tr -d "\"\047"; }
echo "OS	$(osr ID)	$(osr VERSION_CODENAME)	$(osr UBUNTU_CODENAME)"
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f "PKG	\${db:Status-Abbrev}	\${binary:Package}	\${Version}	\${source:Package}	\${source:Version}\n" libbrotli1 python3-brotli 2>/dev/null
  echo "PKGRC	$?"
fi
seen=" "
set -f
old_ifs=$IFS
IFS=:
for d in ${PATH:-/usr/local/bin:/usr/bin:/bin}:/usr/local/bin:/usr/bin:/bin; do
  IFS=$old_ifs
  case $d in /*) ;; *) continue ;; esac
  for n in node nodejs; do
    p="$d/$n"
    [ -f "$p" ] && [ -x "$p" ] || continue
    r=$(readlink -f "$p" 2>/dev/null) || r=$p
    case $seen in *" $r "*) continue ;; esac
    seen="$seen$r "
    echo "NODE	$p	$("$p" --version 2>/dev/null | head -n 1)"
  done
done
IFS=$old_ifs
set +f
for d in /usr/lib/python3/dist-packages /usr/local/lib/python3*/site-packages /usr/lib/python3*/site-packages /opt/*/lib/python3*/site-packages; do
  for m in "$d"/[Bb]rotli-*.dist-info/METADATA "$d"/brotlicffi-*.dist-info/METADATA; do
    [ -f "$m" ] && echo "PY	$m	$(sed -n "s/^Name: *//p" "$m" | head -n 1)	$(sed -n "s/^Version: *//p" "$m" | head -n 1)"
  done
done
echo END
'

# Where the engine connects (docs/design.md 10.20), asked from the engine itself and never
# read from the environment or its configuration files. docker settles it from -H,
# DOCKER_HOST, DOCKER_CONTEXT and the current context of its configuration, in that order,
# and "docker context inspect" with no name answers for the context so chosen; its name then
# keeps every later call on it (--context), even if the current context is switched during the
# scan. podman runs containers itself unless it is a client of a service (--remote, --url,
# CONTAINER_HOST, CONTAINER_CONNECTION); "podman info" says which, but not the service's
# address. Only a unix socket on this host, or podman without a service, counts as this host.
# Sets BCC_C14_KIND (unix, other, unknown, podman_local, podman_remote), BCC_C14_WHERE (the
# endpoint docker stated) and BCC_C14_ARGS (arguments for every later call of the engine).
bcc_c14_connection() {
  local engine=$1 out name host
  BCC_C14_KIND=unknown BCC_C14_WHERE=""
  BCC_C14_ARGS=()
  case $engine in
    docker)
      out=$(bcc_sys docker context inspect --format '{{.Name}} {{.Endpoints.docker.Host}}') || return 0
      out=${out%%$'\n'*}
      [[ $out == *' '* ]] || return 0
      name=${out%% *}
      host=${out#* }
      [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9_.+-]*$ && $host =~ ^[a-z][a-z0-9+.-]*:// ]] || return 0
      BCC_C14_WHERE=$host
      BCC_C14_ARGS=(--context "$name")
      if [[ $host == unix:///?* ]]; then BCC_C14_KIND=unix; else BCC_C14_KIND=other; fi
      ;;
    podman)
      out=$(bcc_sys podman info --format '{{.Host.ServiceIsRemote}}') || return 0
      case ${out%%$'\n'*} in
        false) BCC_C14_KIND=podman_local ;;
        true) BCC_C14_KIND=podman_remote ;;
      esac
      ;;
  esac
}

bcc_check_c14() {
  local engine="" e line id image name
  for e in docker podman; do
    bcc_have "$e" && { engine=$e; break; }
  done
  if [[ -z $engine ]]; then
    bcc_skip C14 "$(bcc_msg skip_no_engine)"
    return
  fi
  # The connection comes first and is always reported, also when the engine then fails.
  local local_host=0 not_local=""
  bcc_c14_connection "$engine"
  case $BCC_C14_KIND in
    unix)
      local_host=1
      bcc_add_info C14 "$(bcc_msg i_c14_conn_unix "$engine" "$BCC_C14_WHERE")"
      ;;
    podman_local)
      local_host=1
      bcc_add_info C14 "$(bcc_msg i_c14_conn_podman_local)"
      ;;
    other)
      bcc_add_info C14 "$(bcc_msg i_c14_conn_other "$engine" "$BCC_C14_WHERE")"
      not_local=$(bcc_msg skip_c14_conn_other "$engine" "$BCC_C14_WHERE")
      ;;
    podman_remote)
      bcc_add_info C14 "$(bcc_msg i_c14_conn_podman_remote)"
      not_local=$(bcc_msg skip_c14_conn_podman_remote)
      ;;
    *)
      local asked="docker context inspect"
      [[ $engine == podman ]] && asked="podman info"
      bcc_add_info C14 "$(bcc_msg i_c14_conn_unknown "$engine" "$asked")"
      not_local=$(bcc_msg skip_c14_conn_unknown "$engine")
      ;;
  esac
  local ps
  if ! ps=$(timeout -k 2 "$BCC_TIMEOUT" env LC_ALL=C "$engine" ${BCC_C14_ARGS[@]+"${BCC_C14_ARGS[@]}"} \
    ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}' </dev/null 2>/dev/null); then
    bcc_skip "C14 $engine" "$(bcc_msg skip_engine_denied "$engine")"
    return
  fi
  local nimages
  nimages=$(bcc_sys "$engine" ${BCC_C14_ARGS[@]+"${BCC_C14_ARGS[@]}"} images -q | sort -u | grep -c . || true)
  bcc_add_info C14 "$(bcc_msg i_c14_inventory "$engine" "$(grep -c . <<<"$ps" || true)" "$nimages")"
  bcc_add_info C14 "$(bcc_msg i_c14_rebuild)"
  [[ -n $ps ]] || return 0
  # Containers reached any other way are listed and counted, but nothing runs inside them:
  # they may be another host's (issue #6). This holds with or without --inspect-containers.
  if ((!local_host)); then
    while IFS= read -r line; do
      bcc_split_tab "$line"
      bcc_add_info C14 "$(bcc_msg i_c14_not_inspected_conn "${BCC_F[2]:-}" "${BCC_F[1]:-}")"
    done <<<"$ps"
    bcc_skip C14 "$not_local"
    return
  fi
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
    bcc_c14_inspect "$engine" "$id" "$name" "$image" ${BCC_C14_ARGS[@]+"${BCC_C14_ARGS[@]}"}
  done <<<"$ps"
}

# Usage: bcc_c14_inspect ENGINE ID NAME IMAGE [ENGINE-ARGS...]
# Only for containers reached through this host (bcc_check_c14); ENGINE-ARGS keep the call on
# the connection that was checked.
bcc_c14_inspect() {
  local engine=$1 id=$2 name=$3 image=$4 out line series="" where ended=0 deb_py_ver=""
  if ! out=$(timeout -k 2 "$BCC_TIMEOUT" "$engine" "${@:5}" exec "$id" sh -c "$BCC_C14_PROBE" </dev/null 2>/dev/null); then
    bcc_skip "container $name" "$(bcc_msg skip_c14_exec_failed)"
    return
  fi
  where="container $name ($image)"
  while IFS= read -r line; do
    bcc_split_tab "$line"
    case ${BCC_F[0]} in
      END) ended=1 ;;
      PKGRC)
        # 1 only means a package is not installed; 2 and above: the database was not read.
        [[ ${BCC_F[1]:-} =~ ^[01]$ ]] || bcc_skip "container $name (dpkg)" "$(bcc_msg skip_c14_dpkg_failed "${BCC_F[1]:-?}")"
        ;;
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
        if [[ $pkg == python3-brotli ]]; then
          # The upstream part of the package's version, as its own metadata states it.
          deb_py_ver=${ver#*:}
          deb_py_ver=${deb_py_ver%%-*}
          deb_py_ver=${deb_py_ver%%[+~]*}
        fi
        bcc_judge "deb-src:$src" "$series" deb "$srcver"
        bcc_add_finding C14 "$BCC_J_STATUS" "$pkg" "$where" "$ver" "$BCC_J_REASON" "$(bcc_msg n_rebuild_image)" "$BCC_J_EVIDENCE" ""
        ;;
      NODE)
        local nver npath=${BCC_F[1]:-}
        nver=$(bcc_semver_parse "${BCC_F[2]:-}") || nver=""
        if [[ -z $nver ]]; then
          bcc_add_finding C14 UNKNOWN node "$where $npath" "" "$(bcc_msg r_version_unknown)" "$(bcc_msg n_check_vendor)" "" ""
          continue
        fi
        bcc_judge node "${nver%%.*}" semver "$nver"
        bcc_add_finding C14 "$BCC_J_STATUS" node "$where $npath" "$nver" "$BCC_J_REASON $(bcc_msg r_c14_node_vs_os)" \
          "$(bcc_msg n_rebuild_image)" "$BCC_J_EVIDENCE" ""
        ;;
      PY)
        local lname meta=${BCC_F[1]:-} pname=${BCC_F[2]:-} pver=${BCC_F[3]:-}
        lname=$(tr '[:upper:]' '[:lower:]' <<<"$pname")
        [[ $lname == brotli || $lname == brotlicffi ]] || continue
        # The distribution's python3-brotli (judged from its PKG line) puts Brotli's metadata
        # here, at its own version; anything else here (brotlicffi, another Brotli by pip
        # --target) is judged by its own version.
        [[ $lname == brotli && -n $deb_py_ver && $pver == "$deb_py_ver" && $meta == /usr/lib/python3/dist-packages/* ]] && continue
        bcc_judge "pypi:$lname" '*' pep440 "$pver"
        # The probe reads the metadata only, so "fixed" stays unconfirmed (see bcc_crosscheck_fixed).
        local pnext
        pnext=$(bcc_msg n_rebuild_image)
        if [[ $BCC_J_STATUS == FIXED ]]; then
          bcc_crosscheck_no_file "$(bcc_msg r_c14_py_unconfirmed "$pver")" "$(bcc_msg n_check_vendor)"
          pnext=$BCC_J_NEXT
        fi
        bcc_add_finding C14 "$BCC_J_STATUS" "$pname" "$where ${meta%/*}" "$pver" "$BCC_J_REASON" "$pnext" "$BCC_J_EVIDENCE" ""
        ;;
    esac
  done <<<"$out"
  ((ended)) || bcc_skip "container $name" "$(bcc_msg skip_c14_incomplete)"
}

# C15: who listens beyond loopback? Only a hint for prioritizing.
bcc_check_c15() {
  if ! bcc_have ss; then
    bcc_skip C15 "$(bcc_msg skip_no_ss)"
    return
  fi
  local line local_addr procinfo pname pid any_hidden=0 out rc=0
  out=$(bcc_sys ss -ltnpH) || rc=$?
  if ((rc != 0)); then
    bcc_skip C15 "$(bcc_msg skip_cmd_failed ss "$rc")"
    return 0
  fi
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
  done <<<"$out"
  ((any_hidden == 0 || BCC_IS_ROOT)) || bcc_skip C15 "$(bcc_msg skip_c15_hidden)"
}
