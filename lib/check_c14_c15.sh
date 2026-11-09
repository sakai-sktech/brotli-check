# shellcheck shell=bash
# C14 containers (--containers, --inspect-containers), C15 listening sockets (--exposure).

# Fixed script run inside a container with --inspect-containers, only through a unix socket
# on this host (bcc_c14_connection). It prints tagged lines only and installs or writes
# nothing; the only programs it starts besides its readers are node/nodejs --version, which
# run as the container's own programs do. os-release is read with sed, never sourced (it is
# a file the image's author controls).
# POSIX sh only: /bin/sh is dash (Debian/Ubuntu) or busybox, and neither knows
# "command -v -a", so node/nodejs are looked up in each PATH directory by hand.
# The END line tells a complete run from one that stopped early. In each Python directory the
# extension modules of Brotli and brotlicffi (EXT: path and size, the globs C06 uses on this
# host) come before the packages' metadata (PY), so that a PY line implies that its directory's
# EXT lines are all there; the modules are then read one by one (bcc_c14_py_crosscheck).
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
  for e in "$d"/_brotli.*so "$d"/brotlicffi/_brotlicffi*.so; do
    [ -f "$e" ] && echo "EXT	$e	$(wc -c 2>/dev/null <"$e")"
  done
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
    bcc_skip failed C14 "$(bcc_msg skip_no_engine)"
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
    bcc_skip failed "C14 $engine" "$(bcc_msg skip_engine_denied "$engine")"
    return
  fi
  # Stopped containers and images are counted and never looked inside, with or without
  # --inspect-containers (issue #8, docs/design.md 10.24). The number goes to "Not scanned",
  # so that the list of running containers is not read as all of them; a count that could not
  # be taken is said so there, never given as 0. What is counted is what --containers covers,
  # so it is left out by choice; a count that failed is a failure (issue #10, 10.26).
  local all images nstopped="?" nimages="?"
  if all=$(bcc_sys "$engine" ${BCC_C14_ARGS[@]+"${BCC_C14_ARGS[@]}"} ps -a --format '{{.ID}}'); then
    nstopped=$(bcc_c14_count_stopped "$ps" "$all")
  fi
  if images=$(bcc_sys "$engine" ${BCC_C14_ARGS[@]+"${BCC_C14_ARGS[@]}"} images -q); then
    nimages=$(sort -u <<<"$images" | grep -c . || true)
  fi
  bcc_add_info C14 "$(bcc_msg i_c14_inventory "$engine" "$(grep -c . <<<"$ps" || true)" "$nstopped" "$nimages")"
  bcc_add_info C14 "$(bcc_msg i_c14_rebuild)"
  if [[ $nstopped == '?' ]]; then
    bcc_skip failed "C14 (stopped containers)" "$(bcc_msg skip_c14_stopped_uncounted "$engine")"
  elif ((nstopped > 0)); then
    bcc_skip chosen "C14 (stopped containers)" "$(bcc_msg skip_c14_stopped "$nstopped")"
  fi
  if [[ $nimages == '?' ]]; then
    bcc_skip failed "C14 (images)" "$(bcc_msg skip_c14_images_uncounted "$engine")"
  elif ((nimages > 0)); then
    bcc_skip chosen "C14 (images)" "$(bcc_msg skip_c14_images "$nimages")"
  fi
  [[ -n $ps ]] || return 0
  # Containers reached any other way are listed and counted, but nothing runs inside them:
  # they may be another host's (issue #6). This holds with or without --inspect-containers; when
  # that option asked to look inside, not doing so is a failure (issue #10).
  if ((!local_host)); then
    while IFS= read -r line; do
      bcc_split_tab "$line"
      bcc_add_info C14 "$(bcc_msg i_c14_not_inspected_conn "${BCC_F[2]:-}" "${BCC_F[1]:-}")"
    done <<<"$ps"
    if ((BCC_INSPECT_CONTAINERS)); then bcc_skip failed C14 "$not_local"; else bcc_skip chosen C14 "$not_local"; fi
    return
  fi
  if ((!BCC_INSPECT_CONTAINERS)); then
    while IFS= read -r line; do
      bcc_split_tab "$line"
      bcc_add_info C14 "$(bcc_msg i_c14_not_inspected "${BCC_F[2]:-}" "${BCC_F[1]:-}")"
    done <<<"$ps"
    bcc_skip chosen C14 "$(bcc_msg skip_c14_inside)"
    return
  fi
  if ((BCC_NO_EXEC)); then
    bcc_skip chosen C14 "$(bcc_msg skip_c14_noexec)"
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

# Usage: bcc_c14_count_stopped RUNNING ALL - how many IDs of "ps -a" (ALL, one per line) are not
# among the running ones (RUNNING, the lines of "ps", ID first). Both lists use the engine's
# own {{.ID}}, so they agree on its length. They are two calls: a container that starts in
# between is counted as stopped (and was not looked inside either way).
bcc_c14_count_stopped() {
  local running=$1 all=$2 line n=0
  local -A up=() seen=()
  while IFS= read -r line; do
    line=${line%%$'\t'*}
    [[ -n $line ]] && up[$line]=1
  done <<<"$running"
  while IFS= read -r line; do
    [[ -n $line && -z ${up[$line]:-} && -z ${seen[$line]:-} ]] || continue
    seen[$line]=1
    n=$((n + 1))
  done <<<"$all"
  printf '%d' "$n"
}

# The next step of a package or Node.js line from bcc_judge inside a container: nothing for a
# FIXED one (n_fixed), else rebuilding the image (updating the host does not reach it).
bcc_c14_next() {
  if [[ $BCC_J_STATUS == FIXED ]]; then
    printf '%s' "$BCC_J_NEXT"
  else
    bcc_msg n_rebuild_image
  fi
}

# A "fixed" version from Python metadata inside a container is confirmed as on this host (C06,
# docs/design.md 10.15 and 10.29): against this package's own extension modules in SITE
# (Brotli: _brotli.*so; brotlicffi: brotlicffi/_brotlicffi*.so), as the check script listed
# them. Each is read inside the container with head through the engine (bcc_c14_read), up to
# the size limit and under the time limit, and its strings are judged here; nothing is written
# on this host. A module larger than the limit is not read (it could not be read to the end).
# No module, one not read to the end and one not read at all each leave the line UNKNOWN with
# its reason; the last two are also listed as could not be scanned. Acts on BCC_J_*.
# Usage: bcc_c14_py_crosscheck ENGINE ID NAME LNAME SITE VERSION [ENGINE-ARGS...]
bcc_c14_py_crosscheck() {
  local engine=$1 id=$2 name=$3 lname=$4 site=$5 ver=$6 i p rest size res rc pattern='_brotli.*so' n=0
  local max=$((BCC_MAX_ELF_MB * 1024 * 1024))
  [[ $lname == brotli ]] || pattern='brotlicffi/_brotlicffi*.so'
  for i in ${BCC_C14_EXT_P[@]+"${!BCC_C14_EXT_P[@]}"}; do
    p=${BCC_C14_EXT_P[i]}
    # $site is taken literally: a "[" or "*" in a path is part of a name, not a pattern. A path
    # in another directory keeps its leading "/" here, and matches neither name below.
    rest=${p#"$site"/}
    if [[ $lname == brotli ]]; then
      [[ $rest == _brotli.*so && $rest != */* ]] || continue
    else
      [[ $rest == brotlicffi/_brotlicffi*.so && ${rest#brotlicffi/} != */* ]] || continue
    fi
    n=$((n + 1))
    # As on this host, the first module that does not confirm the version decides.
    [[ $BCC_J_STATUS == FIXED ]] || continue
    size=${BCC_C14_EXT_S[i]//[[:space:]]/}
    rc=""
    if [[ ! $size =~ ^[0-9]+$ ]]; then
      # The check script could not take its size: it could not open it.
      res=UNREADABLE rc='?'
    elif ((size > max)); then
      res=$(bcc_brotli_classify $'0\t0\t0\t0\t0\t0\tpartial')
    else
      bcc_brotli_scan_stream 0 bcc_c14_read "$engine" "$id" "$p" "$max" "${@:7}"
      case $BCC_SCAN_RC in
        # 124, 137: the time limit (timeout). The bytes read so far are not enough.
        0 | 124 | 137) res=$(bcc_brotli_classify "$BCC_SCAN") ;;
        *) res=UNREADABLE rc=${BCC_SCAN_RC:-?} ;;
      esac
    fi
    [[ $res != UNREADABLE ]] || bcc_skip failed "container $name $p" "$(bcc_msg skip_c14_read_failed "$rc")"
    bcc_crosscheck_apply "$res" "container $name $p" "$(bcc_msg r_in_container "$p")"
  done
  ((n)) || bcc_crosscheck_no_file "$(bcc_msg r_crosscheck_no_ext "$ver" "$pattern")" "$(bcc_msg n_c14_py_check)"
  return 0
}

# One file of a container, read inside it by head through the engine: at most MAX bytes, under
# the time limit, with ENGINE-ARGS keeping the call on the connection that was checked. Exit
# status: head's, through the engine (124 when the time limit was reached).
# Usage: bcc_c14_read ENGINE ID PATH MAX [ENGINE-ARGS...]
bcc_c14_read() {
  timeout -k 2 "$BCC_TIMEOUT" "$1" "${@:5}" exec "$2" head -c "$4" -- "$3" </dev/null 2>/dev/null
}

# Usage: bcc_c14_inspect ENGINE ID NAME IMAGE [ENGINE-ARGS...]
# Only for containers reached through this host (bcc_check_c14); ENGINE-ARGS keep the call on
# the connection that was checked.
bcc_c14_inspect() {
  local engine=$1 id=$2 name=$3 image=$4 out line series="" where ended=0 deb_py_ver=""
  # The extension modules the check script listed (EXT lines): paths and sizes.
  local -a BCC_C14_EXT_P=() BCC_C14_EXT_S=()
  if ! out=$(timeout -k 2 "$BCC_TIMEOUT" "$engine" "${@:5}" exec "$id" sh -c "$BCC_C14_PROBE" </dev/null 2>/dev/null); then
    bcc_skip failed "container $name" "$(bcc_msg skip_c14_exec_failed)"
    return
  fi
  where="container $name ($image)"
  while IFS= read -r line; do
    bcc_split_tab "$line"
    case ${BCC_F[0]} in
      END) ended=1 ;;
      PKGRC)
        # 1 only means a package is not installed; 2 and above: the database was not read.
        [[ ${BCC_F[1]:-} =~ ^[01]$ ]] || bcc_skip failed "container $name (dpkg)" "$(bcc_msg skip_c14_dpkg_failed "${BCC_F[1]:-?}")"
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
        bcc_judge "deb-src:$src" "$series" deb "$srcver" "$(bcc_msg b_deb_container)"
        bcc_add_finding C14 "$BCC_J_STATUS" "$pkg" "$where" "$ver" "$BCC_J_REASON" "$(bcc_c14_next)" "$BCC_J_EVIDENCE" ""
        ;;
      NODE)
        local nver npath=${BCC_F[1]:-}
        nver=$(bcc_semver_parse "${BCC_F[2]:-}") || nver=""
        if [[ -z $nver ]]; then
          bcc_add_finding C14 UNKNOWN node "$where $npath" "" "$(bcc_msg r_version_unknown)" "$(bcc_msg n_check_vendor)" "" ""
          continue
        fi
        bcc_judge node "${nver%%.*}" semver "$nver" "$(bcc_msg b_exec_container "${npath##*/}")"
        bcc_add_finding C14 "$BCC_J_STATUS" node "$where $npath" "$nver" "$BCC_J_REASON $(bcc_msg r_c14_node_vs_os)" \
          "$(bcc_c14_next)" "$BCC_J_EVIDENCE" ""
        ;;
      EXT)
        BCC_C14_EXT_P+=("${BCC_F[1]:-}")
        BCC_C14_EXT_S+=("${BCC_F[2]:-}")
        ;;
      PY)
        local lname meta=${BCC_F[1]:-} pname=${BCC_F[2]:-} pver=${BCC_F[3]:-}
        lname=$(tr '[:upper:]' '[:lower:]' <<<"$pname")
        [[ $lname == brotli || $lname == brotlicffi ]] || continue
        # The distribution's python3-brotli (judged from its PKG line) puts Brotli's metadata
        # here, at its own version; anything else here (brotlicffi, another Brotli by pip
        # --target) is judged by its own version.
        [[ $lname == brotli && -n $deb_py_ver && $pver == "$deb_py_ver" && $meta == /usr/lib/python3/dist-packages/* ]] && continue
        bcc_judge "pypi:$lname" '*' pep440 "$pver" "$(bcc_msg b_metadata_container)"
        # A "fixed" from the metadata is confirmed against the package's own extension modules,
        # as on this host (C06); one that is not confirmed is checked in the image.
        local pnext
        pnext=$(bcc_msg n_rebuild_image)
        if [[ $BCC_J_STATUS == FIXED ]]; then
          bcc_c14_py_crosscheck "$engine" "$id" "$name" "$lname" "${meta%/*/*}" "$pver" "${@:5}"
          if [[ $BCC_J_STATUS == FIXED ]]; then pnext=$BCC_J_NEXT; else pnext=$(bcc_msg n_c14_py_check); fi
        fi
        bcc_add_finding C14 "$BCC_J_STATUS" "$pname" "$where ${meta%/*}" "$pver" "$BCC_J_REASON" "$pnext" "$BCC_J_EVIDENCE" ""
        ;;
    esac
  done <<<"$out"
  ((ended)) || bcc_skip failed "container $name" "$(bcc_msg skip_c14_incomplete)"
}

# C15: who listens beyond loopback? Only a hint for prioritizing.
bcc_check_c15() {
  if ! bcc_have ss; then
    bcc_skip failed C15 "$(bcc_msg skip_no_ss)"
    return
  fi
  local line local_addr procinfo pname pid any_hidden=0 out rc=0
  out=$(bcc_sys ss -ltnpH) || rc=$?
  if ((rc != 0)); then
    bcc_skip failed C15 "$(bcc_msg skip_cmd_failed ss "$rc")"
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
  ((any_hidden == 0 || BCC_IS_ROOT)) || bcc_skip chosen C15 "$(bcc_msg skip_c15_hidden)"
}
