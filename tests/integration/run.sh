#!/usr/bin/env bash
# Integration matrix (docs/design.md 8): build one image per distribution with known
# unfixed/fixed Brotli copies, scan it as root and as an ordinary user, and compare the
# JSON report with the expected verdicts. Needs docker (or podman via ENGINE=podman),
# network access at image build time, and an x86_64 host. Run from the repository: make integration
#   ONLY=debian:12      run one distribution (ONLY=none: only the bash 4.2 check)
#   SKIP_BASH42=1       skip the bash 4.2 check
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
engine=${ENGINE:-docker}
out="$root/tests/tmp/integration"
mkdir -p "$out"
ctx=$(mktemp -d)
c14_name="" c14_stopped="" relay_pid=""
# The end of a log on standard output: CI shows standard output, not the files under $out.
show_tail() { # FILE
  if [[ ! -s $1 ]]; then
    echo "     ($1 is empty or was not written)"
    return 0
  fi
  echo "     last 40 lines of $1:"
  tail -n 40 "$1" | awk '{ print "     | " $0 }'
}
# shellcheck disable=SC2317  # run by the EXIT trap
cleanup() {
  [[ -z $relay_pid ]] || kill "$relay_pid" 2>/dev/null || true
  [[ -z $c14_name ]] || "$engine" rm -f "$c14_name" >/dev/null 2>&1 || true
  [[ -z $c14_stopped ]] || "$engine" rm -f "$c14_stopped" >/dev/null 2>&1 || true
  rm -rf "$ctx"
}
trap cleanup EXIT
cp "$root/tests/integration/Dockerfile" "$root/tests/integration/fetch-node.sh" "$root/dist/brotli-cve-check" "$ctx/"

# BASE | expected C01 verdict for libbrotli1 | expected for python3-brotli
matrix=(
  "ubuntu:22.04|FIXED|FIXED"
  "ubuntu:24.04|FIXED|FIXED"
  "ubuntu:26.04|FIXED|FIXED"
  "debian:12|FIXED|FIXED"
  "debian:13|FIXED|FIXED"
)
if [[ -n ${ONLY:-} ]]; then
  mapfile -t matrix < <(printf '%s\n' "${matrix[@]}" | grep -F "$ONLY")
fi

common=(
  "C04|/opt/node-v22.23.3-linux-x64/bin/node|VULNERABLE"
  "C04|/opt/node-v22.23.4-linux-x64/bin/node|FIXED"
  "C06|/srv/venv-old/|VULNERABLE"
  "C06|/srv/venv-new/|FIXED"
  "C06|/srv/venv-old/|EXPOSURE"
)
servers=(
  "C11|/usr/sbin/nginx|NOT_APPLICABLE"
  "C11|/usr/sbin/apache2|NOT_APPLICABLE"
  "C11|/usr/lib/apache2/modules/mod_brotli.so|NOT_APPLICABLE"
  "C11|/usr/sbin/haproxy|NOT_APPLICABLE"
)

# The fixed script that --inspect-containers runs inside containers (C14), taken from the
# single-file build: it must work with the image's own /bin/sh (dash), not only with bash.
probe=$(bash -c 'eval "$(sed -n "/^BCC_C14_PROBE='"'"'/,/^'"'"'\$/p" "$1")"; printf "%s" "$BCC_C14_PROBE"' _ "$root/dist/brotli-cve-check")
[[ $probe == *'echo END'* ]] || { echo "FAIL: could not extract BCC_C14_PROBE from dist/brotli-cve-check"; exit 1; }
node_path=/opt/node-v22.23.3-linux-x64/bin:/opt/node-v22.23.4-linux-x64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# C14 through a real engine, once per run (with the first image), against a container of the
# image that has both Node.js copies on its PATH and the image's two Python environments in /opt.
# Through the engine's unix socket the tool runs on this host and the check script runs inside
# the container: exit status 1, from the unfixed copies inside it, whatever this host holds. A
# stopped container of the same image is counted and never looked inside, and the stopped
# containers and the images are listed under "Not scanned" (10.24; the numbers depend on the
# host, so only the entries are checked). Found programs on this host are not run: the question
# whether to run them is answered "n" on a pseudo-terminal (--yes would run them on the machine
# that runs the tests). Running the check script inside containers needs no such answer:
# --inspect-containers is the consent.
# Through a TCP relay to the same socket (DOCKER_HOST=tcp://127.0.0.1:PORT) the container is
# listed with the connection and nothing runs inside it (docs/design.md 10.20). On this host the
# exit status of that run would come from what this host holds (a developer's machine or a CI
# runner has Node.js copies of its own, giving 1), so the tool runs in a throw-away container of
# the image instead, with the image's copies hidden: with --inspect-containers the inside could
# not be looked at ("failed"), exit status 2 (10.26); with --containers alone it was left out
# by choice ("chosen"), exit status 0, which shows that the 2 comes from that entry alone.
c14_exit() { # NAME RC WANT REPORT LOG
  if (($2 != $3)) || [[ ! -s $4 ]]; then
    echo "FAIL C14 ($1): the tool exited with $2, expected $3"
    [[ ! -s $4 ]] || python3 -I "$root/tests/integration/assert.py" --summary "$4" || true
    show_tail "$5"
    return 1
  fi
}
c14_run() { # NAME REPORT WANT: the tool on this host
  local name=$1 report=$2 want=$3 rc
  set +e
  printf 'n\n' | script -qec "$(printf '%q ' bash "$root/dist/brotli-cve-check" --json --inspect-containers \
    --roots "$ctx/empty" --timeout 60)>$(printf '%q' "$report")" /dev/null >"$out/c14-$name.log" 2>&1
  rc=$?
  set -e
  c14_exit "$name" "$rc" "$want" "$report" "$out/c14-$name.log"
}
# COMMAND in a throw-away container of TAG with /opt and /srv (the image's copies) hidden, on the
# host network to reach the relay on 127.0.0.1:PORT, as the user running the tests (the relay
# serves no one else), with this host's docker client.
tcp_container() { # TAG PORT COMMAND...
  local tag=$1 port=$2
  shift 2
  "$engine" run --rm --network host --user "$(id -u):$(id -g)" --tmpfs /opt --tmpfs /srv \
    -e HOME=/tmp -e "DOCKER_HOST=tcp://127.0.0.1:$port" \
    -v "$(readlink -f "$(command -v "$engine")"):/usr/local/bin/docker:ro" "$tag" "$@"
}
c14_tcp_run() { # NAME REPORT WANT TAG PORT OPTION: the tool in such a container
  local name=$1 report=$2 want=$3 rc
  set +e
  tcp_container "$4" "$5" brotli-cve-check --json --no-exec "$6" --roots /var/www --timeout 60 \
    >"$report" 2>"$out/c14-$name.log"
  rc=$?
  set -e
  c14_exit "$name" "$rc" "$want" "$report" "$out/c14-$name.log"
}
c14_check() { # TAG BASE
  local tag=$1 base=$2 host sock port report ok=0 run name want option kind shows
  if [[ $engine != docker ]]; then
    echo "SKIP C14 on this host: only with ENGINE=docker (the tool tries docker before podman)"
    return 0
  fi
  if ! command -v script >/dev/null || ! command -v python3 >/dev/null; then
    echo "FAIL C14 on this host: needs script (util-linux) and python3"
    return 1
  fi
  host=$("$engine" context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)
  if [[ $host != unix:///?* ]]; then
    echo "SKIP C14 on this host: docker does not connect through a unix socket here (${host:-not known})"
    return 0
  fi
  sock=${host#unix://}
  mkdir -p "$ctx/empty"
  c14_name="bcc-it-c14-$$"
  if ! "$engine" run -d --rm --name "$c14_name" -e "PATH=$node_path" "$tag" sleep 600 >/dev/null; then
    echo "FAIL C14 on this host: could not start a container of $tag"
    c14_name=""
    return 1
  fi
  # PyPI Brotli 1.2.0 and 1.2.1 (the image's wheels) where the check script looks inside a
  # container, /opt/*/lib/python3*/site-packages: 1.2.1 is FIXED only when its extension module,
  # read through the engine, confirms it (issue #27, docs/design.md 10.29).
  if ! "$engine" exec "$c14_name" cp -a /srv/venv-old /srv/venv-new /opt/; then
    echo "FAIL C14 on this host: could not place the Python environments in the container"
    return 1
  fi
  c14_stopped="$c14_name-stopped"
  if ! "$engine" run --name "$c14_stopped" -e "PATH=$node_path" "$tag" true >/dev/null; then
    echo "FAIL C14 on this host: could not run a container of $tag to its end"
    c14_stopped=""
    return 1
  fi
  report="$out/c14-unix.json"
  if c14_run unix "$report" 1 &&
    python3 -I "$root/tests/integration/assert.py" "$report" \
      "info:C14|Connection of docker: $host (a unix socket on this host)." \
      "C14|container $c14_name ($tag) /opt/node-v22.23.3-linux-x64/bin/node|VULNERABLE" \
      "C14|container $c14_name ($tag) /opt/node-v22.23.4-linux-x64/bin/node|FIXED" \
      "C14|container $c14_name ($tag) /opt/venv-old/|VULNERABLE" \
      "C14|container $c14_name ($tag) /opt/venv-new/|FIXED" \
      "skipped:C14 (stopped containers)|inside of stopped containers (|chosen" \
      "skipped:C14 (images)|inside of images (|chosen" \
      "C14|container $c14_stopped|-"; then
    echo "ok   C14 on this host through $host ($base), exit 1: the check script ran inside the container, PyPI Brotli 1.2.1 confirmed by its module; stopped containers and images only counted"
  else
    echo "     report: $report"
    ok=1
  fi
  python3 -I "$root/tests/integration/relay.py" "$sock" >"$ctx/relay.port" 2>/dev/null &
  relay_pid=$!
  for _ in $(seq 50); do
    [[ -s $ctx/relay.port ]] && break
    sleep 0.1
  done
  port=$(head -n 1 "$ctx/relay.port")
  if [[ ! $port =~ ^[0-9]+$ ]]; then
    echo "FAIL C14 through tcp: the relay to $sock did not start"
    ok=1
  elif ! tcp_container "$tag" "$port" docker version --format '{{.Server.Version}}' >"$out/c14-tcp-client.log" 2>&1; then
    echo "FAIL C14 through tcp://127.0.0.1:$port: this host's docker client, in a container of $tag on the host network, did not reach the engine through the relay (a native engine on this host is needed; not tried with Docker Desktop)"
    show_tail "$out/c14-tcp-client.log"
    ok=1
  else
    # NAME|WANT|OPTION|KIND of the C14 entry under "Not scanned"|what the exit status shows
    for run in "tcp|2|--inspect-containers|failed|the inside could not be looked at" \
      "tcp-control|0|--containers|chosen|the inside was left out by choice, nothing else to review"; do
      IFS='|' read -r name want option kind shows <<<"$run"
      report="$out/c14-$name.json"
      if c14_tcp_run "$name" "$report" "$want" "$tag" "$port" "$option" &&
        python3 -I "$root/tests/integration/assert.py" "$report" \
          "info:C14|Connection of docker: tcp://127.0.0.1:$port. This is not a unix socket on this host" \
          "info:C14|Container $c14_name ($tag) was not inspected" \
          "skipped:C14|docker connects to tcp://127.0.0.1:$port, not to a unix socket on this host|$kind" \
          "C14|container $c14_name ($tag)|-"; then
        echo "ok   C14 through tcp://127.0.0.1:$port from a container of $base, $option, exit $want: listed with the connection, nothing ran inside; $shows ($kind)"
      else
        echo "     report: $report"
        ok=1
      fi
    done
  fi
  kill "$relay_pid" 2>/dev/null || true
  relay_pid=""
  "$engine" rm -f "$c14_name" "$c14_stopped" >/dev/null 2>&1 || true
  c14_name="" c14_stopped=""
  return "$ok"
}

failed=0
c14_done=0
for row in "${matrix[@]}"; do
  IFS='|' read -r base lib py <<<"$row"
  # The ngx_brotli modules are not in Ubuntu 22.04's archive.
  modules=()
  if [[ $base != ubuntu:22.04 ]]; then
    modules=("C11|/usr/lib/nginx/modules/ngx_http_brotli_filter_module.so|NOT_APPLICABLE"
      "C11|/usr/lib/nginx/modules/ngx_http_brotli_static_module.so|NOT_APPLICABLE")
  fi
  tag="bcc-it:${base//[:.]/-}"
  echo "== $base"
  # The whole build output (plain progress, not -q), so that its end shows a failing step's own
  # output and the engine's error.
  build_log="$out/${tag#bcc-it:}-build.log"
  if ! BUILDKIT_PROGRESS=plain "$engine" build --build-arg "BASE=$base" -t "$tag" "$ctx" >"$build_log" 2>&1; then
    echo "FAIL $base: image build failed"
    show_tail "$build_log"
    failed=1
    continue
  fi
  # Found programs run only with consent; without a terminal that is --yes or --no-exec.
  # Both, as root and as an ordinary user: the verdicts must not depend on it.
  for run in "root|no-exec|--no-exec" "root|yes|--yes" "tester|no-exec|--no-exec" "tester|yes|--yes"; do
    IFS='|' read -r who label extra <<<"$run"
    report="$out/${tag#bcc-it:}-$who-$label.json"
    args=(--json --roots '/opt,/srv')
    [[ -n $extra ]] && args+=("$extra")
    set +e
    "$engine" run --rm --user "$who" "$tag" brotli-cve-check "${args[@]}" >"$report"
    rc=$?
    set -e
    if ((rc == 3)); then
      echo "FAIL $base ($who, $label): the tool exited with an error"
      failed=1
      continue
    fi
    if python3 -I "$root/tests/integration/assert.py" "$report" \
      "C01|libbrotli1|$lib" "C01|python3-brotli|$py" "${common[@]}" "${servers[@]}" ${modules[@]+"${modules[@]}"}; then
      echo "ok   $base ($who, $label), exit $rc"
    else
      echo "     report: $report"
      failed=1
    fi
  done
  # C11 on a host that has only the distribution's servers: nothing to review because of them.
  # The copies placed in /opt and /srv on purpose are removed first (in this throw-away container).
  report="$out/${tag#bcc-it:}-servers.json"
  set +e
  "$engine" run --rm "$tag" sh -c 'rm -rf /opt/node-* /srv/venv-* &&
    brotli-cve-check --json --no-exec --roots /var/www' >"$report"
  rc=$?
  set -e
  if ((rc == 0)) && python3 -I "$root/tests/integration/assert.py" "$report" "${servers[@]}" ${modules[@]+"${modules[@]}"}; then
    echo "ok   $base (distribution servers only), exit $rc"
  else
    echo "FAIL $base: distribution servers only, exit $rc, report: $report"
    failed=1
  fi
  # C11 with the real dpkg: an in-house package, and a packaged path overwritten after installation.
  report="$out/${tag#bcc-it:}-unchecked.json"
  set +e
  "$engine" run --rm "$tag" sh -c 'rm -rf /opt/node-* /srv/venv-* &&
    dpkg -i /usr/local/share/acme-internal-nginx.deb >/dev/null &&
    cp /bin/true /usr/sbin/haproxy &&
    brotli-cve-check --json --no-exec --roots /var/www' >"$report"
  rc=$?
  set -e
  if ((rc == 2)) && python3 -I "$root/tests/integration/assert.py" "$report" \
    "C11|/usr/local/sbin/nginx|UNKNOWN" "C11|/usr/sbin/haproxy|UNKNOWN" "C11|/usr/sbin/nginx|NOT_APPLICABLE"; then
    echo "ok   $base (in-house package and overwritten file are UNKNOWN), exit $rc"
  else
    echo "FAIL $base: in-house package, exit $rc, report: $report"
    failed=1
  fi
  # C14's probe in this image's /bin/sh, with both Node.js copies on PATH.
  set +e
  probe_out=$("$engine" run --rm -e "PATH=$node_path" "$tag" sh -c "$probe" 2>&1)
  set -e
  printf '%s\n' "$probe_out" >"$out/${tag#bcc-it:}-probe.txt"
  if grep -q $'^NODE\t/opt/node-v22.23.3-linux-x64/bin/node\tv22.23.3$' <<<"$probe_out" &&
    grep -q $'^NODE\t/opt/node-v22.23.4-linux-x64/bin/node\tv22.23.4$' <<<"$probe_out" &&
    grep -q $'^PKG\tii \tlibbrotli1' <<<"$probe_out" && [[ $(tail -n 1 <<<"$probe_out") == END ]]; then
    echo "ok   $base (C14 probe in /bin/sh: both Node.js copies, packages, END)"
  else
    echo "FAIL $base: C14 probe output:"
    show_tail "$out/${tag#bcc-it:}-probe.txt"
    failed=1
  fi
  if ((!c14_done)); then
    c14_done=1
    c14_check "$tag" "$base" || failed=1
  fi
done

if [[ -n ${SKIP_BASH42:-} ]]; then
  exit "$failed"
fi

# bash 4.2 (the oldest supported) with GNU tools: a PyPI Brotli 1.2.0 must be found and judged
# (exit 1), and the JSON must parse.
echo "== bash:4.2"
set +e
"$engine" run --rm -v "$root/dist/brotli-cve-check:/bcc:ro" bash:4.2 sh -c '
  apk add -q --no-cache coreutils findutils grep sed gawk binutils >/dev/null &&
  mkdir -p /srv/venv/lib/python3.12/site-packages/Brotli-1.2.0.dist-info &&
  printf "Name: Brotli\nVersion: 1.2.0\n" >/srv/venv/lib/python3.12/site-packages/Brotli-1.2.0.dist-info/METADATA &&
  bash /bcc --json --roots /srv,/usr --timeout 60 --yes' >"$out/bash42.json"
rc=$?
set -e
if ((rc == 1)) && python3 -I "$root/tests/integration/assert.py" "$out/bash42.json" "C06|/srv/venv/|VULNERABLE"; then
  echo "ok   bash 4.2, exit $rc"
else
  echo "FAIL bash 4.2 (exit $rc), report: $out/bash42.json"
  failed=1
fi

exit "$failed"
