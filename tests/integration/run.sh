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
c14_name="" relay_pid=""
# shellcheck disable=SC2317  # run by the EXIT trap
cleanup() {
  [[ -z $relay_pid ]] || kill "$relay_pid" 2>/dev/null || true
  [[ -z $c14_name ]] || "$engine" rm -f "$c14_name" >/dev/null 2>&1 || true
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

# C14 through a real engine, once per run (with the first image): the tool runs on this host
# against a container of the image that has both Node.js copies on its PATH. Through the
# engine's unix socket the check script runs inside it; through a TCP relay to the same socket
# (DOCKER_HOST=tcp://127.0.0.1:PORT) the container is listed with the connection, and nothing
# runs inside it (docs/design.md 10.20). Found programs on this host are not run: the question
# whether to run them is answered "n" on a pseudo-terminal (--yes would run them on the machine
# that runs the tests). Running the check script inside containers needs no such answer:
# --inspect-containers is the consent.
c14_run() { # NAME REPORT [ENV-ASSIGNMENT...]
  local name=$1 report=$2 rc
  shift 2
  set +e
  printf 'n\n' | script -qec "$(printf '%q ' env "$@" bash "$root/dist/brotli-cve-check" --json --inspect-containers \
    --roots "$ctx/empty" --timeout 60)>$(printf '%q' "$report")" /dev/null >"$out/c14-$name.log" 2>&1
  rc=$?
  set -e
  if ((rc == 3)) || [[ ! -s $report ]]; then
    echo "FAIL C14 ($name): the tool exited with $rc (see $out/c14-$name.log)"
    return 1
  fi
}
c14_check() { # TAG BASE
  local tag=$1 base=$2 host sock port report ok=0
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
  report="$out/c14-unix.json"
  if c14_run unix "$report" &&
    python3 -I "$root/tests/integration/assert.py" "$report" \
      "info:C14|Connection of docker: $host (a unix socket on this host)." \
      "C14|container $c14_name ($tag) /opt/node-v22.23.3-linux-x64/bin/node|VULNERABLE" \
      "C14|container $c14_name ($tag) /opt/node-v22.23.4-linux-x64/bin/node|FIXED"; then
    echo "ok   C14 on this host through $host ($base): the check script ran inside the container"
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
  report="$out/c14-tcp.json"
  if [[ $port =~ ^[0-9]+$ ]] && c14_run tcp "$report" "DOCKER_HOST=tcp://127.0.0.1:$port" &&
    python3 -I "$root/tests/integration/assert.py" "$report" \
      "info:C14|Connection of docker: tcp://127.0.0.1:$port. This is not a unix socket on this host" \
      "info:C14|Container $c14_name ($tag) was not inspected" \
      "skipped:C14|docker connects to tcp://127.0.0.1:$port, not to a unix socket on this host" \
      "C14|container $c14_name ($tag)|-"; then
    echo "ok   C14 on this host through tcp://127.0.0.1:$port ($base): listed with the connection, nothing ran inside"
  else
    echo "FAIL C14 through tcp://127.0.0.1:${port:-?} (report: $report)"
    ok=1
  fi
  kill "$relay_pid" 2>/dev/null || true
  relay_pid=""
  "$engine" rm -f "$c14_name" >/dev/null 2>&1 || true
  c14_name=""
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
  if ! "$engine" build -q --build-arg "BASE=$base" -t "$tag" "$ctx" >"$out/${tag#bcc-it:}-build.log" 2>&1; then
    echo "FAIL $base: image build failed (see $out/${tag#bcc-it:}-build.log)"
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
    echo "FAIL $base: C14 probe output: $out/${tag#bcc-it:}-probe.txt"
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
