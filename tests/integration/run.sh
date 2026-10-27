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
trap 'rm -rf "$ctx"' EXIT
cp "$root/tests/integration/Dockerfile" "$root/tests/integration/fetch-node.sh" "$root/dist/brotli-cve-check" "$ctx/"

# BASE | expected C01 verdict for libbrotli1 | expected for python3-brotli
matrix=(
  "ubuntu:22.04|NO_FIX_AVAILABLE|NO_FIX_AVAILABLE"
  "ubuntu:24.04|NO_FIX_AVAILABLE|NO_FIX_AVAILABLE"
  "ubuntu:26.04|NO_FIX_AVAILABLE|NO_FIX_AVAILABLE"
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

# The fixed script that --inspect-containers runs inside containers (C14), taken from the
# single-file build: it must work with the image's own /bin/sh (dash), not only with bash.
probe=$(bash -c 'eval "$(sed -n "/^BCC_C14_PROBE='"'"'/,/^'"'"'\$/p" "$1")"; printf "%s" "$BCC_C14_PROBE"' _ "$root/dist/brotli-cve-check")
[[ $probe == *'echo END'* ]] || { echo "FAIL: could not extract BCC_C14_PROBE from dist/brotli-cve-check"; exit 1; }
node_path=/opt/node-v22.23.3-linux-x64/bin:/opt/node-v22.23.4-linux-x64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

failed=0
for row in "${matrix[@]}"; do
  IFS='|' read -r base lib py <<<"$row"
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
      "C01|libbrotli1|$lib" "C01|python3-brotli|$py" "${common[@]}"; then
      echo "ok   $base ($who, $label), exit $rc"
    else
      echo "     report: $report"
      failed=1
    fi
  done
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
