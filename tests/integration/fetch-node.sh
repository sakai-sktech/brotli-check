#!/bin/sh
# Download an official Node.js linux-x64 tarball, verify it against the release's
# SHASUMS256.txt, and unpack it to /opt/node-v<version>-linux-x64. Used at image build time.
# A download that fails for a passing reason (a time-out, a refused connection, HTTP 408, 429 or
# 5xx) is tried again; an HTTP error such as 404 is not. Each try has a time limit, and no new try
# starts after 10 minutes, so a stalled mirror fails the build instead of holding it. Errors and
# the notes on each new try go to the build log (no progress meter).
set -eu
v=$1
name="node-v$v-linux-x64.tar.xz"
work=$(mktemp -d)
cd "$work"
fetch() {
  curl -fLO --no-progress-meter --connect-timeout 30 --max-time 300 \
    --retry 4 --retry-connrefused --retry-max-time 600 "$1"
}
fetch "https://nodejs.org/dist/v$v/$name"
fetch "https://nodejs.org/dist/v$v/SHASUMS256.txt"
grep " $name\$" SHASUMS256.txt | sha256sum -c -
tar -xJf "$name" -C /opt
cd /
rm -rf "$work"
