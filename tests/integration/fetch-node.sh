#!/bin/sh
# Download an official Node.js linux-x64 tarball, verify it against the release's
# SHASUMS256.txt, and unpack it to /opt/node-v<version>-linux-x64. Used at image build time.
set -eu
v=$1
name="node-v$v-linux-x64.tar.xz"
work=$(mktemp -d)
cd "$work"
curl -fsSLO "https://nodejs.org/dist/v$v/$name"
curl -fsSLO "https://nodejs.org/dist/v$v/SHASUMS256.txt"
grep " $name\$" SHASUMS256.txt | sha256sum -c -
tar -xJf "$name" -C /opt
cd /
rm -rf "$work"
