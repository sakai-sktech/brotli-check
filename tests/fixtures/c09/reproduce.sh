#!/usr/bin/env bash
# Reproduce the C09 verification (tests/fixtures/c09/README.md) in WORKDIR:
#   1. build Brotli 1.2.0 and 1.2.1 as a shared library (cmake) and as static archives
#      linked into two small programs (-O2 and LTO + gc-sections, stripped or not);
#   2. with --binaries, also download official Node.js tarballs and PyPI wheels;
#   3. write the "_ERROR_*" string list of every artifact to WORKDIR/fixtures/.
# Nothing is executed except compilers; downloaded binaries are only read.
# No Brotli data of any kind is produced or used.
#
# Usage: tests/fixtures/c09/reproduce.sh WORKDIR [--binaries]
# Needs: curl, tar, cmake, gcc, gcc-ar, strip, strings; with --binaries also xz, unzip, python3.
set -euo pipefail

work=${1:?usage: reproduce.sh WORKDIR [--binaries]}
binaries=${2:-}
mkdir -p "$work"/{src,build,dl,fixtures}
work=$(cd "$work" && pwd)

extract_names() { # NAME FILE
  strings -a "$2" | grep -E '^_ERROR_' | sort -u >"$work/fixtures/$1.txt" || true
  printf '%-34s _ERROR_FORMAT_*=%-3s BLOCK_SWITCH=%s\n' "$1" \
    "$(grep -c '^_ERROR_FORMAT_' "$work/fixtures/$1.txt" || true)" \
    "$(grep -cx '_ERROR_FORMAT_BLOCK_SWITCH' "$work/fixtures/$1.txt" || true)"
}

cat >"$work/src/p1.c" <<'EOF'
/* Links BrotliDecoderDecompress only (never run). */
#include <brotli/decode.h>
#include <stddef.h>
int main(void) {
  const uint8_t in[1] = {0};
  uint8_t out[1];
  size_t n = sizeof out;
  return (int)BrotliDecoderDecompress(0, in, &n, out);
}
EOF
cat >"$work/src/p2.c" <<'EOF'
/* Links the streaming API and BrotliDecoderErrorString (never run). */
#include <brotli/decode.h>
#include <stdio.h>
int main(void) {
  BrotliDecoderState *s = BrotliDecoderCreateInstance(0, 0, 0);
  size_t ai = 0, ao = 0;
  const uint8_t *pi = 0;
  uint8_t *po = 0;
  BrotliDecoderDecompressStream(s, &ai, &pi, &ao, &po, 0);
  puts(BrotliDecoderErrorString(BrotliDecoderGetErrorCode(s)));
  BrotliDecoderDestroyInstance(s);
  return 0;
}
EOF

for v in 1.2.0 1.2.1; do
  tgz="$work/dl/brotli-$v.tar.gz"
  [[ -f $tgz ]] || curl -fsSL -o "$tgz" "https://github.com/google/brotli/archive/refs/tags/v$v.tar.gz"
  sha256sum "$tgz"
  rm -rf "$work/src/brotli-$v"
  tar -xzf "$tgz" -C "$work/src"
  s="$work/src/brotli-$v"

  b="$work/build/$v-shared"
  cmake -S "$s" -B "$b" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON >/dev/null
  cmake --build "$b" --target brotlidec -j >/dev/null
  lib=$(find "$b" -name 'libbrotlidec.so.*.*' -type f | head -n 1)
  extract_names "shared-$v-nostrip" "$lib"
  cp "$lib" "$b/stripped.so"
  strip --strip-all "$b/stripped.so"
  extract_names "shared-$v-strip" "$b/stripped.so"

  for opt in O2 LTO; do
    d="$work/build/$v-$opt"
    rm -rf "$d"
    mkdir -p "$d"
    if [[ $opt == O2 ]]; then
      cflags=(-O2) ldflags=() ar=ar
    else
      cflags=(-O2 -flto -ffunction-sections -fdata-sections) ldflags=(-flto '-Wl,--gc-sections') ar=gcc-ar
    fi
    for c in "$s"/c/common/*.c "$s"/c/dec/*.c; do
      gcc "${cflags[@]}" -I"$s/c/include" -c "$c" -o "$d/$(basename "$c" .c).o"
    done
    "$ar" rcs "$d/libbrotlidec.a" "$d"/*.o
    for p in p1 p2; do
      gcc "${cflags[@]}" -I"$s/c/include" "$work/src/$p.c" "${ldflags[@]}" "$d/libbrotlidec.a" -lm -o "$d/$p"
      extract_names "static-$v-$opt-$p-nostrip" "$d/$p"
      cp "$d/$p" "$d/$p-strip"
      strip --strip-all "$d/$p-strip"
      extract_names "static-$v-$opt-$p-strip" "$d/$p-strip"
    done
  done
done

[[ $binaries == --binaries ]] || exit 0

for v in 22.23.3 22.23.4 24.22.0 24.22.1; do
  d="$work/dl/node-v$v"
  mkdir -p "$d"
  name="node-v$v-linux-x64.tar.xz"
  [[ -f $d/$name ]] || curl -fsSL -o "$d/$name" "https://nodejs.org/dist/v$v/$name"
  curl -fsSL -o "$d/SHASUMS256.txt" "https://nodejs.org/dist/v$v/SHASUMS256.txt"
  (cd "$d" && grep " $name\$" SHASUMS256.txt | sha256sum -c -)
  tar -xJf "$d/$name" -C "$d" "node-v$v-linux-x64/bin/node"
  extract_names "node-v$v" "$d/node-v$v-linux-x64/bin/node"
done

# Wheels, verified against the digests PyPI publishes for each file.
wheel() { # PACKAGE VERSION FILENAME-GLOB NAME
  local d="$work/dl/pypi-$1-$2" url sha
  mkdir -p "$d"
  read -r url sha < <(python3 -I - "$1" "$2" "$3" <<'EOF'
import fnmatch, json, sys, urllib.request
pkg, ver, pattern = sys.argv[1:4]
meta = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/{ver}/json"))
for f in meta["urls"]:
    if fnmatch.fnmatch(f["filename"], pattern):
        print(f["url"], f["digests"]["sha256"])
        break
EOF
  )
  curl -fsSL -o "$d/w.whl" "$url"
  echo "$sha  $d/w.whl" | sha256sum -c -
  unzip -o -q "$d/w.whl" -d "$d/x"
  extract_names "$4" "$(find "$d/x" -name '*.so' | head -n 1)"
}
wheel Brotli 1.2.0 'brotli-1.2.0-cp312-cp312-manylinux*x86_64*.whl' pypi-Brotli-1.2.0
wheel Brotli 1.2.1 'brotli-1.2.1-cp312-cp312-manylinux*x86_64*.whl' pypi-Brotli-1.2.1
for v in 1.2.0.0 1.2.0.1 1.2.0.2 1.2.1.0; do
  wheel brotlicffi "$v" "brotlicffi-$v-*abi3-manylinux*x86_64*.whl" "pypi-brotlicffi-$v"
done
