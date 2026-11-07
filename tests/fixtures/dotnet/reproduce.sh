#!/usr/bin/env bash
# Reproduce tests/fixtures/dotnet/*.txt (README.md) in WORKDIR: download Microsoft's .NET runtime
# archives and PowerShell's (self-contained), check their published hashes, take out the
# System.IO.Compression native library, and write the lines the tool reads to WORKDIR/fixtures/.
# Nothing downloaded is executed; it is only read. No Brotli data of any kind is used.
# The Ubuntu file (ubuntu-24.04-*.txt) comes from `apt-get install dotnet-runtime-8.0` in an
# ubuntu:24.04 container instead: run extract_lines on
# /usr/lib/dotnet/shared/Microsoft.NETCore.App/8.0.33/libSystem.IO.Compression.Native.so.
#
# Usage: tests/fixtures/dotnet/reproduce.sh WORKDIR
# Needs: curl, tar, sha512sum, sha256sum, strings.
set -euo pipefail

work=${1:?usage: reproduce.sh WORKDIR}
mkdir -p "$work"/{dl,x,fixtures}
work=$(cd "$work" && pwd)
dict=timedownlifeleftbackcodedatashowonlysitecity

extract_lines() { # NAME FILE
  {
    LC_ALL=C strings -a "$2" | grep -E '^(_ERROR_[A-Z0-9_]+|BrotliDecoder[A-Za-z]+|@\(#\)Version .*)$' | LC_ALL=C sort -u
    LC_ALL=C strings -a "$2" | grep -o "$dict" || true
  } >"$work/fixtures/$1.txt"
  printf '%-40s _ERROR_FORMAT_*=%-3s BLOCK_SWITCH=%s %s\n' "$1" \
    "$(grep -c '^_ERROR_FORMAT_' "$work/fixtures/$1.txt" || true)" \
    "$(grep -cx '_ERROR_FORMAT_BLOCK_SWITCH' "$work/fixtures/$1.txt" || true)" \
    "$(grep -m 1 '^@' "$work/fixtures/$1.txt" || true)"
}

# version and SHA-512, from release-notes/<line>/releases.json of dotnet/core (2026-11-07)
while read -r v sum; do
  f=dotnet-runtime-$v-linux-x64.tar.gz
  [[ -f $work/dl/$f ]] || curl -fsSL -o "$work/dl/$f" "https://builds.dotnet.microsoft.com/dotnet/Runtime/$v/$f"
  echo "$sum  $work/dl/$f" | sha512sum -c --quiet
  mkdir -p "$work/x/$v"
  name=libSystem.IO.Compression.Native.so
  case $v in 2.* | 3.*) name=System.IO.Compression.Native.so ;; esac
  tar -xzf "$work/dl/$f" -C "$work/x/$v" "./shared/Microsoft.NETCore.App/$v/$name"
  extract_lines "microsoft-$v" "$work/x/$v/shared/Microsoft.NETCore.App/$v/$name"
done <<'LIST'
2.1.30 b7433c9f03f7363759a044b50d8cca9486cfe402fdf62163696ba6a172e9839a140553e3d3298bb75c89dda2f6f4bec294847411f3fc2796fa4881a2b01a7178
3.1.32 a1de9bbc3d2e3a4f5f52b7742c678b182a58a724d36232997511e390027044d60144a7e010a29d6ee016ec91f2911daef28ac5712a827fff8bdde73314b7e002
5.0.17 a9c4784930a977abbc42aff1337dda06ec588c1ec4769a59f9fcab4d5df4fc9efe65f8e61e5433db078f67a94ea2dfe870c32c482a50d4c16283ffacacff4261
6.0.36 afb6018fcabec468ccd7ae2f1131d8c9de7f4de7645b8f0c223efbbdbfdc515fb0642a399ebfe372c02044416c4cae463c9c802cd156b9da4181efff0e33ee94
7.0.20 87855297338555a7b577d7e314e5dbf2c2350f8c867a489cd1e535634bad5c123a1871464d37fc9421837ff5d426c2eadecbe0f60bbf3fd32bc2461f47790a40
8.0.32 639a17d84e4d52fecd62c7d4e528e7bc0ae3c9860de2530cb41a2ee7196b69ea18271d8795849180742770e25b4f913df292a5a236fa197cf5d3cd0ec5ba665f
8.0.33 b314039d337a8c5c4be6a6f99712a2618cbeb5e1ab7cac7a5c1cbf1c97bd355f5d116b9932a8cfc604ac7849f74638896eba0534892c6518311908aba29b4f7b
9.0.21 6faa847e25a02b87c737c8222c6f5f9fd5f20945b7d239a080a7e3d99b97af48e6b6121aa55dee2e797cc89fe7eb97d235e12422b1b22786cbf169420156ae1e
9.0.22 c6f039209e4b5824ac57837ff41e95f6ab3c79b1a118f4a8539707a8381df46d3b2ed98bbd893cc850c680feb18c64f2b2308c81f5f60e50927a76b295e5c402
10.0.13 9574d95364110409416735e7842796f8d614c21d74cb25d204a3e4cfd11b2c05efdf19ca89b8069650a04f64add2705967dcb04b8665a36d7a3f30a5d8c05afe
10.0.14 634326028645f38731c8c4e71a68356e4ca0d6b6607139a234ab760687f742063edaf33a1f20dda615742d2dc8300ca2ff857619d51fbb38090383b71334af89
LIST

# PowerShell 7.4.21 (.NET 8.0.32) and 7.4.22 (.NET 8.0.33): self-contained; SHA-256 as GitHub gives it.
while read -r v sum; do
  f=powershell-$v-linux-x64.tar.gz
  [[ -f $work/dl/$f ]] || curl -fsSL -o "$work/dl/$f" "https://github.com/PowerShell/PowerShell/releases/download/v$v/$f"
  echo "$sum  $work/dl/$f" | sha256sum -c --quiet
  mkdir -p "$work/x/ps-$v"
  tar -xzf "$work/dl/$f" -C "$work/x/ps-$v" libSystem.IO.Compression.Native.so
  extract_lines "powershell-$v" "$work/x/ps-$v/libSystem.IO.Compression.Native.so"
done <<'LIST'
7.4.21 3fc5e1567c450bd7bd5ae69ebb0a9a4a4e0418bbc36b0232cf6dd547f0bfc0eb
7.4.22 9de443bef974f219c98a33b0f4096aace7f30b42188f37a1b14c5da7e82c8a6a
LIST
