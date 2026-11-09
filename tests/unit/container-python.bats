#!/usr/bin/env bats
# Issue #27 (docs/design.md 10.29): PyPI's Brotli and brotlicffi inside a container. A "fixed"
# version from the metadata is confirmed as on this host (C06): against the package's own
# extension modules, which the check script lists with their sizes and which are read inside
# the container with head through the engine (on the context that was checked), up to the
# size limit and under the time limit, and judged here. No module, one not read to the end and
# one not read at all each leave the line UNKNOWN with its reason.
# shellcheck disable=SC2317  # stand-ins for library functions are called by the code under test

load test_helper

setup() {
  load_libs
  setup_fakebin
  D="$BATS_TEST_TMPDIR/docker"
  mkdir -p "$D/root"
  export BCC_FAKE_DOCKER=$D
  BCC_CONTAINERS=1
  BCC_INSPECT_CONTAINERS=1
  SITE=/usr/local/lib/python3.12/site-packages
  MOD=$SITE/_brotli.cpython-312-x86_64-linux-gnu.so
  CFFI=$SITE/brotlicffi/_brotlicffi.abi3.so
  # A fake docker on a unix socket with one running container. "exec ID sh -c ..." prints
  # $D/probe (what the check script would print); "exec ID head -c N -- PATH" reads PATH under
  # $D/root, after sleeping $D/head-sleep seconds or failing with $D/head-rc, if present. Every
  # call is logged.
  cat >"$FAKEBIN/docker" <<'EOS'
#!/bin/sh
D=$BCC_FAKE_DOCKER
echo "$*" >>"$D/log"
[ "$1" = --context ] && shift 2
case $1 in
  context) printf 'default %s\n' "${DOCKER_HOST:-unix:///var/run/docker.sock}" ;;
  ps) if [ "$2" = -a ]; then printf '0123abcd\n'; else printf '0123abcd\timg:1\tweb\n'; fi ;;
  images) ;;
  exec)
    case $3 in
      sh) cat "$D/probe" ;;
      head)
        if [ -f "$D/head-sleep" ]; then exec sleep "$(cat "$D/head-sleep")"; fi
        if [ -f "$D/head-rc" ]; then exit "$(cat "$D/head-rc")"; fi
        [ "$4 $6" = "-c --" ] || exit 99
        exec head -c "$5" -- "$D/root$7"
        ;;
    esac
    ;;
esac
EOS
  chmod +x "$FAKEBIN/docker"
}

FOUND='Found: the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH) among the decoder strings of'
UNSEEN='Not determined: whether all decoder code in the file is fixed (the linker merges equal strings, so an unfixed copy sharing them would not show).'
NEXT_FIXED='No update needed for this line (other lines, and the ranges not scanned or that could not be scanned, are separate).'
NEXT_IMAGE='Updating the host does not fix containers: check this package in the image, or ask whoever built the image; if it is not a fixed version, install one in the image, rebuild it and redeploy.'

# module PATH FIXTURE: a module inside the container with these strings (NUL-separated).
module() {
  mkdir -p "$(dirname "$D/root$1")"
  printf '\177ELF\002\001\001\000' >"$D/root$1"
  tr '\n' '\0' <"$FIXTURES/c09/$2" >>"$D/root$1"
}
# The check script's line for a module: its path and size, as wc -c gives it.
ext() { printf 'EXT\t%s\t%s\n' "$1" "${2:-$(wc -c <"$D/root$1")}"; }
py() { printf 'PY\t%s/%s-%s.dist-info/METADATA\t%s\t%s\n' "$1" "$2" "$3" "$2" "$3"; }
probe() {
  {
    printf 'OS\tdebian\ttrixie\t\nPKGRC\t1\n'
    cat
    printf 'END\n'
  } >"$D/probe"
}

reason_of() {
  local f
  for f in "${BCC_FINDINGS[@]}"; do
    bcc_split_tab "$f"
    [[ ${BCC_F[2]} == "$1" ]] && { printf '%s' "${BCC_F[5]}"; return 0; }
  done
  return 1
}
next_of() {
  local f
  for f in "${BCC_FINDINGS[@]}"; do
    bcc_split_tab "$f"
    [[ ${BCC_F[2]} == "$1" ]] && { printf '%s' "${BCC_F[6]}"; return 0; }
  done
  return 1
}
skipped_text() { printf '%s\n' ${BCC_SKIPPED[@]+"${BCC_SKIPPED[@]}"}; }
# bats does not fail a test on "! cmd"; these do.
nothing_read() { if grep -q -- ' exec 0123abcd head ' "$D/log"; then return 1; fi; }

@test "#27 Brotli 1.2.1 whose own module shows the fix is FIXED, read with head on the checked context" {
  module "$MOD" pypi-Brotli-1.2.1.txt
  { ext "$MOD"; py "$SITE" Brotli 1.2.1; } | probe
  bcc_check_c14
  run findings_brief
  [ "$output" = "FIXED|C14|Brotli|container web (img:1) $SITE/Brotli-1.2.1.dist-info|1.2.1" ]
  [ "$(reason_of Brotli)" = "At or above the fixed version 1.2.1 (version from the package metadata inside the container). $FOUND $MOD inside the container. $UNSEEN" ]
  [ "$(next_of Brotli)" = "$NEXT_FIXED" ]
  # At most the size limit, after "--", on the context that was checked; nothing else was read.
  grep -qxF -- "--context default exec 0123abcd head -c 67108864 -- $MOD" "$D/log"
  [ "$(grep -c ' exec 0123abcd head ' "$D/log")" -eq 1 ]
  [ -z "$(skipped_text)" ]
}

@test "#27 Brotli 1.2.0 stays VULNERABLE, with the rebuild, and its module is not read" {
  module "$MOD" pypi-Brotli-1.2.0.txt
  { ext "$MOD"; py "$SITE" Brotli 1.2.0; } | probe
  bcc_check_c14
  run findings_brief
  [ "$output" = "VULNERABLE|C14|Brotli|container web (img:1) $SITE/Brotli-1.2.0.dist-info|1.2.0" ]
  [[ $(next_of Brotli) == *"rebuild the image"* ]]
  nothing_read
}

@test "#27 brotlicffi is compared with brotlicffi/_brotlicffi*.so only, not with a _brotli module beside it" {
  module "$MOD" pypi-Brotli-1.2.0.txt
  module "$CFFI" pypi-brotlicffi-1.2.1.0.txt
  { ext "$MOD"; ext "$CFFI"; py "$SITE" brotlicffi 1.2.1.0; } | probe
  bcc_check_c14
  run findings_brief
  [ "$output" = "FIXED|C14|brotlicffi|container web (img:1) $SITE/brotlicffi-1.2.1.0.dist-info|1.2.1.0" ]
  [[ $(reason_of brotlicffi) == *"$FOUND $CFFI inside the container. $UNSEEN" ]]
  grep -q -- " head -c 67108864 -- $CFFI\$" "$D/log"
  [ "$(grep -c ' exec 0123abcd head ' "$D/log")" -eq 1 ]
}

@test "#27 Brotli is not confirmed by a brotlicffi module: UNKNOWN, no module of its own" {
  module "$CFFI" pypi-brotlicffi-1.2.1.0.txt
  { ext "$CFFI"; py "$SITE" Brotli 1.2.1; } | probe
  bcc_check_c14
  [ "$(reason_of Brotli)" = "At or above the fixed version 1.2.1 (version from the package metadata inside the container). Not confirmed by a file: the metadata says version 1.2.1, but no extension module was found to compare (_brotli.*so)." ]
  [ "$(next_of Brotli)" = "$NEXT_IMAGE" ]
  nothing_read
}

@test "#27 a module whose strings lack the fix: UNKNOWN, the version may be wrong, checked in the image" {
  module "$MOD" pypi-Brotli-1.2.0.txt
  { ext "$MOD"; py "$SITE" Brotli 1.2.1; } | probe
  bcc_check_c14
  run findings_brief
  [[ $output == "UNKNOWN|C14|Brotli|"* ]]
  [[ $(reason_of Brotli) == *"But the decoder in the file lacks the fix's error name (_ERROR_FORMAT_BLOCK_SWITCH): the version may be wrong." ]]
  [ "$(next_of Brotli)" = "$NEXT_IMAGE" ]
}

@test "#27 two modules: as on this host, the first one that does not confirm decides" {
  local old=$SITE/_brotli.cpython-311-x86_64-linux-gnu.so
  module "$MOD" pypi-Brotli-1.2.1.txt
  module "$old" pypi-Brotli-1.2.0.txt
  { ext "$MOD"; ext "$old"; py "$SITE" Brotli 1.2.1; } | probe
  bcc_check_c14
  [[ $(reason_of Brotli) == *"$FOUND $MOD inside the container. But the decoder in the file lacks"* ]]
  [ "$(grep -c ' exec 0123abcd head ' "$D/log")" -eq 2 ]
}

@test "#27 a module that does not confirm stops the reading: the next one is not read" {
  local other=$SITE/_brotli.abi3.so
  module "$MOD" pypi-Brotli-1.2.0.txt
  module "$other" pypi-Brotli-1.2.1.txt
  { ext "$MOD"; ext "$other"; py "$SITE" Brotli 1.2.1; } | probe
  bcc_check_c14
  [[ $(reason_of Brotli) == *"But the decoder in the file lacks"* ]]
  [[ $(reason_of Brotli) != *"$other"* ]]
  [ "$(grep -c ' exec 0123abcd head ' "$D/log")" -eq 1 ]
}

@test "#27 two fixed modules give one sentence naming both" {
  local other=$SITE/_brotli.abi3.so
  module "$MOD" pypi-Brotli-1.2.1.txt
  module "$other" pypi-Brotli-1.2.1.txt
  { ext "$MOD"; ext "$other"; py "$SITE" Brotli 1.2.1; } | probe
  bcc_check_c14
  [ "$(reason_of Brotli)" = "At or above the fixed version 1.2.1 (version from the package metadata inside the container). $FOUND $MOD inside the container, $other inside the container. $UNSEEN" ]
}

@test "#27 a module listed in another directory or deeper in the site is not this package's" {
  module "$SITE/sub/_brotli.cpython-312-x86_64-linux-gnu.so" pypi-Brotli-1.2.1.txt
  module "/usr/lib/python3/dist-packages/_brotli.cpython-312-x86_64-linux-gnu.so" pypi-Brotli-1.2.1.txt
  module "/usr/local/lib/python3.12/site-packages-old/_brotli.cpython-312-x86_64-linux-gnu.so" pypi-Brotli-1.2.1.txt
  {
    ext "$SITE/sub/_brotli.cpython-312-x86_64-linux-gnu.so"
    ext /usr/lib/python3/dist-packages/_brotli.cpython-312-x86_64-linux-gnu.so
    ext /usr/local/lib/python3.12/site-packages-old/_brotli.cpython-312-x86_64-linux-gnu.so
    py "$SITE" Brotli 1.2.1
  } | probe
  bcc_check_c14
  [[ $(reason_of Brotli) == *"no extension module was found to compare (_brotli.*so)." ]]
  nothing_read
}

@test "#27 a site path with spaces and pattern characters is taken literally and passed to head as one argument" {
  local site='/opt/my [app]*/lib/python3.12/site-packages'
  module "$site/_brotli.abi3.so" pypi-Brotli-1.2.1.txt
  { ext "$site/_brotli.abi3.so"; py "$site" Brotli 1.2.1; } | probe
  bcc_check_c14
  run findings_brief
  [[ $output == "FIXED|C14|Brotli|"* ]]
  grep -qxF -- "--context default exec 0123abcd head -c 67108864 -- $site/_brotli.abi3.so" "$D/log"
}

@test "#27 a module over the size limit is not read: UNKNOWN, could not be read to the end, and listed" {
  module "$MOD" pypi-Brotli-1.2.1.txt
  { ext "$MOD" 67108865; py "$SITE" Brotli 1.2.1; } | probe
  bcc_check_c14
  [[ $(reason_of Brotli) == *"Not confirmed by the file: it could not be read to the end (more than 64 MiB, or the time limit)." ]]
  [ "$(next_of Brotli)" = "$NEXT_IMAGE" ]
  nothing_read
  run skipped_text
  [[ $output == *"container web $MOD"$'\t'"could not be read to the end (more than 64 MiB, or the time limit); its strings were not judged"$'\t'"failed"* ]]
}

@test "#27 a module at exactly the size limit is read" {
  module "$MOD" pypi-Brotli-1.2.1.txt
  BCC_MAX_ELF_MB=1
  # The fake head reads the real file; the size the check script gave is what decides.
  { ext "$MOD" 1048576; py "$SITE" Brotli 1.2.1; } | probe
  bcc_check_c14
  run findings_brief
  [[ $output == "FIXED|C14|Brotli|"* ]]
  grep -q -- " head -c 1048576 -- $MOD\$" "$D/log"
}

@test "#27 a read that fails inside the container (status 127): UNKNOWN, listed with the status" {
  module "$MOD" pypi-Brotli-1.2.1.txt
  { ext "$MOD"; py "$SITE" Brotli 1.2.1; } | probe
  echo 127 >"$D/head-rc"
  bcc_check_c14
  [ "$(reason_of Brotli)" = "At or above the fixed version 1.2.1 (version from the package metadata inside the container). Not confirmed by the file: $MOD inside the container could not be read." ]
  [ "$(next_of Brotli)" = "$NEXT_IMAGE" ]
  run skipped_text
  [[ $output == *"container web $MOD"$'\t'"could not be read inside the container through the engine (status 127); its strings were not judged"$'\t'"failed"* ]]
}

@test "#27 a read that stops at the time limit: UNKNOWN, could not be read to the end, and listed" {
  module "$MOD" pypi-Brotli-1.2.1.txt
  { ext "$MOD"; py "$SITE" Brotli 1.2.1; } | probe
  echo 30 >"$D/head-sleep"
  BCC_TIMEOUT=1
  SECONDS=0
  bcc_check_c14
  ((SECONDS < 10))
  [[ $(reason_of Brotli) == *"Not confirmed by the file: it could not be read to the end (more than 64 MiB, or the time limit)." ]]
  run skipped_text
  [[ $output == *"container web $MOD"$'\t'"could not be read to the end"*$'\t'"failed"* ]]
}

@test "#27 a module whose size the check script could not take is not read: UNKNOWN, listed" {
  module "$MOD" pypi-Brotli-1.2.1.txt
  { printf 'EXT\t%s\t\n' "$MOD"; py "$SITE" Brotli 1.2.1; } | probe
  bcc_check_c14
  [[ $(reason_of Brotli) == *"Not confirmed by the file: $MOD inside the container could not be read." ]]
  nothing_read
  run skipped_text
  [[ $output == *"container web $MOD"$'\t'"could not be read inside the container through the engine (status ?)"* ]]
}

@test "#27 a size with spaces around it (as some wc print it) is taken" {
  module "$MOD" pypi-Brotli-1.2.1.txt
  { printf 'EXT\t%s\t   %s\n' "$MOD" "$(wc -c <"$D/root$MOD")"; py "$SITE" Brotli 1.2.1; } | probe
  bcc_check_c14
  run findings_brief
  [[ $output == "FIXED|C14|Brotli|"* ]]
}

@test "#27 the reasons and the next step are in Japanese too" {
  BCC_LANG=ja
  module "$MOD" pypi-Brotli-1.2.1.txt
  { ext "$MOD"; py "$SITE" Brotli 1.2.1; } | probe
  bcc_check_c14
  [ "$(reason_of Brotli)" = "修正版 1.2.1 以上です（版はコンテナの中のパッケージのメタデータから）。 分かったこと: コンテナの中の $MOD のデコーダーの文字列に、修正で追加されたエラー名（_ERROR_FORMAT_BLOCK_SWITCH）がある。 分からないこと: ファイルの中のデコーダーがすべて修正済みかどうか（同じ文字列はリンカーが 1 つにまとめるため、それを共有する未修正のコピーは見えない）。" ]
  bcc_init_findings
  echo 1 >"$D/head-rc"
  bcc_check_c14
  [[ $(reason_of Brotli) == *"ファイルからは確かめられなかった: コンテナの中の $MOD を読めなかった。" ]]
  [ "$(next_of Brotli)" = "ホストを更新してもコンテナは直らない。イメージの中のこのパッケージを確かめるか、イメージを作った側に確認する。修正版でなければ、修正版を入れてイメージを作り直し、再デプロイする。" ]
  run skipped_text
  [[ $output == *"コンテナの中でエンジン越しに読めなかった（終了状態 1）。文字列による判定はしていない"* ]]
}

@test "#27 with --no-exec, or through another connection, no module is read (nothing runs inside)" {
  module "$MOD" pypi-Brotli-1.2.1.txt
  { ext "$MOD"; py "$SITE" Brotli 1.2.1; } | probe
  BCC_NO_EXEC=1
  bcc_check_c14
  [ "${#BCC_FINDINGS[@]}" -eq 0 ]
  if grep -q ' exec ' "$D/log"; then return 1; fi
  BCC_NO_EXEC=0
  DOCKER_HOST=tcp://127.0.0.1:2375 bcc_check_c14
  [ "${#BCC_FINDINGS[@]}" -eq 0 ]
  if grep -q ' exec ' "$D/log"; then return 1; fi
}

@test "#27 the check script lists each site's modules with their sizes before its metadata (dash)" {
  command -v dash >/dev/null || skip "dash not available"
  local T="$BATS_TEST_TMPDIR/c" probe
  local s="$T/opt/app/lib/python3.12/site-packages"
  mkdir -p "$s/brotlicffi" "$s/Brotli-1.2.1.dist-info" "$s/brotlicffi-1.2.1.0.dist-info" "$s/_brotli.dir.so"
  printf 'Name: Brotli\nVersion: 1.2.1\n' >"$s/Brotli-1.2.1.dist-info/METADATA"
  printf 'Name: brotlicffi\nVersion: 1.2.1.0\n' >"$s/brotlicffi-1.2.1.0.dist-info/METADATA"
  printf '12345' >"$s/_brotli.cpython-312-x86_64-linux-gnu.so"
  printf '1234567' >"$s/brotlicffi/_brotlicffi.abi3.so"
  # Only the /opt directories of the check script are moved under the test's tree.
  probe=${BCC_C14_PROBE// \/opt\/\*\/lib/ $T/opt/*/lib}
  [[ $probe == *" $T/opt/*/lib/python3*/site-packages"* ]]
  run env PATH=/usr/bin:/bin dash -c "$probe"
  [ "$status" -eq 0 ]
  run grep -F -- "$T/" <<<"$output"
  # A directory is not a module; modules come before the metadata of the same site.
  [ "$output" = "EXT	$s/_brotli.cpython-312-x86_64-linux-gnu.so	5
EXT	$s/brotlicffi/_brotlicffi.abi3.so	7
PY	$s/Brotli-1.2.1.dist-info/METADATA	Brotli	1.2.1
PY	$s/brotlicffi-1.2.1.0.dist-info/METADATA	brotlicffi	1.2.1.0" ]
}
