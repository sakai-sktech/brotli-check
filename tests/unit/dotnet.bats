#!/usr/bin/env bats
# .NET's System.IO.Compression native library (issue #17, docs/design.md 10.27): found by name,
# judged by .NET's own version. Fake ELF files carry the string lists of real builds
# (tests/fixtures/dotnet/README.md); no Brotli data of any kind is used.

load test_helper

bats_require_minimum_version 1.5.0

setup() {
  load_libs
  setup_fakebin
  T="$BATS_TEST_TMPDIR/tree"
  mkdir -p "$T"
  D="$FIXTURES/dotnet"
  LIB=libSystem.IO.Compression.Native.so
}

# A shared runtime of VERSION under ROOT, carrying the strings of FIXTURE, with a .version file.
# Usage: shared_runtime ROOT VERSION FIXTURE [FILE-NAME]
shared_runtime() {
  local dir="$1/shared/Microsoft.NETCore.App/$2"
  make_fake_elf "$dir/${4:-$LIB}" "$D/$3.txt"
  printf '%s\n%s\n' 0123456789abcdef0123456789abcdef01234567 "$2" >"$dir/.version"
}

# FIXTURE's strings with its stamp replaced by STAMP (the numbers after "@(#)Version ").
# Usage: restamp FIXTURE STAMP > FILE
restamp() {
  sed "s/^@(#)Version .*/@(#)Version $2 @Commit: 0123456789abcdef0123456789abcdef01234567/" "$D/$1.txt"
}

# Field N of the finding about PATH (0 id, 1 status, 2 component, 4 version, 5 reason, 6 next, 7 evidence).
field_of() {
  local f
  for f in ${BCC_FINDINGS[@]+"${BCC_FINDINGS[@]}"}; do
    bcc_split_tab "$f"
    if [[ ${BCC_F[3]} == "$1" ]]; then
      printf '%s' "${BCC_F[$2]}"
      return 0
    fi
  done
  return 1
}

# A file that holds only the given NUL-separated strings, after the ELF magic.
stamp_file() {
  local f=$1
  shift
  mkdir -p "${f%/*}"
  { printf '\177ELF\002\001\001\000\0'; printf '%s\0' "$@"; } >"$f"
}

@test "#17 the build stamp gives .NET's version (Arcade's file version), from .NET 5 on" {
  local f="$T/lib.so"
  stamp_file "$f" '@(#)Version 8.0.3326.52219 @Commit: da7a9beabf4cccc624399d583f52f080a4c858c2'
  run bcc_dotnet_stamp "$f"
  [ "$status" -eq 0 ]
  [ "$output" = $'8.0.33\t8.0.3326.52219\tda7a9beabf4cccc624399d583f52f080a4c858c2' ]
  stamp_file "$f" '@(#)Version 10.0.1426.52326 @Commit: 0427b9abbead3fa64c6655eb4290c537397131fa'
  run bcc_dotnet_stamp "$f"
  [ "${output%%$'\t'*}" = 10.0.14 ]
  # FILE_MINOR = MINOR * 100 + PATCH / 100: a minor version above 0 and a patch above 99.
  stamp_file "$f" '@(#)Version 5.101.2326.1'
  run bcc_dotnet_stamp "$f"
  [ "$output" = $'5.1.123\t5.101.2326.1\t' ]
  # A release and its previews share the stamp of X.Y.0.
  stamp_file "$f" '@(#)Version 11.0.26.52215 @Commit: 0123456'
  run bcc_dotnet_stamp "$f"
  [ "${output%%$'\t'*}" = 11.0.0 ]
  # corefx's file version (.NET Core 2.x and 3.x) is not .NET's; a build without one has none.
  for s in '@(#)Version 4.700.22.56512 @Commit: b58ef0a19eca6269799664d6288be14b7f0cef3e' \
    '@(#)Version 4.6.30411.02 @BuiltBy: root @Branch: release/2.1-MSRC' '@(#)Version N/A' 'no stamp'; do
    stamp_file "$f" "$s"
    run bcc_dotnet_stamp "$f"
    [ "$status" -eq 1 ]
    [ -z "$output" ]
  done
}

@test "#17 reading the stamp stops early without errors on stderr, also where SIGPIPE is ignored (as on CI)" {
  local f="$T/big.so" i
  stamp_file "$f" '@(#)Version 8.0.3326.52219 @Commit: da7a9beabf4cccc624399d583f52f080a4c858c2'
  # Far more text after the stamp than a pipe holds: the reader is cut off once it is found.
  for ((i = 0; i < 4096; i++)); do printf '%0255d\n' 0; done >>"$f"
  # shellcheck disable=SC2016  # expanded by the inner bash
  run --separate-stderr bash -c 'trap "" PIPE; for x in "$1"/lib/*.sh; do . "$x"; done; BCC_MAX_ELF_MB=64 BCC_TIMEOUT=20 BCC_PROBE_TIMEOUT=5; bcc_dotnet_stamp "$2"' _ "$REPO_ROOT" "$f"
  [ "$status" -eq 0 ]
  [ "${output%%$'\t'*}" = 8.0.33 ]
  [ -z "$stderr" ] || { printf 'stderr was:\n%s\n' "$stderr"; return 1; }
}

@test "#17 Microsoft's .NET 8: 8.0.32 is VULNERABLE, 8.0.33 FIXED by its stamp, saying what the strings cannot show" {
  shared_runtime "$T/dotnet" 8.0.32 microsoft-8.0.32
  shared_runtime "$T/dotnet" 8.0.33 microsoft-8.0.33
  local old="$T/dotnet/shared/Microsoft.NETCore.App/8.0.32/$LIB" new="$T/dotnet/shared/Microsoft.NETCore.App/8.0.33/$LIB"
  bcc_c09_dotnet_entry "$old"
  bcc_c09_dotnet_entry "$new"
  run findings_brief
  [[ $output == *"VULNERABLE|C09|dotnet|$old|8.0.32"* ]]
  [[ $output == *"FIXED|C09|dotnet|$new|8.0.33"* ]]
  [ "$(field_of "$old" 5)" = "Below the fixed version 8.0.33." ]
  [[ $(field_of "$old" 6) == "Update .NET to 8.0.33 or later from where it was installed"*"restart the applications that use it (C03)." ]]
  [[ $(field_of "$new" 5) == "At or above the fixed version 8.0.33 (the .NET version stamped into this file by its build: 8.0.3326.52219). Not determined: whether the decoder code in this file has the fix."* ]]
  [[ $(field_of "$new" 6) == "No update needed for this line"* ]]
  [[ $(field_of "$new" 7) == "stamp 8.0.3326.52219 (commit da7a9beabf4cccc624399d583f52f080a4c858c2); .version 8.0.33; _ERROR_FORMAT_* names: 0, BLOCK_SWITCH: no; data: dotnet 8.0;"* ]]
  # The strings alone would say nothing either way.
  run bcc_brotli_heuristic "$new"
  [[ $output == VENDORED_COPY* ]]
}

@test "#17 Japanese: the stamp and what it leaves open" {
  BCC_LANG=ja
  shared_runtime "$T/dotnet" 8.0.33 microsoft-8.0.33
  local new="$T/dotnet/shared/Microsoft.NETCore.App/8.0.33/$LIB"
  bcc_c09_dotnet_entry "$new"
  [[ $(field_of "$new" 5) == "修正版 8.0.33 以上です（ビルドがこのファイルに刻んだ .NET の版: 8.0.3326.52219）。 分からないこと: このファイルのデコーダーのコードに修正が入っているか。"* ]]
}

@test "#17 .NET 9 and 10: the strings confirm the stamp" {
  local v
  for v in 9.0.21 9.0.22 10.0.13 10.0.14; do shared_runtime "$T/dotnet" "$v" "microsoft-$v"; done
  for v in 9.0.21 9.0.22 10.0.13 10.0.14; do bcc_c09_dotnet_entry "$T/dotnet/shared/Microsoft.NETCore.App/$v/$LIB"; done
  run findings_brief
  [[ $output == *"VULNERABLE|C09|dotnet|$T/dotnet/shared/Microsoft.NETCore.App/9.0.21/$LIB|9.0.21"* ]]
  [[ $output == *"FIXED|C09|dotnet|$T/dotnet/shared/Microsoft.NETCore.App/9.0.22/$LIB|9.0.22"* ]]
  [[ $output == *"VULNERABLE|C09|dotnet|$T/dotnet/shared/Microsoft.NETCore.App/10.0.13/$LIB|10.0.13"* ]]
  [[ $output == *"FIXED|C09|dotnet|$T/dotnet/shared/Microsoft.NETCore.App/10.0.14/$LIB|10.0.14"* ]]
  local r
  r=$(field_of "$T/dotnet/shared/Microsoft.NETCore.App/10.0.14/$LIB" 5)
  [[ $r == *"(the .NET version stamped into this file by its build: 10.0.1426.52326). Found: the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH) among the decoder strings of this file. Not determined: whether all decoder code"* ]]
  [[ $r != *"Its strings carry no decoder error names"* ]]
}

@test "#17 a stamp the strings contradict is UNKNOWN, either way" {
  local a="$T/dotnet/shared/Microsoft.NETCore.App/10.0.14/$LIB" b="$T/dotnet/shared/Microsoft.NETCore.App/10.0.13/$LIB"
  mkdir -p "${a%/*}" "${b%/*}"
  restamp microsoft-10.0.13 10.0.1426.52326 >"$T/a.txt"
  make_fake_elf "$a" "$T/a.txt"
  restamp microsoft-10.0.14 10.0.1326.50504 >"$T/b.txt"
  make_fake_elf "$b" "$T/b.txt"
  bcc_c09_dotnet_entry "$a"
  bcc_c09_dotnet_entry "$b"
  run findings_brief
  [[ $output == *"UNKNOWN|C09|dotnet|$a|10.0.14"* ]]
  [[ $output == *"UNKNOWN|C09|dotnet|$b|10.0.13"* ]]
  [[ $(field_of "$a" 5) == *"But the decoder in the file lacks the fix's error name (_ERROR_FORMAT_BLOCK_SWITCH): the version may be wrong."* ]]
  [[ $(field_of "$b" 5) == "Version 10.0.13 is below the fix, but the decoder strings carry the fix's error name"*"possibly a patched build." ]]
}

@test "#17 a .version file that disagrees with the stamp is UNKNOWN" {
  shared_runtime "$T/dotnet" 8.0.33 microsoft-8.0.33
  local f="$T/dotnet/shared/Microsoft.NETCore.App/8.0.33/$LIB"
  printf 'abc\n8.0.32\n' >"${f%/*}/.version"
  bcc_c09_dotnet_entry "$f"
  [ "$(field_of "$f" 1)" = UNKNOWN ]
  [[ $(field_of "$f" 5) == "The build stamp of this file says .NET 8.0.33 (8.0.3326.52219), but the runtime's .version file says 8.0.32"* ]]
}

@test "#17 self-contained applications: judged by the stamp, with their own next step" {
  local old="$T/opt/pwsh-7.4.21/$LIB" new="$T/opt/pwsh-7.4.22/$LIB"
  make_fake_elf "$old" "$D/powershell-7.4.21.txt"
  make_fake_elf "$new" "$D/powershell-7.4.22.txt"
  bcc_c09_dotnet_entry "$old"
  bcc_c09_dotnet_entry "$new"
  run findings_brief
  [[ $output == *"VULNERABLE|C09|dotnet (self-contained)|$old|8.0.32"* ]]
  [[ $output == *"FIXED|C09|dotnet (self-contained)|$new|8.0.33"* ]]
  [[ $(field_of "$old" 6) == "An application carries this copy (a self-contained .NET application): updating the installed .NET does not change it. Ask its vendor for a release built with .NET 8.0.33 or later, or rebuild and redeploy it." ]]
  [[ $(field_of "$new" 7) != *".version"* ]]
}

@test "#17 an application's own .version file is not the runtime's" {
  local f="$T/opt/app/$LIB"
  make_fake_elf "$f" "$D/powershell-7.4.22.txt"
  printf 'build 4711\n2.3.4\n' >"${f%/*}/.version"
  bcc_c09_dotnet_entry "$f"
  run findings_brief
  [[ $output == *"FIXED|C09|dotnet (self-contained)|$f|8.0.33"* ]]
}

@test "#17 .NET 11 previews: the .version file tells them apart, the stamp alone cannot" {
  local rc2="$T/dotnet/shared/Microsoft.NETCore.App/11.0.0-rc.2.26504.105/$LIB"
  local rc3="$T/dotnet/shared/Microsoft.NETCore.App/11.0.0-rc.3.26522.148/$LIB"
  local ga="$T/dotnet/shared/Microsoft.NETCore.App/11.0.0/$LIB" app="$T/opt/app/$LIB"
  restamp microsoft-10.0.13 11.0.26.50404 >"$T/rc2.txt"
  restamp microsoft-10.0.14 11.0.26.52215 >"$T/rc3.txt"
  make_fake_elf "$rc2" "$T/rc2.txt"
  make_fake_elf "$rc3" "$T/rc3.txt"
  make_fake_elf "$ga" "$T/rc3.txt"
  make_fake_elf "$app" "$T/rc3.txt"
  printf 'abc\n11.0.0-rc.2.26504.105\n' >"${rc2%/*}/.version"
  printf 'abc\n11.0.0-rc.3.26522.148\n' >"${rc3%/*}/.version"
  printf 'abc\n11.0.0\n' >"${ga%/*}/.version"
  local f
  for f in "$rc2" "$rc3" "$ga" "$app"; do bcc_c09_dotnet_entry "$f"; done
  run findings_brief
  [[ $output == *"VULNERABLE|C09|dotnet|$rc2|11.0.0-rc.2.26504.105"* ]]
  [[ $output == *"FIXED|C09|dotnet|$rc3|11.0.0-rc.3.26522.148"* ]]
  [[ $output == *"FIXED|C09|dotnet|$ga|11.0.0"* ]]
  [[ $output == *"UNKNOWN|C09|dotnet (self-contained)|$app|11.0.0"* ]]
  [[ $(field_of "$app" 5) == "The build stamp says .NET 11.0.0, which a preview of that release carries too, and the fix came in the preview 11.0.0-rc.3.26522.148"* ]]
}

@test "#17 end-of-life lines: 3.0 to 7.0 VULNERABLE, 2.1 and 2.2 UNKNOWN, both told to move on" {
  shared_runtime "$T/dotnet" 3.1.32 microsoft-3.1.32 System.IO.Compression.Native.so
  shared_runtime "$T/dotnet" 2.1.30 microsoft-2.1.30 System.IO.Compression.Native.so
  shared_runtime "$T/dotnet" 6.0.36 microsoft-6.0.36
  local f31="$T/dotnet/shared/Microsoft.NETCore.App/3.1.32/System.IO.Compression.Native.so"
  local f21="$T/dotnet/shared/Microsoft.NETCore.App/2.1.30/System.IO.Compression.Native.so"
  local f60="$T/dotnet/shared/Microsoft.NETCore.App/6.0.36/$LIB" app="$T/opt/app/$LIB"
  make_fake_elf "$app" "$D/microsoft-7.0.20.txt"
  local f
  for f in "$f31" "$f21" "$f60" "$app"; do bcc_c09_dotnet_entry "$f"; done
  run findings_brief
  [[ $output == *"VULNERABLE|C09|dotnet|$f31|3.1.32"* ]]
  [[ $output == *"UNKNOWN|C09|dotnet|$f21|2.1.30"* ]]
  [[ $output == *"VULNERABLE|C09|dotnet|$f60|6.0.36"* ]]
  [[ $output == *"VULNERABLE|C09|dotnet (self-contained)|$app|7.0.20"* ]]
  # 3.1's version is the .version file's: its stamp is corefx's.
  [[ $(field_of "$f31" 7) == ".version 3.1.32;"* ]]
  [[ $(field_of "$f31" 5) == "The Brotli bundled with this line is in the affected range, and this line gets no fixed release"* ]]
  [[ $(field_of "$f21" 5) == "The Brotli bundled with this line is older than the range the advisory states, which does not say whether it is affected"* ]]
  [ "$(field_of "$f31" 6)" = "This .NET line gets no fix: move to .NET 8.0.33, 9.0.22, 10.0.14 or later." ]
  [ "$(field_of "$f21" 6)" = "This .NET line gets no fix: move to .NET 8.0.33, 9.0.22, 10.0.14 or later." ]
  [[ $(field_of "$app" 6) == "An application carries this copy (a self-contained .NET application) of a .NET line that gets no fix"* ]]
}

@test "#17 no version anywhere: judged by the strings alone; no decoder at all: information only" {
  local app="$T/opt/app/System.IO.Compression.Native.so" old="$T/opt/old/System.IO.Compression.Native.so"
  make_fake_elf "$app" "$D/microsoft-3.1.32.txt"
  stamp_file "$old" '@(#)Version 4.6.26515.06 @BuiltBy: x'
  bcc_c09_dotnet_entry "$app"
  bcc_c09_dotnet_entry "$old"
  run findings_brief
  [[ $output == *"VENDORED_COPY|C09|dotnet (self-contained)|$app|"* ]]
  [[ $output != *"$old"* ]]
  [[ $(field_of "$app" 5) == ".NET's compression library, with no .NET version in a build stamp or a .version file."* ]]
  [[ ${BCC_INFO[*]} == *"$old is .NET's compression library without a Brotli decoder (.NET Core before 2.1)."* ]]
}

# --- Ubuntu's packages -------------------------------------------------------------------

# dpkg says FILE belongs to $FAKE_OWNER; dpkg-query -W prints $FAKE_DPKG_W.
fake_owner() {
  bcc_dpkg_owner() { [[ -n ${FAKE_OWNER:-} ]] && printf '%s\n' "$FAKE_OWNER"; }
  cat >"$FAKEBIN/dpkg-query" <<'EOF'
#!/bin/sh
[ "$1" = -W ] && printf '%b' "$FAKE_DPKG_W"
EOF
  chmod +x "$FAKEBIN/dpkg-query"
}

@test "#17 Ubuntu's dotnet packages are judged by the source version against USN-8958-1" {
  command -v dpkg >/dev/null || skip "dpkg not available"
  fake_owner
  shared_runtime "$T/usr/lib/dotnet" 8.0.33 ubuntu-24.04-dotnet-runtime-8.0-8.0.33
  local f="$T/usr/lib/dotnet/shared/Microsoft.NETCore.App/8.0.33/$LIB"
  BCC_DEB_SERIES=ubuntu:noble
  export FAKE_OWNER=dotnet-runtime-8.0 FAKE_DPKG_W='8.0.33-0ubuntu1~24.04.1\tdotnet8\t8.0.133-8.0.33-0ubuntu1~24.04.1\n'
  bcc_c09_dotnet_entry "$f"
  run findings_brief
  [[ $output == *"FIXED|C09|dotnet (dotnet-runtime-8.0)|$f|8.0.33-0ubuntu1~24.04.1"* ]]
  [ "$(field_of "$f" 5)" = "At or above the fixed version 8.0.133-8.0.33-0ubuntu1~24.04.1 (the distribution package version)." ]
  [[ $(field_of "$f" 6) == "No update needed for this line"*"If it was updated recently, restart the services that use it (C03)." ]]
  [[ $(field_of "$f" 7) == "source dotnet8 8.0.133-8.0.33-0ubuntu1~24.04.1; data: deb-src:dotnet8 ubuntu:noble; https://ubuntu.com/security/notices/USN-8958-1"* ]]
}

@test "#17 Ubuntu: the release version is VULNERABLE; dotnet6 has no fix, dotnet7 none to come; no series: UNKNOWN" {
  command -v dpkg >/dev/null || skip "dpkg not available"
  fake_owner
  shared_runtime "$T/a" 8.0.4 microsoft-8.0.32
  shared_runtime "$T/b" 6.0.36 microsoft-6.0.36
  shared_runtime "$T/c" 7.0.20 microsoft-7.0.20
  local a="$T/a/shared/Microsoft.NETCore.App/8.0.4/$LIB" b="$T/b/shared/Microsoft.NETCore.App/6.0.36/$LIB"
  local c="$T/c/shared/Microsoft.NETCore.App/7.0.20/$LIB"
  BCC_DEB_SERIES=ubuntu:noble
  export FAKE_OWNER=dotnet-runtime-8.0 FAKE_DPKG_W='8.0.4-0ubuntu1\tdotnet8\t8.0.104-8.0.4-0ubuntu1\n'
  bcc_c09_dotnet_entry "$a"
  BCC_DEB_SERIES=ubuntu:jammy
  export FAKE_OWNER=dotnet-runtime-6.0 FAKE_DPKG_W='6.0.136-0ubuntu1~22.04.1\tdotnet6\t6.0.136-6.0.36-0ubuntu1~22.04.1\n'
  bcc_c09_dotnet_entry "$b"
  export FAKE_OWNER=dotnet-runtime-7.0 FAKE_DPKG_W='7.0.120-0ubuntu1~22.04.1\tdotnet7\t7.0.120-7.0.20-0ubuntu1~22.04.1\n'
  bcc_c09_dotnet_entry "$c"
  run findings_brief
  [[ $output == *"VULNERABLE|C09|dotnet (dotnet-runtime-8.0)|$a|8.0.4-0ubuntu1"* ]]
  [[ $output == *"NO_FIX_AVAILABLE|C09|dotnet (dotnet-runtime-6.0)|$b|"* ]]
  [[ $output == *"VULNERABLE|C09|dotnet (dotnet-runtime-7.0)|$c|"* ]]
  [ "$(field_of "$a" 6)" = "Update the package (apt-get install --only-upgrade dotnet-runtime-8.0) to the version built from dotnet8 8.0.133-8.0.33-0ubuntu1~24.04.1 or later, then restart the applications that use it (C03)." ]
  [ "$(field_of "$b" 5)" = "The distributor has not released a fix yet." ]
  [ "$(field_of "$b" 6)" = "This .NET line gets no fix: move to .NET 8.0.33, 9.0.22, 10.0.14 or later." ]
  [ "$(field_of "$c" 6)" = "This .NET line gets no fix: move to .NET 8.0.33, 9.0.22, 10.0.14 or later." ]
  # Without a known series, nothing is guessed (as in C01).
  bcc_init_findings
  BCC_DEB_SERIES="" BCC_OS_ID=fedora
  bcc_c09_dotnet_entry "$a"
  [ "$(field_of "$a" 1)" = UNKNOWN ]
  [ "$(field_of "$a" 5)" = 'Distribution "fedora" is not in the package data.' ]
}

@test "#17 Microsoft's package (not Ubuntu's source) is judged by the stamp like the archive" {
  fake_owner
  shared_runtime "$T/usr/share/dotnet" 8.0.33 microsoft-8.0.33
  local f="$T/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.33/$LIB"
  BCC_DEB_SERIES=debian:bookworm
  export FAKE_OWNER=dotnet-runtime-8.0 FAKE_DPKG_W='8.0.33-1\tdotnet-runtime-8.0\t8.0.33-1\n'
  bcc_c09_dotnet_entry "$f"
  run findings_brief
  [[ $output == *"FIXED|C09|dotnet (dotnet-runtime-8.0)|$f|8.0.33"* ]]
  [[ $(field_of "$f" 5) == *"(the .NET version stamped into this file by its build: 8.0.3326.52219)"* ]]
  [[ $(field_of "$f" 7) == "package dotnet-runtime-8.0 8.0.33-1; stamp 8.0.3326.52219 (commit da7a9beabf4cccc624399d583f52f080a4c858c2); .version 8.0.33;"* ]]
}

# --- Finding them, data, restarts -----------------------------------------------------------

@test "#17 the index takes both names, and leaves NuGet's packages to the cache count" {
  declare -gA BCC_IDX_SEEN=()
  BCC_IDX_DOTNET=() BCC_IDX_LIB=() BCC_IDX_CACHED=0
  bcc_index_entry "/usr/lib/dotnet/shared/Microsoft.NETCore.App/8.0.33/$LIB"
  bcc_index_entry /opt/app/System.IO.Compression.Native.so
  bcc_index_entry "/home/u/.nuget/packages/microsoft.netcore.app.runtime.linux-x64/8.0.32/runtimes/linux-x64/native/$LIB"
  bcc_index_entry /opt/app/System.IO.Compression.Native.so.dbg
  [ "${#BCC_IDX_DOTNET[@]}" -eq 2 ]
  [ "$BCC_IDX_CACHED" -eq 1 ]
}

@test "#17 a whole run finds a runtime by name under the roots and judges it" {
  shared_runtime "$T/srv/dotnet" 8.0.32 microsoft-8.0.32
  mkdir -p "$T/proc"
  printf 'btime 1761400000\n' >"$T/proc/stat"
  printf 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n' >"$T/os-release"
  export BCC_PROC_ROOT="$T/proc" BCC_OS_RELEASE="$T/os-release" BCC_HOME_DIRS="$T/nohome" BCC_MOUNTINFO=/dev/null
  run "$REPO_ROOT/bin/brotli-cve-check" --roots "$T/srv" --no-exec --timeout 60
  [ "$status" -eq 1 ]
  [[ $output == *"[VULNERABLE] C09 | dotnet | $T/srv/dotnet/shared/Microsoft.NETCore.App/8.0.32/$LIB | 8.0.32 | Below the fixed version 8.0.33."* ]]
}

@test "#17 data: the .NET lines, and what lies before the advisory's range" {
  bcc_judge dotnet 2.1 semver 2.1.30 x
  [ "$BCC_J_STATUS" = UNKNOWN ]
  bcc_judge_advises_update
  bcc_judge dotnet 1.1 semver 1.1.13 x
  [ "$BCC_D_STATUS" = derived_before_range ]
  bcc_judge dotnet 3.0 semver 3.0.3 x
  [ "$BCC_J_STATUS" = VULNERABLE ]
  [ "$BCC_D_STATUS" = derived_bundled ]
  bcc_judge dotnet 9.0 semver 9.0.0-rc.2.24473.5 x
  [ "$BCC_J_STATUS" = UNKNOWN ]
  [ "$BCC_J_OUT_OF_RANGE" = 1 ]
  # The fix came in a preview: earlier previews of the release are simply before it.
  bcc_judge dotnet 11.0 semver 11.0.0-preview.7.26381.103 x
  [ "$BCC_J_STATUS" = VULNERABLE ]
  bcc_judge dotnet 11.0 semver 11.0.0-rc.3.26522.148 x
  [ "$BCC_J_STATUS" = FIXED ]
  bcc_judge dotnet 12.0 semver 12.0.0 x
  [ "$BCC_J_STATUS" = UNKNOWN ]
  [[ $BCC_J_REASON == "No advisory data for dotnet, series 12.0." ]]
}

@test "#17 C03: a process still mapping a deleted .NET library needs a restart" {
  local P="$BATS_TEST_TMPDIR/proc"
  mkdir -p "$P/100" "$P/200"
  printf 'btime 1761400000\n' >"$P/stat"
  printf '7f00-7f10 r-xp 00000000 08:01 1234 /usr/lib/dotnet/shared/Microsoft.NETCore.App/8.0.32/%s (deleted)\n' "$LIB" >"$P/100/maps"
  printf '7f00-7f10 r-xp 00000000 08:01 1234 /usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.32/System.IO.Compression.Native.so (deleted)\n' >"$P/200/maps"
  printf '100 (dotnet) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5000 0\n' >"$P/100/stat"
  printf '200 (dotnet) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5000 0\n' >"$P/200/stat"
  BCC_PROC_ROOT=$P
  bcc_check_c03
  run findings_brief
  [[ $output == *"RESTART_REQUIRED|C03|pid 100|"* ]]
  [[ $output == *"RESTART_REQUIRED|C03|pid 200|"* ]]
  [[ ${BCC_FINDINGS[*]} == *"Still maps a deleted file: /usr/lib/dotnet/shared/Microsoft.NETCore.App/8.0.32/$LIB (deleted)."* ]]
}
