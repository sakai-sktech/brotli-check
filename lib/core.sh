# shellcheck shell=bash
# core.sh - shared helpers: messages, guarded execution, host facts, filesystem walking.
#
# Rules enforced here (docs/design.md 7):
#   - programs the scan *found* run only through bcc_probe (version flags, empty env, timeout);
#   - system query tools run through bcc_sys (LC_ALL=C, timeout);
#   - nothing is written except stdout/stderr and the --output file.

bcc_die() {
  printf 'brotli-cve-check: %s\n' "$*" >&2
  exit 3
}

bcc_warn() {
  printf 'brotli-cve-check: %s\n' "$*" >&2
}

bcc_have() {
  command -v -- "$1" >/dev/null 2>&1
}

# Run a system query tool (dpkg-query, readelf, ss, ...). Output is not localized.
bcc_sys() {
  timeout -k 2 "$BCC_TIMEOUT" env LC_ALL=C "$@" </dev/null 2>/dev/null
}

# Run a program the scan found, for its version only. Returns 125 under --no-exec.
bcc_probe() {
  local bin=$1 a
  shift
  if ((BCC_NO_EXEC)); then
    return 125
  fi
  for a in "$@"; do
    case $a in
      --version | -v | -V | version) ;;
      *) bcc_die "internal error: probe argument not allowed: $a" ;;
    esac
  done
  timeout -k 2 "$BCC_PROBE_TIMEOUT" env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C "$bin" "$@" </dev/null 2>&1
}

# Read KEY from an os-release file without sourcing it.
bcc_os_release_get() {
  local key=$1 file=${BCC_OS_RELEASE:-/etc/os-release}
  [[ -r $file ]] || file=/usr/lib/os-release
  [[ -r $file ]] || return 1
  sed -n "s/^${key}=//p" "$file" | head -n 1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//"
}

bcc_init_host() {
  BCC_OS_ID=$(bcc_os_release_get ID || true)
  BCC_OS_VERSION_ID=$(bcc_os_release_get VERSION_ID || true)
  BCC_OS_CODENAME=$(bcc_os_release_get VERSION_CODENAME || true)
  BCC_OS_PRETTY=$(bcc_os_release_get PRETTY_NAME || true)
  if [[ -z $BCC_OS_CODENAME && $BCC_OS_ID == debian ]]; then
    # Debian testing/unstable may ship without VERSION_CODENAME.
    BCC_OS_CODENAME=sid
  fi
  # Package series used by the data file: "ubuntu:noble", "debian:trixie". Derivatives
  # (Linux Mint, ...) declare the archive they follow in UBUNTU_CODENAME / DEBIAN_CODENAME.
  local ubu deb
  ubu=$(bcc_os_release_get UBUNTU_CODENAME || true)
  deb=$(bcc_os_release_get DEBIAN_CODENAME || true)
  case $BCC_OS_ID in
    ubuntu | debian) BCC_DEB_SERIES="$BCC_OS_ID:$BCC_OS_CODENAME" ;;
    *)
      if [[ -n $ubu ]]; then
        BCC_DEB_SERIES="ubuntu:$ubu"
      elif [[ -n $deb ]]; then
        BCC_DEB_SERIES="debian:$deb"
      else
        BCC_DEB_SERIES=""
      fi
      ;;
  esac
  BCC_KERNEL=$(cat /proc/sys/kernel/osrelease 2>/dev/null || true)
  BCC_UID=$EUID
  if ((EUID == 0)); then BCC_IS_ROOT=1; else BCC_IS_ROOT=0; fi
}

# Home directories of root and regular users, one per line.
bcc_homes() {
  if [[ -n ${BCC_HOME_DIRS:-} ]]; then
    tr ':' '\n' <<<"$BCC_HOME_DIRS"
    return
  fi
  {
    if bcc_have getent; then getent passwd 2>/dev/null; else cat /etc/passwd 2>/dev/null; fi
  } | awk -F: '($3 == 0 || ($3 >= 1000 && $3 < 65534)) && $6 != "" && $6 != "/" { print $6 }' | sort -u
}

# Readable home directories; unreadable ones are recorded as skipped (once).
bcc_init_homes() {
  local h
  BCC_HOMES=()
  while IFS= read -r h; do
    [[ -n $h && -d $h ]] || continue
    if [[ -r $h && -x $h ]]; then
      BCC_HOMES+=("$h")
    else
      bcc_skip "$h" "$(bcc_msg skip_home_unreadable)"
    fi
  done < <(bcc_homes)
}

# Mount points of network file systems (excluded unless --include-remote).
bcc_init_remote_mounts() {
  local mi=${BCC_MOUNTINFO:-/proc/self/mountinfo} mp
  BCC_REMOTE_MOUNTS=()
  ((BCC_INCLUDE_REMOTE)) && return 0
  [[ -r $mi ]] || return 0
  while IFS= read -r mp; do
    [[ -n $mp ]] || continue
    mp=$(printf '%b' "$mp") # mountinfo escapes spaces as \040
    BCC_REMOTE_MOUNTS+=("$mp")
    bcc_skip "$mp" "$(bcc_msg skip_remote_fs)"
  done < <(awk '{
      fs = ""
      for (i = 7; i <= NF; i++) if ($i == "-") { fs = $(i + 1); break }
      if (fs ~ /^(nfs|nfs4|cifs|smb3|smbfs|sshfs|fuse\.sshfs|9p|afs|ceph|glusterfs|fuse\.glusterfs|davfs|fuse\.davfs|fuse\.rclone|fuse\.s3fs|lustre|gpfs)$/) print $5
    }' "$mi")
}

# bcc_find_each CALLBACK ROOT... -- FIND-EXPRESSION...
# Walks ROOTs with -xdev, never follows symlinks, prunes pseudo/remote/excluded
# paths, and calls CALLBACK with each match. Returns find's status (124 = timeout).
bcc_find_each() {
  local cb=$1 p rc=0
  shift
  local -a roots=() expr=() prune=()
  while (($#)); do
    if [[ $1 == -- ]]; then
      shift
      break
    fi
    [[ -e $1 ]] && roots+=("$1")
    shift
  done
  expr=("$@")
  ((${#roots[@]})) || return 0
  for p in /proc /sys /dev /run ${BCC_EXCLUDES[@]+"${BCC_EXCLUDES[@]}"} ${BCC_REMOTE_MOUNTS[@]+"${BCC_REMOTE_MOUNTS[@]}"}; do
    [[ -n $p ]] || continue
    ((${#prune[@]})) && prune+=(-o)
    prune+=(-path "$p")
  done
  while IFS= read -r -d '' p; do
    if [[ $p == __BCC_FIND_RC=* ]]; then
      rc=${p#__BCC_FIND_RC=}
      continue
    fi
    "$cb" "$p"
  done < <(
    timeout -k 2 "$BCC_TIMEOUT" find -P "${roots[@]}" -xdev \( "${prune[@]}" \) -prune -o \( "${expr[@]}" \) -print0 2>/dev/null
    printf '__BCC_FIND_RC=%d\0' "$?"
  )
  return "$rc"
}

# Records a timeout of bcc_find_each as a skipped scope. Usage: bcc_find_status RC SCOPE
bcc_find_status() {
  if (($1 == 124 || $1 == 137)); then
    bcc_skip "$2" "$(bcc_msg skip_timeout "$BCC_TIMEOUT")"
  fi
}

# Is PATH owned by a Debian package? Prints the package name(s).
# dpkg never installs into home directories, so those are not asked (dpkg-query -S
# reads every file list and takes about a second per call). Results are cached.
bcc_dpkg_owner() {
  local path=$1 out h
  bcc_have dpkg-query || return 1
  case $path in /home/* | /root/* | /tmp/* | /var/tmp/*) return 1 ;; esac
  for h in ${BCC_HOMES[@]+"${BCC_HOMES[@]}"}; do
    [[ $path == "$h"/* ]] && return 1
  done
  if [[ -n ${BCC_DPKG_CACHE[$path]+x} ]]; then
    out=${BCC_DPKG_CACHE[$path]}
  else
    out=$(bcc_sys dpkg-query -S "$path") || out=""
    out=${out%%: *}
    BCC_DPKG_CACHE[$path]=$out
  fi
  [[ -n $out ]] || return 1
  printf '%s\n' "$out"
}

bcc_realpath() {
  readlink -f -- "$1" 2>/dev/null
}

# Print each directory of the scanning user's PATH that exists.
bcc_path_dirs() {
  local d
  local -a dirs=()
  IFS=: read -r -a dirs <<<"${PATH:-/usr/bin:/bin}"
  for d in "${dirs[@]}"; do
    [[ -n $d && -d $d ]] && printf '%s\n' "$d"
  done
}

# Candidate executables named NAME: on PATH plus glob patterns read from stdin (one per line).
# Prints unique real paths of ELF files (shims and scripts are dropped).
# Usage: printf '%s\n' PATTERN... | bcc_candidates NAME[|ALIAS]
bcc_candidates() {
  local names=$1 d f m real base n ok
  local -A seen=()
  local -a names_a=() list=()
  IFS='|' read -r -a names_a <<<"$names"
  while IFS= read -r d; do
    for n in "${names_a[@]}"; do list+=("$d/$n"); done
  done < <(bcc_path_dirs)
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    while IFS= read -r m; do list+=("$m"); done < <(compgen -G "$f" || true)
  done
  for f in ${list[@]+"${list[@]}"}; do
    [[ -f $f && -x $f ]] || continue
    real=$(bcc_realpath "$f") || continue
    [[ -n $real && -z ${seen[$real]:-} ]] || continue
    seen[$real]=1
    base=${real##*/}
    ok=0
    for n in "${names_a[@]}"; do [[ $base == "$n" ]] && ok=1; done
    ((ok)) || continue
    bcc_is_elf "$real" || continue
    printf '%s\n' "$real"
  done
}

# Start time of a process as UTC ISO 8601, from DIR=/proc/<pid>. Prints "?" when unknown.
bcc_proc_start_time() {
  local dir=$1 stat rest btime tck start
  local -a f=()
  stat=$(cat -- "$dir/stat" 2>/dev/null) || { printf '?'; return; }
  rest=${stat##*) }
  read -r -a f <<<"$rest"
  start=${f[19]:-}
  btime=$(sed -n 's/^btime //p' "${BCC_PROC_ROOT:-/proc}/stat" 2>/dev/null)
  tck=$(getconf CLK_TCK 2>/dev/null || printf 100)
  if [[ $start =~ ^[0-9]+$ && $btime =~ ^[0-9]+$ && $tck =~ ^[0-9]+$ ]] && ((tck > 0)); then
    date -u -d "@$((btime + start / tck))" +%Y-%m-%dT%H:%M:%SZ
  else
    printf '?'
  fi
}

# Evidence for a process finding: start time, and the command line only with --show-cmdline
# (command lines can carry tokens and passwords).
bcc_proc_evidence() {
  local dir=$1 ev cmd
  ev=$(bcc_msg e_started "$(bcc_proc_start_time "$dir")")
  if ((BCC_SHOW_CMDLINE)); then
    cmd=$(tr '\0' ' ' <"$dir/cmdline" 2>/dev/null) && ev+="; $(bcc_msg e_cmdline "${cmd% }")"
  fi
  printf '%s' "$ev"
}

# Seconds since the epoch for "today" (overridable for tests).
bcc_today_epoch() {
  if [[ -n ${BCC_TODAY:-} ]]; then
    date -u -d "$BCC_TODAY" +%s
  else
    date -u +%s
  fi
}
