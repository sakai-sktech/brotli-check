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

# System tools (readelf, stat, timeout, dpkg-query, ...) come from fixed system directories,
# never from the caller's PATH: a directory on root's PATH that another user can write would
# otherwise supply them, and they run even under --no-exec. /usr/local/{sbin,bin} are added
# last, only when no one but root can change them (Debian's old root:staff 2775 does not pass).
# The caller's PATH is kept in BCC_USER_PATH, only for finding programs to judge.
BCC_SYSTEM_PATH=/usr/sbin:/usr/bin:/sbin:/bin
bcc_init_path() {
  local p=$BCC_SYSTEM_PATH d
  BCC_USER_PATH=${PATH:-/usr/bin:/bin}
  PATH=$p
  hash -r
  for d in /usr/local/sbin /usr/local/bin; do
    [[ -d $d ]] && bcc_safe_to_exec "$d" 0 >/dev/null && p+=":$d"
  done
  PATH=$p
  hash -r
}

# Run a system query tool (dpkg-query, readelf, ss, ...). Output is not localized.
bcc_sys() {
  timeout -k 2 "$BCC_TIMEOUT" env LC_ALL=C "$@" </dev/null 2>/dev/null
}

# Read a file the scan found (others may have put it there). Only a regular file: a FIFO
# would block forever and a device may never end. The file is opened and read by a child
# under a time limit (opening happens there too, so a FIFO swapped in after the test
# cannot hang the scan), and at most MAX bytes are read. Small reads get the short probe
# timeout, large ones the search timeout. Status: 0 read, 1 not a readable regular file,
# other: the read failed or timed out (output may be partial).
# Usage: bcc_read_file FILE MAX-BYTES
bcc_read_file() {
  local f=$1 max=$2 t=$BCC_TIMEOUT
  [[ -f $f && -r $f ]] || return 1
  ((max > 1048576)) || t=$BCC_PROBE_TIMEOUT
  timeout -k 2 "$t" head -c "$max" -- "$f" 2>/dev/null
}

# Is GID the user private group of UID (umask 002 setups)? All must hold: the group's name
# is the owner's login name, it is the owner's primary group, exactly one group entry has
# this GID, its member list names nobody but the owner, and no other user has it as primary
# group. Any lookup that fails means "no". Used only when not running as root.
bcc_group_is_private() {
  local uid=$1 gid=$2 key="$1:$2" pw grp name members m n
  if [[ -n ${BCC_PRIVGRP_CACHE[$key]+x} ]]; then
    return "${BCC_PRIVGRP_CACHE[$key]}"
  fi
  BCC_PRIVGRP_CACHE[$key]=1
  bcc_have getent || return 1
  pw=$(getent passwd "$uid" 2>/dev/null) || return 1
  name=${pw%%:*}
  [[ -n $name && $(cut -d: -f4 <<<"$pw") == "$gid" ]] || return 1
  grp=$(getent group "$gid" 2>/dev/null) || return 1
  [[ ${grp%%:*} == "$name" ]] || return 1
  n=$(getent group 2>/dev/null | awk -F: -v g="$gid" '$3 == g' | grep -c .) || return 1
  ((n == 1)) || return 1
  members=${grp##*:}
  for m in ${members//,/ }; do
    [[ $m == "$name" ]] || return 1
  done
  [[ -z $(getent passwd 2>/dev/null | awk -F: -v g="$gid" -v u="$uid" '$4 == g && $3 != u' | head -n 1) ]] || return 1
  BCC_PRIVGRP_CACHE[$key]=0
  return 0
}

# Can nobody but root (or, when not running as root, the current user) change PATH? The
# file and every directory above it belong to root (or the current user) and none is
# writable by others; group-writable is refused when running as root, and otherwise
# accepted only for the owner's user private group (bcc_group_is_private). The path must be
# canonical (no symlink anywhere in it); prints it on success. Used for the tool's own
# system tools (bcc_init_path). Programs the scan finds are not judged by it: the user
# decides about those, from the facts (lib/exec.sh).
# Usage: bcc_safe_to_exec PATH [EFFECTIVE-UID]  (the second argument exists for tests only)
bcc_safe_to_exec() {
  local p uid gid mode real euid=${2:-$EUID} line
  local -a chain=() st=()
  real=$(bcc_realpath "$1") || return 1
  [[ -n $real && $real == "$1" ]] || return 1
  p=$real
  while :; do
    chain+=("$p")
    [[ $p == / ]] && break
    p=${p%/*}
    [[ -n $p ]] || p=/
  done
  # One stat for the whole chain (the paths are canonical: no symlink to follow).
  mapfile -t st < <(stat -L -c '%u %g %a' -- "${chain[@]}" 2>/dev/null)
  ((${#st[@]} == ${#chain[@]})) || return 1
  for line in "${st[@]}"; do
    read -r uid gid mode <<<"$line"
    [[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && $mode =~ ^[0-7]+$ ]] || return 1
    if ((euid == 0)); then
      ((uid == 0)) || return 1
    else
      ((uid == 0 || uid == euid)) || return 1
    fi
    (((8#$mode & 8#002) == 0)) || return 1
    if (((8#$mode & 8#020) != 0)); then
      # Never for root, never on root-owned paths; otherwise only the user private group.
      ((euid != 0 && uid != 0)) || return 1
      bcc_group_is_private "$uid" "$gid" || return 1
    fi
  done
  printf '%s\n' "$real"
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

# File systems from mountinfo. Network file systems are excluded unless --include-remote.
# File systems on local disks (and, with --include-remote, network ones) mounted below a
# search root are searched too (find -xdev would stop at their mount point); other kinds
# (tmpfs, overlay, squashfs, fuse, ...) are not, and bcc_find_each lists them as not scanned.
BCC_REMOTE_FS_RE='^(nfs|nfs4|cifs|smb3|smbfs|sshfs|fuse\.sshfs|9p|afs|ceph|glusterfs|fuse\.glusterfs|davfs|fuse\.davfs|fuse\.rclone|fuse\.s3fs|lustre|gpfs)$'
BCC_LOCAL_DISK_FS_RE='^(ext2|ext3|ext4|xfs|btrfs|zfs|f2fs|jfs|reiserfs|bcachefs|nilfs2|vfat|exfat|ntfs|ntfs3|hfsplus|fuseblk)$'
bcc_init_remote_mounts() {
  local mi=${BCC_MOUNTINFO:-/proc/self/mountinfo} fs mp
  BCC_REMOTE_MOUNTS=()
  BCC_MOUNTS=()
  BCC_MOUNT_TYPES=()
  [[ -r $mi ]] || return 0
  while IFS=$'\t' read -r fs mp; do
    [[ -n $mp ]] || continue
    mp=$(printf '%b' "$mp") # mountinfo escapes spaces as \040
    if [[ $fs =~ $BCC_REMOTE_FS_RE ]] && ((!BCC_INCLUDE_REMOTE)); then
      BCC_REMOTE_MOUNTS+=("$mp")
      bcc_skip "$mp" "$(bcc_msg skip_remote_fs)"
    else
      BCC_MOUNTS+=("$mp")
      BCC_MOUNT_TYPES+=("$fs")
    fi
  done < <(awk '{
      fs = ""
      for (i = 7; i <= NF; i++) if ($i == "-") { fs = $(i + 1); break }
      if (fs != "") printf "%s\t%s\n", fs, $5
    }' "$mi")
}

# Is PATH under one of the --exclude paths, or a pruned pseudo file system?
bcc_is_excluded() {
  local x
  for x in /proc /sys /dev /run ${BCC_EXCLUDES[@]+"${BCC_EXCLUDES[@]}"} ${BCC_REMOTE_MOUNTS[@]+"${BCC_REMOTE_MOUNTS[@]}"}; do
    [[ $1 == "$x" || $1 == "$x"/* ]] && return 0
  done
  return 1
}

# Mount points strictly below ROOT, one per line as "TYPE<TAB>MOUNTPOINT".
bcc_mounts_below() {
  local root=$1 i mp
  [[ $root == / ]] && root=""
  for i in ${BCC_MOUNTS[@]+"${!BCC_MOUNTS[@]}"}; do
    mp=${BCC_MOUNTS[i]}
    [[ $mp == "$root"/?* ]] || continue
    bcc_is_excluded "$mp" && continue
    printf '%s\t%s\n' "${BCC_MOUNT_TYPES[i]}" "$mp"
  done
}

# bcc_find_each CALLBACK ROOT... -- FIND-EXPRESSION...
# Walks ROOTs with -xdev, never follows symlinks, prunes pseudo/remote/excluded paths, and
# calls CALLBACK with each match. Local-disk file systems mounted below a root are walked
# as roots of their own; other mounts below are recorded as not scanned (one line per kind).
# find's error messages come back through the same stream, so unreadable directories are
# counted (BCC_FIND_ERRORS, BCC_FIND_ERROR_EXAMPLE; bcc_find_status reports them).
# Returns find's status (124 = timeout).
bcc_find_each() {
  local cb=$1 p rc=0 r fs mp
  shift
  local -a roots=() expr=() prune=()
  local -A other=() other_n=() seen_root=()
  BCC_FIND_ERRORS=0
  BCC_FIND_ERROR_EXAMPLE=""
  while (($#)); do
    if [[ $1 == -- ]]; then
      shift
      break
    fi
    # find -P does not descend into a root that is itself a symlink (/srv -> /data/srv):
    # walk its target, once, and match mounts and exclusions against that.
    if [[ -e $1 ]]; then
      r=$(bcc_realpath "$1") || r=$1
      [[ -n $r && -z ${seen_root[$r]:-} ]] && { seen_root[$r]=1; roots+=("$r"); }
    fi
    shift
  done
  expr=("$@")
  ((${#roots[@]})) || return 0
  for r in "${roots[@]}"; do
    while IFS=$'\t' read -r fs mp; do
      [[ -n $mp ]] || continue
      # (Network file systems are in this list only with --include-remote.)
      if [[ $fs =~ $BCC_LOCAL_DISK_FS_RE || $fs =~ $BCC_REMOTE_FS_RE ]]; then
        roots+=("$mp")
      else
        other_n[$fs]=$((${other_n[$fs]:-0} + 1))
        [[ -n ${other[$fs]:-} ]] || other[$fs]=$mp
      fi
    done < <(bcc_mounts_below "$r")
  done
  for fs in ${other[@]+"${!other[@]}"}; do
    bcc_skip "${other[$fs]}" "$(bcc_msg skip_other_fs "$fs" "${other_n[$fs]}")"
  done
  for p in /proc /sys /dev /run ${BCC_EXCLUDES[@]+"${BCC_EXCLUDES[@]}"} ${BCC_REMOTE_MOUNTS[@]+"${BCC_REMOTE_MOUNTS[@]}"}; do
    [[ -n $p ]] || continue
    ((${#prune[@]})) && prune+=(-o)
    prune+=(-path "$p")
  done
  while IFS= read -r -d '' p; do
    case $p in
      __BCC_FIND_RC=*)
        rc=${p#__BCC_FIND_RC=}
        ;;
      __BCC_FIND_ERR=*)
        # A file that vanished during the walk is not a gap in coverage.
        [[ $p == *"No such file or directory" ]] && continue
        BCC_FIND_ERRORS=$((BCC_FIND_ERRORS + 1))
        if [[ -z $BCC_FIND_ERROR_EXAMPLE && $p =~ ^__BCC_FIND_ERR=find:\ \'(.*)\':\  ]]; then
          BCC_FIND_ERROR_EXAMPLE=${BASH_REMATCH[1]}
        fi
        ;;
      *) "$cb" "$p" ;;
    esac
  done < <(
    timeout -k 2 "$BCC_TIMEOUT" env LC_ALL=C find -P "${roots[@]}" -xdev \( "${prune[@]}" \) -prune -o \( "${expr[@]}" \) -print0 \
      2> >(while IFS= read -r p; do printf '__BCC_FIND_ERR=%s\0' "$p"; done)
    printf '__BCC_FIND_RC=%d\0' "$?"
  )
  return "$rc"
}

# Records a timeout, and directories find could not read, of the last bcc_find_each as
# skipped scopes. Usage: bcc_find_status RC SCOPE
bcc_find_status() {
  if (($1 == 124 || $1 == 137)); then
    bcc_skip "$2" "$(bcc_msg skip_timeout "$BCC_TIMEOUT")"
  fi
  if ((${BCC_FIND_ERRORS:-0} > 0)); then
    bcc_skip "$2 (find)" "$(bcc_msg skip_find_errors "$BCC_FIND_ERRORS" "${BCC_FIND_ERROR_EXAMPLE:-?}")"
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

# Print each directory of the scanning user's PATH that exists (where to look, not what runs).
bcc_path_dirs() {
  local d
  local -a dirs=()
  IFS=: read -r -a dirs <<<"${BCC_USER_PATH:-${PATH:-/usr/bin:/bin}}"
  for d in "${dirs[@]}"; do
    [[ -n $d && -d $d ]] && printf '%s\n' "$d"
  done
}

# Candidate executables named NAME (or another of NAME|ALIAS): in each directory of the
# caller's PATH, plus NUL-terminated records on stdin: "G<pattern>" (a glob) or "L<path>" (a
# literal path, from the index). The name is matched on the path as found and on the file
# it resolves to: the target must carry the name too, as in /opt/x/bin/node -> node-22.0.0
# or node -> nodejs. A link to a program of another name is a multi-call shim (mise, volta),
# not the runtime, and is dropped, as are scripts. Prints the unique real paths of ELF
# files, NUL-terminated (paths may contain newlines).
# Usage: printf 'G%s\0' PATTERN... | bcc_candidates NAME[|ALIAS]
bcc_candidates() {
  local names=$1 d f rec real n ok
  local -A seen=()
  local -a names_a=() list=()
  IFS='|' read -r -a names_a <<<"$names"
  while IFS= read -r d; do
    for n in "${names_a[@]}"; do list+=("$d/$n"); done
  done < <(bcc_path_dirs)
  while IFS= read -r -d '' rec; do
    case $rec in
      L*) list+=("${rec#L}") ;;
      G*)
        bcc_glob "${rec#G}"
        list+=(${BCC_GLOB[@]+"${BCC_GLOB[@]}"})
        ;;
    esac
  done
  for f in ${list[@]+"${list[@]}"}; do
    ok=0
    for n in "${names_a[@]}"; do [[ ${f##*/} == "$n" ]] && ok=1; done
    ((ok)) || continue
    [[ -f $f && -x $f ]] || continue
    real=$(bcc_realpath "$f") || continue
    ok=0
    for n in "${names_a[@]}"; do [[ ${real##*/} == "$n"* ]] && ok=1; done
    ((ok)) || continue
    [[ -n $real && -z ${seen[$real]:-} ]] || continue
    seen[$real]=1
    bcc_is_elf "$real" || continue
    printf '%s\0' "$real"
  done
}

# Glob patterns (one per line on stdin) as "G" records for bcc_candidates.
bcc_glob_records() {
  local p
  while IFS= read -r p; do [[ -n $p ]] && printf 'G%s\0' "$p"; done
  return 0
}

# Executables of running processes whose name is one of NAMES (not deleted), NUL-terminated.
bcc_running_exes() {
  local d exe n
  for d in "${BCC_PROC_ROOT:-/proc}"/[0-9]*; do
    exe=$(readlink -- "$d/exe" 2>/dev/null) || continue
    [[ $exe == *" (deleted)" ]] && continue
    for n in "$@"; do
      [[ ${exe##*/} == "$n" ]] && { printf '%s\0' "$exe"; break; }
    done
  done
  return 0
}

# Start time of a process as UTC ISO 8601, from DIR=/proc/<pid>. Prints "?" when unknown.
bcc_proc_start_time() {
  local dir=$1 stat rest btime tck start
  local -a fields=()
  stat=$(cat -- "$dir/stat" 2>/dev/null) || { printf '?'; return; }
  rest=${stat##*) }
  read -r -a fields <<<"$rest"
  start=${fields[19]:-}
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
    cmd=$(tr '\0' ' ' 2>/dev/null <"$dir/cmdline") && ev+="; $(bcc_msg e_cmdline "${cmd% }")"
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
