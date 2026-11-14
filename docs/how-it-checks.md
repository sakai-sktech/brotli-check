# How it checks, and where it stops

日本語: [how-it-checks.ja.md](how-it-checks.ja.md)

What brotli-cve-check looks for, how, and where it stops, check by check (C01 to C15). It is
written for the administrators who run the tool: use it to read what a result confirms, and what
it does not.

## What this document is

- **The result of the scan is the original.** How it is handled (who is told what, whether to
  look further) is for the site that uses it to decide; the tool does not decide it.
- **How far the tool looks is a design decision, and this document is the rule.** Code that
  differs from it is a bug. Moving a place where a check stops is a design change: the decision
  is written into section 10 of the design notes ([design.md](design.md)) and this document
  changes in the same change ([CONTRIBUTING.md](../CONTRIBUTING.md), design notes 10.30).
- What can be missed is summed up in [limitations.md](limitations.md), the reasons are in the
  design notes, and the fields of the result in [json-schema.md](json-schema.md).
- It was written against the code on main (commit `c964751`, to be released as v0.2.0).

## How to read it

- Every check answers the same four questions: **what it looks for / how it finds it / what it
  reads and in which order it decides / where it stops**.
- Each stop says what the result shows when the check stops there (or that it shows nothing),
  and which record decided it: [design 10.28] is item 28 of section 10 of the design notes,
  [design 6] is section 6. **[no record] marks a stop that no record decided** (the behaviour is
  the code's).
- Where the code is known to differ from this document and is to be fixed, the text is marked
  **[bug]** and gives both the rule and what the code does now. Where a stop is to be moved, it
  is marked **[to change]** and the stop is described as it is now (the change will update
  section 10 of the design notes and this document).
- "Backing" at the end of each part says how each statement was checked: [test] a unit test
  (file and test name under `tests/unit/`), [integration] the integration run
  (`tests/integration/`, five images), [measured] a run on the developer's host (Ubuntu 24.04),
  [code] read from the code only, with no test (the function in `lib/`).

## Contents

1. [Common to all checks](#1-common-to-all-checks)
2. [Check by check](#2-check-by-check): [C01](#c01-os-packages) · [C02](#c02-packages-that-depend-on-libbrotli1-information) · [C03](#c03-processes-still-using-a-deleted-file) · [C04](#c04-nodejs) · [C05](#c05-bun) ·
   [C06](#c06-python-pypi-brotli-brotlicffi-conda) · [C07](#c07-nodejs-projects---projects) · [C08](#c08-curl) · [C09](#c09-bundled-decoders) · [C10](#c10-envoy) ·
   [C11](#c11-web-servers) · [C12](#c12-snap-and-flatpak) · [C13](#c13-browsers) · [C14](#c14-containers---containers---inspect-containers) · [C15](#c15-listening-sockets---exposure)

---

## 1. Common to all checks

### 1.1 Clues: how a copy of the decoder is found

The tool finds only copies that leave one of these clues. **A copy that leaves none is not found.**

| Clue | Seen through | Used by |
|---|---|---|
| A package record | `dpkg-query` (on the host and inside containers), `snap list`, `flatpak list` | C01, C02, C09 (Ubuntu's .NET), C11, C12, C13, C14 |
| A file of a known name | The name index built in one walk of the search roots (1.2), and candidates in fixed places | C04, C05, C06, C09, C10, C11, C13 |
| The executable of a product known to carry Brotli | node, bun, envoy, curl, nginx, Apache, HAProxy, Traefik, Caddy, Chromium, Chrome, Firefox, Electron applications, .NET | C04, C05, C08, C09, C10, C11, C12, C13 |
| Strings inside an ELF file | The decoder's function names and error names (1.4) | `--deep` (C09); the other checks also judge a file of unknown version this way |
| Running processes | `/proc/*/maps`, `/proc/*/exe` | C03, C04, C05 |
| Hints of a path (not a decoder) | Metadata of Python HTTP clients, `package.json`, an Envoy configuration file, listening sockets | C06, C07, C10, C15 |

Examples of what is not found: a static copy without markers, built into a file of another name;
without `--deep`, a copy in a file of another name; the inside of archives (`.asar`, `.jar`,
`.zip`), squashfs (snaps, AppImages), stopped containers, container images, virtual machine disks
and firmware (edk2); anything outside the places searched.

### 1.2 Where the walk goes

**Search roots:** `/opt,/usr/local,/srv,/var/www,/home,/root` by default. `--roots` replaces them
(it does not add to them).

**The name index:** one `find` walks the roots and, whatever `--roots` says, these fixed places:
`/usr/lib`, `/usr/lib64`, `/lib64`, `/usr/share/dotnet` (each when it is not a symlink), and the
Python directories (`/usr/lib/python3`, `/usr/lib/python3.*`, `/usr/local/lib/python3.*`, and in
each home `.local/lib`, mise, pyenv, uv, pipx, conda (`.conda`, `miniconda3`, `anaconda3`,
`miniforge3`) and `.virtualenvs`). It takes these names:

| Name | Used by |
|---|---|
| `brotli-*.dist-info`, `brotli-*.egg-info`, `brotlicffi-*.dist-info`, `brotlicffi-*.egg-info` (any case) | C06 |
| `conda-meta/libbrotlidec-<digit>*.json` (regular files) | C06 (conda) |
| `libbrotlidec*.so*`, `libbrotlidec*.a` (regular files) | C09 |
| `libSystem.IO.Compression.Native.so`, `System.IO.Compression.Native.so` (regular files) | C09 (.NET) |
| `node`, `nodejs`, `bun`, `envoy` (regular files with the owner's execute bit) | C04, C05, C10 |

**How it walks:** `find -P` (symlinks are not followed) with `-xdev`. It does not enter `/proc`,
`/sys`, `/dev`, `/run`, the places given to `--exclude`, or network file systems (NFS, CIFS,
sshfs and the like, unless `--include-remote`). File systems on local disks (ext4, xfs, btrfs,
zfs, ...) mounted below a root are walked as roots of their own. A root that is a symlink is
walked at its target (one line under information). Files found inside package-manager caches
(pip, uv, poetry, npm, yarn, NuGet) are only counted, under information, and not reported.

**Homes:** the entries of `getent passwd` with uid 0 or 1000 to 65533 whose home is not `/`.

**Where it stops**

- A default root that does not exist → dropped quietly. A root named with `--roots` that does not
  exist → could not be scanned [design 10.26.2]
- A root or home that cannot be read → not scanned when not running as root, could not be scanned
  as root [design 10.26.3]
- Directories `find` could not read → one line with their number and an example: not scanned
  when every error was "Permission denied" and the tool does not run as root, otherwise could
  not be scanned. Files that vanish during the walk are not counted [design 10.9.8, 10.26.3]
- `find` reaches the time limit (`--timeout`, 120 seconds by default) → could not be scanned
  [design 10.9.8]
- File systems below a root that are not on local disks (tmpfs, overlay, squashfs, fuse, ...) →
  not entered; one line per kind, not scanned [design 10.9.9]
- A btrfs subvolume that is not a mount point → not entered. **Nothing is shown** [design 10.9.9]
- Network file systems → not scanned [design 7]. Places given to `--exclude` → not scanned
- Package-manager caches → counted under information [design 10.2, 10.27.5]
- Outside the roots and the fixed places → not looked at. Nothing is shown [design 10.1]
- Candidates found by name (C04, C05, C08, C10, C11, C13) that this user cannot run or cannot read
  → not taken. Nothing is shown. This does not happen as root (a file with any execute bit can be
  run, and everything can be read); a run as another user has the "root" line under not scanned,
  which covers them [design 10.30]

### 1.3 How linked libraries are followed

Whether a program or library loads libbrotlidec is found by reading the file with `readelf` and
following its libraries in the order glibc's ld.so does (the program is not run, and `ldd` is not
used). C04 (node), C08 (curl), C11 (servers), C09 `--deep` (files whose NEEDED names
libbrotlidec) and links to programs of another name use it, and so do the facts listed before a
program runs (1.6).

1. `readelf -l` gives PT_INTERP (the loader), `readelf -d` NEEDED, RPATH, RUNPATH and SONAME.
2. Each needed name is looked up in this order: the RPATH of the object that needs it and then of
   the objects that loaded that one, up to the program (none of them when the needing object has a
   RUNPATH) → that object's RUNPATH → the ld.so cache (`ldconfig -p`, 64-bit entries first) → the
   default directories (`/lib64`, `/usr/lib64`, `/lib/x86_64-linux-gnu`, `/usr/lib/x86_64-linux-gnu`,
   `/lib/aarch64-linux-gnu`, `/usr/lib/aarch64-linux-gnu`, `/lib`, `/usr/lib`).
3. In every directory the `glibc-hwcaps` subdirectories (`x86-64-v3` and the like) come first, in
   the order this host's system loader gives when asked with `--help` (once per run, from `/` with
   an empty environment, only when no one but root can change the loader and it is glibc 2.33 or
   later; also with `--no-exec`). When it could not be asked, or the program names another loader,
   every copy in those subdirectories is a candidate, and the report says that which one loads
   could not be told.
4. `$ORIGIN` in RPATH and RUNPATH is expanded. Other tokens (`$LIB`, ...), relative entries and
   empty entries are not searched (the facts say so).
5. Breadth first. A name already loaded (an object's SONAME included) is not looked up again. Up
   to 8 levels.

The answer is every `libbrotlidec*` reached (in load order, one per file; one not found is
"NAME (not found)") and one of three states:

| State | Meaning | What the checks do with it |
|---|---|---|
| Loads | One or more libbrotlidec | Each is judged: a file of a package C01 judged gives information (C01 decides); any other copy is judged as C09; one not found is `UNKNOWN` |
| Does not load | Followed to the end, no libbrotlidec | A static copy, or no Brotli: up to each check |
| Undetermined | No libbrotlidec was found, and readelf is missing, readelf failed, a needed library was not found, or the 8 levels were exceeded | Up to each check (mostly `UNKNOWN`) |

**[bug]** A line made `UNKNOWN` because the walk was undetermined gives in its reason what could
not be followed (the name of the library not found, the file readelf failed on, the depth limit),
and a next step that fits the case (installing binutils only when readelf is missing). The code
now gives, in C04 (a packaged node), C08, C09 `--deep` and C11, the same two sentences in every
case: "Could not determine whether it loads libbrotlidec." and "Install binutils (readelf) and run
again." (also when readelf is there).

**Where it stops**

- `LD_LIBRARY_PATH`, `LD_PRELOAD`, what `dlopen` opens later → not seen. `/etc/ld.so.preload` is
  used for the facts only [design 10.11]
- The older hwcaps subdirectories of glibc 2.36 and earlier (`tls`, `x86_64`, `haswell/x86_64`,
  ...) and their cache entries → not looked at. **Nothing is shown** [design 10.28.5]
- The order is this host's CPU's, from the loader asked with an empty environment. A service
  started with `GLIBC_TUNABLES`, or another machine, may load another copy [design 10.28.5]
- A library not found or not readable, the depth limit → when a libbrotlidec was found, the walk
  is judged by what was found and **that it stopped is not shown** [design 10.28.5; no record for
  the number 8] **[to change: report a walk that could not be followed to the end]**. When none was
  found, the walk is undetermined (see each check)
- No readelf → every walk is undetermined; one "binutils" line under not scanned [design 4, 10.26.1]

### 1.4 The strings estimate

A copy of unknown version, and a version read from a file (1.5), are judged by the strings in the
file. Only a regular file is read, up to 512 MiB under a time limit, cut into runs of printable
bytes, and these are counted:

- error names starting with `_ERROR_FORMAT_` (whole strings; distinct ones, up to 64), and
  whether `_ERROR_FORMAT_BLOCK_SWITCH` (the error -17 added by the fix) is among them
- copies of Brotli's built-in dictionary (one per copy of Brotli)
- decoder markers: `BrotliDecoderDecompressStream`, `BrotliDecoderCreateInstance`,
  `_ERROR_FORMAT_EXUBERANT_NIBBLE`
- Go build information and the name of the cgo Brotli binding
  (`github.com/google/brotli/go/cbrotli`) (for C11)
- whether the file was read to its end (from the exit status of the reader, `tr`, `grep` and
  `awk` alone, never from the file's bytes)

In this order:

1. Not read to the end (over 512 MiB, the time limit, the memory limit) → `UNKNOWN`, and a line
   under could not be scanned
2. Fewer than 8 error names → `VENDORED_COPY` (a decoder, but fixed and unfixed cannot be told apart)
3. `_ERROR_FORMAT_BLOCK_SWITCH` present and 2 or more dictionaries → `UNKNOWN` (equal strings are
   merged, so a fixed copy can hide an old one)
4. `_ERROR_FORMAT_BLOCK_SWITCH` present → `LIKELY_FIXED` (the reason says what is known and what is not)
5. Otherwise → `LIKELY_VULNERABLE`

Builds tried: Brotli 1.2.0 and 1.2.1, shared, static and LTO, stripped or not (gcc 13 on Ubuntu
24.04, x86_64), the official Node.js binaries 22.23.3/22.23.4 and 24.22.0/24.22.1, and the PyPI
wheels of Brotli and brotlicffi ([tests/fixtures/c09/README.md](../tests/fixtures/c09/README.md)).

**Where it stops**

- A static copy without markers (stripped, LTO, without `BrotliDecoderErrorString`) → not found
  by `--deep`; `VENDORED_COPY` in the other checks [design 6, 10.5, limitations]
- Two decoders sharing one dictionary, a build with an external dictionary → cannot be told
  apart; a `LIKELY_FIXED` reason says so under what is not known [design 10.10.5]
- A vendor's own fix that adds no error name → shows as `LIKELY_VULNERABLE` [limitations]
- Builds of 1.0.x and 1.1.x, other compilers and architectures → not tried [design 10.22]

### 1.5 The advisory data and how versions are compared

Verdicts come from the advisory data shipped with the tool (`data/advisories.tsv`; `--data FILE`
replaces it). A row is picked by component and series (a row for exactly that series first, then
`*` and `<=X` rows in file order), and its status and the version decide:

| Status of the row | Version | Verdict |
|---|---|---|
| `fixed`, `analysis`, `unreleased` | At or above the fixed version | `FIXED` (the reason says where the version came from) |
| 〃 | A pre-release of the fixed version (unless the fixed version is itself a pre-release) | `UNKNOWN` |
| 〃 | Before the advisory's affected range | `UNKNOWN` (an update is advised; leads to exit status 2) |
| `unreleased` | Below the fixed version | `NO_FIX_AVAILABLE` |
| `fixed`, `analysis` | Below the fixed version | `VULNERABLE` |
| 〃 | Cannot be compared | `UNKNOWN` |
| `no_fix` | (not looked at) | `NO_FIX_AVAILABLE` |
| `derived_eol`, `derived_bundled` | (not looked at) | `VULNERABLE` (the reason gives the ground) |
| `derived_before_range` | (not looked at) | `UNKNOWN` (moving on is advised) |
| `unknown` | (not looked at) | `UNKNOWN` (the reason gives the ground) |
| No row | | `UNKNOWN` |

Versions are compared in three ways: distribution packages with `dpkg --compare-versions` (the
source package's version); PyPI with a subset of PEP 440 (trailing zeros dropped, dev <
pre-release < release < post, local versions `+...` ignored); everything else as numeric fields
(a pre-release before its release; two pre-releases of one release by SemVer, 11).

**A version read from a file** (a directory name, `node_version.h`, package metadata, a library's
file name, `application.ini`, a conda record) gives `FIXED` only when the decoder's strings show
the fix in a single copy. Otherwise (no fix error name, more than one copy, not read to the end,
no file to compare) the line is `UNKNOWN` and says what was missing. The exception is .NET's build
stamp (C09). A version a program gave (`--version`) and one from a package record are not checked
against strings.

**Where it stops**

- Fixes released after the data's date → not known (a `NO_FIX_AVAILABLE` may be out of date). Data
  30 days old or more is warned about at the top of the result [design 5.2]
- A component or series not in the data → `UNKNOWN` [design 6]
- A version before the advisory's affected range → `UNKNOWN` (neither vulnerable nor safe) [design 10.16]
- A `--data` file that others than root (or you) can change → used, with a warning at the top [design 10.10.8]

### 1.6 Running found programs (consent)

To read an exact version, the tool asks to run some of the programs it found, with one argument.
It asks only for these:

| Check | Programs asked for | Argument |
|---|---|---|
| C04 | node, unless it is known to load libbrotlidec (a packaged node only when it is known not to) | `--version` |
| C05 | every bun found | `--version` |
| C08 | curl known not to load libbrotlidec | `-V` |
| C10 | every envoy found | `--version` |
| C13 | browsers that are not a package's | `--version` |

Each comes with facts: who besides root (or you) can change the program, a directory above it, a
library it loads or a directory those are looked up in; empty or relative search entries; what
could not be examined. At a terminal you choose: all, none, or by number. Without a terminal
`--yes` (all) or `--no-exec` (none) is needed; with neither, the tool lists them and stops (exit
status 3). Only the chosen ones run: from `/`, with only three environment variables
(`PATH=/usr/bin:/bin`, `HOME=/nonexistent`, `LC_ALL=C`), stdin closed, a time limit (the smaller
of `--timeout` and 10 seconds), and only the first 64 KiB of output kept.

When a program is not run (`--no-exec`, or not chosen), the check reads instead:

| Check | Read instead |
|---|---|
| C04 | `../include/node/node_version.h` → the version manager's directory name → strings |
| C05 | the directory name → strings |
| C08 | strings when the file has decoder markers; otherwise `UNKNOWN` (not `NOT_APPLICABLE`) |
| C10 | strings |
| C13 | for Firefox, the `application.ini` next to it → strings |

The system tools the checks use (`dpkg-query`, `dpkg`, `readelf`, `ldconfig`, `stat`, `find`,
..., `ss`, `snap`, `flatpak`, and `docker` and `podman` with `--containers`) and the system
loader's `--help` (1.3) run also with `--no-exec`. They come from `/usr/sbin`, `/usr/bin`, `/sbin`,
`/bin` (and `/usr/local/sbin`, `/usr/local/bin` when only root can change them), never from the
caller's `PATH`.

**Where it stops**

- What a program opens once it runs (plugins, configuration files) → not in the facts [design 10.11]
- What a program that runs does (writing, the network) → not prevented [design 10.11, README]
- Programs not run → one line under not scanned (`--no-exec`, or how many were not chosen) [design 10.26.1]

### 1.7 Limits

| Limit | Value | What the result shows when it is reached | Record |
|---|---|---|---|
| Size read for a file's strings | 512 MiB (no option changes it) | The line is `UNKNOWN`, one line under could not be scanned | design 7, 10.9.7 |
| Size of a file `--deep` opens | below 512 MiB | Not opened; the number and an example under could not be scanned | design 7, 10.26.1 |
| Time for system tools, `find`, and reads of more than 1 MiB | `--timeout` (120 seconds by default) | Could not be scanned | design 7, 10.9.8 (no record for 120) |
| Time for running a found program, and for reads of 1 MiB or less | the smaller of `--timeout` and 10 seconds | Running: the version is read from files when the output gives none. Reads: up to each check | no record |
| Depth of the dependency walk | 8 levels | See 1.3 | no record (the limitations say it) |
| Chain of symlinks followed for the facts | 40 | The facts say it could not be followed | design 10.13 |
| Memory of `grep` and `awk` | 256 MiB | Taken as not read to the end | design 10.9.7 |
| Error names counted | 64 distinct | Nothing (the verdict only asks whether there are 8) | design 10.9.7 |
| Advisory data file | 16 MiB | Tool error (exit status 3) | design 10.10.8 |
| `--envoy-config` file | 64 MiB | Could not be scanned, when no entry was found | no record |
| Small files (`package.json` 1 MiB; `METADATA`, `node_version.h`, `application.ini`, `/etc/ld.so.preload` 64 KiB; .NET's `.version` 4 KiB) | Only the start is read | Nothing | no record |
| Output of a program run | 64 KiB kept, 4096 characters in JSON | Nothing | design 10.11 |
| Depth searched for Electron markers / flatpak runtime libraries (C12) | 4 / 8 levels | Nothing | no record |

### 1.8 Not scanned, could not be scanned, and the exit status

What was not looked at is always listed, in two kinds (one line per range and kind) [design 10.26].

- **Not scanned** (`chosen`, `[SKIPPED]`): left out by how the tool was run. Options not given
  (`--deep`, `--projects`, `--containers`, `--exposure`), `--exclude`, `--no-exec` and programs
  not chosen, not running as root (and what this user therefore could not read), network file
  systems and other kinds of file systems below a root, what `--containers` only counts (stopped
  containers and images), no readelf.
- **Could not be scanned** (`failed`, `[FAILED]`): the run set out to look and could not. A tool
  that failed (`dpkg-query`, `snap list`, `flatpak list`, `ss`, the engine's `ps` and `images`,
  the check script inside a container), a tool the check needs that is missing (dpkg; ss for
  `--exposure`; docker and podman for `--containers`), a time limit, a file not read to the end or
  over the size limit, a link to a program of another name that could not be followed, what root
  could not read, a place named with `--roots` or `--envoy-config` that is not there, a container
  not looked inside although `--inspect-containers` asked for it.

Exit status: `1` when there is a `VULNERABLE` or a `RESTART_REQUIRED`; `2` when there is none of
those but a `NO_FIX_AVAILABLE`, `VENDORED_COPY`, `LIKELY_*` or `UNKNOWN`, or a range that could not
be scanned; `0` when there is none of these (ranges not scanned are not counted); `3` for an error
of the tool itself. `EXPOSURE` and `NOT_APPLICABLE` are not counted.

**Backing (section 1)**

- 1.2: [test] `hardening.bats` "find: directories that could not be read are listed as not
  scanned", "mounts: a local disk below a root is searched, a tmpfs is listed as not scanned",
  "--exclude paths are listed as not scanned", "round 5: a search root that is a symlink is walked
  at its target, and said so"; `checks.bats` "index: package-manager caches are not reported";
  `skipped.bats` "#10 a place named on the command line that is not there ...", "#10 directories
  find could not read for another reason than permission ...", "#10 what this user could not read
  ...". The fixed places and names of the index: [code] `bcc_build_index`, `bcc_python_dirs`.
  btrfs subvolumes: [code] only.
- 1.3: [test] the 17 tests of `deps.bats` (every libbrotlidec, the loader's order, hwcaps entries of
  the cache, an order not known, another loader, breadth first); `hardening.bats` "round 6:
  libraries are looked up through the RPATH inherited from the executable", "mutation 10/27: a
  RUNPATH hides the same object's RPATH ...", "mutation 10/27: a chain of libraries deeper than
  the walk follows is said so", "review 10/27: library lookups under different search paths are
  kept apart"; `checks.bats` "linkage that cannot be followed is undetermined (2), never 'not
  linked'". [measured] the loader's answer: `deps.bats` "#18: this host's loader answers". That the
  older hwcaps and `LD_LIBRARY_PATH` are not looked at: [code] `bcc_dep_walk_uncached`,
  `bcc_elf_resolve`.
- 1.4: [test] the 7 tests of `heuristic.bats`; `hardening.bats` "strings: a fixed copy next to
  another copy of Brotli is not LIKELY_FIXED", "reads: a file above the size limit is INCOMPLETE
  ...", "reads: distinct error names are counted only up to 64 ...", "round 6: the end of a read is
  never taken from the file's own bytes".
- 1.5: [test] the 32 tests of `data.bats`, the 11 of `version.bats`; `hardening.bats` "pre-release
  of the fixed version is UNKNOWN; ..."; `basis.bats` "#9 every call of bcc_judge in lib/ says where
  its version came from".
- 1.6: [test] the 3 "consent: ..." tests of `cli.bats` and the 3 of `hardening.bats`;
  `hardening.bats` "mutation 10/27: a chosen program runs with an empty environment, stdin closed,
  its output capped" (`NODE_OPTIONS` does not reach it), "mutation 10/27: the plan leaves out what
  its verdict does not need, and asks for the rest", "trusted tools: PATH is fixed to system
  directories ..."; `cli.bats` "system tools never come from the caller's PATH ...". The three
  environment variables: [code] `bcc_exec_run`.
- 1.7: 512 MiB, 64 names, not read to the end and the `--deep` limit: 1.4 and `hardening.bats`
  "--deep: files above the size limit are listed as not scanned". The other values: [code].
- 1.8: [test] the 17 tests of `skipped.bats`; `cli.bats` "exit 1 when something is VULNERABLE",
  "text output ends with the four-line summary ...". [integration] exit status 0, 1 and 2 in five
  images (0 with only the distribution's servers, 2 with an in-house `.deb` and an overwritten
  HAProxy).

---

## 2. Check by check

### C01 OS packages

**What it looks for** — the distribution packages `libbrotli1`, `brotli`, `libbrotli-dev` and
`python3-brotli`, when installed.

**How it finds them** — `dpkg-query -W` gives the state, package name, version, source package
and source version. The series comes from `ID` and `VERSION_CODENAME` in `/etc/os-release` (`sid`
for Debian without a codename); derivatives (Linux Mint and the like) from `UBUNTU_CODENAME` or
`DEBIAN_CODENAME`.

**What it reads, and in which order it decides**

1. No `dpkg-query` → could not be scanned, "C01: dpkg is not available (not Debian/Ubuntu)". Done
2. `dpkg-query` exits with 2 or more, or reaches the time limit → could not be scanned; it does not
   say that none is installed
3. Packages not in state `ii` or `hi` (removed ones, for example) are skipped. With none left:
   information "None of libbrotli1, brotli, libbrotli-dev, python3-brotli is installed."
4. Series not known (neither Debian nor Ubuntu, nor a derivative of either) → `UNKNOWN`,
   "Distribution "..." is not in the package data."
5. The source package's version is compared with the `deb-src:<source>` row for that series
   (1.5). `python3-brotli` carries Brotli statically, so it has its own line
6. The next step of a `VULNERABLE` line is the update with `apt`; a `FIXED` line says no update is
   needed for this line, and to restart

The location field reads like `dpkg (ubuntu:noble)`. The verdict also stands for the programs that
load the package's files and for processes still using its deleted files (C03).

**Where it stops**

- The package's files are not read: the version dpkg recorded decides, and a file changed since
  goes unnoticed [no record]
- Packages other than these four (ones that carry Brotli statically, for example) → not C01's;
  node, curl and the rest have their own checks [design 10.9.4]
- A series not in the data → `UNKNOWN` [design 6]
- One package for two architectures → the verdict of the first line stands for the files (the
  version is the same) [no record]

**Backing** — [test] `checks.bats` "C01: Ubuntu noble packages are judged against USN-8956-1;
...", "C01: Debian trixie judges the source version ...", "C01: removed packages (rc) are not
judged", "C01: an unknown distribution is UNKNOWN, not guessed", "host: derivatives map to the
archive they follow"; the 2 "#9 C01: ..." tests of `basis.bats`; `skipped.bats` "#10 dpkg-query
fails: C01 could not be scanned, ...", "#10 a needed program that is missing: dpkg ..."; 
`hardening.bats` "C01: a failing dpkg-query is not reported as 'none installed'". [integration]
`libbrotli1` and `python3-brotli` are `FIXED` in the five images.

### C02 Packages that depend on libbrotli1 (information)

**What it looks for** — installed packages that depend directly on `libbrotli1` (except C01's
four). This is information, not a finding: the update and restart of C01 fix them, and they are
not counted twice.

**How it finds them** — `Depends` and `Pre-Depends` of every package, from `dpkg-query -W`.

**What it reads, and in which order it decides** — the packages in state `ii` or `hi` whose
dependencies name `libbrotli1`: their number and names, on one line of information. No verdict.

**Where it stops**

- Indirect dependents (a package depending on a library that depends on `libbrotli1`) → not
  listed [no record]
- `dpkg-query` fails → could not be scanned [design 10.26.1]. Without it, nothing (C01 says so)

**Backing** — [test] `checks.bats` "C02: dependents of libbrotli1 are information, not findings";
`skipped.bats` "#10 commands that fail could not be scanned: dpkg-query for C02, ...".

### C03 Processes still using a deleted file

**What it looks for** — processes that keep running an old decoder that an update removed from
the disk.

**How it finds them** — lines of `/proc/*/maps` that end in ` (deleted)` and name
`libbrotlidec*.so*`, `_brotli*.so` (the extension modules of PyPI's Brotli and brotlicffi), or
.NET's `libSystem.IO.Compression.Native.so` or `System.IO.Compression.Native.so`. A process whose
node or bun executable itself was deleted is reported by C04 or C05. C03 runs after the checks that
judge the files on disk.

**What it reads, and in which order it decides**

1. `RESTART_REQUIRED` for each such process (its pid and executable; up to three deleted files in
   the reason)
2. A process in another mount namespace, or one whose namespace cannot be read → not compared; the
   next step is to check the version, then restart
3. The reason gives how the other lines of this result judged the file now at the same path (a
   package's file: C01's verdict)
4. Next step: restart when all of them are `FIXED`; follow the line first when one is
   `VULNERABLE`, `NO_FIX_AVAILABLE` or `LIKELY_VULNERABLE`; otherwise (no verdict, no file,
   `UNKNOWN` and the like) check the version, then restart

The deleted file itself is not read: whatever the old code was, once the disk is fixed, a
restart is the next step.

**Where it stops**

- Processes of other programs that carry a decoder statically (envoy, curl, browsers, .NET
  single-file applications, ...) → not looked at. **Nothing is shown** [design 10.19, limitations]
- An old file and its replacement with different names (`.so.1.1.0` replaced by `.so.1.2.1`) →
  nothing is at the old path now, so: check the version, then restart [design 10.19]
- `maps` that cannot be read (other users' processes) → their number, not scanned when not running
  as root, could not be scanned as root [design 10.26.3]
- No such line is no proof that nothing needs a restart [limitations]

**Backing** — [test] the 3 "C03: ..." and 11 "#5 C03: ..." tests of `checks.bats`, and "#5: a
program that loads the OS libbrotlidec is judged on disk with that package"; `dotnet.bats` "#17
C03: a process still mapping a deleted .NET library needs a restart".

### C04 Node.js

**What it looks for** — `node` and `nodejs` executables. The official Node.js carries Brotli
statically and is judged by Node.js's own version (`process.versions.brotli` is not used: the fixed
22.23.4 still says `1.1.0`).

**How it finds them** — from four sources, each real path once:

- fixed places: `/usr/bin/node`, `/usr/bin/nodejs`, `/usr/local/bin/node`, `/opt/*/bin/node`,
  `/opt/*/*/bin/node`, `/usr/local/n/versions/node/*/bin/node`, `/snap/node/current/bin/node`, and
  in each home the per-version directories of nvm, volta, fnm, asdf, mise and n, and
  `~/.local/bin/node`
- `node` and `nodejs` in the name index (1.2)
- every directory of the caller's `PATH`
- the executables of running processes named `node` or `nodejs`

Only ELF files are candidates (scripts are dropped). A file named `node` that is a link to a
program of another name (`node -> mise`, for example) is not a candidate; the file it points to is
judged by what it carries (links to a program of another name, below).

**What it reads, and in which order it decides**

1. Its libraries are followed (1.3). When it **loads libbrotlidec**, it is judged by that library,
   whoever installed it (each one: information for one of C01's, C09 for any other). When the
   file itself also has 8 or more decoder error names, that copy is judged by its strings too
   ("(own copy)")
2. A dpkg package's file known **not to load** it → judged by its strings (1.4); the reason begins
   "Distribution package that bundles Brotli statically; ...".
   **[bug]** The file judged is the one that carries the decoder, and a file without decoder
   markers is never said to contain one. The code now, for Ubuntu 20.04's distribution nodejs,
   reads the strings of the launcher `/usr/bin/node` (no markers), which only loads
   `libnode.so.64`, reports `VENDORED_COPY` "It contains a Brotli decoder, but ...", and does not
   look at `libnode.so.64`, where the decoder is
3. A dpkg package's file whose walk is **undetermined** → `UNKNOWN` "Could not determine whether
   it loads libbrotlidec.", next step "Install binutils (readelf) and run again." **[bug: 1.3]**
4. Otherwise the version is read: `node --version` (when you agreed to run it) →
   `../include/node/node_version.h` (`-pre` when `NODE_VERSION_IS_RELEASE` is 0) → the version
   manager's directory name (`v22.17.1`, `node-v22.17.1-linux-x64`). With none, it is judged by its
   strings
5. Judged by the data's `node` row for that major version (1.5); a version not read by running it
   is confirmed by strings
6. Next step of a `VULNERABLE` line: move to a supported line for an end-of-life line, update to the
   fixed version otherwise, and restart the running processes by pid

A process still running a deleted node is `RESTART_REQUIRED` (the rule of C03).

**Links to a program of another name** (common to C04, C05, C08, C10, C11 and C13) — not run, no
version read; the file it points to is looked at as `--deep` would. One that loads libbrotlidec is
judged by that library, one with decoder markers by its strings, under the file's own name, with
the link in the reason. One with neither is information ("... is a link to ..., a program of
another name ..., and was not judged as node: ..."). One not read to the end, or whose libraries
could not be followed, could not be scanned. A second link to a file already judged points to that
line (information).

**Where it stops**

- Node.js under a name other than `node` or `nodejs` (`node22`, for example) → not found by name
  (`--deep` finds its strings) [no record]
- Script shims (asdf, nodenv) → dropped without a word; the runtime they start is found where it is
  installed [design 10.23.5]
- An unpackaged node whose walk is undetermined → judged by its version, without a word [no record]
  **[to change: report a walk that could not be followed to the end]**
- The Node.js inside Electron applications → not C04's (C12, `--deep`) [design 10.12]
- Node.js inside containers → C14 [design 10.20]
- A pre-release or nightly of the fixed version → `UNKNOWN` [design 10.9.6]

**Backing** — [test] the 16 "C04: ..." and 4 "#5 C04: ..." tests of `checks.bats`; the 5 "#9 C04:
..." tests of `basis.bats`; `hardening.bats` "round 8: C04: a Node.js that loads libbrotlidec is
judged by it, with or without a package", "round 6: a candidate found by its name is kept when it is
a symlink to another name", "round 6: a link to a program of another name (a mise or volta shim) is
not the runtime", "pre-release: Bun and Node.js from paths and headers"; `deps.bats` "#18: a program
that loads the OS libbrotlidec and a private one gets both judged". [integration] the official
Node.js 22.23.3 is `VULNERABLE` and 22.23.4 `FIXED` (with `--no-exec` and with `--yes`).
[measured] on the developer's host, the Node.js carried by VS Code Server and by GitHub Actions
runners is found (README, "What was checked"). The [bug] of step 2 (Ubuntu 20.04's distribution
nodejs) was seen in a real container on 2026-11-11; that of step 3 is C08's (see its backing).

### C05 Bun

**What it looks for** — `bun` executables (Bun carries Brotli statically).

**How it finds them** — fixed places (`/usr/local/bin/bun`, `/usr/bin/bun`, `/opt/*/bin/bun`, and
in each home `~/.bun/bin/bun`, mise and asdf), the name index, `PATH`. ELF files only; links to a
program of another name as in C04.

**What it reads, and in which order it decides**

1. Version: `bun --version` (when you agreed; a pre-release suffix is kept) → the directory name in
   `.../<version>/bin/bun`. With neither, it is judged by its strings
2. Judged by the data's `bun` row (the affected range is 1.0.21 to 1.4.3; before 1.0.21, `UNKNOWN`);
   a version not read by running it is confirmed by strings
3. When an update is due (`VULNERABLE`, or before the range), the next step: update to the fixed
   version, restart the running processes, and rebuild executables made with
   `bun build --compile`

Its libraries are not followed (Bun carries Brotli statically). A process still running a deleted
bun is `RESTART_REQUIRED`.

**Where it stops**

- Executables made with `bun build --compile` → not found by name; whether `--deep` finds their
  strings was not tried [no record]
- Linked libraries → not followed [no record]

**Backing** — [test] `checks.bats` "C05: Bun 1.0.20 is before the advisory's range: ...", "C05: Bun
1.4.3 is VULNERABLE and the advice mentions compiled executables", "#5 C05: ...", "C05: a bun that
is a link to a program of another name is named in the report"; the 2 "#9 C05: ..." tests of
`basis.bats`.

### C06 Python (PyPI Brotli, brotlicffi, conda)

**What it looks for** — PyPI's `Brotli` and `brotlicffi` (the decoder is in their extension
modules), and `libbrotlidec` in conda environments. With them, the HTTP clients in the same
environment (`EXPOSURE`).

**How it finds them** — the `brotli-*` and `brotlicffi-*` `.dist-info` and `.egg-info` of the name
index (1.2), and conda's `conda-meta/libbrotlidec-<version>-*.json`.

**What it reads, and in which order it decides (PyPI)**

1. `Name:` and `Version:` from the first 64 KiB of `METADATA` (or `PKG-INFO`, or the `.egg-info`
   file). A name other than `brotli` or `brotlicffi` is skipped
2. A file of a package C01 judged (`python3-brotli`) → information "... belongs to the
   distribution package ...; C01 judges it." (its version is upstream's and does not show the
   distribution's fix)
3. Judged by the data's `pypi:brotli` or `pypi:brotlicffi` row, with PEP 440
4. A `FIXED` is confirmed against this package's own extension modules in the same directory
   (Brotli: `_brotli.*so`; brotlicffi: `brotlicffi/_brotlicffi*.so`), one by one; the first that
   does not confirm it makes the line `UNKNOWN`. With no module at all: `UNKNOWN` "Not confirmed by
   a file: ... no extension module was found to compare"
5. When an update is due, the next step: the update of the dpkg package it belongs to, if any (a
   vendor's `.deb` with its own Python), otherwise a `pip` command

**conda:** the version in the record's name (`libbrotlidec-1.2.1-...`) is judged by the data's
`brotli` row for its series, and a `FIXED` is confirmed against the environment's
`lib/libbrotlidec.so.*` (regular files; symlinks are not counted); with none, `UNKNOWN`. A record
whose version has another form (`1.2.1rc0`, for example) is `UNKNOWN`.

**EXPOSURE:** when `urllib3`, `requests`, `httpx`, `aiohttp` or `scrapy` metadata is in the same
directory, one line per directory, saying that these clients decode a br response when they receive
one and that whether an application fetches from outside with them is not checked (for aiohttp,
also that an aiohttp.web server decodes request bodies).

**Where it stops**

- Metadata that is missing or unreadable, or lacks `Name:` or `Version:` → **nothing is shown**
  **[bug]** (what could not be judged is shown, with why)
- Extension modules elsewhere or deeper, distributions with other file names → not compared; even a
  fixed one is `UNKNOWN` [design 10.15.2]
- A conda environment whose `lib/` holds only symlinks → `UNKNOWN` even when fixed [design 10.15.3]
- The inside of a zipped `.egg` → not looked at [no record]
- Other Python packages that carry Brotli (the `libbrotlidec` in Pillow's wheel, for example) → not
  C06's; a file named `libbrotlidec*` is C09's [no record]
- Whether an application uses the HTTP clients → not looked at [design 10.21]

**Backing** — [test] the 22 "C06: ..." tests of `checks.bats` and "issue #7: C06 says ..."; the 5
"#9 C06: ..." tests of `basis.bats`; `hardening.bats` "dpkg: Brotli in a vendor's packaged Python is
judged ...", "dpkg: python3-brotli is left to C01 only when C01 judged it", "round 5: an empty
conda-meta/ next to a library does not hide it; ...", "round 6: a conda record saying fixed is
confirmed ...". [integration] PyPI Brotli 1.2.0 (with urllib3) is `VULNERABLE` and `EXPOSURE`, 1.2.1
is `FIXED`. Unreadable metadata: [code] `bcc_c06_entry`.

### C07 Node.js projects (`--projects`)

**What it looks for** — npm packages that could hand attacker data to the decoder (hints of a path;
`EXPOSURE`).

**How it finds them** — `node_modules` directories under the roots (without going into them).

**What it reads, and in which order it decides** — the `version` in the `package.json` (up to
1 MiB) of packages directly under `node_modules`: on the receiving side `body-parser` (2.x only),
`express` (5.x only), `@fastify/compress`, `koa-body`, `co-body`, `inflation`; on the fetching side
`undici`, `axios`, `got`, `node-fetch`. With any of them, one `EXPOSURE` line for the project (the
parent of `node_modules`), saying the package is installed and that whether the application uses it
is not checked.

**Where it stops**

- Nested `node_modules` → not looked at (npm hoists what matters) [no record]
- Whether the application uses the package, and through which path → not looked at [design 10.21]
- Bundled applications, Yarn PnP (zip archives) → not looked at [no record]
- `find` timing out, directories it cannot read → as in 1.2

**Backing** — [test] `checks.bats` "C07: inbound and outbound decoding packages are exposure
hints" and the 2 "issue #7: C07 ..." tests.

### C08 curl

**What it looks for** — `curl` executables.

**How it finds them** — `/usr/bin/curl`, `/usr/local/bin/curl`, `/opt/*/bin/curl`, `PATH`. The name
index is not used.

**What it reads, and in which order it decides**

1. When you agreed to run it, whether `curl -V` lists `brotli` under `Features:`
2. Its libraries are followed (1.3). It **loads libbrotlidec** → judged by that library, with the
   information "curl decodes br only with --compressed or CURLOPT_ACCEPT_ENCODING."; its own copy is
   looked for too
3. It **does not load** it:
   - `-V` lists brotli, or it was not run and has decoder markers → judged by its strings ("curl
     with Brotli support that does not load libbrotlidec (bundled copy).")
   - `-V` does not list brotli → `NOT_APPLICABLE`
   - not run and no markers → `UNKNOWN` (a static curl may carry no markers); next step "Run "curl
     -V" and look for brotli under Features ...".
     **[bug]** A next step names what can be done with this tool. The sentence now goes on "(or run
     this tool with --allow-exec)", an option removed in design 10.11 (with it, the tool stops with
     an unknown option, exit status 3)
4. **Undetermined** → `UNKNOWN`, next step "Install binutils (readelf) and run again." **[bug: 1.3]**

**Where it stops**

- `NOT_APPLICABLE` only on curl's own word (`-V`) [design 10.9.5]
- Other programs that use `libcurl` → not C08's (`libcurl4` depends on `libbrotli1`, so it shows in
  C02) [no record]
- curl outside the fixed places and `PATH` → not found (`--deep` finds its strings) [no record]

**Backing** — [test] `hardening.bats` "C08: a curl that was not run and shows no markers is
UNKNOWN, not NOT_APPLICABLE", "mutation 10/27: the plan leaves out ...". The [bug] of step 4:
[measured] 2026-11-13, an ELF built with gcc whose NEEDED names a library that is not there, with
the real readelf. The [bug] of step 3: [code] `n_c08_check_features` in `lib/i18n.sh`. The other
branches of steps 1 to 3: [code] `bcc_c08_entry`.

### C09 Bundled decoders

C09 judges copies of the decoder outside the package manager, by four routes.

**(a) libbrotlidec found by name (always)**

- **How it finds them:** `libbrotlidec*.so*` and `libbrotlidec*.a` in the name index. A
  libbrotlidec that another check reached through linked libraries and that is not C01's is judged
  here too (even under a file name of another kind).
- **How it decides:**
  1. A file of a package C01 judged, or one C06 compared with a conda record → not reported here
  2. The strings are estimated (1.4); not read to the end also goes under could not be scanned
  3. No `.so.X.Y.Z` version in the file name (`.so.1`, `.a`) → judged by its strings
     ("libbrotlidec outside the package manager, without a version in its file name.")
  4. A version → judged by the data's `brotli` row for its series; a `FIXED` is confirmed by the
     strings. Version and strings disagreeing (fixed by version, unfixed by strings, or the
     reverse) → `UNKNOWN`
  5. When an update is due: replace that file with a fixed version, and restart the programs that
     load it

**(b) .NET (always)** — .NET builds Google's C decoder into its System.IO.Compression native
library and does not load libbrotlidec.

- **How it finds them:** `libSystem.IO.Compression.Native.so` and `System.IO.Compression.Native.so`
  in the name index (the roots, `/usr/lib` with `/usr/lib/dotnet`, and `/usr/share/dotnet`).
- **How it decides:**
  1. No decoder markers → information ("... .NET Core before 2.1") when read to the end; could not be
     scanned otherwise
  2. A copy outside `<root>/shared/Microsoft.NETCore.App/<version>/` is one an application carries
     (`dotnet (self-contained)`)
  3. A file whose dpkg owner comes from a `dotnetN` source package (Ubuntu's .NET) → its source
     version against the data's `deb-src:dotnetN` row (as C01 does)
  4. Anything else (Microsoft's archives and packages, self-contained applications) → the build
     stamp in the file, `@(#)Version 8.0.3326.52219` (.NET 5 and later; read as 8.0.33), and for a
     shared runtime its `.version`. If they disagree, `UNKNOWN`; with neither, judged by its strings
  5. Judged by the data's `dotnet` row for its series; a `FIXED` is confirmed by the strings. Where
     the strings cannot tell (.NET 8 has no error names), the stamp alone gives `FIXED`, and the
     reason says what is not known. A stamp of X.Y.0 alone, for a line fixed in a preview →
     `UNKNOWN`. An unfixed version with fixed strings → `UNKNOWN`
  6. Next step: for an application's copy, a build of the application with a fixed .NET; for a line
     that gets no fix, moving on; otherwise the update of .NET

**(c) A libbrotlidec loaded that is not C01's** — reached through linked libraries by C04, C08,
C11, `--deep` or a link to a program of another name. Judged as in (a), with the loading program
named under information. One not found is `UNKNOWN` "It loads ..., which could not be found here:
the decoder it uses was not examined.". A candidate among hwcaps copies whose order is not known
says under information that which copy loads could not be told.

**(d) `--deep`** — bundled decoders searched by their strings in the ELF files under the roots.

- **How it finds them:** regular files under the roots with the owner's execute bit, or named
  `*.so`, `*.so.*` or `*.node`, below 512 MiB. Those that contain a decoder marker
  (`BrotliDecoderDecompressStream`, `BrotliDecoderCreateInstance`, `_ERROR_FORMAT_EXUBERANT_NIBBLE`)
  are picked with `grep`, under the time limit.
- **How it decides:**
  1. Already judged by another route, inside a package-manager cache, an extension module C06
     judged, not an ELF file → skipped
  2. NEEDED names libbrotlidec → its libraries are followed and the copies that are not C01's are
     judged as in (c) (C01's add nothing); its own copy is looked for too. **Undetermined** →
     `UNKNOWN`, next step "Install binutils (readelf) and run again." **[bug: 1.3]**
  3. A file of a package C01 judged → skipped
  4. Otherwise → judged by its strings ("Carries its own copy of the Brotli decoder (does not load
     libbrotlidec).")

**Where it stops**

- Without `--deep` → copies inside files of other names are not looked at; "C09 --deep" under not
  scanned [design 7.1]
- `--deep` walks the roots only. Static copies in the fixed places (`/usr/lib` and the like, not
  among the default roots) are not looked at [design 10.1, README]
- Files of 512 MiB or more → not opened, could not be scanned [design 7, 10.26.1]. Files that
  cannot be read → their number, not scanned when not running as root, could not be scanned as
  root [design 10.26.3]
- `grep` errors and the time limit → could not be scanned [design 10.10.9]
- Files with neither an execute bit nor a `.so` or `.node` name, the inside of archives, static
  copies without markers → not seen [design 10.24.3, limitations]
- A file that loads libbrotlidec and whose walk stopped part way → judged by what was found; that it
  stopped is not shown [design 10.28.5] **[to change: 1.3]**
- .NET single-file and NativeAOT executables → `--deep` strings only (a .NET 8 build is
  `VENDORED_COPY`); the stamp is not read [design 10.27.5]
- Runtime packs in NuGet's packages folder → counted as a cache [design 10.27.5]
- .NET in snaps and inside containers → not looked at [limitations]
- Go, Rust and Java decoders (other implementations) → not looked at [limitations]

**Backing** — [test] the 4 "C09: ..." and 3 "C09 --deep: ..." tests of `checks.bats`; `basis.bats`
"#9 C09: a library's file name confirmed by its strings"; the 19 tests of `dotnet.bats`; `deps.bats`
"#18: --deep: every private libbrotlidec of a program is judged, the OS one adds nothing";
`hardening.bats` "dpkg: a libbrotlidec owned by a vendor's package is judged, ...", "round 5: a
program loading a libbrotlidec that C01 did not judge gets that copy judged", "round 6: a
libbrotlidec loaded under a name its file does not have is still judged", "round 6: a file that
loads libbrotlidec and carries its own decoder gets that copy judged", "round 8: --deep: a program's
private library is judged even when --deep would not find its file", "round 9: --deep: a library
that is gone is not left to C01, ...", "round 5: --deep search errors ... are listed as not
scanned", "--deep: files above the size limit are listed as not scanned". [measured] on the
developer's host, the `libbrotlidec` in Pillow's wheel is found (README, "What was checked"); .NET
archives and PowerShell were judged (design 10.27.9).

### C10 Envoy

**What it looks for** — `envoy` executables, and the configuration file named with
`--envoy-config`.

**How it finds them** — `/usr/local/bin/envoy`, `/usr/bin/envoy`, `/opt/*/bin/envoy`,
`~/.func-e/versions/*/bin/envoy` in each home, the name index, `PATH`.

**What it reads, and in which order it decides**

1. The version only from `version: <sha>/X.Y.Z/` in `envoy --version` (when you agreed). Otherwise
   it is judged by its strings
2. Judged by the data's `envoy` row for its series (1.35 and earlier: `derived_bundled`,
   `VULNERABLE`; 1.17 and earlier: `unknown`). The reason adds "Envoy decodes Brotli only where a
   Brotli decompressor filter is configured."
3. `--envoy-config FILE`: up to 64 MiB is read. A decompressor filter's name
   (`envoy.compression.brotli.decompressor` and the like) → `EXPOSURE` (the file names one; whether
   the running Envoy uses this file, and whether that entry is in effect, is not checked). None →
   information; not read to the end → could not be scanned
4. One line of information on Istio sidecars

**Where it stops**

- When not run, no version is read from files (no directory name, no header) → strings only [no record]
- The running Envoy's configuration (admin API), configuration files not named → not looked at
  [design 10.21.3]
- Envoy inside containers (Istio sidecars and the like) → not looked at; C14 does not look for
  Envoy either [no record]
- `--envoy-config` that does not exist or is not a regular file → could not be scanned; one that
  cannot be read → not scanned when not running as root [design 10.26.2]

**Backing** — [test] `checks.bats` "C10: Envoy 1.35 is VULNERABLE, ...", "C10: an Envoy
configuration with a Brotli decompressor is EXPOSURE", "issue #7: C10 ..."; `basis.bats` "#9 C10:
..."; `hardening.bats` "round 6: an Envoy configuration read only in part is not reported as free of
Brotli"; `skipped.bats` "#10 --envoy-config: ..."; `data.bats` "data: Envoy before Brotli support is
UNKNOWN; ...".

### C11 Web servers

**What it looks for** — servers that mostly use Brotli for compression only (nginx, Apache
(`apache2`, `httpd`), HAProxy, Traefik, Caddy) and nginx's and Apache's Brotli modules. They are
judged by what the files carry, not by the product's name.

**How it finds them** — `/usr/sbin/<name>`, `/usr/local/sbin/<name>`, `/usr/local/bin/<name>` and
`PATH` (Apache as `apache2` and `httpd`). Modules: `/usr/lib/nginx/modules/*brotli*.so`,
`/usr/lib/apache2/modules/mod_brotli.so`, `/usr/lib64/httpd/modules/mod_brotli.so`. Nothing is run.

**What it reads, and in which order it decides**

1. Decoder markers, and no libbrotlidec in NEEDED → judged by its strings (a bundled copy)
2. It **loads libbrotlidec** → judged by that library; its own copy is looked for too
3. The file was not read to the end → `UNKNOWN`, could not be scanned (no claim that markers are absent)
4. It **does not load** it (and has no markers):
   - a distribution package whose sources were checked (nginx, `libnginx-mod-http-brotli-*`,
     `apache2-bin`, `haproxy`), with the distribution's version form and Maintainer, the file as the
     package installed it (`dpkg --verify`), and the package recording a checksum for that file →
     `NOT_APPLICABLE`
   - a Go program whose build information does not name `cbrotli` → `NOT_APPLICABLE`
   - another package, a changed file, a comparison that failed, no checksum recorded → `UNKNOWN`
     (the reason gives the package's version and Maintainer)
   - a build of its own, not a package's → `UNKNOWN`
5. **Undetermined** → `UNKNOWN`, next step "Install binutils (readelf) and run again." **[bug: 1.3]**

**Where it stops**

- Servers outside the fixed places and `PATH` (`/opt/nginx/sbin/nginx`, for example), modules
  outside the fixed places → not found (`--deep` finds their strings) [no record]
- Other servers (lighttpd, h2o, ...) → not looked at [no record]
- A distribution package rebuilt keeping all three (name, Maintainer, version form) → looks like the
  distribution's (dpkg's records are only as honest as whoever wrote them) [design 10.17.2]
- Of the cgo bindings, only `cbrotli` is looked for [design 10.17.5]

**Backing** — [test] the 8 "C11: ..." tests of `hardening.bats`, "round 5: C11 does not take a
partly read file for one without markers" and the 2 "round 7: C11: ..." tests. [integration] the
distribution's nginx, Apache and HAProxy (and the ngx_brotli modules) are `NOT_APPLICABLE` in the
five images; an in-house `.deb`'s `/usr/local/sbin/nginx` and an overwritten `/usr/sbin/haproxy` are
`UNKNOWN` (through the real dpkg).

### C12 snap and flatpak

**What it looks for** — what was installed as snaps and flatpaks and is known to carry a Brotli
decoder.

**How it finds them** — `snap list`, `flatpak list --app` (application ID, version, installation),
and the `libbrotlidec*` under `/var/lib/flatpak/runtime` (up to 8 levels deep; debug symbols left
out).

**What it reads, and in which order it decides**

1. The `node` snap → its `snap list` version against the data's `node` rows. `chromium`, `firefox`
   → the browser rules (C13)
2. Other snaps → `VENDORED_COPY` (Electron-based) when `resources.pak`, `app.asar`,
   `chrome_100_percent.pak` or `libnode.so` is under `/snap/<name>/current` (up to 4 levels).
   Otherwise nothing is shown
3. Chromium, Chrome and Firefox flatpaks → the browser rules (whatever the installation)
4. Other flatpak applications → for a `system` installation, `VENDORED_COPY` when the same markers
   are under `/var/lib/flatpak/app/<ID>/current/active/files`. A `user` installation is not looked
   into
5. A flatpak runtime's `libbrotlidec` → judged by the version in its file name and confirmed by its
   strings (strings alone without a version)
6. Next step: `snap refresh` / `flatpak update`; a `FIXED` line needs no update for that line

`snap list` or `flatpak list` failing → could not be scanned. Without `snap` or `flatpak`, nothing
is done.

**Where it stops**

- Libraries inside snaps (the `libbrotlidec` in base snaps such as `core22` and `core24`, or in
  `gnome-42-2204` and the like) → not looked at. **Nothing is shown** [no record] **[to change:
  judge the libbrotlidec inside snaps, as for flatpak runtimes]**
- flatpak applications installed per user (or in an extra installation) → not looked into for
  Electron. **Nothing is shown**. Electron applications are found by `--deep`'s strings (they are
  under the homes), and a per-user runtime's `libbrotlidec` is found by name by C09 (it is under the
  homes) [design 10.30]
- The decoder inside snap or flatpak applications without Electron markers → not looked at [no record]
- snap and flatpak versions are not checked against strings (a package record) [design 10.25]

**Backing** — [test] the 4 "#9 C12: ..." tests of `basis.bats`; `hardening.bats` "round 6: Electron
snaps are found through /snap/NAME/current, which is a symlink", "round 6: Firefox's application.ini
and a flatpak runtime's file name are confirmed by strings", "C12: a flatpak runtime's libbrotlidec
before the range is UNKNOWN, ...", "round 8: flatpak runtimes: real libbrotlidec.so and archives are
found, debug symbols are not", "round 7: a flatpak runtime's libbrotlidec without a full version in
its name ...", "round 6: snap list and ss failures are listed as not scanned"; `skipped.bats` "#10
commands that fail could not be scanned: ..., snap list, flatpak list, ss". Per-user flatpaks: [code]
`bcc_check_c12`. libbrotlidec inside snaps: [measured] 2026-11-13 on the developer's host (1.0.9 in
`core22` and `gnome-42-2204`, 1.1.0 in `core24` and `gnome-46-2404`).

### C13 Browsers

**What it looks for** — Chromium, Google Chrome and Firefox (which bundle Brotli).

**How it finds them** — Chromium by the names `chromium` and `chromium-browser` at
`/usr/lib/chromium/chromium`, `/usr/lib/chromium-browser/chromium-browser` and on `PATH`; Chrome at
`/opt/google/chrome/chrome`; Firefox by the names `firefox` and `firefox-esr` at
`/usr/lib/firefox/firefox`, `/usr/lib/firefox-esr/firefox-esr`, `/opt/firefox/firefox` and on `PATH`.

**What it reads, and in which order it decides**

1. Version: `--version` (not a package's; when you agreed; a log line Chrome prints before the
   version is not taken) → for Firefox, `Version=` in the `application.ini` next to it → for a dpkg
   package, the package's version (before the `-`). With none, it is judged by its strings
2. Chromium needs a four-part version, else `UNKNOWN`; 148 with a build before 7778 is `UNKNOWN`
   (before the Brotli roll). A Debian-style `~` suffix is a pre-release
3. Firefox with `esr` in the version uses the ESR row, otherwise the regular one; `a1`, `b3` and
   `~b3` are pre-releases
4. A `FIXED` from `application.ini` is confirmed by the strings of the `libxul.so` next to it (or
   the browser itself when there is none)
5. The next step of a `VULNERABLE` line is the browser's update

Information: "Electron applications bundle their own Chromium and Brotli; --deep lists such
copies."

**Where it stops**

- Edge, Brave, Opera, Vivaldi and other Chromium-based browsers → not found by name and not judged
  by version (`--deep` finds their strings) [limitations]
- Browsers outside the fixed places and `PATH` → not found [no record]
- The baselines come from Chromium's and Firefox's source trees, not from a vendor's advisory
  (`analysis`; the reason says so) [design 6, 10.16]
- Browsers as snaps and flatpaks → C12

**Backing** — [test] `checks.bats` "C13: Chromium needs a four-part version; ...", "C13: Firefox and
Firefox ESR use their own thresholds"; the 3 "#9 C13: ..." tests of `basis.bats`; `hardening.bats`
"pre-release: Firefox Nightly and Beta of the fixed version are UNKNOWN", "round 5: a Chromium
version with a Debian-style pre-release suffix is not the release"; `version.bats` "version from
output: a log line before the version is not taken (Chrome)".

### C14 Containers (`--containers`, `--inspect-containers`)

**What it looks for** — running containers, and inside them (`--inspect-containers`) the
distribution's `libbrotli1` and `python3-brotli`, Node.js, and PyPI's Brotli and brotlicffi.

**How it finds them** — `docker` (or `podman` when there is no `docker`). First the engine is asked
where it connects (`docker context inspect`, `podman info`), then `ps` (running), `ps -a` and
`images -q`. Every later call stays on the context that was checked.

**What it reads, and in which order it decides**

1. Neither docker nor podman → could not be scanned. Done
2. Where it connects, under information (a unix socket on this host, podman with no service,
   anything else, not known)
3. `ps` fails → could not be scanned. Done
4. The number of stopped containers (IDs in `ps -a` and not in `ps`) and of images, under
   information; each, when 1 or more, one line under not scanned. A number that could not be taken
   is "?", under could not be scanned
5. Not reached through this host → the containers are listed under information and nothing runs
   inside (could not be scanned with `--inspect-containers`, not scanned without)
6. Without `--inspect-containers` → listed only (not scanned). With `--no-exec` → not looked inside
   (not scanned)
7. In each container a fixed check script (POSIX sh) runs through `exec`. It reads `ID`,
   `VERSION_CODENAME` and `UBUNTU_CODENAME` of `/etc/os-release`; `dpkg-query` for `libbrotli1` and
   `python3-brotli`; `--version` of `node` and `nodejs` on `PATH` (and `/usr/local/bin:/usr/bin:/bin`);
   in the Python directories (`/usr/lib/python3/dist-packages`, `/usr/local/lib/python3*/site-packages`,
   `/usr/lib/python3*/site-packages`, `/opt/*/lib/python3*/site-packages`) the extension modules (path
   and size) and the metadata of Brotli and brotlicffi; and `END` last
8. Packages: when the OS is Debian or Ubuntu (or has `UBUNTU_CODENAME`), judged by the source
   version as in C01. Any other OS: information "Container ...: OS "..." is not supported for package
   checks."
9. Node.js: judged by its `--version` (the libraries it loads are not looked at).
   **[bug]** The rule is the host's: a node that loads libbrotlidec is judged by that library, and a
   distribution's nodejs follows the verdict on `libbrotli1` (README, "What a verdict rests on";
   limitations). The code now judges a node inside a container by its version alone, so a
   distribution's nodejs that loads the OS libbrotli (Ubuntu 22.04's 12.22.9, Debian 12's 18.19.0,
   ...) is `VULNERABLE` as an end-of-life line (exit status 1)
10. PyPI: Brotli metadata at `python3-brotli`'s own version (in `/usr/lib/python3/dist-packages`) is
    left to the package line. Anything else is judged as in C06, and a `FIXED` is confirmed against
    the package's own extension modules, read inside the container by `head -c` through the engine
    (under the size and time limits) and judged on this host. No module, one not read to the end,
    one not read at all → `UNKNOWN` (the last two also under could not be scanned)
11. Next step: a `FIXED` line needs no update for that line; otherwise rebuild the image and
    redeploy (for an unconfirmed Python package, check it in the image)
12. The script does not run → could not be scanned. No `END` → could not be scanned. `dpkg-query`
    failing inside → could not be scanned

**Where it stops**

- The inside of stopped containers and images → not looked at; their number under not scanned
  [design 10.24]
- Containers not reached through a unix socket on this host (or podman with no service) → nothing
  runs inside [design 10.20]. Another host's socket brought to a unix socket here (over ssh, for
  example) cannot be told from this host's [design 10.20.2]. podman-docker does not say where it
  connects, so its containers are not looked inside [design 10.20.6]
- With docker present, podman is not tried [design 10.20.6]
- Packages of Alpine (apk) and the like → not judged [design 6]
- Node.js not on `PATH`, Python outside the four directories above, other copies inside the
  container (Envoy, .NET, a private libbrotlidec, static copies) → not looked at [design 10.9.10,
  10.29.6; no record for the other copies]
- A container without `head` → the script cannot take names and versions; the PY and OS lines do not
  appear [no record; decided not to change for now]
- Processes inside containers needing a restart → C03 does not compare them [design 10.19.3]

**Backing** — [test] the 29 tests of `containers.bats`, the 19 of `container-python.bats`; the 3
"C14: ..." tests of `checks.bats`; the 3 "#9 C14: ..." tests of `basis.bats`; `hardening.bats` "C14:
the probe finds node with dash ...", "C14: a probe that stops before its end ...", "pre-release: a
Node.js release candidate in a container is UNKNOWN", "round 6: Brotli under a container's
dist-packages without python3-brotli is judged", "round 6: a Python package of the distribution in a
container is left to its PKG line", "round 7: C14: ...", "round 8: C14: ...", "round 9: C14: ...".
[integration] through docker's real unix socket, both Node.js copies and PyPI Brotli 1.2.0
(`VULNERABLE`) and 1.2.1 (`FIXED`) inside a container; through a TCP relay nothing inside is looked
at; a stopped container is listed under not scanned. [measured] podman's answer on whether it is a
client (`podman info`) on podman 3.4.4, 4.3.1, 4.9.3, 5.4.2 and 5.7.0 (design 10.20.1); looking
inside a real podman's containers was not tried. The [bug] of step 9: seen on 2026-11-13 with a fake
docker (as the unit tests use one); not tried with a real container.

### C15 Listening sockets (`--exposure`)

**What it looks for** — node, bun, envoy and Python processes listening beyond loopback (hints of a
path; `EXPOSURE`).

**How it finds them** — `ss -ltnpH` (TCP listening sockets, with processes).

**What it reads, and in which order it decides**

1. No `ss`, or `ss` fails → could not be scanned
2. Loopback (`127.*`, `::1`, `::ffff:127.*`) is skipped
3. An owning process named `node`, `nodejs`, `bun`, `envoy`, `python`, `python3`, `python3.*`,
   `uvicorn` or `gunicorn` → `EXPOSURE` ("Listens on a non-loopback address. Whether it can be
   reached from outside (firewall, routing) is not checked.")
4. Sockets whose owner cannot be seen, when not running as root → not scanned

**Where it stops**

- Whether it can be reached from outside (firewall, routing) → not looked at [design 10.21]
- Programs that do not listen but fetch and decode responses → not shown; no `EXPOSURE` is no proof
  that there is no path [design 10.21.4]
- UDP sockets → not looked at [no record]
- Only the first process of a socket is looked at. Processes of other names (`docker-proxy`, for
  example) → not shown [no record]
- Sockets inside containers (other network namespaces) → not visible to this host's `ss` [no record]

**Backing** — [test] `checks.bats` "issue #7: C15 says the process listens beyond loopback, ...";
`skipped.bats` "#10 a needed program that is missing: ... ss for --exposure ...", "#10 commands that
fail could not be scanned: ...", "#10 other users' sockets are left out by not being root". The list
of names, and taking the first process only: [code] `bcc_check_c15`.
