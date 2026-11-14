# Changelog

## 0.2.0 - 2026-11-14

For automation: exit status `2` now also means that a range the run set out to look at could not
be scanned, even when nothing was found, and JSON `skipped[]` entries carry `"kind"` (`"chosen"` or
`"failed"`). Both are described in the item on exit status 2 below.

- `RESTART_REQUIRED`: the line now gives what this report judged about the file now at the
  deleted file's path, and the next step follows from it: restart when that file is fixed; update
  first when it is not (a restart alone does not fix it); check the version first when nothing
  judged it, when there is no file there, or when the process runs in another mount namespace (a
  container, snap or flatpak). The status is defined as what is seen: a process still using a
  deleted Brotli-related file. "Replaced" became "deleted" in the reasons. In JSON, C03's findings
  now come after C13's (docs/design.md 10.19, #5).
- README: get v0.1.0 from its release, in a new directory, with the download and the checksum
  check joined so that a failure stops the rest; reading and running are separate steps, and the
  commands that run the file check the checksum again. The checksum confirms an intact download,
  not who made the file. The source tree, at the tag, is described as the other way (#4).
- Verification results say what the tests show and what they do not: in the images, ways of
  running and builds tried, every expected verdict matched; how often copies are missed or
  misjudged on real hosts was not measured. "The tool judges correctly" and "the only undecidable
  case" now name their conditions (Brotli 1.2.0 and 1.2.1 built with gcc 13 on x86_64, official
  Node.js binaries, PyPI wheels; 1.0.x, 1.1.x, other compilers and architectures not tried), and
  Fig. 02 calls exit status 1 the intended result. The JSON `confidence` of `LIKELY_*` lines names
  the builds tried instead of saying "verified" (docs/design.md 10.22, #11).
- A `node`, `bun`, `curl`, `envoy`, server or browser found by its name that is a link to a
  program of another name (a version manager's shim such as `node -> mise`, snap's launcher in
  `/snap/bin`) is no longer dropped without a word. It is still not run, and no version is read
  for it. The file it points to is judged by the libbrotlidec it loads or by its decoder strings;
  with neither, the report names the link under information, and under "Not scanned" when that
  could not be told (docs/design.md 10.23, #19).
- `EXPOSURE` reasons (C06, C07, C10, C15) say what was seen and what was not: that a package is
  installed, that a configuration file names a Brotli decompressor, that a process listens beyond
  loopback; not whether an application uses it, whether the running Envoy uses that file, or
  whether it can be reached from outside. They no longer say "decodes ... automatically". The
  README and the JSON schema say that no `EXPOSURE` is not proof that there is no path (#7).
- Containers (C14): the report shows where docker or podman connects, as the engine states it
  (`docker context inspect`, `podman info`). Containers are listed and counted whatever the
  connection, but the check script of `--inspect-containers` runs inside them only through a unix
  socket on this host, or with podman running them itself, and on the docker context that was
  checked; otherwise the connection and the reason are listed under "Not scanned". The help and
  the report header no longer say "read-only"; for-clinics and figure 01 tell what the tool itself
  does from what the programs it runs may do. The integration run tries C14 through a real
  engine, by its unix socket and by a TCP relay to it (docs/design.md 10.20, #6).
- Containers (C14): `--containers` also counts the stopped containers, and the stopped containers
  and the images are listed with their number under "Not scanned" (`C14 (stopped containers)`,
  `C14 (images)`), also when no container runs; nothing inside them is run or read, with or
  without `--inspect-containers`. A count that could not be taken is shown as `?` with the call
  that failed, no longer as 0 images. The "Not scanned" lines for running containers say
  "running containers". `--help` says which files `--deep` reads (executable or named `*.so`,
  `*.so.*`, `*.node`; ELF below 512 MiB; not the whole disk) and that `--containers` lists the
  running containers and only counts the rest; the limitations say the same (docs/design.md
  10.24, #8).
- `FIXED` reasons say where the version came from: "At or above the fixed version X (the
  distribution package version)", "(output of node --version)", "(version from the directory
  name)", and likewise for snap, flatpak, dpkg's record of a browser's package, package metadata,
  conda records, library file names and `application.ini`, inside containers too. A version read
  from a file, which needs the decoder's strings to confirm the fix, also says what was found (in
  which file the fix's error name is) and what was not determined (whether all decoder code in
  the file is fixed), as `LIKELY_FIXED` does. The next step of every `FIXED` line is "No update
  needed for this line (other lines and the ranges not scanned are separate)"; C01 keeps its
  restart sentence after it, and `FIXED` lines inside containers and of flatpak browsers no longer
  say to rebuild the image or to run flatpak update. `UNKNOWN` from the data (Node.js 10 and
  earlier, Envoy 1.17 and earlier) says why instead of "see evidence" (docs/design.md 10.25, #9).
- **The meaning of exit status 2 changes.** A range that the run set out to look at but could
  not now makes the exit status `2` even with no finding (`1` stays `1`); before, such a run
  exited `0` and said that nothing was found, for example when dpkg-query failed and no
  distribution package was judged. Ranges left out by how the tool was run (options not given,
  `--exclude`, `--no-exec`, programs not chosen, not running as root, network and other file
  systems below the roots, stopped containers and images, which are only counted) are still not
  counted. A missing program the check needs counts as could not be scanned: no dpkg (not
  Debian/Ubuntu), no ss with `--exposure`, neither docker nor podman with `--containers`; so does
  a root named with `--roots` that does not exist, and what root could not read. Automation that
  gives `--containers` to hosts without an engine now gets `2` from them. The text report lists
  these under a new section "Could not be scanned" (`[FAILED]`) before "Not scanned" (`[SKIPPED]`),
  and the summary has a fifth line, "Could not be scanned: ..." ("none" when there is nothing).
  JSON `skipped[]` entries carry `"kind": "chosen"` or `"failed"`. As root, unread processes are
  no longer told to run as root. The `FIXED` next step names both kinds of ranges (docs/design.md
  10.26, #10).
- .NET (C09): the decoder that the .NET runtime builds into `libSystem.IO.Compression.Native.so`
  (`System.IO.Compression.Native.so` before .NET 5) is found by name under the search roots and
  in `/usr/lib/dotnet` and `/usr/share/dotnet`, and judged by .NET's own version: a file of
  Ubuntu's .NET packages by the package's version (USN-8958-1), any other copy (Microsoft's
  archives and packages, the copy a self-contained application carries) by the version its build
  stamped into the file, `@(#)Version 8.0.3326.52219` being 8.0.33. New data rows: Microsoft's
  8.0.33, 9.0.22, 10.0.14 and 11.0.0-rc.3.26522.148 (GHSA-p3jp-9v83-76w9); Ubuntu's dotnet8,
  dotnet10 and dotnet11; end-of-life lines .NET Core 3.0 to .NET 7 and Ubuntu's dotnet7
  `VULNERABLE` (they bundle Brotli 1.0.7 or 1.0.9 and get no fix), .NET Core 2.1 and 2.2 `UNKNOWN`
  under a new status `derived_before_range` (Brotli 1.0.1, before the advisory's range), Ubuntu's
  dotnet6 `NO_FIX_AVAILABLE`. .NET 8's library carries no decoder error names, so its `FIXED`
  rests on the stamp and says that the fix is not seen in its strings; .NET 9 and 10 are checked
  against their strings too. A copy outside `shared/Microsoft.NETCore.App/<version>/` is
  `dotnet (self-contained)`, with "a release built with a fixed .NET" as its next step.
  Single-file and NativeAOT executables are left to `--deep`, and NuGet's packages folder is
  counted with the package-manager caches. C03 also reports processes that still map a deleted
  .NET library. Pre-releases of one version now sort by their identifiers (rc.2 before rc.3)
  (docs/design.md 10.27, #17).
- A program that loads more than one library named `libbrotlidec*` (the OS one and a private one,
  for example) gets every one judged, no longer the first alone; one file reached under two
  names, or needed by two libraries, counts once, and a name already loaded is not looked up
  again, as ld.so does. `glibc-hwcaps` subdirectories (`x86-64-v3` and the like) are tried in the
  order the system's loader gives for this CPU, no longer by name, in RUNPATH and RPATH
  directories, the ld.so cache and the default directories, and the facts on the list of
  programs to run name only the ones it searches. To learn that order the tool runs the system's
  loader once with `--help`, from `/` with an empty environment, also with `--no-exec` (only when
  only root can change it, and glibc 2.33 or later). For a program that names another loader, or
  when the loader could not be asked, every copy in those subdirectories is judged and the report
  says that which one loads could not be told. The older hwcaps subdirectories of glibc 2.36 and
  earlier (`tls`, `x86_64`, ...) are not looked at; the limitations say so (docs/design.md 10.28,
  #18).
- PyPI's Brotli and brotlicffi inside a container (`--inspect-containers`) at or above the fixed
  version can be `FIXED` now, as on this host: each package's own extension module
  (`_brotli.*so`, `brotlicffi/_brotlicffi*.so`) is read inside the container by `head` through
  the engine, on the docker context that was checked, up to the size limit and under the time
  limit, and its strings are judged on this host; nothing is written. The check script lists the
  modules with their sizes. A module that is not there, is over the size limit, could not be read
  to the end or could not be read at all leaves the line `UNKNOWN` with its reason (the last
  three also under "Could not be scanned"), and the next step of such a line is about the image
  (check the package in it, or ask whoever built it), no longer "ask the vendor". The help, the
  README, the limitations and SECURITY.md say that `head` runs inside containers too; the
  integration run's C14 step expects PyPI Brotli 1.2.0 `VULNERABLE` and 1.2.1 `FIXED` in a real
  container (docs/design.md 10.29, #27).
- New document, `docs/how-it-checks.md` (and `.ja.md`): for each check, C01 to C15, what it looks
  for, how it finds it, what it reads and in which order it decides, and where it stops, after a
  part common to all of them (the clues a copy is found by, where the walk goes, how linked
  libraries are followed, the strings estimate, the advisory data, running programs, the limits,
  and the ranges not scanned). Each place where a check stops names the design note that decided
  it, or says that none did, and each statement says whether a test or a measurement backs it.
  Where the checks stop is a design decision and this document is the rule: code that differs
  from it is a bug, and moving a stop needs a design note and a change of the document in the
  same pull request (CONTRIBUTING.md, docs/design.md 10.30, #35). The README links to it.
- Advisory data snapshot 2026-11-14 (docs/design.md 2.3): every primary source checked again. Debian
  testing (forky) is fixed in 1.2.0-4.1, which migrated on 2026-11-04: 1.2.0-4 there is now
  `VULNERABLE`, no longer `NO_FIX_AVAILABLE`, and no row is `unreleased`. A new `analysis` row for
  Istio 1.32.0. The notes of .NET 8 and 9 give their end of support (2026-11-10) and their last
  releases, which have the same Brotli; the note of .NET 11 says that 11.0.0 has the same Brotli as
  the fixed release candidate. The notes of pre-1.0 Brotli and of PyPI's Brotli and brotlicffi add
  Debian's statement that the flaw came with 35e69fc7 (v1.0.3); the sources still disagree below
  1.0.3. Firefox's source URL points at the tag its note is about. The limitations name virtual
  machine firmware (edk2), which Debian's tracker lists for this CVE and the tool does not check.

## 0.1.0 - 2026-11-02

First version.

- Detection items C01-C15: distribution packages, packages depending on libbrotli,
  processes needing a restart, Node.js, Bun, PyPI Brotli/brotlicffi and conda, Node.js
  project exposure hints, curl, libbrotlidec outside the package manager and bundled decoders
  (`--deep`), Envoy, compression-only web servers, snap/flatpak, browsers, containers,
  listening sockets.
- String heuristic for bundled copies (`_ERROR_FORMAT_BLOCK_SWITCH`), verified on Brotli
  1.2.0/1.2.1 builds, official Node.js binaries and PyPI wheels.
- Text (English/Japanese) and JSON output; exit codes 0-3.
- Advisory data snapshot 2026-10-27 (every primary source checked again on that date): Ubuntu
  is fixed by USN-8956-1 (2026-10-26), Debian unstable has the fix, Bun is judged by its advisory
  GHSA-663w-cv8g-jj2p (docs/design.md 2.1).
- Found programs (node, bun, envoy, browsers `--version`; curl `-V`) run only with your consent:
  the tool lists them first, with who besides root or you could change each program or what it
  loads, and asks (all, none, by number); without a terminal, `--yes` or `--no-exec`. The report
  lists what ran, its output, and what did not (docs/design.md 10.11). `ldd` is not used.
- Hardening from an adversarial review before release (docs/design.md 10.9): system tools come
  from fixed system directories; `--output` cannot be redirected into a planted directory;
  vendor packages are not mistaken for the
  distribution's Brotli; no decoder markers is no longer proof for hand-built servers or a curl
  that was not run; pre-releases are never taken for the fixed release; reads of found files are
  bounded; failures, exclusions and other file systems are listed under "Not scanned", and local
  disks mounted below the search roots are searched; Node.js inside containers is found with the
  containers' own shell.
- Further rounds of the review (docs/design.md 10.10, 10.12): programs run from `/`; a version
  read from a file is FIXED only when the strings confirm it (also for Firefox, flatpak runtimes,
  conda); the completeness of a read never depends on the file's own bytes; the string heuristic
  reports what it found and what it could not determine; a program loading a private
  libbrotlidec gets that copy judged; search roots that are symlinks are searched at their
  targets (and Electron snaps through `/snap/NAME/current`); a `--data` file that others can
  change is reported at the top; a file that loads libbrotlidec but carries its own decoder is
  judged too; paths with newlines stay whole; failures of snap, flatpak and ss are listed.
- Found paths holding control characters, newlines or tabs (docs/design.md 10.13): the list of
  programs to run is filtered like the report (control characters, tabs and newlines as `?`;
  findings too); the facts stay whole and correct; the program that runs is always the one listed
  (a tab in a path used to make the tool run another file); libraries searched through `$ORIGIN`,
  directories with `[` in their names and long symlink chains are reported as they are.
- A version read from package metadata with no file to confirm it is no longer FIXED
  (docs/design.md 10.15): PyPI Brotli and brotlicffi without their extension module, and conda's
  libbrotlidec without a shared library (not counting symbolic links), are UNKNOWN and say so.
  Python inside containers is UNKNOWN at or above the fix, since the strings are not compared
  there. Each PyPI package is now compared only with its own extension module.
- A version before the affected range an advisory states is no longer VULNERABLE (docs/design.md
  10.16): Bun before 1.0.21, Brotli 1.0.2 and earlier and 0.x, and PyPI Brotli and brotlicffi before
  1.0.3 are UNKNOWN, and the reason names the advisory and the range and recommends an update.
  Node.js end-of-life lines and Envoy 1.35 and earlier stay VULNERABLE, and the reason now gives the
  ground in the text report. The data has a new column, `affected`, and `derived` is now
  `derived_eol` and `derived_bundled`, so a `--data` file in the old form is refused.
- A web server without decoder markers is no longer `NOT_APPLICABLE` just for belonging to a
  package (docs/design.md 10.17): only the distribution's nginx, Apache and HAProxy packages, whose
  sources were read, with the file as installed. Other packages, files changed after installation
  and packages that cannot be compared are `UNKNOWN` and say so. The reason of a Go program says
  that only `cbrotli` is looked for.
- Advisory data snapshot 2026-11-02 (docs/design.md 2.2): every primary source checked again. New
  rows for Ubuntu 20.04, 18.04 and 16.04 (USN-8956-2, Ubuntu Pro) and Firefox ESR 153 and 115; Envoy
  1.17 and earlier, which have no Brotli in their source, are UNKNOWN instead of VULNERABLE.
- Rounds 7 to 11 of the review (docs/design.md 10.18): an old static archive next to a fixed conda
  library and a brotlicffi next to `python3-brotli` in a container are no longer lost; a web server
  that loads libbrotlidec is checked for its own copy too; own copies not read to the end are
  listed; a real `libbrotlidec.so.1` in a Flatpak runtime is judged by strings; a NEEDED entry that
  is a path is recognized; `NOT_APPLICABLE` needs a recorded checksum of the file, and no vendor
  text in the upstream version; dpkg's answer counts only for the very path asked about (it reads
  paths as patterns); what is at a diverted path counts as unpackaged everywhere; very long version
  components no longer wrap; a directory in `PATH` may hold a newline.
- `docs/limitations.md` no longer calls .NET a separate code base: it contains Google's decoder, and
  a default run says nothing about it. Three more cases were added.
