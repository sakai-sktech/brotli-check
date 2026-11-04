# Changelog

## Unreleased

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
