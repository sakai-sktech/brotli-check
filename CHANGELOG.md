# Changelog

## 0.1.0 - unreleased

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
