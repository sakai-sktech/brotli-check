# Limitations

日本語: [limitations.ja.md](limitations.ja.md)

What the tool can miss or cannot decide, and why. "Nothing found" never means "safe".

## Copies the tool can miss

- **Outside the search roots.** By default `/opt, /usr/local, /srv, /var/www, /home, /root`
  plus the system Python and library directories. Use `--roots` for other places.
- **Inside archives and images that are not running**: `.asar`, `.jar`, `.zip`, AppImage and
  squashfs files, container images without a running container, VM disks, backups.
- **Static copies without markers.** `--deep` recognizes a bundled decoder by its exported
  symbol names (`BrotliDecoderDecompressStream`, ...) or its error-name strings. A fully
  stripped, link-time-optimized binary that does not use `BrotliDecoderErrorString` can carry
  neither and is then invisible. For the web servers of C11 this is why "no markers" is
  `NOT_APPLICABLE` only for a packaged file or a Go program without the cgo binding; a server
  you built yourself is `UNKNOWN`. A static curl that was not run is `UNKNOWN` for the same reason.
- **Network file systems** (NFS, CIFS, sshfs, ...) unless `--include-remote`.
- **Search roots that are symbolic links** are searched at their targets (the report says so);
  other symbolic links are never followed.
- **Other file systems below the search roots.** Local disks mounted below a root are searched;
  tmpfs, overlay, squashfs, fuse and other kinds are not, and are listed under "Not scanned"
  (name them with `--roots`). btrfs subvolumes that are not mount points are not searched and not
  listed (`find -xdev` stops at them, and they do not appear in the mount table).
- **Other implementations.** Go (`andybalholm/brotli`), Rust (`brotli-decompressor`), Java and
  .NET decoders are separate code bases and are not checked; whether they are affected by this
  CVE is not covered here.
- **Electron applications** installed outside snap/flatpak are found only with `--deep`.
- **Containers based on Alpine** (apk) get no package check inside (`--inspect-containers`
  covers Debian/Ubuntu-based images and Node.js / PyPI copies).
- Only Linux. Only Debian, Ubuntu and their derivatives for package checks.

## Without root

Other users' processes (C03, C04 restart checks, C15 socket owners), `/root` and unreadable
home directories are not visible. The report lists them under "Not scanned".

## The string heuristic (LIKELY_FIXED / LIKELY_VULNERABLE)

The fix added a new decoder error, `_ERROR_FORMAT_BLOCK_SWITCH` (-17), and
`BrotliDecoderErrorString` builds its names from the error list. Verified results
([tests/fixtures/c09/README.md](../tests/fixtures/c09/README.md)):

| Build | Unfixed (1.2.0) | Fixed (1.2.1) |
|---|---|---|
| shared library, stripped or not | 16 names, no BLOCK_SWITCH | 17 names, BLOCK_SWITCH |
| static, -O2, stripped or not | same | same |
| static, LTO + gc-sections, program uses `BrotliDecoderErrorString` | same | same |
| static, LTO + gc-sections, program does not use it | **0 names** | **0 names** |
| Node.js 22.23.3 / 22.23.4, 24.22.0 / 24.22.1 official binaries | 16 | 17 |
| PyPI Brotli 1.2.0 / 1.2.1, brotlicffi 1.2.0.x / 1.2.1.0 wheels | 16 | 17 |

So the heuristic decides only when the error names are present (at least 8), and reports
`VENDORED_COPY` otherwise. The 1.0.10 and 1.1.1 fixes add the same error code (checked in the
source); their binaries were not built for the verification. A vendor's own patch that fixes
the flaw differently would not carry the marker and would show as `LIKELY_VULNERABLE`; when
a file name says one thing and the strings another, the tool reports `UNKNOWN`.

The linker merges equal strings, so a file with two copies of the decoder shows one set of
names: one fixed copy would hide an unfixed one. The tool counts copies of Brotli's built-in
dictionary (one per copy) and reports `UNKNOWN` instead of `LIKELY_FIXED` when there are two or
more. Two decoders that share one dictionary, or a copy built with an external dictionary, are
not told apart; that is why a `LIKELY_FIXED` line says what was found (the fix's error name, the
number of dictionaries) and what was not determined (whether all decoder code in the file is
fixed). Files are read up to the size limit (512 MiB); a file that could not be read to the end
is `UNKNOWN` and is listed under "Not scanned".

A version read from a file rather than from the program (a directory name, `node_version.h`,
package metadata, a library's file name) gives `FIXED` only when the file's strings confirm the
fix in a single copy of Brotli; otherwise the result is `UNKNOWN` and says what was missing.

## Version numbers

- Distribution packages are compared by the distributor's fixed version; a fix released after
  the data snapshot is not known (`NO_FIX_AVAILABLE` may be outdated). Watch the data date.
- The data is per release line. Bun before 1.0.21 is outside the range of its advisory
  (GHSA-663w-cv8g-jj2p: 1.0.21 to 1.4.3) but is reported like the other versions before 1.4.4.
- Debian's `nodejs` uses the system libbrotli (judged through `libbrotli1`); a statically
  linked distribution build is judged by strings because its version may not show backports.
- Chromium and Firefox thresholds come from the source trees (third_party/brotli,
  modules/brotli), not from vendor advisories. Chromium-based browsers other than Chrome and
  Chromium (Edge, Brave, ...) are not judged by version.
- Node.js lines that reached end of life (20 and earlier, 21, 23, 25) are reported as
  vulnerable by derivation: the Node.js advisory says end-of-life versions are always affected
  and no fixed release exists for them. Versions 10 and earlier are `UNKNOWN` (they may predate
  bundled Brotli).
- A pre-release (`1.4.4-rc.1`, Firefox `150.0a1`/`150.0b3`, Node.js nightly or `-pre` builds) of
  exactly the fixed version is `UNKNOWN`: it may have been built before the fix.

## Running programs

To read exact versions the tool asks to run some programs it found, each with one argument
(`--version`, or `-V` for curl). Nothing found runs without your consent: the tool lists them
first, with facts — who besides root (or you) could change the program, a directory on its
path, a library it would load or a directory those are searched in, and anything it could not
examine — and asks at the terminal (all, none, or by number). Without a terminal it needs
`--yes` or `--no-exec`. The facts are as complete as the walk can make them: it follows
symlinks where they are and looks libraries up the way glibc's ld.so does (DT_RPATH of the
needing object and of its loaders, DT_RUNPATH, the ld.so cache, the default directories), but it
cannot see what a program opens once it runs (dlopen, configuration files), and tokens such as
`$LIB` are not expanded (the facts say so). Programs run from `/`, with an empty environment, a
time limit and their output capped. `--inspect-containers` runs a fixed read-only script inside
running containers; asking for it is the consent.

System tools (`readelf`, `stat`, `dpkg-query`, ...) are taken from `/usr/sbin`, `/usr/bin`,
`/sbin` and `/bin` (and `/usr/local/sbin`, `/usr/local/bin` when only root can change them),
never from your `PATH`. The launcher itself is found through your `PATH`
(`#!/usr/bin/env bash`): run it as `sudo bash brotli-cve-check`, where sudo's `secure_path`
applies.

## The advisory data (`--data`)

The data decides the verdicts. A file given with `--data` that users other than root (or you)
can change — the file, or a directory on its path, by the same rule as `--output` — is used, but
the report warns about it at the top (`data_writable_by_others` in JSON). Only regular files are
read, at most 16 MiB, under the time limit.

## Writing the report (`--output`)

`--output` creates a new file and never overwrites or opens an existing one. Every directory
from the target up to `/` must be owned by root (or by you, when you are not root), and not
writable by other users except through the sticky bit of a root-owned directory such as `/tmp`.
As root, that rules out users' home directories: a user who owns the directory could otherwise
redirect a root-written file elsewhere. To keep a root scan in your home, redirect stdout:
`sudo bash brotli-cve-check > report.txt`.

## What the result is not

- Not an intrusion check. Updating does not remove traces of a compromise that happened
  before the update.
- Not a statement about other hosts, or about containers that were not running.
