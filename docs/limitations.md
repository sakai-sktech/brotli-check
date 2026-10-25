# Limitations

What the tool can miss or cannot decide, and why. "Nothing found" never means "safe".

## Copies the tool can miss

- **Outside the search roots.** By default `/opt, /usr/local, /srv, /var/www, /home, /root`
  plus the system Python and library directories. Use `--roots` for other places.
- **Inside archives and images that are not running**: `.asar`, `.jar`, `.zip`, AppImage and
  squashfs files, container images without a running container, VM disks, backups.
- **Static copies without markers.** `--deep` recognizes a bundled decoder by its exported
  symbol names (`BrotliDecoderDecompressStream`, ...) or its error-name strings. A fully
  stripped, link-time-optimized binary that does not use `BrotliDecoderErrorString` can carry
  neither and is then invisible.
- **Network file systems** (NFS, CIFS, sshfs, ...) unless `--include-remote`.
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

## Version numbers

- Distribution packages are compared by the distributor's fixed version; a fix released after
  the data snapshot is not known (`NO_FIX_AVAILABLE` may be outdated). Watch the data date.
- Debian's `nodejs` uses the system libbrotli (judged through `libbrotli1`); a statically
  linked distribution build is judged by strings because its version may not show backports.
- Chromium and Firefox thresholds come from the source trees (third_party/brotli,
  modules/brotli), not from vendor advisories. Chromium-based browsers other than Chrome and
  Chromium (Edge, Brave, ...) are not judged by version.
- Node.js lines that reached end of life (20 and earlier, 21, 23, 25) are reported as
  vulnerable by derivation: the Node.js advisory says end-of-life versions are always affected
  and no fixed release exists for them. Versions 10 and earlier are `UNKNOWN` (they may predate
  bundled Brotli).

## Running programs

The tool runs a found program only for `--version` (or `-V`), with an empty environment and a
timeout, and only if the file and every directory above it belong to root (or to you, when you
are not root) and are not writable by others. As root, group-writable paths are never run.
As an ordinary user, a group-writable directory is accepted only when its group is your user
private group (same name as you, your primary group, one entry for the GID, no other members,
nobody else's primary group). This cannot see group passwords (`gshadow`) or users that a
directory service does not enumerate; use `--no-exec` where that matters. Others are judged from files. `ldd` is
subject to the same rule; otherwise linkage is followed with `readelf` and `ldconfig -p`,
which can miss unusual `RUNPATH` setups. `--inspect-containers` runs a fixed read-only script
inside running containers.

## What the result is not

- Not an intrusion check. Updating does not remove traces of a compromise that happened
  before the update.
- Not a statement about other hosts, or about containers that were not running.
