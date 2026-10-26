# Verification results

日本語: [verification.ja.md](verification.ja.md)

What was checked before the first release, how, and what came out. Date: **2026-10-26**.
Advisory data: snapshot 2026-10-26.

One-page figures (A4): [Fig. 01 What we checked, and how](zukai/01_check-method_en.pdf) ·
[Fig. 02 Results on 5 OSes, and how to read them](zukai/02_results-reading_en.pdf)
(Japanese: [図解 01](zukai/01_check-method_ja.pdf), [図解 02](zukai/02_results-reading_ja.pdf)).

## How to read these results (as of 2026-10-26)

The integration tests below put known-unfixed and known-fixed copies into each image on purpose,
so every run ends with exit status 1. What they show:

- **The tool judges correctly.** Every expected verdict matched, as root and as an ordinary user
  with `--no-exec`.
- **Ubuntu: the operating system's Brotli is not fixed yet in any release.** `libbrotli1` and
  `python3-brotli` are `NO_FIX_AVAILABLE` on 22.04, 24.04 and 26.04 (and 26.10). Their versions
  (1.0.9, 1.1.0, 1.2.0) are all inside the affected range 1.0.3–1.2.0, and Ubuntu had not
  published a fix: the CVE page says "Needs evaluation" and there is no USN.
  - Candidate updates (`1.0.9-2ubuntu0.1`, `1.1.0-2ubuntu0.1`, `1.2.0-3ubuntu0.1`,
    `1.2.0-4ubuntu0.1`) appeared in the `ubuntu-security-proposed` PPA on 2026-10-25. That PPA is
    for testing and is not used by normal systems; a fix reaches them through the `-security` pocket
    once a USN is published. Until then there is nothing to install from Ubuntu, and the tool's
    advice is to wait and to update bundled copies first.
- **Debian: fixed.** Debian 12 (`1.0.9-2+deb12u1`) and 13 (`1.1.0-2+deb13u1`) are `FIXED`.
- **Bundled copies can be fixed today on every distribution.** Node.js 22.23.4 and PyPI
  Brotli 1.2.1 are `FIXED` and their predecessors `VULNERABLE` regardless of the OS. These copies
  are not touched by OS updates, which is why the tool looks for them.

## Static checks and unit tests

| Check | Tool | Result |
|---|---|---|
| `make lint` (per file, and the single-file build with all checks) | ShellCheck 0.9.0 (Ubuntu package) and 0.10.0 (upstream release) | zero warnings |
| `make test` | Bats 1.10.0 (Ubuntu package) and bats-core 1.11.1 | 83 / 83 passed |

## Integration tests (`tests/integration/`)

Docker 28.3.0 (Docker Desktop, x86_64). Each image adds, on top of the distribution:
official Node.js 22.23.3 and 22.23.4 in `/opt` (verified against `SHASUMS256.txt`), PyPI Brotli
1.2.0 with urllib3 in `/srv/venv-old`, and Brotli 1.2.1 in `/srv/venv-new`. Each image is scanned
twice: as root, and as an ordinary user with `--no-exec`.

| Image (as reported) | Python | `libbrotli1` / `python3-brotli` | Node.js 22.23.3 / 22.23.4 | PyPI Brotli 1.2.0 / 1.2.1 | urllib3 next to 1.2.0 | root / user |
|---|---|---|---|---|---|---|
| Ubuntu 22.04.5 LTS | 3.10 | 1.0.9-2build6: `NO_FIX_AVAILABLE` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |
| Ubuntu 24.04.5 LTS | 3.12 | 1.1.0-2build2: `NO_FIX_AVAILABLE` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |
| Ubuntu 26.04.1 LTS | 3.14 | 1.2.0-3build1: `NO_FIX_AVAILABLE` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |
| Debian 12 (bookworm) | 3.11 | 1.0.9-2+deb12u1: `FIXED` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |
| Debian 13 (trixie) | 3.13 | 1.1.0-2+deb13u1: `FIXED` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |

Notes:

- The Node.js tarballs keep their packager's owner (uid 1001) when unpacked by root. As root, the
  tool therefore did not run them and read the version from `include/node/node_version.h`; the
  verdicts were the same as with `--version`.
- **bash 4.2** (`bash:4.2`, digest `sha256:75a8dcd5c2a865e69116225dc486e2dbdd2dda1434759fa7f1fc50c72eeadbea`,
  with GNU coreutils, findutils, grep, sed, gawk and binutils added): a PyPI Brotli 1.2.0 record
  was found and judged `VULNERABLE`, exit status 1, valid JSON.
- Sample output from the Ubuntu 24.04 image: [sample-output.md](sample-output.md).

Problems found by the integration run and fixed before this result: the Node.js download helper
was not executable; one expectation was wrong (`EXPOSURE` needs an HTTP client next to Brotli, and
the first image had none); the bash 4.2 step did not exercise any verdict; two English messages
broke grammar with a count of one.

## String heuristic for bundled copies (C09)

Brotli 1.2.0 and 1.2.1 built as shared and static libraries (-O2 and LTO, stripped or not),
official Node.js 22.23.3 / 22.23.4 / 24.22.0 / 24.22.1, and PyPI Brotli and brotlicffi wheels:
every fixed artifact contains `_ERROR_FORMAT_BLOCK_SWITCH` and every unfixed one does not. The only
undecidable case is LTO with garbage collection when the program never calls
`BrotliDecoderErrorString`; the tool then reports `VENDORED_COPY`. Rerunning
`tests/fixtures/c09/reproduce.sh` from scratch produced byte-identical fixtures.
Details and download checksums: [tests/fixtures/c09/README.md](../tests/fixtures/c09/README.md).

## On a real workstation

Run on a developer workstation (Ubuntu 24.04, as an ordinary user), the tool found copies that an
OS update does not fix, for example: Node.js 14.16.0 bundled by VS Code Server, Node.js bundled by
Playwright and by a GitHub Actions self-hosted runner (one runner process still running a replaced
executable: `RESTART_REQUIRED`), `libbrotlidec` 1.2.0 inside Pillow wheels, and, with `--deep`,
Cloudflare workerd, .NET's `libSystem.IO.Compression.Native.so`, PyMuPDF and several Electron
applications. Paths are not published here.

## Primary sources

The re-check of every advisory version against its primary source, and the corrections it led
to, are in [design.md, section 2](design.md#2-primary-sources-re-checked-settled-2026-10-26).
