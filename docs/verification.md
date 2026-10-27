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

- **The tool judges correctly.** Every expected verdict matched, as root and as an ordinary user,
  with `--no-exec` and with `--yes`.
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
| `make test` | Bats 1.10.0 (Ubuntu package) and bats-core 1.11.1 | 83 / 83 passed (first run) |
| `make lint`, `make test` after the Codex review, round 4 | ShellCheck 0.9.0, Bats 1.10.0 | zero warnings; 123 / 123 passed |
| the same after round 5 | ShellCheck 0.9.0, Bats 1.10.0 | zero warnings; 134 / 134 passed |
| the same after the consent model and round 6 (2026-10-27) | ShellCheck 0.9.0, Bats 1.10.0 | zero warnings; 153 / 153 passed |
| the same after fixing the automatic security review's findings (2026-10-27, design 10.13) | ShellCheck 0.9.0, Bats 1.10.0 | zero warnings; 161 / 161 passed; the 8 new tests fail on the code before the fix |

## Integration tests (`tests/integration/`)

Docker 28.3.0 (Docker Desktop, x86_64). Each image adds, on top of the distribution:
official Node.js 22.23.3 and 22.23.4 in `/opt` (verified against `SHASUMS256.txt`), PyPI Brotli
1.2.0 with urllib3 in `/srv/venv-old`, and Brotli 1.2.1 in `/srv/venv-new`. Since 2026-10-27 each
image is scanned four times: as root and as an ordinary user, each with `--no-exec` and with
`--yes` (found programs run only with consent; a container has no terminal to ask). Before that,
after rounds 4 and 5, the runs were root by default, root with `--allow-exec`, and an ordinary
user with `--no-exec`. The fixed script of `--inspect-containers` (C14) is also run in each
image's own `/bin/sh` (dash) with both Node.js copies on `PATH`; it must report both, the packages,
and its `END` line.

| Image (as reported) | Python | `libbrotli1` / `python3-brotli` | Node.js 22.23.3 / 22.23.4 | PyPI Brotli 1.2.0 / 1.2.1 | urllib3 next to 1.2.0 | all scans (4) / C14 probe |
|---|---|---|---|---|---|---|
| Ubuntu 22.04.5 LTS | 3.10 | 1.0.9-2build6: `NO_FIX_AVAILABLE` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |
| Ubuntu 24.04.5 LTS | 3.12 | 1.1.0-2build2: `NO_FIX_AVAILABLE` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |
| Ubuntu 26.04.1 LTS | 3.14 | 1.2.0-3build1: `NO_FIX_AVAILABLE` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |
| Debian 12 (bookworm) | 3.11 | 1.0.9-2+deb12u1: `FIXED` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |
| Debian 13 (trixie) | 3.13 | 1.1.0-2+deb13u1: `FIXED` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |

Notes:

- The Node.js tarballs keep their packager's owners (non-root uids) when unpacked by root. With
  `--yes` they are run (the facts in the report name those owners); with `--no-exec` the version
  comes from `include/node/node_version.h`. The verdicts were the same either way.
- Run after the fixes for the Codex review, round 4, again after round 5 (2026-10-26), and after
  the consent model and round 6 (2026-10-27, bash 4.2 with `--yes`), and after the fixes of design
  10.13 (2026-10-27), with Docker 28.3.0: every row ok, bash 4.2 ok. The previous version of the C14 script, run the same way, printed no Node.js
  line and no `END` (the defect of finding 10).
- **bash 4.2** (`bash:4.2`, digest `sha256:75a8dcd5c2a865e69116225dc486e2dbdd2dda1434759fa7f1fc50c72eeadbea`,
  with GNU coreutils, findutils, grep, sed, gawk and binutils added): a PyPI Brotli 1.2.0 record
  was found and judged `VULNERABLE`, exit status 1, valid JSON.
- Sample output from the Ubuntu 24.04 image: [sample-output.md](sample-output.md).

Problems found by the integration run and fixed before this result: the Node.js download helper
was not executable; one expectation was wrong (`EXPOSURE` needs an HTTP client next to Brotli, and
the first image had none); the bash 4.2 step did not exercise any verdict; two English messages
broke grammar with a count of one.

## Codex adversarial review, round 4

Ten findings (P1 × 6, P2 × 4), all confirmed and fixed; the decisions are in
[design.md 10.9](design.md#10-decisions-made-during-implementation-2026-10-26). Each fix has a unit
test in `tests/unit/hardening.bats` (and one in `cli.bats`). To check that the tests catch the
defects, each of twelve fixes was undone in a copy of the tree and the matching tests run: every
undone fix made at least one test fail (three needed sharper tests first: the mount and `PATH`
tests did not see the call site, and the dependency test is skipped under a world-writable
directory such as `/tmp`).

Run time on the development workstation stayed about 20 seconds (a first version of the
dependency check took 51; see design.md 10.9).

Round 5 (the whole single-file build again): round 4's items 2, 3, 4, 9 and 10 confirmed fixed;
ten further findings (design.md 10.10). Two were confirmed by experiment first: `find -P` walks
nothing below a search root that is a symlink, and a program with RUNPATH `:/nonexistent` loaded
a library from the working directory. Each fix has a test in `hardening.bats` (one in
`cli.bats`); undoing each of the thirteen fixes made a test fail (two tests were sharpened first:
a trailing empty RUNPATH entry, and a test filter that had matched nothing). On the development
workstation the findings were the same as before round 5; only the wording of the string
heuristic changed.

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
