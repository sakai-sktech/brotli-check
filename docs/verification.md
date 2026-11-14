# Verification results

日本語: [verification.ja.md](verification.ja.md)

What was checked, how, under which conditions, and what came out. Each section says when it was
run and with which advisory data: the first checks on **2026-10-26**; the integration table on
**2026-10-27** (advisory data snapshot 2026-10-27, docs/design.md 2.1); the C11 section and the
unit-test table up to its row of **2026-11-02** (snapshot 2026-11-02, docs/design.md 2.2); the next
four rows of that table and the section "Integration runs since 2026-11-04" cover **2026-11-04 to
2026-11-14**, with the advisory data still at the snapshot of 2026-11-02; the last row of the table
is of **2026-11-14**, after that day's update of the data (snapshot 2026-11-14, docs/design.md 2.3).

One-page figures (A4): [Fig. 01 What we checked, and how](zukai/01_check-method_en.pdf) ·
[Fig. 02 Results on 5 OSes, and how to read them](zukai/02_results-reading_en.pdf)
(Japanese: [図解 01](zukai/01_check-method_ja.pdf), [図解 02](zukai/02_results-reading_ja.pdf)).

## What these tests show, and what they do not

The tests put copies whose verdict is known in advance into containers and test files on
purpose, and compare the tool's report with the expected verdicts. In the images, the ways of
running and the builds listed on this page, every expected verdict matched. That is what they
show. They do not measure how often the tool misses a copy or misjudges one on real hosts, and
they do not show that it judges every build, distribution or architecture as expected:

- The string heuristic (C09) was tried on Brotli 1.2.0 and 1.2.1 built with gcc 13 on Ubuntu
  24.04 (x86_64), on official Node.js binaries and on PyPI wheels. Builds of 1.0.x and 1.1.x,
  other compilers and other architectures were not tried.
- The integration images are x86_64 containers of Ubuntu 22.04, 24.04, 26.04 and Debian 12, 13,
  each holding one set of copies placed there. RHEL and the like, Ubuntu 26.10, derivatives and
  other architectures were not tried.
- The run on a real workstation ("On a real workstation") shows what the tool found there, not
  what it missed.

The expected verdicts of the integration tests are in `tests/integration/run.sh`; CI runs them on
every push and pull request, on images built at that time.

## How to read the integration results (images and data of 2026-10-27)

The integration tests below put known-unfixed and known-fixed copies into each image on purpose,
so every run ends with exit status 1. In those five images:

- **Every expected verdict matched**, as root and as an ordinary user, with `--no-exec` and with
  `--yes`.
- **The operating system's Brotli was fixed on every distribution tested.** Ubuntu fixed 22.04,
  24.04, 26.04 and 26.10 on 2026-10-26 (USN-8956-1: `1.0.9-2ubuntu0.1`, `1.1.0-2ubuntu0.1`,
  `1.2.0-3ubuntu0.1`, `1.2.0-4ubuntu0.1`); Debian fixed 12 (`1.0.9-2+deb12u1`) and 13
  (`1.1.0-2+deb13u1`). The images built on 2026-10-27 got these versions, and `libbrotli1` and
  `python3-brotli` were `FIXED` in all five. A host that has not been updated since has them
  `VULNERABLE`: update with apt and restart what uses them (the tool lists those processes as
  `RESTART_REQUIRED`).
  - Until the data of 2026-10-27, the tool reported Ubuntu's packages as `NO_FIX_AVAILABLE`: on
    2026-10-26 the CVE page said "Needs evaluation" and there was no USN, and the data was not
    updated when the USN came out later that day. The sample output captured on 2026-10-27 showed
    the fixed version reported that way (docs/design.md 2.1).
- **Bundled copies are not fixed by OS updates.** Node.js 22.23.4 and PyPI Brotli 1.2.1 were
  `FIXED` and their predecessors `VULNERABLE` in all five images, whatever the OS. These copies have
  to be updated product by product, which is why the tool looks for them.

## Static checks and unit tests

| Check | Tool | Result |
|---|---|---|
| `make lint` (per file, and the single-file build with all checks) | ShellCheck 0.9.0 (Ubuntu package) and 0.10.0 (upstream release) | zero warnings |
| `make test` | Bats 1.10.0 (Ubuntu package) and bats-core 1.11.1 | 83 / 83 passed (first run) |
| `make lint`, `make test` after the Codex review, round 4 | ShellCheck 0.9.0, Bats 1.10.0 | zero warnings; 123 / 123 passed |
| the same after round 5 | ShellCheck 0.9.0, Bats 1.10.0 | zero warnings; 134 / 134 passed |
| the same after the consent model and round 6 (2026-10-27) | ShellCheck 0.9.0, Bats 1.10.0 | zero warnings; 153 / 153 passed |
| the same after fixing the automatic security review's findings (2026-10-27, design 10.13) | ShellCheck 0.9.0, Bats 1.10.0 | zero warnings; 161 / 161 passed; the 8 new tests fail on the code before the fix |
| mutation tests of 2026-10-27 (test record, chapter 13), and the data of 2026-10-27 | Bats 1.10.0 | 91 fixes reverted one at a time: 69 caught; 10 tests added for the 21 gaps; then all 22 re-run caught. 172 / 172 passed |
| the same after rounds 7 to 11 of the review and the data of 2026-11-02 (design 10.18, 2.2) | ShellCheck 0.9.0, Bats 1.10.0 | zero warnings; 239 / 239 passed |
| the same after the six changes of 2026-11-04 to 05 (#5, #6, #7, #8, #11, #19; design 10.19 to 10.24) | ShellCheck, Bats (Ubuntu 24.04 packages) | zero warnings; 299 / 299 passed |
| the same after the two changes of 2026-11-06 (the basis of `FIXED`, and `failed` / `chosen` with exit status 2; #9, #10; design 10.25, 10.26) | ShellCheck, Bats (Ubuntu 24.04 packages) | zero warnings; 350 / 350 passed. Mutations of the new code, each made a test fail: 17 for the first change, 19 for the second |
| the same after the three changes of 2026-11-07 to 10 (.NET, every `libbrotlidec` a program loads, Python modules inside containers; #17, #18, #27; design 10.27 to 10.29) | ShellCheck, Bats (Ubuntu 24.04 packages) | zero warnings; 407 / 407 passed (a final run with nothing touched, 12 min 39 s). Mutations of the new code: 20 and 21 for the first two changes, each made a test fail; 19 of 20 for the third (the one that did not was a check that another check already made redundant, and was removed) |
| the same on 2026-11-14, after the change to the integration tests only (`tests/integration/`; the tool's code did not change) | ShellCheck (Ubuntu 24.04 package) | zero warnings (`make lint` includes the integration scripts); the unit tests are the same 407 |
| the same on 2026-11-14, after that day's advisory data (design 2.3) and the version number 0.2.0 | ShellCheck, Bats (Ubuntu 24.04 packages); integration on a native Docker engine (Docker 29.9.3, `/var/run/docker.sock`) | zero warnings; 408 / 408 passed (13 min 17 s). The test of `unreleased` now uses a made-up row: four mutations of that path (the branch removed, handled as `no_fix`, the comparison reversed, the reason replaced) and the shipped forky row set back to `unreleased` each made a test fail. `make integration`: the five images and bash 4.2 passed (39 checks; C14 with exit statuses 1, 2 and 0). The old images were removed first; the rebuilt ones took the layers below the tool from the engine's build cache |

## Integration tests (`tests/integration/`)

The table and notes below are from the runs of 2026-10-26 and 27, made with Docker 28.3.0 (Docker
Desktop, x86_64); the runs since are described after the notes. Each image adds, on top of the distribution:
official Node.js 22.23.3 and 22.23.4 in `/opt` (verified against `SHASUMS256.txt`), PyPI Brotli
1.2.0 with urllib3 in `/srv/venv-old`, and Brotli 1.2.1 in `/srv/venv-new`. Since 2026-10-27 each
image is scanned four times: as root and as an ordinary user, each with `--no-exec` and with
`--yes` (found programs run only with consent; a container has no terminal to ask). Before that,
after rounds 4 and 5, the runs were root by default, root with `--allow-exec`, and an ordinary
user with `--no-exec`. The fixed script of `--inspect-containers` (C14) is also run in each
image's own `/bin/sh` (dash) with both Node.js copies on `PATH`; it must report both, the packages,
and its `END` line.

| Image (as reported) | Python | `libbrotli1` / `python3-brotli` (images built 2026-10-27, data of 2026-10-27; with the data of 2026-10-26 the Ubuntu rows were `NO_FIX_AVAILABLE`) | Node.js 22.23.3 / 22.23.4 | PyPI Brotli 1.2.0 / 1.2.1 | urllib3 next to 1.2.0 | all scans (4) / C14 probe |
|---|---|---|---|---|---|---|
| Ubuntu 22.04.5 LTS | 3.10 | 1.0.9-2ubuntu0.1: `FIXED` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |
| Ubuntu 24.04.5 LTS | 3.12 | 1.1.0-2ubuntu0.1: `FIXED` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |
| Ubuntu 26.04.1 LTS | 3.14 | 1.2.0-3ubuntu0.1: `FIXED` | `VULNERABLE` / `FIXED` | `VULNERABLE` / `FIXED` | `EXPOSURE` | ok / ok |
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

## Integration runs since 2026-11-04

The five images and bash 4.2 are unchanged. What changed is how they are run and what they check:

- **CI.** On every push and pull request, GitHub Actions runs the unit tests and then the five
  images and bash 4.2 (7 jobs, 14 checks counting both triggers) on the Docker of its Ubuntu
  24.04 runner (the version is not recorded here). The final state of the pull request of each
  change of 2026-11-04 to 10 (the rows of those dates in the table above) and of the
  integration-test change below passed all 14. (One run during the changes of 2026-11-07 to 10
  failed before that, on the runner's own .NET installation, and was fixed; one run of `main`
  failed once while building an image and passed when run again on the same tree.)
- **A real container engine for C14, since 2026-11-04 (#6).** The C14 step starts a container of
  the image and runs `--inspect-containers` against the engine twice: through the engine's unix
  socket (the tool looks inside the running container) and through a TCP relay on `127.0.0.1` (it
  cannot look inside, and says so). Since 2026-11-09 (#27) it also checks the Python modules
  inside the container: PyPI Brotli 1.2.0 `VULNERABLE`, 1.2.1 `FIXED`, in all five images.
- **Exit statuses of C14, since 2026-11-13.** The step now expects exit status 1 for the unix
  socket run (the container holds unfixed copies), exactly 2 for the TCP run (the one
  `failed` entry of C14 and no other finding; the tool runs inside a throwaway container of the
  image with `/opt` and `/srv` hidden, so that what the test host holds does not change the
  status), and 0 for the same run with `--containers` only (the same sentence, kind `chosen`).
  Before, it checked only that the status was not 3. With one expectation changed at a time
  (1 to 2, 2 to 1, 0 to 2), each run failed; with a Node.js version that does not exist, the build
  failure printed the failing step and the download error. On 2026-11-13 the five images and bash
  4.2 passed, and each image run alone passed (50 checks); in CI the five images gave 1, 2 and 0.
  A failed image build now prints the end of its log on the standard output.
- **Which engine.** The local runs of 2026-11-07 to 10 and of 2026-11-13 used a native Docker
  engine through `/var/run/docker.sock` (Docker 29.9.3), because the Docker Desktop engine of the
  development workstation was stopped; the engine of the CI is the runner's. **The TCP step of C14
  needs a native engine** (a container on the host network must reach the test host's
  `127.0.0.1`). It was **not tried with Docker Desktop**, where it is expected to stop with FAIL
  and the client's own output; the runs of 2026-10-26 and 27 above, with Docker Desktop, were
  before this step existed in its present form.

## C11: the distributions' web servers (2026-11-02, design 10.17)

Added to every integration image: the distribution's nginx, Apache and HAProxy, and the ngx_brotli
modules where the archive has them. Versions as installed from the archives on that date:

| Image | nginx | `apache2-bin` | `haproxy` | ngx_brotli modules |
|---|---|---|---|---|
| Ubuntu 22.04 | `nginx-core` 1.18.0-6ubuntu14.22 | 2.4.52-1ubuntu4.25 | 2.4.30-0ubuntu0.22.04.2 | not in the archive |
| Ubuntu 24.04 | `nginx` 1.24.0-2ubuntu7.19 | 2.4.58-1ubuntu8.17 | 2.8.30-0ubuntu0.24.04.1 | 1.0.0~rc-5build1 |
| Ubuntu 26.04 | `nginx` 1.28.3-2ubuntu1.12 | 2.4.66-2ubuntu2.6 | 3.2.25-0ubuntu0.26.04.1 | 1.0.0~rc-7build3 |
| Debian 12 | `nginx` 1.22.1-9+deb12u10 | 2.4.68-1~deb12u1 | 2.6.12-1+deb12u4 | 1.0.0~rc-3 |
| Debian 13 | `nginx` 1.26.3-3+deb13u10 | 2.4.69-1~deb13u1 | 3.0.11-1+deb13u4 | 1.0.0~rc-6 |

- **Each server file was `NOT_APPLICABLE`** in all four scans (root and ordinary user, `--no-exec`
  and `--yes`). With the copies placed on purpose removed, the exit status was `0` on all five.
- **The sources of those packages** (`apt-get source`) hold none of `BrotliDecoder`,
  `brotli/decode.h`, `_ERROR_FORMAT_`. `mod_brotli.c` and ngx_brotli include only `brotli/encode.h`.
  HAProxy's sources do not contain the word "brotli". None of them ships a copy of Brotli
  (ngx_brotli's `deps/brotli` holds no files in Ubuntu 26.04, the one where that was counted).
- **With the real `dpkg`**, on all five: an in-house `.deb` with a file at `/usr/local/sbin/nginx`,
  and `/usr/sbin/haproxy` overwritten after installation, were `UNKNOWN` with exit status `2`.
- **Tried by hand, once each:** nginx.org's `nginx` 1.26.0-1~noble on Ubuntu 24.04 was `UNKNOWN`, exit
  `2`. Debian's `caddy` 2.6.2-12+deb13u1 was `NOT_APPLICABLE` as a Go program, exit `0`. `nginx-extras`
  on Ubuntu 22.04 was `NOT_APPLICABLE`, exit `0`.
- **Unit tests:** 218 / 218 on 2026-11-02, with the fixes for #1 and #2 merged, and zero ShellCheck warnings. Fifteen
  mutations of the new code (each check removed or loosened in a copy of the tree) each made a test fail.

What this does not show: no package holding a real stripped static decoder was built, so the
in-house package here is `/bin/true` under another name. Later versions of these packages were not
read. Rebuilds that keep the name, maintainer and version form look the same to the tool. Go
programs with a C Brotli through a cgo binding other than `cbrotli` were not tried.

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

Tried on Brotli 1.2.0 and 1.2.1 built with gcc 13 on Ubuntu 24.04 (x86_64) as shared and static
libraries (-O2 and LTO, stripped or not), on official Node.js 22.23.3 / 22.23.4 / 24.22.0 / 24.22.1,
and on PyPI Brotli and brotlicffi wheels: every fixed artifact among them contains
`_ERROR_FORMAT_BLOCK_SWITCH` and every unfixed one does not. Among these builds, the only case that
could not be decided was LTO with garbage collection when the program never calls
`BrotliDecoderErrorString`; the tool then reports `VENDORED_COPY`. Builds of 1.0.x and 1.1.x (the
fixed 1.0.10 and 1.1.1 carry the same marker in their source), other compilers and other
architectures were not tried. Some cases are not told apart whatever the build, such as two
decoders in one file sharing one dictionary (see "The string heuristic" in
[limitations.md](limitations.md)). Rerunning `tests/fixtures/c09/reproduce.sh` from scratch
produced byte-identical fixtures.
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
