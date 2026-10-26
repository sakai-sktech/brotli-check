# Design notes — CVE-2026-111497 check script

日本語: [design.ja.md](design.ja.md)

- Status: **approved** 2026-10-26 (the open points in section 9 were decided the same day)
- Request: `brotli_check_script_prompt_20261026.html` (株式会社ジェイ・メディック, 2026-10-26; not in the repository)
- Role of this document: step 2 of the request ("write the design notes and get approval before implementing").

## 1. Purpose, and what the tool must not do

On one Ubuntu 22.04 / 24.04 / 26.04 host (and Debian 12 / 13), list **read-only** every copy of
the Brotli decoder that may be affected by CVE-2026-111497.

Hard constraints (section 2 of the request, used as design constraints): no installing, updating,
removing, restarting or reconfiguring; no network access; no scanning of other hosts; no
generating, downloading or shipping attack data; no intrusion check; never say "safe".

## 2. Primary sources re-checked (settled 2026-10-26)

Differences from the snapshot in section 8 of the request, with the requester's confirmations and
instructions of 2026-10-26. All retrieved on 2026-10-26 (JST). Every row of
`data/advisories.tsv` carries its URL and retrieval date.

| # | Item | Request (section 8) | Result → data | Source |
|---|---|---|---|---|
| 1 | Google Brotli | 1.0.10 / 1.1.1 / 1.2.1 | Agrees. Fix commits per line: b418fa81 (v1.2.1), da980636 (v1.1.1), 50a9b70a (v1.0.10); 0ed4268a is the original commit on main | github.com/google/brotli/releases, notes in the Debian tracker |
| 2 | PyPI Brotli / brotlicffi | 1.2.1 / 1.2.1.0, PYSEC-2026-4322 / 4323 | Agrees (4322 = brotli, 4323 = brotlicffi) | `pypa/advisory-database`: `vulns/brotli/PYSEC-2026-4322.yaml`, `vulns/brotlicffi/PYSEC-2026-4323.yaml` (raw) |
| 3 | Bun | 1.4.4 | Agrees, but the basis is the **source**, not the release notes: tag `bun-v1.4.4` pins `db24a98a` (v1.2.1) in `scripts/build/deps/brotli.ts`, `bun-v1.4.3` pins `028fb5a2` (v1.2.0) | raw.githubusercontent.com/oven-sh/bun/bun-v1.4.4/scripts/build/deps/brotli.ts |
| 4 | Node.js fixed releases | 22.23.4 / 24.22.1 / 26.12.1 | Agrees | nodejs.org/en/blog/vulnerability/october-2026-security-releases |
| 5 | Node.js end-of-life lines | 20 and earlier, 21, 23, 25 get no fix | The advisory names no lines. **Derived** from "end-of-life versions are always affected" plus "no fixed release exists": `status=derived` with the reasoning in the note | same |
| 6 | `process.versions.brotli` | stays "1.1.0" even when fixed | Agrees. At nodejs/node tag v22.23.4, `deps/brotli/c/common/version.h` says 1.1.0 and `decode.h` has `BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17)`; at v22.23.3 `decode.h` says `/* -17 code is reserved */`. (v24.22.1's version.h says 1.2.0: the value differs per line and cannot be used.) | raw.githubusercontent.com/nodejs/node/v22.23.{3,4}/deps/brotli/… |
| 7 | Debian bookworm / trixie | +deb12u1 (DLA-4855-1) / +deb13u1 (DSA-6582-1) | Agrees | security-tracker.debian.org/tracker/CVE-2026-111497 |
| 8 | Debian sid / forky | 1.2.0-4 unfixed | The tracker's "Fixed Version" table has `brotli source (unstable) 1.2.0-4.1` (bug 1151690) (retrieved 2026-10-25T21:40Z), but the archive (sources.debian.org/api/src/brotli/) has only 1.2.0-4 for forky and sid. **Unfixed until it reaches the archive** (`unreleased` in 5.1) | same tracker, sources.debian.org |
| 9 | Debian nodejs | (not covered) | Vulnerable in all releases in the tracker (unstable: unfixed, unimportant; note "nodejs uses system provided brotli library"). The dependency sits on libnode108 / libnode115, not on nodejs. **Judge by transitive ldd resolution, not by dpkg Depends** | same tracker, packages.debian.org |
| 10 | Ubuntu | all releases "Needs evaluation", no USN | Agrees (brotli and nodejs "Needs evaluation" for jammy / noble / resolute / 26.10 stonking). noble ships brotli 1.1.0-2build2 (same on the development host) | ubuntu.com/security/CVE-2026-111497, launchpad.net/ubuntu/+source/brotli |
| 11 | Amazon Linux | no advisory | **Updated**: AL2023 brotli ALAS2023-2026-3334, nodejs24 ALAS2023-2026-3330 (2026-10-24, Fixed) | explore.alas.aws.amazon.com/CVE-2026-111497.html |
| 12 | Alpine | edge 1.2.1-r0 (3.23/3.24 to confirm) | 3.23 / 3.24 / edge all 1.2.1-r0, listed in secdb | pkgs.alpinelinux.org, secdb.alpinelinux.org |
| 13 | Envoy | advisory and tags disagree | **No disagreement.** Tags v1.36.12 / 1.37.8 / 1.38.6 / 1.39.3 all pin Brotli `42a2ed43` (129 commits after 0ed4268a, i.e. fixed); v1.38.5 pins 1.2.0. The request's "UNKNOWN if the disagreement remains" does not apply: **FIXED as the advisory says** | GHSA-3wvj-j6qm-62mr, `bazel/repository_locations.bzl` per tag, GitHub compare API |
| 14 | Istio | 1.31.2 / 1.30.6 / 1.29.9 | Agrees (ISTIO-SECURITY-2026-007, 2026-10-15, earlier than Envoy's advisory) | istio.io |
| 15 | Chromium | Stable 148 and later | Agrees. 148.0.7728.2 (early development) lacks it, 148.0.7778.96 has it. Threshold **148.0.7778.0**; 148 development builds below it are UNKNOWN | third_party/brotli/README.chromium per tag |
| 16 | Firefox | 150.0 / ESR 140.10 | Agrees (149.0 and ESR 140.9 lack it) | modules/brotli/moz.yaml per tag |
| 17 | RHEL family | RHSA-2026:2042 etc. are unrelated | Agrees (CVE-2025-6176). No RHEL advisory for this CVE found | access.redhat.com |
| 18 | Background paper | jmedic.co.jp/pubdoc/… | 404 (not published). Not used | — |

Could not be retrieved: the CVE.org / NVD records (JavaScript only); packages.ubuntu.com
(HTTP 500 — the Ubuntu python3-brotli and nodejs dependencies are therefore measured on the
host instead); a primary source stating that HAProxy and Caddy contain no C decoder (see C11 in
section 6).

## 3. Added from measurements on the development host

Requirements not in the request, found by read-only inspection of the development machine
(Ubuntu 24.04.5).

1. **Search mise's Node.js / Python** (`~/.local/share/mise/installs/{node,python}/*`). mise and
   asdf add alias symlinks such as `22` → `22.17.1`, so **deduplicate by real path**.
2. **C06 must not read dpkg-owned dist-packages.** Ubuntu's python3-brotli installs
   `/usr/lib/python3/dist-packages/Brotli-1.1.0.egg-info` (Version: 1.1.0, the upstream
   version). Compared with PyPI's 1.2.1 it would stay VULNERABLE after the distributor's fix.
   Anything with a `dpkg -S` owner is left out of C06 and judged by C01.
3. **Official Node.js tarballs reveal their version without running.** `../include/node/node_version.h`
   next to the executable has `NODE_{MAJOR,MINOR,PATCH}_VERSION`.
4. Official Node.js and python3-brotli's `_brotli*.so` both carry the decoder statically and
   contain strings starting with `_ERROR_FORMAT_`: the C09 heuristic (section 6) may work.

## 4. Structure

```
bin/brotli-cve-check          entry point (development); loads lib/*.sh and data, calls bcc_main
lib/main.sh                   options → detection items → output → exit status
lib/core.sh                   shared (execution limits bcc_probe / bcc_sys, find exclusions, home directories)
lib/index.sh                  index of things found by name (one find; 10.1)
lib/findings.sh               findings (array) and counts
lib/version.sh                version comparison (dpkg / semver / the needed part of PEP 440)
lib/data.sh                   loading advisories.tsv and judging against it
lib/elf.sh                    ELF detection, transitive dynamic linkage, string heuristic
lib/check_c01_c03.sh … lib/check_c14_c15.sh   detection items (2-4 per file)
lib/output.sh                 text and JSON output
lib/i18n.sh                   message catalog (en / ja, associative arrays)
data/advisories.tsv
scripts/build-dist.sh         single-file build (data embedded as a here-document)
Makefile                      lint (shellcheck), test (bats), dist, integration
```
(The file split was settled during implementation as above; the plan had one file per detection
item and separate text and JSON output files.)

- Bash 4.2 or later (associative arrays, `declare -g`). Depends on coreutils / findutils / grep /
  awk / sed. Without binutils (readelf / strings) it falls back to `grep -a` and the like, and says
  that precision is lower (SKIPPED / reason).
- `set -u` and `set -o pipefail`; no `set -e` (a failing detection item must not stop the run; it
  becomes UNKNOWN / SKIPPED).
- One finding is one array element with tab-separated fields:
  `id status component path version reason next_step evidence confidence`.
  JSON is escaped by the script itself (no jq).

## 5. Data (data/advisories.tsv)

### 5.1 Columns

The request's six columns (component, line, fixed version, status, primary source URL, retrieval
date) plus a **note** column, because `derived` and similar statuses need a place for their
reasoning.

| Column | Example |
|---|---|
| component | `node` / `bun` / `pypi:brotli` / `deb-src:brotli` / `envoy` / `chromium` … |
| branch | `22`, `debian:trixie`, `ubuntu:noble`, `*` |
| fixed | `22.23.4`, `1.1.0-2+deb13u1`, `-` (no fix) |
| status | `fixed` / `no_fix` / `unreleased` / `derived` / `analysis` |
| source_url | primary source URL |
| retrieved | `2026-10-26` |
| note | short reasoning |

Meaning of `status`:
- `fixed` — the primary source names the fixed version
- `no_fix` — the distributor has not released a fix (all Ubuntu releases) → NO_FIX_AVAILABLE
- `unreleased` — a fixed version is named but has not reached the archive (Debian sid / forky
  1.2.0-4.1). Installed version at or above `fixed` → FIXED, below → NO_FIX_AVAILABLE
- `derived` — derived from a general statement of the primary source (Node.js end-of-life lines);
  the note is shown as the reason
- `analysis` — from the product's source tree, not a vendor advisory (Chromium / Firefox / Bun);
  the result says so

### 5.2 Freshness

The result shows `data_snapshot_date` (the date declared at the top of the file, not the oldest
`retrieved`) and warns at 30 days or more. `--data FILE` replaces the data.

## 6. Detection items (mainly what differs from section 3 of the request)

Only changes and refinements are listed; everything else follows the request.

**C01 OS packages** — the series comes from `ID` and `VERSION_CODENAME` in `/etc/os-release`
(derivatives through `UBUNTU_CODENAME` / `DEBIAN_CODENAME`). Read with
`dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\n'` and compare
the **source package version** (`source:Version`) with the tracker's fixed version, so that
binNMU suffixes such as `+b2` on binary packages do not matter. Unknown series → UNKNOWN (reason:
not in the data).

**C02 packages depending on libbrotli1 (information)** — extracted from
`dpkg-query -W -f '${Package}\t${Depends}\n'`, including `libnode*` (Debian's nodejs goes through it).

**C04 Node.js** — mise and asdf added to the search, deduplicated by real path. Version: by default
`node --version` (with a timeout); with `--no-exec`, `../include/node/node_version.h`, then the
nvm / mise / asdf directory name; otherwise the C09 heuristic, then UNKNOWN. A **distribution
package's node** (it has a `dpkg -S` owner) is split by whether it links libbrotlidec
**transitively**: `ldd` by default (glibc's ldd asks the system loader to `--list` dependencies
instead of using the file's PT_INTERP; main does not run); with `--no-exec`, the NEEDED entries of
`readelf -d` are followed with `ldconfig -p` and RUNPATH (lower precision, reported). Dynamic →
covered by C01; static → judged by its strings.

**C06 Python** — mise / pyenv / uv (`~/.local/share/uv/{python,tools}`) added to the search.
dpkg-owned entries excluded (3.2). PEP 440: trailing zeros of the release are ignored (1.2.1 equals
1.2.1.0), pre-releases sort before the release, local versions (`+…`) are ignored.

**C09 bundled copies and the fix heuristic** — hypothesis: the fixed decode.c builds names in
`BrotliDecoderErrorString` from `#PREFIX #NAME`, so a fixed binary contains
`_ERROR_FORMAT_BLOCK_SWITCH`; in an unfixed one -17 is reserved (`/* -17 code is reserved */`)
and the string is absent. Steps (a)(b)(c) of the request are done before implementation and the
results kept in `tests/fixtures/c09/` and `docs/limitations.md`:
- (a) compare the v1.2.0 / v1.2.1 sources (done up to the point above; also check `decode.h` of v1.1.1 / v1.0.10)
- (b) build v1.2.0 / v1.2.1 (shared and static × stripped or not × -O2 / LTO) and compare `strings`
- (c) compare the official Node.js 22.23.3 / 22.23.4 binaries
Verdict: other `_ERROR_FORMAT_*` strings present but `_ERROR_FORMAT_BLOCK_SWITCH` absent →
LIKELY_VULNERABLE; `_ERROR_FORMAT_BLOCK_SWITCH` present → LIKELY_FIXED; no `_ERROR_FORMAT_*`
strings (fewer than 8) → VENDORED_COPY (the function was removed; 10.5). Confidence follows the
verification; if the verification fails, the heuristic is not implemented and only VENDORED_COPY
is reported.

**C10 Envoy** — judged by the advisory's fixed versions (2.13: no disagreement). 1.35 and earlier
are `derived` (older Envoy bundles Brotli 1.0.9 / 1.1.0).

**C11 compression-only products** — primary sources confirmed ngx_brotli (libbrotlienc only),
mod_brotli (compression filter only) and Traefik (Go implementation, andybalholm/brotli). HAProxy
and Caddy are to be confirmed in their upstream sources during implementation; if not confirmed,
they are reported as information with their version, not as NOT_APPLICABLE. Distribution nginx and
Apache are additionally measured with `ldd` to confirm they do not load libbrotlidec.
(Implemented as a decision from the files themselves; 10.6.)

**C13 browsers** — Chromium threshold 148.0.7778.0 (2.15).

**C14 / C15** — as requested. Alpine-based containers (apk) are out of scope in the first version
and reported with a reason.

## 7. Keeping it read-only

- Writes go to stdout and the `--output` file only. No temporary files (process substitution and
  variables instead).
- Found programs run only through one function (`bcc_probe`), bounded by `timeout` and an allow-list
  of arguments (`--version` and the like); system tools (`dpkg-query`, `ldd`, ...) through
  `bcc_sys`. With `--no-exec`, `bcc_probe` runs nothing.
- `find` uses `-xdev` and `-P` (never follows symlinks) and prunes `/proc /sys /dev /run`. NFS,
  CIFS, fuse.sshfs and similar are pruned unless `--include-remote` (from `/proc/self/mountinfo`).
  The ELF search has a 512 MiB size limit by default.
- No environment variables are read (except the scanning user's `PATH`). Command lines only with
  `--show-cmdline`.
- Other users' homes are enumerated with `getent passwd`; unreadable ones are listed as skipped.

### 7.1 Interpretation of the request (settled during implementation, 2026-10-26)

- **`--no-exec` stops running *found* programs**: `--version` of node, bun, curl, envoy and
  browsers, `ldd` on found executables, and commands inside containers. System query tools
  (dpkg-query, dpkg, readelf, ldconfig, ss, snap, flatpak, docker ps) still run; they are outside
  "running the programs it found" in section 2.4 of the request.
- **Every external command runs with `LC_ALL=C`.** The development host's readelf printed localized
  output. Found programs run with an emptied environment (`env -i`) so that `NODE_OPTIONS` and the
  like have no effect.
- **`--output` never overwrites or opens an existing file.** The report goes to a temporary file
  created exclusively in the same directory, which is then hard-linked to the requested name
  (link(2) fails on any existing name and never follows symlinks). Directories that other users
  can modify without the sticky bit are refused, and every directory up to `/` must be owned by root
  (or by the user, when not root); a sticky directory must also be owned by root or the user. The
  resolved directory is the one written to. (First implemented with bash's noclobber; the
  Codex review showed that noclobber still opens existing FIFOs and devices, e.g. a symlink to a
  disk planted after the option check.)
- **Test hooks**: only `BCC_PROC_ROOT`, `BCC_OS_RELEASE`, `BCC_HOME_DIRS`, `BCC_MOUNTINFO` and
  `BCC_TODAY` are read from the environment (the exception to "no environment variables"; all are
  the tool's own).
- **C09's search by file name always runs.** Looking for `libbrotlidec.so*` outside dpkg
  (/usr/local, /opt, conda, ...) by name is cheap, so it is on by default and judged by the version
  in the file name. Only the generic search that reads ELF contents needs `--deep`.
- **C02 and "covered by C01" are information, not findings.** As findings they would double-count,
  as "needs update", things that one apt update fixes. JSON keeps them in `info[]`, separate from
  `findings[]`.

## 8. Test plan

- Unit: bats-core. Fake `dpkg-query`, `node`, `bun`, `ldd` first on PATH; fake dist-info; fake
  `/proc` (`BCC_PROC_ROOT`).
- C09: the results of (b)(c) are fixed as fixtures (lists of extracted strings) and the verdict
  function is tested against them.
- Integration: ubuntu:22.04 / 24.04 / 26.04, debian:12 / 13 (tags confirmed to exist) with
  unfixed and fixed Node.js and Brotli 1.2.0 / 1.2.1 virtual environments; the verdicts must match.
- No test uses crafted Brotli data.
- CI: GitHub Actions with shellcheck, bats and the integration matrix.

Results: [verification.md](verification.md).

## 9. Decisions (requester's answers, 2026-10-26)

1. **The repository keeps the name `brotli-check`.** The request's provisional name
   `brotli-cve-2026-111497-check` and the nicknames HTTP2Shell / Node2Shell appear only as README
   keywords. The executable is `brotli-cve-check`, as requested.
2. **The request HTML is excluded by `.gitignore`.** It stays locally as the original and is not
   published with the open-source repository.
3. **Development tools:** the requester installs shellcheck and bats with apt and starts Docker
   Desktop for the integration tests.
4. **Downloads for the C09 verification are allowed**: google/brotli sources and the official
   Node.js 22.23.3 / 22.23.4 binaries, into a scratch area, at development time only; the tool
   itself never uses the network.
5. The note column and the `unreleased` status of advisories.tsv as in 5.1 (part of the approval).
6. **Documentation language (decided the same day):** English is the primary version in docs/, with
   Japanese versions alongside as `.ja.md` (the naming of the existing `README.ja.md` and
   `for-clinics.ja.md`), because Japanese users will read it too. These notes exist as `design.md`
   (English, this file) and `design.ja.md`.

## 10. Decisions made during implementation (2026-10-26)

Changes after approval, from implementation and tests on real hosts. Each: decision / reason /
rejected alternative.

1. **Everything found by name comes from one `find` (an index, `lib/index.sh`).** One find per
   detection item walked /home (about 2.45 million files) several times, and a `dpkg-query -S` per
   path (about one second each) made a run take 60 seconds. With the index and no dpkg questions
   about home directories, it takes about 20 seconds. node / bun / envoy are also searched by name
   under all of `--roots`, which finds the Node.js bundled by VS Code Server, CI runners and
   Playwright. Rejected: listing install locations only (missed many copies on a real host).
2. **Package-manager caches (pip, uv, poetry, npm, yarn) are not findings.** They hold downloads;
   installed copies are found on their own. Only the count is given as information.
3. **When a found program may run** (from the automated security review). The file and every
   directory above it belong to root (or to the invoking user when not root) and are not writable
   by others. Group-writable: never as root; as an ordinary user only for the owner's user private
   group (same name as the owner, the owner's primary group, one group entry for the GID, no other
   members) — tightened back for root after the review's second round. The path must be canonical
   and exactly the checked path is run (TOCTOU). `ldd` follows the same rule. Reason: running as
   root, root could otherwise run `--version` of a node that an ordinary user replaced. Rejected:
   always `--no-exec` as root (cannot run even root's own programs, and does not protect an
   ordinary user from other users' files).
4. **Versions are read only from a line of the expected shape per product.** Chrome prints a log
   line (`[1026/070739.474907:WARNING:…]`) before its version; taking the first number produced a
   false FIXED. Chromium needs a four-part version, otherwise UNKNOWN.
5. **C09: if the version in the file name and the strings disagree, UNKNOWN**, so that a patched
   build is not misjudged by either one alone. The heuristic decides only with at least 8
   `_ERROR_FORMAT_*` names (every verified build had 16 or 17, or none).
6. **C11 decides from the files, not the product name**: does a binary or module carry decoder
   markers, or load libbrotlidec? (Measures the request's "compression only, therefore
   NOT_APPLICABLE".)
7. **Control characters in the text report are shown as `?`**, and paths and package names inside
   suggested commands are quoted with `%q` (same review). JSON uses RFC 8259 escaping.
8. **The single-file build concatenates `lib/*.sh` and the data** (`scripts/build-dist.sh`).
   shellcheck must report zero warnings both per file (except SC2034, SC2004) and on the build (all
   checks).
