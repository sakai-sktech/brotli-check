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

### 2.1 Re-checked before release (2026-10-27)

Comparing the data with J-MEDIC's technical note, published on 2026-10-27 (row 18 was a 404 on
10-26), showed that the note named an Ubuntu notice the data did not have. Every row's primary
source was then checked again, and the snapshot moved to 2026-10-27. The wrong verdict was
already in this repository: `docs/sample-output.md`, captured on 10-27 from the Ubuntu 24.04
integration image, shows `libbrotli1` `1.1.0-2ubuntu0.1` - the fixed version, which the freshly
built image had pulled from `noble-security` - reported as `NO_FIX_AVAILABLE`, "the distributor
has not released a fix yet". Neither the review nor the integration tests caught it: with a
`no_fix` row every installed version gives `NO_FIX_AVAILABLE`, so the expected verdict held.
Changes:

| Row | Was (2026-10-26) | Now (2026-10-27) → data | Source |
|---|---|---|---|
| 10 Ubuntu | "Needs evaluation", no USN → `no_fix` | **Fixed** by USN-8956-1 (2026-10-26) in jammy 1.0.9-2ubuntu0.1, noble 1.1.0-2ubuntu0.1, resolute 1.2.0-3ubuntu0.1, stonking 1.2.0-4ubuntu0.1 (brotli, libbrotli1, python3-brotli) → `fixed`. These are the versions that were candidates in the ubuntu-security-proposed PPA on 10-25. Ubuntu's nodejs is "Not affected" in those releases (it uses the system library, which C01 judges) | ubuntu.com/security/notices/USN-8956-1, ubuntu.com/security/CVE-2026-111497 |
| 8 Debian sid / forky | 1.2.0-4.1 not in the archive → `unreleased` | sid has 1.2.0-4.1 in the archive → `fixed`; forky still has 1.2.0-4 → stays `unreleased` | security-tracker.debian.org, sources.debian.org/api/src/brotli/ |
| 3 Bun | source analysis → `analysis` | Bun's advisory GHSA-663w-cv8g-jj2p (published 2026-10-23; affected >= 1.0.21, < 1.4.4; `bun build --compile` executables stay affected until rebuilt) → `fixed`. It was missed on 10-26, when the release notes were read instead; the source analysis agrees with it. Versions before 1.0.21 are outside its range but, as the data is per series, are reported like the others before 1.4.4 | github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p |
| 18 Background paper | 404 | Published (quick report, 2026-10-27); linked from the README. Its versions agree with the data after this update | jmedic.co.jp/pubdoc/http2shell_report_20261027.html |

Unchanged on re-check: Google Brotli tags (v1.0.10 / v1.1.1 / v1.2.1, published 2026-10-21),
GHSA-9v8h-qqgm-4m35, PYSEC-2026-4322 / 4323, the Node.js advisory and its list of end-of-life
lines, Debian bookworm / trixie, Envoy GHSA-3wvj-j6qm-62mr, ISTIO-SECURITY-2026-007, Chromium's
`README.chromium` (cfa184a9) and Firefox's `moz.yaml` (4792c8e4).

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
- `no_fix` — the distributor has not released a fix (all Ubuntu releases until 2026-10-26; none
  as of 2026-10-27) → NO_FIX_AVAILABLE
- `unreleased` — a fixed version is named but has not reached the archive (Debian forky
  1.2.0-4.1; sid until 2026-10-27). Installed version at or above `fixed` → FIXED, below → NO_FIX_AVAILABLE
- `derived` — derived from a general statement of the primary source (Node.js end-of-life lines);
  the note is shown as the reason
- `analysis` — from the product's source tree, not a vendor advisory (Chromium / Firefox; Bun
  until 2026-10-27);
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
  `bcc_sys`. They run only with the user's consent, after being listed with their facts
  (`lib/exec.sh`, 10.11); with `--no-exec` nothing found runs.
- System tools run from `/usr/sbin:/usr/bin:/sbin:/bin` (plus `/usr/local/{sbin,bin}` when only root
  can change them), never from the caller's `PATH` (10.9).
- `find` uses `-xdev` and `-P` (never follows symlinks) and prunes `/proc /sys /dev /run`. NFS,
  CIFS, fuse.sshfs and similar are pruned unless `--include-remote` (from `/proc/self/mountinfo`).
  Local-disk file systems mounted below a root are walked too; other mounts below a root, and
  `--exclude` paths, are listed as not scanned (10.9). The ELF search has a 512 MiB size limit by
  default, and files above it are listed.
- Files the scan found are read only as regular files, under a time limit and up to the size limit
  (`bcc_read_file`, 10.9).
- No environment variables are read (the caller's `PATH` only tells where to look for programs to
  judge). Command lines only with `--show-cmdline`.
- Other users' homes are enumerated with `getent passwd`; unreadable ones are listed as skipped.

### 7.1 Interpretation of the request (settled during implementation, 2026-10-26)

- **`--no-exec` stops running *found* programs**: `--version` of node, bun, curl, envoy and
  browsers, `ldd` on found executables, and commands inside containers. System query tools
  (dpkg-query, dpkg, readelf, ldconfig, ss, snap, flatpak, docker ps) still run; they are outside
  "running the programs it found" in section 2.4 of the request. Without `--no-exec`, found
  programs run only after the user chose them from the list (or gave `--yes`), 10.11;
  `--inspect-containers` runs its fixed script inside containers, the option itself being the
  consent. `--no-exec` with `--yes` is an error.
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
   ordinary user from other users' files). **Superseded by 10.11** (2026-10-27): the tool shows
   the facts and the user decides; it no longer decides by such a rule.
4. **Versions are read only from a line of the expected shape per product.** Chrome prints a log
   line (`[1026/070739.474907:WARNING:…]`) before its version; taking the first number produced a
   false FIXED. Chromium needs a four-part version, otherwise UNKNOWN.
5. **C09: if the version in the file name and the strings disagree, UNKNOWN**, so that a patched
   build is not misjudged by either one alone. The heuristic decides only with at least 8
   `_ERROR_FORMAT_*` names (every verified build had 16 or 17, or none).
6. **C11 decides from the files, not the product name**: does a binary or module carry decoder
   markers, or load libbrotlidec? (Measures the request's "compression only, therefore
   NOT_APPLICABLE".) **Refined by 10.9.5**: no markers is NOT_APPLICABLE only for a packaged file
   or a Go program without the cgo binding; a hand-built one is UNKNOWN.
7. **Control characters in the text report are shown as `?`**, and paths and package names inside
   suggested commands are quoted with `%q` (same review). JSON uses RFC 8259 escaping.
8. **The single-file build concatenates `lib/*.sh` and the data** (`scripts/build-dist.sh`).
   shellcheck must report zero warnings both per file (except SC2034, SC2004) and on the build (all
   checks).
9. **Codex adversarial review, round 4 (2026-10-26): ten findings, all confirmed and fixed**
   (two hours, source on stdin; P1 × 6, P2 × 4). Three were the requester's decisions (1, 5, 9).
   1. **As root, found programs are not run unless `--allow-exec`.** (Superseded by 10.11.) The rule of 10.3 covers the
      file and the directories above it, not the code it loads: a root-owned `/opt/app/bin/node`
      whose RUNPATH points to a user-writable `/opt/app/lib` would run that user's library
      constructors as root. When programs do run (ordinary users by default, root with
      `--allow-exec`), the loader (PT_INTERP), every RUNPATH/RPATH directory with the
      glibc-hwcaps/tls subdirectories ld.so tries first, every needed library as resolved here and
      `/etc/ld.so.preload` must pass the same rule; without readelf nothing runs. Reason: even the
      extended check cannot see dlopen or files read at run time, and root is where a mistake
      costs most. Lost as root by default: `--version` of root-owned bun, envoy, curl and browsers
      (official Node.js tarballs were never run as root: their files belong to uid 1001); versions
      come from headers, package records, paths and strings. Rejected: extending the check and
      keeping execution as root's default (still blind to dlopen); never running as root (no way
      left to get exact versions).
   2. **System tools come from `/usr/sbin:/usr/bin:/sbin:/bin`**, with `/usr/local/{sbin,bin}`
      appended only when only root can change them; the caller's `PATH` is kept for discovery.
      readelf, stat and timeout run even under `--no-exec`, so a directory on root's `PATH` that
      another user can write would supply them. (The precondition is a root `PATH` that is
      already unsafe; the fix is cheap.)
   3. **`ln -T` for `--output`.** Without it GNU ln creates the link inside a directory planted at
      the target name. (The symlink variant in `/tmp` is already blocked by
      `fs.protected_symlinks`; the directory variant still misplaced the report.)
   4. **Only packages that C01 judged are left to C01.** Any dpkg owner used to make C09 skip a
      libbrotlidec and C06 a PyPI Brotli, so a vendor's `.deb` (an agent with its own Python under
      `/opt/<vendor>/embedded`) was never judged. Such copies are now judged like unpackaged ones,
      and the advice names the package to update. `--deep` no longer skips `libbrotlidec*` by name.
   5. **Absent markers are not proof.** C11 says NOT_APPLICABLE only where the build is known: a
      file from a package, or a Go program whose build info does not name the cgo binding
      (`github.com/google/brotli/go/cbrotli`); a hand-built server without markers is UNKNOWN.
      Rejected: UNKNOWN for every server (every nginx/Apache host would exit 2, and "needs review"
      would be ignored); NOT_APPLICABLE with only a wording change (the request's literal C11).
      C08: NOT_APPLICABLE only when `curl -V` lists no brotli; not run and no markers → UNKNOWN (a
      static curl names no decoder symbols and does not use `BrotliDecoderErrorString`). Several
      copies in one file: the linker merges equal strings, so a fixed copy hides an unfixed one.
      The copies of Brotli's dictionary are counted (one per copy: 1 in libbrotlicommon and in
      Node.js); with two or more, LIKELY_FIXED, or FIXED from a path or metadata, becomes UNKNOWN.
   6. **Pre-releases keep their suffix and are never the release.** Bun `1.4.4-rc.1`, Firefox
      `150.0a1` / `150.0b3` / Debian's `150.0~b3`, Node.js `v26.0.0-nightly…` and a header with
      `NODE_VERSION_IS_RELEASE 0` (read as `X.Y.Z-pre`) lost the suffix and could come out FIXED.
      A pre-release of exactly the fixed version is UNKNOWN; of an earlier release VULNERABLE; of a
      later one FIXED. Platform parts of archive names (`-linux-x64`) are dropped; anything else
      after X.Y.Z in a directory name counts as a pre-release.
   7. **Reads of found files are bounded** (`bcc_read_file`): regular files only, opened by
      `head -c` under `timeout` (a FIFO swapped in after the test cannot hang the scan), up to the
      size limit. The string scan is one pass without `sort` (distinct names counted up to 64),
      with grep and awk under a 256 MiB address-space limit (a file that is one huge printable
      line). A file not read to the end is UNKNOWN, never judged by part of its strings.
      Rejected: `tr -s` or `fold` to cap lines (seven times slower on a 130 MB node binary).
   8. **Failures go to "Not scanned"**: dpkg-query exiting 2 or more (or timing out) no longer
      reads as "none installed"; directories find could not read are counted with an example
      (files that vanished during the walk are not); a timeout of the `--deep` search is recorded.
   9. **Excluded ranges are listed; local disks below the roots are searched.** File systems on
      local disks mounted below a root (ext4, xfs, btrfs, zfs, …; network ones too with
      `--include-remote`) are walked as roots of their own, since `-xdev` stops at their mount
      point. Other kinds (tmpfs, overlay, squashfs, fuse) are listed once per kind with a count;
      `--exclude` paths and `--deep` files above the size limit are listed. Rejected: listing all
      mounts below the roots and asking for `--roots` (a data disk under `/srv` is what the roots
      mean). Not covered: btrfs subvolumes that are not mounts (`-xdev` stops at them and
      mountinfo does not list them).
   10. **The container probe is POSIX sh.** `command -v -a` exists in neither dash nor busybox;
      the error was discarded, so Node.js inside containers produced neither a finding nor a
      skipped entry, and the unit test fed mock output without running the script. The probe now
      walks `PATH` itself, deduplicates by real path and ends with `END`; output without it is
      listed under "Not scanned". The script now runs in the unit test (dash) and in the
      integration test (each image's `/bin/sh`, with real Node.js).

   The dependency check first tripled the run time on the development host (20 s → 51 s); one
   `stat` per path chain, no `dirname` processes and caches for libraries, directories and
   whole dependency trees brought it back to about 20 s.
10. **Codex adversarial review, round 5 (2026-10-26): ten findings, nine fixed, one answered by
    reporting.** Round 4's items 2, 3, 4, 9 and 10 were confirmed fixed; the rest led to the
    findings below. Two were the requester's decisions (5, 8).
    1. **Symlinks anywhere on a path are checked where they live.** `bcc_safe_path` canonicalized
       the parent first, so a RUNPATH `/srv/shared/current/lib` whose `current` link sits in a
       directory others can write passed while it pointed into a root-owned release. The path is
       now walked one component at a time from `/`, each directory checked before a link in it
       is followed.
    2. **Empty RUNPATH/RPATH entries mean "do not run".** ld.so reads an empty entry
       (`:/x`, `/x:`, `/x::/y`) as the current directory (verified: a library there was
       loaded). Such programs are not run, and what does run (the probe, `ldd`) is started
       from `/`.
    3. **A version from a file needs the strings to confirm it.** Path, header, metadata or file
       name saying "fixed" yields FIXED only when the strings show the fix's error name in one
       copy of Brotli; no error names, several copies, or a file not read to the end make it
       UNKNOWN, with what was and was not found (this is what the implementation record already
       said: "no marker of the fix → UNKNOWN"; the code had kept FIXED when there were no names
       at all). A file not read to the end is also listed under "Not scanned", and C11 does not
       take a partly read file for one without markers.
    4. **conda coverage needs the record.** An empty `conda-meta/` next to a `lib/libbrotlidec*`
       hid the library; C09 now defers only to an environment for which C06 reported a record.
    5. **What the strings show is reported as found and not found** (requester's decision, instead
       of either keeping "probably fixed" or making every such case UNKNOWN). The status names
       stay (they are the request's and the JSON's); the reason says, for example, "Found: the
       fix's error name; copies of the Brotli dictionary: 1. Not determined: whether all decoder
       code in the file is fixed (equal strings are merged)", and the advice no longer says
       "probably fixed". Two decoders sharing one dictionary cannot be told apart; that is now
       said in the result itself and in limitations.md, rather than claimed away.
    6. **"Covered by C01" is said only of a library C01 judged.** A program that loads a
       private libbrotlidec (through RUNPATH, possibly outside the search roots) used to be
       reported as using "the OS libbrotlidec"; that copy is now judged where it is (as in C09),
       and one that cannot be found is UNKNOWN.
    7. **Chromium**: a Debian-style `~` suffix is a pre-release. (Chromium's own channels use plain
       four-part numbers; `-rc` forms do not occur.)
    8. **`--data`: bounded read, and a warning instead of a refusal** (requester's decision). A
       FIFO or oversized file is refused before it is opened, and the file is read by a bounded
       child. A data file that users other than root (or the scanning user) can change — the file
       or a directory on its path, the `--output` rule — is used, but the report says so at the
       top (`data_writable_by_others` in JSON): the scan checks; it does not vouch for a file
       someone else may have edited. Rejected: refusing such a file as root.
    9. **Failures inside a run that completed are reported**: grep errors in `--deep` (xargs folded
       them into the "no match" status), and `dpkg-query` failing inside a container (the probe
       now prints its status).
    10. **Search roots that are symlinks are walked at their targets** (`find -P` does not descend
       into a symlink given as a starting point; a host with `/srv -> /data/srv` lost the whole
       tree silently). Exclusions are resolved the same way, and the report says which root was
       a link.
11. **Running found programs: the user decides, from the facts (2026-10-27, requester's
    decision; supersedes 10.3 and 10.9.1).** Six rounds of adversarial review kept finding gaps
    in the rule that decided by itself which found programs were "safe" to run: each fix
    (ownership of the file, then of the libraries, RPATH, symlinks on the way, empty entries,
    inherited RPATH) moved the question without settling it, and the decisions it made
    surfaced in the results as reservations nobody had asked for. The requester's principle:
    the tool checks; what it needs to do for that is stated, with the reason, before it is
    done; the result goes back to the user, and the judgment is the user's. So:
    - The checks name the programs whose version they need (node, bun, envoy, browsers
      `--version`; curl `-V`). A packaged node or curl that loads the OS libbrotlidec, and a
      packaged browser, are not asked for: their verdict does not depend on it.
    - Each comes with facts: who besides root (or you) could change the program, a directory
      on its path, a library it would load, or a directory those are searched in (walked the
      way the kernel and glibc's ld.so resolve them, including inherited DT_RPATH); empty or
      relative search entries; what could not be examined.
    - At a terminal the user chooses: all, none, or by number. Without a terminal, `--yes` or
      `--no-exec` must be given; otherwise the tool lists the programs and stops (exit 3). With
      nothing to run, nothing is asked.
    - The chosen programs run from `/`, with an empty environment, stdin closed, a time limit,
      and their output capped; the report lists what ran (with its output), what did not and
      why, and the facts (JSON `execution`).
    - `ldd` is no longer used: it hands the file to the loader, which is running it in all but
      name. Linkage is followed with readelf only.
    Rejected: deciding by rules (6 rounds; see above); running nothing ever (versions from
    files are weaker, and the user may well want them); running everything without asking
    (the user would learn the facts only afterwards). The tool's own system tools still come
    from fixed directories (10.9.2): those are the tool's, not the host's findings.
12. **Codex adversarial review, round 6 (2026-10-26/27): fixed under the principle of 10.11.**
    The execution items (ancestor and dangling symlinks, inherited RPATH) became facts shown
    before asking. The rest were fixed: the completeness of a read is taken from the exit
    status of every stage, never from marks in the data (a file could forge them); a version
    read from a file is confirmed against the decoder for Firefox (`application.ini` against
    `libxul.so`), flatpak runtimes and conda records too; a file that loads libbrotlidec but
    carries its own decoder error names gets that copy judged; a libbrotlidec loaded under a
    name its file does not have is still judged; candidates are matched by name before and
    after resolving links (an alias such as `node -> node-22.0.0` is kept, a multi-call shim
    such as mise's `node -> mise` is not - the first version of this fix ran `mise --version`
    as a node, which the new report showed at once); paths travel NUL-separated, so a newline
    in a path cannot split it; a container's dist-packages counts as the distribution's only
    when python3-brotli is installed there; an Envoy configuration read in part is not called
    free of Brotli; failures of `snap list`, `flatpak list` and `ss` are listed as not scanned;
    Electron snaps are found through `/snap/NAME/current` (a symlink, which `find -P` would
    not enter - missed since the first version).
13. **The list of programs to run, and its facts, hold whatever bytes a found path holds
    (2026-10-27; automatic security review after the commit of 10.11/10.12, two findings, and
    what checking them showed).** The list is the screen the user decides on (10.11), so what
    it shows must be what is there, and what runs must be what it showed. Seen on this host
    before fixing:
    - The list was written to the terminal as it was: an escape sequence in a directory name
      reached the terminal and could rewrite the facts above the question. It now goes through
      the same filter as the report (control characters as `?`), and tabs and newlines in a
      path or fact are shown as `?` too, so a path cannot print a line that reads like another
      program or fact. Fields of findings show tabs and newlines as `?` as well (they were
      spaces): one path reads the same in every part of the report.
    - A path with a newline gave wrong facts, not just fewer: `IFS=/ read` stopped at the
      newline, so the walk examined a shorter path and said "`/…/a` does not exist", and the
      facts joined with `\037` and read back with `read` lost everything after the first
      newline. Facts are now kept in arrays (`BCC_FACT_POOL`, with caches holding ranges), and
      paths are split with parameter expansion.
    - Found while checking (not in the review): **a tab in a path ran another program.** A plan
      entry was "path<TAB>argument" and was split at the first tab, so for
      `/x/evil<TAB>dir/bin/bun` the tool showed that path and ran `/x/evil` with the argument
      `dir/bin/bun<TAB>--version`. The entry's key is now only compared; the program and the
      argument are kept apart (`BCC_PLAN_BIN`, `BCC_PLAN_ARG`).
    - The dependency walk wrote its records as lines of tab-separated fields, and the search
      path a library inherits as a `:`-joined string. A program under a directory with a
      newline and an `$ORIGIN` RUNPATH (common in Electron and Chromium builds) gave facts
      about the wrong directory. Records and inherited chains are now arrays; the cache key of
      a library lookup gives each part with its length, so two different searches never share
      one (a directory reached through `$ORIGIN` may hold `:`).
    - Smaller ones in the same functions: a symlink target ending in a newline lost it to
      `$(...)`; a chain of more than 40 links (where the kernel stops too) or an unreadable link
      ended the walk silently and could leave only "as far as examined, only root…" - now a fact
      says so; a `[` or `*` in a library directory was taken as a glob pattern when looking for
      `glibc-hwcaps`; and readelf's `Library runpath: [VALUE]` was parsed with a greedy
      `.*\[`, so `/opt/app [1]/lib` became the relative entry `1]/lib` and the real directory
      was never examined (the new test showed it). The value now runs from the first `[` to
      the `]` that ends the line.
    Checked: each new test fails on the code before the fix and passes after; `--no-exec --json`
    on the development host gives the same `execution` (32 entries with their facts) and the same
    64 findings before and after, in the same time. Left as they are (for the next review): the
    path of a linked libbrotlidec is passed to the checks as "path<TAB>readelf" and split at the
    first tab; a candidate whose resolved name ends in a newline loses it to `$(...)`; a value
    inside the ELF (RPATH, NEEDED, PT_INTERP) holding a newline is cut by readelf's line output.
    Each needs a crafted name; in each, what runs is still the program listed.
14. **Mutation tests of 10.11-10.13 (2026-10-27; test record, chapter 13).** Each fix was reverted
    on its own in a copy of the tree and the whole unit suite run. Of 91 mutations (including the
    rounds 4 and 5 ones still applicable), 69 were caught. The 21 gaps were in the consent model
    (how a chosen program runs; what the plan leaves out; listing what did not run) and in the facts
    and the dependency walk (owners other than root or you, the loader, each library, relative
    entries, `/etc/ld.so.preload`, RUNPATH hiding RPATH, the depth limit, `:` in an inherited
    directory, `[` in an RPATH). Ten tests were added, using a fake `stat` and a fake `readelf` where
    only root or a hand-made ELF could produce the case; all 22 mutations re-run were caught. Two
    code changes came with them: `/etc/ld.so.preload` can be replaced by `BCC_LD_PRELOAD_FILE` in
    tests (as `BCC_PROC_ROOT` replaces `/proc`), and the plan's ignored `bcc_dpkg_owner` status is
    written `|| true` (no change in behaviour; it lets the function run under bats' `set -e`).
