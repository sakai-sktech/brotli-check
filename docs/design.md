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
| 5 | Node.js end-of-life lines | 20 and earlier, 21, 23, 25 get no fix | The advisory names no lines. **Derived** from "end-of-life versions are always affected" plus "no fixed release exists": `status=derived` (`derived_eol` since 10.16) with the reasoning in the note | same |
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
section 6; for HAProxy the Debian and Ubuntu source packages were read on 2026-11-02, 10.17).

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
| 3 Bun | source analysis → `analysis` | Bun's advisory GHSA-663w-cv8g-jj2p (published 2026-10-23; affected >= 1.0.21, < 1.4.4; `bun build --compile` executables stay affected until rebuilt) → `fixed`. It was missed on 10-26, when the release notes were read instead; the source analysis agrees with it. Versions before 1.0.21 are outside its range; as the data was per series, they were reported like the others before 1.4.4 until 10.16 | github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p |
| 18 Background paper | 404 | Published (quick report, 2026-10-27); linked from the README. Its versions agree with the data after this update | jmedic.co.jp/pubdoc/http2shell_report_20261027.html |

Unchanged on re-check: Google Brotli tags (v1.0.10 / v1.1.1 / v1.2.1, published 2026-10-21),
GHSA-9v8h-qqgm-4m35, PYSEC-2026-4322 / 4323, the Node.js advisory and its list of end-of-life
lines, Debian bookworm / trixie, Envoy GHSA-3wvj-j6qm-62mr, ISTIO-SECURITY-2026-007, Chromium's
`README.chromium` (cfa184a9) and Firefox's `moz.yaml` (4792c8e4).

### 2.2 Re-checked before release (2026-11-02)

Every row's primary source was read again, and the snapshot moved to 2026-11-02. No existing row's
version changed. Changes:

| Row | Found | Data | Source |
|---|---|---|---|
| Ubuntu ESM | USN-8956-2 (2026-10-27) fixes 20.04 focal, 18.04 bionic and 16.04 xenial, with Ubuntu Pro only | Three `fixed` rows: 1.0.7-6ubuntu0.1+esm1, 1.0.3-1ubuntu1.3+esm1, 1.0.3-1ubuntu1~16.04.2+esm1. Those hosts were UNKNOWN ("no data") | ubuntu.com/security/notices/USN-8956-2, ubuntu.com/security/CVE-2026-111497 |
| Firefox ESR | The current ESR is 153 (`FIREFOX_153_0esr_RELEASE` has 4792c8e4), and 115 is still updated (115.34.0esr has e61745a6, 115.35.0esr has 4792c8e4). 128 ended at 128.14.0esr without it | Two `analysis` rows: 153.0 and 115.35.0. 128 has no row, so it stays UNKNOWN | `modules/brotli/moz.yaml` per tag, product-details.mozilla.org |
| Envoy 1.17 and earlier | Envoy's source has no Brotli before v1.18.0 (no mention in `repository_locations.bzl`, `repositories.bzl`, `extensions_build_config.bzl` at v1.14.0-v1.17.4; the filter arrived in 127aa553, 2021-02-08). "Bundles Brotli in the affected range" was too much for these lines | New `unknown` row `<=1.17`; the `<=1.35` note now gives what was pinned (0cd2e392 and 6d03dfbe, both v1.0.9 plus commits, and 1.1.0) | the same files per tag |
| .NET | Not a row. dotnet/runtime builds Google's C decoder (`src/native/external/brotli`, 1.0.9 at v8.0.29) into `libSystem.IO.Compression.Native.so`, and USN-8958-1 (2026-10-29) names this CVE for it. `docs/limitations.md` called .NET a separate code base, which was wrong. See 10.18 | none yet | ubuntu.com/security/notices/USN-8958-1, github.com/dotnet/runtime |

Unchanged on re-check: Google Brotli tags; GHSA-9v8h-qqgm-4m35 (modified 2026-10-29, same ranges);
PYSEC-2026-4322 / 4323, which still disagree with it below 1.0.3, so PyPI stays as in 10.16.6; no
PyPI release lies between the stated last versions and the fixes; Debian bookworm, trixie, sid and
forky (still 1.2.0-4); Ubuntu's four rows; the Node.js advisory and the end-of-life dates of 20, 21,
23 and 25; Bun's GHSA-663w-cv8g-jj2p and its pin db24a98a (identical to v1.2.1); Envoy's advisory
and the pin 42a2ed43 in all five fixed tags, a descendant of the fix 0ed4268a; ISTIO-SECURITY-2026-007
and 1.29's end of life on that date; Chromium's cfa184a9, a descendant of the fix. Chromium's
threshold 148.0.7778.0 stays: tags from 148.0.7750.0 already have cfa184a9, so development builds
between there and the threshold are UNKNOWN when they could be FIXED, which changes no next step for
a build nobody runs in production.

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
date) plus a **note** column, because `derived_*` and similar statuses need a place for their
reasoning, and an **affected** column for the range an advisory states (10.16).

| Column | Example |
|---|---|
| component | `node` / `bun` / `pypi:brotli` / `deb-src:brotli` / `envoy` / `chromium` … |
| branch | `22`, `debian:trixie`, `ubuntu:noble`, `*` |
| fixed | `22.23.4`, `1.1.0-2+deb13u1`, `-` (no fix) |
| status | `fixed` / `no_fix` / `unreleased` / `derived_eol` / `derived_bundled` / `analysis` / `unknown` |
| affected | `GHSA-663w-cv8g-jj2p:1.0.21:1.4.3` (`ADVISORY:FIRST:LAST`), `-` (none stated); `fixed` rows only |
| source_url | primary source URL |
| retrieved | `2026-10-26` |
| note | short reasoning |

Meaning of `status`:
- `fixed` — the primary source names the fixed version. With `affected`, a version below `FIRST`
  is UNKNOWN (the advisory does not say whether it is affected) and an update is recommended
- `no_fix` — the distributor has not released a fix (all Ubuntu releases until 2026-10-26; none
  as of 2026-10-27) → NO_FIX_AVAILABLE
- `unreleased` — a fixed version is named but has not reached the archive (Debian forky
  1.2.0-4.1; sid until 2026-10-27). Installed version at or above `fixed` → FIXED, below → NO_FIX_AVAILABLE
- `derived_eol` — the primary source says end-of-life versions are always affected, and the line
  gets no fix (Node.js) → VULNERABLE; the reason states that ground
- `derived_bundled` — the line bundles a Brotli in the affected range, and gets no fix (Envoy 1.35
  and earlier; the advisory does not name them) → VULNERABLE; the reason states that ground
- `analysis` — from the product's source tree, not a vendor advisory (Chromium / Firefox; Bun
  until 2026-10-27);
  the result says so
- `unknown` — the data cannot decide (Node.js 10 and earlier, which may predate the bundled
  Brotli; Envoy 1.17 and earlier, whose source has no Brotli) → UNKNOWN; the reason states that
  ground (some versions or builds of the line have no Brotli), not a pointer to the evidence (10.25)

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
are `derived_bundled` (older Envoy bundles Brotli 1.0.9 / 1.1.0).

**C11 compression-only products** — primary sources confirmed ngx_brotli (libbrotlienc only),
mod_brotli (compression filter only) and Traefik (Go implementation, andybalholm/brotli). HAProxy
and Caddy are to be confirmed in their upstream sources during implementation; if not confirmed,
they are reported as information with their version, not as NOT_APPLICABLE. Distribution nginx and
Apache are additionally measured with `ldd` to confirm they do not load libbrotlidec.
(Implemented as a decision from the files themselves; 10.6. Which packages are NOT_APPLICABLE:
10.17.)

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
  (dpkg-query, dpkg, readelf, ldconfig, ss, snap, flatpak, docker ps, docker context inspect,
  podman info) still run; they are outside "running the programs it found" in section 2.4 of the
  request. Without `--no-exec`, found programs run only after the user chose them from the list
  (or gave `--yes`), 10.11; `--inspect-containers` runs its fixed script inside containers, the
  option itself being the consent, and only through a unix socket on this host (10.20). `--no-exec`
  with `--yes` is an error.
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
   NOT_APPLICABLE".) **Refined by 10.9.5 and 10.17**: no markers is NOT_APPLICABLE only for a
   distribution package whose sources were read or a Go program without the cgo binding; any other
   package and a hand-built one are UNKNOWN.
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
   5. **Absent markers are not proof.** (10.17 narrows "a file from a package" to the checked
      ones.) C11 says NOT_APPLICABLE only where the build is known: a
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
15. **No file to compare means no FIXED (2026-11-01, issue #1).** 10.10-3 said a version from a
    file needs the strings to confirm it, but when C06 found no file to look at, its loop did not
    run and the FIXED from `bcc_judge` stood.
    1. **No file: UNKNOWN**, with a reason saying which file was looked for, and a next step that
       fits (the installation may be broken), since "ask the vendor which Brotli it bundles" does
       not. A version below the fix stays VULNERABLE: nothing confirms it either, but an update is
       the next step whichever is true.
    2. **Each PyPI package is compared with its own module** (Brotli: `_brotli.*so`; brotlicffi:
       `brotlicffi/_brotlicffi*.so`, the names in the wheels of 1.2.0, 1.2.1, 1.2.0.2 and 1.2.1.0).
       The old glob took both for either package, so a fixed `_brotli` module could confirm a
       brotlicffi that had none, and an unfixed one made a confirmed brotlicffi UNKNOWN. C09
       defers only those same files, and only for the package C06 judged in that site; otherwise
       narrowing the glob would have left a stray `_brotli` module next to brotlicffi unread.
    3. **conda still does not count symbolic links** (the request of the issue), so an environment
       whose `lib/` holds only links, as with conda's `always_softlink`, is UNKNOWN even when
       fixed. The reason says that links are not counted.
    4. **Paths are taken literally.** `compgen -G` and `bcc_glob` read a `[` or `*` in the site or
       environment path as a pattern; with this rule that would have turned into "no file found".
    5. **C14: Python in a container is UNKNOWN at or above the fix; the probe was not extended.**
       Alternatives: compare the strings in the probe (a second implementation of the heuristic in
       POSIX sh, where `sort` may write to the container's `/tmp` and no pipeline status is
       available), or stream each module through `docker exec` to `bcc_brotli_scan` (one heuristic,
       more reads through the engine). Accepted cost: a fixed Python in a container is never FIXED,
       and such a line adds to exit code 2. Why now: UNKNOWN says only what was seen, can be
       tightened later without taking anything back, and issue #6 is still deciding what `docker
       exec` may do and where. Streaming is the option to weigh after #6.
16. **What an advisory's range leaves out is UNKNOWN, not VULNERABLE (2026-11-01, issue #2).**
    `bcc_judge` had no lower bound and `derived` rows were VULNERABLE whatever their ground, so a
    version confirmed in the range and one that was merely old had the same verdict, reason and
    exit status. The difference was only in the English note, which the text report does not show.
    1. **A new column `affected` (`ADVISORY:FIRST:LAST`), not more rows.** Rows are chosen by line,
       and Brotli 1.0.2 and 1.0.3 are the same line. It is allowed on `fixed` rows only. The loader
       refuses a malformed, misplaced or reversed range, since one would silently turn VULNERABLE
       into UNKNOWN. A `--data` file with the old 7 columns is refused (no release has used them).
    2. **Below FIRST: UNKNOWN, with no new verdict.** The advisory says neither that the version is
       affected nor that it is not. A new verdict such as `OUT_OF_RANGE` was the alternative; it
       would ask every reader to learn it for what UNKNOWN and a reason can say. The reason names
       the advisory and the range and recommends an update, and the caller's own way of updating
       still applies (`bcc_judge_advises_update`), because the next step does not change. Accepted
       cost: such a version adds to exit status 2, not 1, and is not counted under "Needs update".
       When a part's old versions turn out to be affected or not, its row changes.
    3. **Brotli 0.x is a `fixed` row with `fixed` 1.0.10 and the same range,** so it takes the path
       of 2 with no status of its own, and its update target is a real version. Accepted cost: on
       this row `fixed` is the oldest fixed release to move to, not a fix of the 0.x line (the note
       says so).
    4. **`derived` became `derived_eol` (Node.js) and `derived_bundled` (Envoy),** so that the reason
       can state the ground in both languages. Alternatives: print the note (English in a Japanese
       report, and free text), or add a column naming a message (one more thing to validate, where
       the loader already validates statuses). Accepted cost: another kind of ground needs a status
       and messages.
    5. **Envoy's next step named a version again.** A `derived` Envoy row said "Update to - or later";
       it now names the lines to move to, as Node.js already did.
    6. **PyPI went beyond the issue, which named only Bun and Brotli.** GHSA-9v8h-qqgm-4m35 says
       >= 1.0.3 for PyPI Brotli and brotlicffi, while PYSEC-2026-4322 and 4323 have `introduced: 0`
       and list older versions. CONTRIBUTING says to prefer unknown while sources disagree, so these
       rows carry the GHSA's range and the note records both. Accepted cost: the reason cites only
       the GHSA; the disagreement is in the evidence.
    7. **The snapshot stays 2026-10-27,** against the letter of CONTRIBUTING: the README says every
       row's source was checked on that date, and moving it for a few rows would overstate that.
       What was read on 2026-11-01 is dated in the PyPI notes; the re-check of all rows before the
       release moves the snapshot.
17. **Only packages whose build was checked are NOT_APPLICABLE (2026-11-02, issue #3).** 10.9.5 gave
    "the build of a package is public" as the reason, but the code took any dpkg owner, so an
    in-house `.deb` read "whose build does not decode Brotli". It keeps the decision of 10.9.5 not
    to make every server UNKNOWN, and narrows "a package".
    1. **What was checked.** For Debian 12, 13 and Ubuntu 22.04, 24.04, 26.04, the source packages
       `nginx`, `libnginx-mod-http-brotli` (not in 22.04), `apache2` and `haproxy` were fetched with
       `apt-get source` and searched for `BrotliDecoder`, `brotli/decode.h` and `_ERROR_FORMAT_`:
       no hit in any of them, `debian/` and nginx's bundled modules included. `mod_brotli.c` and
       ngx_brotli include only `brotli/encode.h`. HAProxy's sources do not contain the word
       "brotli" at all, which is the primary source section 2 could not find, so HAProxy joins the
       list. The binary packages of those sources are listed in `BCC_C11_CHECKED_PACKAGES`. A later
       release of the same package is taken on trust until it is added to this check.
    2. **How the distribution's package is told: name, `Maintainer` and the form of `Version`,
       from dpkg's own record.** All three, because each alone lets a real case through: the name
       (nginx.org's package is also `nginx`: `1.26.0-1~noble`, NGINX Packaging), the maintainer
       (the `apache2-bin` of Ondřej Surý's PPA keeps Debian's Apache Maintainers:
       `2.4.69-1+ubuntu24.04.1+deb.sury.org+1`; its nginx PPA could not be fetched), the version
       form (anyone can write `-1`). The accepted forms are those measured on the five releases,
       plus `~bpo12+1` and `+esm1`, which follow the distributions' conventions but were not seen on
       these packages. Rejected: `apt-cache policy`. An installed version the archive no longer has
       shows only `/var/lib/dpkg/status` (tried with `1.26.3-3+deb13u8` on Debian 13, between the
       release's and the current one), as does a host without lists (the images here remove them),
       and that host would exit 2 for being behind or tidy. Apt also says what a repository offers,
       not where the file came from: a rebuild with the same version looks the same there too.
       Accepted cost: a rebuild that keeps all three looks like the
       distribution's, and the reason says so. This is not a security boundary, as whoever can
       install a package can also write dpkg's records; it keeps honest in-house and third-party
       builds from being taken for the distribution's.
    3. **The file must be the one the package installed** (`dpkg --verify`, which compares with the
       recorded MD5 and works without root). `make install` over `/usr/sbin/nginx` leaves dpkg's
       owner in place, and the issue's premise is the build of that package. Its exit status is 0
       with differences too, so the output is read, and only the line for this file counts: images
       remove documentation, and other packages' files say nothing about this one. A failed
       comparison is UNKNOWN with its own reason. The cost is one read of the package's files per
       server file, in the branch reached only when nothing else decided.
    4. **A diverted path is not the package's.** `dpkg-query -S` then begins with `diversion by X
       from`. `dpkg --verify` compares the diverted original, not this file, so skipping those lines
       would have found the package and an empty comparison. It is UNKNOWN (10.18.2 moved this into
       `bcc_dpkg_owner`, so the words no longer reach the reason).
    5. **Go comes before "any other package".** Debian's `caddy` is a package with no source check
       here, but it is a Go program without `cbrotli`, and that is the better statement about it.
       The reason now says only `cbrotli` is looked for. Other cgo bindings were not tried.
    6. **The reason of an unchecked package gives its version and maintainer**, since those decided
       it and a reader with nginx.org's `nginx` would otherwise see "the build was not checked"
       next to a familiar name.
    Accepted: a host with a third-party nginx, or with a Debian `nginx` rebuilt under another
    version, now exits 2 (the point of the issue). The integration tests install the three servers
    in every image and expect exit status 0 once the copies placed on purpose are removed.
18. **Round 7 of the adversarial review, before the first release (2026-11-02, issue #4).** It gave
    15 P1 findings against the whole tool; each behaviour holds in the code (the checksum and diversion
    ones were also seen on Ubuntu 24.04). Eleven were fixed, three are listed in
    `docs/limitations.md` and left for later issues, one was declined. The requester chose this split
    and that the gate before releasing is a review of this diff, not of the whole tool again. That
    review (round 8) gave 5 more, two left over and three caused by the fixes, and rounds 9 to 11, each
    of a smaller diff, gave 4, 1 and 1 (one of the 4 repeats 7 below); they are included here. The
    requester closed the gate at round 11: its one-line fix has tests and mutation checks, and has not
    been through another review.
    1. **What a check leaves to another must be what that check looked at.** C09 left every decoder
       file of a conda environment to C06, which compares only `lib/libbrotlidec.so.*`, so an old
       `libbrotlidec.a` next to a fixed library was in neither; it now leaves the files C06 compared.
       C14 treated `python3-brotli` as speaking for everything in `dist-packages`, including a
       brotlicffi; now only for Brotli's metadata at the package's own upstream version. Accepted: a Debian `python3-brotlicffi`, which uses
       the system library, is judged by its upstream version in a container, as it already was
       without `python3-brotli`.
    2. **What dpkg says about a path is read for that path.** `dpkg-query -S` takes a pattern and prints
       the recorded names, so an unowned file named `/usr/bin/[l]dd` was taken for `libc-bin`'s `ldd`
       (seen on the five releases; older than this work). Only a line naming the path itself now counts;
       a literal name comes back as asked on all five, with no `/lib` and `/usr/lib` aliasing.
       **A diversion is decided in `bcc_dpkg_owner`, and there is no owner.** 10.17.4 let the words
       `diversion by X from` through for C11, where they did no harm, but the function has five other
       callers: C04 called the replacement a distribution package, C06 advised updating a package with
       that name, C13 left the browser out of the list of programs to run, and C09 split the words, so
       a diversion by a package named `brotli` counted as covered by C01. What is at a diverted path
       now counts as unpackaged everywhere, unless the diverting package itself is also listed for the
       path: its own file is exempt from its diversion. Rejected: an extra reason saying "diverted" in
       C11, as the next step is the same. Since a package may no longer own a Node.js here, C04 now
       looks at what the program loads first, whoever installed it; such a program is not listed to run.
    3. **Silence is an answer only from what was asked.** `dpkg --verify` says nothing about a file
       with no recorded checksum, so with `md5sums` gone a replaced `/usr/sbin/nginx` was
       `NOT_APPLICABLE` and "as installed". The file must now be in `dpkg-query --control-show PKG
       md5sums`; otherwise it is UNKNOWN, with its own reason, also with a dpkg without that option.
       A file recorded as `sbin/x` and found as `/usr/sbin/x` counts as not recorded; the reason is
       then still true, and the servers checked here are recorded under `usr/`.
    4. **A checked version form keeps only forms that were seen.** The upstream part of
       `BCC_C11_DISTRO_VERSION` took any letters, so `1.26.3~acme1-1` passed. It now takes digits and
       dots with `~rc`, `~alpha`, `~beta`, `~pre` or `~dev`, and `+dfsg` or `+ds` as before.
    5. **Own copies.** C11 now looks for one next to a linked libbrotlidec, as C04 and C08 do, and
       one not read to its end is listed as not scanned instead of being dropped when too few names
       were read. A Flatpak runtime is searched for the index's names, without debug symbols, and a
       real file without a full version in its name is judged by its strings. A NEEDED entry may be a
       path (a library linked without a SONAME), and is recognized by its last component. With
       `--deep`, a program's library that C01 did not judge is reported through the program: its file
       need not be under the roots, nor look like a library.
    6. **Numbers and paths.** `bcc_numcmp` compares components as digits, since arithmetic wrapped a
       very long one, which let a reversed range through the loader and could turn a version read from a
       file into something else. The caller's PATH is split without `read` and passed NUL-separated,
       as a directory may hold a newline (10.13).
    7. **Left for later (issues #18 and #19), with an entry in the limitations:** only the first of several differently named
       libbrotlidec libraries of one program is judged (two in one process are rare, and callers take
       one path); a `node` that is a link to a program of another name is not taken, and not listed (the
       filter exists for version-manager shims, 10.12, and telling a shim from a runtime is the real
       work; 10.23 names such links and judges what their files carry); glibc-hwcaps directories are tried in name order rather than glibc's priority (the right
       order needs the CPU's supported levels).
    8. **Declined: `--output` writes a temporary file first.** It is created beside the requested name
       in the directory that was just checked, linked to that name so that nothing is overwritten
       (`noclobber` does not refuse every kind of existing file), and removed. Writing directly would
       trade this for a partial report under the final name. The README now mentions it.
    9. **.NET is a known gap, not a detail of the limitations.** Ubuntu's `dotnet-runtime-8.0`
       (8.0.33, fixed per Ubuntu) holds a decoder in `/usr/lib/dotnet/.../libSystem.IO.Compression.Native.so`,
       and it does not load libbrotli. The default run says nothing about it and `/usr/lib/dotnet` is
       not in the default roots; `--deep --roots /usr/lib/dotnet` gives `VENDORED_COPY`. A fair verdict
       needs rows for .NET's own versions, so it is a separate issue (#17).
19. **RESTART_REQUIRED takes its next step from the file now at the same path (2026-11-04, issue
    #5).** The status was defined as "the fix is on disk but a process still runs the old code", but
    C03-C05 saw only that a process uses a deleted file. A process restarted onto a file that is still
    unfixed would be taken for fixed. The status and what it counts (the summary's "Needs restart",
    exit status 1) stay; its definition is now what is seen, and the line says what is on disk.
    1. **What is at the path now is what this run already said about it.** Every finding about a file
       records its status for that path (`bcc_note_disk`, from `bcc_add_finding`). Files judged
       through something else are recorded where that happens: a package's files through C01 (by the
       dpkg owner of the path, `bcc_c01_notes`), the extension modules and conda libraries C06
       compared, and a program that loads libbrotlidec gets that library's judgment
       (`bcc_note_loaded`; Debian's `nodejs` is judged through `libbrotli1`). The issue names C01,
       C04, C05 and C06; C09's libraries (a private `libbrotlidec.so.1.2.0` under `/opt`) follow
       from the same rule, since every finding is recorded. The deleted file itself is not read:
       whatever the old code was, the next step is the same.
    2. **Three next steps.** Every judgment FIXED: restart, as before. Any VULNERABLE,
       NO_FIX_AVAILABLE or LIKELY_VULNERABLE: a restart alone does not fix it; follow that line first
       (named by ID and component), then restart. Anything else (UNKNOWN, LIKELY_FIXED,
       VENDORED_COPY, no judgment, no file at the path now): check the version a restart would use,
       then restart. LIKELY_VULNERABLE goes with "update" because the summary already counts it as
       needing an update; LIKELY_FIXED goes with "check" because its own line says to ask the vendor.
       A process with several deleted files gets the strongest (update, then check, then restart).
    3. **A process in another mount namespace is not compared** (not in the issue). A process in a
       container, a snap or a flatpak names its files by paths that lead to other files on this host;
       without this, a container whose image is unfixed would be told "restart" because the host's
       library is fixed. `/proc/<pid>/ns/mnt` is compared with the tool's own; different, or not
       readable: not compared, and the line says to check first. Reading it needs the same
       permission as the maps C03 reads.
    4. **Order.** C03 now runs after C13, once C06 and C09 have judged; C04 and C05 report deleted
       executables after judging their candidates. The text report groups findings by ID, so it does
       not change; in JSON, C03's findings now come after C13's (the order of `findings` was never
       specified).
    5. **Wording.** "replaced" became "deleted": a file can be removed with nothing in its place.
       The reason gives each judgment as "ID component: STATUS", so the line it rests on can be
       found. Not finding a deleted file is not proof that nothing needs a restart
       (`docs/limitations.md`).
    Rejected: following the soname (`libbrotlidec.so.1`) to what a restart would load, instead of
    the same path. It is closer to what a restart does, but the issue asks for the same path, and
    when the file name changed, "no file there now; check the version" is still true. Rejected:
    reading a container process's files through `/proc/<pid>/root` (reaching into containers is
    what #6 is deciding). Accepted: a process whose old file had another name than the new one
    (`libbrotlidec.so.1.1.0` replaced by `.1.2.1`) is told to check first even when the new library
    is fixed.
20. **Containers: the connection is reported, and the check script runs only through this host
    (2026-11-04, issue #6).** C14 used docker or podman with the caller's connection settings and
    never looked at them, so `DOCKER_HOST` or a docker context naming another host put that host's
    containers into this host's report, and `--inspect-containers` ran the check script inside them.
    The help and the report header called the tool read-only, which holds for the tool's own code
    only.
    1. **The engine is asked; its settings are not read.** docker settles the connection from `-H`,
       `DOCKER_HOST`, `DOCKER_CONTEXT` and the current context of its configuration, in that order,
       and `docker context inspect` with no name answers for the context so chosen (docker 29.9 on
       the development host, 2026-11-04: `DOCKER_HOST` over `DOCKER_CONTEXT`, an unknown
       `DOCKER_CONTEXT` fails). Reading the variables and `config.json` would be a second
       implementation of that order, and the tool reads no environment variables (7). podman runs
       containers itself unless it is a client of a service, and `podman info` says which
       (`.Host.ServiceIsRemote`). Measured with podman 3.4.4, 4.3.1, 4.9.3, 5.4.2 and 5.7.0 of the
       five releases: from 4.3 on it is true with `CONTAINER_HOST`, `--url` or `CONTAINER_CONNECTION`,
       and false with only a default connection registered; 3.4 keeps running locally with those
       variables and says false, which is then true.
    2. **Only a unix socket on this host, or podman with no service, counts as this host.**
       `tcp://localhost` may be an ssh tunnel to another host. A socket of another host brought here
       as a unix socket cannot be told apart; the README and the limitations say so. Docker
       Desktop's engine runs in a virtual machine on this host behind a unix socket, and counts as
       this host.
    3. **The list and the counts stay, with the connection** (the triage's A2; stopping C14 for other
       connections was too heavy). The connection line comes first, and also when the engine then
       fails, where "cannot be used" may be about another host. Each container not looked inside
       points at that line, and one "Not scanned" entry gives the connection and the reason. This
       also holds without `--inspect-containers`, where suggesting that option would lead nowhere,
       and with `--no-exec`.
    4. **Every later call stays on the context that was checked** (`docker --context NAME`). A scan
       takes tens of seconds, and the user may switch contexts in another terminal meanwhile
       (`docker context use`); `ps` and `exec` would follow the switch. podman is not pinned: whether
       it is a client is settled at its start from its arguments, environment and configuration,
       which a context switch does not touch.
    5. **podman as a client is not looked inside, even through a unix socket,** because podman does
       not state the client's address: `podman system connection list` shows the configured default
       and not `CONTAINER_HOST` (measured), and `.Host.RemoteSocket.Path` is the service's own
       socket (it printed `unix:///run/podman/podman.sock` in client mode), a unix socket also when
       the service is reached over ssh. Accepted cost: podman with `CONTAINER_HOST` naming a local
       socket is not looked inside; the reason says why, and podman without it runs locally.
    6. **An answer of another shape is "not known".** docker's must be a context name of docker's
       characters and an endpoint with a scheme; podman's must be `true` or `false`. A `docker`
       without contexts (before 19.03) or podman's emulation (podman-docker, whose `context inspect`
       printed nothing on 4.3 to 5.7 and failed on 3.4) gives "not known": listed, nothing run
       inside. Accepted cost: with podman-docker, containers are looked inside only through
       `podman`, which C14 does not try when `docker` exists.
    7. **Words.** The help and the report header no longer say "read-only"; `--inspect-containers`
       says that it runs a fixed check script, and where. The script's own reasons say "check
       script", since it starts the `node` it finds with `--version`, as a program of the container.
       for-clinics and figure 01 no longer say "without changing anything" or "uses no network"; the
       README had already separated the tool's own actions from those of the programs it runs (#13).
    8. **Two questions left by issue #1, answered by the requester (2026-11-04).** Python inside a
       container stays UNKNOWN at or above the fix (10.15.5): this issue narrows where the check
       script may run, and streaming each extension module to the host through the engine is a
       feature of its own, with more reads through the engine. A real container is now tested in the
       integration run (`tests/integration/run.sh`), once per run: the tool runs on the test host
       against a container of the image, through the engine's unix socket (the script runs inside;
       both Node.js copies are judged) and through a TCP relay to the same socket (listed with the
       connection; nothing runs inside; the relay serves only the test user's own sockets, by the owner
       `/proc/net/tcp` gives, since a loopback port is open to every user of the machine and the
       engine's socket gives control of the engine). Found programs of the test host are not run: the question
       is answered "n" on a pseudo-terminal, since `--yes` would run them on the developer's machine
       under `make integration`.
21. **EXPOSURE reasons say what was seen and what was not (2026-11-04, issue #7).** C06, C07 and C15
    see only that a package is installed or that a process listens, but their reasons said "decodes
    ... automatically" and "prioritize this process", which the external review (R7) read as
    statements about the application. The verdict, its place outside the exit status and what each
    check looks at are unchanged.
    1. **Each reason states what was seen, then one sentence on what was not.** C07: packages that
       can decode br request bodies (express 5, body-parser 2, ...) or br responses they fetch
       (undici, axios, ...) are installed; whether an application uses them, and through which
       path, is not checked. That sentence comes once per line, for both kinds: the issue drafted
       one per kind, and a line with both would have said it twice. C06: these HTTP clients decode
       a br response when they receive one; whether an application fetches with them is not
       checked. C15: it listens beyond loopback; whether it can be reached from outside (firewall,
       routing) is not checked. "Prioritize" stays in the next step, where it already was.
    2. **aiohttp.** C06 adds that aiohttp.web servers decode br request bodies by default. After a
       sentence on what was not checked that spoke only of fetching, that read as if a server had
       been seen. With aiohttp, the sentence on what was not checked comes last and names receiving
       requests with aiohttp.web as well (a second message, since a message is one printf format).
    3. **C10 too, beyond the issue (requester's answer, 2026-11-04).** The `--envoy-config` file is
       searched for the decompressor's name, so a commented-out filter matches, and whether the
       running Envoy uses that file is not seen. "The configuration enables a Brotli decompressor"
       now reads: the file names one, and whether the running Envoy uses the file and whether the
       entry is in effect is not checked. The README's row for `EXPOSURE` covers entries in
       configuration files, and would not have been true of C10 otherwise.
    4. **No `EXPOSURE` is not proof of no path.** A program that fetches and decodes responses
       without listening (a crawler, URL previews, an AI agent) does not show in C15, and C06 and
       C07 see client packages only where they look (C07 only with `--projects`). This is said in
       the README (what the tool does not tell you, the status table, the `--exposure` row of "How
       far it looks") and in `docs/json-schema.md`. Not in the summary, the alternative the issue
       allowed: those four lines are for non-specialists, and most runs have no `EXPOSURE` check
       at all (C07 and C15 are off by default); a line only when one ran would make the summary's
       shape depend on the options.
    5. **`docs/sample-output.md`: only the C06 line was edited**, by hand, and the page says so. It
       is to be captured again after #9, which changes other lines.
    Accepted: longer reasons. The tests compare whole reasons in both languages, so a change of
    wording changes them too; putting back any of the old sentences fails a test.
22. **What a test showed is written with its conditions (2026-11-04, issue #11).** The verification
    page said "The tool judges correctly" and "The only undecidable case is ...", and the
    confidence of the string heuristic said "verified". What had been shown is narrower: in five
    images, four ways of running and the builds tried (Brotli 1.2.0 and 1.2.1 with gcc 13 on
    x86_64, official Node.js binaries, PyPI wheels), every expected verdict matched.
    1. **The conditions are the subject.** `docs/verification.md` opens with what the tests show
       and what they do not (how often copies are missed or misjudged on real hosts was not
       measured; other builds, distributions and architectures were not tried), and says when each
       section was run and with which data. Fig. 02 calls exit status 1 "the intended result".
    2. **The tool's output follows.** The `confidence` of `LIKELY_*` lines (JSON only) names the
       builds tried instead of saying "verified", and so does `docs/json-schema.md`. A unit test
       keeps "verified" out of the message catalog.
    3. **Not changed:** the 0.1.0 entry of the CHANGELOG ("verified on Brotli 1.2.0/1.2.1 builds,
       official Node.js binaries and PyPI wheels") stays as released; it names the builds. The
       integration tests were not run again for this: the table keeps the images and data of
       2026-10-27, and the page says that CI checks the same expected verdicts on every push.
23. **A link to a program of another name is named in the report, and judged only by what its
    file carries (2026-11-04, issue #19).** `bcc_candidates` does not take a `node` (or `bun`,
    `curl`, `envoy`, a server, a browser) whose link resolves to a file of another name: a
    multi-call shim (`node -> mise`) would answer `--version` for itself (10.12). It dropped such a
    link silently, so a runtime under another name (`node -> runtime`) left no trace, not even
    under "Not scanned" (10.18.7).
    1. **What is kept.** Such a link is still not a candidate: it is not on the list of programs to
       run, and no version is read for it by running it, from a header or from its path. (The
       header next to a `/usr/bin/mise` would be `/usr/include/node/node_version.h`, there on a host
       with the Node.js headers: reading it would take mise for that Node.js.)
    2. **What the file carries decides, not what it is.** This CVE does not need a shim told from a
       runtime; it needs to know whether the file holds or loads the C decoder. The link's file is
       looked at as `--deep` looks at an ELF file: one that loads libbrotlidec is judged by that
       library (and by its own copy, if any), one with decoder markers by its strings. The finding
       is under the check that found the link, with the file's own name as the component (it is not
       called `node`) and the link in the reason. A file with neither is information ("not judged
       as node: that file carries no Brotli decoder and does not load libbrotlidec"). When that
       could not be told - the file not read to its end, or its libraries not followed - the link is
       listed as not scanned, the unread file first. A second link to a file already judged points
       to its lines.
    3. **Measured on the developer's workstation (Ubuntu 24.04).** Three such links:
       `~/.local/share/mise/shims/node -> ~/.local/bin/mise` (164 MB, Rust: no decoder markers, one
       copy of the Brotli dictionary - a Rust decoder, outside this CVE), and `/snap/bin/firefox`
       and `/snap/bin/chromium -> /usr/lib/snapd/snapd` (35 MB, Go: neither). The official Node.js
       26.4.0 next to it carries markers. Reading them took 1.2 s for mise and 0.25 s for snapd (once
       per link). Run at the same time with `--no-exec`, this branch and `main` differed only in the
       three information lines.
    4. **Every caller.** The filter is shared, so C04, C05, C08, C10, C11 and C13 report such links;
       on Ubuntu with snaps, `firefox` and `chromium` in `/snap/bin` are links to snapd. A link is
       named once, by its directory's real path (`/bin/x` and `/usr/bin/x` on a merged `/usr` are
       one). `bcc_candidates` now runs in the calling shell and fills `BCC_LIST`: in a pipe, it had
       nowhere to keep the links.
    5. **Not changed.** Scripts of any name are dropped without a word, as before: a script holds no
       decoder, and the runtimes that the script shims of asdf or nodenv start are found where they
       are installed, under the search roots (the index takes any executable named `node` there).
    Rejected: running the file with `--version` (the regression of 10.12, `mise --version` read as
    a node), and listing every such link as not scanned without looking at it (a shim would then
    read as a gap in what was looked at).
24. **Stopped containers and images are counted and listed as not scanned; the help says what
    `--deep` and `--containers` look at (2026-11-05, issue #8).** C14 listed the running containers
    (`ps` without `-a`) and counted the images, and neither went to "Not scanned": an entry came only
    from running containers not looked inside, so with no container running `--containers` left no
    C14 entry at all, and a report could read as if every container had been looked at. The help
    said that `--deep` searches "all ELF files under --roots" and that `--containers` lists
    "containers and images".
    1. **Counted, never looked inside.** The stopped containers are the IDs of
       `ps -a --format '{{.ID}}'` that `ps` did not list (the same template, so the same ID length;
       two calls, so a container started in between counts as stopped, and was not looked inside
       either way). The images are the distinct IDs of `images -q`, as before. Both calls stay on the
       context that was checked (10.20.4). Each count above 0 is one "Not scanned" entry
       (`C14 (stopped containers)`, `C14 (images)`), on every connection, with or without
       `--inspect-containers`, and also when no container runs. A count of 0 gives no entry: nothing
       of that kind was left out.
    2. **A count that could not be taken is not 0.** A failing `images -q` used to give "0 images".
       Now a failed `ps -a` or `images` shows `?` in the inventory line, and its entry names the call
       that failed.
    3. **Words.** The entries for running containers now say "running containers", so that they
       read apart from the stopped ones. The help gives `--deep`'s selection as the code has it
       (executable or named `*.so`, `*.so.*`, `*.node`; ELF; below `BCC_MAX_ELF_MB`, which is passed
       into the help text so that the number cannot drift) and "not the whole disk"; `--containers`
       lists the running containers and counts the stopped ones and the images, reading nothing
       inside; `--inspect-containers` never runs inside stopped containers or images. The README
       tables and the limitations follow (the README part of #8 was done in #13).
    4. **Measured on the development host (docker 29.9, 2026-11-05).** Docker Desktop's context:
       0 running, 0 stopped, 11 images; `/var/run/docker.sock`: 0 running, 45 stopped (all
       `exited`), 33 images, as `docker ps -a` and `docker images -q | sort -u` give them. The
       integration run now also runs a container of the image to its end and expects both entries,
       and no finding from that container (the numbers depend on the runner, so only the entries are
       checked).
    Rejected: naming each stopped container (a CI host can hold hundreds, and the number is what
    tells that the list is not all of them); looking inside stopped containers or images (recorded
    in the triage as an idea, not part of this issue: `docker create` and copying out, reading the
    layers, or an image scanner where the images are built); one call with a state field (it needs
    each engine's state names and its support of the field; the difference of two lists of IDs
    needs neither).
25. **A FIXED line says where its version came from, and one read from a file what its strings
    showed and what they do not; its next step is for that line (2026-11-06, issue #9).** Every
    FIXED reason read "At or above the fixed version X." whether the version came from the
    distributor's package, from running the program, or from a directory name confirmed by strings;
    where it came from was in the JSON `evidence` only (for C06 not even there). The next step of a
    FIXED line was empty, except C01's ("No update needed. ..."), C14's ("rebuild the image") and
    that of a flatpak browser ("flatpak update"); the last two contradicted the status.
    1. **The basis is a phrase given where the version is read.** `bcc_judge` takes a fifth
       argument, BASIS (a `b_*` message), and a FIXED reason is "At or above the fixed version X
       (BASIS)." Three kinds: a package's record (C01 and C14 the distribution package; C12
       `snap list`, `flatpak list`; C13 dpkg's record of a browser's package), a program's output
       (`NAME --version`, also inside a container), and a file (the directory name,
       `node_version.h`, package metadata, the conda record, a library's file name,
       `application.ini`). A unit test checks that every `bcc_judge` call in `lib/` passes one. The
       per-path record of 10.19 (`BCC_DISK_JUDGED`, `bcc_note_disk`) was looked at first: it holds
       which line judged a file (ID, component, status) and is filled when the finding is added,
       after its reason is written, so it cannot tell where a version came from. The phrase is made
       where that is known (the `method` of C04, C05 and C13; each check's own source).
    2. **A version from a file says what its strings showed and what they do not,** as a
       `LIKELY_FIXED` line does: "Found: the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH)
       among the decoder strings of this file. Not determined: whether all decoder code in the file
       is fixed (...)". `bcc_crosscheck_fixed` rebuilds the reason from `bcc_judge`'s (`BCC_J_BASE`)
       with the files confirmed so far (`BCC_J_CONFIRMED`): two modules of one PyPI package give one
       sentence of each kind, and when a later file disagrees, the UNKNOWN keeps what was found and
       drops what only a FIXED leaves open. When the strings are in another file than the line's
       (C06's extension module and conda library, Firefox's `libxul.so`), the sentence names it.
       The "Not determined" sentence is shared with `LIKELY_FIXED` (`r_fixed_unseen`, split out of
       `r_heur_fixed`; that line reads as before). An UNKNOWN made from a FIXED by the cross-check
       keeps the basis, so "the version may be wrong" and "the version above is the only basis" now
       say which version.
    3. **The next step of FIXED is for that line only** (requester's decision, 2026-11-06): "No
       update needed for this line (other lines and the ranges not scanned are separate)."
       `bcc_judge` sets it; C01 adds its restart sentence after it; C14 and flatpak give it instead
       of "rebuild the image" and "flatpak update" (a VULNERABLE line inside a container still says
       to rebuild).
    4. **Rows the data cannot decide say why** (a note of wave 1, in a comment on #9).
       `r_data_unknown` said "(see evidence)", which the text report does not show. It now gives the
       ground both `unknown` rows share (Node.js 10 and earlier, Envoy 1.17 and earlier): some
       versions or builds of the line have no Brotli, and the data does not tell which. The same
       treatment `derived_eol` and `derived_bundled` got in #2.
    Rejected: the data row's note in the reason (English only, and long); one message per component
    for `unknown` (it would copy facts of the data file into the catalog); naming the line's own
    file again (its path is on the line); the basis on VULNERABLE lines too (not asked for; such a
    line needs an update whatever the version came from); a separate field in JSON (`reason`
    carries the basis in both outputs; a new field changes the schema).
