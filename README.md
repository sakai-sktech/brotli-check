# brotli-cve-check

A read-only shell script that lists, on one Ubuntu or Debian host, the copies of the
Google Brotli **decoder** that may be affected by **CVE-2026-111497**
(out-of-bounds write in `c/dec/decode.c`, Brotli 1.0.3 to 1.2.0; fixed in 1.0.10, 1.1.1, 1.2.1).

Keywords: CVE-2026-111497, GHSA-9v8h-qqgm-4m35, Brotli decoder, "HTTP2Shell", "Node2Shell".
(Despite the nickname, this is not an HTTP/2 flaw.)

日本語: [README.ja.md](README.ja.md) / 医療機関・中小企業の方へ: [docs/for-clinics.ja.md](docs/for-clinics.ja.md)

## What it does, and what it does not

It **does**:

- check the distribution packages (`libbrotli1`, `python3-brotli`, ...) against the
  distributor's fixed versions;
- find the copies that updating the OS package does **not** fix: Node.js, Bun, PyPI
  `Brotli` / `brotlicffi`, conda, Envoy, curl builds, browsers, snap/flatpak apps,
  `libbrotlidec` files outside the package manager, and (with `--deep`) any ELF file that
  carries its own decoder;
- find processes that keep running the old code after an update (restart needed);
- give exposure hints (HTTP clients that decode Brotli automatically, listening sockets).

It **does not**:

- check whether the host was compromised. Updating does not remove traces of an intrusion
  that happened before the update;
- scan other hosts, use the network, install, update, restart or change anything;
- generate, download or contain attack data;
- ever say "safe". The best result is "no known vulnerable component was found in the
  scanned ranges", followed by the list of ranges that were not scanned.

## Quick start

Do not pipe it into a shell. Download, verify, read, then run:

```sh
VERSION=v0.1.0
BASE=https://github.com/sakai-sktech/brotli-check/releases/download/$VERSION
curl -fsSLO "$BASE/brotli-cve-check"
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS          # must print "brotli-cve-check: OK"
less brotli-cve-check            # read what you are about to run
bash brotli-cve-check            # as an ordinary user
sudo bash brotli-cve-check       # as root: also other users' processes and homes
```

Useful options:

```sh
bash brotli-cve-check --lang ja                     # Japanese output
bash brotli-cve-check --json --output report.json   # machine-readable (docs/json-schema.md)
bash brotli-cve-check --no-exec                     # never run any program it finds
sudo bash brotli-cve-check --deep --containers      # slower, wider
bash brotli-cve-check --help
```

Requirements: bash 4.2 or later, coreutils, findutils, grep, sed, awk. binutils
(`readelf`) is optional; without it some linkage checks are less precise and the report says so.
No Python, no network.

## Reading the result

Each finding is one line:

```
[STATUS] ID | component | where | version | reason | next step
```

| Status | Meaning | Next step |
|---|---|---|
| `VULNERABLE` | A known affected version | Update it (the line says to what) |
| `RESTART_REQUIRED` | The fix is on disk, but a process still runs the old code | Restart that process or service |
| `NO_FIX_AVAILABLE` | The distributor has not released a fix | Wait; meanwhile update the products that bundle their own copy |
| `VENDORED_COPY` | Carries its own decoder; the version could not be determined | Ask the vendor which Brotli it bundles |
| `LIKELY_VULNERABLE` / `LIKELY_FIXED` | Judged from the decoder's strings (verified heuristic, see below) | Confirm with the vendor |
| `UNKNOWN` | Could not be judged; the reason is always given | Read the reason |
| `EXPOSURE` | A path by which attacker data could reach a decoder; not a vulnerability by itself | Prioritize the updates it points to |
| `NOT_APPLICABLE` | No decoder in that file (for example a compression-only module) | None for that file |
| `FIXED` | Contains the fix | None |

The report ends with four lines for non-specialists ("needs update", "needs restart",
"needs human review", "not scanned") and the intrusion disclaimer.

Exit status: `0` nothing needing action was found in the scanned ranges (not proof of
safety), `1` `VULNERABLE` or `RESTART_REQUIRED`, `2` something needs review
(`NO_FIX_AVAILABLE`, `VENDORED_COPY`, `LIKELY_*`, `UNKNOWN`), `3` error of the tool itself.

## How versions are judged

Version numbers are not trusted blindly:

- Debian and Ubuntu fix packages without changing the upstream version; the **source package
  version** (`1.1.0-2+deb13u1`) is compared with the distributor's fixed version.
- Fixed Node.js 22.23.4 still reports `process.versions.brotli` = `"1.1.0"`; that value is
  never used. Node.js is judged by its own version.
- `python3-brotli` from the distribution is compiled statically and judged separately from
  `libbrotli1`.
- For a bundled copy whose version is unknown, the decoder's error-name strings are used:
  the fix added `_ERROR_FORMAT_BLOCK_SWITCH` (error -17). This was verified on builds of
  1.2.0 and 1.2.1 (shared, static, LTO, stripped or not), on official Node.js binaries and on
  PyPI wheels ([tests/fixtures/c09/README.md](tests/fixtures/c09/README.md)). When the linker
  removed the error-name table, the copy is reported as `VENDORED_COPY`, never as fixed.
- The tool runs a program it found only to ask for its version, with an empty environment and
  a timeout, and only when nobody but root (or you) could have replaced it. Otherwise, and with
  `--no-exec`, versions come from files (headers, package records, paths, strings).

## Limitations

See [docs/limitations.md](docs/limitations.md). In short: copies inside archives and
images that are not running can be missed; without root, other users' processes and homes are
not visible; the advisory data is a snapshot.

## Advisory data and its date

All known versions live in [data/advisories.tsv](data/advisories.tsv), with the primary
source URL and the retrieval date on every row. The report shows the data's snapshot date and
warns when it is 30 days old or more. Newer data can be passed with `--data FILE`.
Snapshot: **2026-10-26**. Ubuntu, Red Hat and others had not released fixes at that date.

Note: Red Hat advisories RHSA-2026:2042 / 2227 / 2389 are about a different issue
(CVE-2025-6176). Updating `pip` or `certifi` is unrelated to this CVE (CPython itself does
not contain Brotli).

## Development

```sh
make lint          # shellcheck, zero warnings
make test          # bats unit tests
make dist          # dist/brotli-cve-check (single file) and dist/SHA256SUMS
make integration   # Ubuntu 22.04/24.04/26.04 and Debian 12/13 containers (needs docker)
```

Sample output: [docs/sample-output.md](docs/sample-output.md). Design notes: [docs/design.md](docs/design.md) (Japanese). Contributing:
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues in this tool: [SECURITY.md](SECURITY.md).

## Disclaimer

Provided "as is", without warranty (see [LICENSE](LICENSE)). A result is only as good as
the ranges scanned and the data's date; it does not prove that a host is safe.

## License

MIT. Copyright (c) 2026 株式会社ジェイ・メディック.
