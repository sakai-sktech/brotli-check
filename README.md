# brotli-cve-check

A shell script that finds, on one Ubuntu or Debian host, the copies of the Google Brotli
**decoder** that may be affected by **CVE-2026-111497** (out-of-bounds write in
`c/dec/decode.c`), and lists, on the evidence of versions and strings, the ones that need an
update or a check.

Affected are Brotli 1.0.3 to 1.0.9, 1.1.0 and 1.2.0 (the advisory's range 1.0.3 to 1.2.0,
minus the fixed releases 1.0.10 and 1.1.1). The fixed releases are 1.0.10, 1.1.1 and 1.2.1.
Debian and Ubuntu take in fixes without changing the version number, so distribution packages
are judged against the distributor's fixed versions.

Keywords: CVE-2026-111497, GHSA-9v8h-qqgm-4m35, Brotli decoder, "HTTP2Shell", "Node2Shell".
(Despite the nickname, this is not an HTTP/2 flaw.)

What the flaw is, which paths can carry attacker data to a decoder, and how to judge whether it
concerns you: [technical note by J-MEDIC Co., Ltd. (in Japanese)](https://www.jmedic.co.jp/pubdoc/http2shell_report_20261027.html). This tool is the
next step: it inventories one host.

日本語: [README.ja.md](README.ja.md) / 医療機関・中小企業の方へ: [docs/for-clinics.ja.md](docs/for-clinics.ja.md)
(Every document in docs/ has a Japanese version next to it as `*.ja.md`.)

## What it tells you, and what it does not

**It tells you**

- where on the host copies of the Brotli decoder are, and whether each is a fixed version. Not
  only distribution packages (`libbrotli1`, `python3-brotli`, ...) but also the bundled copies
  that updating the OS does **not** fix (Node.js, Bun, PyPI `Brotli` / `brotlicffi`, conda,
  Envoy, browsers, snap/flatpak apps, `libbrotlidec` files outside the package manager, ...);
- which processes keep using deleted old files after an update;
- what it could not judge, and why; and what it did not look at (always listed as "Not scanned").

**It does not tell you (and does not judge)**

- whether attacker-controlled data can reach a decoder it found. Data can come in as a
  compressed request, as a response the host fetches and decodes automatically (`fetch()`, URL
  previews, crawlers, AI agents), or through a direct call to a decompression API; which of these
  apply to your services is for you to judge. An `EXPOSURE` finding is a hint, not a
  confirmation that data gets there;
- whether an attack would succeed, or whether the host was compromised. Updating does not remove
  traces of an intrusion that happened before the update;
- whether the whole host is safe. The best result is "no known vulnerable component was found
  in the scanned ranges", always with the ranges that were not scanned.

The tool itself installs, updates, stops and reconfigures nothing. It writes only to standard
output and to a new file named with `--output`. It does not generate, download or contain attack
data. A program you allow it to run to read its version, however, runs with your rights (see
"[Running programs to read versions](#running-programs-to-read-versions)").

## Who it is for, and where it runs

It is run by whoever administers the server being checked. If you work at a clinic or a small
business and receive the results, read [docs/for-clinics.ja.md](docs/for-clinics.ja.md) (in Japanese).

Run it on each server you want to check, on that server. It does not reach into other hosts.
Docker is not needed (only to look at containers).

| Environment | Notes |
|---|---|
| Ubuntu and Debian hosts | The main target. Distribution packages are judged for the releases in the bundled advisory data |
| Where it was checked | x86_64 containers of Ubuntu 22.04, 24.04, 26.04 and Debian 12, 13 ([docs/verification.md](docs/verification.md)), and the developer's workstation (Ubuntu 24.04). Ubuntu 26.10 is in the data but not in the integration tests |
| Ubuntu and Debian derivatives (Linux Mint, ...) | When os-release names the base release in `UBUNTU_CODENAME` / `DEBIAN_CODENAME`, judged as that release. Not in the integration tests |
| Other Linux (RHEL and the like) | Not tried. Distribution packages are not judged |
| Windows, macOS | Not supported |
| Inside WSL, a virtual machine or a container | Only what is visible inside it. Not a result for the host outside |

## At a glance

<table>
<tr>
<td width="50%" valign="top"><a href="docs/zukai/01_check-method_en.pdf"><img src="docs/zukai/01_check-method_en.png" alt="Fig. 01 What we checked, and how: the vulnerability, where copies of the Brotli decoder hide on a host (OS layer and bundled layer), and how brotli-cve-check checks each of them"></a></td>
<td width="50%" valign="top"><a href="docs/zukai/02_results-reading_en.pdf"><img src="docs/zukai/02_results-reading_en.png" alt="Fig. 02 Results on 5 OSes and how to read them: the OS copies on Ubuntu 22.04/24.04/26.04 and Debian 12/13 are fixed (update with apt and restart), bundled copies such as Node.js and PyPI Brotli have to be updated product by product"></a></td>
</tr>
<tr>
<td><b>Fig. 01 What we checked, and how</b><br>Updating the OS fixes only the OS's copy; bundled copies are found and told apart by version and by strings.<br><a href="docs/zukai/01_check-method_en.pdf">PDF</a> · <a href="docs/zukai/01_check-method_en.html">HTML</a></td>
<td><b>Fig. 02 Results on 5 OSes, and how to read them</b><br>On every OS the OS's own copy is fixed by apt; bundled copies stay until each product is updated (as of 2026-10-27).<br><a href="docs/zukai/02_results-reading_en.pdf">PDF</a> · <a href="docs/zukai/02_results-reading_en.html">HTML</a></td>
</tr>
</table>

Japanese versions: [Fig. 01](docs/zukai/01_check-method_ja.pdf), [Fig. 02](docs/zukai/02_results-reading_ja.pdf).

## First run

### Getting it

v0.1.0 has not been released yet (planned in [issue #4](https://github.com/sakai-sktech/brotli-check/issues/4)).
For now, clone the repository and run `bin/brotli-cve-check` inside it. `bin/brotli-cve-check`
reads `lib/` and `data/` from the same tree, so that file alone does not run. Do not pipe
anything into a shell.

```sh
git clone https://github.com/sakai-sktech/brotli-check.git &&
cd brotli-check &&
git log -1 --format='%H %cd'     # note which commit you checked with
```

Read what is in `bin/`, `lib/` and `data/` before running it. The commands below are run inside
the cloned tree.

### First, as an ordinary user, starting nothing

```sh
bash bin/brotli-cve-check --no-exec
```

With `--no-exec`, programs it finds (node and the like) are not started to read their versions;
versions come from files (package records, headers, paths, strings). The system tools it checks
with (dpkg-query, readelf, ...) do run. When it is done, look at the summary at the end and at
"Not scanned" (see "[Reading the result](#reading-the-result)"). `--lang ja` gives Japanese output.

### Then, if needed, look further

**Run as root** to see other users' homes and processes as well. The cloned tree can be changed
by you, an ordinary user, so running it with `sudo` as it is would have root run code you can
write, and the report starts with a warning about the advisory data. To run as root, build the
single-file version and put it where only root can write:

```sh
make dist &&
sudo install -D -m 0644 dist/brotli-cve-check /root/brotli-cve-check/brotli-cve-check &&
sudo bash /root/brotli-cve-check/brotli-cve-check --no-exec > report.txt
```

Save root's report through your own shell (as root, `--output` only writes into root-owned
directories).

**Read exact versions.** Run it at a terminal without `--no-exec`, and it lists the programs it
wants to run to read their versions, each with who could change it. You choose: all, none, or
by number. `--yes` agrees to all of them without showing the list (see
"[Running programs to read versions](#running-programs-to-read-versions)").

**Look in more places** with `--deep`, `--projects`, `--exposure`, `--containers` and others
(see "[How far it looks](#how-far-it-looks)").

```sh
bash bin/brotli-cve-check --json --output report.json   # machine-readable (docs/json-schema.md)
bash bin/brotli-cve-check --help                        # all options
```

Requirements: bash 4.2 or later, coreutils, findutils, grep, sed, awk. binutils (`readelf`) is
optional; without it some linkage checks are less precise and the report says so. git and make
to get it and build the single file. docker or podman for `--containers`, ss (iproute2) for
`--exposure`. No Python. The tool itself does not connect to the network (docker or podman used
by `--containers`, and programs you allow it to run, are another matter).

## Reading the result

First comes "Programs run to read their versions" (what ran, what it printed, what did not
run), then the findings per check, information, "Not scanned", and the summary at the end.
Each finding is one line:

```
[STATUS] ID | component | where | version | reason | next step
```

| Status | Meaning | Next step |
|---|---|---|
| `VULNERABLE` | Older than the fixed version in the advisory data, or a version of a line that gets no fixed release | Update it (the line says to what) |
| `RESTART_REQUIRED` | A process keeps using a deleted Brotli-related file (libbrotlidec, `_brotli*.so`, a node or bun executable). Whether the file now on disk is fixed is told by the other lines of the same report | If the disk has the fixed version, restart that process or service; if not, update first |
| `NO_FIX_AVAILABLE` | As of the advisory data's date, the distributor had not released a fix | Look at the vendor's latest information; meanwhile update the products that bundle their own copy |
| `VENDORED_COPY` | Carries its own decoder; neither its version nor whether it is fixed could be determined | Ask the vendor which Brotli it bundles |
| `LIKELY_VULNERABLE` / `LIKELY_FIXED` | Judged from the decoder's strings; the reason says what was found and what was not (see "[What a verdict rests on](#what-a-verdict-rests-on)") | Confirm with the vendor |
| `UNKNOWN` | Could not be judged; the reason is always given | Read the reason |
| `EXPOSURE` | A hint of a path by which attacker data could reach a decoder (a related package, a setting, a listening socket). Whether an application uses it, or whether it can be reached from outside, is not checked. Not a vulnerability by itself | Prioritize the updates it points to |
| `NOT_APPLICABLE` | The file has no decoder markers and does not load libbrotlidec, and it belongs to a package or is a Go program that does not build in the C Brotli. A build of your own that merely shows no markers is `UNKNOWN` | None for that file |
| `FIXED` | The version obtained meets the fixed-version condition of the advisory data. How strong that is depends on where the version came from (see "[What a verdict rests on](#what-a-verdict-rests-on)") | No update needed for this line |

The summary at the end is four lines for non-specialists and the intrusion disclaimer:

```
Needs update: 2
Needs restart: 0
Needs human review: 0
Not scanned: C09 --deep, C07 --projects, C14 --containers, C15 --exposure
This tool does not check for intrusion. Updating to a fixed version does not remove traces of an intrusion that happened before the update.
```

Run with no options, `--deep`, `--projects`, `--containers` and `--exposure` are always under
"Not scanned". That line stays even when there are no findings.

Exit status:

| Value | Meaning |
|---|---|
| `0` | No finding for `1` or `2`. Ranges not scanned are not counted: it does not mean everything was looked at, and it is not proof of safety |
| `1` | `VULNERABLE` or `RESTART_REQUIRED` present |
| `2` | None of the above, but something needs human review (`NO_FIX_AVAILABLE`, `VENDORED_COPY`, `LIKELY_*`, `UNKNOWN`) |
| `3` | Error of the tool itself (bad option, unreadable data file, ...) |

For automation, read not only the exit status but also `skipped` (not scanned) and `options`
(the options given) in the JSON ([docs/json-schema.md](docs/json-schema.md)).

## How far it looks

| Option | Adds | Does not look at |
|---|---|---|
| default | Distribution packages, fixed places (the system's Python and library directories, ...), Python and conda, libraries found by name, Node.js, Bun, Envoy, browsers, snap/flatpak. Default search roots: `/opt,/usr/local,/srv,/var/www,/home,/root` | Listening sockets, node_modules, containers, bundled copies not found by name |
| `--roots DIR,...` | Replaces the search roots | Does not add to them. The fixed places are looked at regardless of `--roots` |
| `--deep` | Searches the ELF files under the roots for bundled decoders by their strings | Static copies without markers, the inside of archives, files of 512 MiB or more, files with neither an executable bit nor a `.so` / `.node` name. Not the whole disk |
| `--projects` | Related packages in node_modules (hints) | Whether an application uses them |
| `--exposure` | Non-loopback listening sockets of node, python, bun and envoy (hints) | Whether they can be reached from outside (firewall, routing) |
| `--containers` | The list of running containers and the number of images | The inside of containers, stopped containers, the inside of images |
| `--inspect-containers` | Packages, Node.js and PyPI inside running containers | Stopped containers, the inside of images, apk packages (Alpine and the like) |
| `--no-exec` | Starts none of the programs it finds | More `UNKNOWN` where no version can be read. The system tools it checks with still run |
| `sudo` | Other users' homes and processes | Not everything is then seen. Programs you allow to run run as root |

There are also `--exclude` (places to leave out), `--include-remote` (also search network file
systems such as NFS), `--envoy-config FILE`, `--timeout SEC` and `--data FILE` (`--help`). What
can be missed is detailed in [docs/limitations.md](docs/limitations.md).

## Running programs to read versions

To read exact versions, the tool wants to run some of the programs it found, each with one
argument such as `--version`. At a terminal it first shows you the list — each program, and
who besides root or you could change it, a directory above it, or a library it loads — and
you choose: all, none, or by number. That list is the point: it is what you are deciding on.
Without a terminal, pass `--yes` or `--no-exec`.

`--yes` means "run everything on that list, without showing it to me first". It exists for
runs with no one at a terminal: a script, cron, a container. Use it knowing what you agree to:

- **A program runs with your rights.** With `sudo`, that means as root, with full control of
  the host. If a program on the list belongs to another user, or sits where another user can
  write, then that user decides what runs as root. The list says when this is the case
  ("belongs to alice", "can be written by anyone"); `--yes` agrees without reading it.
- **What a program does is not something this tool can stop.** It is run from `/`, with an
  empty environment, stdin closed, a time limit and a cap on its output, but nothing keeps it
  from writing files or using the network.
- **The list covers what can be seen before running**: the file, the directories above it,
  the libraries it loads. What a program opens once it is running (plugins, configuration
  files) is not on it.
- **A version that a program reports is only as trustworthy as the program.** The report's
  first section, "Programs run to read their versions", shows what ran, what it printed, and
  the facts. Read the findings with it: a FIXED that came from running a program others can
  change says what that program printed, nothing more.

If you are not sure, run once at a terminal and look at the list. For unattended runs where
nobody will read that section, `--no-exec` is the plain choice: nothing found is run, versions
come from files (headers, package records, paths, strings), and the report says what was not
run.

Even with `--no-exec`, the system tools it checks with (dpkg-query, readelf, ss, snap, flatpak,
and docker or podman with `--containers`) run.

**Where containers are looked at.** `--containers` and `--inspect-containers` use docker or
podman with their current connection settings. If `DOCKER_HOST` or the docker context points at
another host, the tool looks at that host's containers, and with `--inspect-containers` runs
commands inside them. When you mean this host's containers, make sure the connection is this
host's socket before running.

## What a verdict rests on

Version numbers are not trusted blindly:

- Debian and Ubuntu fix packages without changing the upstream version; the **source package
  version** (`1.1.0-2+deb13u1`) is compared with the distributor's fixed version.
- Fixed Node.js 22.23.4 still reports `process.versions.brotli` = `"1.1.0"`; that value is
  never used. Node.js is judged by its own version.
- `python3-brotli` from the distribution is compiled statically and judged separately from
  `libbrotli1`.
- A pre-release of exactly the fixed version (`1.4.4-rc.1`, Firefox `150.0a1`, ...) is not taken
  for the release; it is `UNKNOWN`.

A `FIXED` rests on one of three kinds of evidence:

| Evidence | Example | What it says |
|---|---|---|
| Distribution package version | `libbrotli1` in C01 | At or above the version the distributor named as fixed |
| A program's output | `node --version` | The program answered so (see "[Running programs to read versions](#running-programs-to-read-versions)") |
| A file plus strings | A version from a path or package metadata, and the strings of the decoder in the file | The version read from files is at or above the fixed one, and the decoder's strings show the fix too |

A version read from a file (a directory name, a header, package metadata) gives `FIXED` only
when the decoder's strings confirm the fix. In the text report today, the reason reads "At or
above the fixed version X." whatever the evidence; where the version came from is in the JSON
`evidence`.

**The string heuristic.** For a bundled copy whose version is unknown, the decoder's error-name
strings are used: the fix added `_ERROR_FORMAT_BLOCK_SWITCH` (error -17). This was checked on
the builds tried (Brotli 1.2.0 and 1.2.1, shared, static, LTO, stripped or not, built with gcc 13
on Ubuntu 24.04, x86_64), on official Node.js binaries and on PyPI wheels
([tests/fixtures/c09/README.md](tests/fixtures/c09/README.md)). Builds of 1.0.x and 1.1.x, other
compilers and other architectures were not tried. When the linker removed the error-name table,
the copy is reported as `VENDORED_COPY`, never as fixed. Some cases cannot be told apart, such as
two decoders in one file sharing a dictionary, so a heuristic line says what was found and what
was not.

## After reading the result

1. Look at where the findings that need an update or a review are, and at their reasons
   (the evidence).
2. Match them with the products and environments you actually use, and look at the vendors'
   latest fix information (fixes released after the advisory data's date are unknown to the tool).
3. Plan and carry out the updates, service restarts and container rebuilds. OS packages are
   fixed by apt; bundled copies stay until each product is updated, and containers until their
   images are rebuilt and replaced.
4. Check again over the same ranges, and see that no update, `UNKNOWN`, heuristic line or
   "Not scanned" range is left.

Check for intrusion separately; this tool does not.

## Limitations and advisory data

See [docs/limitations.md](docs/limitations.md). In short: copies inside archives and images that
are not running can be missed; without root, other users' processes and homes are not visible;
the advisory data is a snapshot.

All known versions live in [data/advisories.tsv](data/advisories.tsv), with the primary
source URL and the retrieval date on every row. The report shows the data's snapshot date and
warns when it is 30 days old or more; less than 30 days old is not necessarily up to date.
Newer data can be passed with `--data FILE`. Snapshot: **2026-10-27**: every row's primary source
was checked again on that date. Ubuntu fixed 22.04, 24.04, 26.04 and 26.10 on 2026-10-26
([USN-8956-1](https://ubuntu.com/security/notices/USN-8956-1)); Debian 12, 13 and unstable are
fixed, and testing (forky) was still waiting for the fix to migrate.

Note: Red Hat advisories RHSA-2026:2042 / 2227 / 2389 are about a different issue
(CVE-2025-6176). Updating `pip` or `certifi` is unrelated to this CVE (CPython itself does
not contain Brotli).

### Known problems

Problems known in the current version. Each is removed from this list once fixed.

- Python and conda: with no extension module or shared library present, the metadata version alone gives `FIXED` ([#1](https://github.com/sakai-sktech/brotli-check/issues/1))
- Versions before an advisory's affected range (Bun before 1.0.21, Brotli 1.0.2 and earlier, 0.x) are also `VULNERABLE` ([#2](https://github.com/sakai-sktech/brotli-check/issues/2))
- A file without markers is `NOT_APPLICABLE` whatever package it belongs to ([#3](https://github.com/sakai-sktech/brotli-check/issues/3))
- A `RESTART_REQUIRED` line advises only a restart even when the disk is still unfixed ([#5](https://github.com/sakai-sktech/brotli-check/issues/5))
- The container connection is neither checked nor shown in the report ([#6](https://github.com/sakai-sktech/brotli-check/issues/6))
- `EXPOSURE` reasons say "decodes ... automatically" when a package is merely installed ([#7](https://github.com/sakai-sktech/brotli-check/issues/7))
- The text report does not show which kind of evidence a `FIXED` rests on ([#9](https://github.com/sakai-sktech/brotli-check/issues/9))
- The exit status is `0` even when part of the check could not be done, for example when dpkg-query fails ([#10](https://github.com/sakai-sktech/brotli-check/issues/10))

All: [issues](https://github.com/sakai-sktech/brotli-check/issues)

## What was checked, development, contact

This tool is published on the basis of what the developer could check on their own workstation
and on containers that can be built and thrown away.

- **On the developer's workstation** (Ubuntu 24.04, ordinary user) it found copies that updating
  the OS does not fix (Node.js bundled with VS Code Server and a GitHub Actions self-hosted
  runner, `libbrotlidec` inside Pillow wheels, ...).
- **Integration tests**: x86_64 containers of Ubuntu 22.04, 24.04, 26.04 and Debian 12, 13, with
  unfixed and fixed copies put in on purpose; every expected verdict matched, as root and as an
  ordinary user, with `--no-exec` and with `--yes`.
- **172 unit tests** and ShellCheck with zero warnings. The string heuristic was checked on the
  builds listed under "What a verdict rests on".
- **Not checked**: how often it misses copies or misjudges them on real hosts; architectures
  other than x86_64; RHEL and the like; integration tests on Ubuntu 26.10 and on derivatives.

Full results: [docs/verification.md](docs/verification.md). Sample output:
[docs/sample-output.md](docs/sample-output.md).

```sh
make lint          # shellcheck, zero warnings
make test          # bats unit tests
make dist          # dist/brotli-cve-check (single file) and dist/SHA256SUMS
make integration   # Ubuntu 22.04/24.04/26.04 and Debian 12/13 containers (needs docker)
```

Design notes: [docs/design.md](docs/design.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

Report bugs and errors in the advisory data as an [issue](https://github.com/sakai-sktech/brotli-check/issues)
(for the data, with the primary source URL; see CONTRIBUTING.md). Report security problems in
this tool itself not as a public issue but as described in [SECURITY.md](SECURITY.md).

## Disclaimer

Provided "as is", without warranty (see [LICENSE](LICENSE)). A result is only as good as
the ranges scanned and the data's date; it does not prove that a host is safe.

## License

MIT. Copyright (c) 2026 株式会社ジェイ・メディック.
