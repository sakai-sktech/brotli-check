# JSON output (`--json`)

日本語: [json-schema.ja.md](json-schema.ja.md)

One JSON object on one line, UTF-8. Fields are added in a backward-compatible way; a
removed or renamed field changes the major part of `tool_version`.

```jsonc
{
  "tool": "brotli-cve-check",
  "tool_version": "0.1.0",
  "cve": "CVE-2026-111497",

  "data_snapshot_date": "2026-10-27",   // "# snapshot:" line of the advisory data
  "data_age_days": 0,                   // days between the snapshot and today
  "data_stale": false,                  // true when data_age_days >= 30
  "data_source": "embedded",            // "embedded" or the path given with --data
  "data_writable_by_others": false,     // the --data file (or a directory on its path) can be
                                        // changed by users other than root (or you); warned about

  "host": {
    "os_id": "ubuntu",                  // /etc/os-release ID
    "os_version_id": "24.04",
    "os_codename": "noble",
    "os_pretty_name": "Ubuntu 24.04.5 LTS",
    "package_series": "ubuntu:noble",   // series used for package data ("" if unknown)
    "kernel": "6.8.0-48-generic",
    "uid": 0,
    "is_root": true
  },

  "options": {
    "deep": false, "projects": false, "containers": false, "inspect_containers": false,
    "exposure": false,
    "no_exec": false,                   // --no-exec: found programs were not run
    "yes": false,                       // --yes: the listed programs were run without asking
    "include_remote": false, "lang": "en"
  },

  "scanned_roots": ["/opt", "/usr/local", "/srv", "/var/www", "/home", "/root"],

  "execution": [                        // programs the checks asked to run, in the order listed
    { "path": "/usr/local/bin/bun", "argument": "--version", "check": "C05 bun",
      "ran": true, "exit_status": 0, "output": "1.4.4",            // output: at most 4096 chars
      "facts": ["as far as examined, only root can change it and what it loads"] },
    { "path": "/home/alice/.bun/bin/bun", "argument": "--version", "check": "C05 bun",
      "ran": false, "not_run_because": "not-chosen",               // or "no-exec"
      "facts": ["/home/alice/.bun/bin/bun belongs to alice"] }
  ],

  "skipped": [                          // ranges NOT scanned, always listed; see "skipped" below
    { "scope": "C09 --deep", "reason": "generic search of ELF files ... (use --deep)",
      "kind": "chosen" },               // left out by how the tool was run: not in exit_code
    { "scope": "C01", "reason": "dpkg-query failed (status 2): ...",
      "kind": "failed" }                // could not be scanned: exit_code 2 unless 1
  ],

  "findings": [
    {
      "id": "C04",                      // detection item C01..C15
      "status": "VULNERABLE",           // see "status" below
      "component": "node",
      "path": "/opt/node-v22.23.3-linux-x64/bin/node",
      "version": "22.23.3",             // "" when unknown
      "reason": "Below the fixed version 22.23.4.",
      "next_step": "Update to 22.23.4 or later.",
      "evidence": "version via exec; data: node 22; https://nodejs.org/... (2026-10-27)",
      "confidence": ""                  // set for LIKELY_* (string heuristic)
    }
  ],

  "info": [                             // context that is not a finding (no effect on counts)
    { "id": "C02", "text": "11 installed packages depend on libbrotli1; ..." }
  ],

  "summary": {
    "needs_update": 1,                  // VULNERABLE + LIKELY_VULNERABLE
    "needs_restart": 0,                 // RESTART_REQUIRED
    "needs_review": 2,                  // NO_FIX_AVAILABLE + VENDORED_COPY + UNKNOWN + LIKELY_FIXED
                                        // (findings only: a failed range is in "skipped")
    "by_status": { "VULNERABLE": 1, "FIXED": 3, "...": 0 }
  },

  "exit_code": 1,
  "disclaimer": "This tool does not check for intrusion. ..."
}
```

## status

| Value | Meaning |
|---|---|
| `VULNERABLE` | Known affected version; update needed |
| `FIXED` | The version obtained meets the fixed-version condition of the advisory data. `reason` says where the version came from: a package's record, a program's output, or a file whose decoder strings confirmed the fix (then `reason` also says what was found and what was not). `next_step` is for this line only: other lines and `skipped` are separate |
| `NO_FIX_AVAILABLE` | The distributor has not released a fix yet |
| `RESTART_REQUIRED` | A process keeps using a deleted Brotli-related file (libbrotlidec, `_brotli*.so`, a node or bun executable). Whether the file now at that path is fixed is not part of the status: `reason` gives what this report judged about it (or that it did not, or that there is no file, or that the process is in another mount namespace), and `next_step` follows from that: restart; update first; or check the version, then restart |
| `VENDORED_COPY` | Carries its own decoder; version must be checked by a person |
| `LIKELY_FIXED`, `LIKELY_VULNERABLE` | Judged by the string heuristic, checked on the builds tried; see `confidence` |
| `EXPOSURE` | A hint of a path by which attacker data could reach a decoder (not a vulnerability). `reason` says what was seen and what was not. No `EXPOSURE` is not proof that there is no path |
| `NOT_APPLICABLE` | No sign of a decoder in that file, backed by a distribution package whose sources were read, a Go program without `cbrotli`, or `curl -V` listing no brotli. Not proof of absence; `reason` says what it rests on |
| `UNKNOWN` | Could not be judged; `reason` says why |
| `SKIPPED` | Reserved; not-scanned ranges are reported in `skipped` |

## skipped

Every range not scanned is one entry: `scope` (a check, a path, or a name such as `root`),
`reason`, and `kind`:

| `kind` | Meaning | In `exit_code` |
|---|---|---|
| `chosen` | Left out by how the tool was run: an option not given (or given: `--exclude`, `--no-exec`), programs not chosen to run, not running as root (and what this user therefore could not read), network file systems and other kinds of file systems below the roots, what an option only counts (stopped containers, images), readelf not installed (what it leaves undecided is an `UNKNOWN` finding or a `failed` entry). Text report: "Not scanned", `[SKIPPED]` | Not counted |
| `failed` | The run set out to look at it and could not: a command failed, or a program the check needs is missing (dpkg, ss for `--exposure`, docker and podman for `--containers`); a time limit; a file not read to the end or over the size limit; a link not followed to the end; what root could not read; a place named with `--roots` or `--envoy-config` that is not there; a container not looked inside although `--inspect-containers` asked for it. Text report: "Could not be scanned", `[FAILED]` | `2`, unless something gives `1` |

A scope appears at most once for each kind. The text summary lists the scopes of each kind on a
line of its own ("Could not be scanned: none" when there is none).

## exit_code

| Value | Meaning |
|---|---|
| 0 | None of the statuses for 1 or 2 in the scanned ranges, and no `skipped` entry of kind `failed`. Entries of kind `chosen` are not counted: 0 does not mean everything was looked at (not proof of safety) |
| 1 | `VULNERABLE` or `RESTART_REQUIRED` present (whatever `skipped` holds) |
| 2 | None of the above, but `NO_FIX_AVAILABLE`, `VENDORED_COPY`, `LIKELY_*` or `UNKNOWN` present, or a `skipped` entry of kind `failed` (then `summary.needs_review` may be 0) |
| 3 | Error of the tool itself (bad option, unreadable data file, ...) |

For automation, read `skipped` and `options` along with `exit_code`. A program the check needs
that is missing is `failed`, so giving `--containers` to a host with neither docker nor podman
(or `--exposure` to one without ss) gives 2 every time.

## Notes

- `reason`, `next_step` and `info[].text` are in the language chosen with `--lang`; the
  `note` part of `evidence` (from the data file) is always English.
- Process command lines appear in `evidence` only with `--show-cmdline`.
- Strings are escaped per RFC 8259; control characters appear as `\u00XX`.
- `execution[].path` and `execution[].facts` hold paths exactly as found (a newline appears as
  `\n`). In `findings`, `info` and `skipped`, tabs, newlines and carriage returns in a field are
  shown as `?` (the fields are kept tab-separated inside the tool); the text report shows every
  control character as `?`.
