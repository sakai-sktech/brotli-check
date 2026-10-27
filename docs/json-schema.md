# JSON output (`--json`)

日本語: [json-schema.ja.md](json-schema.ja.md)

One JSON object on one line, UTF-8. Fields are added in a backward-compatible way; a
removed or renamed field changes the major part of `tool_version`.

```jsonc
{
  "tool": "brotli-cve-check",
  "tool_version": "0.1.0",
  "cve": "CVE-2026-111497",

  "data_snapshot_date": "2026-10-26",   // "# snapshot:" line of the advisory data
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

  "skipped": [                          // ranges NOT scanned, always listed
    { "scope": "C09 --deep", "reason": "generic search of ELF files ... (use --deep)" }
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
      "evidence": "version via exec; data: node 22; https://nodejs.org/... (2026-10-26)",
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
| `FIXED` | Version that contains the fix |
| `NO_FIX_AVAILABLE` | The distributor has not released a fix yet |
| `RESTART_REQUIRED` | The fix is on disk but a process still runs the old code |
| `VENDORED_COPY` | Carries its own decoder; version must be checked by a person |
| `LIKELY_FIXED`, `LIKELY_VULNERABLE` | Judged by the verified string heuristic; see `confidence` |
| `EXPOSURE` | A path by which attacker data could reach a decoder (not a vulnerability) |
| `NOT_APPLICABLE` | No decoder in that file (compression only, or no Brotli) |
| `UNKNOWN` | Could not be judged; `reason` says why |
| `SKIPPED` | Reserved; not-scanned ranges are reported in `skipped` |

## exit_code

| Value | Meaning |
|---|---|
| 0 | None of the statuses for 1 or 2 in the scanned ranges (not proof of safety) |
| 1 | `VULNERABLE` or `RESTART_REQUIRED` present |
| 2 | None of the above, but `NO_FIX_AVAILABLE`, `VENDORED_COPY`, `LIKELY_*` or `UNKNOWN` present |
| 3 | Error of the tool itself (bad option, unreadable data file, ...) |

## Notes

- `reason`, `next_step` and `info[].text` are in the language chosen with `--lang`; the
  `note` part of `evidence` (from the data file) is always English.
- Process command lines appear in `evidence` only with `--show-cmdline`.
- Strings are escaped per RFC 8259; control characters appear as `\u00XX`.
- `execution[].path` and `execution[].facts` hold paths exactly as found (a newline appears as
  `\n`). In `findings`, `info` and `skipped`, tabs, newlines and carriage returns in a field are
  shown as `?` (the fields are kept tab-separated inside the tool); the text report shows every
  control character as `?`.
