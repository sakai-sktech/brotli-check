# Integration tests

`run.sh` builds one image per distribution and scans it four times: as root and as an ordinary
user, each with `--no-exec` (found programs are not run) and with `--yes` (the programs the
tool lists to read their versions are run; there is no terminal to ask). It also runs
the fixed script of `--inspect-containers` (C14) in the image's own `/bin/sh` (dash) with both
Node.js copies on `PATH`, and expects both copies, the package lines and the final `END`.

| Image | Expected for `libbrotli1` / `python3-brotli` (data snapshot 2026-10-26) |
|---|---|
| ubuntu:22.04, 24.04, 26.04 | `NO_FIX_AVAILABLE` (Ubuntu: "Needs evaluation", no USN) |
| debian:12 | `FIXED` (1.0.9-2+deb12u1, DLA-4855-1) |
| debian:13 | `FIXED` (1.1.0-2+deb13u1, DSA-6582-1) |

Every image also contains:

- official Node.js 22.23.3 (expected `VULNERABLE`) and 22.23.4 (`FIXED`) in `/opt`,
  downloaded at build time and verified against the release's `SHASUMS256.txt`;
- PyPI Brotli 1.2.0 with urllib3 in `/srv/venv-old` (`VULNERABLE`, plus `EXPOSURE` because
  urllib3 decodes Brotli responses automatically) and 1.2.1 in `/srv/venv-new` (`FIXED`).

A last step runs the single-file build under `bash:4.2` (the oldest supported version) with
GNU tools added, places a PyPI Brotli 1.2.0 record, and expects exit status 1 with that
finding `VULNERABLE` in valid JSON.

When the expected verdicts change (for example Ubuntu releases a fix), update the matrix in
`run.sh` together with `data/advisories.tsv`.

No Brotli data is created or used. The images only hold software at known versions.

```sh
make dist
bash tests/integration/run.sh                  # everything
ONLY=debian:13 SKIP_BASH42=1 bash tests/integration/run.sh
ENGINE=podman bash tests/integration/run.sh
```

Reports are kept in `tests/tmp/integration/` (ignored by git). The latest recorded results:
[docs/verification.md](../../docs/verification.md).
