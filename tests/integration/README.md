# Integration tests

`run.sh` builds one image per distribution and scans it four times: as root and as an ordinary
user, each with `--no-exec` (found programs are not run) and with `--yes` (the programs the
tool lists to read their versions are run; there is no terminal to ask). It also runs
the fixed script of `--inspect-containers` (C14) in the image's own `/bin/sh` (dash) with both
Node.js copies on `PATH`, and expects both copies, the package lines and the final `END`.

| Image | Expected for `libbrotli1` / `python3-brotli` (data snapshot 2026-11-02) |
|---|---|
| ubuntu:22.04, 24.04, 26.04 | `FIXED` (1.0.9-2ubuntu0.1 / 1.1.0-2ubuntu0.1 / 1.2.0-3ubuntu0.1, USN-8956-1) |
| debian:12 | `FIXED` (1.0.9-2+deb12u1, DLA-4855-1) |
| debian:13 | `FIXED` (1.1.0-2+deb13u1, DSA-6582-1) |

Every image also contains:

- official Node.js 22.23.3 (expected `VULNERABLE`) and 22.23.4 (`FIXED`) in `/opt`,
  downloaded at build time and verified against the release's `SHASUMS256.txt`;
- PyPI Brotli 1.2.0 with urllib3 in `/srv/venv-old` (`VULNERABLE`, plus `EXPOSURE` because
  urllib3 decodes Brotli responses automatically) and 1.2.1 in `/srv/venv-new` (`FIXED`);
- the distribution's nginx, Apache and HAProxy, and the ngx_brotli modules where the archive has
  them, all expected `NOT_APPLICABLE` in C11 (docs/design.md 10.17).

Two more runs of each image, after removing those Node.js and Python copies inside the throw-away
container: with only the distribution's servers the exit status must be `0`; with an in-house
`.deb` installed (`/usr/local/sbin/nginx`) and `/usr/sbin/haproxy` overwritten, both must be `UNKNOWN`
through the real `dpkg` and the exit status `2`.

Once per run, with the first image, C14 is tried through the real engine: the single-file build
runs on the test host with `--inspect-containers` against a container of the image that has
both Node.js copies on its `PATH`. Through docker's unix socket the connection line must say so
and both copies must be judged inside the container; through a TCP relay to the same socket
(`relay.py`, `DOCKER_HOST=tcp://127.0.0.1:PORT`) the container must be listed with the connection
and the reason under "Not scanned", with no finding from inside it (docs/design.md 10.20). The
programs the tool finds on the test host are not run: the question is answered "n" on a
pseudo-terminal (`script`). This step needs `ENGINE=docker` (the default) connected through a
unix socket, `script` (util-linux) and `python3`; otherwise it says SKIP or FAIL.

A last step runs the single-file build under `bash:4.2` (the oldest supported version) with
GNU tools added, places a PyPI Brotli 1.2.0 record, and expects exit status 1 with that
finding `VULNERABLE` in valid JSON.

The packages come from the distribution's archive when the image is built, so the expected
verdicts are those of an image built now. An image cached from before an update keeps the old
packages: rebuild it (`docker rmi bcc-it:...`, or `docker builder prune`) after the data changes.
When the expected verdicts change (as on 2026-10-27, when Ubuntu's fix of 2026-10-26 entered
the data), update the matrix in `run.sh` together with `data/advisories.tsv`.

No Brotli data is created or used. The images only hold software at known versions.

```sh
make dist
bash tests/integration/run.sh                  # everything
ONLY=debian:13 SKIP_BASH42=1 bash tests/integration/run.sh
ENGINE=podman bash tests/integration/run.sh
```

Reports are kept in `tests/tmp/integration/` (ignored by git). The latest recorded results:
[docs/verification.md](../../docs/verification.md).
