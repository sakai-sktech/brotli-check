# Integration tests

`run.sh` builds one image per distribution and scans it four times: as root and as an ordinary
user, each with `--no-exec` (found programs are not run) and with `--yes` (the programs the
tool lists to read their versions are run; there is no terminal to ask). It also runs
the fixed script of `--inspect-containers` (C14) in the image's own `/bin/sh` (dash) with both
Node.js copies on `PATH`, and expects both copies, the package lines and the final `END`.

| Image | Expected for `libbrotli1` / `python3-brotli` (data snapshot 2026-11-14) |
|---|---|
| ubuntu:22.04, 24.04, 26.04 | `FIXED` (1.0.9-2ubuntu0.1 / 1.1.0-2ubuntu0.1 / 1.2.0-3ubuntu0.1, USN-8956-1) |
| debian:12 | `FIXED` (1.0.9-2+deb12u1, DLA-4855-1) |
| debian:13 | `FIXED` (1.1.0-2+deb13u1, DSA-6582-1) |

Every image also contains:

- official Node.js 22.23.3 (expected `VULNERABLE`) and 22.23.4 (`FIXED`) in `/opt`,
  downloaded at build time and verified against the release's `SHASUMS256.txt` (`fetch-node.sh`:
  a download that fails for a passing reason, such as a time-out, a refused connection or HTTP
  408, 429 or 5xx, is tried again; each try has a time limit, and no new try starts after 10
  minutes);
- PyPI Brotli 1.2.0 with urllib3 in `/srv/venv-old` (`VULNERABLE`, plus `EXPOSURE` because
  urllib3 decodes Brotli responses automatically) and 1.2.1 in `/srv/venv-new` (`FIXED`);
- the distribution's nginx, Apache and HAProxy, and the ngx_brotli modules where the archive has
  them, all expected `NOT_APPLICABLE` in C11 (docs/design.md 10.17).

Two more runs of each image, after removing those Node.js and Python copies inside the throw-away
container: with only the distribution's servers the exit status must be `0`; with an in-house
`.deb` installed (`/usr/local/sbin/nginx`) and `/usr/sbin/haproxy` overwritten, both must be `UNKNOWN`
through the real `dpkg` and the exit status `2`.

Once per run, with the first image, C14 is tried through the real engine, against a container of
the image that has both Node.js copies on its `PATH`, and the image's two Python environments
copied to `/opt` inside it (where the check script looks).

- Through docker's unix socket the single-file build runs on the test host with
  `--inspect-containers`. The connection line must say so, both Node.js copies must be judged
  inside the container, PyPI Brotli 1.2.0 must be `VULNERABLE` and 1.2.1 `FIXED` (its extension
  module read inside the container through the engine and compared on the test host), and the
  exit status must be `1` (from those copies, whatever the test host holds). A second container
  of the image, run to its end, must be counted under "Not scanned" with the images, as left out
  by choice (`chosen`), and give no finding (10.24; only the entries are checked, since the
  numbers depend on the host). The programs the tool finds on the test host are not run: the
  question is answered "n" on a pseudo-terminal (`script`).
- Through a TCP relay to the same socket (`relay.py`, `DOCKER_HOST=tcp://127.0.0.1:PORT`; it
  serves only sockets of the user running the tests, since the engine's socket gives control of
  the engine) the container must be listed with the connection and the reason under "Not
  scanned", with no finding from inside it (docs/design.md 10.20). On the test host the exit
  status of this run would come from the host's own copies (a developer's machine or a CI runner
  has Node.js of its own), so the tool runs in a throw-away container of the image instead: `/opt`
  and `/srv` hidden under empty tmpfs, on the host network (to reach the relay on `127.0.0.1`),
  as the user running the tests, with the test host's `docker` client mounted read-only. With
  `--inspect-containers` the C14 entry must be `failed` and the exit status `2` (10.26); with
  `--containers` alone the entry must be `chosen` and the exit status `0`, which shows that the
  `2` comes from that entry alone.

This step needs `ENGINE=docker` (the default) connected through a unix socket of a native engine
on the test host (a container on the host network must reach the test host's `127.0.0.1`; not
tried with Docker Desktop), a `docker` client that runs inside the image (the one tried needs
only the C library), `script` (util-linux) and `python3`; otherwise it says SKIP or FAIL, with
the client's own output when it could not reach the engine from such a container. When an exit
status is not the expected one, the counts by status and the `failed` entries of that report are
printed, with the end of the run's log.

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

Reports and logs are kept in `tests/tmp/integration/` (ignored by git). CI shows only standard
output, so when an image build fails the last 40 lines of its log (`<image>-build.log`, the whole
build output in plain progress) are printed: the failing step's own output and the engine's
error. The same is done for the other logs a failure points to. The latest recorded results:
[docs/verification.md](../../docs/verification.md).
