# Security policy

## Reporting a vulnerability in this tool

Please report problems in **brotli-cve-check itself** (for example: it runs something it
should not, writes outside `--output`, leaks secrets into its output, or can be tricked by
files on the scanned host) through GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on the repository page. Please do not open a public issue
for these.

Include the version (`brotli-cve-check --version`), the distribution, and the smallest
reproduction you can. Do not attach exploit data for Brotli.

## Not handled here

- CVE-2026-111497 itself belongs to Google Brotli: <https://github.com/google/brotli>.
- Fixes for a product that bundles Brotli belong to that product's vendor.
- Wrong or outdated advisory data is not a security issue of the tool: open a normal issue or
  pull request with the primary source (see CONTRIBUTING.md).

## Design rules this tool keeps

- The tool itself installs, updates, stops and reconfigures nothing. It writes only to standard
  output and to a new file named with `--output`, which never overwrites a file and is only
  created in a directory that nobody but root (or the invoking user, when not root) can change.
- It does not connect to the network itself, and does not generate, download or contain attack
  data.
- Programs it finds are run only to read their version, with one argument, from `/`, with an
  empty environment, stdin closed, a time limit and a cap on their output. Before anything runs
  it lists them, each with who besides root or the invoking user could change the program, a
  directory above it, or a library it loads, and runs only those chosen (all of them with
  `--yes`, none with `--no-exec`). Nothing keeps a program allowed to run from writing files or
  using the network.
- With `--containers`, docker or podman are used with their current connection settings.
- Command lines of processes are not shown unless `--show-cmdline`.
