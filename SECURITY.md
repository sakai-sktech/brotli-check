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

Read-only; no network; no attack data; found programs run only for their version, with an empty
environment, a timeout, and only when nobody but root (or the invoking user) could have replaced
them; command lines are not shown unless `--show-cmdline`; `--output` never overwrites a file.
