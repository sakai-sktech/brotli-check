# Contributing

## Updating the advisory data (`data/advisories.tsv`)

The data decides every verdict, so it has the strictest rules.

1. **Every row needs a primary source URL and the retrieval date** (`YYYY-MM-DD`). Primary
   means the project or distributor: release notes, security trackers, advisories, the source
   tree. **News articles and blog posts are not enough on their own.**
2. Use the narrowest status that the source supports:
   `fixed` (the source names the fixed version), `no_fix` (the distributor has not released
   one), `unreleased` (announced but not in the archive yet), `derived` (follows from a general
   statement; explain in `note`), `analysis` (from a source tree, not a vendor advisory),
   `unknown`.
3. When sources disagree, write what each one says in `note` and prefer `unknown` until the
   disagreement is resolved.
4. Update the `# snapshot:` line to the date of the newest retrieval.
5. Run `make test` (the data file is loaded and validated by the tests).

Columns are tab-separated: `component, branch, fixed, status, source_url, retrieved, note`.
See the header of the file and docs/design.md 5.1.

## Code

- Bash 4.2 or later, coreutils, findutils, grep, sed, awk. No Python in the tool.
  Write empty-array expansions as `${a[@]+"${a[@]}"}` (bash 4.2 with `set -u`).
- Read-only: no writes outside `--output`, no network, no `--version`-style probes outside
  `bcc_probe`, external tools through `bcc_sys` (`LC_ALL=C`, timeout).
- Every user-visible message goes into `lib/i18n.sh` in English and Japanese.
- `make lint` must report zero warnings; `make test` must pass. Add a test for every
  new verdict path.

## Tests must never use attack data

No crafted or "broken" Brotli streams, no proof-of-concept inputs, in tests or anywhere else.
Detection is checked with fake programs, fake `/proc` trees, metadata files, and the string
lists in `tests/fixtures/c09/`.

## Commits

Small commits with a clear message. Mention the primary source in the message when a data
row changes.
