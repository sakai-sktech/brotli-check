# Changelog

## 0.1.0 - unreleased

First version.

- Detection items C01-C15: distribution packages, packages depending on libbrotli,
  processes needing a restart, Node.js, Bun, PyPI Brotli/brotlicffi and conda, Node.js
  project exposure hints, curl, libbrotlidec outside the package manager and bundled decoders
  (`--deep`), Envoy, compression-only web servers, snap/flatpak, browsers, containers,
  listening sockets.
- String heuristic for bundled copies (`_ERROR_FORMAT_BLOCK_SWITCH`), verified on Brotli
  1.2.0/1.2.1 builds, official Node.js binaries and PyPI wheels.
- Text (English/Japanese) and JSON output; exit codes 0-3.
- Advisory data snapshot 2026-10-26.
