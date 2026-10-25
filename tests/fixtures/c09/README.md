# C09 string heuristic: verification record

The heuristic in `lib/elf.sh` (`bcc_brotli_heuristic`) decides whether a bundled Brotli
decoder contains the CVE-2026-111497 fix by looking at the decoder's error-name strings.
This directory holds the evidence it was checked against. The unit tests
(`tests/unit/heuristic.bats`) run the heuristic on these files.

## Why the marker exists

`c/dec/decode.c` builds the names returned by `BrotliDecoderErrorString` from the error list in
`c/include/brotli/decode.h`:

```c
#define BROTLI_ERROR_CODE_CASE_(PREFIX, NAME, CODE) \
    case BROTLI_DECODER ## PREFIX ## NAME: return #PREFIX #NAME;
```

The fix added error -17. Source of each release's `decode.h` (2026-10-26):

| Tag | Line for -17 |
|---|---|
| v1.0.9 | `/* -17..-18 codes are reserved */` |
| v1.0.10 | `BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17) SEPARATOR` |
| v1.1.0 | `/* -17 code is reserved */` |
| v1.1.1 | `BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17) SEPARATOR` |
| v1.2.0 | `/* -17 code is reserved */` |
| v1.2.1 | `BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17) SEPARATOR` |

Node.js vendors the same files: `deps/brotli/c/include/brotli/decode.h` says
`/* -17 code is reserved */` at tag v22.23.3 and has the `BLOCK_SWITCH, -17` line at v22.23.4
(where `deps/brotli/c/common/version.h` still says 1.1.0).

So a fixed decoder carries the string `_ERROR_FORMAT_BLOCK_SWITCH`; an unfixed one has the
other `_ERROR_FORMAT_*` names but not this one. Only whole strings count: Node.js also keeps
`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` in its own table.

## Results (2026-10-26)

`_ERROR_FORMAT_*` = number of strings starting with `_ERROR_FORMAT_`; BS = `_ERROR_FORMAT_BLOCK_SWITCH` present.
P1 calls only `BrotliDecoderDecompress`; P2 also calls `BrotliDecoderErrorString`.

| Artifact | 1.2.0 | 1.2.1 |
|---|---|---|
| `libbrotlidec.so` (cmake Release), stripped or not | 16, no BS | 17, BS |
| static, `-O2`, P1 and P2, stripped or not | 16, no BS | 17, BS |
| static, `-O2 -flto -ffunction-sections -fdata-sections -Wl,--gc-sections`, P2 | 16, no BS | 17, BS |
| same, P1 (`BrotliDecoderErrorString` removed by the linker) | **0** | **0** |

| Official binary | Result |
|---|---|
| Node.js v22.23.3 / v24.22.0 `bin/node` | 16, no BS |
| Node.js v22.23.4 / v24.22.1 `bin/node` | 17, BS |
| PyPI Brotli 1.2.0 (cp312 manylinux x86_64) | 16, no BS |
| PyPI Brotli 1.2.1 | 17, BS |
| PyPI brotlicffi 1.2.0.0 / 1.2.0.1 / 1.2.0.2 (abi3) | 16, no BS |
| PyPI brotlicffi 1.2.1.0 | 17, BS |

No counter-example (fixed, but other names present without BS) was found. The one case that
cannot be decided is LTO + gc-sections when the program never calls
`BrotliDecoderErrorString`: then no name is left, and the tool reports `VENDORED_COPY`.
The heuristic requires at least 8 names before it decides.

Not built for this record: 1.0.10 and 1.1.1 binaries (their source carries the same marker).

## Downloads

| File | SHA256 | Verified against |
|---|---|---|
| github.com/google/brotli/archive/refs/tags/v1.2.0.tar.gz | 816c96e8e8f193b40151dad7e8ff37b1221d019dbcb9c35cd3fadbfe6477dfec | (computed; GitHub publishes none) |
| github.com/google/brotli/archive/refs/tags/v1.2.1.tar.gz | 98d35d11a78dc453aebb7d10c3748f3f73ff78c8267c0dc697b8631f67bf7e8f | (computed) |
| nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz | df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de | SHASUMS256.txt |
| nodejs.org/dist/v22.23.4/node-v22.23.4-linux-x64.tar.xz | 1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce | SHASUMS256.txt |
| nodejs.org/dist/v24.22.0/node-v24.22.0-linux-x64.tar.xz | cc2f601cee82d9a5a233302fe307abc600727035fd7d2c3a3571755989e95008 | SHASUMS256.txt |
| nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz | 6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6 | SHASUMS256.txt |
| brotli-1.2.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl | 072e7624b1fc4d601036ab3f4f27942ef772887e876beff0301d261210bca97f | PyPI JSON digests |
| brotli-1.2.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl | 4b9dd0173ca5e01d1eb307d3c184fe8c09bdc168ede560889b1018d216d38c61 | PyPI JSON digests |
| brotlicffi-1.2.0.0-cp38-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl | 33cfb408d0cff64cd50bef268c0fed397c46fbb53944aa37264148614a62e990 | PyPI JSON digests |
| brotlicffi-1.2.0.1-cp38-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl | 6f3314a3476f59e5443f9f72a6dff16edc0c3463c9b318feaef04ae3e4683f5a | PyPI JSON digests |
| brotlicffi-1.2.0.2-cp39-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl | 22916101de0e7ff535f2edf54b52a85591853b8ae9a98737643defdd3c063a3a | PyPI JSON digests |
| brotlicffi-1.2.1.0-cp39-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl | 0a7281a39de91432e90c27ab9c4f9feb3a9cf33fda3873534c2a88270d9f60a2 | PyPI JSON digests |

## Reproducing

```sh
tests/fixtures/c09/reproduce.sh /tmp/c09 --binaries
diff -r tests/fixtures/c09 /tmp/c09/fixtures   # only README.md and reproduce.sh differ
```

The script builds with the host's gcc/cmake and only reads the downloaded binaries; it never
runs them and never creates Brotli data. Run on Ubuntu 24.04 (gcc 13) on 2026-10-26, it produced
fixture files byte-identical to the ones committed here.
