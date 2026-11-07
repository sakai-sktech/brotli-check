# .NET: what the System.IO.Compression native library carries

.NET builds Google's C decoder into its System.IO.Compression native library
(`libSystem.IO.Compression.Native.so`; `System.IO.Compression.Native.so` before .NET 5) and does
not load libbrotlidec. The tool judges each copy by .NET's own version (docs/design.md 10.27).
This directory holds what that rests on: the strings of the library in the builds below, as the
tool reads them. The unit tests (`tests/unit/dotnet.bats`) run the checks on fake ELF files made
from these lists. No Brotli data of any kind is used.

Each `.txt` keeps, from `strings -a`, the lines the tool looks at: the `_ERROR_*` names, the
`BrotliDecoder*` symbols (decoder markers), the build stamp `@(#)Version ...`, and one
`timedownlifeleftbackcodedatashowonlysitecity` line per copy of the Brotli dictionary (its
first 44 characters; the tool counts copies by them). Reproduce with `reproduce.sh WORKDIR`.

## Results (2026-11-07, x86_64)

`names` = strings starting with `_ERROR_FORMAT_`; BS = `_ERROR_FORMAT_BLOCK_SWITCH` present.

| File | Source | Stamp | names | BS |
|---|---|---|---|---|
| `microsoft-2.1.30.txt` | `dotnet-runtime-2.1.30-linux-x64.tar.gz` | `4.6.30411.02` (corefx) | 0 | no |
| `microsoft-3.1.32.txt` | `dotnet-runtime-3.1.32-linux-x64.tar.gz` | `4.700.22.56512` (corefx) | 0 | no |
| `microsoft-5.0.17.txt` | `dotnet-runtime-5.0.17-linux-x64.tar.gz` | `5.0.1722.21314` | 0 | no |
| `microsoft-6.0.36.txt` | `dotnet-runtime-6.0.36-linux-x64.tar.gz` | `6.0.3624.51421` | 0 | no |
| `microsoft-7.0.20.txt` | `dotnet-runtime-7.0.20-linux-x64.tar.gz` | `7.0.2024.26716` | 0 | no |
| `microsoft-8.0.32.txt` | `dotnet-runtime-8.0.32-linux-x64.tar.gz` | `8.0.3226.50405` | 0 | no |
| `microsoft-8.0.33.txt` | `dotnet-runtime-8.0.33-linux-x64.tar.gz` | `8.0.3326.52219` | 0 | no |
| `microsoft-9.0.21.txt` | `dotnet-runtime-9.0.21-linux-x64.tar.gz` | `9.0.2126.50404` | 16 | no |
| `microsoft-9.0.22.txt` | `dotnet-runtime-9.0.22-linux-x64.tar.gz` | `9.0.2226.52218` | 17 | yes |
| `microsoft-10.0.13.txt` | `dotnet-runtime-10.0.13-linux-x64.tar.gz` | `10.0.1326.50504` | 16 | no |
| `microsoft-10.0.14.txt` | `dotnet-runtime-10.0.14-linux-x64.tar.gz` | `10.0.1426.52326` | 17 | yes |
| `powershell-7.4.21.txt` | `powershell-7.4.21-linux-x64.tar.gz` (self-contained, .NET 8.0.32) | `8.0.3226.46521` | 0 | no |
| `powershell-7.4.22.txt` | `powershell-7.4.22-linux-x64.tar.gz` (self-contained, .NET 8.0.33) | `8.0.3326.52219` | 0 | no |
| `ubuntu-24.04-dotnet-runtime-8.0-8.0.33.txt` | Ubuntu 24.04 `dotnet-runtime-8.0` 8.0.33-0ubuntu1~24.04.1 (source `dotnet8` 8.0.133-8.0.33-0ubuntu1~24.04.1) | `8.0.3326.52219` | 0 | no |

The archives come from `builds.dotnet.microsoft.com` with the SHA-512 sums listed in
`release-notes/<line>/releases.json` of `dotnet/core`, and from the GitHub releases of
`PowerShell/PowerShell` with the SHA-256 digests GitHub gives; all matched. Microsoft's Debian 12
package `dotnet-runtime-8.0` 8.0.33-1 (packages.microsoft.com) installs the same stamp under
`/usr/share/dotnet` (not kept here).

What the results show:

- **The stamp is .NET's version from .NET 5 on.** Arcade's file version encodes it:
  `FILE_MINOR = MINOR * 100 + PATCH / 100`, `FILE_PATCH = (PATCH % 100) * 100 + yy`
  (dotnet/arcade, `Documentation/Versioning.md`), so `8.0.3326.52219` is 8.0.33, built in
  2026. The commit after it is the release tag's (`da7a9bea` = dotnet/runtime `v8.0.33`), and
  the runtime's `.version` file gives the same commit and version. PowerShell 7.4.22 carries the
  same file as the 8.0.33 runtime (identical bytes); 7.4.21 carries an earlier build of 8.0.32
  (another commit, the same version). .NET Core 2.1 and 3.1 stamp corefx's file version
  (4.6.x, 4.700.x), which is not .NET's.
- **The strings decide for .NET 9 and 10, not for .NET 8.** .NET 9 and 10 bundle Brotli 1.1.x
  and keep the error names (16 before the fix, 17 with `_ERROR_FORMAT_BLOCK_SWITCH` after it).
  .NET 8 (Brotli 1.0.9, then 1.0.10) and the end-of-life lines keep none, so their library is a
  `VENDORED_COPY` to the strings, before and after the fix alike.
- Ubuntu's 8.0.33, built from source, has the same stamp and commit as Microsoft's.
