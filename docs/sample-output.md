# Sample output

Captured on 2026-11-06, with the advisory data of this version (snapshot 2026-11-02), from the
integration image for Ubuntu 24.04 (`tests/integration/`), scanned as root with
`--roots /opt,/srv --yes` (no terminal in the container, so the consent to run the listed programs
is given in advance). The tool is the source tree after issue #9, not yet released (its header still
says 0.1.0). The image holds Node.js 22.23.3 and 22.23.4 from nodejs.org, PyPI Brotli 1.2.0 (with
urllib3) and 1.2.1 in two virtual environments, and the distribution's nginx, Apache and HAProxy.
Exit status: 1.

The first section lists the programs the tool ran to read their versions, their output, and the
facts shown before asking: here the Node.js tarballs keep their packager's owners (non-root
uids, which in this image happen to be the users ubuntu and tester), and the report says so. At a terminal, without `--yes`, the same list is shown first and you choose.

Each `FIXED` line says what it rests on: the distribution package version (C01), the output of
`node --version` (C04), or the package metadata confirmed by the strings of the extension module,
with what those strings do not show (C06). Its next step is for that line only.

The distribution's packages in the image were installed on 2026-10-27, after Ubuntu's fix
(USN-8956-1, 2026-10-26), so its `libbrotli1` and `python3-brotli` are the fixed
`1.1.0-2ubuntu0.1`. An earlier capture of this page, made with the data of 2026-10-26, reported that
same version as `NO_FIX_AVAILABLE` ("the distributor has not released a fix yet"): the data predated
the fix (docs/design.md 2.1).

This image has no process using a deleted file (`RESTART_REQUIRED`), no link to a program of another
name, and the run gives no `--containers`, so the lines for those do not appear here.

## English (default)

```
brotli-cve-check 0.1.0 - local check for CVE-2026-111497 (Brotli decoder)
Host: Ubuntu 24.04.5 LTS [ubuntu:noble], kernel 6.10.14-linuxkit, running as root
Data: snapshot 2026-11-02 (4 days old), embedded
Search roots: /opt,/srv | options: --yes

== Programs run to read their versions ==
[RUN] /opt/node-v22.23.3-linux-x64/bin/node --version -> v22.23.3 (exit status 0)  (C04 node)
    - /opt/node-v22.23.3-linux-x64 belongs to ubuntu
    - /opt/node-v22.23.3-linux-x64/bin belongs to ubuntu
    - /opt/node-v22.23.3-linux-x64/bin/node belongs to ubuntu
[RUN] /opt/node-v22.23.4-linux-x64/bin/node --version -> v22.23.4 (exit status 0)  (C04 node)
    - /opt/node-v22.23.4-linux-x64 belongs to tester
    - /opt/node-v22.23.4-linux-x64/bin belongs to tester
    - /opt/node-v22.23.4-linux-x64/bin/node belongs to tester

== C01 OS packages (Debian/Ubuntu) ==
[FIXED] C01 | libbrotli1 | dpkg (ubuntu:noble) | 1.1.0-2ubuntu0.1 | At or above the fixed version 1.1.0-2ubuntu0.1 (the distribution package version). | No update needed for this line (other lines and the ranges not scanned are separate). If it was updated recently, restart the services that use it (C03).
[FIXED] C01 | python3-brotli | dpkg (ubuntu:noble) | 1.1.0-2ubuntu0.1 | At or above the fixed version 1.1.0-2ubuntu0.1 (the distribution package version). | No update needed for this line (other lines and the ranges not scanned are separate). If it was updated recently, restart the services that use it (C03).

== C04 Node.js ==
[VULNERABLE] C04 | node | /opt/node-v22.23.3-linux-x64/bin/node | 22.23.3 | Below the fixed version 22.23.4. | Update to 22.23.4 or later.
[FIXED] C04 | node | /opt/node-v22.23.4-linux-x64/bin/node | 22.23.4 | At or above the fixed version 22.23.4 (output of node --version). | No update needed for this line (other lines and the ranges not scanned are separate).

== C06 Python packages (PyPI, conda) ==
[FIXED] C06 | brotli | /srv/venv-new/lib/python3.12/site-packages/brotli-1.2.1.dist-info | 1.2.1 | At or above the fixed version 1.2.1 (version from the package metadata). Found: the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH) among the decoder strings of /srv/venv-new/lib/python3.12/site-packages/_brotli.cpython-312-x86_64-linux-gnu.so. Not determined: whether all decoder code in the file is fixed (the linker merges equal strings, so an unfixed copy sharing them would not show). | No update needed for this line (other lines and the ranges not scanned are separate).
[VULNERABLE] C06 | brotli | /srv/venv-old/lib/python3.12/site-packages/brotli-1.2.0.dist-info | 1.2.0 | Below the fixed version 1.2.1. | In the environment that owns /srv/venv-old/lib/python3.12/site-packages, run: pip install -U "brotli>=1.2.1"
[EXPOSURE] C06 | python-http-clients | /srv/venv-old/lib/python3.12/site-packages | - | Brotli is installed here, so these HTTP clients decode a br response when they receive one: urllib3. Whether an application fetches from outside with them is not checked. | Not a vulnerability by itself: update the decoder it uses (other findings) with priority.

== C11 Compression-only web servers ==
[NOT_APPLICABLE] C11 | nginx | /usr/sbin/nginx | - | From the distribution package nginx: no decoder markers in the file and no libbrotlidec. A stripped static copy without error names would carry no markers, so this rests on the package: its name, maintainer and version form are a distribution's, the file is as it installed it (dpkg --verify), and the sources of this package in Debian 12, 13 and Ubuntu 22.04, 24.04, 26.04 hold no Brotli decoder (read 2026-11-02). A rebuild that keeps the name, maintainer and version form cannot be told apart. | Other processes on this host still need their own check.
[NOT_APPLICABLE] C11 | apache2 | /usr/sbin/apache2 | - | From the distribution package apache2-bin: no decoder markers in the file and no libbrotlidec. A stripped static copy without error names would carry no markers, so this rests on the package: its name, maintainer and version form are a distribution's, the file is as it installed it (dpkg --verify), and the sources of this package in Debian 12, 13 and Ubuntu 22.04, 24.04, 26.04 hold no Brotli decoder (read 2026-11-02). A rebuild that keeps the name, maintainer and version form cannot be told apart. | Other processes on this host still need their own check.
[NOT_APPLICABLE] C11 | haproxy | /usr/sbin/haproxy | - | From the distribution package haproxy: no decoder markers in the file and no libbrotlidec. A stripped static copy without error names would carry no markers, so this rests on the package: its name, maintainer and version form are a distribution's, the file is as it installed it (dpkg --verify), and the sources of this package in Debian 12, 13 and Ubuntu 22.04, 24.04, 26.04 hold no Brotli decoder (read 2026-11-02). A rebuild that keeps the name, maintainer and version form cannot be told apart. | Other processes on this host still need their own check.
[NOT_APPLICABLE] C11 | ngx_http_brotli_filter_module.so | /usr/lib/nginx/modules/ngx_http_brotli_filter_module.so | - | From the distribution package libnginx-mod-http-brotli-filter: no decoder markers in the file and no libbrotlidec. A stripped static copy without error names would carry no markers, so this rests on the package: its name, maintainer and version form are a distribution's, the file is as it installed it (dpkg --verify), and the sources of this package in Debian 12, 13 and Ubuntu 22.04, 24.04, 26.04 hold no Brotli decoder (read 2026-11-02). A rebuild that keeps the name, maintainer and version form cannot be told apart. | Other processes on this host still need their own check.
[NOT_APPLICABLE] C11 | ngx_http_brotli_static_module.so | /usr/lib/nginx/modules/ngx_http_brotli_static_module.so | - | From the distribution package libnginx-mod-http-brotli-static: no decoder markers in the file and no libbrotlidec. A stripped static copy without error names would carry no markers, so this rests on the package: its name, maintainer and version form are a distribution's, the file is as it installed it (dpkg --verify), and the sources of this package in Debian 12, 13 and Ubuntu 22.04, 24.04, 26.04 hold no Brotli decoder (read 2026-11-02). A rebuild that keeps the name, maintainer and version form cannot be told apart. | Other processes on this host still need their own check.
[NOT_APPLICABLE] C11 | mod_brotli.so | /usr/lib/apache2/modules/mod_brotli.so | - | From the distribution package apache2-bin: no decoder markers in the file and no libbrotlidec. A stripped static copy without error names would carry no markers, so this rests on the package: its name, maintainer and version form are a distribution's, the file is as it installed it (dpkg --verify), and the sources of this package in Debian 12, 13 and Ubuntu 22.04, 24.04, 26.04 hold no Brotli decoder (read 2026-11-02). A rebuild that keeps the name, maintainer and version form cannot be told apart. | Other processes on this host still need their own check.

== Information ==
[INFO] C02 | Installed packages depending on libbrotli1 (3), fixed by the libbrotli1 update plus a restart: apache2-bin, libcurl4t64, libnginx-mod-http-brotli-filter
[INFO] C06 | /usr/lib/python3/dist-packages/Brotli-1.1.0.egg-info belongs to the distribution package python3-brotli; C01 judges it.
[INFO] C08 | /usr/bin/curl (curl) loads the OS libbrotlidec (/lib/x86_64-linux-gnu/libbrotlidec.so.1, found by readelf); C01 covers it. curl decodes br only with --compressed or CURLOPT_ACCEPT_ENCODING.
[INFO] C10 | Istio sidecars run Envoy inside containers; fixed in Istio 1.29.9 / 1.30.6 / 1.31.2.
[INFO] C13 | Electron applications bundle their own Chromium and Brotli; --deep lists such copies.

== Not scanned ==
[SKIPPED] C09 --deep | generic search of ELF files for bundled decoders (use --deep)
[SKIPPED] C07 --projects | node_modules exposure hints (use --projects)
[SKIPPED] C14 --containers | containers (use --containers)
[SKIPPED] C15 --exposure | listening sockets (use --exposure)

== Summary ==
Needs update: 2
Needs restart: 0
Needs human review: 0
Not scanned: C09 --deep, C07 --projects, C14 --containers, C15 --exposure
This tool does not check for intrusion. Updating to a fixed version does not remove traces of an intrusion that happened before the update.
```

## 日本語（`--lang ja`）

```
brotli-cve-check 0.1.0 - CVE-2026-111497（Brotli デコーダー）のローカル点検
ホスト: Ubuntu 24.04.5 LTS [ubuntu:noble]、カーネル 6.10.14-linuxkit、root で実行
既知データ: 2026-11-02 時点（4 日前）、embedded
探索した場所: /opt,/srv | オプション: --yes

== 版を読むために実行したプログラム ==
[実行した] /opt/node-v22.23.3-linux-x64/bin/node --version → v22.23.3（終了状態 0）  (C04 node)
    - /opt/node-v22.23.3-linux-x64 は ubuntu の所有
    - /opt/node-v22.23.3-linux-x64/bin は ubuntu の所有
    - /opt/node-v22.23.3-linux-x64/bin/node は ubuntu の所有
[実行した] /opt/node-v22.23.4-linux-x64/bin/node --version → v22.23.4（終了状態 0）  (C04 node)
    - /opt/node-v22.23.4-linux-x64 は tester の所有
    - /opt/node-v22.23.4-linux-x64/bin は tester の所有
    - /opt/node-v22.23.4-linux-x64/bin/node は tester の所有

== C01 OS パッケージ（Debian/Ubuntu） ==
[FIXED] C01 | libbrotli1 | dpkg (ubuntu:noble) | 1.1.0-2ubuntu0.1 | 修正版 1.1.0-2ubuntu0.1 以上です（配布元パッケージの版）。 | この行については更新は不要（ほかの行と走査しなかった範囲は別）。 最近更新したなら、使っているサービスを再起動する（C03）。
[FIXED] C01 | python3-brotli | dpkg (ubuntu:noble) | 1.1.0-2ubuntu0.1 | 修正版 1.1.0-2ubuntu0.1 以上です（配布元パッケージの版）。 | この行については更新は不要（ほかの行と走査しなかった範囲は別）。 最近更新したなら、使っているサービスを再起動する（C03）。

== C04 Node.js ==
[VULNERABLE] C04 | node | /opt/node-v22.23.3-linux-x64/bin/node | 22.23.3 | 修正版 22.23.4 より古い版です。 | 22.23.4 以上に更新する。
[FIXED] C04 | node | /opt/node-v22.23.4-linux-x64/bin/node | 22.23.4 | 修正版 22.23.4 以上です（node --version の出力）。 | この行については更新は不要（ほかの行と走査しなかった範囲は別）。

== C06 Python のパッケージ（PyPI・conda） ==
[FIXED] C06 | brotli | /srv/venv-new/lib/python3.12/site-packages/brotli-1.2.1.dist-info | 1.2.1 | 修正版 1.2.1 以上です（版はパッケージのメタデータから）。 分かったこと: /srv/venv-new/lib/python3.12/site-packages/_brotli.cpython-312-x86_64-linux-gnu.so のデコーダーの文字列に、修正で追加されたエラー名（_ERROR_FORMAT_BLOCK_SWITCH）がある。 分からないこと: ファイルの中のデコーダーがすべて修正済みかどうか（同じ文字列はリンカーが 1 つにまとめるため、それを共有する未修正のコピーは見えない）。 | この行については更新は不要（ほかの行と走査しなかった範囲は別）。
[VULNERABLE] C06 | brotli | /srv/venv-old/lib/python3.12/site-packages/brotli-1.2.0.dist-info | 1.2.0 | 修正版 1.2.1 より古い版です。 | /srv/venv-old/lib/python3.12/site-packages を持つ環境で pip install -U "brotli>=1.2.1" を実行する。
[EXPOSURE] C06 | python-http-clients | /srv/venv-old/lib/python3.12/site-packages | - | この環境には Brotli が入っているので、次の HTTP クライアントは br の応答を受け取ると展開します: urllib3。 アプリがこれらで外から取得しているかは見ていません。 | それ自体は脆弱性ではない。使っているデコーダー（ほかの所見）の更新を優先する。

== C11 圧縮専用の Web サーバー ==
[NOT_APPLICABLE] C11 | nginx | /usr/sbin/nginx | - | 配布元のパッケージ nginx のファイルです。ファイルにデコーダーの印も libbrotlidec の参照もありません。エラー名を持たない strip 済みの静的コピーは印を持たないので、根拠はパッケージの側です: 名前・Maintainer・版の形が配布元のもので、ファイルはインストールされたときのままで（dpkg --verify）、Debian 12・13 と Ubuntu 22.04・24.04・26.04 のこのパッケージのソースに Brotli のデコーダーはありません（2026-11-02 に確認）。名前・Maintainer・版の形を保ったまま作り直したものは見分けられません。 | 同じホストの他のプロセスは別に判定が必要。
[NOT_APPLICABLE] C11 | apache2 | /usr/sbin/apache2 | - | 配布元のパッケージ apache2-bin のファイルです。ファイルにデコーダーの印も libbrotlidec の参照もありません。エラー名を持たない strip 済みの静的コピーは印を持たないので、根拠はパッケージの側です: 名前・Maintainer・版の形が配布元のもので、ファイルはインストールされたときのままで（dpkg --verify）、Debian 12・13 と Ubuntu 22.04・24.04・26.04 のこのパッケージのソースに Brotli のデコーダーはありません（2026-11-02 に確認）。名前・Maintainer・版の形を保ったまま作り直したものは見分けられません。 | 同じホストの他のプロセスは別に判定が必要。
[NOT_APPLICABLE] C11 | haproxy | /usr/sbin/haproxy | - | 配布元のパッケージ haproxy のファイルです。ファイルにデコーダーの印も libbrotlidec の参照もありません。エラー名を持たない strip 済みの静的コピーは印を持たないので、根拠はパッケージの側です: 名前・Maintainer・版の形が配布元のもので、ファイルはインストールされたときのままで（dpkg --verify）、Debian 12・13 と Ubuntu 22.04・24.04・26.04 のこのパッケージのソースに Brotli のデコーダーはありません（2026-11-02 に確認）。名前・Maintainer・版の形を保ったまま作り直したものは見分けられません。 | 同じホストの他のプロセスは別に判定が必要。
[NOT_APPLICABLE] C11 | ngx_http_brotli_filter_module.so | /usr/lib/nginx/modules/ngx_http_brotli_filter_module.so | - | 配布元のパッケージ libnginx-mod-http-brotli-filter のファイルです。ファイルにデコーダーの印も libbrotlidec の参照もありません。エラー名を持たない strip 済みの静的コピーは印を持たないので、根拠はパッケージの側です: 名前・Maintainer・版の形が配布元のもので、ファイルはインストールされたときのままで（dpkg --verify）、Debian 12・13 と Ubuntu 22.04・24.04・26.04 のこのパッケージのソースに Brotli のデコーダーはありません（2026-11-02 に確認）。名前・Maintainer・版の形を保ったまま作り直したものは見分けられません。 | 同じホストの他のプロセスは別に判定が必要。
[NOT_APPLICABLE] C11 | ngx_http_brotli_static_module.so | /usr/lib/nginx/modules/ngx_http_brotli_static_module.so | - | 配布元のパッケージ libnginx-mod-http-brotli-static のファイルです。ファイルにデコーダーの印も libbrotlidec の参照もありません。エラー名を持たない strip 済みの静的コピーは印を持たないので、根拠はパッケージの側です: 名前・Maintainer・版の形が配布元のもので、ファイルはインストールされたときのままで（dpkg --verify）、Debian 12・13 と Ubuntu 22.04・24.04・26.04 のこのパッケージのソースに Brotli のデコーダーはありません（2026-11-02 に確認）。名前・Maintainer・版の形を保ったまま作り直したものは見分けられません。 | 同じホストの他のプロセスは別に判定が必要。
[NOT_APPLICABLE] C11 | mod_brotli.so | /usr/lib/apache2/modules/mod_brotli.so | - | 配布元のパッケージ apache2-bin のファイルです。ファイルにデコーダーの印も libbrotlidec の参照もありません。エラー名を持たない strip 済みの静的コピーは印を持たないので、根拠はパッケージの側です: 名前・Maintainer・版の形が配布元のもので、ファイルはインストールされたときのままで（dpkg --verify）、Debian 12・13 と Ubuntu 22.04・24.04・26.04 のこのパッケージのソースに Brotli のデコーダーはありません（2026-11-02 に確認）。名前・Maintainer・版の形を保ったまま作り直したものは見分けられません。 | 同じホストの他のプロセスは別に判定が必要。

== 情報 ==
[INFO] C02 | libbrotli1 に依存するパッケージ（3 個）。libbrotli1 の更新と再起動で直ります: apache2-bin, libcurl4t64, libnginx-mod-http-brotli-filter
[INFO] C06 | /usr/lib/python3/dist-packages/Brotli-1.1.0.egg-info は配布元パッケージ python3-brotli のものなので、C01 で判定します。
[INFO] C08 | /usr/bin/curl（curl）は OS の libbrotlidec（/lib/x86_64-linux-gnu/libbrotlidec.so.1、readelf で確認）を読み込むので、C01 の判定に従います。 curl が br を展開するのは --compressed／CURLOPT_ACCEPT_ENCODING を指定したときだけです。
[INFO] C10 | Istio のサイドカーはコンテナ内で Envoy を動かします。修正版は Istio 1.29.9 / 1.30.6 / 1.31.2 です。
[INFO] C13 | Electron アプリは独自の Chromium と Brotli を同梱しています。--deep でそうしたコピーを列挙します。

== 走査しなかった範囲 ==
[SKIPPED] C09 --deep | ELF ファイルからの同梱デコーダーの汎用探索（--deep で実行）
[SKIPPED] C07 --projects | node_modules からの露出のヒント（--projects で実行）
[SKIPPED] C14 --containers | コンテナ（--containers で実行）
[SKIPPED] C15 --exposure | 待ち受けポート（--exposure で実行）

== 要約 ==
更新が必要なもの: 2 件
再起動が必要なもの: 0 件
人の確認が必要なもの: 0 件
走査しなかった範囲: C09 --deep, C07 --projects, C14 --containers, C15 --exposure
このツールは侵入の有無を調べません。修正版に更新しても、更新前の侵入の痕跡は消えません。
```
