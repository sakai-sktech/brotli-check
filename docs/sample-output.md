# Sample output

Captured on 2026-10-27 from the integration image for Ubuntu 24.04 (`tests/integration/`),
scanned as root with `--roots /opt,/srv --yes` (no terminal in the container, so the consent
to run the listed programs is given in advance). The image holds Node.js 22.23.3 and 22.23.4
from nodejs.org and PyPI Brotli 1.2.0 (with urllib3) and 1.2.1 in two virtual environments.
Exit status: 1.

The first section lists the programs the tool ran to read their versions, their output, and the
facts shown before asking: here the Node.js tarballs keep their packager's owners (non-root
uids, which in this image happen to be the users ubuntu and tester), and the report says so. At a terminal, without `--yes`, the same list is shown first and you choose.

## English (default)

```
brotli-cve-check 0.1.0 - read-only local check for CVE-2026-111497 (Brotli decoder)
Host: Ubuntu 24.04.5 LTS [ubuntu:noble], kernel 6.10.14-linuxkit, running as root
Data: snapshot 2026-10-26 (1 days old), embedded
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
[NO_FIX_AVAILABLE] C01 | libbrotli1 | dpkg (ubuntu:noble) | 1.1.0-2ubuntu0.1 | The distributor has not released a fix yet. | Wait for the distributor's fix; meanwhile, update products that bundle their own copy first.
[NO_FIX_AVAILABLE] C01 | python3-brotli | dpkg (ubuntu:noble) | 1.1.0-2ubuntu0.1 | The distributor has not released a fix yet. | Wait for the distributor's fix; meanwhile, update products that bundle their own copy first.

== C04 Node.js ==
[VULNERABLE] C04 | node | /opt/node-v22.23.3-linux-x64/bin/node | 22.23.3 | Below the fixed version 22.23.4. | Update to 22.23.4 or later.
[FIXED] C04 | node | /opt/node-v22.23.4-linux-x64/bin/node | 22.23.4 | At or above the fixed version 22.23.4. | -

== C06 Python packages (PyPI, conda) ==
[FIXED] C06 | brotli | /srv/venv-new/lib/python3.12/site-packages/brotli-1.2.1.dist-info | 1.2.1 | At or above the fixed version 1.2.1. | -
[VULNERABLE] C06 | brotli | /srv/venv-old/lib/python3.12/site-packages/brotli-1.2.0.dist-info | 1.2.0 | Below the fixed version 1.2.1. | In the environment that owns /srv/venv-old/lib/python3.12/site-packages, run: pip install -U "brotli>=1.2.1"
[EXPOSURE] C06 | python-http-clients | /srv/venv-old/lib/python3.12/site-packages | - | Brotli is installed here, so these HTTP clients decode Brotli responses from remote servers automatically: urllib3. | Not a vulnerability by itself: update the decoder it uses (other findings) with priority.

== Information ==
[INFO] C02 | Installed packages depending on libbrotli1 (1), fixed by the libbrotli1 update plus a restart: libcurl4t64
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
Needs human review: 2
Not scanned: C09 --deep, C07 --projects, C14 --containers, C15 --exposure
This tool does not check for intrusion. Updating to a fixed version does not remove traces of an intrusion that happened before the update.
```

## 日本語（`--lang ja`）

```
brotli-cve-check 0.1.0 - CVE-2026-111497（Brotli デコーダー）の読み取り専用ローカル点検
ホスト: Ubuntu 24.04.5 LTS [ubuntu:noble]、カーネル 6.10.14-linuxkit、root で実行
既知データ: 2026-10-26 時点（1 日前）、embedded
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
[NO_FIX_AVAILABLE] C01 | libbrotli1 | dpkg (ubuntu:noble) | 1.1.0-2ubuntu0.1 | 配布元が修正版をまだ出していません。 | 配布元の修正を待つ。待つ間は、同梱コピーのある製品を優先して更新する。
[NO_FIX_AVAILABLE] C01 | python3-brotli | dpkg (ubuntu:noble) | 1.1.0-2ubuntu0.1 | 配布元が修正版をまだ出していません。 | 配布元の修正を待つ。待つ間は、同梱コピーのある製品を優先して更新する。

== C04 Node.js ==
[VULNERABLE] C04 | node | /opt/node-v22.23.3-linux-x64/bin/node | 22.23.3 | 修正版 22.23.4 より古い版です。 | 22.23.4 以上に更新する。
[FIXED] C04 | node | /opt/node-v22.23.4-linux-x64/bin/node | 22.23.4 | 修正版 22.23.4 以上です。 | -

== C06 Python のパッケージ（PyPI・conda） ==
[FIXED] C06 | brotli | /srv/venv-new/lib/python3.12/site-packages/brotli-1.2.1.dist-info | 1.2.1 | 修正版 1.2.1 以上です。 | -
[VULNERABLE] C06 | brotli | /srv/venv-old/lib/python3.12/site-packages/brotli-1.2.0.dist-info | 1.2.0 | 修正版 1.2.1 より古い版です。 | /srv/venv-old/lib/python3.12/site-packages を持つ環境で pip install -U "brotli>=1.2.1" を実行する。
[EXPOSURE] C06 | python-http-clients | /srv/venv-old/lib/python3.12/site-packages | - | この環境には Brotli が入っているため、次の HTTP クライアントは外部から取得した応答を自動で展開します: urllib3。 | それ自体は脆弱性ではない。使っているデコーダー（ほかの所見）の更新を優先する。

== 情報 ==
[INFO] C02 | libbrotli1 に依存するパッケージ（1 個）。libbrotli1 の更新と再起動で直ります: libcurl4t64
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
人の確認が必要なもの: 2 件
走査しなかった範囲: C09 --deep, C07 --projects, C14 --containers, C15 --exposure
このツールは侵入の有無を調べません。修正版に更新しても、更新前の侵入の痕跡は消えません。
```
