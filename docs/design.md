# 設計メモ — CVE-2026-111497 点検スクリプト

- 状態: **了承済み** 2026-10-26（9 章の未決事項も同日に決定）
- 依頼文: `brotli_check_script_prompt_20261026.html`（株式会社ジェイ・メディック、2026-10-26）
- この文書の位置づけ: 依頼文「12. 作業の進め方」の手順 2。了承を得るまで実装に入らない。

## 1. 目的と、やらないこと

Ubuntu 22.04 / 24.04 / 26.04（と Debian 12 / 13）の 1 台のホストで、CVE-2026-111497 に該当しうる
Brotli デコーダーのコピーを**読み取り専用で**洗い出す。

やらないこと（依頼文 2 章の絶対条件をそのまま設計の制約にする）:
インストール・更新・削除・再起動・設定変更／ネットワークアクセス／他ホストの走査／
攻撃データの生成・取得・同梱／侵入の有無の調査／「安全」という表示。

## 2. 一次資料の再確認結果（2026-10-26 確定分）

依頼文 8 章の既知データとの差分と、本人の確認・指示（2026-10-26）を反映した確定事項。
取得日はすべて 2026-10-26（JST）。`data/advisories.tsv` の各行に URL と取得日を持たせる。

| # | 項目 | 依頼文 8 章 | 確認結果 → データへの反映 | 根拠 |
|---|---|---|---|---|
| 1 | Google Brotli | 1.0.10 / 1.1.1 / 1.2.1 | 一致。修正コミットは系列ごとに b418fa81（v1.2.1）／da980636（v1.1.1）／50a9b70a（v1.0.10）。0ed4268a は main 上の元コミット | github.com/google/brotli/releases、Debian tracker の notes |
| 2 | PyPI Brotli / brotlicffi | 1.2.1 / 1.2.1.0、PYSEC-2026-4322 / 4323 | 一致（4322=brotli、4323=brotlicffi） | `pypa/advisory-database` の `vulns/brotli/PYSEC-2026-4322.yaml`、`vulns/brotlicffi/PYSEC-2026-4323.yaml`（raw） |
| 3 | Bun | 1.4.4 | 一致。ただし根拠はリリースノートではなく**ソース**: タグ `bun-v1.4.4` の `scripts/build/deps/brotli.ts` が `db24a98a`（v1.2.1）、`bun-v1.4.3` が `028fb5a2`（v1.2.0） | raw.githubusercontent.com/oven-sh/bun/bun-v1.4.4/scripts/build/deps/brotli.ts |
| 4 | Node.js 修正版 | 22.23.4 / 24.22.1 / 26.12.1 | 一致 | nodejs.org/en/blog/vulnerability/october-2026-security-releases |
| 5 | Node.js の EOL 系列 | 20 以前・21・23・25 は修正なし | 告知に系列の名指しは無い。「EOL は常に影響」＋修正版が出ていない、からの**導出**として `status=derived` と根拠を明記 | 同上 |
| 6 | `process.versions.brotli` | 修正版でも "1.1.0" | 一致。nodejs/node タグ v22.23.4 の `deps/brotli/c/common/version.h` が 1.1.0、`decode.h` に `BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17)`。v22.23.3 の `decode.h` は `/* -17 code is reserved */`。（v24.22.1 の version.h は 1.2.0。系列ごとに値が違うので判定に使えない） | raw.githubusercontent.com/nodejs/node/v22.23.{3,4}/deps/brotli/… |
| 7 | Debian bookworm / trixie | +deb12u1（DLA-4855-1）／+deb13u1（DSA-6582-1） | 一致 | security-tracker.debian.org/tracker/CVE-2026-111497 |
| 8 | Debian sid / forky | 1.2.0-4 は未修正 | tracker の「Fixed Version」表に `brotli source (unstable) 1.2.0-4.1`（bug 1151690）の行がある（2026-10-25T21:40Z 取得）。一方、アーカイブ（sources.debian.org/api/src/brotli/）は forky / sid とも 1.2.0-4 のみ。**アーカイブに入るまで未修正扱い**（→ 5.1 の `unreleased`） | 同 tracker、sources.debian.org |
| 9 | Debian の nodejs | （記載なし） | tracker 上は全版 vulnerable（unstable は unfixed・unimportant、notes「nodejs uses system provided brotli library」）。依存は nodejs ではなく libnode108 / libnode115 に付く。**判定は dpkg の Depends ではなく ldd の推移的な解決結果で行う** | 同 tracker、packages.debian.org |
| 10 | Ubuntu | 全版 Needs evaluation、USN なし | 一致（jammy / noble / resolute / 26.10 stonking とも brotli・nodejs が Needs evaluation）。noble の brotli は 1.1.0-2build2（このホストの実測も同じ） | ubuntu.com/security/CVE-2026-111497、launchpad.net/ubuntu/+source/brotli |
| 11 | Amazon Linux | 勧告なし | **更新**: AL2023 brotli ALAS2023-2026-3334、nodejs24 ALAS2023-2026-3330（2026-10-24, Fixed） | explore.alas.aws.amazon.com/CVE-2026-111497.html |
| 12 | Alpine | edge 1.2.1-r0（3.23/3.24 は要確認） | 3.23 / 3.24 / edge とも 1.2.1-r0、secdb に記載あり | pkgs.alpinelinux.org、secdb.alpinelinux.org |
| 13 | Envoy | 勧告と公式タグに食い違い | **食い違いは無かった**。v1.36.12 / 1.37.8 / 1.38.6 / 1.39.3 のタグはすべて Brotli を `42a2ed43` に固定（0ed4268a の 129 コミット先＝修正を含む）。v1.38.5 は 1.2.0。依頼文の「食い違いが残っていれば UNKNOWN」の条件に当たらないので、**勧告どおり FIXED** とする | GHSA-3wvj-j6qm-62mr、各タグの `bazel/repository_locations.bzl`、GitHub compare API |
| 14 | Istio | 1.31.2 / 1.30.6 / 1.29.9 | 一致（ISTIO-SECURITY-2026-007、2026-10-15。Envoy の勧告より早い） | istio.io |
| 15 | Chromium | Stable 148 以降 | 一致。148.0.7728.2（開発初期）は未取り込み、148.0.7778.96 は取り込み済み。基準は **148.0.7778.0 以上**とし、148 の開発版で番号が小さいものは UNKNOWN | third_party/brotli/README.chromium（タグごと） |
| 16 | Firefox | 150.0 / ESR 140.10 | 一致（149.0 と ESR 140.9 は未取り込み） | modules/brotli/moz.yaml（タグごと） |
| 17 | RHEL 系 | RHSA-2026:2042 等は別件 | 一致（CVE-2025-6176）。RHEL の本件の修正勧告は見当たらない | access.redhat.com |
| 18 | 背景資料 | jmedic.co.jp/pubdoc/… | 404（未公開）。参照しない | — |

確認できなかったもの: CVE.org / NVD のレコード本体（JS 必須で取得不可）、packages.ubuntu.com（HTTP 500。
Ubuntu の python3-brotli と nodejs の依存関係は、ホスト上の実測で分岐する設計にして回避する）、
HAProxy・Caddy が C 実装のデコーダーを含まないことの一次資料（→ 6 章 C11）。

## 3. このホストでの実測から足したこと

開発機（Ubuntu 24.04.5）で読み取りだけ行って分かった、依頼文に無い要件。

1. **mise の Node.js / Python を探索場所に足す**（`~/.local/share/mise/installs/{node,python}/*`）。
   mise・asdf は `22` → `22.17.1` のような別名のシンボリックリンクを並べるので、**実体のパスで重複を除く**。
2. **dpkg 管理下の dist-packages を C06 で読まない。** Ubuntu の python3-brotli は
   `/usr/lib/python3/dist-packages/Brotli-1.1.0.egg-info`（Version: 1.1.0＝上流の版）を置く。
   これを PyPI の基準 1.2.1 と比べると、ディストリが修正しても VULNERABLE と誤判定する。
   `dpkg -S` で所有パッケージがあるものは C06 から外し、C01 の判定に任せる。
3. **公式 tarball の Node.js は `--no-exec` でも版が分かる。** 実行ファイルの隣の
   `../include/node/node_version.h` に `NODE_{MAJOR,MINOR,PATCH}_VERSION` がある。
4. 公式 Node.js と python3-brotli の `_brotli*.so` はどちらも libbrotlidec を動的リンクせず、
   `_ERROR_FORMAT_` で始まる文字列を含む。C09 の推定（6 章）が効く可能性がある。

## 4. 全体構成

```
bin/brotli-cve-check          入口。オプション解析 → 各検出項目 → 出力 → 終了コード
lib/core.sh                   共通（ログ、timeout 付き実行、find の共通除外、ユーザーのホーム列挙）
lib/findings.sh               所見の蓄積（配列）と集計
lib/version.sh                版比較（dpkg / semver / PEP 440 の必要部分）
lib/data.sh                   advisories.tsv の読み込みと参照
lib/elf.sh                    ELF 判定、動的リンクの推移的な解決、文字列探索
lib/check_c01_dpkg.sh … lib/check_c15_exposure.sh   検出項目ごとに 1 ファイル
lib/output_text.sh, lib/output_json.sh
lib/i18n.sh                   メッセージカタログ（en / ja。連想配列）
data/advisories.tsv
Makefile                      lint（shellcheck）、test（bats）、dist（1 ファイルに結合。data は heredoc で埋め込み）
```

- bash 4.2 以上（連想配列・`declare -g` を使う）。依存は coreutils / findutils / grep / awk / sed。
  binutils（readelf / strings）が無ければ `grep -a` などで代替し、精度が落ちる旨を SKIPPED／理由に出す。
- `set -u` と `set -o pipefail` を使う。`set -e` は使わない（検出項目の失敗で全体を止めず、UNKNOWN／SKIPPED に落とすため）。
- 所見 1 件はフィールドをタブ区切りにした 1 要素として配列に積む:
  `id status component path version reason next_step evidence confidence`。
  JSON は自前でエスケープして出力する（jq に依存しない）。

## 5. データ（data/advisories.tsv）

### 5.1 列

依頼文の 6 列（部品、系列、修正版、状態、一次資料 URL、取得日）に、**根拠（note）** を 1 列足す
（`derived` などの判定根拠を書く場所が要るため）。

| 列 | 例 |
|---|---|
| component | `node` / `bun` / `pypi:brotli` / `deb-src:brotli` / `envoy` / `chromium` … |
| branch | `22`、`debian:trixie`、`ubuntu:noble`、`*` |
| fixed | `22.23.4`、`1.1.0-2+deb13u1`、`-`（修正なし） |
| status | `fixed` / `no_fix` / `unreleased` / `derived` / `analysis` |
| source_url | 一次資料の URL |
| retrieved | `2026-10-26` |
| note | 根拠の短文 |

`status` の意味:
- `fixed` — 一次資料が修正版を示している
- `no_fix` — 配布元が修正版を出していない（Ubuntu 全版など）→ NO_FIX_AVAILABLE
- `unreleased` — 修正版の番号は示されているがアーカイブ未着（Debian sid / forky の 1.2.0-4.1）。
  インストール済みの版が `fixed` 以上なら FIXED、それ未満なら NO_FIX_AVAILABLE
- `derived` — 一次資料の一般的な記述からの導出（Node.js の EOL 系列）。結果の理由欄に note を出す
- `analysis` — ベンダーの告知ではなくソースツリーの分析（Chromium / Firefox / Bun）。結果にその旨を明記

### 5.2 データの鮮度

結果に `data_snapshot_date`（最古の retrieved ではなくファイル先頭の宣言日）を出し、
30 日以上古ければ警告する。`--data FILE` で差し替え可。

## 6. 検出項目ごとの設計（依頼文 3 章からの変更点を中心に）

依頼文どおりのところは書かない。変更・具体化したところだけ。

**C01 OS パッケージ** — `/etc/os-release` の `ID` と `VERSION_CODENAME` で系列を決める。
`dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\n'` で取り、
**ソースパッケージの版**（`source:Version`）を tracker の修正版と比べる（バイナリ側に `+b2` などが付いても正しく比べるため）。
未知の系列は UNKNOWN（理由: データに無い系列）。

**C02 libbrotli1 に依存するパッケージ（情報）** — `dpkg-query -W -f '${Package}\t${Depends}\n'` から抽出。
`libnode*` も含める（Debian の nodejs はここを経由する）。

**C04 Node.js** — 探索場所に mise・asdf を追加し、実体パスで重複を除く。
版の取得: 既定は `node --version`（timeout 付き）。`--no-exec` のときは `../include/node/node_version.h`、
nvm / mise / asdf のディレクトリ名の順に試し、どれも無ければ UNKNOWN。
**配布元パッケージの node**（`dpkg -S` で所有者がいるもの）は、libbrotlidec に**推移的に**リンクしているかで分岐する:
既定は `ldd`（glibc の ldd は実行ファイル自身の PT_INTERP を使わずシステムの ld.so に `--list` させる。
main は走らない）。`--no-exec` のときは `readelf -d` の NEEDED を `ldconfig -p` と RUNPATH で自前で辿る（精度が落ちる旨を表示）。
動的なら C01 に委ね、静的なら版で判定する。

**C06 Python** — mise / pyenv / uv（`~/.local/share/uv/{python,tools}`）を探索場所に追加。
dpkg 管理下のものは除外（3 章の 2）。PEP 440 は、リリース番号の末尾のゼロを詰めて比較する
（1.2.1 と 1.2.1.0 は等しい）。プレリリースはリリースより小さい。ローカル版（`+…`）は無視。

**C09 同梱コピーの汎用探索と修正有無の推定** — 推定の仮説:
修正版の decode.c は `BrotliDecoderErrorString` の中で `#PREFIX #NAME` から文字列を作るので、
修正版のバイナリには `_ERROR_FORMAT_BLOCK_SWITCH` が現れる。未修正版では -17 が予約（`/* -17 code is reserved */`）なので現れない。
依頼文の検証手順 (a)(b)(c) を実装前に行い、結果を `tests/fixtures/c09/` と `docs/limitations.md` に残す:
- (a) v1.2.0 / v1.2.1 のソース比較（上の点まで確認済み。v1.1.1 / v1.0.10 の `decode.h` も確認する）
- (b) v1.2.0 / v1.2.1 を自分でビルド（共有・静的 × strip 有無 × -O2 / LTO）して `strings` を比較
- (c) Node.js 公式バイナリ 22.23.3 / 22.23.4 で比較
判定: `_ERROR_FORMAT_` 系の文字列が**ある**のに `_ERROR_FORMAT_BLOCK_SWITCH` が無い → LIKELY_VULNERABLE。
`_ERROR_FORMAT_BLOCK_SWITCH` がある → LIKELY_FIXED。`_ERROR_FORMAT_` 系が 1 つも無い → UNKNOWN（関数ごと削られている）。
確度は検証結果に応じて書く。検証が崩れたら推定は実装せず VENDORED_COPY だけを出す。

**C10 Envoy** — 2 章 13 のとおり、勧告の修正版で判定（食い違いは無かった）。1.35 以前は `derived`（Envoy の旧版は 1.0.9 / 1.1.0 を同梱）。

**C11 圧縮専用の製品** — 一次資料で確認できたのは ngx_brotli（libbrotlienc のみ）と mod_brotli（圧縮フィルタのみ）、
Traefik（Go 実装の andybalholm/brotli）。HAProxy と Caddy は実装時に上流ソースで確認し、確認できなければ
NOT_APPLICABLE ではなく「情報」として版だけ出す。さらに配布元パッケージの nginx・Apache は `ldd` で libbrotlidec を引いていないことを実測で確かめる。

**C13 ブラウザ** — Chromium の基準は 148.0.7778.0（2 章 15）。

**C14 / C15** — 依頼文どおり。Alpine ベースのコンテナ（apk）は初版では対象外とし、UNKNOWN（理由つき）。

## 7. 読み取り専用を守る仕組み

- 書き込みは標準出力と `--output` のファイルだけ。一時ファイルは作らない（プロセス置換と変数で済ませる）。
- 外部コマンドの実行は 1 か所の関数（`run_probe`）を通し、`timeout` と許可リスト（`--version` 系、`dpkg-query`、`ldd` など）で縛る。
  `--no-exec` のときはこの関数が見つかったプログラムを一切実行しない。
- `find` は `-xdev`・`-P`（シンボリックリンクを辿らない）を基本にし、`/proc /sys /dev /run` を除外。
  nfs / cifs / fuse.sshfs などは `--include-remote` が無ければ除外（`/proc/self/mountinfo` で判定）。
  ELF 探索は既定 512 MiB を上限にする。
- 環境変数は読まない（自分の `PATH` を除く）。コマンドラインは `--show-cmdline` のときだけ。
- 他ユーザーのホームは `getent passwd` で列挙し、読めなければ SKIPPED に積む。

### 7.1 依頼文の解釈（実装時に確定・2026-10-26）

- **`--no-exec` が止めるのは「見つけたプログラム」の実行。** node・bun・curl・envoy・ブラウザの `--version`、
  見つけた実行ファイルへの `ldd`、コンテナ内での実行を止める。システムの照会コマンド
  （dpkg-query・dpkg・readelf・ldconfig・ss・snap・flatpak・docker ps）は止めない（依頼文 2 章 4 の
  「見つけたプログラムの実行」の範囲外と読む）。
- **外部コマンドはすべて `LC_ALL=C` で動かす。** 開発機の readelf は出力が日本語化されていた（「共有ライブラリ」）。
  見つけたプログラムは `env -i` で環境変数を空にして動かす（`NODE_OPTIONS` などの影響を受けないため）。
- **`--output` は既存のファイルを上書きしない**（noclobber）。root で動かしたときに、
  他人が置いたシンボリックリンク経由で別のファイルを壊さないため。
- **テスト用の差し替え口**として `BCC_PROC_ROOT`・`BCC_OS_RELEASE`・`BCC_HOME_DIRS`・`BCC_MOUNTINFO`・`BCC_TODAY`
  だけは環境変数から読む（7 章の「環境変数は読まない」の例外。いずれもツール自身の変数）。
- **C09 の名前による探索は常に行う。** `libbrotlidec.so*` を dpkg 管理外（/usr/local、/opt、conda など）で
  ファイル名から探すのは軽いので既定で行い、ファイル名の版で判定する。ELF の中身を読む汎用探索だけを `--deep` にする。
- **C02 と「C01 に委ねる」判定は所見ではなく情報として出す。** 所見にすると、apt の 1 回の更新で直るものを
  「更新が必要」として二重に数えるため。JSON では `findings[]` と別に `info[]` に入れる。

## 8. テスト計画

- 単体: bats-core。偽の `dpkg-query`・`node`・`bun`・`ldd` を PATH の先頭に置く。偽の dist-info、偽の `/proc`（`BCC_PROC_ROOT`）。
- C09: 上の (b)(c) の結果を fixture（抽出した文字列の一覧）として固定し、判定関数をテスト。
- 統合: ubuntu:22.04 / 24.04 / 26.04、debian:12 / 13（タグ実在は確認済み）。未修正・修正版の Node.js、
  Brotli 1.2.0 / 1.2.1 の仮想環境を入れたイメージで期待どおりの判定になるか。
- どのテストも細工した Brotli データを使わない。
- CI: GitHub Actions で shellcheck / bats / 統合テストのマトリクス。

## 9. 決定事項（2026-10-26 本人回答）

1. **リポジトリ名は `brotli-check` のまま。** 依頼文の仮名 `brotli-cve-2026-111497-check` と通称 HTTP2Shell / Node2Shell は README のキーワードとしてだけ載せる。実行ファイル名は依頼文どおり `brotli-cve-check`。
2. **依頼文の HTML は `.gitignore` で除外。** 手元に原本として残し、OSS のリポジトリには載せない。
3. **開発用の道具:** shellcheck と bats は本人が apt で入れる。統合テストの Docker Desktop は本人が起動する。
4. **C09 の検証のためのダウンロードは可。** google/brotli のソースと Node.js 公式バイナリ 22.23.3 / 22.23.4 をスクラッチ領域へ。開発時だけで、ツール本体はネットワークを使わない。
5. advisories.tsv の note 列と `unreleased` 状態は 5.1 のとおり（設計の了承に含む）。
6. 文書の言語: 未決のまま。この設計メモは日本語。docs/ を英語にそろえるかは公開前に決める。

## 10. 実装時に加えた判断（2026-10-26）

設計の了承後、実装と実機での試験で分かったことによる変更。決めたこと／理由／捨てた案の順。

1. **名前で探すものは 1 回の find で索引にする**（`lib/index.sh`）。理由: 検出項目ごとに find すると
   /home（約 245 万ファイル）を何度もなめ、さらにパスごとの `dpkg-query -S`（1 回約 1 秒）が重なって
   60 秒かかった。索引化とホーム配下への dpkg 問い合わせの省略で 20 秒台。node / bun / envoy も
   `--roots` 全体から名前で探すことにし、VS Code Server・CI ランナー・Playwright が抱える Node.js を拾えるようにした。
   捨てた案: 探索場所の列挙だけで済ませる（実機で見落としが多かった）。
2. **パッケージ管理のキャッシュ（pip・uv・poetry・npm・yarn）は所見にしない。** ダウンロード物で、
   インストール済みのものは別に見つかるため。件数だけ情報に出す。
3. **見つけたプログラムを実行する条件**（自動セキュリティレビューの指摘による）。ファイルと上位の
   ディレクトリがすべて root（root 以外で動くときは実行者）所有で、他者が書き込めないこと。グループ書き込みは
   root で動くときは一律に不可、一般ユーザーで動くときは所有者専用グループ（名前が本人と同じ・本人の主グループ・
   同じ GID の項目が 1 つ・他のメンバーなし）に限る（同レビューの 2 回目の指摘で root 側を厳格に戻した）。パスは正規化済みであることを要求し、検査したパスそのものを実行する（TOCTOU 対策）。
   `ldd` も同じ条件。理由: root で動かすと、一般ユーザーが置き換えた node を root が `--version` で
   実行しうる。捨てた案: root のときは一律に `--no-exec`（自分のホームのものも実行できず不便、
   かつ一般ユーザー実行時の他人のファイルを防げない）。
4. **版は製品ごとに決めた行の形からだけ読む。** Chrome は版の前にログ行（`[1026/070739.474907:WARNING:…]`）
   を出し、最初の数字を拾う実装は偽の FIXED を出した。Chromium は 4 部の版でなければ UNKNOWN。
5. **C09: ファイル名の版と文字列の推定が食い違えば UNKNOWN。** 修正を取り込んだ独自ビルドを、どちらか一方で
   誤判定しないため。推定は `_ERROR_FORMAT_` 系が 8 個以上あるときだけ（検証した全ビルドは 16 か 17、または 0）。
6. **C11 は製品名ではなくファイルで判定する。** バイナリとモジュールにデコーダーの印があるか、
   libbrotlidec を引くかを見る（依頼文の「圧縮専用だから NOT_APPLICABLE」を実測で裏づける）。
7. **テキスト出力の制御文字は `?` にする**、案内文の中のパスとパッケージ名は `%q` でクォートする
   （同レビューの指摘）。JSON は RFC 8259 のエスケープ。
8. **単一ファイル版は `lib/*.sh` とデータの連結**（`scripts/build-dist.sh`）。shellcheck はファイル単位
   （SC2034・SC2004 を除く）と、まとめた版（全項目）の両方で警告ゼロにする。
