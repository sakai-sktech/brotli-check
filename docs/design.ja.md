# 設計メモ — CVE-2026-111497 点検スクリプト

English: [design.md](design.md)

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

### 2.1 公開前の再確認（2026-10-27）

2026-10-27 に公開されたジェイ・メディックの技術解説（10/26 は 18 行目のとおり 404）と既知データを突き合わせたところ、
解説にある Ubuntu の告知がデータに無かった。そこで全行の一次資料を確かめ直し、スナップショットを 2026-10-27 にした。誤った判定はすでに
このリポジトリに出ていた: 10/27 に Ubuntu 24.04 の統合テストのイメージで取った `docs/sample-output.md` は、`libbrotli1` の
`1.1.0-2ubuntu0.1`（作り直したイメージが `noble-security` から取り込んだ修正版）を `NO_FIX_AVAILABLE`「配布元が修正版をまだ出して
いません」と出している。レビューも統合テストも気づかなかった。`no_fix` の行では入っている版によらず `NO_FIX_AVAILABLE` になるので、
期待した判定のとおりだったため。変わったもの:

| 行 | 以前（2026-10-26） | いま（2026-10-27）→ データ | 出典 |
|---|---|---|---|
| 10 Ubuntu | 「Needs evaluation」、USN なし → `no_fix` | USN-8956-1（2026-10-26）で**修正**: jammy 1.0.9-2ubuntu0.1、noble 1.1.0-2ubuntu0.1、resolute 1.2.0-3ubuntu0.1、stonking 1.2.0-4ubuntu0.1（brotli・libbrotli1・python3-brotli）→ `fixed`。10/25 に ubuntu-security-proposed PPA にあった候補と同じ版。これらのリリースの Ubuntu の nodejs は「Not affected」（システムのライブラリを使い、それは C01 が判定する） | ubuntu.com/security/notices/USN-8956-1、ubuntu.com/security/CVE-2026-111497 |
| 8 Debian sid / forky | 1.2.0-4.1 はアーカイブ未着 → `unreleased` | sid はアーカイブに 1.2.0-4.1 → `fixed`。forky はまだ 1.2.0-4 → `unreleased` のまま | security-tracker.debian.org、sources.debian.org/api/src/brotli/ |
| 3 Bun | ソースの分析 → `analysis` | Bun の告知 GHSA-663w-cv8g-jj2p（2026-10-23 公開。影響 1.0.21 以上 1.4.4 未満。`bun build --compile` の実行ファイルは作り直すまで影響が残る）→ `fixed`。10/26 はリリースノートを読んでいて見落とした。ソースの分析とも一致。1.0.21 より前は範囲外だが、データが系列単位なので 1.4.4 より前のほかの版と同じに出る | github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p |
| 18 背景資料 | 404 | 公開（速報版、2026-10-27）。README からリンク。この更新の後の既知データと版は一致 | jmedic.co.jp/pubdoc/http2shell_report_20261027.html |

確かめ直して変わらなかったもの: Google Brotli のタグ（v1.0.10／v1.1.1／v1.2.1、2026-10-21 公開）、GHSA-9v8h-qqgm-4m35、
PYSEC-2026-4322／4323、Node.js の告知と EOL 系列の一覧、Debian bookworm／trixie、Envoy GHSA-3wvj-j6qm-62mr、
ISTIO-SECURITY-2026-007、Chromium の `README.chromium`（cfa184a9）、Firefox の `moz.yaml`（4792c8e4）。

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
bin/brotli-cve-check          入口（開発用）。lib/*.sh と data を読み、bcc_main を呼ぶ
lib/main.sh                   オプション解析 → 各検出項目 → 出力 → 終了コード
lib/core.sh                   共通（実行の制限 bcc_probe / bcc_sys、find の共通除外、ホームの列挙）
lib/index.sh                  名前で探すものの索引（1 回の find。10 章の 1）
lib/findings.sh               所見の蓄積（配列）と集計
lib/version.sh                版比較（dpkg / semver / PEP 440 の必要部分）
lib/data.sh                   advisories.tsv の読み込みと判定
lib/elf.sh                    ELF 判定、動的リンクの推移的な解決、文字列による推定
lib/check_c01_c03.sh … lib/check_c14_c15.sh   検出項目（2〜4 項目ずつ）
lib/output.sh                 テキストと JSON の出力
lib/i18n.sh                   メッセージカタログ（en / ja。連想配列）
data/advisories.tsv
scripts/build-dist.sh         1 ファイル版の生成（data は heredoc で埋め込み）
Makefile                      lint（shellcheck）、test（bats）、dist、integration
```
（ファイルの分け方は実装時に上のとおり整理した。計画時は検出項目ごとに 1 ファイル、出力はテキストと JSON で別ファイルだった。）

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
- `no_fix` — 配布元が修正版を出していない（2026-10-26 までの Ubuntu 全版。2026-10-27 時点では該当なし）→ NO_FIX_AVAILABLE
- `unreleased` — 修正版の番号は示されているがアーカイブ未着（Debian forky の 1.2.0-4.1。sid は 2026-10-27 まで）。
  インストール済みの版が `fixed` 以上なら FIXED、それ未満なら NO_FIX_AVAILABLE
- `derived` — 一次資料の一般的な記述からの導出（Node.js の EOL 系列）。結果の理由欄に note を出す
- `analysis` — ベンダーの告知ではなくソースツリーの分析（Chromium / Firefox。Bun は 2026-10-27 まで）。結果にその旨を明記

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
`_ERROR_FORMAT_BLOCK_SWITCH` がある → LIKELY_FIXED。`_ERROR_FORMAT_` 系が無い（8 個未満）→ VENDORED_COPY（関数ごと削られている。10 章の 5）。
確度は検証結果に応じて書く。検証が崩れたら推定は実装せず VENDORED_COPY だけを出す。

**C10 Envoy** — 2 章 13 のとおり、勧告の修正版で判定（食い違いは無かった）。1.35 以前は `derived`（Envoy の旧版は 1.0.9 / 1.1.0 を同梱）。

**C11 圧縮専用の製品** — 一次資料で確認できたのは ngx_brotli（libbrotlienc のみ）と mod_brotli（圧縮フィルタのみ）、
Traefik（Go 実装の andybalholm/brotli）。HAProxy と Caddy は実装時に上流ソースで確認し、確認できなければ
NOT_APPLICABLE ではなく「情報」として版だけ出す。さらに配布元パッケージの nginx・Apache は `ldd` で libbrotlidec を引いていないことを実測で確かめる。

**C13 ブラウザ** — Chromium の基準は 148.0.7778.0（2 章 15）。

**C14 / C15** — 依頼文どおり。Alpine ベースのコンテナ（apk）は初版では対象外とし、UNKNOWN（理由つき）。

## 7. 読み取り専用を守る仕組み

- 書き込みは標準出力と `--output` のファイルだけ。一時ファイルは作らない（プロセス置換と変数で済ませる）。
- 見つけたプログラムの実行は 1 か所の関数（`bcc_probe`）を通し、`timeout` と許可リスト（`--version` 系、`dpkg-query`、`ldd` など）で縛る。
  見つけたプログラムは、事実とともに一覧に示して同意を得たものだけを実行する（`lib/exec.sh`、10 章 11）。`--no-exec` のときは一切実行しない。
- システムの道具は `/usr/sbin:/usr/bin:/sbin:/bin`（root しか変更できなければ `/usr/local/{sbin,bin}` も）から使い、
  呼び出し側の `PATH` からは使わない（10 章 9）。
- `find` は `-xdev`・`-P`（シンボリックリンクを辿らない）を基本にし、`/proc /sys /dev /run` を除外。
  nfs / cifs / fuse.sshfs などは `--include-remote` が無ければ除外（`/proc/self/mountinfo` で判定）。
  探す場所の下にマウントされたローカルディスクのファイルシステムも探し、それ以外のマウントと `--exclude` の場所は
  「走査しなかった範囲」に並べる（10 章 9）。ELF 探索は既定 512 MiB を上限にし、超えたファイルも並べる。
- 見つけたファイルは、通常のファイルだけを、制限時間の下でサイズの上限まで読む（`bcc_read_file`、10 章 9）。
- 環境変数は読まない（呼び出し側の `PATH` は判定するプログラムを探す場所として使うだけ）。コマンドラインは `--show-cmdline` のときだけ。
- 他ユーザーのホームは `getent passwd` で列挙し、読めなければ SKIPPED に積む。

### 7.1 依頼文の解釈（実装時に確定・2026-10-26）

- **`--no-exec` が止めるのは「見つけたプログラム」の実行。** node・bun・curl・envoy・ブラウザの `--version`、
  見つけた実行ファイルへの `ldd`、コンテナ内での実行を止める。システムの照会コマンド
  （dpkg-query・dpkg・readelf・ldconfig・ss・snap・flatpak・docker ps）は止めない（依頼文 2 章 4 の
  「見つけたプログラムの実行」の範囲外と読む）。`--no-exec` が無いとき、見つけたプログラムは一覧から人が選んだもの
  （または `--yes`）だけを実行する（10 章 11）。`--inspect-containers` はコンテナの中で固定のスクリプトを走らせる
  （その指定が同意）。`--no-exec` と `--yes` の同時指定はエラー。
- **外部コマンドはすべて `LC_ALL=C` で動かす。** 開発機の readelf は出力が日本語化されていた（「共有ライブラリ」）。
  見つけたプログラムは `env -i` で環境変数を空にして動かす（`NODE_OPTIONS` などの影響を受けないため）。
- **`--output` は既存のものを上書きも、開きもしない。** 同じディレクトリに一時ファイルを排他的に作って書き、
  目的の名前にハードリンクする（link(2) は既存の名前があれば種類を問わず失敗し、シンボリックリンクも辿らない）。
  sticky bit の無い、他人が変更できるディレクトリには書かない。保存先から `/` までのすべての階層が root
  （root 以外で動くときは本人）の所有であること、sticky のディレクトリも所有者が root か本人であることを求め、
  実体のパスに解決したディレクトリに書く（自動セキュリティレビューの指摘）。（当初は bash の noclobber だったが、Codex の
  レビューで、noclobber は既存の FIFO やデバイスを開いてしまう＝引数の確認後に置かれたディスクへのシンボリック
  リンクに root が書き込みうると分かった。）以下は当初の記述: root で動かしたときに、
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

結果: [verification.ja.md](verification.ja.md)。

## 9. 決定事項（2026-10-26 本人回答）

1. **リポジトリ名は `brotli-check` のまま。** 依頼文の仮名 `brotli-cve-2026-111497-check` と通称 HTTP2Shell / Node2Shell は README のキーワードとしてだけ載せる。実行ファイル名は依頼文どおり `brotli-cve-check`。
2. **依頼文の HTML は `.gitignore` で除外。** 手元に原本として残し、OSS のリポジトリには載せない。
3. **開発用の道具:** shellcheck と bats は本人が apt で入れる。統合テストの Docker Desktop は本人が起動する。
4. **C09 の検証のためのダウンロードは可。** google/brotli のソースと Node.js 公式バイナリ 22.23.3 / 22.23.4 をスクラッチ領域へ。開発時だけで、ツール本体はネットワークを使わない。
5. advisories.tsv の note 列と `unreleased` 状態は 5.1 のとおり（設計の了承に含む）。
6. **文書の言語（同日に決定）:** docs/ は英語を正とし、日本語版を `.ja.md` で並べる（既存の `README.ja.md`・`for-clinics.ja.md` と同じ命名）。日本の利用者も読みに来るため。この設計メモも `design.md`（英語）と `design.ja.md`（本書）の 2 本。

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
   かつ一般ユーザー実行時の他人のファイルを防げない）。**10 章 11 で置き換えた**（2026-10-27）: ツールは事実を示し、
   人が決める。こうした規則でツールが決めることはやめた。
4. **版は製品ごとに決めた行の形からだけ読む。** Chrome は版の前にログ行（`[1026/070739.474907:WARNING:…]`）
   を出し、最初の数字を拾う実装は偽の FIXED を出した。Chromium は 4 部の版でなければ UNKNOWN。
5. **C09: ファイル名の版と文字列の推定が食い違えば UNKNOWN。** 修正を取り込んだ独自ビルドを、どちらか一方で
   誤判定しないため。推定は `_ERROR_FORMAT_` 系が 8 個以上あるときだけ（検証した全ビルドは 16 か 17、または 0）。
6. **C11 は製品名ではなくファイルで判定する。** バイナリとモジュールにデコーダーの印があるか、
   libbrotlidec を引くかを見る（依頼文の「圧縮専用だから NOT_APPLICABLE」を実測で裏づける）。**10 章 9 の 5 で
   細かくした**: 印が無いときに NOT_APPLICABLE とするのはパッケージのファイルと、cgo の Brotli を使わない Go の
   プログラムだけ。自前のビルドは UNKNOWN。
7. **テキスト出力の制御文字は `?` にする**、案内文の中のパスとパッケージ名は `%q` でクォートする
   （同レビューの指摘）。JSON は RFC 8259 のエスケープ。
8. **単一ファイル版は `lib/*.sh` とデータの連結**（`scripts/build-dist.sh`）。shellcheck はファイル単位
   （SC2034・SC2004 を除く）と、まとめた版（全項目）の両方で警告ゼロにする。
9. **Codex の敵対的レビュー 4 回目（2026-10-26）: 指摘 10 件、すべて確認して修正**
   （2 時間・ソースは stdin。P1 × 6、P2 × 4）。うち 3 つ（1・5・9）は本人の判断。
   1. **root では見つけたプログラムを `--allow-exec` が無ければ実行しない。**（10 章 11 で置き換えた） 10 章 3 の条件が覆うのはファイルと
      上位のディレクトリで、読み込むコードではない。root 所有の `/opt/app/bin/node` の RUNPATH が一般ユーザーの
      書ける `/opt/app/lib` を指していれば、そのユーザーのライブラリのコンストラクタが root で動く。実行するとき
      （一般ユーザーの既定、root の `--allow-exec`）は、ローダー（PT_INTERP）、RUNPATH/RPATH のすべてのディレクトリ
      （ld.so が先に試す glibc-hwcaps・tls などの下位ディレクトリを含む）、ここで解決した必要なライブラリすべて、
      `/etc/ld.so.preload` も同じ条件に通す。readelf が無ければ実行しない。理由: 検査を広げても dlopen や実行時に
      読むファイルは見えず、誤りの代償がいちばん大きいのが root。root の既定で失うもの: root 所有の bun・envoy・
      curl・ブラウザの `--version`（Node.js の公式 tarball は uid 1001 所有なので元々 root では実行していない）。版は
      ヘッダー・パッケージの記録・パス・文字列から取る。捨てた案: 検査を広げて root でも既定で実行（dlopen は見えない
      まま）、root では一切実行しない（正確な版を得る手段が無くなる）。
   2. **システムの道具は `/usr/sbin:/usr/bin:/sbin:/bin` から使う。** `/usr/local/{sbin,bin}` は root しか変更できない
      ときだけ末尾に足す。呼び出し側の `PATH` は探索にだけ使う。readelf・stat・timeout は `--no-exec` でも動くので、
      root の `PATH` に他人が書ける場所があれば差し替えられる（前提は root の `PATH` がすでに危ないことだが、直すのは安い）。
   3. **`--output` に `ln -T`。** 無いと GNU ln は、保存先の名前に後から置かれたディレクトリの中にリンクを作る
      （`/tmp` のシンボリックリンク版は `fs.protected_symlinks` で止まるが、ディレクトリ版では報告の置き場がずれた）。
   4. **C01 に任せるのは、C01 が実際に判定したパッケージのものだけ。** どの dpkg 所有者でも C09 は libbrotlidec を、
      C06 は PyPI の Brotli を飛ばしていたため、ベンダーの `.deb`（`/opt/<vendor>/embedded` に自前の Python を持つ
      エージェントなど）は一度も判定されなかった。そうしたコピーはパッケージ管理外と同じに判定し、案内には更新すべき
      パッケージ名を出す。`--deep` も `libbrotlidec*` を名前で飛ばさない。
   5. **印が無いことは証明ではない。** C11 が NOT_APPLICABLE と言うのはビルドが分かっているものだけ: パッケージの
      ファイル、または Go のビルド情報に cgo の Brotli（`github.com/google/brotli/go/cbrotli`）が無い Go のプログラム。
      印の無い自前ビルドのサーバーは UNKNOWN。捨てた案: サーバーはすべて UNKNOWN（nginx・Apache のあるホストが
      どれも終了コード 2 になり、「要確認」が読まれなくなる）、NOT_APPLICABLE のまま文言だけ変える（依頼文の C11 の字義どおり）。
      C08: NOT_APPLICABLE は `curl -V` が brotli を挙げないときだけ。実行しておらず印も無ければ UNKNOWN（静的にリンク
      した curl はデコーダーのシンボル名を持たず、`BrotliDecoderErrorString` も使わない）。1 つのファイルに複数のコピー:
      リンカーが同じ文字列をまとめるので、修正済みのコピーが未修正のコピーを隠す。Brotli の辞書のコピー（コピー
      1 つに 1 個。libbrotlicommon と Node.js は 1）を数え、2 個以上なら LIKELY_FIXED や、パス・メタデータからの FIXED を UNKNOWN にする。
   6. **プレリリースは後ろを残し、正式版として扱わない。** Bun `1.4.4-rc.1`、Firefox `150.0a1`・`150.0b3`・Debian の
      `150.0~b3`、Node.js `v26.0.0-nightly…`、`NODE_VERSION_IS_RELEASE 0` のヘッダー（`X.Y.Z-pre` と読む）は後ろが
      落ちて FIXED になりえた。修正版と同じ番号のプレリリースは UNKNOWN、それより前の版のものは VULNERABLE、後の版の
      ものは FIXED。アーカイブ名のプラットフォーム部分（`-linux-x64`）は外し、ディレクトリ名の X.Y.Z の後ろに
      それ以外があればプレリリースとみなす。
   7. **見つけたファイルの読み取りに上限を付ける**（`bcc_read_file`）: 通常のファイルだけを、`timeout` の下の
      `head -c` で開いて（確認の後に FIFO に差し替えられても止まらない）、サイズの上限まで読む。文字列の走査は
      `sort` を使わない 1 回の読み取り（重複しない名前は 64 個まで数える）で、grep と awk は 256 MiB のアドレス空間の
      上限の下で動かす（ファイル全体が 1 行の巨大な文字列のとき）。最後まで読めなかったファイルは UNKNOWN にし、
      一部の文字列で判定しない。捨てた案: `tr -s` や `fold` で行の長さを抑える（130 MB の node で 7 倍遅い）。
   8. **失敗は「走査しなかった範囲」に出す。** dpkg-query が 2 以上で終わる（または時間切れ）と「どれも入っていない」
      と読まない。find が読めなかったディレクトリは例つきで数える（走査中に消えたファイルは数えない）。`--deep` の
      探索の時間切れも記録する。
   9. **除外した範囲を並べ、探す場所の下のローカルディスクは探す。** 探す場所の下にマウントされたローカルディスクの
      ファイルシステム（ext4・xfs・btrfs・zfs など。`--include-remote` ならネットワークのものも）は、それ自体を探す
      場所として歩く（`-xdev` はマウントポイントで止まるため）。それ以外（tmpfs・overlay・squashfs・fuse）は種類ごとに
      件数つきで 1 行。`--exclude` の場所と、`--deep` で上限を超えたファイルも並べる。捨てた案: 下のマウントをすべて
      並べて `--roots` での指定を促す（`/srv` の下のデータディスクは探す場所の意味のうち）。対象外: マウントではない
      btrfs のサブボリューム（`-xdev` が止まり、mountinfo にも出ない）。
   10. **コンテナの中の確認スクリプトは POSIX sh で書く。** `command -v -a` は dash にも busybox にも無い。エラーを
      捨てていたため、コンテナの中の Node.js は所見にも「走査しなかった範囲」にも出ず、単体テストは模擬の出力を
      渡すだけでスクリプトを走らせていなかった。`PATH` を自分で回し、実体のパスで重複を除き、最後に `END` を出す。
      `END` の無い出力は「走査しなかった範囲」に出す。単体テスト（dash）と統合テスト（各イメージの `/bin/sh`、本物の
      Node.js）でスクリプトそのものを走らせる。

   依存の検査で、開発機の所要は最初 3 倍近くになった（20 秒 → 51 秒）。パスの各階層を 1 回の `stat` で調べる、
   `dirname` のプロセスを使わない、ライブラリ・ディレクトリ・依存ツリーごとにキャッシュする、で約 20 秒に戻した。
10. **Codex の敵対的レビュー 5 回目（2026-10-26）: 指摘 10 件。9 件を修正し、1 件は報告のしかたで答えた。**
    4 回目の 2・3・4・9・10 は修正済みと確認された。残りは以下の指摘に含まれる。うち 2 つ（5・8）は本人の判断。
    1. **パスの途中の symlink も、置かれた場所で検査する。** `bcc_safe_path` は親を先に実体のパスへ直していたため、
       RUNPATH `/srv/shared/current/lib` の `current` が他人の書けるディレクトリにあっても、root 所有のリリースを
       指している間は通った。いまは `/` から 1 段ずつたどり、ディレクトリを検査してからその中のリンクを辿る。
    2. **RUNPATH/RPATH の空の項目があれば実行しない。** ld.so は空の項目（`:/x`、`/x:`、`/x::/y`）を作業ディレクトリと
       読む（実験で、そこに置いたライブラリが読み込まれた）。そうしたプログラムは実行せず、実行するもの（版の表示、
       `ldd`）は `/` から起動する。
    3. **ファイルから読んだ版は、文字列で確かめられたときだけ FIXED。** パス・ヘッダー・メタデータ・ファイル名が
       「修正済み」を示しても、文字列に修正のエラー名があり Brotli のコピーが 1 つのときだけ FIXED。エラー名が無い、
       コピーが複数、最後まで読めなかった、のいずれかなら UNKNOWN とし、分かったことと分からなかったことを書く
       （実装記録の「修正の印が無ければ UNKNOWN」どおり。コードはエラー名がまったく無いとき FIXED のままにしていた）。
       読み切れなかったファイルは「走査しなかった範囲」にも出し、C11 は一部しか読めなかったファイルを「印なし」とみなさない。
    4. **conda に任せるのは記録があるときだけ。** `lib/libbrotlidec*` の隣に空の `conda-meta/` があるだけで見えなく
       なっていた。C06 がその環境の記録を報告したときだけ C09 は任せる。
    5. **文字列から分かることは「分かったこと／分からないこと」で書く**（本人の判断。「たぶん修正済み」のまま残すか、
       すべて UNKNOWN にするかの二択ではなく）。状態の名前は依頼文と JSON のものなので変えない。理由は例えば
       「分かったこと: 修正で追加されたエラー名がある。Brotli の辞書は 1 個。分からないこと: ファイルの中のデコーダーが
       すべて修正済みかどうか（同じ文字列はまとめられるため）」とし、案内から「修正済みの可能性が高い」を外した。
       辞書を共有する 2 つのデコーダーは見分けられない。そのことは結果と limitations.ja.md に書き、無いことにはしない。
    6. **「C01 で判定」と言うのは、C01 が判定したライブラリだけ。** RUNPATH 経由で（探す場所の外にあることもある）
       自前の libbrotlidec を読み込むプログラムを「OS の libbrotlidec」と言っていた。そのコピーはその場で（C09 と
       同じに）判定し、見つからなければ UNKNOWN。
    7. **Chromium:** Debian 式の `~` の付いた版はプレリリース（Chromium 自身のチャンネルは 4 部の数字だけで、`-rc` の形は無い）。
    8. **`--data`: 読み取りに上限を付け、拒まずに警告する**（本人の判断）。FIFO や大きすぎるファイルは開く前に
       断り、上限つきの子プロセスで読む。root（または実行者）以外が変更できるデータファイル（ファイル自体か置き場所の
       ディレクトリ。`--output` と同じ条件）は使うが、そのことを結果の冒頭に出す（JSON は `data_writable_by_others`）。
       点検は確かめるもので、他人が書き換えうるファイルの正しさまでは保証しない。捨てた案: root ではそうしたファイルを拒む。
    9. **完走した実行の中の失敗も報告する:** `--deep` の grep のエラー（xargs が「見つからない」と同じ終了状態に
       まとめていた）、コンテナの中の `dpkg-query` の失敗（スクリプトが終了状態を出す）。
    10. **シンボリックリンクの探索場所はリンク先を歩く**（`find -P` は起点に渡した symlink の中へ降りない。
       `/srv -> /data/srv` のホストではツリーごと黙って抜けていた）。除外する場所も同じく解決し、リンクだった探索場所は結果に出す。
11. **見つけたプログラムの実行: 事実を示して、人が決める（2026-10-27、本人の判断。10 章 3 と 10 章 9 の 1 を置き換える）。**
    6 回の敵対的レビューで、どの見つけたプログラムなら実行して「安全」かをツール自身が決める規則には、毎回穴が見つかった。
    本体の所有者、次にライブラリ、RPATH、途中の symlink、空の項目、継承される RPATH と直すたびに問いが移るだけで決着せず、
    ツールが下した判断は、誰も頼んでいない留保として結果に現れた。本人の思想: ツールは点検する。そのためにすることは、
    理由とともに、する前に示す。結果を人に返し、判断は人がする。そこで:
    - 検出項目が、版を読むために実行したいプログラムを挙げる（node・bun・envoy・ブラウザの `--version`、curl の `-V`）。
      OS の libbrotlidec を読み込むパッケージの node・curl と、パッケージのブラウザは挙げない（判定がそれに依らない）。
    - それぞれに事実を付ける: root（または実行者）のほかに、本体・パスの途中のディレクトリ・読み込むライブラリ・それを
      探すディレクトリを書き換えられる人（カーネルと glibc の ld.so と同じたどり方。継承される DT_RPATH を含む）、空や
      相対の探索先、調べられなかったこと。
    - 端末があれば人が選ぶ（全部・しない・番号）。端末が無ければ `--yes` か `--no-exec` が要り、無ければ一覧を示して止まる
      （終了コード 3）。実行したいものが無ければ何も尋ねない。
    - 選ばれたものだけを、`/` から、環境変数を空にし、標準入力を閉じ、制限時間を付け、出力に上限を付けて実行する。結果には、
      実行したもの（出力つき）・しなかったものと理由・事実を出す（JSON は `execution`）。
    - `ldd` は使わない。ファイルをローダーに渡すので、名前が違うだけで実行と同じ。リンクは readelf だけで辿る。
    捨てた案: 規則で決める（上のとおり 6 回）、一切実行しない（ファイルからの版は弱く、人は実行を望むかもしれない）、尋ねずに全部
    実行する（人が事実を知るのは後になる）。ツール自身が使うシステムの道具は今までどおり決まったディレクトリから（10 章 9 の 2）。
    それはツールのもので、ホストで見つけたものではない。
12. **Codex の敵対的レビュー 6 回目（2026-10-26〜27）: 10 章 11 の思想の下で直した。** 実行に関わる指摘（途中の
    symlink・壊れたリンク・継承される RPATH）は、尋ねる前に示す事実になった。ほかは修正: 読み取りが最後まで終わったかは、
    各段の終了状態だけで決め、データの中の印には頼らない（ファイルが偽造できる）。ファイルから読んだ版は、Firefox
    （`application.ini` を `libxul.so` で）・flatpak のランタイム・conda の記録でもデコーダーで確かめる。libbrotlidec を
    読み込みつつ自前のデコーダーのエラー名も持つファイルは、そのコピーも判定する。ファイル名と違う名前で読み込まれる
    libbrotlidec も判定する。候補は、リンクを解決する前と後の両方の名前で照合する（`node -> node-22.0.0` のような別名は残し、
    mise の `node -> mise` のような多役の shim は外す。この修正の最初の版は `mise --version` を node として実行しかけ、新しい
    結果の一覧ですぐ見えた）。パスは NUL 区切りで運び、改行入りのパスでも分かれない。コンテナの dist-packages を配布元の
    ものとみなすのは python3-brotli が入っているときだけ。一部しか読めなかった Envoy の設定を「Brotli 無し」と言わない。
    `snap list`・`flatpak list`・`ss` の失敗は「走査しなかった範囲」に出す。Electron の snap を `/snap/名前/current`
    （symlink。`find -P` は入らない）経由でも見つける（初版からの見落とし）。
13. **実行したいプログラムの一覧とその事実は、見つけたパスがどんなバイトを含んでいても正しく示す（2026-10-27。10 章 11・12 の
    commit 後の自動セキュリティレビューの 2 件と、それを確かめる中で見つけたもの）。** 一覧は人が判断する画面（10 章 11）なので、
    そこに出るものはそこにあるものでなければならず、実行するものは示したものでなければならない。直す前にこの端末で確かめたこと:
    - 一覧はそのまま端末に出ていた。ディレクトリ名に仕込んだエスケープ列が端末に届き、質問の上の事実を書き換えられた。
      いまは結果と同じ濾過（制御文字を `?`）を通し、パスや事実の中のタブと改行も `?` にする（パスが、別のプログラムや
      事実に見える行を出せないように）。所見の欄もタブと改行を `?` にした（これまでは空白）。同じパスが結果のどこでも
      同じに見える。
    - 改行を含むパスでは、事実が減るだけでなく**誤った**事実が出ていた。`IFS=/ read` が改行で止まるので短いパスを調べて
      「`/…/a` は存在しない」と言い、`\037` でつないだ事実を `read` で読み戻すと最初の改行より後が消えた。事実は配列で持つ
      （`BCC_FACT_POOL`。キャッシュはその範囲を持つ）。パスはパラメータ展開で分ける。
    - 確かめる中で見つけたもの（レビューには無い）: **パスにタブがあると別のプログラムが実行された。** 計画の項目は
      「パス<TAB>引数」で、最初のタブで分けていたので、`/x/evil<TAB>dir/bin/bun` ならそのパスを示したうえで `/x/evil` を
      引数 `dir/bin/bun<TAB>--version` で実行していた。項目のキーは照合にだけ使い、プログラムと引数は別に持つ
      （`BCC_PLAN_BIN`、`BCC_PLAN_ARG`）。
    - 依存の辿りは記録をタブ区切りの行で、ライブラリが受け継ぐ探索先を `:` でつないだ文字列で持っていた。改行を含む
      ディレクトリの下で `$ORIGIN` の RUNPATH を持つプログラム（Electron・Chromium によくある）では、違うディレクトリの事実が
      出た。記録と受け継ぐ探索先は配列にし、ライブラリの探索のキャッシュのキーは各部分を長さ付きで並べる（`$ORIGIN` 経由の
      ディレクトリは `:` を含みうるので、違う探索が同じキーにならないように）。
    - 同じ関数の中の小さなもの: 改行で終わる symlink の先が `$(...)` で改行を失っていた。40 を超える symlink の連鎖（カーネルも
      そこで止まる）や読めないリンクで、辿りが黙って終わり、「調べた範囲では root だけ」だけが残りえた（いまは事実として出す）。
      ライブラリのディレクトリの `[` や `*` が、`glibc-hwcaps` を探すときに glob の記号として扱われていた。readelf の
      `Library runpath: [値]` を貪欲な `.*\[` で読んでいたので、`/opt/app [1]/lib` が相対の探索先 `1]/lib` になり、本当の
      ディレクトリは調べていなかった（新しいテストで分かった）。値は最初の `[` から行末の `]` まで。
    確かめたこと: 新しいテストはどれも直す前のコードで落ち、直した後で通る。開発機での `--no-exec --json` は、直す前と後で
    `execution`（32 件とその事実）と所見 64 件が同じで、所要も同じ。残したもの（次のレビューで見る）: リンクされた libbrotlidec の
    パスをチェックへ「パス<TAB>readelf」で渡し、最初のタブで分けている。解決した名前が改行で終わる候補は `$(...)` で改行を失う。
    ELF の中の値（RPATH・NEEDED・PT_INTERP）に改行があると readelf の行の出力で切れる。どれも名前を作り込む必要があり、
    どの場合も、実行されるのは一覧に示したプログラムのまま。
14. **10 章 11〜13 の変異テスト（2026-10-27、テスト記録 13 章）。** 修正を 1 つずつ写しの中で戻し、単体テストを全件走らせた。
    変異 91 個（4・5 回目のもののうち今も当てはまるものを含む）のうち 69 個で落ちた。落ちなかった 21 個は、同意の形（選んだ
    プログラムの動かし方、計画に挙げないもの、実行しなかったものの記載）と、事実・依存の辿り（root や実行者以外の所有者、
    ローダー、ライブラリそのもの、相対の探索先、`/etc/ld.so.preload`、RUNPATH が RPATH を隠すこと、深さの上限、受け継ぐ
    ディレクトリの `:`、RPATH の `[`）にあった。テストを 10 件足し（root か手作りの ELF でしか作れない場合は偽の `stat`・`readelf`
    で）、測り直した 22 個はすべて落ちた。コードの変更は 2 つ: テストで `/etc/ld.so.preload` を `BCC_LD_PRELOAD_FILE` で
    差し替えられるようにした（`/proc` を `BCC_PROC_ROOT` で差し替えるのと同じ）。計画の中で終了状態を見ない
    `bcc_dpkg_owner` を `|| true` と書いた（動作は同じ。bats の `set -e` の下でも動く）。
