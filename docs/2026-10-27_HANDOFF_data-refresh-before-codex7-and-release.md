---
title: brotli-cve-check 引き継ぎ — 現在地・既存資料の読み方・次の一手（データ更新と変異テストの後、Codex 7 回目とリリースの前）
date: 2026-10-27
status: handoff (next session starts here)
audience: 文脈を持たない次セッションの LLM / 後日の本人
related_files:
  - docs/2026-10-27_path-bytes-mutation-tests-and-data-refresh.md
  - docs/2026-10-27_checker-reports-facts-human-decides.md
  - docs/design.ja.md（2.1、10 章 11〜14）
  - docs/2026-10-26_test-record_codex-round4-5.html（12・13 章）
  - data/advisories.tsv
tags: [handoff, reading-guide, release, codex-review, advisory-data, mutation-testing]
---

# brotli-cve-check 引き継ぎ（データ更新と変異テストの後、Codex 7 回目とリリースの前）

> **次セッションはまずこれを読め。** これ＋「最初に読む 3 点」で文脈が立ち上がる。
> 前の引き継ぎ `docs/2026-10-27_HANDOFF_after-codex-round6-consent-model.md` は凍結（後継＝本書）。その §4（運用）の細部は本書 §4 に移した。

## 0. 30 秒サマリ

- **何か:** CVE-2026-111497（Brotli の C デコーダーの範囲外書き込み）に該当しうるデコーダーのコピーを、Ubuntu/Debian のホスト 1 台から
  読み取りで洗い出す bash ツール `brotli-cve-check`。GitHub は **public**（sakai-sktech/brotli-check）。**v0.1.0 は未リリース**。
  会社（株式会社ジェイ・メディック）の速報記事 https://www.jmedic.co.jp/pubdoc/http2shell_report_20261027.html が README からリンクされた
  （記事＝何が問題か、GitHub＝自分の環境をどう調べるか）。
- **このセッション（2026-10-27 午後〜夜）でしたこと:**
  1. 前の引き継ぎ §5-0（自動セキュリティレビュー 2 件）を直した。確かめる中で、**タブを含むパスで一覧と違うプログラムが実行される**欠陥など
     同根（パスのバイトを区切りに使う）の欠陥も直した（設計メモ 10 章 13、`882a479`、push 済み・CI 緑）。
  2. **変異テスト**（テスト記録 13 章）: 91 個中 69 個で落ちた。穴 21 個にテスト 10 件を足し、測り直した 22 個はすべて落ちた（設計メモ 10 章 14）。
  3. 本人が共有した ChatGPT（本人は「チャッピー」と呼ぶ）の助言を読むために会社の記事を読み、**既知データの誤り**を見つけた: Ubuntu は
     **USN-8956-1（2026-10-26）**で修正済みなのに、データは「修正待ち（no_fix）」。公開済みの `docs/sample-output.md` が修正版を
     `NO_FIX_AVAILABLE` と出していた。全行の一次資料を確かめ直し、**スナップショット 2026-10-27**（Ubuntu fixed、Debian sid fixed、Bun は公式告知）。
  4. README に記事リンクと「**棚卸しの道具で、攻撃データが届くかは判定しない**」を明記。図解 2 枚（英日）を今の事実で**作り直し、同名で上書き**。
- **いまの段階:** 単体 172/172、統合 26/26、ShellCheck 0、変異 22/22（第 2 回）。このセッションの変更は session-close で commit・push する
  （本書の §4 の git の行を参照）。**次は Codex 7 回目 → リリース v0.1.0。**

## 1. 最初に読む 3 点

1. **`docs/2026-10-27_path-bytes-mutation-tests-and-data-refresh.md`**（このセッションの実装記録）— 何をなぜ直し、何を捨てたか。
   棄却記録（`read -d $'\037'` を採らなかった理由など）と Key Learnings（期待値が同じデータから出るテストはデータの古さを検出できない）が重要。
2. **`docs/2026-10-27_checker-reports-facts-human-decides.md`**（前のセッションの壁打ち記録）— 本人の思想「点検ツールは事実を返し、判断は人がする」。
   **このプロジェクトでツールの責務を考えるときの基準**。Codex 7 回目の依頼文の基準もここから来る。
3. **`docs/design.ja.md` の 2.1 と 10 章 11〜14**（英語版 `design.md` が正）— 2.1 は 2026-10-27 の既知データの再確認（何が変わり、どう見つけたか）。
   10 章 11 は同意モデル、12 は Codex 6 回目、13 はパスのバイト、14 は変異テスト。

コードを触る前に `lib/exec.sh` の冒頭のコメント（同意モデルの 4 段）と、`lib/findings.sh` の `bcc_init_findings`（配列・キャッシュの宣言。
事実と依存の辿りの記録は配列で、キャッシュは「start count」の範囲）を読むこと。

## 2. 既存資料の読み方（docs マップ・実在を ls で確認済み）

| ファイル | 中身 | 状態 |
|---|---|---|
| `docs/design.md` / `design.ja.md` | 設計メモ。2 章 一次資料の再確認（**2.1 = 2026-10-27 の再確認**）、5 章 データの列と状態、7 章 読み取り専用、10 章 実装時の判断（1〜14） | ✅ 正（英語が正）。10 章 3 と 9 の 1 は 10 章 11 で置き換え（本文に注記）。5.1 の例は 10/27 の状態に更新済み |
| `docs/limitations.md` / `.ja.md` | 見落としうるもの・判定できないもの。Bun の 1.0.21 より前の扱いを追記 | ✅ 正 |
| `docs/json-schema.md` / `.ja.md` | `--json` の形式。`execution[]` の path・facts は正確、`findings` 等の欄はタブ・改行を `?` | ✅ 正 |
| `docs/verification.md` / `.ja.md` | 検証結果。「読み方」は 2026-10-27 時点（OS のコピーは 5 OS とも修正済み）。統合の表の Ubuntu 行は 10/27 の実測 | ✅ 正（10/27） |
| `docs/sample-output.md` | Ubuntu 24.04 の統合イメージでの出力（`--yes`、データ 10/27）。前の取得で修正版を NO_FIX と出していたことを冒頭に注記 | ✅ 正（10/27 取り直し） |
| `docs/2026-10-26_test-record_codex-round4-5.html` | **テスト記録（本人の依頼）**。1〜10 章 10/26、11 章 同意モデル、**12 章 §5-0 の修正、13 章 変異テスト（実測から生成）**。冒頭に訂正の注記 | 記録（13 章まで）。1〜11 章の Ubuntu の NO_FIX は 10/26 のデータによる（注記済み） |
| `docs/zukai/01_*`, `02_*` | A4 図解 2 枚（英日・HTML/PDF/PNG）。**2026-10-27 に作り直して同名で上書き**（同意モデル、棚卸し、5 OS 修正済み、統合 26 項目） | ✅ 正（10/27） |
| `README.md` / `README.ja.md` | 使い方、記事リンク、**棚卸しで到達性は判定しない**、`--yes` を使う前に、結果の読み方、版の判定方法、既知データ 2026-10-27 | ✅ 正（`--yes` の注意書きの文体は本人の確認待ち） |
| `CHANGELOG.md` | 0.1.0（未リリース）の内容。データ 2026-10-27 の行あり | ✅ 正（日付は未記入） |
| `data/advisories.tsv` | 既知データ。**snapshot 2026-10-27、全行の retrieved 2026-10-27** | ✅ 正 |
| `tests/integration/README.md` | 統合テストの中身。Ubuntu の期待は FIXED。**キャッシュされた古いイメージは作り直す**注意を追記 | ✅ 正 |
| `docs/2026-10-27_path-bytes-mutation-tests-and-data-refresh.md` | 実装記録（このセッション） | 記録（凍結） |
| `docs/2026-10-27_codex-review-round4-6-and-consent-model.md` | 実装記録（前のセッション: Codex 4〜6 回目、同意モデル） | foundational。冒頭に訂正注記（Ubuntu の (b) 案は不要に） |
| `docs/2026-10-27_checker-reports-facts-human-decides.md` | 壁打ち記録（前のセッション） | foundational（**責務の基準**） |
| `docs/2026-10-27_HANDOFF_after-codex-round6-consent-model.md` | 前の引き継ぎ | ⚠️ 凍結（後継＝本書。§3-9 に訂正、§5 に進捗の注記） |
| `docs/2026-10-26_brotli-cve-check-initial-implementation.md` | 初版の実装記録 | foundational。**実行の扱いの節は撤回バナー**、**Ubuntu の修正待ちは訂正バナー** |
| `docs/2026-10-26_reading-results-and-reviewing-before-release.md` | 結果の読ませ方・レビューの待ち方（壁打ち） | foundational（Ubuntu の記述に訂正バナー） |
| `docs/2026-10-26_HANDOFF_release-readiness.md` | 最初の引き継ぎ | ⚠️ 凍結（訂正バナー付き） |
| `docs/for-clinics.ja.md` | 医療機関・中小企業向けの説明 | ✅ 正（Ubuntu の状況は書いていない） |
| `tests/fixtures/c09/README.md` | C09 文字列推定の検証記録 | ✅ 正 |
| `.context/codex-review-2026-10-26-round4/5/6.md`、`codex-round4-triage-2026-10-26.md` | **Codex の指摘の全文（verbatim）**と検討メモ | 🔒 手元だけ（`.git/info/exclude`）。**push しない・公開しない** |
| `~/ダウンロード/ChatGPT-Brotli速報版OSS公開!-20261027-1600.md` | 本人が共有した ChatGPT の助言（リポジトリ外） | 一次原本（本人の資料）。取捨は実装記録の 5 |
| memory `reply-in-japanese.md` | 本人向けの報告・質問は日本語で（AskUserQuestion の選択肢も） | ✅ 正 |

撤回・訂正のまとめ: (1) 初版実装記録の「実行の条件」→ 10 章 11 で置き換え。(2) **「Ubuntu は修正待ち」→ 2026-10-26 の USN-8956-1 で修正済み**
（10/26 の記録すべてと前の引き継ぎに訂正バナー）。(3) テスト記録の変異テストの番号は、推測でなく実測で書く（4 章で一度誤り、取り直した）。

## 3. 確定している知見（訂正後の最新）

1. **ツールの責務**（本人の思想・最優先）: 点検ツールは、必要なことを理由とともに示し、事実を返し、判断は人がする。ツールが「安全」を規則で
   決めて黙って実行をやめる・留保を付ける、はしない。**変更する操作（`--output` の書き込み）はツールが厳格に守る**。
2. **棚卸しであって露出の判定ではない**（README に明記）: 見つけたデコーダーに攻撃者のデータが届くかは判定しない。経路は 3 つ（圧縮された
   リクエスト、取りに行って自動で展開する応答、展開 API を直接呼ぶ処理）。EXPOSURE は手がかり。
3. **実行（`lib/exec.sh`）**: 検出項目が版を要するプログラムだけを挙げ、事実を付けて一覧 → 端末で選ぶ／`--yes`／`--no-exec`／端末なしで
   指定なしは一覧を出して exit 3。実行は `/` から、`env -i`、stdin 閉、timeout、出力 64 KiB。**実行するものは `BCC_PLAN_BIN`/`BCC_PLAN_ARG` から
   取り、計画のキーは分けない**（タブ入りのパスで別のプログラムを実行した欠陥の修正）。
4. **パスは NUL 以外のどんなバイトも含みうる**: 事実（`BCC_FACT_POOL`）・依存の辿りの記録（`BCC_WALK_K/_A/_B`）・受け継ぐ探索先は配列で持ち、
   区切り文字でつながない。表示のときだけ制御文字・タブ・改行を `?`（一覧も結果も）。JSON の execution は正確、所見の欄は `?`。
5. **依存の辿り**: glibc の ld.so の順（要求側 DT_RPATH → 読み込み元の DT_RPATH を実行ファイルまで → DT_RUNPATH → キャッシュ → 既定。
   DT_RUNPATH があればその DT_RPATH と継承は使わない）。readelf だけ。**ldd は使わない**。readelf の `[値]` は最初の `[` から行末の `]` まで。
6. **既知データ（2026-10-27）**: Ubuntu 22.04/24.04/26.04/26.10 は **USN-8956-1 で修正済み**（1.0.9-2ubuntu0.1 / 1.1.0-2ubuntu0.1 /
   1.2.0-3ubuntu0.1 / 1.2.0-4ubuntu0.1）。Debian 12/13・sid 修正済み、forky は移行待ち（unreleased）。Bun は GHSA-663w-cv8g-jj2p（1.0.21〜1.4.3）。
   上流 1.0.10/1.1.1/1.2.1、Node.js 22.23.4/24.22.1/26.12.1、PyPI 1.2.1/1.2.1.0、Envoy・Istio・Chromium・Firefox は 10/26 から変わらず。
   **~~Ubuntu は全リリース修正待ち~~（撤回: 10/26 の取得時点のもの）。**
7. **期待値が同じデータから出るテストは、データの古さを検出できない**（no_fix の行では、入っている版が修正版でも NO_FIX になり期待どおり）。
   データの誤りは独立した出典との突き合わせで見つかった。**公開前・リリース前に既知データを一次資料で確かめ直す**。
8. **確度の書き方**: 文字列推定は「分かったこと／分からないこと」で書く（状態名 LIKELY_FIXED は残す）。ファイルから読んだ版で FIXED にするのは
   文字列が 1 コピーで修正を示すときだけ。読み取りの完了は各段の終了状態で決め、データ中の印は使わない。
9. **版番号を信じない**: ソースパッケージの版で比べる、`process.versions.brotli` は使わない（ChatGPT の助言にあったが、この CVE では誤り）、
   プレリリースは正式版扱いしない。
10. **`--yes`** は一覧を見ずに全部実行する同意。README の「`--yes` を使う前に」に平易に書いた（本人判断: コードで除外せず説明で足りる）。
11. **撤回済み**: 「root では既定で実行しない（`--allow-exec`）」（10 章 11 で置き換え。`--allow-exec` は存在しない）。

## 4. 運用・インフラ状態

- **git**: `882a479`（§5-0 の修正）まで push 済み、CI 緑。**このセッションの残りの変更（データ更新、テスト 10 件、文書、図解、記録、本書）は
  session-close で 1 つの commit にまとめて push する**（次セッションは `git log -3` と `gh run list -L 2` で確かめる）。`.context/` は exclude 済み。
- **CI**: `.github/workflows/ci.yml` の 3 ジョブ（lint-and-unit、integration（5 イメージ）、bash42）。integration は毎回イメージを新しく作るので、
  Ubuntu は修正版が入り FIXED になる（期待どおり）。CI のランナーには `/usr/local/bin/node` があるので、CLI テストで `--no-exec`/`--yes` を
  付け忘れると「端末が無い」で exit 3 になる。
- **開発**: `make lint`（ShellCheck 0 であること）、`make test`（bats 172 件、約 6 分）、`make dist`、`make integration`（Docker 28.3.0、約 10 分）。
  統合のイメージは `bcc-it:<distro>`（`ubuntu-22-04` など）。1 つだけ: `ONLY=ubuntu:24.04 SKIP_BASH42=1 bash tests/integration/run.sh`。
  **イメージはキャッシュされる**: データを変えたら、古いパッケージのままのイメージを作り直すこと（`docker rmi bcc-it:...`）。いまのイメージは 10/27 に作ったもの。
- **テストの書き方**:
  - 端末のテストは `script -qec` の擬似端末（cli.bats）。Ubuntu の cc は `--as-needed` なので NEEDED を残すには `-Wl,--no-as-needed`。
  - root でしか作れない状況は偽物で作る: `fake_stat_others`（他の所有者を返す stat）、`fake_readelf` と `dyn`（`FILE.dyn` を動的セクションとして返す）、
    `BCC_LD_PRELOAD_FILE`（ld.so.preload の差し替え）。補助は `tests/unit/hardening.bats` の末尾。`has_fact`・`walk_records` も同じファイル。
  - bats では `! cmd` は失敗にならない（`[[ … ]]` で書く）。`set -e` の下で動くので、終了状態を捨てる呼び出しは `|| true`。
    `grep -q` にパイプで流さず here-string で渡す（pipefail で Broken pipe）。
  - **日付を決め打ちしない**（既知データの日付が変わると落ちる。stale data のテストはデータの snapshot から計算する形にした）。
- **変異テスト**: 写しはリポジトリ内 `tests/tmp/` に置く（`/tmp` の下だと「誰でも書ける」で事実が変わる）。今回の仕組みは
  `tests/tmp/mutrec27.F7vF/`（`muts27.py` に第 1 回の 91 個の定義、`baseline.sh`、`results.jsonl` が実測。`phase2/` は第 2 回で、`muts27.py` は
  NEEDED の 1 個を足した 92 個、`only.txt` で 22 個に絞る）。
  `python3 -I muts27.py check` で定義が当たるか確かめ、`python3 -I muts27.py 6` で 6 並列。先に `baseline.sh` で変異なしの全件成功を確かめる。
  13 章は `results.jsonl` から生成した（生成スクリプトはスクラッチにあり、消える。表の形は 13 章そのものを見れば再現できる）。
  `tests/tmp/` は git 管理外で、`make clean` で消える（古い写し `mut.*`・`mut5.*`・`mutrec.*`・数字のディレクトリも残っている）。
- **Codex**: この端末ではサンドボックスがコマンドを実行できない（Ubuntu 24.04 の `kernel.apparmor_restrict_unprivileged_userns = 1`）。codex スキルの
  Step 1.5 で確認し、`make dist` の単一ファイル版（約 170 KB）を stdin で渡す。`timeout 7200`、`--json` を jsonl に、run_in_background。
- **図解**: a4-zukai スキル（子エージェント、Opus。出典付きの配布物なので effort high）。PNG は `pdftoppm -r 120 -png -singlefile`（992×1404）。
- **WebFetch の要約は小さなモデル経由**: データを変える前に一次資料（USN、CVE ページ、tracker、GHSA）を自分で確かめる。sources.debian.org は
  `curl -fsS https://sources.debian.org/api/src/brotli/` で JSON が取れる。GitHub の告知・タグは `gh api` でも取れる。
- **この端末の対話シェルの `grep` は ugrep に置き換わっている**（手で計測するときは `/usr/bin/grep`）。計測は負荷で揺れるので HEAD と交互に。
- 実機（開発機・一般ユーザー）: `--no-exec --json` 約 25 秒、stderr 空、終了コード 1。`--yes` はこのセッションでは走らせていない。

## 5. 未解決スレッド / Next Steps（優先順）

1. **[実装に降ろす・最優先] Codex 7 回目**（単一ファイル版の全体）。**依頼文に新しい基準を書く**: P1 は「事実として誤った報告（結果・事実の一覧）／
   黙った抜け（走査しなかった範囲に出ない欠落）／同意なしの実行・示さない実行／`--output` 以外への書き込み・ハング」。設計判断として除外:
   同意モデルそのもの（`--yes` の意味は README に明記）、事実の網羅性の限界（dlopen・設定ファイル・`$LIB`・ld.so のキャッシュの選択）、
   LIKELY_FIXED を「分かったこと／分からないこと」付きで残すこと、`--data` は警告して使うこと、C11 の出どころ分け。**既知として伝える**:
   設計メモ 10 章 13 の末尾の 3 点、Bun の 1.0.21 より前。今日の変更（配列化、データ更新）も見てもらう。6 回目の 15 件の確認（FIXED/PARTIAL）も頼む。
   結果は `.context/codex-review-<日付>-round7.md` に全文、本人に verbatim で提示してから検討。
2. **[実装に降ろす] リリース v0.1.0**: **直前に既知データを一次資料で確かめ直す**（§3-7）。タグ、`dist/brotli-cve-check` と `dist/SHA256SUMS` を
   GitHub Release に添付、CHANGELOG の日付。README の Quick start がこれで 404 でなくなる。README に「Docker は不要、点検したいサーバーごとに
   走らせる」を 1 行（持ち越し）。リリースは外向きの操作なので本人に確認してから。
3. **[本人判断] README の「`--yes` を使う前に」の文体**（本人の要求「言い訳っぽくなく、分かりやすい言葉で丁寧に」に合っているか）。
4. **[本人判断] 状態名 LIKELY_FIXED を残すこと**（私の判断。本人の明示の同意は未）。
5. **[本人判断] 所見の欄のタブ・改行を `?` で表すこと**（このセッションの私の判断。本人は異を唱えず commit を指示したが、明示の同意ではない）。
6. **[実装に降ろす・小] 速度**: 同意モデルで所要が約 20 秒から約 25 秒に。事実の収集を計画に入る候補だけに絞れているかの再確認。
7. **[寝かせてよい]** 統合テストでデータの古さを検出する仕組み（入っている版と期待の版を並べる等）。Codex のサンドボックスの恒久対策（AppArmor、sudo）。
   設計メモ 10 章 13 の残り 3 点（Codex 7 回目の結果次第）。
8. **[壁打ち]** 「事実」の網羅性の線引き。点検するツールと変更するツールの責務の違い。データの古さという「ツールが黙って誤る」形への備え
   （ツールは日付を出すが、利用者がそれを読むか）。
9. **[外部発信・本人判断]** dev.to の題材「点検ツールは保証しない — 6 回の敵対的レビューから同意モデルへ」。今回の「自社の記事との突き合わせで
   既知データの誤りに気づいた（テストは同じデータを期待値にしていた）」も題材になりうる（記録時の推測）。

他リポジトリ: skill-inventory に未 push の commit 2 件（前々回の引き継ぎから持ち越し・本セッションでも未確認）。

## 6. Done-when（このハンドオフの役目）

次セッションが §1 の 3 点を読み、§4 の git の行で前セッションの commit・push と CI を確かめ、§5-1（Codex 7 回目）に着手した時点で役目を果たす。
7 回目の結果と対応を新しい日付の実装記録に残し、v0.1.0 のリリースまで進んだら、本書の冒頭に「後継あり: <後継のファイル名>」を 1 行足して凍結すること。
