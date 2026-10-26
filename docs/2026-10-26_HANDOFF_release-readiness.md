---
title: brotli-cve-check 引き継ぎ — 現在地・既存資料の読み方・次の一手（リリース前）
date: 2026-10-26
status: handoff (next session starts here)
audience: 文脈を持たない次セッションの LLM / 後日の本人
related_files:
  - docs/2026-10-26_brotli-cve-check-initial-implementation.md
  - docs/design.ja.md
  - docs/verification.ja.md
tags: [handoff, reading-guide, release, codex-review]
---

# brotli-cve-check 引き継ぎ（リリース前）

> **次セッションはまずこれを読め。** これ＋「最初に読む 3 点」で文脈が立ち上がる。

## 0. 30 秒サマリ

- **何か:** CVE-2026-111497（Brotli の C デコーダーの範囲外書き込み）に該当しうるデコーダーのコピーを、Ubuntu/Debian の
  ホスト 1 台から読み取り専用で洗い出す bash ツール `brotli-cve-check`。依頼文（社内・リポジトリ外）に沿って作った初版。
- **今どこ:** 実装・単体テスト（93 件）・shellcheck（ゼロ）・統合テスト（Ubuntu 22.04/24.04/26.04・Debian 12/13・bash 4.2）
  まで合格。GitHub は **public**（sakai-sktech/brotli-check）。
- **止まっている所:** リリース前の別系統レビュー（Codex）。1 回目の途中結論で実在の欠陥 5 件を直した。
  **4 回目は完走し、GATE: FAIL（P1 × 6・P2 × 4・P3 なし）。** 本人判断で修正は次セッションに回した（§5 の 1）。
  **リリース v0.1.0 は未作成**（README の Quick start はリリースを前提にしているので、今は 404）。

## 1. 最初に読む 3 点

1. `docs/2026-10-26_brotli-cve-check-initial-implementation.md` — 何をなぜそう作ったか、何を捨てたか、どこでつまずいたか。
2. `docs/design.ja.md`（英語版 `design.md`）— 2 章が一次資料の再確認表（データの根拠）、7.1 と 10 章が実装時の判断。
3. `docs/verification.ja.md` — 何をどう確かめたか、結果の読み方（Ubuntu は OS の Brotli が全リリース修正待ち、等）。

## 2. 既存資料の読み方（docs マップ）

| ファイル | 中身 | 状態 |
|---|---|---|
| `docs/design.md` / `design.ja.md` | 設計メモ（一次資料の再確認・データの列・検出項目・安全設計・決定事項・実装時の判断） | ✅ 正（英語が正、日本語は対訳。2026-10-26 時点の実装に合わせて更新済み） |
| `docs/verification.md` / `.ja.md` | 検証結果（静的検査・単体・統合・C09・実機）と読み方 | ✅ 正（2026-10-26 時点。Codex 修正後の統合テストも合格） |
| `docs/limitations.md` / `.ja.md` | 見落としうるもの・判定できないもの | ✅ 正（`--output` の節まで反映済み） |
| `docs/json-schema.md` / `.ja.md` | `--json` の形式 | ✅ 正 |
| `docs/sample-output.md` | Ubuntu 24.04 の統合テストのイメージでの出力（英日） | ✅ 正（Codex 修正前に取ったが、出力の形は変わっていない） |
| `docs/for-clinics.ja.md` | 医療機関・中小企業向けの説明 | ✅ 正 |
| `docs/zukai/01_*`, `02_*` | A4 図解 2 枚（英日・HTML/PDF/PNG）。README の冒頭に PNG を並べている | ✅ 正（2026-10-26 時点の写像） |
| `docs/2026-10-26_brotli-cve-check-initial-implementation.md` | 実装記録 | 記録（凍結） |
| `docs/2026-10-26_reading-results-and-reviewing-before-release.md` | 壁打ち記録（結果の読ませ方・レビューの待ち方） | 記録（凍結） |
| `tests/fixtures/c09/README.md` | C09 文字列推定の検証記録・SHA256・再現手順 | ✅ 正（再現スクリプトでバイト一致を確認） |
| `tests/integration/README.md` | 統合テストの中身と期待値 | ✅ 正 |
| `data/advisories.tsv` | 既知データ（各行に一次資料 URL と取得日） | ✅ 正（スナップショット 2026-10-26） |

撤回・訂正済みの文書は無い（会話中に覆った主張＝「PYSEC 番号が逆」は文書に入る前に訂正した）。

## 3. 確定している知見

1. 版番号を信じない: Debian/Ubuntu はソースパッケージの版で比べる。`process.versions.brotli` は使わない（修正版 Node 22.23.4 でも 1.1.0）。
2. 同梱コピーの修正有無は `_ERROR_FORMAT_BLOCK_SWITCH`（エラー -17）の有無で推定できる。行頭一致・8 個未満なら判定しない。
   LTO＋gc-sections で `BrotliDecoderErrorString` を呼ばないビルドだけは判定不能（VENDORED_COPY）。
3. 実行せずに得た版（パス・ヘッダー・METADATA）で FIXED のときは文字列で確かめる（Codex の指摘）。
4. 見つけたプログラムを実行するのは、root（または本人）以外が置き換えられない正規化済みパスのものだけ。`--output` は
   mktemp＋ln、保存先から `/` までの全階層を検査、root では root 所有のみ。
5. Ubuntu の OS の Brotli は全リリース修正待ち（試験用 PPA に候補あり・普通は使わない）。Debian 12/13 は修正済み。

## 4. 運用・インフラ状態

- 開発: `make lint`（shellcheck）・`make test`（bats）・`make dist`・`make integration`（docker が要る）。
  テストは `set -o pipefail` で本体と同じ条件。統合テストは Docker Desktop の起動が前提。キャッシュ不整合でイメージ作成が
  失敗したら `ONLY=<image> SKIP_BASH42=1 bash tests/integration/run.sh` で作り直す。
- CI（GitHub Actions）: 最初の実行（b7a59b8）は lint-and-unit で失敗。原因 3 件は ceb743d で修正済みだが**未 push**。
- Codex: この端末では sandbox がコマンドを実行できない（Ubuntu 24.04 の `kernel.apparmor_restrict_unprivileged_userns = 1`）。
  codex スキル（2026-10-26 改訂）の Step 1.5 で事前確認し、ソースを stdin で渡す（`make dist` の単一ファイル版を渡すのが簡単）。
  リポジトリの中で、`</dev/null` かソースを stdin に付けて実行する。待ち時間は 2 時間。
- 4 回目の Codex の指摘の全文（verbatim）は **`.context/codex-review-2026-10-26-round4.md`**（このリポジトリの作業ツリー、
  `.git/info/exclude` で除外＝手元だけ・push されない）。未修正のセキュリティ上の指摘を含むので、直すまで公開しない。
  手元に無い（別の端末・消えた）場合は、codex スキルの手順で同じプロンプト（直した 6 件を除外・最大 10 件・P1〜P3、
  ソースは `make dist` の単一ファイル版を stdin）でもう一度走らせる。2 時間の規約で完走した実績あり。

## 5. 未解決スレッド / Next Steps（優先順）

1. **[実装に降ろす] Codex 4 回目の指摘 10 件を直す**（全文は §4 の `.context/…round4.md`）。分野は、見つけたプログラムを
   実行する条件、外部コマンドの探し方、`--output` の書き込み、dpkg 所有の扱い、印が無いときの判定、版の読み取り
   （プレリリース）、読み取りの制限時間、失敗・除外範囲の報告漏れ、コンテナ内の node の探し方。前セッションの見立てでは
   10 件とも当たっており、うち 3 件（3・6・10）はそのまま直せる。直したら単体テスト・統合テスト（C14 を通す項目を足す）・
   Codex の再レビュー（同じ規約）まで回す。
   - **[本人判断が先] 指摘 1:** root で動くとき、見つけたプログラムを既定で実行するか。前セッションの推奨は
     「root では既定で実行しない（版はファイルと文字列から）、実行は明示したときだけ」。
   - **[本人判断が先] 指摘 5:** デコーダーの印が見つからないとき NOT_APPLICABLE と言い切るか、「印は見つからなかった（判定保留）」
     にするか。後者は安全側だが、nginx・apache などが常に「要確認」に並ぶ。
2. **[実装に降ろす] push → CI 緑:** ceb743d・2c672aa・4af7bbc と記録 3 本。CI の 3 ジョブ（lint-and-unit・integration・bash42）が通ること。
3. **[本人判断] 既知データ (b) 案:** Ubuntu の行を `unreleased` にして PPA の修正候補の版（jammy 1.0.9-2ubuntu0.1 /
   noble 1.1.0-2ubuntu0.1 / resolute 1.2.0-3ubuntu0.1 / 26.10 1.2.0-4ubuntu0.1）を登録するか。先に PPA の changelog で
   CVE-2026-111497 の修正であることを確かめる。採らないなら、USN が出たら即データ更新・再リリースの運用。
4. **[実装に降ろす] リリース v0.1.0:** タグ、`dist/brotli-cve-check` と `dist/SHA256SUMS` を添付。CHANGELOG の日付を入れる。
   README の Quick start がこれで 404 でなくなる。
5. **[実装に降ろす] README:** 「Docker は不要、点検したいサーバーごとに走らせる」を短く足す（提案済み・未実施）。
6. **[本人判断・寝かせてよい] Codex の sandbox の恒久対策:** bwrap/codex 用の AppArmor プロファイル（sudo が要る）。

他リポジトリ: skill-inventory に未 push の commit 2 件（newrepo の `.gitignore` 生成、codex スキル改訂）。

## 6. Done-when（このハンドオフの役目）

次セッションが §1 を読み、§5 の 1（Codex の残り）に着手した時点で役目を果たす。リリース v0.1.0 まで進んだら、
結果を実装記録（新しい日付の doc）に残し、このハンドオフは「後継あり」として後継のファイル名を 1 行追記する。
