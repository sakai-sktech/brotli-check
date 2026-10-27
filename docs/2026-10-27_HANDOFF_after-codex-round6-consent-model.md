---
title: brotli-cve-check 引き継ぎ — 現在地・既存資料の読み方・次の一手（Codex 6 回目と同意モデルの後、リリース前）
date: 2026-10-27
status: handoff (next session starts here)
audience: 文脈を持たない次セッションの LLM / 後日の本人
related_files:
  - docs/2026-10-27_codex-review-round4-6-and-consent-model.md
  - docs/2026-10-27_checker-reports-facts-human-decides.md
  - docs/design.ja.md（10 章 11・12）
  - docs/2026-10-26_test-record_codex-round4-5.html
  - lib/exec.sh
tags: [handoff, reading-guide, release, codex-review, consent-model]
---

# brotli-cve-check 引き継ぎ（Codex 6 回目と同意モデルの後）

> **次セッションはまずこれを読め。** これ＋「最初に読む 3 点」で文脈が立ち上がる。
> 前の引き継ぎ `docs/2026-10-26_HANDOFF_release-readiness.md` は凍結（後継＝本書）。

## 0. 30 秒サマリ

- **何か:** CVE-2026-111497（Brotli の C デコーダーの範囲外書き込み）に該当しうるデコーダーのコピーを、Ubuntu/Debian のホスト 1 台から
  読み取りで洗い出す bash ツール `brotli-cve-check`。GitHub は **public**（sakai-sktech/brotli-check）。**v0.1.0 は未リリース**。
- **このセッション（2026-10-26〜27）でしたこと:** Codex の敵対的レビュー 4・5・6 回目の指摘を検討・修正。6 回目のあと本人の思想で
  **実行の扱いを作り直した**: 見つけたプログラムを実行するかはツールが規則で決めず、**実行するもの・理由・事実（誰が書き換えられるか）を
  先に示して人が選ぶ**（端末で全部／しない／番号。端末が無ければ `--yes` か `--no-exec`）。ldd は廃止。README に「`--yes` を使う前に」。
  テストの記録を HTML で作成。
- **いまの段階:** 単体 153/153、統合 26/26、ShellCheck 0。**作業ツリーは未 commit**（このセッションを閉じるときに commit・push する予定。
  §4 の git 状態を確かめよ）。次は **今日の修正の変異テスト → Codex 7 回目（新しい基準）→ push と CI → 図解 → リリース**。

## 1. 最初に読む 3 点

1. **`docs/2026-10-27_codex-review-round4-6-and-consent-model.md`**（実装記録）— 何をなぜ直し、何を捨て、どこでつまずいたか。
   棄却記録（root の既定停止・ldd・tr -s など）が特に重要。
2. **`docs/2026-10-27_checker-reports-facts-human-decides.md`**（壁打ち記録）— 本人の思想「点検ツールは事実を返し、判断は人がする」に
   至った転回。**このプロジェクトでツールの責務を考えるときの基準**。Codex 7 回目の依頼文の基準もここから来る。
3. **`docs/design.ja.md` 10 章 11・12**（英語版 `design.md` が正）— 同意モデルの仕様と 6 回目の修正の一覧。10 章 9・10 は 4・5 回目の判断
   （一部は 10 章 11 で置き換え済み。各項目に注記あり）。

コードを触る前に `lib/exec.sh` の冒頭のコメント（同意モデルの 4 段）を読むこと。

## 2. 既存資料の読み方（docs マップ・実在を ls で確認済み）

| ファイル | 中身 | 状態 |
|---|---|---|
| `docs/design.md` / `design.ja.md` | 設計メモ。2 章 一次資料の再確認、7 章 読み取り専用の仕組み、10 章 実装時の判断（1〜12） | ✅ 正（英語が正）。10 章 3 と 9 の 1 は **10 章 11 で置き換え**（本文に注記） |
| `docs/limitations.md` / `.ja.md` | 見落としうるもの・判定できないもの。「プログラムの実行」「既知データ」の節は同意モデルに更新済み | ✅ 正 |
| `docs/json-schema.md` / `.ja.md` | `--json` の形式。`execution[]`、`options.yes`、`data_writable_by_others` を追加済み | ✅ 正 |
| `docs/verification.md` / `.ja.md` | 検証結果。4・5 回目後と 10/27（同意モデル・6 回目後）の結果を併記 | ✅ 正（10/27 時点） |
| `docs/sample-output.md` | Ubuntu 24.04 の統合テストのイメージでの出力（`--yes`）。冒頭に「版を読むために実行したプログラム」節 | ✅ 正（10/27 取り直し） |
| `docs/2026-10-26_test-record_codex-round4-5.html` | **テスト記録（本人の依頼）**。テストごとに目的と結果。1〜10 章は 10/26 時点、11 章が 10/27 の追記 | 記録（11 章まで） |
| `docs/2026-10-27_codex-review-round4-6-and-consent-model.md` | 実装記録（本セッション） | 記録（凍結） |
| `docs/2026-10-27_checker-reports-facts-human-decides.md` | 壁打ち記録（本セッション） | 記録（凍結） |
| `docs/2026-10-26_brotli-cve-check-initial-implementation.md` | 初版の実装記録 | foundational。**実行の扱いの節は撤回バナー付き**（10 章 11 で置き換え）。ほかは有効 |
| `docs/2026-10-26_reading-results-and-reviewing-before-release.md` | 前回の壁打ち記録（結果の読ませ方・レビューの待ち方） | foundational |
| `docs/2026-10-26_HANDOFF_release-readiness.md` | 前回の引き継ぎ | ⚠️ 凍結（後継＝本書。冒頭にバナー） |
| `docs/for-clinics.ja.md` | 医療機関・中小企業向けの説明 | ✅ 正（実行の話は書いていない） |
| `docs/zukai/01_*`, `02_*` | A4 図解 2 枚（英日・HTML/PDF/PNG） | ⚠️ **10/26 の状態の写像**。「`--version` を尋ねるときだけ実行」「root/一般で 10/10」は今の形（同意して実行、26 項目）と食い違う。作り直すかは本人判断（§5） |
| `README.md` / `README.ja.md` | 使い方、`--yes` を使う前に（新）、結果の読み方、版の判定方法 | ✅ 正（`--yes` の注意書きの文体は本人の確認待ち） |
| `CHANGELOG.md` | 0.1.0（未リリース）の内容 | ✅ 正（日付は未記入） |
| `tests/integration/README.md` | 統合テストの中身（4 通りの走査＋プローブ） | ✅ 正 |
| `tests/fixtures/c09/README.md` | C09 文字列推定の検証記録 | ✅ 正（変更なし） |
| `.context/codex-review-2026-10-26-round4.md` / `round5.md` / `round6.md` | **Codex の指摘の全文（verbatim）** | 🔒 手元だけ（`.git/info/exclude`）。**push しない・公開しない** |
| `.context/codex-round4-triage-2026-10-26.md` | 4・5 回目の検討表と本人判断のメモ | 🔒 手元だけ |
| memory `reply-in-japanese.md` | 本人向けの報告・質問は日本語で（AskUserQuestion の選択肢も） | ✅ 正 |

撤回・訂正: (1) 初版実装記録の「実行の条件」→ 10 章 11 で置き換え（バナー済み）。(2) テスト記録の変異テストの「落ちたテスト」の番号は、
最初に推測で書いて実測と違った → 取り直して実測に修正済み（記録内に「記録作成時の実測」と明記）。

## 3. 確定している知見（訂正後の最新）

1. **ツールの責務**（本人の思想・最優先）: 点検ツールは、必要なことを理由とともに示し、事実を返し、判断は人がする。ツールが「安全」を規則で
   決めて黙って実行をやめる・留保を付ける、はしない。**ただし変更する操作（`--output` の書き込み）はツールが厳格に守る**（`ln -T`、全階層の検査）。
2. **実行（`lib/exec.sh`）**: 検出項目が版を必要とするプログラムだけを挙げる（パッケージの node/curl で OS の libbrotlidec を読むもの、パッケージの
   ブラウザは挙げない）。事実を付けて一覧 → 端末で選ぶ／`--yes`／`--no-exec`／端末なしで指定なしは一覧を出して exit 3。実行は `/` から、
   `env -i`、stdin 閉、timeout、出力 64 KiB。結果の冒頭と JSON `execution` に実行した・しなかった・事実。
3. **依存の辿り**: glibc の ld.so の順（要求側 DT_RPATH → 読み込み元の DT_RPATH を実行ファイルまで → DT_RUNPATH → キャッシュ → 既定。DT_RUNPATH が
   あればその DT_RPATH と継承は使わない）。readelf だけ。**ldd は使わない**。本体シェルで `readelf -d` と解決をキャッシュ。
4. **確度の書き方**: 文字列推定は「分かったこと／分からないこと」で書く（状態名 LIKELY_FIXED は残す）。ファイルから読んだ版で FIXED にするのは
   文字列が 1 コピーで修正を示すときだけ（パス・ヘッダー・メタデータ・ファイル名・application.ini・flatpak・conda の記録）。
5. **読み取りの完了**は各段の終了状態（PIPESTATUS）で決め、データ中の印は使わない（ファイルが偽造できる）。
6. **`--data`**: 他人が書き換えられるファイルも使い、冒頭で警告（拒まない）。FIFO・16 MiB 超は開く前に断る。
7. **`--yes`**: 一覧を見ずに全部実行する同意。root なら他人のプログラムが root で動きうる。README の「`--yes` を使う前に」に平易に書いた
   （本人判断: コードで除外せず、説明で足りる）。
8. **版番号を信じない**（前回から有効）: ソースパッケージの版、`process.versions.brotli` は使わない、プレリリースは正式版扱いしない。
9. Ubuntu の OS の Brotli は全リリース修正待ち、Debian 12/13 は修正済み（既知データ 2026-10-26）。
10. **撤回**: 「root では既定で実行しない（`--allow-exec`）」は 10/26 に本人が選び、10/27 に本人の思想で置き換えた。`--allow-exec` は存在しない。

## 4. 運用・インフラ状態

- **git**: HEAD は `eb4205b`（前セッションの最後）。本セッションの変更は**未 commit**（session-close で commit・push する予定）。次セッションの最初に
  `git status --short` と `git log --oneline -3` で、commit されたか・push されたかを確かめよ。`.context/` は exclude 済み（commit に入らない）。
- **CI**: 最後に緑なのは `eb4205b`。本セッションの変更は CI 未実行。**CI のランナーには `/usr/local/bin/node` がある**ので、CLI テストで
  `--no-exec`/`--yes` を付け忘れると「端末が無い」で exit 3 になる（ローカルでも一度起きた）。
- **開発**: `make lint`（ShellCheck、0 であること）、`make test`（bats 153 件、約 6〜8 分）、`make dist`、`make integration`（Docker Desktop が要る）。
  統合のイメージは `bcc-it:<distro>`。1 つだけ: `ONLY=ubuntu:24.04 SKIP_BASH42=1 bash tests/integration/run.sh`。
- **テストの書き方の落とし穴**: CLI テストはホストの node なども一覧に入る（番号がずれる）。端末のテストは `script -qec` で擬似端末を作る
  （cli.bats の最後）。Ubuntu の cc は `--as-needed` なので、libbrotlidec を NEEDED に入れるには `-Wl,--no-as-needed`。
- **変異テストの写し**は `tests/tmp/` の下（リポジトリ内）に置く。`/tmp` の下だと実行系のテストが「誰でも書ける」で事実が変わる・skip される。
  前回の写し `tests/tmp/mut.U7FojH`・`mut5.aRE1RQ`・`mutrec.gkBKqn` と数字の作業ディレクトリが残っている（git 管理外。`make clean` で消える）。
  `tests/tmp/mutrec.*/muts.py` に 25 個の変異の定義がある（再利用できる）。
- **Codex**: この端末ではサンドボックスがコマンドを実行できない（Ubuntu 24.04 の `kernel.apparmor_restrict_unprivileged_userns = 1`）。codex スキルの
  Step 1.5 で確認し、`make dist` の単一ファイル版（約 170 KB）を stdin で渡す。`timeout 7200`、`--json` を jsonl に、run_in_background。
  4〜6 回目の依頼文は `.context` には保存していない（スクラッチは消える）。7 回目の依頼文は §5-2 の基準で書き直すこと。
- **この端末の対話シェルの `grep` は ugrep に置き換わっている**（手で計測するときは `/usr/bin/grep`）。計測は負荷で揺れるので HEAD と交互に。
- 実機（開発機・一般ユーザー）: `--no-exec`・`--yes` とも約 23.5 秒、stderr 空。

## 5. 未解決スレッド / Next Steps（優先順）

1. **[実装に降ろす] 今日の修正の変異テスト**（同意の判定、事実の収集、継承 RPATH、完了の判定、6 回目の各修正、候補の名前照合）。
   `tests/tmp/mutrec.*/muts.py` を土台に、10/27 の修正の変異を足す。結果はテスト記録の HTML に 12 章として追記（**実測で書く**）。
2. **[実装に降ろす] Codex 7 回目**（単一ファイル版の全体）。**依頼文に新しい基準を書く**: P1 は「事実として誤った報告（結果・事実の一覧）／
   黙った抜け（走査しなかった範囲に出ない欠落）／同意なしの実行・示さない実行／`--output` 以外への書き込み・ハング」。設計判断として除外:
   同意モデルそのもの（`--yes` の意味は README に明記）、事実の網羅性の限界（dlopen・設定ファイル・`$LIB`・ld.so のキャッシュの選択）、
   LIKELY_FIXED を「分かったこと／分からないこと」付きで残すこと、`--data` は警告して使うこと、C11 の出どころ分け。6 回目の 15 件の
   確認（FIXED/PARTIAL）も頼む。結果は `.context/codex-review-<日付>-round7.md` に全文、本人に verbatim で提示してから検討。
3. **[実装に降ろす] push → CI** の 3 ジョブが緑か（session-close で push 済みなら確認だけ）。
4. **[本人判断] 図解 2 枚**を作り直すか（a4-zukai スキル。今の形: 同意して実行、統合 26 項目）。
5. **[本人判断] README の「`--yes` を使う前に」の文体**（本人の要求「言い訳っぽくなく、分かりやすい言葉で丁寧に」に合っているか）。
6. **[本人判断] 状態名 LIKELY_FIXED を残すこと**（私の判断。本人の明示の同意は未）。
7. **[実装に降ろす] リリース v0.1.0**: タグ、`dist/brotli-cve-check` と `dist/SHA256SUMS` を添付、CHANGELOG の日付。README の Quick start がこれで
   404 でなくなる。README に「Docker は不要、点検したいサーバーごとに走らせる」を 1 行（前回からの持ち越し）。
8. **[実装に降ろす・小] 速度**: 同意モデルで所要が HEAD の約 20 秒から約 23.5 秒に。事実の収集を計画に入る候補だけに絞れているかの再確認。
9. **[本人判断・寝かせてよい]** Ubuntu の既知データ (b) 案（PPA の修正候補を `unreleased` で登録するか）。Codex のサンドボックスの恒久対策（AppArmor、sudo）。
10. **[壁打ち]** 「事実」の網羅性の線引き（どこまで書けば誤りでないか）。点検するツールと変更するツールの責務の違い。dev.to の題材「点検ツールは
    保証しない — 6 回の敵対的レビューから同意モデルへ」（本人判断）。

他リポジトリ: skill-inventory に未 push の commit 2 件（前回の引き継ぎから持ち越し・本セッションでは未確認）。

## 6. Done-when（このハンドオフの役目）

次セッションが §1 の 3 点を読み、§5 の 1（変異テスト）か 2（Codex 7 回目）に着手した時点で役目を果たす。7 回目の結果と対応を新しい日付の
実装記録に残し、v0.1.0 のリリースまで進んだら、本書の冒頭に「後継あり: <後継のファイル名>」を 1 行足して凍結すること。
