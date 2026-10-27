---
title: Codex 敵対的レビュー 4〜6 回目の修正と、実行の同意モデルへの作り直し（brotli-cve-check 0.1.0 リリース前）
date: 2026-10-27
version: 0.1.0（未リリース）
status: partial
participants:
  - role: human
    name: maintainer
  - role: assistant
    model: claude-opus-5-5
related_files:
  - lib/exec.sh（新設）
  - lib/elf.sh, lib/core.sh, lib/main.sh, lib/output.sh, lib/i18n.sh, lib/index.sh, lib/findings.sh
  - lib/check_c01_c03.sh, lib/check_c04_c05.sh, lib/check_c06_c07.sh, lib/check_c08_c09.sh, lib/check_c10_c13.sh, lib/check_c14_c15.sh
  - lib/data.sh, lib/version.sh
  - tests/unit/hardening.bats（新設）, tests/unit/cli.bats, tests/unit/checks.bats, tests/unit/test_helper.bash
  - tests/integration/run.sh, tests/integration/README.md
  - docs/design.md, docs/design.ja.md（10 章 9〜12）
  - docs/limitations*.md, docs/json-schema*.md, docs/verification*.md, docs/sample-output.md
  - docs/2026-10-26_test-record_codex-round4-5.html（テスト記録・11 章に 10/27 追記）
  - README.md, README.ja.md（「--yes を使う前に」）, CHANGELOG.md
  - .context/（手元だけ・push しない: Codex 4〜6 回目の全文、検討メモ）
tags:
  - CVE-2026-111497
  - codex-review
  - consent-model
  - ld.so
  - mutation-testing
---

# Codex 敵対的レビュー 4〜6 回目の修正と、実行の同意モデルへの作り直し

> **2026-10-27 追記（訂正）:** Next Steps の「Ubuntu の既知データ (b) 案（PPA の修正候補を登録するか）」は不要になった。Ubuntu は
> 2026-10-26 に USN-8956-1 で修正し、既知データは 2026-10-27 に更新した（`docs/design.md` 2.1）。本書のほかの記述はそのまま有効。

## Purpose & Context

- 前セッションのハンドオフ（`docs/2026-10-26_HANDOFF_release-readiness.md`）の §5-1「Codex 4 回目の指摘 10 件を直す」から開始。
  本人の指示は「ハンドオフを読んで続きを進めてくれ。Codex のレビュー内容を確認して検討することが最優先」。
- 4 回目（P1×6・P2×4、GATE FAIL）→ 修正 → 5 回目（P1×10）→ 修正 → 6 回目（P1×7・P2×2＋前回の PARTIAL 6 件）と進み、
  6 回目のあと本人の思想の指示で、見つけたプログラムの実行のしかたを根本から作り直した（§Implementation Decisions の 4）。
- 途中で本人の依頼により、テストの記録を HTML で作成（`docs/2026-10-26_test-record_codex-round4-5.html`）。最後に README に
  `--yes` の注意書きを足した。
- Codex は前回同様サンドボックスが動かない（`SANDBOX_BROKEN`）ため、`make dist` の単一ファイル版を stdin で渡す方式。2 時間の規約。
  4〜6 回目とも 2 時間以内に完走した（5・6 回目は数分〜数十分）。

## Implementation Decisions

### 1. 4 回目の指摘の検討（10 件とも当たり、うち 3 件は実験で再現）

- 再現: R4-3（GNU ln は既存ディレクトリの中にリンクを作る。`ln -T` で EEXIST）、R4-6（bun `1.4.4-rc.1`→`1.4.4`、Firefox `150.0a1`→`150.0` 等）、
  R4-10（dash も busybox も `command -v -a` は Illegal option）。
- 重さの見立てを Codex と変えたもの: R4-2（PATH）・R4-3（ln）は P1→P2（前提が既に危ない／`fs.protected_symlinks` で symlink 版は止まる）、
  R4-10 は P2→P1（`--inspect-containers` が CVE の主対象の Node を黙って見落とす）。
- 本人の判断 3 点（AskUserQuestion）: Q1 root では既定で実行しない（`--allow-exec` で明示）→ **後で 4. で置き換え**／Q2 C11 は出どころで分ける
  （パッケージ・cbrotli を使わない Go 製は NOT_APPLICABLE、自前ビルドは UNKNOWN）／Q3 探す場所の下のローカルディスクのマウントは自動で探索に加える。
- 質問を英語で出してしまい本人に指摘された（「なんで英語で俺に聞いてくるのか」）。memory に「本人向けは日本語」を保存。

### 2. 5 回目の指摘と本人の判断

- 実験で確認: `find -P` は symlink の起点の下を歩かない（`/srv → /data/srv` で木ごと抜ける）／RUNPATH `:/nonexistent` で作業ディレクトリの
  `libfoo.so` が読み込まれる。
- **本人の判断（指摘 6: 辞書を共有する新旧 2 デコーダーは見分けられない）**: 最初の私の問い（LIKELY_FIXED を残すか UNKNOWN にするか）は
  「意味がわからない」と言われ、噛み砕いて再質問した結果、本人の答えは「多分修正済み、じゃなくて、分かったことと分からなかったこと
  （修正済みとは言えない可能性がある）をしっかり出力すれば事足りる」。→ 状態名は依頼文・JSON のものなので変えず、理由の文を
  「分かったこと／分からないこと」の形にし、案内から「修正済みの可能性が高い」を外した。
- **本人の判断（指摘 8: 他人が書ける `--data`）**: 私の「root では拒むか」という問いに対し、本人は「点検が目的で、すべての正誤判定を永遠に
  保証するわけではない。誰でも書き換えられる場所なら、その権限の問題を指摘として出力すれば良い」。→ 拒まず、冒頭に警告と JSON の
  `data_writable_by_others`。FIFO・巨大ファイルは開く前に断る。
- 6 回目のレビューは「全体をもう一度」（本人の選択）。

### 3. 6 回目のあとの転回: 規則で「安全」を決めるのをやめる

- 6 回続けて GATE FAIL。実行まわりは毎回、前回の修正の穴（所有者 → ライブラリ → RPATH → 途中の symlink → 空の項目 → 継承 RPATH）が出た。
  グローバル規約の「3 回で収まらなければ止まって相談」に当たると判断し、案 A（全部直して 7 回目）／B（一般ユーザーも既定で実行しない）／
  C（リリース基準を決める）を提示。推奨は B＋C。
- 本人の応答（要旨）: 「実行を既定で止めるの意味が伝わってこない。チェックに必要な実行なら実行すればよい。実行の許可を理由とともに最初から
  明示すればよい。脆弱性をローカルでチェックするのが目的なのだから、必要なことはユーザーに明示して、結果を返す。判断は人間が行えばよい。
  お前が判断までしようとするから変な留保が出てくるんだ」。
- 私の取り違えの言語化: 「他人のコードを実行しない」「偽の安心を出さない」を**ツールが保証すべきもの**として扱い、Codex への依頼文にも
  そう書いていた。点検ツールには保証しきれないので、毎回「保証の穴」が P1 として出ていた。穴を塞ぐたびにツールが黙って判断する箇所が増え、
  それが「変な留保」（黙って実行しない・確かめられないと UNKNOWN に落とす等）として結果に現れていた。
- 許可の受け取り方は AskUserQuestion（プレビュー付き）で本人が選択: **実行前に一覧を見せて確認**（端末で y/n/番号、端末が無ければ
  `--yes` か `--no-exec` が無いと止まる）。

### 4. 同意モデルの実装（`lib/exec.sh`、設計メモ 10 章 11）

- 流れ: 索引 → `bcc_build_exec_plan`（各検出項目の候補関数から、版が判定に要るものだけを挙げる）→ `bcc_exec_facts`（事実）→
  `bcc_exec_consent`（`--no-exec`／`--yes`／端末で質問／端末なしは一覧を stderr に出して exit 3）→ `bcc_exec_run`（`/` から、`env -i`、
  stdin 閉、timeout、出力 64 KiB 上限）→ 各チェックは `bcc_probe` で結果を引くだけ（実行しない）→ 結果の冒頭に「版を読むために実行した
  プログラム」節と JSON の `execution`。
- 計画に入れないもの（判定がそれに依らない）: パッケージの node・curl で OS の libbrotlidec を読み込むもの（C01 が判定）、パッケージのブラウザ（パッケージの版）。
- 候補探しは各項目の関数（`bcc_c04_candidates` 等）に切り出し、計画とチェックで同じ候補を使う（一度だけ計算して配列に保持）。
- 事実（`bcc_path_facts`）: パスを `/` から 1 段ずつ、symlink は置かれた場所で辿り、各ディレクトリと最終のファイルについて「他の所有者」
  「グループが書ける」「誰でも書ける（sticky を除く）」「symlink 自体の所有者」「存在しない（上に書ける人が作れる）」を集める。
  対象は本体・PT_INTERP・依存ライブラリ・探索先ディレクトリ（glibc-hwcaps 下位を含む）・`/etc/ld.so.preload`。
- 依存の辿り（`bcc_dep_walk_uncached`）: glibc の `_dl_map_object` の順に合わせた（要求側の DT_RPATH → 読み込み元の DT_RPATH を
  実行ファイルまで → DT_RUNPATH → キャッシュ → 既定。DT_RUNPATH を持つものは自分の DT_RPATH も継承も使わない。`get-dynamic-info` が
  両方あると RPATH を捨てる挙動）。空・相対・`$LIB` 等の探索先は事実として報告。
- **ldd を廃止**。理由: ファイルをローダーに渡す＝名前が違うだけで実行と同じで、「示さずに実行」にあたる。リンクは readelf だけで辿る。
- 消したもの: `--allow-exec`、root の既定停止（`bcc_init_exec_policy`）、`bcc_exec_ok`／`bcc_safe_deps`／`bcc_safe_path`（黙って実行を止める判定）。
  `bcc_safe_to_exec` はツール自身の道具の PATH 固定（`/usr/local/*` を足すか）にだけ残す。
- 棄却: 規則で決める（6 回の経緯）、一切実行しない（ファイルからの版は弱く、本人は実行を望むことがある）、尋ねずに全部実行（人が事実を知るのが後になる）。
- 自動セキュリティレビュー（プラグイン）が「root で `--yes` は他人のコードを root で動かす。ツールが除外すべき」と指摘。私は事実として正しいと
  認めたうえで、思想に沿う代替（`--yes=all`／`--yes=clean`）を提示。本人の判断: 「それなら `--yes` の注意事項を README に丁寧に書けばいい。
  root で動かすことの意味を理解していない人が `--yes` でやると結果も読み間違える。言い訳っぽくなく、分かりやすい言葉で」。→ README（英日）に
  「`--yes` を使う前に」を追加（あなたの権限で動く／一覧に載るのは実行前に見えるものだけ／プログラムが答えた版はそのプログラムと同じだけしか信用できない／無人なら `--no-exec`）。コードは変えていない。

### 5. 4〜6 回目のそのほかの修正（要点。全件は設計メモ 10 章 9・10・12）

- PATH を `/usr/sbin:/usr/bin:/sbin:/bin` に固定（`/usr/local/*` は root しか変更できないときだけ末尾）、呼び出し側の PATH は探索用。
- `--output` に `ln -T`。dpkg 所有は「C01 が実際に判定したパッケージ」のときだけ任せる（ベンダーの .deb の同梱 Python 等）。
- プレリリース: 版の後ろを残し、修正版と同じ番号のプレリリースは UNKNOWN（bun rc、Firefox a/b/~、Node nightly/-pre、Chromium ~）。
- 読み取り: `bcc_read_file`（通常ファイルのみ、`head -c` を timeout の下で開く）。文字列走査は sort を使わず、grep/awk を `ulimit -v` 256 MiB の下で。
  **読み終えたかは各段の終了状態（PIPESTATUS）で判定し、データ中の印は使わない**（5 回目までの実装はデータに `__BCC_READ_RC=` を流しており、
  6 回目に「ファイルが偽造できる」と指摘された。実験で、偽の印入りの 300 MB ファイルが partial になることを確認）。
- ファイルから読んだ版（パス・ヘッダー・メタデータ・ファイル名・application.ini・flatpak・conda の記録）で FIXED にするのは、文字列が 1 コピーで
  修正を示すときだけ。前の実装記録の「修正の印が無ければ UNKNOWN」にコードを合わせた（エラー名がまったく無いとき FIXED のままだった）。
- C11 は出どころで分ける（本人判断）。C08 curl は `-V` を見ていなければ NOT_APPLICABLE と言わない。辞書の数で複数コピーを検出。
- 「走査しなかった範囲」: dpkg-query の失敗、find のエラー、`--deep` の grep の失敗（xargs が 123 にまとめるので各バッチが自分で報告）、
  コンテナの dpkg-query、snap/flatpak/ss の失敗、`--exclude`、サイズ上限超え、tmpfs 等の別種のマウント（ローカルディスクは探索に加える）。
- symlink の探索場所はリンク先を歩く。Electron の snap は `/snap/名前/current`（symlink）の先を見る（**初版からの見落とし**）。
- コンテナのプローブは POSIX sh（PATH を自分で回す、END の印）。dist-packages を配布元扱いするのは python3-brotli があるときだけ。
- 候補は名前を解決前と解決後の両方で照合（`node → node-22.0.0` は残し、`node → mise` の shim は外す）。パスは NUL 区切りで運ぶ（改行入りのパス）。

### 棄却記録（Rejected Decisions）

- **root では既定で実行しない（`--allow-exec` で明示）** — 4 回目後に本人も選んだが、6 回目後に置き換え。痛み: ツールが「安全」を決める規則は
  レビューのたびに 1 段奥の穴（ライブラリ → 継承 RPATH → symlink）を突かれ、6 回で収束しなかった。しかも黙って実行しないことで、結果には
  「なぜ版がヘッダー由来なのか」「なぜ UNKNOWN なのか」という説明の付かない留保が出た。有効になる条件: 事実を見せる手段が無い（UI が無い）用途。
- **検査を広げて「安全なものだけ」実行** — 4 回目の推奨候補 B（Completeness 5/10）。dlopen・設定ファイル・hwcaps は覆えないまま、検査コードだけが
  膨らむ。実際、検査コード自体が 5・6 回目の指摘対象になった。
- **ldd でリンクを辿る** — 精度は良いが、対象ファイルをローダーに渡す（ldd(1) 自身が信頼できないファイルに使うなと書いている）。同意の外で
  実行に近いことをしないため廃止。代償: readelf の辿りは近似（キャッシュ・hwcaps の選択）。
- **`tr -s` や `fold` で行の長さを抑える** — 130 MB の node で `tr -c` 0.05 秒に対し `tr -cs` 0.36 秒、`fold` も同程度。node 30 本で数秒〜十数秒の差。
  `ulimit -v` で grep/awk のメモリを抑える形にした。
- **`--data` を root で拒む** — 本人が否定（点検ツールは永遠の正しさを保証しない。権限の問題は指摘として出せばよい）。
- **すべての LIKELY_FIXED を UNKNOWN にする**（5 回目指摘 6 の Codex 案）— 本人の答えは「分かったこと／分からないこと」を書くこと。
  状態名を変えると依頼文・JSON と食い違う。どちらでも「人の確認が必要」・終了コード 2 で、違いは表示だけだった。
- **curl の「brotli/%u.%u.%u」書式文字列で実行せずに Brotli 対応を見分ける** — この端末の libcurl・curl に見つからず、「brotli」という語だけでは弱いので採らず。
- **下のマウントを並べて `--roots` で足すよう案内するだけ** — 本人判断で自動で加える方に。`/srv` の下のデータディスクは探索場所の意味のうち。

## Key Learnings

- **author ≠ reviewer の 2 時間規約は今回も効いたが、収束しない形もある。** 4〜6 回目で毎回本物の欠陥（Electron snap の初版からの見落とし、
  ファイルで偽造できる完了印、改行パス、空の RUNPATH 等）が出た。一方、実行の安全を「ツールが保証する」前提のまま直すと、毎回 1 段奥の
  穴が出続けた。収束しないときは、前提（脅威モデル・責務）を本人と見直すのが正しかった。
- **「判断は人が行う」を設計にすると、テストでは見えない不具合が実機ですぐ見える。** 実行一覧を結果に出した最初の実機の実行で、
  「`/home/…/.local/bin/mise --version（C04 node）`」が出て、別名を拾う修正の回帰（mise の shim を node と扱う）が即座に分かった。
- **変異テストは必要だった。** 4 回目の修正は 1 回目で全テストが通ったが、修正を戻して確かめると 12 個中 3 個は捉えておらず
  （写しを /tmp に置いて skip されていた・本物のマウントでない・関数単体しか見ていない）、テストを直して全部捉えた。5 回目でも 13 個中
  3 個（末尾の `:`、絞り込み語の誤り、二重の守り）。**テスト記録の作成時に推測で書いた番号は実測と違っていた**（プレリリース規則は 4 でなく 5 件、
  依存の検査は 2 でなく 3 件）。記録は実測で作る。
- **速度の罠:** 依存の検査を足した最初の版は 20 秒 → 51 秒。原因はライブラリ 1 つあたり約 30 プロセス（stat・dirname・readlink・readelf×2）と
  `tr -s`。stat を 1 回にまとめる、dirname をやめる、ディレクトリ・ライブラリ・依存の木・`readelf -d` の結果・解決をキャッシュする、で
  約 20〜24 秒に戻した。キャッシュは本体シェルで持たないと `$(…)` のサブシェルで消える（`bcc_dpkg_owner` のキャッシュは以前から多くの呼び出しで効いていなかった）。
- bash の細部: printf は `%2$s` の位置指定が使えない（日本語の語順を英語に合わせる）／`read -a` は末尾の空フィールドを黙って捨てる／
  空配列の `"${a[@]}"` は bash 4.2 の `set -u` で落ちる／未宣言の配列に文字列の添字を入れると算術評価で落ちる（宣言は `bcc_init_findings` に集める）／
  `ln` は既存ディレクトリの中に作る／Ubuntu の cc は `--as-needed` で未使用の NEEDED を落とす（テストでは `--no-as-needed`）。
- この端末の対話シェルでは `grep` が ugrep に置き換わっていて、手での計測が一度崩れた（`/usr/bin/grep` を直接使う）。計測は負荷で大きく揺れるので、HEAD と交互に測る。
- `snap list` は snap が無くても終了状態 0（案内は stderr）。`/snap/*/current` はすべて symlink。

## Current State

- 実装: 同意モデル（`lib/exec.sh`）、Codex 4・5・6 回目の指摘への対応（6 回目は 10.11 の思想の下で、実行まわりは事実として提示）。README に `--yes` の注意書き。
- テスト: ShellCheck 警告 0。bats 153 / 153（skip 0。前回 93 から新規 60、書き換え含む）。端末での確認は `script` の擬似端末で番号選択まで確認。
  統合テスト 26 / 26（Ubuntu 22.04/24.04/26.04・Debian 12/13 × root/一般 × `--no-exec`/`--yes`、各イメージの `/bin/sh` での C14 プローブ、bash 4.2 は `--yes`）。
  変異テスト: 4・5 回目の修正 25 個は記録作成時に全 134 件で取り直し、24 個で落ち、1 個は設計上の二重の守り。**今日（6 回目・同意モデル）の修正の変異テストは未実施。**
- 実機（開発機・一般ユーザー）: `--no-exec`・`--yes` とも完走、stderr 空、所要 約 23.5 秒（HEAD 約 20 秒）。
- **未実施**: Codex 7 回目、CI（未 push）、図解（`docs/zukai/`）の更新、リリース v0.1.0、README の「Docker 不要」の 1 行、Ubuntu の既知データ (b) 案の判断。
- 既知の限界（文書化済み）: 実行後に開くもの（dlopen・設定）は事実に出ない／`$LIB` 等は展開しない／辞書を共有する 2 デコーダーは見分けられない／
  マウントでない btrfs サブボリューム／Alpine コンテナのパッケージ。

## Next Steps

1. **今日の修正の変異テスト**（同意の判定・事実の収集・継承 RPATH・完了の判定・各 6 回目の修正）。手順はテスト記録 4 章と同じ（写しはリポジトリの
   `tests/tmp/` の下に置く。/tmp の下だと実行系のテストが skip される）。
2. **Codex 7 回目**: 全体（`make dist` の単一ファイル版を stdin）。**基準を伝える**: P1 は「事実として誤った報告／黙った抜け／同意なしの実行（示さない実行）／
   `--output` 以外への書き込み」。事実の網羅性の限界（dlopen 等）・`--yes` の意味（README に明記）・LIKELY_FIXED の扱い・`--data` の警告は設計判断として除外。
3. push → CI（lint-and-unit・integration・bash42）が緑か。CI のランナーには `/usr/local/bin/node` があるので、CLI テストで `--no-exec`/`--yes` を
   付け忘れると exit 3 で落ちる（ローカルでは同じ理由で一度落ちた）。
4. 図解 2 枚の作り直し（root の既定・同意の形・統合テストの件数）か、そのままにするかを本人に確認。
5. リリース v0.1.0（タグ、`dist/brotli-cve-check` と `SHA256SUMS`、CHANGELOG の日付）。README の Quick start が 404 でなくなる。
6. 寝かせてよい: Codex のサンドボックスの恒久対策（AppArmor、sudo）、Ubuntu の既知データ (b) 案。
