# JSON 出力（`--json`）

English: [json-schema.md](json-schema.md)

UTF-8 の JSON オブジェクトを 1 行で出します。フィールドは後方互換を保って追加します。フィールドを削ったり
名前を変えたりするときは `tool_version` のメジャー番号を上げます。

フィールドの一覧と例は英語版 [json-schema.md](json-schema.md) の例をそのまま参照してください
（キー名は英語のまま）。ここでは意味だけを日本語で示します。

| キー | 意味 |
|---|---|
| `tool`, `tool_version`, `cve` | ツール名、版、対象の CVE |
| `data_snapshot_date` | 既知データの日付（ファイル先頭の `# snapshot:` 行） |
| `data_age_days`, `data_stale` | 今日までの日数。30 日以上で `data_stale` が true |
| `data_source` | `embedded`（同梱）か、`--data` で渡したパス |
| `data_writable_by_others` | `--data` のファイル（または置き場所のディレクトリ）を root（または実行者）以外が変更できるとき true（結果の冒頭でも警告） |
| `host` | OS（`/etc/os-release`）、パッケージの系列（例 `ubuntu:noble`）、カーネル、uid、root かどうか |
| `options` | 指定されたオプション。`no_exec` は `--no-exec`、`yes` は `--yes`（一覧のプログラムを尋ねずに実行した） |
| `execution[]` | 版を読むために実行したいと挙げたプログラム（一覧の順）。`path`・`argument`・`check`、`ran`（実行したか）、実行したものは `exit_status` と `output`（4096 文字まで）、しなかったものは `not_run_because`（`not-chosen` か `no-exec`）、`facts`（尋ねる前に示した事実） |
| `scanned_roots` | 探索した場所 |
| `skipped[]` | **見ていない範囲**（`scope`・`reason`・`kind`）。必ず出す。`kind` は下表 |
| `findings[]` | 所見。`id`（C01〜C15）、`status`、`component`、`path`、`version`、`reason`、`next_step`、`evidence`、`confidence` |
| `info[]` | 所見ではない補足（件数や終了コードに影響しない） |
| `summary` | `needs_update`（VULNERABLE＋LIKELY_VULNERABLE）、`needs_restart`（RESTART_REQUIRED）、`needs_review`（NO_FIX_AVAILABLE＋VENDORED_COPY＋UNKNOWN＋LIKELY_FIXED。所見だけを数え、走査できなかった範囲は `skipped` にある）、`by_status`（判定ごとの件数） |
| `exit_code` | 終了コード（下表） |
| `disclaimer` | 侵入の有無は調べない旨 |

## status

| 値 | 意味 |
|---|---|
| `VULNERABLE` | 既知の脆弱な版。更新が必要 |
| `FIXED` | 取得した版が、既知データの修正版の条件を満たした。何から版を取ったか（パッケージの記録、プログラムの出力、デコーダーの文字列で修正を確かめたファイル）は `reason` に書く（ファイルのときは、分かったことと分からないことも）。`next_step` はこの行についてだけで、ほかの行と `skipped` は別 |
| `NO_FIX_AVAILABLE` | 配布元が修正版をまだ出していない |
| `RESTART_REQUIRED` | 削除済みの Brotli 関連のファイル（libbrotlidec、`_brotli*.so`、node・bun の実行ファイル）を使い続けているプロセスがある。同じパスにいまあるファイルが修正版かは判定名に含まない。`reason` に、この結果がそのファイルをどう判定したか（判定していない、ファイルが無い、別のマウント名前空間のプロセス、のどれか）を書き、`next_step` はそれに従う（再起動する／先に更新する／版を確かめてから再起動する） |
| `VENDORED_COPY` | デコーダーを同梱している。版を人が確認する必要がある |
| `LIKELY_FIXED`, `LIKELY_VULNERABLE` | 試したビルドで確かめた文字列による推定。`confidence` を参照 |
| `EXPOSURE` | 攻撃者のデータがデコーダーに届く経路の手がかり（脆弱性そのものではない）。見たことと見ていないことは `reason` に書く。出ないことは経路が無いことの証明ではない |
| `NOT_APPLICABLE` | そのファイルにデコーダーの形跡が無く、ソースを確かめた配布元のパッケージ、`cbrotli` の無い Go のプログラム、`curl -V` が brotli を挙げないこと、のどれかが裏づける。無いことの証明ではなく、何を根拠にしたかは `reason` に書く |
| `UNKNOWN` | 判定できない。理由は `reason` |
| `SKIPPED` | 予約。走査しなかった範囲は `skipped` に出す |

## skipped

見ていない範囲は 1 つずつ要素になります。`scope`（検出項目、パス、`root` などの名前）、`reason`、`kind`:

| `kind` | 意味 | 終了コード |
|---|---|---|
| `chosen` | 実行のしかたで外れた。付けなかったオプション（付けたもの: `--exclude`・`--no-exec`）、実行に選ばなかったプログラム、root でないこと（とそのために読めなかったもの）、ネットワークファイルシステムと探す場所の下の別の種類のファイルシステム、オプションが数えるだけのもの（止まっているコンテナとイメージ）、readelf が無いこと（そのために決まらなかったものは `UNKNOWN` の所見か `failed` の要素になる）。テキストの結果では「走査しなかった範囲」、`[SKIPPED]` | 数えない |
| `failed` | 見ようとしたのに見られなかった。コマンドの失敗、点検に要るプログラムが無い（dpkg、`--exposure` の ss、`--containers` の docker と podman）、時間切れ、最後まで読めなかったファイルや上限を超えるファイル、辿り切れなかったリンク、root でも読めなかったもの、`--roots`・`--envoy-config` で名指ししたのに無いもの、`--inspect-containers` を付けたのに中を見なかったコンテナ。テキストの結果では「走査できなかった範囲」、`[FAILED]` | `1` に当たるものが無ければ `2` |

同じ `scope` は種類ごとに 1 つまでです。テキストの要約は種類ごとに 1 行で範囲を並べます（無いときは「走査できなかった範囲: なし」）。

## exit_code

| 値 | 意味 |
|---|---|
| 0 | 走査した範囲に 1 と 2 に当たる判定が無く、`kind` が `failed` の `skipped` も無い。`chosen` は数えないので、全部を見たという意味ではない（安全の証明でもない） |
| 1 | `VULNERABLE` または `RESTART_REQUIRED` がある（`skipped` によらない） |
| 2 | 上記は無いが、`NO_FIX_AVAILABLE`・`VENDORED_COPY`・`LIKELY_*`・`UNKNOWN` があるか、`kind` が `failed` の `skipped` がある（このとき `summary.needs_review` は 0 のこともある） |
| 3 | ツール自体のエラー（不正なオプション、既知データを読めない、など） |

自動化では `exit_code` とあわせて `skipped` と `options` を見てください。点検に要るプログラムが無いことは `failed` なので、
docker も podman も無いホストに `--containers` を付ける（ss の無いホストに `--exposure` を付ける）と、毎回 2 になります。

## 注意

- `reason`・`next_step`・`info[].text` は `--lang` で選んだ言語です。`evidence` のうち既知データ由来の
  `note` は常に英語です。
- プロセスのコマンドラインは `--show-cmdline` のときだけ `evidence` に入ります。
- 文字列は RFC 8259 に従ってエスケープし、制御文字は `\u00XX` で表します。
- `execution[].path` と `execution[].facts` のパスは見つけたとおりです（改行は `\n`）。`findings`・`info`・`skipped`
  の欄の中のタブ・改行・復帰は `?` で表します（ツールの中でタブ区切りで持つため）。テキストの結果では制御文字はすべて `?` です。
