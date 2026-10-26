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
| `host` | OS（`/etc/os-release`）、パッケージの系列（例 `ubuntu:noble`）、カーネル、uid、root かどうか |
| `options` | 指定されたオプション |
| `scanned_roots` | 探索した場所 |
| `skipped[]` | **走査しなかった範囲**（`scope` と `reason`）。必ず出す |
| `findings[]` | 所見。`id`（C01〜C15）、`status`、`component`、`path`、`version`、`reason`、`next_step`、`evidence`、`confidence` |
| `info[]` | 所見ではない補足（件数や終了コードに影響しない） |
| `summary` | `needs_update`（VULNERABLE＋LIKELY_VULNERABLE）、`needs_restart`（RESTART_REQUIRED）、`needs_review`（NO_FIX_AVAILABLE＋VENDORED_COPY＋UNKNOWN＋LIKELY_FIXED）、`by_status`（判定ごとの件数） |
| `exit_code` | 終了コード（下表） |
| `disclaimer` | 侵入の有無は調べない旨 |

## status

| 値 | 意味 |
|---|---|
| `VULNERABLE` | 既知の脆弱な版。更新が必要 |
| `FIXED` | 修正を含む版 |
| `NO_FIX_AVAILABLE` | 配布元が修正版をまだ出していない |
| `RESTART_REQUIRED` | 修正はディスク上にあるが、古いコードで動き続けているプロセスがある |
| `VENDORED_COPY` | デコーダーを同梱している。版を人が確認する必要がある |
| `LIKELY_FIXED`, `LIKELY_VULNERABLE` | 検証済みの文字列による推定。`confidence` を参照 |
| `EXPOSURE` | 攻撃者のデータがデコーダーに届く経路の手がかり（脆弱性そのものではない） |
| `NOT_APPLICABLE` | そのファイルにはデコーダーがない（圧縮専用、または Brotli なし） |
| `UNKNOWN` | 判定できない。理由は `reason` |
| `SKIPPED` | 予約。走査しなかった範囲は `skipped` に出す |

## exit_code

| 値 | 意味 |
|---|---|
| 0 | 走査した範囲に、1 と 2 に当たる判定が無い（安全の証明ではない） |
| 1 | `VULNERABLE` または `RESTART_REQUIRED` がある |
| 2 | 上記は無いが、`NO_FIX_AVAILABLE`・`VENDORED_COPY`・`LIKELY_*`・`UNKNOWN` がある |
| 3 | ツール自体のエラー（不正なオプション、既知データを読めない、など） |

## 注意

- `reason`・`next_step`・`info[].text` は `--lang` で選んだ言語です。`evidence` のうち既知データ由来の
  `note` は常に英語です。
- プロセスのコマンドラインは `--show-cmdline` のときだけ `evidence` に入ります。
- 文字列は RFC 8259 に従ってエスケープし、制御文字は `\u00XX` で表します。
