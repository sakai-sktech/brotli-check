# 検証結果

English: [verification.md](verification.md)

最初の公開の前に何を、どう確かめ、どうなったか。最初の確認: **2026-10-26**、更新: **2026-10-27**（既知データ 2026-10-27 時点。
設計メモ 2.1）。

A4 一枚の図解: [図解 01 何を、どのようにチェックしたか](zukai/01_check-method_ja.pdf)・
[図解 02 5 つの OS での点検結果と読み方](zukai/02_results-reading_ja.pdf)
（英語版: [Fig. 01](zukai/01_check-method_en.pdf)、[Fig. 02](zukai/02_results-reading_en.pdf)）。

## この結果の読み方（2026-10-27 時点）

下の統合テストでは、各イメージに未修正のものと修正済みのものを意図的に入れているので、どの実行も
終了コード 1 になります。分かることは次のとおりです。

- **ツールの判定は正しい。** 期待した判定はすべて一致しました（root と一般ユーザーのそれぞれで、`--no-exec` でも `--yes` でも）。
- **OS の Brotli は、試したすべてのディストリビューションで修正済みです。** Ubuntu は 2026-10-26 に 22.04・24.04・26.04・
  26.10 を修正しました（USN-8956-1: `1.0.9-2ubuntu0.1`・`1.1.0-2ubuntu0.1`・`1.2.0-3ubuntu0.1`・`1.2.0-4ubuntu0.1`）。Debian は
  12（`1.0.9-2+deb12u1`）と 13（`1.1.0-2+deb13u1`）を修正済みです。いま作ったイメージにはこれらの版が入り、5 つとも
  `libbrotli1` と `python3-brotli` は `FIXED` です。その後に更新していないホストでは `VULNERABLE` になります。apt で更新し、
  それを使うものを再起動してください（ツールはそのプロセスを `RESTART_REQUIRED` で挙げます）。
  - 2026-10-27 の既知データより前は、Ubuntu のパッケージを `NO_FIX_AVAILABLE` と出していました。2026-10-26 の時点では
    CVE のページが「Needs evaluation」で USN が無く、同じ日の後で USN が出たときにデータを更新していなかったためです。
    2026-10-27 に取った出力例は、修正版をそう出していました（設計メモ 2.1）。
- **同梱コピーは OS の更新では直りません。** Node.js 22.23.4 と PyPI の Brotli 1.2.1 は OS に関係なく `FIXED`、その前の版は
  `VULNERABLE` です。製品ごとに更新が要るので、ツールが探しに行きます。

## 静的検査と単体テスト

| 検査 | 道具 | 結果 |
|---|---|---|
| `make lint`（ファイル単位と、1 ファイル版の全項目） | ShellCheck 0.9.0（Ubuntu パッケージ）と 0.10.0（上流リリース） | 警告ゼロ |
| `make test` | Bats 1.10.0（Ubuntu パッケージ）と bats-core 1.11.1 | 83 / 83 成功（初回） |
| Codex レビュー 4 回目の修正後の `make lint`・`make test` | ShellCheck 0.9.0、Bats 1.10.0 | 警告ゼロ、123 / 123 成功 |
| 5 回目の修正後の同じもの | ShellCheck 0.9.0、Bats 1.10.0 | 警告ゼロ、134 / 134 成功 |
| 同意して実行する形と 6 回目の修正の後（2026-10-27） | ShellCheck 0.9.0、Bats 1.10.0 | 警告ゼロ、153 / 153 成功 |
| 自動セキュリティレビューの指摘を直した後（2026-10-27、設計メモ 10 章 13） | ShellCheck 0.9.0、Bats 1.10.0 | 警告ゼロ、161 / 161 成功。新しい 8 件は直す前のコードで落ちる |
| 2026-10-27 の変異テスト（テスト記録 13 章）と既知データの更新の後 | Bats 1.10.0 | 修正 91 個を 1 つずつ戻して 69 個で落ちた。落ちなかった 21 個の穴にテスト 10 件を足し、測り直した 22 個はすべて落ちた。172 / 172 成功 |

## 統合テスト（`tests/integration/`）

Docker 28.3.0（Docker Desktop、x86_64）。各イメージには、ディストリビューションに加えて次を入れます:
`/opt` に Node.js 公式の 22.23.3 と 22.23.4（`SHASUMS256.txt` で検証）、`/srv/venv-old` に PyPI の
Brotli 1.2.0 と urllib3、`/srv/venv-new` に Brotli 1.2.1。2026-10-27 からは各イメージを、root と一般ユーザーの
それぞれで `--no-exec` と `--yes` の 4 回点検します（見つけたプログラムは同意があるときだけ実行し、コンテナには
尋ねる端末が無いため）。それ以前（4・5 回目の後）は、root の既定・root の `--allow-exec`・一般ユーザーの
`--no-exec` の 3 回でした。さらに `--inspect-containers`
（C14）がコンテナの中で動かす固定のスクリプトを、各イメージ自身の `/bin/sh`（dash）で、2 つの Node.js を
`PATH` に置いて走らせ、両方の Node.js・パッケージ・最後の `END` 行が出ることを確かめます。

| イメージ（ツールの表示） | Python | `libbrotli1`／`python3-brotli`（2026-10-27 に作ったイメージ、2026-10-27 の既知データ。2026-10-26 のデータでは Ubuntu の行は `NO_FIX_AVAILABLE`） | Node.js 22.23.3／22.23.4 | PyPI Brotli 1.2.0／1.2.1 | 1.2.0 の隣の urllib3 | すべての走査（4 回）／C14 のスクリプト |
|---|---|---|---|---|---|---|
| Ubuntu 22.04.5 LTS | 3.10 | 1.0.9-2ubuntu0.1: `FIXED` | `VULNERABLE`／`FIXED` | `VULNERABLE`／`FIXED` | `EXPOSURE` | 合格／合格 |
| Ubuntu 24.04.5 LTS | 3.12 | 1.1.0-2ubuntu0.1: `FIXED` | `VULNERABLE`／`FIXED` | `VULNERABLE`／`FIXED` | `EXPOSURE` | 合格／合格 |
| Ubuntu 26.04.1 LTS | 3.14 | 1.2.0-3ubuntu0.1: `FIXED` | `VULNERABLE`／`FIXED` | `VULNERABLE`／`FIXED` | `EXPOSURE` | 合格／合格 |
| Debian 12（bookworm） | 3.11 | 1.0.9-2+deb12u1: `FIXED` | `VULNERABLE`／`FIXED` | `VULNERABLE`／`FIXED` | `EXPOSURE` | 合格／合格 |
| Debian 13（trixie） | 3.13 | 1.1.0-2+deb13u1: `FIXED` | `VULNERABLE`／`FIXED` | `VULNERABLE`／`FIXED` | `EXPOSURE` | 合格／合格 |

補足:

- Node.js の tarball は、root で展開しても作成者の所有者（root でない uid）が残ります。`--yes` では実行し（結果の
  事実にその所有者が出る）、`--no-exec` では `include/node/node_version.h` から版を読みます。判定はどちらも同じでした。
- Codex レビュー 4 回目の修正の後、5 回目の修正の後（2026-10-26）、同意して実行する形と 6 回目の修正の後
  （2026-10-27、bash 4.2 は `--yes`）、設計メモ 10 章 13 の修正の後（2026-10-27）に、Docker 28.3.0 で実行: すべての行が合格、
  bash 4.2 も合格。
  修正前の C14 のスクリプトを同じように走らせると、Node.js の行も `END` も出なかった（指摘 10 の欠陥）。
- **bash 4.2**（`bash:4.2`、ダイジェスト `sha256:75a8dcd5c2a865e69116225dc486e2dbdd2dda1434759fa7f1fc50c72eeadbea`、
  GNU の coreutils・findutils・grep・sed・gawk・binutils を追加）: PyPI の Brotli 1.2.0 の記録を見つけて
  `VULNERABLE` と判定し、終了コード 1、JSON は正しく読めました。
- Ubuntu 24.04 のイメージでの出力例: [sample-output.md](sample-output.md)。

この結果の前に統合テストで見つかり、直した問題: Node.js を取得する補助スクリプトに実行権限が無かった／
期待値の誤り（`EXPOSURE` には Brotli の隣に HTTP クライアントが要るが、最初のイメージには無かった）／
bash 4.2 の確認が判定の経路を通っていなかった／英語のメッセージ 2 つが件数 1 のとき文法が崩れていた。

## Codex の敵対的レビュー 4 回目

指摘 10 件（P1 × 6、P2 × 4）。すべて確認して直した。判断は [design.ja.md 10 章 9](design.ja.md#10-実装時に加えた判断2026-10-26)。
修正ごとに単体テストを `tests/unit/hardening.bats`（と `cli.bats` に 1 つ）に置いた。テストが欠陥を捉えるかを確かめる
ため、作業ツリーの写しで 12 の修正を 1 つずつ元に戻し、対応するテストを走らせた。戻すとどれも少なくとも 1 つの
テストが落ちた（うち 3 つは先にテストを鋭くした: マウントと `PATH` のテストは呼び出し元を見ておらず、依存の
テストは `/tmp` のような誰でも書けるディレクトリの下では skip される）。

開発機での所要は約 20 秒のまま（依存の検査の最初の版は 51 秒。design.ja.md 10 章 9）。

5 回目（単一ファイル版の全体をもう一度）: 4 回目の 2・3・4・9・10 は修正済みと確認され、ほかに 10 件の指摘
（design.ja.md 10 章 10）。うち 2 件は先に実験で確かめた: 探索場所が symlink だと `find -P` はその下を 1 つも
歩かない／RUNPATH が `:/nonexistent` のプログラムは作業ディレクトリのライブラリを読み込んだ。修正ごとに
`hardening.bats`（と `cli.bats` に 1 つ）にテストを置き、13 の修正を 1 つずつ戻すとどれもテストが落ちた（2 つは
先にテストを鋭くした: 末尾の空の RUNPATH 項目、何にも当たっていなかったテストの絞り込み）。開発機での所要と
所見は 5 回目の前と同じで、変わったのは文字列による推定の文面だけ。

## 同梱コピーの文字列による推定（C09）

Brotli 1.2.0 と 1.2.1 を共有・静的ライブラリで（-O2 と LTO、strip の有無）ビルドしたもの、Node.js 公式の
22.23.3／22.23.4／24.22.0／24.22.1、PyPI の Brotli と brotlicffi の wheel で確かめました。修正済みのものには
すべて `_ERROR_FORMAT_BLOCK_SWITCH` があり、未修正のものにはありません。判定できないのは、LTO と不要部分の
削除を使い、かつ `BrotliDecoderErrorString` を呼ばないプログラムだけで、そのときは `VENDORED_COPY` とします。
`tests/fixtures/c09/reproduce.sh` を空の状態から再実行すると、fixture はバイト単位で一致しました。
詳細とダウンロードの SHA256: [tests/fixtures/c09/README.md](../tests/fixtures/c09/README.md)。

## 実際の作業端末で

開発者の作業端末（Ubuntu 24.04、一般ユーザー）で動かすと、OS の更新では直らないコピーが見つかりました。
例: VS Code Server が抱える Node.js 14.16.0、Playwright と GitHub Actions のセルフホストランナーが抱える
Node.js（ランナーのプロセス 1 つは置き換え後も古い実行ファイルで動いていた: `RESTART_REQUIRED`）、Pillow の
wheel の中の `libbrotlidec` 1.2.0、`--deep` では Cloudflare workerd、.NET の
`libSystem.IO.Compression.Native.so`、PyMuPDF、いくつかの Electron アプリ。パスはここには載せません。

## 一次資料

既知の版をすべて一次資料で確かめ直した結果と、それによる訂正は
[design.ja.md の 2 章](design.ja.md#2-一次資料の再確認結果2026-10-26-確定分)にあります。
