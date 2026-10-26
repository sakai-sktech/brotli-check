# 検証結果

English: [verification.md](verification.md)

最初の公開の前に何を、どう確かめ、どうなったか。実施日: **2026-10-26**。既知データ: 2026-10-26 時点。

A4 一枚の図解: [図解 01 何を、どのようにチェックしたか](zukai/01_check-method_ja.pdf)・
[図解 02 5 つの OS での点検結果と読み方](zukai/02_results-reading_ja.pdf)
（英語版: [Fig. 01](zukai/01_check-method_en.pdf)、[Fig. 02](zukai/02_results-reading_en.pdf)）。

## この結果の読み方（2026-10-26 時点）

下の統合テストでは、各イメージに未修正のものと修正済みのものを意図的に入れているので、どの実行も
終了コード 1 になります。分かることは次のとおりです。

- **ツールの判定は正しい。** 期待した判定はすべて一致しました（root でも、一般ユーザーの `--no-exec` でも）。
- **Ubuntu: OS の Brotli は、どのリリースでもまだ修正されていません。** 22.04・24.04・26.04（と 26.10）の
  `libbrotli1` と `python3-brotli` は `NO_FIX_AVAILABLE` です。入っている版（1.0.9・1.1.0・1.2.0）はどれも
  影響範囲 1.0.3〜1.2.0 の中にあり、Ubuntu は修正版を出していません（CVE のページは「Needs evaluation」、
  USN なし）。
  - 修正候補（`1.0.9-2ubuntu0.1`・`1.1.0-2ubuntu0.1`・`1.2.0-3ubuntu0.1`・`1.2.0-4ubuntu0.1`）は
    2026-10-25 に `ubuntu-security-proposed` の PPA に出ています。ただしこれは試験用で、普通のシステムは
    使いません。一般のシステムに届くのは、USN が出て `-security` に載ってからです。それまでは Ubuntu から
    入れられるものは無く、ツールの案内も「待つ。待つ間は同梱コピーのある製品を優先して更新する」です。
- **Debian: 修正済み。** Debian 12（`1.0.9-2+deb12u1`）と 13（`1.1.0-2+deb13u1`）は `FIXED` です。
- **同梱コピーは、どのディストリビューションでも今すぐ直せます。** Node.js 22.23.4 と PyPI の Brotli 1.2.1
  は OS に関係なく `FIXED`、その前の版は `VULNERABLE` です。これらは OS の更新では直らないので、ツールが
  探しに行きます。

## 静的検査と単体テスト

| 検査 | 道具 | 結果 |
|---|---|---|
| `make lint`（ファイル単位と、1 ファイル版の全項目） | ShellCheck 0.9.0（Ubuntu パッケージ）と 0.10.0（上流リリース） | 警告ゼロ |
| `make test` | Bats 1.10.0（Ubuntu パッケージ）と bats-core 1.11.1 | 83 / 83 成功 |

## 統合テスト（`tests/integration/`）

Docker 28.3.0（Docker Desktop、x86_64）。各イメージには、ディストリビューションに加えて次を入れます:
`/opt` に Node.js 公式の 22.23.3 と 22.23.4（`SHASUMS256.txt` で検証）、`/srv/venv-old` に PyPI の
Brotli 1.2.0 と urllib3、`/srv/venv-new` に Brotli 1.2.1。各イメージを root と、一般ユーザーの
`--no-exec` の 2 回点検します。

| イメージ（ツールの表示） | Python | `libbrotli1`／`python3-brotli` | Node.js 22.23.3／22.23.4 | PyPI Brotli 1.2.0／1.2.1 | 1.2.0 の隣の urllib3 | root／一般 |
|---|---|---|---|---|---|---|
| Ubuntu 22.04.5 LTS | 3.10 | 1.0.9-2build6: `NO_FIX_AVAILABLE` | `VULNERABLE`／`FIXED` | `VULNERABLE`／`FIXED` | `EXPOSURE` | 合格／合格 |
| Ubuntu 24.04.5 LTS | 3.12 | 1.1.0-2build2: `NO_FIX_AVAILABLE` | `VULNERABLE`／`FIXED` | `VULNERABLE`／`FIXED` | `EXPOSURE` | 合格／合格 |
| Ubuntu 26.04.1 LTS | 3.14 | 1.2.0-3build1: `NO_FIX_AVAILABLE` | `VULNERABLE`／`FIXED` | `VULNERABLE`／`FIXED` | `EXPOSURE` | 合格／合格 |
| Debian 12（bookworm） | 3.11 | 1.0.9-2+deb12u1: `FIXED` | `VULNERABLE`／`FIXED` | `VULNERABLE`／`FIXED` | `EXPOSURE` | 合格／合格 |
| Debian 13（trixie） | 3.13 | 1.1.0-2+deb13u1: `FIXED` | `VULNERABLE`／`FIXED` | `VULNERABLE`／`FIXED` | `EXPOSURE` | 合格／合格 |

補足:

- Node.js の tarball は、root で展開しても作成者の所有者（uid 1001）が残ります。そのため root では実行せず、
  `include/node/node_version.h` から版を読みました。判定は `--version` で取った場合と同じでした。
- **bash 4.2**（`bash:4.2`、ダイジェスト `sha256:75a8dcd5c2a865e69116225dc486e2dbdd2dda1434759fa7f1fc50c72eeadbea`、
  GNU の coreutils・findutils・grep・sed・gawk・binutils を追加）: PyPI の Brotli 1.2.0 の記録を見つけて
  `VULNERABLE` と判定し、終了コード 1、JSON は正しく読めました。
- Ubuntu 24.04 のイメージでの出力例: [sample-output.md](sample-output.md)。

この結果の前に統合テストで見つかり、直した問題: Node.js を取得する補助スクリプトに実行権限が無かった／
期待値の誤り（`EXPOSURE` には Brotli の隣に HTTP クライアントが要るが、最初のイメージには無かった）／
bash 4.2 の確認が判定の経路を通っていなかった／英語のメッセージ 2 つが件数 1 のとき文法が崩れていた。

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
