# どう調べ、どこで止まるか

English: [how-it-checks.md](how-it-checks.md)

brotli-cve-check が何を、どうやって調べ、どこで止まるかを、検出項目（C01〜C15）ごとに書いた資料です。読む相手は、このツールを
動かす管理者です。結果が何を確かめたもので、何を確かめていないかを読むために使ってください。

## この資料の位置づけ

- **走査の結果が原本です。** それをどう扱うか（誰に何を報告するか、さらに調べるか）は、使う現場が決めることで、このツールは決めません。
- **どこまで調べるかは設計で決めています。この資料はその決まりです。** コードがこの資料と違えば、それは不具合です。止まる所を変えるのは
  設計の変更で、設計メモ（[design.ja.md](design.ja.md)）10 章に判断を書き、同じ変更でこの資料を直します（[CONTRIBUTING.md](../CONTRIBUTING.md)、設計メモ 10 章 30）。
- 見落としうるものの要約は [limitations.ja.md](limitations.ja.md)、判断の経緯は設計メモ、結果の欄の意味は [json-schema.ja.md](json-schema.ja.md) にあります。
- main のコード（コミット `c964751`、v0.2.0 として出すもの）と突き合わせて書きました。

## 読み方

- 各項目は同じ 4 つの問いに答えます: **何を探すか／どうやって見つけるか／何を読み、どの順で判定を決めるか／どこで止まるか**。
- 「どこで止まるか」には、止まったときに結果に何が出るか（何も出ないか）と、その止まり方を決めた記録を付けます。
  〔設計 10.28〕は設計メモの 10 章 28、〔設計 6〕は 6 章です。**〔記録なし〕は、止まる所を決めた記録が無いもの**です（今の動きはコードのとおり）。
- コードがこの資料と違うと分かっていて、直すと決めた所には〔不具合〕を付け、決まりと、いまの動きの両方を書きます。
  止まる所を変えると決めた所には〔変える予定〕を付け、いまの止まり方を書きます（変えるときに、設計メモ 10 章とこの資料を直します）。
- 各項目の最後の「裏づけ」に、書いたことをどう確かめたかを書きます。
  〔試験〕単体試験（`tests/unit/` のファイルと試験名）、〔統合〕統合試験（`tests/integration/`、5 つのイメージ）、
  〔実測〕開発者の端末（Ubuntu 24.04）で動かしたもの、〔コード〕コードを読んだだけで試験の無いもの（`lib/` の関数名）。
- 結果の文の例は `--lang ja` のものです。

## 目次

1. [全体に共通すること](#1-全体に共通すること)
2. [検出項目ごと](#2-検出項目ごと): [C01](#c01-os-のパッケージ) · [C02](#c02-libbrotli1-に依存するパッケージ情報) · [C03](#c03-削除済みのファイルを使い続けるプロセス) · [C04](#c04-nodejs) · [C05](#c05-bun) ·
   [C06](#c06-pythonpypi-の-brotlibrotlicfficonda) · [C07](#c07-nodejs-のプロジェクト--projects) · [C08](#c08-curl) · [C09](#c09-同梱のデコーダー) · [C10](#c10-envoy) ·
   [C11](#c11-web-サーバー) · [C12](#c12-snapflatpak) · [C13](#c13-ブラウザ) · [C14](#c14-コンテナ--containers--inspect-containers) · [C15](#c15-待ち受け--exposure)

---

## 1. 全体に共通すること

### 1.1 手がかり — デコーダーのコピーをどう見つけるか

このツールは、次の手がかりのどれかがあるコピーだけを見つけます。**どの手がかりも無いコピーは見つかりません。**

| 手がかり | 何で見るか | 使う項目 |
|---|---|---|
| パッケージの記録 | `dpkg-query`（ホストと、コンテナの中）、`snap list`、`flatpak list` | C01・C02・C09（Ubuntu の .NET）・C11・C12・C13・C14 |
| 決まった名前のファイル | 探す場所を 1 回歩いて作る名前の索引（1.2）と、決まった場所の候補 | C04・C05・C06・C09・C10・C11・C13 |
| Brotli を抱えると分かっている製品の実行ファイル | node、bun、envoy、curl、nginx・Apache・HAProxy・Traefik・Caddy、Chromium・Chrome・Firefox、Electron のアプリ、.NET | C04・C05・C08・C09・C10・C11・C12・C13 |
| ELF の中の文字列 | デコーダーの関数名とエラー名（1.4） | `--deep`（C09）。ほかの項目も、版の分からないファイルをこれで判定する |
| 動いているプロセス | `/proc/*/maps`、`/proc/*/exe` | C03・C04・C05 |
| 経路の手がかり（デコーダーそのものではない） | Python の HTTP クライアントのメタデータ、`package.json`、Envoy の設定ファイル、待ち受け | C06・C07・C10・C15 |

見つからない例: 名前の違うファイルに組み込まれ、印の消えた静的なコピー。`--deep` を付けないときの、名前の違うファイルの中のコピー。
アーカイブ（`.asar`・`.jar`・`.zip`）、squashfs（snap・AppImage）、止まっているコンテナ・コンテナイメージ・仮想マシンのディスクの中。探す場所の外。

### 1.2 どこを歩くか

**探す場所（roots）:** 既定は `/opt,/usr/local,/srv,/var/www,/home,/root`。`--roots` は置き換えます（足すのではありません）。

**名前の索引:** 1 回の `find` で、探す場所と、次の決まった場所を歩きます（`--roots` によらず）:
`/usr/lib`、`/usr/lib64`、`/lib64`、`/usr/share/dotnet`（それぞれシンボリックリンクでないとき）、Python のディレクトリ
（`/usr/lib/python3`、`/usr/lib/python3.*`、`/usr/local/lib/python3.*`、各ホームの `.local/lib`・mise・pyenv・uv・pipx・conda（`.conda`・
`miniconda3`・`anaconda3`・`miniforge3`）・`.virtualenvs`）。拾う名前は次のとおりです。

| 名前 | 使う項目 |
|---|---|
| `brotli-*.dist-info`・`brotli-*.egg-info`・`brotlicffi-*.dist-info`・`brotlicffi-*.egg-info`（大文字・小文字を問わない） | C06 |
| `conda-meta/libbrotlidec-<数字>*.json`（通常のファイル） | C06（conda） |
| `libbrotlidec*.so*`・`libbrotlidec*.a`（通常のファイル） | C09 |
| `libSystem.IO.Compression.Native.so`・`System.IO.Compression.Native.so`（通常のファイル） | C09（.NET） |
| `node`・`nodejs`・`bun`・`envoy`（持ち主の実行ビットのある通常のファイル） | C04・C05・C10 |

**歩き方:** `find -P`（シンボリックリンクを辿らない）と `-xdev`。`/proc`・`/sys`・`/dev`・`/run`、`--exclude` の場所、ネットワークファイルシステム
（NFS・CIFS・sshfs など。`--include-remote` を付けない限り）には入りません。探す場所の下にマウントされたローカルディスクのファイルシステム
（ext4・xfs・btrfs・zfs など）は、それ自体を探す場所として歩きます。探す場所そのものがシンボリックリンクなら、リンク先を歩きます（情報に 1 行）。
パッケージ管理のキャッシュ（pip・uv・poetry・npm・yarn・NuGet）の中で見つけたものは、件数だけを情報に出し、報告しません。

**ホーム:** `getent passwd` の uid 0 と 1000〜65533 で、ホームが `/` でないもの。

**どこで止まるか**

- 既定の探す場所が無い → 黙って外す。`--roots` で名指しした場所が無い → 走査できなかった範囲〔設計 10.26.2〕
- 読めない探す場所・ホーム → root でなければ走査しなかった範囲、root なら走査できなかった範囲〔設計 10.26.3〕
- `find` が読めなかったディレクトリ → 数と例を 1 行。理由が Permission denied だけで root でなければ走査しなかった範囲、それ以外は走査できなかった範囲。
  歩いている間に消えたファイルは数えない〔設計 10.9.8・10.26.3〕
- `find` の時間切れ（`--timeout`、既定 120 秒）→ 走査できなかった範囲〔設計 10.9.8〕
- 探す場所の下の、ローカルディスクでないファイルシステム（tmpfs・overlay・squashfs・fuse など）→ 入らない。種類ごとに 1 行、走査しなかった範囲〔設計 10.9.9〕
- マウントポイントでない btrfs のサブボリューム → 入らない。**何も出ない**〔設計 10.9.9〕
- ネットワークファイルシステム → 走査しなかった範囲〔設計 7〕。`--exclude` の場所 → 走査しなかった範囲
- パッケージ管理のキャッシュ → 件数だけ情報に〔設計 10.2・10.27.5〕
- 探す場所と決まった場所の外 → 見ない。何も出ない〔設計 10.1〕
- 名前で見つけた候補（C04・C05・C08・C10・C11・C13）のうち、このユーザーが実行できない、または読めないもの → 候補にしない。何も出ない。
  root では起きない（実行ビットがどこかにあれば実行でき、読めないものは無い）。root でない実行では「root」の行（走査しなかった範囲）が覆う〔設計 10.30〕

### 1.3 読み込むライブラリの辿り方

プログラムやライブラリが libbrotlidec を読み込むかは、ファイルを `readelf` で読んで、glibc の ld.so と同じ順で辿ります（プログラムは動かしません。
`ldd` も使いません）。使うのは C04（node）・C08（curl）・C11（サーバー）・C09 `--deep`（NEEDED に libbrotlidec のあるファイル）・別の名前へのリンク、
それと実行の一覧に付ける事実（1.6）です。

1. `readelf -l` で PT_INTERP（ローダー）、`readelf -d` で NEEDED・RPATH・RUNPATH・SONAME を読む。
2. 要るライブラリの名前ごとに、次の順で探す:
   その名前を要るもの（と、それを読み込んだものをプログラムまで遡ったもの）の RPATH（要るものに RUNPATH があれば RPATH は使わない）→
   その RUNPATH → ld.so のキャッシュ（`ldconfig -p`。64 ビットの項目を先に）→ 既定のディレクトリ（`/lib64`・`/usr/lib64`・`/lib/x86_64-linux-gnu`・
   `/usr/lib/x86_64-linux-gnu`・`/lib/aarch64-linux-gnu`・`/usr/lib/aarch64-linux-gnu`・`/lib`・`/usr/lib`）。
3. どのディレクトリでも、`glibc-hwcaps` の下位ディレクトリ（`x86-64-v3` など）を先に試す。順はこのホストのシステムのローダーに `--help` で尋ねたもの
   （1 回の実行で 1 度。`/` から、環境変数を空にして。root のほかにローダーを変えられる人がいなく、glibc 2.33 以降のときだけ。`--no-exec` でも尋ねる）。
   尋ねられないとき、またはプログラムが別のローダーを名乗るときは、下位ディレクトリのコピーをすべて候補にし、どれが読み込まれるかは分からないと情報に書く。
4. RPATH・RUNPATH の `$ORIGIN` は展開する。`$LIB` などの記号、相対の項目、空の項目では探さない（実行の一覧の事実に書く）。
5. 幅優先。一度読み込んだ名前（SONAME を含む）はもう探さない。8 段まで。

結果は、届いた `libbrotlidec*` のすべて（読み込む順、ファイルごとに 1 つ。見つからないものは「名前 (not found)」）と、次の 3 つの状態のどれかです。

| 状態 | 意味 | 各項目のあつかい |
|---|---|---|
| 読み込む | libbrotlidec が 1 つ以上ある | それぞれを判定する。C01 が判定したパッケージのファイルなら情報（C01 に従う）、それ以外のコピーは C09 として判定、見つからないものは `UNKNOWN` |
| 読み込まない | 最後まで辿れて、libbrotlidec は無い | 静的なコピーか Brotli なし。項目ごと |
| 決まらない | libbrotlidec が 1 つも見つからず、readelf が無い・readelf が失敗した・要るライブラリが見つからない・8 段を超えた | 項目ごと（多くは `UNKNOWN`） |

〔不具合〕「決まらない」で `UNKNOWN` にする行は、理由に何が辿れなかったか（見つからないライブラリの名前、readelf が失敗したファイル、段数の上限）を書き、
次にやることはその場面に合わせる（binutils を入れるよう勧めるのは readelf が無いときだけ）。いまのコードは C04（パッケージの node）・C08・C09 `--deep`・C11 で、
どの場合も「libbrotlidec を読み込むかどうかを判定できませんでした。」と「binutils（readelf）を入れて再実行する。」を出す（readelf があっても）。

**どこで止まるか**

- `LD_LIBRARY_PATH`・`LD_PRELOAD`、`dlopen` で後から開くもの → 見ない。`/etc/ld.so.preload` は実行の一覧の事実にだけ使う〔設計 10.11〕
- glibc 2.36 以前の旧式の hwcaps の下位ディレクトリ（`tls`・`x86_64`・`haswell/x86_64` など）と、そのキャッシュの項目 → 見ない。**何も出ない**〔設計 10.28.5〕
- 順はこのホストの CPU と、環境変数を空にして尋ねたローダーのもの。`GLIBC_TUNABLES` を付けて起動したサービスや、別のマシンでは、別のコピーが読み込まれうる〔設計 10.28.5〕
- 見つからない・読めないライブラリ、8 段の上限 → libbrotlidec が 1 つでも見つかっていれば、それだけで判定し、**辿りが途中で止まったことは何も出ない**
  〔設計 10.28.5。8 段という数は記録なし〕〔変える予定: 辿り切れなかったことを結果に出す〕。1 つも見つからなければ「決まらない」（各項目へ）
- readelf が無い → すべて「決まらない」。走査しなかった範囲に「binutils」の 1 行〔設計 4・10.26.1〕

### 1.4 文字列による推定

版の分からないコピーと、ファイルから読んだ版の確かめ（1.5）には、ファイルの中の文字列を使います。ファイルは通常のファイルだけを、
制限時間の下で 512 MiB まで読み、表示できる文字の並びに分けて、次を数えます。

- `_ERROR_FORMAT_` で始まるエラー名（それだけの文字列。異なるものを 64 個まで）と、その中に `_ERROR_FORMAT_BLOCK_SWITCH`（修正で足されたエラー -17）があるか
- Brotli の組み込みの辞書の数（コピー 1 つに 1 個）
- デコーダーの印: `BrotliDecoderDecompressStream`・`BrotliDecoderCreateInstance`・`_ERROR_FORMAT_EXUBERANT_NIBBLE`
- Go のビルド情報と、cgo の Brotli のバインディング（`github.com/google/brotli/go/cbrotli`）の名前（C11 で使う）
- 最後まで読めたか（読む段・`tr`・`grep`・`awk` のそれぞれの終了状態だけで決める。ファイルの中身では決めない）

上から順に:

1. 最後まで読めなかった（512 MiB を超える、時間切れ、メモリの上限）→ `UNKNOWN`。走査できなかった範囲にも 1 行
2. エラー名が 8 個未満 → `VENDORED_COPY`（デコーダーはあるが、修正の有無を見分けられない）
3. `_ERROR_FORMAT_BLOCK_SWITCH` があり、辞書が 2 個以上 → `UNKNOWN`（同じ文字列はまとめられるので、修正済みのコピーが古いコピーを隠しうる）
4. `_ERROR_FORMAT_BLOCK_SWITCH` がある → `LIKELY_FIXED`（理由に、分かったことと分からないことを書く）
5. それ以外 → `LIKELY_VULNERABLE`

試したビルド: Brotli 1.2.0 と 1.2.1 の共有・静的・LTO、strip の有無（Ubuntu 24.04 の gcc 13、x86_64）、Node.js の公式バイナリ 22.23.3／22.23.4・24.22.0／24.22.1、
PyPI の Brotli・brotlicffi の wheel（[tests/fixtures/c09/README.md](../tests/fixtures/c09/README.md)）。

**どこで止まるか**

- 印の無い静的なコピー（strip・LTO で `BrotliDecoderErrorString` を使わないもの）→ `--deep` では見つからない。ほかの項目では `VENDORED_COPY`〔設計 6・10.5、limitations〕
- 辞書を 1 つ共有する 2 つのデコーダー、外部の辞書を使うビルド → 見分けられない。`LIKELY_FIXED` の理由に「分からないこと」として書く〔設計 10.10.5〕
- エラー名を足さない独自の直し → `LIKELY_VULNERABLE` と出る〔limitations〕
- 1.0.x・1.1.x のビルド、ほかのコンパイラ・アーキテクチャ → 試していない〔設計 10.22〕

### 1.5 既知データとの照合と、版の比べ方

判定は同梱の既知データ（`data/advisories.tsv`。`--data FILE` で差し替えられる）で決まります。部品と系列で行を選び（系列が完全に一致する行を先に、
次に `*` と `<=X` の行をファイルの順で）、行の status と版で決めます。

| 行の status | 版 | 判定 |
|---|---|---|
| `fixed`・`analysis`・`unreleased` | 修正版以上 | `FIXED`（理由に版を何から取ったかを書く） |
| 〃 | 修正版と同じ番号のプレリリース（修正版自体がプレリリースのときを除く） | `UNKNOWN` |
| 〃 | 告知の影響範囲より前 | `UNKNOWN`（更新を勧める。終了コードは 2 につながる） |
| `unreleased` | 修正版より前 | `NO_FIX_AVAILABLE` |
| `fixed`・`analysis` | 修正版より前 | `VULNERABLE` |
| 〃 | 版を比べられない | `UNKNOWN` |
| `no_fix` | （見ない） | `NO_FIX_AVAILABLE` |
| `derived_eol`・`derived_bundled` | （見ない） | `VULNERABLE`（理由に根拠を書く） |
| `derived_before_range` | （見ない） | `UNKNOWN`（移行を勧める） |
| `unknown` | （見ない） | `UNKNOWN`（理由に根拠を書く） |
| 行が無い | | `UNKNOWN` |

版の比べ方は 3 つ: 配布元のパッケージは `dpkg --compare-versions`（ソースパッケージの版）、PyPI は PEP 440 の一部（末尾の 0 を詰める、
dev ＜ プレリリース ＜ 正式版 ＜ post、ローカル版 `+…` は無視）、それ以外は数字の列（プレリリースは正式版の前。同じ版のプレリリースどうしは SemVer の 11）。

**ファイルから読んだ版**（ディレクトリ名・`node_version.h`・パッケージのメタデータ・ライブラリのファイル名・`application.ini`・conda の記録）で `FIXED` と
言うのは、デコーダーの文字列が 1 つのコピーで修正を示したときだけです。それ以外（修正のエラー名が無い、コピーが複数、最後まで読めない、照合するファイルが
無い）は `UNKNOWN` にし、何が足りなかったかを書きます。例外は .NET のビルドの刻印です（C09）。プログラムが答えた版（`--version`）とパッケージの記録の版は、
文字列では確かめません。

**どこで止まるか**

- 既知データの日付より後に出た修正 → 分からない（`NO_FIX_AVAILABLE` が古くなっていることがある）。日付が 30 日以上前なら結果の冒頭で警告〔設計 5.2〕
- 既知データに無い部品・系列 → `UNKNOWN`〔設計 6〕
- 告知の影響範囲より前の版 → `UNKNOWN`（脆弱とも安全とも言わない）〔設計 10.16〕
- `--data` のファイルを root（または実行者）以外が変更できる → 使うが、結果の冒頭で警告〔設計 10.10.8〕

### 1.6 見つけたプログラムの実行（同意）

正確な版を読むため、見つけたプログラムの一部を引数 1 つで実行したいと尋ねます。実行したいと挙げるのは次のものだけです。

| 項目 | 挙げるもの | 引数 |
|---|---|---|
| C04 | libbrotlidec を読み込むと分かったもの以外の node（パッケージの node は、読み込まないと分かったときだけ） | `--version` |
| C05 | 見つけた bun すべて | `--version` |
| C08 | libbrotlidec を読み込まないと分かった curl | `-V` |
| C10 | 見つけた envoy すべて | `--version` |
| C13 | パッケージのものでないブラウザ | `--version` |

一覧には、プログラムごとに事実（root（または実行者）のほかに、本体・その上のディレクトリ・読み込むライブラリ・それを探すディレクトリを書き換えられる人、
空や相対の探索先、調べられなかったこと）を付けます。端末があれば全部・しない・番号で選びます。端末が無ければ `--yes`（全部）か `--no-exec`（しない）が要り、
どちらも無ければ一覧を出して止まります（終了コード 3）。選ばれたものだけを、`/` から、環境変数を `PATH=/usr/bin:/bin`・`HOME=/nonexistent`・`LC_ALL=C` の
3 つだけにし、標準入力を閉じ、制限時間（`--timeout` と 10 秒の小さいほう）を付けて動かし、出力は先頭 64 KiB だけ持ちます。

実行しなかったとき（`--no-exec`、選ばなかった）の代わり:

| 項目 | 代わりに読むもの |
|---|---|
| C04 | `../include/node/node_version.h` → バージョン管理ツールのディレクトリ名 → 文字列 |
| C05 | ディレクトリ名 → 文字列 |
| C08 | デコーダーの印があれば文字列。無ければ `UNKNOWN`（`NOT_APPLICABLE` にはしない） |
| C10 | 文字列 |
| C13 | Firefox は隣の `application.ini` → 文字列 |

点検用のシステムの道具（`dpkg-query`・`dpkg`・`readelf`・`ldconfig`・`stat`・`find` など、`ss`・`snap`・`flatpak`、`--containers` のときの `docker`・`podman`）と、
システムのローダーの `--help`（1.3）は、`--no-exec` でも動きます。道具は `/usr/sbin`・`/usr/bin`・`/sbin`・`/bin`（root しか変更できなければ `/usr/local/sbin`・
`/usr/local/bin` も）から使い、呼び出し側の `PATH` からは使いません。

**どこで止まるか**

- 動き出してから開くもの（プラグイン、設定ファイル）→ 一覧の事実に載らない〔設計 10.11〕
- 実行したプログラムがすること（書き込み、通信）→ 止めない〔設計 10.11、README〕
- 実行しなかったプログラム → 走査しなかった範囲に 1 行（`--no-exec`、または選ばなかった数）〔設計 10.26.1〕

### 1.7 上限

| 上限 | 値 | 当たったとき結果に出るもの | 記録 |
|---|---|---|---|
| 1 つのファイルの文字列を読む大きさ | 512 MiB（変えるオプションは無い） | その行は `UNKNOWN`、走査できなかった範囲に 1 行 | 設計 7・10.9.7 |
| `--deep` で開くファイルの大きさ | 512 MiB 未満 | 開かず、数と例を走査できなかった範囲に | 設計 7・10.26.1 |
| 外部の道具・`find`・1 MiB を超える読み取りの時間 | `--timeout`（既定 120 秒） | 走査できなかった範囲 | 設計 7・10.9.8（120 秒という値は記録なし） |
| 見つけたプログラムの実行、1 MiB 以下の読み取りの時間 | `--timeout` と 10 秒の小さいほう | 実行: 版が読めなければファイルから。読み取り: 項目ごと | 記録なし |
| 依存の辿りの深さ | 8 段 | 1.3 | 記録なし（limitations にはある） |
| 実行の一覧の事実で辿るシンボリックリンクの連鎖 | 40 | 事実に「辿れなかった」 | 設計 10.13 |
| `grep`・`awk` のメモリ | 256 MiB | 最後まで読めなかった扱い | 設計 10.9.7 |
| 数えるエラー名 | 異なるもの 64 個 | 出ない（判定は 8 個以上かで決まる） | 設計 10.9.7 |
| 既知データのファイル | 16 MiB | ツールのエラー（終了コード 3） | 設計 10.10.8 |
| `--envoy-config` のファイル | 64 MiB | 記述が見つからなければ走査できなかった範囲 | 記録なし |
| 小さなファイル（`package.json` 1 MiB、`METADATA`・`node_version.h`・`application.ini`・`/etc/ld.so.preload` 64 KiB、.NET の `.version` 4 KiB） | 先頭だけ読む | 出ない | 記録なし |
| 実行の出力 | 64 KiB を持ち、JSON には 4096 文字 | 出ない | 設計 10.11 |
| C12 で Electron の印を探す深さ／flatpak のランタイムを探す深さ | 4 段／8 段 | 出ない | 記録なし |

### 1.8 走査しなかった範囲・走査できなかった範囲・終了コード

見ていない範囲は 2 種類に分けて、必ず結果に出します（同じ範囲は種類ごとに 1 行）〔設計 10.26〕。

- **走査しなかった範囲**（`chosen`、`[SKIPPED]`）: 実行のしかたで外れたもの。付けなかったオプション（`--deep`・`--projects`・`--containers`・`--exposure`）、
  `--exclude`、`--no-exec` と選ばなかったプログラム、root でないこと（とそのために読めなかったもの）、ネットワークファイルシステムと探す場所の下の別の種類の
  ファイルシステム、`--containers` が数えるだけのもの（止まっているコンテナとイメージ）、readelf が無いこと。
- **走査できなかった範囲**（`failed`、`[FAILED]`）: 見ようとしたのに見られなかったもの。道具の失敗（`dpkg-query`・`snap list`・`flatpak list`・`ss`・
  エンジンの `ps`・`images`、コンテナの中の確認のスクリプト）、点検に要る道具が無い（dpkg、`--exposure` の ss、`--containers` の docker と podman）、時間切れ、
  最後まで読めなかったファイルと上限を超えるファイル、最後まで辿れなかった別の名前へのリンク、root でも読めなかったもの、`--roots`・`--envoy-config` で
  名指ししたのに無いもの、`--inspect-containers` を付けたのに中を見なかったコンテナ。

終了コード: `1` は `VULNERABLE` か `RESTART_REQUIRED` がある。`2` はそれが無く、`NO_FIX_AVAILABLE`・`VENDORED_COPY`・`LIKELY_*`・`UNKNOWN` があるか、
走査できなかった範囲がある。`0` はどれも無い（走査しなかった範囲は数えない）。`3` はツール自体のエラー。`EXPOSURE` と `NOT_APPLICABLE` は数えません。

**裏づけ（1 章）**

- 1.2: 〔試験〕`hardening.bats`「find: directories that could not be read are listed as not scanned」「mounts: a local disk below a root is searched, a tmpfs is listed as not scanned」
  「--exclude paths are listed as not scanned」「round 5: a search root that is a symlink is walked at its target, and said so」、`checks.bats`「index: package-manager caches are not reported」、
  `skipped.bats`「#10 a place named on the command line that is not there …」「#10 directories find could not read for another reason than permission …」「#10 what this user could not read …」。
  索引の決まった場所と名前は〔コード〕`bcc_build_index`・`bcc_python_dirs`。btrfs のサブボリュームは〔コード〕のみ。
- 1.3: 〔試験〕`deps.bats` の 17 件（すべての libbrotlidec、ローダーの順、キャッシュの hwcaps、順が分からないとき、別のローダー、幅優先）、
  `hardening.bats`「round 6: libraries are looked up through the RPATH inherited from the executable」「mutation 10/27: a RUNPATH hides the same object's RPATH …」
  「mutation 10/27: a chain of libraries deeper than the walk follows is said so」「review 10/27: library lookups under different search paths are kept apart」、
  `checks.bats`「linkage that cannot be followed is undetermined (2), never 'not linked'」。〔実測〕ローダーの答え: `deps.bats`「#18: this host's loader answers」。
  旧式の hwcaps を見ないこと、`LD_LIBRARY_PATH` を見ないことは〔コード〕`bcc_dep_walk_uncached`・`bcc_elf_resolve`。
- 1.4: 〔試験〕`heuristic.bats` の 7 件、`hardening.bats`「strings: a fixed copy next to another copy of Brotli is not LIKELY_FIXED」「reads: a file above the size limit is INCOMPLETE …」
  「reads: distinct error names are counted only up to 64 …」「round 6: the end of a read is never taken from the file's own bytes」。
- 1.5: 〔試験〕`data.bats` の 32 件、`version.bats` の 11 件、`hardening.bats`「pre-release of the fixed version is UNKNOWN; …」、`basis.bats`「#9 every call of bcc_judge in lib/ says where its version came from」。
- 1.6: 〔試験〕`cli.bats`「consent: …」の 3 件、`hardening.bats`「consent: …」の 3 件・「mutation 10/27: a chosen program runs with an empty environment, stdin closed, its output capped」
  （`NODE_OPTIONS` が渡らないこと）・「mutation 10/27: the plan leaves out what its verdict does not need, and asks for the rest」・「trusted tools: PATH is fixed to system directories …」、
  `cli.bats`「system tools never come from the caller's PATH …」。環境変数の 3 つの値は〔コード〕`bcc_exec_run`。
- 1.7: 512 MiB・64 個・最後まで読めないこと・`--deep` の上限は 1.4 と `hardening.bats`「--deep: files above the size limit are listed as not scanned」。ほかの値は〔コード〕。
- 1.8: 〔試験〕`skipped.bats` の 17 件、`cli.bats`「exit 1 when something is VULNERABLE」「text output ends with the four-line summary …」。
  〔統合〕5 つのイメージで終了コード 0・1・2 を見る（配布元のサーバーだけなら 0、社内の `.deb` と書き換えた HAProxy で 2）。

---

## 2. 検出項目ごと

### C01 OS のパッケージ

**何を探すか** — 配布元のパッケージ `libbrotli1`・`brotli`・`libbrotli-dev`・`python3-brotli`（入っているもの）。

**どうやって見つけるか** — `dpkg-query -W` で、状態・パッケージ名・版・ソースパッケージ名・ソースの版を取る。系列は `/etc/os-release` の `ID` と
`VERSION_CODENAME`（Debian で codename が無ければ `sid`）。派生（Linux Mint など）は `UBUNTU_CODENAME`・`DEBIAN_CODENAME`。

**何を読み、どの順で判定を決めるか**

1. `dpkg-query` が無い → 走査できなかった範囲「C01: dpkg が無い（Debian/Ubuntu ではない）」。ここで終わり
2. `dpkg-query` が 2 以上で終わる、または時間切れ → 走査できなかった範囲。「どれも入っていない」とは言わない
3. 状態が `ii`・`hi` でないもの（削除済みなど）は見ない。1 つも無ければ情報「どれも入っていません」
4. 系列が分からない（Debian・Ubuntu でもその派生でもない）→ `UNKNOWN`「ディストリビューション「…」はパッケージの既知データにありません。」
5. ソースパッケージの版を、既知データの `deb-src:<ソース>` のその系列の行と比べる（1.5）。`python3-brotli` は静的に Brotli を持つので、別の行になる
6. `VULNERABLE` の次にやることは `apt` での更新、`FIXED` は「この行については更新は不要」と再起動

結果の場所の欄は `dpkg (ubuntu:noble)` のような系列。ここでの判定は、そのパッケージのファイルを読み込むプログラムと、削除済みのファイルを使うプロセス（C03）にも使います。

**どこで止まるか**

- パッケージのファイルの中身は読まない。dpkg が記録した版で判定し、ファイルが書き換えられていても気づかない〔記録なし〕
- この 4 つ以外のパッケージ（Brotli を静的に持つものなど）→ C01 では見ない。node・curl などは各項目で〔設計 10.9.4〕
- 既知データに無い系列 → `UNKNOWN`〔設計 6〕
- 2 つのアーキテクチャの同じパッケージ → 最初の行の判定をファイルに当てる（版は同じ）〔記録なし〕

**裏づけ** — 〔試験〕`checks.bats`「C01: Ubuntu noble packages are judged against USN-8956-1; …」「C01: Debian trixie judges the source version …」
「C01: removed packages (rc) are not judged」「C01: an unknown distribution is UNKNOWN, not guessed」「host: derivatives map to the archive they follow」、
`basis.bats`「#9 C01: …」の 2 件、`skipped.bats`「#10 dpkg-query fails: C01 could not be scanned, …」「#10 a needed program that is missing: dpkg …」、
`hardening.bats`「C01: a failing dpkg-query is not reported as 'none installed'」。〔統合〕5 つのイメージで `libbrotli1`・`python3-brotli` が `FIXED`。

### C02 libbrotli1 に依存するパッケージ（情報）

**何を探すか** — `libbrotli1` に直接依存する、入っているパッケージ（C01 の 4 つを除く）。所見ではなく情報です（C01 の更新と再起動で直るものを二重に数えないため）。

**どうやって見つけるか** — `dpkg-query -W` で全パッケージの `Depends` と `Pre-Depends`。

**何を読み、どの順で判定を決めるか** — 状態が `ii`・`hi` で、依存に `libbrotli1` の名前があるものの数と名前を、情報に 1 行。判定はしません。

**どこで止まるか**

- 間接の依存（`libbrotli1` に依存するライブラリに依存するもの）→ 挙げない〔記録なし〕
- `dpkg-query` が失敗 → 走査できなかった範囲〔設計 10.26.1〕。無いときは何も出ない（C01 が出している）

**裏づけ** — 〔試験〕`checks.bats`「C02: dependents of libbrotli1 are information, not findings」、`skipped.bats`「#10 commands that fail could not be scanned: dpkg-query for C02, …」。

### C03 削除済みのファイルを使い続けるプロセス

**何を探すか** — 更新で消えた古いデコーダーを、メモリに持ったまま動いているプロセス。

**どうやって見つけるか** — `/proc/*/maps` の、` (deleted)` で終わる次の名前の行: `libbrotlidec*.so*`、`_brotli*.so`（PyPI の Brotli と brotlicffi の拡張モジュール）、
.NET の `libSystem.IO.Compression.Native.so`・`System.IO.Compression.Native.so`。node・bun の実行ファイルそのものが削除済みのプロセスは C04・C05 が出します。
C03 は、ほかの項目がディスクの上のファイルを判定し終えてから動きます。

**何を読み、どの順で判定を決めるか**

1. 当たったプロセスごとに `RESTART_REQUIRED`（プロセス ID と実行ファイル。削除済みのファイルは 3 つまで理由に）
2. そのプロセスが別のマウント名前空間にいる、または名前空間を読めない → 照合せず、次にやることは「版を確かめてから再起動」
3. 同じパスにいまあるファイルを、この結果のほかの行がどう判定したかを理由に書く（パッケージのファイルは C01 の判定）
4. 次にやること: すべて `FIXED` なら再起動。`VULNERABLE`・`NO_FIX_AVAILABLE`・`LIKELY_VULNERABLE` が 1 つでもあれば「先にその行に従う」。
   それ以外（判定が無い、ファイルが無い、`UNKNOWN` など）は「版を確かめてから再起動」

削除済みのファイルの中身は読みません（何であれ、ディスクが直っていれば次の一手は再起動）。

**どこで止まるか**

- デコーダーを静的に持つほかのプログラム（envoy、curl、ブラウザ、.NET の single-file など）のプロセス → 見ない。**何も出ない**〔設計 10.19、limitations〕
- 古いファイルと新しいファイルの名前が違う（`.so.1.1.0` が `.so.1.2.1` に）→ いまそのパスにファイルは無いので「版を確かめてから再起動」〔設計 10.19〕
- 読めない `maps`（他ユーザーのプロセス）→ 数を、root でなければ走査しなかった範囲、root なら走査できなかった範囲〔設計 10.26.3〕
- 行が無いことは、再起動が要らないことの証明ではない〔limitations〕

**裏づけ** — 〔試験〕`checks.bats`「C03: …」の 3 件と「#5 C03: …」の 11 件、「#5: a program that loads the OS libbrotlidec is judged on disk with that package」、
`dotnet.bats`「#17 C03: a process still mapping a deleted .NET library needs a restart」。

### C04 Node.js

**何を探すか** — `node`・`nodejs` の実行ファイル。公式の Node.js は Brotli を静的に持ち、Node.js 自身の版で判定します（`process.versions.brotli` は使いません。
修正版の 22.23.4 でも `1.1.0` と答えるため）。

**どうやって見つけるか** — 次の 4 つを合わせ、実体のパスで重複を除きます。

- 決まった場所: `/usr/bin/node`、`/usr/bin/nodejs`、`/usr/local/bin/node`、`/opt/*/bin/node`、`/opt/*/*/bin/node`、`/usr/local/n/versions/node/*/bin/node`、
  `/snap/node/current/bin/node`、各ホームの nvm・volta・fnm・asdf・mise・n の版ごとのディレクトリと `~/.local/bin/node`
- 名前の索引（1.2）の `node`・`nodejs`
- 呼び出した人の `PATH` の各ディレクトリ
- 動いているプロセスの実行ファイルで名前が `node`・`nodejs` のもの

ELF のものだけを候補にします（スクリプトは落とします）。名前は `node` でも、別の名前のプログラムへのリンク（`node -> mise` など）は候補にせず、
リンク先のファイルが持つものだけで判定します（別の名前へのリンク、下）。

**何を読み、どの順で判定を決めるか**

1. 読み込むライブラリを辿る（1.3）。**libbrotlidec を読み込む**なら、入れた人によらず、そのライブラリで判定する（それぞれ。C01 のものなら情報、それ以外は C09）。
   さらに、ファイル自体にデコーダーのエラー名が 8 個以上あれば、そのコピーも文字列で判定する（「(own copy)」）
2. dpkg のパッケージのファイルで、**読み込まない**と分かった → 文字列で判定する（1.4）。理由の頭に「Brotli を静的に抱えた配布元パッケージです。…」
   〔不具合〕判定するのはデコーダーを持つファイルで、デコーダーの印の無いファイルを「デコーダーを含む」とは言わない。いまのコードは、Ubuntu 20.04 の配布元の
   nodejs で、`libnode.so.64` を読むだけの起動役 `/usr/bin/node`（印が無い）を文字列で調べて `VENDORED_COPY`「Brotli デコーダーを含みますが、…」と出し、
   デコーダーのある `libnode.so.64` を見ない
3. dpkg のパッケージのファイルで、**決まらない** → `UNKNOWN`「libbrotlidec を読み込むかどうかを判定できませんでした。」、次にやること「binutils（readelf）を入れて再実行する。」〔不具合: 1.3〕
4. それ以外は版を読む: `node --version`（実行に同意したとき）→ `../include/node/node_version.h`（`NODE_VERSION_IS_RELEASE 0` なら `-pre`）→
   バージョン管理ツールのディレクトリ名（`v22.17.1`、`node-v22.17.1-linux-x64`）。どれも無ければ文字列で判定する
5. 既知データの `node` のその major の行で判定する（1.5）。実行以外から読んだ版は文字列で確かめる
6. `VULNERABLE` の次にやること: サポートが終わった系列は「サポートされている系列へ移る」、それ以外は修正版への更新。動いているプロセスがあれば、その pid の再起動

削除済みの node を動かし続けているプロセスは `RESTART_REQUIRED`（C03 と同じ決まり）。

**別の名前へのリンク**（C04・C05・C08・C10・C11・C13 に共通）— 実行せず、版も読まず、リンク先のファイルを `--deep` と同じに見ます。
libbrotlidec を読み込めばそのライブラリで、デコーダーの印があれば文字列で判定し、部品名はファイル自身の名前、理由にリンクを書きます。どちらも無ければ情報
「…は別の名前のプログラム…へのリンクで、node としては判定していません。…」。最後まで読めない、または辿り切れなければ走査できなかった範囲。すでに判定したファイルへの
2 本目のリンクは、その行を指す情報。

**どこで止まるか**

- `node`・`nodejs` 以外の名前の Node.js（`node22` など）→ 名前で探さないので見つからない（`--deep` なら文字列で）〔記録なし〕
- スクリプトのシム（asdf・nodenv）→ 何も言わずに落とす。シムが起動するランタイムは入れた場所で見つかる〔設計 10.23.5〕
- パッケージでない node で、辿りが「決まらない」→ 何も出さずに版で判定する〔記録なし〕〔変える予定: 辿り切れなかったことを結果に出す〕
- Electron のアプリが抱える Node.js → C04 では見ない（C12、`--deep`）〔設計 10.12〕
- コンテナの中の Node.js → C14〔設計 10.20〕
- 修正版と同じ番号のプレリリース、nightly → `UNKNOWN`〔設計 10.9.6〕

**裏づけ** — 〔試験〕`checks.bats`「C04: …」の 16 件と「#5 C04: …」の 4 件、`basis.bats`「#9 C04: …」の 5 件、`hardening.bats`「round 8: C04: a Node.js that loads libbrotlidec is judged by it, with or without a package」
「round 6: a candidate found by its name is kept when it is a symlink to another name」「round 6: a link to a program of another name (a mise or volta shim) is not the runtime」
「pre-release: Bun and Node.js from paths and headers」、`deps.bats`「#18: a program that loads the OS libbrotlidec and a private one gets both judged」。
〔統合〕公式の Node.js 22.23.3 が `VULNERABLE`、22.23.4 が `FIXED`（`--no-exec` と `--yes` の両方）。
〔実測〕開発者の端末で、VS Code Server・GitHub Actions のランナーが抱える Node.js が見つかる（README「確かめたこと」）。
2 の〔不具合〕（Ubuntu 20.04 の配布元 nodejs）は 2026-11-11 に実物のコンテナで確かめた。3 の〔不具合〕は C08 と同じ（C08 の裏づけ）。

### C05 Bun

**何を探すか** — `bun` の実行ファイル（Brotli を静的に持つ）。

**どうやって見つけるか** — 決まった場所（`/usr/local/bin/bun`、`/usr/bin/bun`、`/opt/*/bin/bun`、各ホームの `~/.bun/bin/bun`・mise・asdf）、名前の索引、`PATH`。
ELF だけ。別の名前へのリンクは C04 と同じ。

**何を読み、どの順で判定を決めるか**

1. 版: `bun --version`（同意したとき。プレリリースの後ろも残す）→ `…/<版>/bin/bun` のディレクトリ名。どれも無ければ文字列で判定する
2. 既知データの `bun` の行で判定する（影響範囲は 1.0.21〜1.4.3。1.0.21 より前は `UNKNOWN`）。実行以外から読んだ版は文字列で確かめる
3. 更新が要るとき（`VULNERABLE`・範囲より前）の次にやること: 修正版への更新、動いているプロセスの再起動、`bun build --compile` で作った実行ファイルの作り直し

読み込むライブラリは辿りません（Bun は Brotli を静的に持つ）。削除済みの bun のプロセスは `RESTART_REQUIRED`。

**どこで止まるか**

- `bun build --compile` で作った実行ファイル → 名前で探さないので見つからない。`--deep` の文字列で見つかるかは試していない〔記録なし〕
- 読み込むライブラリ → 辿らない〔記録なし〕

**裏づけ** — 〔試験〕`checks.bats`「C05: Bun 1.0.20 is before the advisory's range: …」「C05: Bun 1.4.3 is VULNERABLE and the advice mentions compiled executables」
「#5 C05: …」「C05: a bun that is a link to a program of another name is named in the report」、`basis.bats`「#9 C05: …」の 2 件。

### C06 Python（PyPI の Brotli・brotlicffi、conda）

**何を探すか** — PyPI の `Brotli`・`brotlicffi`（拡張モジュールにデコーダーを持つ）と、conda の環境の `libbrotlidec`。あわせて、同じ環境の HTTP クライアント（`EXPOSURE`）。

**どうやって見つけるか** — 名前の索引（1.2）の `brotli-*`・`brotlicffi-*` の `.dist-info`・`.egg-info` と、conda の `conda-meta/libbrotlidec-<版>-*.json`。

**何を読み、どの順で判定を決めるか（PyPI）**

1. `METADATA`（または `PKG-INFO`、`.egg-info` のファイル）の先頭 64 KiB から `Name:` と `Version:`。名前が `brotli`・`brotlicffi` でなければ見ない
2. C01 が判定したパッケージ（`python3-brotli`）のファイル → 情報「…は配布元パッケージ … のものなので、C01 で判定します。」（版は上流の版で、配布元の修正が表れないため）
3. 既知データの `pypi:brotli`・`pypi:brotlicffi` の行で、PEP 440 で判定する
4. `FIXED` なら、同じディレクトリのそのパッケージ自身の拡張モジュール（Brotli は `_brotli.*so`、brotlicffi は `brotlicffi/_brotlicffi*.so`）を 1 つずつ文字列で確かめる。
   確かめられないものが出たら `UNKNOWN`。モジュールが 1 つも無ければ `UNKNOWN`「ファイルからは確かめられなかった: … 照合する拡張モジュールが見つからなかった」
5. 更新が要るときの次にやること: ほかの dpkg のパッケージ（ベンダーの `.deb` の中の Python）ならそのパッケージの更新、それ以外は `pip` のコマンド

**conda**: 記録のファイル名の版（`libbrotlidec-1.2.1-…`）を既知データの `brotli` のその系列の行で判定し、`FIXED` なら環境の `lib/libbrotlidec.so.*`（通常のファイル。
シンボリックリンクは数えない）で確かめます。無ければ `UNKNOWN`。版の形が違う（`1.2.1rc0` など）記録は `UNKNOWN`。

**EXPOSURE**: 同じディレクトリに `urllib3`・`requests`・`httpx`・`aiohttp`・`scrapy` のメタデータがあれば、ディレクトリごとに 1 行。理由は「br の応答を受け取ると展開する。
アプリがこれらで外から取得しているかは見ていない」（aiohttp は、aiohttp.web のサーバーが受信本文を展開することも）。

**どこで止まるか**

- メタデータが無い・読めない・`Name:`／`Version:` が無いもの → **何も出ない**〔不具合〕（判定できなかったものは、理由とともに出す）
- 別の場所・下の階層の拡張モジュール、別の名前の配布形態 → 照合しない。修正済みでも `UNKNOWN`〔設計 10.15.2〕
- conda の `lib/` がシンボリックリンクだけの環境 → 修正済みでも `UNKNOWN`〔設計 10.15.3〕
- `.egg`（zip）の中 → 見ない〔記録なし〕
- PyPI の Brotli・brotlicffi 以外で Brotli を持つパッケージ（Pillow の wheel の `libbrotlidec` など）→ C06 では見ない。名前が `libbrotlidec*` なら C09〔記録なし〕
- アプリが HTTP クライアントを使っているか → 見ない〔設計 10.21〕

**裏づけ** — 〔試験〕`checks.bats`「C06: …」の 22 件と「issue #7: C06 says …」、`basis.bats`「#9 C06: …」の 5 件、`hardening.bats`「dpkg: Brotli in a vendor's packaged Python is judged …」
「dpkg: python3-brotli is left to C01 only when C01 judged it」「round 5: an empty conda-meta/ next to a library does not hide it; …」「round 6: a conda record saying fixed is confirmed …」。
〔統合〕PyPI Brotli 1.2.0（urllib3 と）が `VULNERABLE` と `EXPOSURE`、1.2.1 が `FIXED`。メタデータが読めないときは〔コード〕`bcc_c06_entry`。

### C07 Node.js のプロジェクト（`--projects`）

**何を探すか** — 攻撃者のデータをデコーダーに渡しうる npm のパッケージ（経路の手がかり。`EXPOSURE`）。

**どうやって見つけるか** — 探す場所の下の `node_modules` ディレクトリ（その中へは降りない）。

**何を読み、どの順で判定を決めるか** — `node_modules` の直下の `package.json`（1 MiB まで）の `version`:
受信側 `body-parser`（2.x だけ）、`express`（5.x だけ）、`@fastify/compress`、`koa-body`、`co-body`、`inflation`、取得側 `undici`、`axios`、`got`、`node-fetch`。
1 つでもあれば、そのプロジェクト（`node_modules` の親）に `EXPOSURE` を 1 行。理由は「パッケージが入っている。アプリが使っているかは見ていない」。

**どこで止まるか**

- 入れ子の `node_modules` → 見ない（npm は要るものを直下に置く）〔記録なし〕
- アプリがそのパッケージを使っているか、どの経路か → 見ない〔設計 10.21〕
- バンドルされたアプリ、Yarn の PnP（zip の中）→ 見ない〔記録なし〕
- `find` の時間切れ・読めないディレクトリ → 1.2 と同じ

**裏づけ** — 〔試験〕`checks.bats`「C07: inbound and outbound decoding packages are exposure hints」「issue #7: C07 …」の 2 件。

### C08 curl

**何を探すか** — `curl` の実行ファイル。

**どうやって見つけるか** — `/usr/bin/curl`、`/usr/local/bin/curl`、`/opt/*/bin/curl`、`PATH`。名前の索引は使いません。

**何を読み、どの順で判定を決めるか**

1. 実行に同意していれば `curl -V` の `Features:` に `brotli` があるか
2. 読み込むライブラリを辿る（1.3）。**読み込む** → そのライブラリで判定し、情報に「curl が br を展開するのは --compressed／CURLOPT_ACCEPT_ENCODING を指定したときだけです。」。自前のコピーも見る
3. **読み込まない**:
   - `-V` が brotli を挙げる、または実行しておらずデコーダーの印がある → 文字列で判定（「Brotli に対応しているのに libbrotlidec を読み込まない curl です（同梱コピー）。」）
   - `-V` が brotli を挙げない → `NOT_APPLICABLE`
   - 実行しておらず印も無い → `UNKNOWN`（静的な curl は印を持たないことがある）。次にやること「「curl -V」の Features に brotli があるか確認する …」。
     〔不具合〕次にやることは、このツールで実際にできることを書く。いまの文は続けて「（または --allow-exec を付けて再実行する）」と、設計 10.11 で消した
     オプションを勧める（付けると不明なオプションで終了コード 3）
4. **決まらない** → `UNKNOWN`、次にやること「binutils（readelf）を入れて再実行する。」〔不具合: 1.3〕

**どこで止まるか**

- `NOT_APPLICABLE` は curl 自身の答え（`-V`）があるときだけ〔設計 10.9.5〕
- `libcurl` を使うほかのプログラム → C08 では見ない（`libcurl4` は `libbrotli1` に依存するので C02 に出る）〔記録なし〕
- 決まった場所と `PATH` の外の curl → 見つからない（`--deep` なら文字列で）〔記録なし〕

**裏づけ** — 〔試験〕`hardening.bats`「C08: a curl that was not run and shows no markers is UNKNOWN, not NOT_APPLICABLE」「mutation 10/27: the plan leaves out …」。
4 の〔不具合〕は〔実測〕2026-11-13、無いライブラリを NEEDED に持つ ELF を gcc で作り、本物の readelf のもとで確かめた。3 の〔不具合〕は〔コード〕`lib/i18n.sh` の `n_c08_check_features`。1〜3 のほかの枝は〔コード〕`bcc_c08_entry`。

### C09 同梱のデコーダー

C09 は 4 つの道で、パッケージ管理の外のデコーダーのコピーを判定します。

**(a) 名前で見つかる libbrotlidec（いつも）**

- **見つけ方:** 名前の索引の `libbrotlidec*.so*`・`libbrotlidec*.a`。ほかの項目が辿りで見つけた、C01 のものでない libbrotlidec も（名前が違うファイルでも）ここで判定する。
- **判定:**
  1. C01 が判定したパッケージのファイル、C06 が conda の記録と照合したファイル → ここでは出さない
  2. 文字列で推定する（1.4）。最後まで読めなければ走査できなかった範囲にも
  3. ファイル名に `.so.X.Y.Z` の版が無い（`.so.1`、`.a`）→ 文字列で判定（「パッケージ管理外の libbrotlidec で、ファイル名に版がありません。」）
  4. 版があれば既知データの `brotli` のその系列の行で判定し、`FIXED` は文字列で確かめる。版と文字列が食い違う（版は修正済み・文字列は未修正、またはその逆）→ `UNKNOWN`
  5. 更新が要るときの次にやること: そのファイルを修正版に置き換え、読み込むプログラムを再起動

**(b) .NET（いつも）** — .NET は Google の C のデコーダーを System.IO.Compression のネイティブライブラリに組み込み、libbrotlidec を読み込みません。

- **見つけ方:** 名前の索引の `libSystem.IO.Compression.Native.so`・`System.IO.Compression.Native.so`（探す場所と、`/usr/lib/dotnet` を含む `/usr/lib`、`/usr/share/dotnet`）。
- **判定:**
  1. デコーダーの印が無い → 最後まで読めたなら情報「… .NET Core 2.1 より前」、読めなければ走査できなかった範囲
  2. `<root>/shared/Microsoft.NETCore.App/<版>/` の外にあるコピーは、アプリが抱えるもの（`dotnet (self-contained)`）
  3. dpkg の持ち主のソースパッケージが `dotnetN`（Ubuntu の .NET）→ そのソースの版を既知データの `deb-src:dotnetN` の行で判定（C01 と同じ）
  4. それ以外（Microsoft のアーカイブ・パッケージ、self-contained のアプリ）→ ファイルの中のビルドの刻印 `@(#)Version 8.0.3326.52219`（.NET 5 以降。8.0.33 と読む）と、
     共有ランタイムならその `.version`。食い違えば `UNKNOWN`。どちらも無ければ文字列で判定
  5. 既知データの `dotnet` のその系列の行で判定。`FIXED` は文字列で確かめる。ただし、文字列で見分けられない（.NET 8 はエラー名が無い）ときは刻印だけで `FIXED` とし、
     理由に分からないことを書く。刻印が X.Y.0 だけで修正がプレビューで入った系列は `UNKNOWN`。版は未修正なのに文字列は修正済み → `UNKNOWN`
  6. 次にやること: アプリのコピーは「修正版の .NET で作ったアプリの版」、修正の出ない系列は移行、それ以外は .NET の更新

**(c) 読み込まれる、C01 のものでない libbrotlidec** — C04・C08・C11・`--deep`・別の名前へのリンクが辿りで見つけたもの。(a) と同じに判定し、読み込むプログラムの名前を情報に。
見つからなければ `UNKNOWN`「… を読み込みますが、ここでは見つかりませんでした。」。順が分からない hwcaps の候補なら、情報に「どのコピーを読み込むかは分かりません」。

**(d) `--deep`** — 探す場所の下の ELF から、同梱のデコーダーを文字列で探します。

- **見つけ方:** 探す場所の下の通常のファイルで、持ち主の実行ビットがあるか名前が `*.so`・`*.so.*`・`*.node` で、512 MiB 未満のもの。デコーダーの印
  （`BrotliDecoderDecompressStream`・`BrotliDecoderCreateInstance`・`_ERROR_FORMAT_EXUBERANT_NIBBLE`）を含むものを `grep` で選ぶ（時間の上限の下）。
- **判定:**
  1. すでにほかの道で判定したもの、パッケージ管理のキャッシュの中、C06 が判定した拡張モジュール、ELF でないもの → 飛ばす
  2. NEEDED に libbrotlidec がある → 読み込むライブラリを辿り、C01 のものでないコピーを (c) で判定する（C01 のものは何も出さない）。自前のコピーも見る。
     **決まらない** → `UNKNOWN`、次にやること「binutils（readelf）を入れて再実行する。」〔不具合: 1.3〕
  3. C01 が判定したパッケージのファイル → 飛ばす
  4. それ以外 → 文字列で判定（「Brotli デコーダーの同梱コピーを持っています（libbrotlidec を読み込みません）。」）

**どこで止まるか**

- `--deep` を付けないとき → 名前の違うファイルの中のコピーは見ない。走査しなかった範囲「C09 --deep」〔設計 7.1〕
- `--deep` が歩くのは探す場所だけ。`/usr/lib` などの決まった場所（既定の探す場所に無い）の中の静的なコピーは見ない〔設計 10.1・README〕
- 512 MiB 以上のファイル → 開かず、走査できなかった範囲〔設計 7・10.26.1〕。読めないファイル → 数を、root でなければ走査しなかった範囲、root なら走査できなかった範囲〔設計 10.26.3〕
- `grep` のエラー・時間切れ → 走査できなかった範囲〔設計 10.10.9〕
- 実行属性も `.so`・`.node` の名前も無いファイル、アーカイブの中、印の無い静的なコピー → 見えない〔設計 10.24.3、limitations〕
- libbrotlidec を読み込み、その辿りが途中で止まったもの → 見つけた分だけで判定し、止まったことは出ない〔設計 10.28.5〕〔変える予定: 1.3〕
- .NET の single-file・NativeAOT の実行ファイル → `--deep` の文字列だけ（.NET 8 は `VENDORED_COPY`）。刻印は読まない〔設計 10.27.5〕
- NuGet のパッケージフォルダーの runtime pack → キャッシュとして件数だけ〔設計 10.27.5〕
- snap の .NET、コンテナの中の .NET → 見ない〔limitations〕
- Go・Rust・Java のデコーダー（別の実装）→ 調べない〔limitations〕

**裏づけ** — 〔試験〕`checks.bats`「C09: …」の 4 件と「C09 --deep: …」の 3 件、`basis.bats`「#9 C09: a library's file name confirmed by its strings」、`dotnet.bats` の 19 件、
`deps.bats`「#18: --deep: every private libbrotlidec of a program is judged, the OS one adds nothing」、`hardening.bats`「dpkg: a libbrotlidec owned by a vendor's package is judged, …」
「round 5: a program loading a libbrotlidec that C01 did not judge gets that copy judged」「round 6: a libbrotlidec loaded under a name its file does not have is still judged」
「round 6: a file that loads libbrotlidec and carries its own decoder gets that copy judged」「round 8: --deep: a program's private library is judged even when --deep would not find its file」
「round 9: --deep: a library that is gone is not left to C01, …」「round 5: --deep search errors … are listed as not scanned」「--deep: files above the size limit are listed as not scanned」。
〔実測〕開発者の端末で Pillow の wheel の中の `libbrotlidec` が見つかる（README「確かめたこと」）、.NET のアーカイブと PowerShell の判定（設計 10.27.9）。

### C10 Envoy

**何を探すか** — `envoy` の実行ファイルと、`--envoy-config` で名指しした設定ファイル。

**どうやって見つけるか** — `/usr/local/bin/envoy`、`/usr/bin/envoy`、`/opt/*/bin/envoy`、各ホームの `~/.func-e/versions/*/bin/envoy`、名前の索引、`PATH`。

**何を読み、どの順で判定を決めるか**

1. 版は `envoy --version` の `version: <sha>/X.Y.Z/` だけ（同意したとき）。読めなければ文字列で判定する
2. 既知データの `envoy` のその系列の行で判定（1.35 以前は `derived_bundled` で `VULNERABLE`、1.17 以前は `unknown`）。理由に「Envoy が Brotli を展開するのは、Brotli の展開フィルタを設定した箇所だけです。」
3. `--envoy-config FILE`: 64 MiB まで読み、展開フィルタの名前（`envoy.compression.brotli.decompressor` など）があれば `EXPOSURE`
  （ファイルに記述がある。動いている Envoy がこのファイルを使っているか、その記述が効いているかは見ていない）。無ければ情報。最後まで読めなければ走査できなかった範囲
4. Istio のサイドカーについての情報を 1 行

**どこで止まるか**

- 実行しないときは版をファイルから読まない（ディレクトリ名もヘッダーも使わない）→ 文字列だけ〔記録なし〕
- 動いている Envoy の設定（管理 API）、名指ししない設定ファイル → 見ない〔設計 10.21.3〕
- コンテナの中の Envoy（Istio のサイドカーなど）→ 見ない。C14 も Envoy は見ない〔記録なし〕
- `--envoy-config` が無い・通常のファイルでない → 走査できなかった範囲。読めない → root でなければ走査しなかった範囲〔設計 10.26.2〕

**裏づけ** — 〔試験〕`checks.bats`「C10: Envoy 1.35 is VULNERABLE, …」「C10: an Envoy configuration with a Brotli decompressor is EXPOSURE」「issue #7: C10 …」、
`basis.bats`「#9 C10: …」、`hardening.bats`「round 6: an Envoy configuration read only in part is not reported as free of Brotli」、`skipped.bats`「#10 --envoy-config: …」、`data.bats`「data: Envoy before Brotli support is UNKNOWN; …」。

### C11 Web サーバー

**何を探すか** — 圧縮だけに Brotli を使うことが多いサーバー（nginx、Apache（`apache2`・`httpd`）、HAProxy、Traefik、Caddy）と、nginx・Apache の Brotli のモジュール。
製品名ではなく、ファイルが何を持つかで判定します。

**どうやって見つけるか** — `/usr/sbin/<名前>`、`/usr/local/sbin/<名前>`、`/usr/local/bin/<名前>`、`PATH`（Apache は `apache2` と `httpd`）。モジュールは
`/usr/lib/nginx/modules/*brotli*.so`、`/usr/lib/apache2/modules/mod_brotli.so`、`/usr/lib64/httpd/modules/mod_brotli.so`。実行はしません。

**何を読み、どの順で判定を決めるか**

1. デコーダーの印があり、NEEDED に libbrotlidec が無い → 文字列で判定（同梱コピー）
2. libbrotlidec を**読み込む** → そのライブラリで判定。自前のコピーも見る
3. ファイルを最後まで読めなかった → `UNKNOWN`、走査できなかった範囲（印が無いとは言わない）
4. **読み込まない**（印も無い）:
   - ソースを確かめた配布元のパッケージ（nginx・`libnginx-mod-http-brotli-*`・`apache2-bin`・`haproxy`）で、版の形と Maintainer が配布元のもの、`dpkg --verify` で
     インストールされたときのままで、パッケージがそのファイルのチェックサムを記録している → `NOT_APPLICABLE`
   - Go のプログラムで、ビルド情報に `cbrotli` が無い → `NOT_APPLICABLE`
   - ほかのパッケージ、変わったファイル、比べられなかったもの、チェックサムの記録が無いもの → `UNKNOWN`（理由にパッケージの版と Maintainer）
   - パッケージのものでない独自のビルド → `UNKNOWN`
5. **決まらない** → `UNKNOWN`、次にやること「binutils（readelf）を入れて再実行する。」〔不具合: 1.3〕

**どこで止まるか**

- 決まった場所と `PATH` の外のサーバー（`/opt/nginx/sbin/nginx` など）、決まった場所の外のモジュール → 見つからない（`--deep` なら文字列で）〔記録なし〕
- ほかのサーバー（lighttpd、h2o など）→ 見ない〔記録なし〕
- 3 つとも保って作り直した配布元のパッケージ → 配布元のものに見える（dpkg の記録は書いた人が正直な範囲でしか当てにならない）〔設計 10.17.2〕
- cgo のバインディングで見るのは `cbrotli` だけ〔設計 10.17.5〕

**裏づけ** — 〔試験〕`hardening.bats`「C11: …」の 8 件と「round 5: C11 does not take a partly read file for one without markers」「round 7: C11: …」の 2 件。
〔統合〕5 つのイメージの配布元の nginx・Apache・HAProxy（と ngx_brotli のモジュール）が `NOT_APPLICABLE`。社内の `.deb` の `/usr/local/sbin/nginx` と、書き換えた
`/usr/sbin/haproxy` が `UNKNOWN`（本物の dpkg で）。

### C12 snap・flatpak

**何を探すか** — snap・flatpak で入れたもののうち、Brotli のデコーダーを持つと分かっているもの。

**どうやって見つけるか** — `snap list`、`flatpak list --app`（アプリ ID・版・インストール先）、`/var/lib/flatpak/runtime` の下の `libbrotlidec*`（深さ 8 まで。デバッグシンボルを除く）。

**何を読み、どの順で判定を決めるか**

1. snap の `node` → `snap list` の版を既知データの `node` で判定。`chromium`・`firefox` → ブラウザの決まり（C13）で判定
2. ほかの snap → `/snap/<名前>/current` の下（深さ 4 まで）に `resources.pak`・`app.asar`・`chrome_100_percent.pak`・`libnode.so` があれば `VENDORED_COPY`（Electron 系）。無ければ何も出さない
3. flatpak の Chromium・Chrome・Firefox → ブラウザの決まりで判定（インストール先によらず）
4. ほかの flatpak のアプリ → インストール先が `system` なら `/var/lib/flatpak/app/<ID>/current/active/files` に同じ印があれば `VENDORED_COPY`。`user` のものは見ない
5. flatpak のランタイムの `libbrotlidec` → ファイル名の版で判定し、文字列で確かめる（版が無ければ文字列だけ）
6. 次にやること: `snap refresh`／`flatpak update`。`FIXED` は「この行については更新は不要」

`snap list`・`flatpak list` が失敗 → 走査できなかった範囲。`snap`・`flatpak` が無ければ何もしません。

**どこで止まるか**

- snap の中のライブラリ（ベースの `core22`・`core24`、`gnome-42-2204` などの中の `libbrotlidec`）→ 見ない。**何も出ない**〔記録なし〕〔変える予定: flatpak のランタイムと同じに、snap の中の libbrotlidec を判定する〕
- ユーザー単位（と追加のインストール先）の flatpak のアプリ → Electron の印を見ない。**何も出ない**。Electron のアプリは `--deep` の文字列で見つかる（ホームの下）。ユーザー単位のランタイムの `libbrotlidec` は、ホームの下なので C09 が名前で見つける〔設計 10.30〕
- Electron の印の無い snap・flatpak のアプリの中のデコーダー → 見ない〔記録なし〕
- snap・flatpak の版は文字列で確かめない（パッケージの記録）〔設計 10.25〕

**裏づけ** — 〔試験〕`basis.bats`「#9 C12: …」の 4 件、`hardening.bats`「round 6: Electron snaps are found through /snap/NAME/current, which is a symlink」
「round 6: Firefox's application.ini and a flatpak runtime's file name are confirmed by strings」「C12: a flatpak runtime's libbrotlidec before the range is UNKNOWN, …」
「round 8: flatpak runtimes: real libbrotlidec.so and archives are found, debug symbols are not」「round 7: a flatpak runtime's libbrotlidec without a full version in its name …」
「round 6: snap list and ss failures are listed as not scanned」、`skipped.bats`「#10 commands that fail could not be scanned: …, snap list, flatpak list, ss」。
ユーザー単位の flatpak は〔コード〕`bcc_check_c12`。snap の中に libbrotlidec があることは〔実測〕2026-11-13、開発者の端末（`core22`・`gnome-42-2204` に 1.0.9、`core24`・`gnome-46-2404` に 1.1.0）。

### C13 ブラウザ

**何を探すか** — Chromium・Google Chrome・Firefox（Brotli を同梱する）。

**どうやって見つけるか** — Chromium は `chromium`・`chromium-browser` の名前で `/usr/lib/chromium/chromium`・`/usr/lib/chromium-browser/chromium-browser` と `PATH`、
Chrome は `/opt/google/chrome/chrome`、Firefox は `firefox`・`firefox-esr` の名前で `/usr/lib/firefox/firefox`・`/usr/lib/firefox-esr/firefox-esr`・`/opt/firefox/firefox` と `PATH`。

**何を読み、どの順で判定を決めるか**

1. 版: `--version`（パッケージのものでなく、同意したとき。Chrome が版の前に出すログの行は読まない）→ Firefox は隣の `application.ini` の `Version=` →
   dpkg のパッケージならその版（`-` より前）。どれも無ければ文字列で判定
2. Chromium は 4 つの部分の版でなければ `UNKNOWN`。148 で build が 7778 より前は `UNKNOWN`（Brotli の更新の前）。Debian 式の `~` はプレリリース
3. Firefox は版に `esr` があれば ESR の行、無ければ通常の行。`a1`・`b3`・`~b3` はプレリリース
4. `application.ini` から読んだ版の `FIXED` は、隣の `libxul.so`（無ければ本体）の文字列で確かめる
5. `VULNERABLE` の次にやることはブラウザの更新

情報に「Electron アプリは独自の Chromium と Brotli を同梱しています。--deep でそうしたコピーを列挙します。」

**どこで止まるか**

- Edge・Brave・Opera・Vivaldi など、ほかの Chromium 系のブラウザ → 名前で探さない。版でも判定しない（`--deep` なら文字列で）〔limitations〕
- 決まった場所と `PATH` の外のブラウザ → 見つからない〔記録なし〕
- 基準は Chromium・Firefox のソースツリーで、ベンダーの告知ではない（`analysis`。理由に書く）〔設計 6・10.16〕
- snap・flatpak のブラウザ → C12

**裏づけ** — 〔試験〕`checks.bats`「C13: Chromium needs a four-part version; …」「C13: Firefox and Firefox ESR use their own thresholds」、`basis.bats`「#9 C13: …」の 3 件、
`hardening.bats`「pre-release: Firefox Nightly and Beta of the fixed version are UNKNOWN」「round 5: a Chromium version with a Debian-style pre-release suffix is not the release」、
`version.bats`「version from output: a log line before the version is not taken (Chrome)」。

### C14 コンテナ（`--containers`・`--inspect-containers`）

**何を探すか** — 動いているコンテナと、その中（`--inspect-containers`）の配布元の `libbrotli1`・`python3-brotli`、Node.js、PyPI の Brotli・brotlicffi。

**どうやって見つけるか** — `docker`（無ければ `podman`）。まず接続先をエンジンに尋ねる（`docker context inspect`、`podman info`）。続いて `ps`（動いているもの）、
`ps -a`、`images -q`。以降の呼び出しは確かめた context に留めます。

**何を読み、どの順で判定を決めるか**

1. docker も podman も無い → 走査できなかった範囲。ここで終わり
2. 接続先を情報に出す（このホストの unix ソケット、サービスを介さない podman、それ以外、分からない）
3. `ps` が失敗 → 走査できなかった範囲。ここで終わり
4. 止まっているコンテナ（`ps -a` にあって `ps` に無い ID）とイメージの数を情報に。1 以上なら走査しなかった範囲に 1 行ずつ。数えられなければ「?」で走査できなかった範囲
5. 接続先がこのホストでない → コンテナを情報に並べ、中は見ない（`--inspect-containers` があれば走査できなかった範囲、無ければ走査しなかった範囲）
6. `--inspect-containers` が無い → 並べるだけ（走査しなかった範囲）。`--no-exec` → 中を見ない（走査しなかった範囲）
7. それぞれのコンテナで、決まった確認のスクリプト（POSIX sh）を `exec` で動かす。スクリプトが読むもの:
   `/etc/os-release` の `ID`・`VERSION_CODENAME`・`UBUNTU_CODENAME`、`dpkg-query` の `libbrotli1`・`python3-brotli`、`PATH`（と `/usr/local/bin:/usr/bin:/bin`）の上の
   `node`・`nodejs` の `--version`、Python のディレクトリ（`/usr/lib/python3/dist-packages`、`/usr/local/lib/python3*/site-packages`、`/usr/lib/python3*/site-packages`、
   `/opt/*/lib/python3*/site-packages`）の拡張モジュール（名前と大きさ）と Brotli・brotlicffi のメタデータ。最後に `END`
8. パッケージ: OS が Debian・Ubuntu（か `UBUNTU_CODENAME` がある）なら、C01 と同じにソースの版で判定。それ以外の OS は情報「…はパッケージの判定に対応していません」
9. Node.js: `--version` の版で判定（読み込むライブラリは見ない）。
   〔不具合〕決まりはホストと同じ: libbrotlidec を読み込む node はそのライブラリで判定し、配布元の nodejs は `libbrotli1` の判定に従う（README「判定の根拠」、
   limitations）。いまのコードはコンテナの中の node を版だけで判定するので、OS の libbrotli を読む配布元の nodejs（Ubuntu 22.04 の 12.22.9、Debian 12 の
   18.19.0 など）が、サポートが終わった系列として `VULNERABLE`（終了コード 1）になる
10. PyPI: `python3-brotli` の版と同じ Brotli のメタデータ（`/usr/lib/python3/dist-packages`）はパッケージの行に任せる。それ以外は C06 と同じに判定し、`FIXED` は
    そのパッケージ自身の拡張モジュールを、コンテナの中の `head -c` でエンジン越しに（大きさと時間の上限の下で）読み、このホストで文字列を確かめる。
    モジュールが無い・最後まで読めない・まったく読めない → `UNKNOWN`（後の 2 つは走査できなかった範囲にも）
11. 次にやること: `FIXED` は「この行については更新は不要」、それ以外はイメージを作り直して再デプロイ（Python の確かめられなかったものは、イメージの中を確かめる）
12. スクリプトが動かない → 走査できなかった範囲。`END` が無い → 走査できなかった範囲。コンテナの中の `dpkg-query` が失敗 → 走査できなかった範囲

**どこで止まるか**

- 止まっているコンテナとイメージの中 → 見ない。数だけを走査しなかった範囲に〔設計 10.24〕
- 接続先がこのホストの unix ソケット（またはサービスを介さない podman）でないコンテナ → 中で何も動かさない〔設計 10.20〕。ssh などで別のホストのソケットを
  このホストの unix ソケットに引いてきたものは見分けられない〔設計 10.20.2〕。podman-docker は接続先を答えないので中を見ない〔設計 10.20.6〕
- docker があれば podman は試さない〔設計 10.20.6〕
- Alpine（apk）などのパッケージ → 判定しない〔設計 6〕
- `PATH` の上にない Node.js、上の 4 つの外の Python、コンテナの中のほかのコピー（Envoy、.NET、自前の libbrotlidec、静的なコピー）→ 見ない〔設計 10.9.10・10.29.6。ほかのコピーは記録なし〕
- `head` の無いコンテナ → スクリプトが名前と版を取れず、PY と OS の行が出ない〔記録なし。今は直さないと決めた〕
- コンテナの中のプロセスの再起動 → C03 は照合しない〔設計 10.19.3〕

**裏づけ** — 〔試験〕`containers.bats` の 29 件、`container-python.bats` の 19 件、`checks.bats`「C14: …」の 3 件、`basis.bats`「#9 C14: …」の 3 件、
`hardening.bats`「C14: the probe finds node with dash …」「C14: a probe that stops before its end …」「pre-release: a Node.js release candidate in a container is UNKNOWN」
「round 6: Brotli under a container's dist-packages without python3-brotli is judged」「round 6: a Python package of the distribution in a container is left to its PKG line」
「round 7: C14: …」「round 8: C14: …」「round 9: C14: …」。〔統合〕本物の docker の unix ソケットで、コンテナの中の 2 つの Node.js と PyPI Brotli 1.2.0（`VULNERABLE`）・
1.2.1（`FIXED`）、TCP の中継越しでは中を見ないこと、止まったコンテナが走査しなかった範囲に出ること。〔実測〕podman が客かどうかの答え
（`podman info`）は podman 3.4.4・4.3.1・4.9.3・5.4.2・5.7.0 で測った（設計 10.20.1）。本物の podman のコンテナの中を見ることは試していない。
9 の〔不具合〕は 2026-11-13、偽の docker（単体試験と同じやり方）で確かめた。実物のコンテナでは試していない。

### C15 待ち受け（`--exposure`）

**何を探すか** — ループバック以外で待ち受けている node・bun・envoy・Python のプロセス（経路の手がかり。`EXPOSURE`）。

**どうやって見つけるか** — `ss -ltnpH`（TCP の待ち受け、プロセス付き）。

**何を読み、どの順で判定を決めるか**

1. `ss` が無い・失敗 → 走査できなかった範囲
2. ループバック（`127.*`、`::1`、`::ffff:127.*`）は飛ばす
3. 持ち主のプロセスの名前が `node`・`nodejs`・`bun`・`envoy`・`python`・`python3`・`python3.*`・`uvicorn`・`gunicorn` → `EXPOSURE`（理由「ループバック以外のアドレスで待ち受けています。外から届くか（ファイアウォール・経路）は見ていません。」）
4. 持ち主が見えないソケットがあり、root でない → 走査しなかった範囲

**どこで止まるか**

- 外から届くか（ファイアウォール・経路）→ 見ない〔設計 10.21〕
- 待ち受けずに外へ取りに行って応答を展開するプログラム → 出ない。`EXPOSURE` が無いことは経路が無いことの証明ではない〔設計 10.21.4〕
- UDP の待ち受け → 見ない〔記録なし〕
- 1 つのソケットの最初のプロセスだけを見る。ほかの名前のプロセス（`docker-proxy` など）→ 出ない〔記録なし〕
- コンテナの中の待ち受け（別のネットワーク名前空間）→ このホストの `ss` には見えない〔記録なし〕

**裏づけ** — 〔試験〕`checks.bats`「issue #7: C15 says the process listens beyond loopback, …」、`skipped.bats`「#10 a needed program that is missing: … ss for --exposure …」
「#10 commands that fail could not be scanned: …」「#10 other users' sockets are left out by not being root」。名前の一覧と最初のプロセスだけを見ることは〔コード〕`bcc_check_c15`。
