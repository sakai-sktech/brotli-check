# shellcheck shell=bash
# i18n.sh - message catalog (en, ja). Every key must exist in both (tests/unit/i18n.bats).
# Values are printf formats: use %s for arguments and %% for a literal percent sign.

declare -gA BCC_MSG_EN=() BCC_MSG_JA=()

bcc_msg() {
  local key=$1 fmt=""
  shift
  [[ ${BCC_LANG:-en} == ja ]] && fmt=${BCC_MSG_JA[$key]:-}
  [[ -n $fmt ]] || fmt=${BCC_MSG_EN[$key]:-}
  if [[ -z $fmt ]]; then
    printf '%s' "$key"
    return
  fi
  # shellcheck disable=SC2059  # formats come from the catalog above
  printf -- "$fmt" "$@"
}

BCC_MSG_EN[usage]='brotli-cve-check %s - read-only local check for CVE-2026-111497 (Brotli decoder)

Usage: brotli-cve-check [options]

Scan scope
  --roots DIR[,DIR...]    places to search (default: %s)
  --exclude DIR[,DIR...]  places to skip
  --include-remote        also search network file systems (NFS, CIFS, sshfs; excluded by default)
  --deep                  C09: search all ELF files under --roots for bundled decoders (slow)
  --projects              C07: exposure hints from node_modules under --roots
  --containers            C14: list containers and images (docker/podman)
  --inspect-containers    C14: also run read-only checks inside running containers
  --exposure              C15: listening sockets of node/python/bun/envoy
  --envoy-config FILE     C10: look for a Brotli decompressor in an Envoy configuration
Behaviour
  To read exact versions, the tool asks to run some programs it found with one version
  argument (node/bun/envoy/browsers --version, curl -V). Before anything runs it lists them,
  with who could change each program or the libraries it loads, and asks at the terminal
  (all, none, or by number). Without a terminal, give one of:
  --yes                   run the listed programs without asking
  --no-exec               never run found programs; judge from files only
  --show-cmdline          include process command lines (may contain secrets)
  --timeout SEC           time limit for each search (default 120)
  --data FILE             use another advisory data file
Output
  --json                  JSON output (docs/json-schema.md)
  --output FILE           also write the result to a new FILE (never overwrites; as root, only in
                          root-owned directories: otherwise redirect stdout)
  --lang ja|en            language (default en)
  --version, --help

Exit status: 0 nothing needing action in the scanned ranges (not proof of safety),
1 VULNERABLE or RESTART_REQUIRED, 2 needs review (NO_FIX_AVAILABLE, VENDORED_COPY,
LIKELY_*, UNKNOWN), 3 error of the tool itself.
This tool does not check for intrusion.
'
BCC_MSG_JA[usage]='brotli-cve-check %s - CVE-2026-111497（Brotli デコーダー）の読み取り専用ローカル点検

使い方: brotli-cve-check [オプション]

走査の範囲
  --roots DIR[,DIR...]    探索する場所（既定: %s）
  --exclude DIR[,DIR...]  除外する場所
  --include-remote        ネットワークファイルシステム（NFS・CIFS・sshfs）も探す（既定は除外）
  --deep                  C09: --roots 配下の ELF ファイルすべてから同梱デコーダーを探す（時間がかかる）
  --projects              C07: --roots 配下の node_modules から露出のヒントを出す
  --containers            C14: コンテナとイメージを一覧する（docker/podman）
  --inspect-containers    C14: 実行中のコンテナの中も読み取り専用で確認する
  --exposure              C15: node/python/bun/envoy の待ち受けポートを確認する
  --envoy-config FILE     C10: Envoy の設定に Brotli の展開フィルタがあるか確認する
動作
  正確な版を読むため、見つけたプログラムの一部を版の引数 1 つで実行したいと尋ねます（node・bun・
  envoy・ブラウザの --version、curl の -V）。実行する前に一覧と、それぞれのプログラムや読み込む
  ライブラリを誰が書き換えられるかを示し、端末で尋ねます（全部・しない・番号で選ぶ）。端末が無いときは
  次のどちらかを指定します:
  --yes                   一覧のプログラムを尋ねずに実行する
  --no-exec               見つけたプログラムを一切実行しない（ファイルの読み取りだけで判定）
  --show-cmdline          プロセスのコマンドラインを表示する（秘密を含みうる）
  --timeout SEC           各探索の制限時間（既定 120 秒）
  --data FILE             既知データのファイルを差し替える
出力
  --json                  JSON で出力（docs/json-schema.md）
  --output FILE           結果を新しいファイルにも書く（上書きしない。root では root 所有の
                          ディレクトリにだけ書く。それ以外は標準出力をリダイレクトする）
  --lang ja|en            言語（既定 en）
  --version, --help

終了コード: 0 走査した範囲で対応が必要なものは無い（安全の証明ではない）、
1 VULNERABLE または RESTART_REQUIRED がある、2 人の確認が必要（NO_FIX_AVAILABLE・
VENDORED_COPY・LIKELY_*・UNKNOWN）、3 ツール自体のエラー。
このツールは侵入の有無を調べません。
'

# --- header -----------------------------------------------------------------
BCC_MSG_EN[h_title]='brotli-cve-check %s - read-only local check for %s (Brotli decoder)'
BCC_MSG_JA[h_title]='brotli-cve-check %s - %s（Brotli デコーダー）の読み取り専用ローカル点検'
BCC_MSG_EN[h_host]='Host: %s [%s], kernel %s, %s'
BCC_MSG_JA[h_host]='ホスト: %s [%s]、カーネル %s、%s'
BCC_MSG_EN[h_root]='running as root'
BCC_MSG_JA[h_root]='root で実行'
BCC_MSG_EN[h_not_root]='running as uid %s (not root)'
BCC_MSG_JA[h_not_root]='uid %s で実行（root ではない）'
BCC_MSG_EN[h_data]='Data: snapshot %s (%s days old), %s'
BCC_MSG_JA[h_data]='既知データ: %s 時点（%s 日前）、%s'
BCC_MSG_EN[w_data_writable]='WARNING: users other than root (or you) can change the advisory data %s or a directory on its path, and so the verdicts below. Keep it where only root (or you) can write.'
BCC_MSG_JA[w_data_writable]='警告: 既知データ %s（またはその置き場所のディレクトリ）は、root（または実行者）以外のユーザーが書き換えられます。以下の判定はこのデータに基づきます。root（または実行者）しか書けない場所に置いてください。'
BCC_MSG_EN[w_data_stale]='WARNING: the advisory data is %s days old. Newer fixes may exist: get a newer release or pass --data.'
BCC_MSG_JA[w_data_stale]='警告: 既知データが %s 日前のものです。新しい修正が出ている可能性があります。新しい版を入手するか --data で差し替えてください。'
BCC_MSG_EN[h_roots]='Search roots: %s | options: %s'
BCC_MSG_JA[h_roots]='探索した場所: %s | オプション: %s'

BCC_MSG_EN[title_C01]='OS packages (Debian/Ubuntu)'
BCC_MSG_JA[title_C01]='OS パッケージ（Debian/Ubuntu）'
BCC_MSG_EN[title_C02]='Packages using the OS libbrotli'
BCC_MSG_JA[title_C02]='OS の libbrotli を使うパッケージ'
BCC_MSG_EN[title_C03]='Processes still using an old libbrotli'
BCC_MSG_JA[title_C03]='古い libbrotli を使い続けているプロセス'
BCC_MSG_EN[title_C04]='Node.js'
BCC_MSG_JA[title_C04]='Node.js'
BCC_MSG_EN[title_C05]='Bun'
BCC_MSG_JA[title_C05]='Bun'
BCC_MSG_EN[title_C06]='Python packages (PyPI, conda)'
BCC_MSG_JA[title_C06]='Python のパッケージ（PyPI・conda）'
BCC_MSG_EN[title_C07]='Node.js projects (exposure hints)'
BCC_MSG_JA[title_C07]='Node.js プロジェクト（露出のヒント）'
BCC_MSG_EN[title_C08]='curl'
BCC_MSG_JA[title_C08]='curl'
BCC_MSG_EN[title_C09]='Bundled copies of the Brotli decoder'
BCC_MSG_JA[title_C09]='Brotli デコーダーの同梱コピー'
BCC_MSG_EN[title_C10]='Envoy'
BCC_MSG_JA[title_C10]='Envoy'
BCC_MSG_EN[title_C11]='Compression-only web servers'
BCC_MSG_JA[title_C11]='圧縮専用の Web サーバー'
BCC_MSG_EN[title_C12]='snap / flatpak'
BCC_MSG_JA[title_C12]='snap / flatpak'
BCC_MSG_EN[title_C13]='Browsers'
BCC_MSG_JA[title_C13]='ブラウザ'
BCC_MSG_EN[title_C14]='Containers'
BCC_MSG_JA[title_C14]='コンテナ'
BCC_MSG_EN[title_C15]='Listening sockets (exposure hints)'
BCC_MSG_JA[title_C15]='待ち受けポート（露出のヒント）'
BCC_MSG_EN[title_exec]='Programs run to read their versions'
BCC_MSG_JA[title_exec]='版を読むために実行したプログラム'
BCC_MSG_EN[title_info]='Information'
BCC_MSG_JA[title_info]='情報'
BCC_MSG_EN[title_skipped]='Not scanned'
BCC_MSG_JA[title_skipped]='走査しなかった範囲'
BCC_MSG_EN[title_summary]='Summary'
BCC_MSG_JA[title_summary]='要約'

# --- summary ----------------------------------------------------------------
BCC_MSG_EN[s_update]='Needs update: %s'
BCC_MSG_JA[s_update]='更新が必要なもの: %s 件'
BCC_MSG_EN[s_restart]='Needs restart: %s'
BCC_MSG_JA[s_restart]='再起動が必要なもの: %s 件'
BCC_MSG_EN[s_review]='Needs human review: %s'
BCC_MSG_JA[s_review]='人の確認が必要なもの: %s 件'
BCC_MSG_EN[s_skipped]='Not scanned: %s'
BCC_MSG_JA[s_skipped]='走査しなかった範囲: %s'
BCC_MSG_EN[s_skipped_none]='(none listed)'
BCC_MSG_JA[s_skipped_none]='（記録なし）'
BCC_MSG_EN[s_clean]='No known vulnerable component was found in the scanned ranges. This is not proof of safety; see "Not scanned".'
BCC_MSG_JA[s_clean]='走査した範囲では、既知の脆弱な部品は見つかりませんでした。安全の証明ではありません（「走査しなかった範囲」を参照）。'
BCC_MSG_EN[s_disclaimer]='This tool does not check for intrusion. Updating to a fixed version does not remove traces of an intrusion that happened before the update.'
BCC_MSG_JA[s_disclaimer]='このツールは侵入の有無を調べません。修正版に更新しても、更新前の侵入の痕跡は消えません。'

# --- reasons ----------------------------------------------------------------
BCC_MSG_EN[r_no_data]='No advisory data for %s, series %s.'
BCC_MSG_JA[r_no_data]='%s の系列 %s は既知データにありません。'
BCC_MSG_EN[r_fixed_ge]='At or above the fixed version %s.'
BCC_MSG_JA[r_fixed_ge]='修正版 %s 以上です。'
BCC_MSG_EN[r_below_fixed]='Below the fixed version %s.'
BCC_MSG_JA[r_below_fixed]='修正版 %s より古い版です。'
BCC_MSG_EN[r_unreleased]='The distributor lists %s as the fix, but it has not reached the archive yet.'
BCC_MSG_JA[r_unreleased]='配布元は修正版を %s としていますが、まだアーカイブに入っていません。'
BCC_MSG_EN[r_no_fix]='The distributor has not released a fix yet.'
BCC_MSG_JA[r_no_fix]='配布元が修正版をまだ出していません。'
BCC_MSG_EN[r_derived]='No fixed release exists for this line (derived from the advisory; see evidence).'
BCC_MSG_JA[r_derived]='この系列には修正版がありません（勧告からの導出。根拠は evidence を参照）。'
BCC_MSG_EN[r_data_unknown]='Cannot be judged from the data (see evidence).'
BCC_MSG_JA[r_data_unknown]='既知データからは判定できません（evidence を参照）。'
BCC_MSG_EN[r_analysis_basis]='(Basis: analysis of the source tree, not a vendor advisory.)'
BCC_MSG_JA[r_analysis_basis]='（根拠はソースツリーの分析で、ベンダーの告知ではありません）'
BCC_MSG_EN[r_version_unparsable]='Could not read the version "%s".'
BCC_MSG_JA[r_version_unparsable]='版「%s」を読み取れませんでした。'
BCC_MSG_EN[r_unknown_series]='Distribution "%s" is not in the package data.'
BCC_MSG_JA[r_unknown_series]='ディストリビューション「%s」はパッケージの既知データにありません。'
BCC_MSG_EN[r_crosscheck_conflict]='%s But the decoder in the file lacks the fix'"'"'s error name (_ERROR_FORMAT_BLOCK_SWITCH): the version may be wrong.'
BCC_MSG_JA[r_crosscheck_conflict]='%s ただし、ファイルの中のデコーダーには修正で追加されたエラー名（_ERROR_FORMAT_BLOCK_SWITCH）がありません。版の表示が正しくない可能性があります。'
BCC_MSG_EN[r_prerelease]='Pre-release %s of the fixed version %s: it may have been built before the fix.'
BCC_MSG_JA[r_prerelease]='プレリリース版（%s）で、修正版 %s の前段階です。修正が入る前に作られた可能性があります。'
BCC_MSG_EN[r_heur_multiple]='The file holds more than one copy of Brotli, and equal strings are merged by the linker: the fix'"'"'s error name shows that one copy is fixed, not that all are.'
BCC_MSG_JA[r_heur_multiple]='ファイルに Brotli のコピーが複数あります。同じ文字列はリンカーが 1 つにまとめるため、修正で追加されたエラー名からは、すべてのコピーが修正済みとは言えません。'
BCC_MSG_EN[r_heur_incomplete]='The file could not be read to the end (more than %s MiB, or the time limit): its strings were not judged.'
BCC_MSG_JA[r_heur_incomplete]='ファイルを最後まで読めませんでした（%s MiB を超える、または制限時間）。文字列による推定はしていません。'
BCC_MSG_EN[r_crosscheck_unconfirmed]='Not confirmed by the file: its decoder strings carry no error names, so the fix cannot be seen there; the version above is the only basis.'
BCC_MSG_JA[r_crosscheck_unconfirmed]='ファイルからは確かめられなかった: デコーダーの文字列にエラー名が無く、修正の有無が見えない。根拠は上の版だけ。'
BCC_MSG_EN[r_crosscheck_incomplete]='Not confirmed by the file: it could not be read to the end (more than %s MiB, or the time limit).'
BCC_MSG_JA[r_crosscheck_incomplete]='ファイルからは確かめられなかった: 最後まで読めなかった（%s MiB を超える、または制限時間）。'
BCC_MSG_EN[r_own_copy]='Besides loading libbrotlidec, the file carries decoder error names of its own: a bundled copy.'
BCC_MSG_JA[r_own_copy]='libbrotlidec を読み込むほかに、ファイル自体にもデコーダーのエラー名がある（同梱コピー）。'
BCC_MSG_EN[r_linked_lib_missing]='It loads %s, which could not be found here: the decoder it uses was not examined.'
BCC_MSG_JA[r_linked_lib_missing]='%s を読み込みますが、ここでは見つかりませんでした。使っているデコーダーは調べていません。'
BCC_MSG_EN[r_c03_deleted_lib]='Still maps a replaced (deleted) file: %s'
BCC_MSG_JA[r_c03_deleted_lib]='置き換えられた（削除済みの）ファイルを使い続けています: %s'
BCC_MSG_EN[r_exe_deleted]='The executable was replaced on disk, but this process still runs the old one.'
BCC_MSG_JA[r_exe_deleted]='実行ファイルはディスク上で置き換えられましたが、このプロセスは古いものを動かし続けています。'
BCC_MSG_EN[r_version_unknown]='Could not determine the version.'
BCC_MSG_JA[r_version_unknown]='版を特定できませんでした。'
BCC_MSG_EN[r_distro_static]='Distribution package that bundles Brotli statically; its version number may not show backported fixes.'
BCC_MSG_JA[r_distro_static]='Brotli を静的に抱えた配布元パッケージです。版番号に修正の取り込みが表れないことがあります。'
BCC_MSG_EN[r_link_undetermined]='Could not determine whether it loads libbrotlidec.'
BCC_MSG_JA[r_link_undetermined]='libbrotlidec を読み込むかどうかを判定できませんでした。'
BCC_MSG_EN[r_heur_fixed]='Found: the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH) among its decoder strings; copies of the Brotli dictionary: %s. Not determined: whether all decoder code in the file is fixed (the linker merges equal strings, so an unfixed copy sharing them would not show).'
BCC_MSG_JA[r_heur_fixed]='分かったこと: デコーダーの文字列に、修正で追加されたエラー名（_ERROR_FORMAT_BLOCK_SWITCH）がある。Brotli の辞書は %s 個。分からないこと: ファイルの中のデコーダーがすべて修正済みかどうか（同じ文字列はリンカーが 1 つにまとめるため、それを共有する未修正のコピーは見えない）。'
BCC_MSG_EN[r_heur_vuln]='Found: decoder error names, but not the one added by the fix (_ERROR_FORMAT_BLOCK_SWITCH). Not determined: whether the vendor fixed it in another way (that would look the same).'
BCC_MSG_JA[r_heur_vuln]='分かったこと: デコーダーのエラー名はあるが、修正で追加されたもの（_ERROR_FORMAT_BLOCK_SWITCH）が無い。分からないこと: 提供元が別のやり方で直していないか（その場合も同じに見える）。'
BCC_MSG_EN[r_heur_none]='It contains a Brotli decoder, but not the strings that tell fixed from unfixed.'
BCC_MSG_JA[r_heur_none]='Brotli デコーダーを含みますが、修正の有無を見分ける文字列がありません。'
BCC_MSG_EN[r_c06_exposure]='Brotli is installed here, so these HTTP clients decode Brotli responses from remote servers automatically: %s.'
BCC_MSG_JA[r_c06_exposure]='この環境には Brotli が入っているため、次の HTTP クライアントは外部から取得した応答を自動で展開します: %s。'
BCC_MSG_EN[r_c06_aiohttp]='aiohttp.web servers also decode request bodies sent with Content-Encoding: br by default.'
BCC_MSG_JA[r_c06_aiohttp]='aiohttp.web のサーバーは、既定で br 圧縮の受信本文も展開します。'
BCC_MSG_EN[r_c07_inbound]='Decodes br request bodies: %s.'
BCC_MSG_JA[r_c07_inbound]='受信本文を br で自動展開する構成: %s。'
BCC_MSG_EN[r_c07_outbound]='Decodes br responses it fetches: %s.'
BCC_MSG_JA[r_c07_outbound]='取得した応答を自動展開する: %s。'
BCC_MSG_EN[r_c08_static]='curl with Brotli support that does not load libbrotlidec (bundled copy).'
BCC_MSG_JA[r_c08_static]='Brotli に対応しているのに libbrotlidec を読み込まない curl です（同梱コピー）。'
BCC_MSG_EN[r_c08_no_brotli]='Built without a Brotli decoder.'
BCC_MSG_JA[r_c08_no_brotli]='Brotli のデコーダーを含まないビルドです。'
BCC_MSG_EN[r_c08_not_run]='A curl that does not load libbrotlidec and was not run: a static curl carries no decoder markers, so whether it decodes br is not known.'
BCC_MSG_JA[r_c08_not_run]='libbrotlidec を読み込まない curl で、実行していません。静的にリンクした curl はデコーダーの印を持たないため、br を展開するかどうか分かりません。'
BCC_MSG_EN[r_c09_lib_noversion]='libbrotlidec outside the package manager, without a version in its file name.'
BCC_MSG_JA[r_c09_lib_noversion]='パッケージ管理外の libbrotlidec で、ファイル名に版がありません。'
BCC_MSG_EN[r_c09_conflict]='The version in the file name says %s, but the strings say %s; possibly a patched build.'
BCC_MSG_JA[r_c09_conflict]='ファイル名の版からは %s、文字列からは %s で、食い違っています。修正を取り込んだ独自ビルドの可能性があります。'
BCC_MSG_EN[r_c09_vendored]='Carries its own copy of the Brotli decoder (does not load libbrotlidec).'
BCC_MSG_JA[r_c09_vendored]='Brotli デコーダーの同梱コピーを持っています（libbrotlidec を読み込みません）。'
BCC_MSG_EN[r_c10_decompressor]='Envoy decodes Brotli only where a Brotli decompressor filter is configured.'
BCC_MSG_JA[r_c10_decompressor]='Envoy が Brotli を展開するのは、Brotli の展開フィルタを設定した箇所だけです。'
BCC_MSG_EN[r_c10_config_br]='The configuration enables a Brotli decompressor.'
BCC_MSG_JA[r_c10_config_br]='設定で Brotli の展開フィルタが有効です。'
BCC_MSG_EN[r_c11_no_decoder_pkg]='From the package %s, whose build does not decode Brotli: no decoder markers in the file and no libbrotlidec. (A stripped static copy without error names would carry no markers; the package build rules that out.)'
BCC_MSG_JA[r_c11_no_decoder_pkg]='パッケージ %s のファイルで、そのビルドは Brotli を展開しません。ファイルにデコーダーの印も libbrotlidec の参照もありません（エラー名を持たない strip 済みの静的コピーは印を持ちませんが、パッケージのビルドでその可能性を除きます）。'
BCC_MSG_EN[r_c11_go]='A Go program that does not use the cgo Brotli binding (cbrotli): Go'"'"'s Brotli is a separate implementation, and no libbrotlidec is loaded.'
BCC_MSG_JA[r_c11_go]='C の Brotli（cbrotli）を組み込んでいない Go のプログラムです。Go の Brotli は別の実装で、libbrotlidec も読み込みません。'
BCC_MSG_EN[r_c11_no_marker_custom]='Not from a package (a build of its own) and no decoder markers found. A stripped static copy without error names carries no markers, so this is not proof that it has no decoder.'
BCC_MSG_JA[r_c11_no_marker_custom]='パッケージのものではない独自のビルドで、デコーダーの印は見つかりませんでした。エラー名を持たない strip 済みの静的コピーは印を持たないため、デコーダーが無いことの証明にはなりません。'
BCC_MSG_EN[r_c12_electron]='Electron/Chromium-based application; it bundles its own Brotli.'
BCC_MSG_JA[r_c12_electron]='Electron/Chromium 系のアプリで、独自の Brotli を同梱しています。'
BCC_MSG_EN[r_c13_148_early]='A Chromium 148 build from before branch 7778 may predate the Brotli update.'
BCC_MSG_JA[r_c13_148_early]='ブランチ 7778 より前の Chromium 148 のビルドは、Brotli の更新前の可能性があります。'
BCC_MSG_EN[r_c14_node_vs_os]='(The Node.js inside the image and the image'"'"'s OS libbrotli are separate things.)'
BCC_MSG_JA[r_c14_node_vs_os]='（イメージ内の Node.js 本体の版と、ベース OS の libbrotli の版は別物です）'
BCC_MSG_EN[r_c15_listen]='Listens on a non-loopback address: prioritize this process.'
BCC_MSG_JA[r_c15_listen]='ループバック以外のアドレスで待ち受けています。このプロセスを優先してください。'

# --- next steps ---------------------------------------------------------------
BCC_MSG_EN[n_update_pkg]='Update the package (apt-get install --only-upgrade %s) to %s or later, then restart the services that use it (C03).'
BCC_MSG_JA[n_update_pkg]='apt-get install --only-upgrade %s で %s 以上に更新し、使っているサービスを再起動する（C03）。'
BCC_MSG_EN[n_restart_after_update]='No update needed. If it was updated recently, restart the services that use it (C03).'
BCC_MSG_JA[n_restart_after_update]='更新は不要。最近更新したなら、使っているサービスを再起動する（C03）。'
BCC_MSG_EN[n_restart]='Restart this process or its service.'
BCC_MSG_JA[n_restart]='このプロセス（またはサービス）を再起動する。'
BCC_MSG_EN[n_restart_pids]='Then restart the running processes (pid %s).'
BCC_MSG_JA[n_restart_pids]='その後、実行中のプロセス（pid %s）を再起動する。'
BCC_MSG_EN[n_wait_vendor]='Wait for the distributor'"'"'s fix; meanwhile, update products that bundle their own copy first.'
BCC_MSG_JA[n_wait_vendor]='配布元の修正を待つ。待つ間は、同梱コピーのある製品を優先して更新する。'
BCC_MSG_EN[n_check_vendor]='Ask the vendor or maintainer which Brotli version it bundles.'
BCC_MSG_JA[n_check_vendor]='同梱している Brotli の版を、提供元・保守担当に確認する。'
BCC_MSG_EN[n_confirm_vendor]='Ask the vendor which Brotli version it bundles: the strings show a fixed copy, not that every copy is fixed.'
BCC_MSG_JA[n_confirm_vendor]='同梱している Brotli の版を提供元に確認する（文字列から分かるのは、修正済みのコピーがあることまで）。'
BCC_MSG_EN[n_update_product]='Update this product to a release built with Brotli 1.0.10 / 1.1.1 / 1.2.1 or later.'
BCC_MSG_JA[n_update_product]='Brotli 1.0.10 / 1.1.1 / 1.2.1 以降で作られた版に更新する。'
BCC_MSG_EN[n_update_runtime]='Update to %s or later.'
BCC_MSG_JA[n_update_runtime]='%s 以上に更新する。'
BCC_MSG_EN[n_node_move_line]='This line gets no fix: move to Node.js 22.23.4, 24.22.1, 26.12.1 or later.'
BCC_MSG_JA[n_node_move_line]='この系列には修正版が出ない。Node.js 22.23.4 / 24.22.1 / 26.12.1 以降に移行する。'
BCC_MSG_EN[n_bun_compiled]='Executables built with "bun build --compile" keep the Bun they were built with: rebuild them.'
BCC_MSG_JA[n_bun_compiled]='「bun build --compile」で作った実行ファイルは作成時の Bun を抱えたままなので、作り直す。'
BCC_MSG_EN[n_pip_upgrade]='In the environment that owns %s, run: pip install -U "%s>=%s"'
BCC_MSG_JA[n_pip_upgrade]='%s を持つ環境で pip install -U "%s>=%s" を実行する。'
BCC_MSG_EN[n_conda_update]='conda update -p %s libbrotlidec (to 1.0.10 / 1.1.1 / 1.2.1 or later).'
BCC_MSG_JA[n_conda_update]='conda update -p %s libbrotlidec で 1.0.10 / 1.1.1 / 1.2.1 以降にする。'
BCC_MSG_EN[n_update_lib]='Replace %s with Brotli %s or later, then restart the programs that load it.'
BCC_MSG_JA[n_update_lib]='%s を Brotli %s 以上に置き換え、読み込んでいるプログラムを再起動する。'
BCC_MSG_EN[n_install_binutils]='Install binutils (readelf) and run again.'
BCC_MSG_JA[n_install_binutils]='binutils（readelf）を入れて再実行する。'
BCC_MSG_EN[n_exposure_hint]='Not a vulnerability by itself: update the decoder it uses (other findings) with priority.'
BCC_MSG_JA[n_exposure_hint]='それ自体は脆弱性ではない。使っているデコーダー（ほかの所見）の更新を優先する。'
BCC_MSG_EN[n_c07]='Not a vulnerability: the fix is updating Node.js itself (C04).'
BCC_MSG_JA[n_c07]='脆弱性ではない。根本対策は Node.js 本体の更新（C04）。'
BCC_MSG_EN[n_c11_other]='Other processes on this host still need their own check.'
BCC_MSG_JA[n_c11_other]='同じホストの他のプロセスは別に判定が必要。'
BCC_MSG_EN[n_c11_custom]='Check which modules were compiled in (ngx_brotli only compresses); any module that decompresses Brotli needs Brotli 1.0.10 / 1.1.1 / 1.2.1 or later.'
BCC_MSG_JA[n_c11_custom]='組み込んだモジュールを確認する（ngx_brotli は圧縮だけ）。Brotli を展開するモジュールがあれば Brotli 1.0.10 / 1.1.1 / 1.2.1 以降で作り直す。'
BCC_MSG_EN[n_c08_check_features]='Run "curl -V" and look for brotli under Features (or run this tool with --allow-exec).'
BCC_MSG_JA[n_c08_check_features]='「curl -V」の Features に brotli があるか確認する（または --allow-exec を付けて再実行する）。'
BCC_MSG_EN[n_prerelease]='Move to the final release %s or later.'
BCC_MSG_JA[n_prerelease]='正式版 %s 以上に移る。'
BCC_MSG_EN[n_update_owner_pkg]='It belongs to the package %s: update that package (do not change its files with pip).'
BCC_MSG_JA[n_update_owner_pkg]='パッケージ %s のものなので、そのパッケージを更新する（pip で中を書き換えない）。'
BCC_MSG_EN[n_snap_refresh]='snap refresh %s'
BCC_MSG_JA[n_snap_refresh]='snap refresh %s を実行する。'
BCC_MSG_EN[n_flatpak_update]='flatpak update'
BCC_MSG_JA[n_flatpak_update]='flatpak update を実行する。'
BCC_MSG_EN[n_update_browser]='Update the browser to the latest version.'
BCC_MSG_JA[n_update_browser]='ブラウザを最新版に更新する。'
BCC_MSG_EN[n_rebuild_image]='Updating the host does not fix containers: rebuild the image on a fixed base and redeploy.'
BCC_MSG_JA[n_rebuild_image]='ホストを更新してもコンテナは直らない。修正済みのベースで再ビルドして再デプロイする。'
BCC_MSG_EN[n_c15]='Update the runtime of this process first (C04-C06, C10).'
BCC_MSG_JA[n_c15]='このプロセスの実行環境を優先して更新する（C04〜C06、C10）。'
BCC_MSG_EN[n_none]='No action.'
BCC_MSG_JA[n_none]='対応不要。'

# --- evidence -----------------------------------------------------------------
BCC_MSG_EN[e_started]='started %s'
BCC_MSG_JA[e_started]='起動 %s'
BCC_MSG_EN[e_version_method]='version via %s'
BCC_MSG_JA[e_version_method]='版の取得方法 %s'
BCC_MSG_EN[e_heur]='_ERROR_FORMAT_* names: %s, BLOCK_SWITCH: %s'
BCC_MSG_JA[e_heur]='_ERROR_FORMAT_* の数: %s、BLOCK_SWITCH: %s'
BCC_MSG_EN[e_dicts]='copies of the Brotli dictionary: %s'
BCC_MSG_JA[e_dicts]='Brotli の辞書のコピー: %s 個'
BCC_MSG_EN[e_cmdline]='cmdline: %s'
BCC_MSG_JA[e_cmdline]='コマンドライン: %s'
BCC_MSG_EN[conf_heur]='medium (string heuristic verified on Brotli 1.2.0/1.2.1 builds and official Node.js and PyPI binaries)'
BCC_MSG_JA[conf_heur]='中（文字列による推定。Brotli 1.2.0/1.2.1 のビルドと Node.js・PyPI の公式バイナリで検証済み）'

# --- information --------------------------------------------------------------
BCC_MSG_EN[i_c01_none]='None of libbrotli1, brotli, libbrotli-dev, python3-brotli is installed.'
BCC_MSG_JA[i_c01_none]='libbrotli1・brotli・libbrotli-dev・python3-brotli はどれも入っていません。'
BCC_MSG_EN[i_c02_dependents]='Installed packages depending on libbrotli1 (%s), fixed by the libbrotli1 update plus a restart: %s'
BCC_MSG_JA[i_c02_dependents]='libbrotli1 に依存するパッケージ（%s 個）。libbrotli1 の更新と再起動で直ります: %s'
BCC_MSG_EN[i_c06_dpkg]='%s belongs to the distribution package %s; C01 judges it.'
BCC_MSG_JA[i_c06_dpkg]='%s は配布元パッケージ %s のものなので、C01 で判定します。'
BCC_MSG_EN[i_pkg_cached]='%s files in package-manager caches (pip, uv, poetry, npm, yarn) were not reported: they are downloads, not installed software. Installed copies are reported on their own.'
BCC_MSG_JA[i_pkg_cached]='パッケージ管理のキャッシュ（pip・uv・poetry・npm・yarn）にある %s 件は報告していません。ダウンロードしたもので、インストール済みのソフトではないためです。インストール済みのものは別に報告します。'
BCC_MSG_EN[i_uses_os_lib]='%s (%s) loads the OS libbrotlidec (%s, found by %s); C01 covers it.'
BCC_MSG_JA[i_uses_os_lib]='%s（%s）は OS の libbrotlidec（%s、%s で確認）を読み込むので、C01 の判定に従います。'
BCC_MSG_EN[i_uses_private_lib]='%s (%s) loads a libbrotlidec that C01 did not judge (%s, found by %s); that copy is judged under C09.'
BCC_MSG_JA[i_uses_private_lib]='%s（%s）は、C01 が判定していない libbrotlidec（%s、%s で確認）を読み込みます。そのコピーは C09 で判定します。'
BCC_MSG_EN[i_root_symlink]='Search root %s is a symbolic link; searched its target %s.'
BCC_MSG_JA[i_root_symlink]='探索する場所 %s はシンボリックリンクなので、リンク先 %s を探しました。'
BCC_MSG_EN[i_c08_compressed]='curl decodes br only with --compressed or CURLOPT_ACCEPT_ENCODING.'
BCC_MSG_JA[i_c08_compressed]='curl が br を展開するのは --compressed／CURLOPT_ACCEPT_ENCODING を指定したときだけです。'
BCC_MSG_EN[i_c10_config_none]='No Brotli decompressor in %s.'
BCC_MSG_JA[i_c10_config_none]='%s に Brotli の展開フィルタはありません。'
BCC_MSG_EN[i_c10_istio]='Istio sidecars run Envoy inside containers; fixed in Istio 1.29.9 / 1.30.6 / 1.31.2.'
BCC_MSG_JA[i_c10_istio]='Istio のサイドカーはコンテナ内で Envoy を動かします。修正版は Istio 1.29.9 / 1.30.6 / 1.31.2 です。'
BCC_MSG_EN[i_c13_electron]='Electron applications bundle their own Chromium and Brotli; --deep lists such copies.'
BCC_MSG_JA[i_c13_electron]='Electron アプリは独自の Chromium と Brotli を同梱しています。--deep でそうしたコピーを列挙します。'
BCC_MSG_EN[i_c14_inventory]='%s: %s running containers, %s images.'
BCC_MSG_JA[i_c14_inventory]='%s: 実行中のコンテナ %s 個、イメージ %s 個。'
BCC_MSG_EN[i_c14_rebuild]='Updating the host does not fix containers. The Node.js version inside an image and the image'"'"'s OS libbrotli are separate things.'
BCC_MSG_JA[i_c14_rebuild]='ホストを更新してもコンテナは直りません。イメージ内の Node.js 本体の版と、ベース OS の libbrotli の版は別物です。'
BCC_MSG_EN[i_c14_not_inspected]='Container %s (%s) was not inspected (use --inspect-containers).'
BCC_MSG_JA[i_c14_not_inspected]='コンテナ %s（%s）の中は確認していません（--inspect-containers で確認）。'
BCC_MSG_EN[i_c14_unsupported_os]='Container %s: OS "%s" is not supported for package checks.'
BCC_MSG_JA[i_c14_unsupported_os]='コンテナ %s: OS「%s」はパッケージの判定に対応していません。'

# --- skipped ------------------------------------------------------------------
BCC_MSG_EN[skip_home_unreadable]='home directory not readable'
BCC_MSG_JA[skip_home_unreadable]='ホームディレクトリを読めない'
BCC_MSG_EN[skip_remote_fs]='network file system (use --include-remote)'
BCC_MSG_JA[skip_remote_fs]='ネットワークファイルシステム（--include-remote で対象にする）'
BCC_MSG_EN[skip_timeout]='timed out after %s seconds (use --timeout)'
BCC_MSG_JA[skip_timeout]='%s 秒で打ち切り（--timeout で延長）'
BCC_MSG_EN[skip_proc_unreadable]='processes that could not be read: %s (other users; run as root)'
BCC_MSG_JA[skip_proc_unreadable]='%s 個のプロセスを読めなかった（他ユーザーのもの。root で実行すると対象になる）'
BCC_MSG_EN[skip_no_dpkg]='dpkg is not available (not Debian/Ubuntu)'
BCC_MSG_JA[skip_no_dpkg]='dpkg が無い（Debian/Ubuntu ではない）'
BCC_MSG_EN[skip_missing]='does not exist'
BCC_MSG_JA[skip_missing]='存在しない'
BCC_MSG_EN[skip_unreadable]='not readable'
BCC_MSG_JA[skip_unreadable]='読めない'
BCC_MSG_EN[skip_no_engine]='neither docker nor podman is installed'
BCC_MSG_JA[skip_no_engine]='docker も podman も入っていない'
BCC_MSG_EN[skip_engine_denied]='%s cannot be used by this user (permission or daemon not running)'
BCC_MSG_JA[skip_engine_denied]='このユーザーは %s を使えない（権限がない、またはデーモンが止まっている）'
BCC_MSG_EN[skip_c14_inside]='inside of containers (use --inspect-containers)'
BCC_MSG_JA[skip_c14_inside]='コンテナの中（--inspect-containers で確認）'
BCC_MSG_EN[skip_c14_noexec]='inside of containers: --no-exec forbids running commands there'
BCC_MSG_JA[skip_c14_noexec]='コンテナの中（--no-exec のためコマンドを実行しない）'
BCC_MSG_EN[skip_c14_exec_failed]='the read-only check could not run inside the container'
BCC_MSG_JA[skip_c14_exec_failed]='コンテナの中で読み取り専用の確認を実行できなかった'
BCC_MSG_EN[skip_c14_incomplete]='the read-only check inside the container stopped before its end; findings for it may be missing'
BCC_MSG_JA[skip_c14_incomplete]='コンテナの中の読み取り専用の確認が最後まで終わらなかった（所見が欠けている可能性がある）'
BCC_MSG_EN[skip_dpkg_failed]='dpkg-query failed (status %s): the package database could not be read'
BCC_MSG_JA[skip_dpkg_failed]='dpkg-query が失敗した（終了状態 %s）。パッケージのデータベースを読めなかった'
BCC_MSG_EN[skip_other_fs]='%s file systems mounted below the search roots (%s; this is one) are not searched; add them with --roots'
BCC_MSG_JA[skip_other_fs]='探索する場所の下にマウントされた %s のファイルシステム（%s 個。これはその 1 つ）は探していない。--roots で指定すると対象になる'
BCC_MSG_EN[skip_find_errors]='%s directories could not be read (e.g. %s)'
BCC_MSG_JA[skip_find_errors]='%s 個のディレクトリを読めなかった（例: %s）'
BCC_MSG_EN[skip_c09_big]='%s files larger than %s MiB were not searched (e.g. %s)'
BCC_MSG_JA[skip_c09_big]='%s 個のファイルは %s MiB を超えるため探していない（例: %s）'
BCC_MSG_EN[skip_c09_unreadable]='%s files could not be read'
BCC_MSG_JA[skip_c09_unreadable]='%s 個のファイルを読めなかった'
BCC_MSG_EN[skip_incomplete]='could not be read to the end (more than %s MiB, or the time limit); its strings were not judged'
BCC_MSG_JA[skip_incomplete]='最後まで読めなかった（%s MiB を超える、または制限時間）。文字列による判定はしていない'
BCC_MSG_EN[skip_c09_grep_errors]='some files could not be searched (read errors): bundled decoders in them may be missing'
BCC_MSG_JA[skip_c09_grep_errors]='一部のファイルを探索できなかった（読み取りエラー）。その中の同梱デコーダーは漏れている可能性がある'
BCC_MSG_EN[skip_c14_dpkg_failed]='dpkg-query failed inside the container (status %s): its packages were not judged'
BCC_MSG_JA[skip_c14_dpkg_failed]='コンテナの中で dpkg-query が失敗した（終了状態 %s）。パッケージは判定していない'
BCC_MSG_EN[skip_cmd_failed]='%s failed (status %s): what it lists was not judged'
BCC_MSG_JA[skip_cmd_failed]='%s が失敗した（終了状態 %s）。それが示すものは判定していない'
BCC_MSG_EN[skip_excluded]='excluded with --exclude'
BCC_MSG_JA[skip_excluded]='--exclude で除外'
BCC_MSG_EN[skip_exec_declined]='%s programs listed to read their versions were not chosen; their versions come from files'
BCC_MSG_JA[skip_exec_declined]='版を読むために挙げたプログラムのうち %s 個は選ばれなかった（版はファイルから取得）'
BCC_MSG_EN[skip_no_ss]='ss (iproute2) is not available'
BCC_MSG_JA[skip_no_ss]='ss（iproute2）が無い'
BCC_MSG_EN[skip_c15_hidden]='owners of other users'"'"' sockets are hidden (run as root)'
BCC_MSG_JA[skip_c15_hidden]='他ユーザーのソケットの持ち主は見えない（root で実行すると対象になる）'
BCC_MSG_EN[skip_opt_deep]='generic search of ELF files for bundled decoders (use --deep)'
BCC_MSG_JA[skip_opt_deep]='ELF ファイルからの同梱デコーダーの汎用探索（--deep で実行）'
BCC_MSG_EN[skip_opt_projects]='node_modules exposure hints (use --projects)'
BCC_MSG_JA[skip_opt_projects]='node_modules からの露出のヒント（--projects で実行）'
BCC_MSG_EN[skip_opt_containers]='containers (use --containers)'
BCC_MSG_JA[skip_opt_containers]='コンテナ（--containers で実行）'
BCC_MSG_EN[skip_opt_exposure]='listening sockets (use --exposure)'
BCC_MSG_JA[skip_opt_exposure]='待ち受けポート（--exposure で実行）'
BCC_MSG_EN[skip_opt_noexec]='found programs were not run; versions come from files only'
BCC_MSG_JA[skip_opt_noexec]='見つけたプログラムは実行していない（版はファイルからのみ取得）'
BCC_MSG_EN[skip_not_root]='other users'"'"' processes and files this user cannot read (run as root to include them)'
BCC_MSG_JA[skip_not_root]='このユーザーが読めない他ユーザーのプロセスとファイル（root で実行すると対象になる）'
BCC_MSG_EN[skip_no_binutils]='binutils (readelf) is not installed: linkage checks are less precise'
BCC_MSG_JA[skip_no_binutils]='binutils（readelf）が無いため、リンクの判定の精度が落ちる'

# --- running found programs (lib/exec.sh) ----------------------------------------------
BCC_MSG_EN[x_plan_head]='To read exact versions, these programs found on this host would be run with the argument shown (nothing else; programs not run are judged from files). Facts about each: who besides root (or you) could change it or what it loads.'
BCC_MSG_JA[x_plan_head]='正確な版を読むため、このホストで見つけた次のプログラムを、示した引数で実行したいと考えています（実行するのはこれだけ。実行しないものはファイルから判定します）。それぞれの事実: root（または実行者）のほかに、本体や読み込むものを書き換えられる人。'
BCC_MSG_EN[x_prompt]='Run them? [y] all / [n] none / numbers (e.g. 1,3 or 2-4): '
BCC_MSG_JA[x_prompt]='実行しますか？ [y] 全部 / [n] しない / 番号（例 1,3 や 2-4）: '
BCC_MSG_EN[x_prompt_invalid]='Answer y, n, or numbers from 1 to %s.'
BCC_MSG_JA[x_prompt_invalid]='y、n、または 1〜%s の番号で答えてください。'
BCC_MSG_EN[x_ran]='[RUN] %s %s -> %s (exit status %s)'
BCC_MSG_JA[x_ran]='[実行した] %s %s → %s（終了状態 %s）'
BCC_MSG_EN[x_not_run]='[NOT RUN] %s %s (%s)'
BCC_MSG_JA[x_not_run]='[実行しなかった] %s %s（%s）'
BCC_MSG_EN[x_reason_noexec]='--no-exec'
BCC_MSG_JA[x_reason_noexec]='--no-exec'
BCC_MSG_EN[x_reason_declined]='not chosen'
BCC_MSG_JA[x_reason_declined]='選ばれなかった'
BCC_MSG_EN[f_owner]='%s belongs to %s'
BCC_MSG_JA[f_owner]='%s は %s の所有'
BCC_MSG_EN[f_group_write]='%s can be written by group %s'
BCC_MSG_JA[f_group_write]='%s はグループ %s が書き込める'
BCC_MSG_EN[f_world_write]='%s can be written by anyone'
BCC_MSG_JA[f_world_write]='%s は誰でも書き込める'
BCC_MSG_EN[f_missing]='%s does not exist (whoever can write in the directory above could create it)'
BCC_MSG_JA[f_missing]='%s は存在しない（その上のディレクトリに書ける人が作れる）'
BCC_MSG_EN[f_rp_empty]='%s has an empty library search entry: ld.so also looks in the working directory (the tool runs programs from /)'
BCC_MSG_JA[f_rp_empty]='%s のライブラリの探索先に空の項目がある: ld.so は作業ディレクトリも探す（このツールは / から実行する）'
BCC_MSG_EN[f_rp_relative]='%s has a relative library search entry (looked up from the working directory; the tool runs programs from /)'
BCC_MSG_JA[f_rp_relative]='%s のライブラリの探索先が相対パス（作業ディレクトリから探される。このツールは / から実行する）'
BCC_MSG_EN[f_rp_token]='%s has a library search entry this tool does not expand; where it points was not examined'
BCC_MSG_JA[f_rp_token]='%s のライブラリの探索先に、このツールが展開しない記号がある。その先は調べていない'
BCC_MSG_EN[f_lib_missing]='the library %s was not found here; where ld.so would take it from was not examined'
BCC_MSG_JA[f_lib_missing]='ライブラリ %s がここで見つからない。ld.so がどこから読むかは調べていない'
BCC_MSG_EN[f_readelf_failed]='readelf could not read %s; what it loads was not examined'
BCC_MSG_JA[f_readelf_failed]='readelf が %s を読めなかった。読み込むものは調べていない'
BCC_MSG_EN[f_depth]='the libraries were followed only 8 levels deep'
BCC_MSG_JA[f_depth]='ライブラリは 8 段までしか辿っていない'
BCC_MSG_EN[f_no_readelf]='binutils (readelf) is not installed: the libraries it loads were not examined'
BCC_MSG_JA[f_no_readelf]='binutils（readelf）が無いため、読み込むライブラリは調べていない'
BCC_MSG_EN[f_only_root]='as far as examined, only root can change it and what it loads'
BCC_MSG_JA[f_only_root]='調べた範囲では、本体と読み込むものを変更できるのは root だけ'
BCC_MSG_EN[f_only_root_you]='as far as examined, only root and you can change it and what it loads'
BCC_MSG_JA[f_only_root_you]='調べた範囲では、本体と読み込むものを変更できるのは root と実行者だけ'

# --- errors -------------------------------------------------------------------
BCC_MSG_EN[err_needs_value]='%s needs a value'
BCC_MSG_JA[err_needs_value]='%s には値が必要です'
BCC_MSG_EN[err_bad_lang]='--lang must be ja or en: %s'
BCC_MSG_JA[err_bad_lang]='--lang は ja か en です: %s'
BCC_MSG_EN[err_bad_timeout]='--timeout must be a positive integer: %s'
BCC_MSG_JA[err_bad_timeout]='--timeout は正の整数です: %s'
BCC_MSG_EN[err_unknown_option]='unknown option: %s (see --help)'
BCC_MSG_JA[err_unknown_option]='不明なオプションです: %s（--help を参照）'
BCC_MSG_EN[err_relative]='paths must be absolute: %s'
BCC_MSG_JA[err_relative]='パスは絶対パスで指定してください: %s'
BCC_MSG_EN[err_output_exists]='refusing to overwrite an existing file: %s'
BCC_MSG_JA[err_output_exists]='既存のファイルは上書きしません: %s'
BCC_MSG_EN[err_output_dir]='refusing to write %s: a directory on its path is owned or writable by another user (as root, use a directory owned by root, or redirect stdout: brotli-cve-check > FILE)'
BCC_MSG_JA[err_output_dir]='%s には書きません: パスの途中に、他のユーザーが所有するか書き込めるディレクトリがあります（root で動かすときは root 所有のディレクトリを使うか、標準出力をリダイレクトしてください: brotli-cve-check > FILE）'
BCC_MSG_EN[err_output_write]='could not write %s'
BCC_MSG_JA[err_output_write]='%s に書き込めませんでした'
BCC_MSG_EN[err_data_unreadable]='cannot read the data file: %s'
BCC_MSG_JA[err_data_unreadable]='既知データのファイルを読めません: %s'
BCC_MSG_EN[err_data_line]='data error in %s, line %s: %s'
BCC_MSG_JA[err_data_line]='既知データの誤り（%s の %s 行目）: %s'
BCC_MSG_EN[err_data_columns]='expected 7 tab-separated columns'
BCC_MSG_JA[err_data_columns]='タブ区切りで 7 列必要です'
BCC_MSG_EN[err_data_empty]='component, branch and fixed must not be empty'
BCC_MSG_JA[err_data_empty]='component・branch・fixed は空にできません'
BCC_MSG_EN[err_data_status]='unknown status "%s"'
BCC_MSG_JA[err_data_status]='不明な status「%s」'
BCC_MSG_EN[err_data_url]='source_url must start with https://'
BCC_MSG_JA[err_data_url]='source_url は https:// で始めてください'
BCC_MSG_EN[err_data_date]='retrieved must be YYYY-MM-DD'
BCC_MSG_JA[err_data_date]='retrieved は YYYY-MM-DD で書いてください'
BCC_MSG_EN[err_data_snapshot]='no valid "# snapshot: YYYY-MM-DD" line in %s'
BCC_MSG_JA[err_data_snapshot]='%s に正しい「# snapshot: YYYY-MM-DD」の行がありません'
BCC_MSG_EN[err_data_norows]='no data rows'
BCC_MSG_JA[err_data_norows]='データの行がありません'
BCC_MSG_EN[err_exec_conflict]='--no-exec and --yes cannot be used together'
BCC_MSG_JA[err_exec_conflict]='--no-exec と --yes は同時に指定できません'
BCC_MSG_EN[err_need_consent]='the programs above would be run to read their versions, and there is no terminal to ask: run again with --yes (run them) or --no-exec (do not run them)'
BCC_MSG_JA[err_need_consent]='版を読むために上のプログラムを実行したいのですが、尋ねる端末がありません。--yes（実行する）か --no-exec（実行しない）を付けて実行し直してください'
BCC_MSG_EN[err_missing_tool]='required tool not found: %s'
BCC_MSG_JA[err_missing_tool]='必要なコマンドが見つかりません: %s'
