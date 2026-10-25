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
  --no-exec               never run found programs; judge from files only
  --show-cmdline          include process command lines (may contain secrets)
  --timeout SEC           time limit for each search (default 120)
  --data FILE             use another advisory data file
Output
  --json                  JSON output (docs/json-schema.md)
  --output FILE           also write the result to FILE (never overwrites)
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
  --no-exec               見つけたプログラムを一切実行しない（ファイルの読み取りだけで判定）
  --show-cmdline          プロセスのコマンドラインを表示する（秘密を含みうる）
  --timeout SEC           各探索の制限時間（既定 120 秒）
  --data FILE             既知データのファイルを差し替える
出力
  --json                  JSON で出力（docs/json-schema.md）
  --output FILE           結果をファイルにも書く（既存のファイルは上書きしない）
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
BCC_MSG_EN[r_heur_fixed]='Its decoder strings include the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH).'
BCC_MSG_JA[r_heur_fixed]='デコーダーの文字列に、修正で追加されたエラー名（_ERROR_FORMAT_BLOCK_SWITCH）があります。'
BCC_MSG_EN[r_heur_vuln]='Its decoder strings lack the error name added by the fix (_ERROR_FORMAT_BLOCK_SWITCH).'
BCC_MSG_JA[r_heur_vuln]='デコーダーの文字列に、修正で追加されたエラー名（_ERROR_FORMAT_BLOCK_SWITCH）がありません。'
BCC_MSG_EN[r_heur_none]='It contains a Brotli decoder, but not the strings that tell fixed from unfixed.'
BCC_MSG_JA[r_heur_none]='Brotli デコーダーを含みますが、修正の有無を見分ける文字列がありません。'
BCC_MSG_EN[r_c06_exposure]='Brotli is installed here, so %s decode Brotli responses from remote servers automatically.'
BCC_MSG_JA[r_c06_exposure]='この環境には Brotli が入っているため、%s は外部から取得した応答を自動で展開します。'
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
BCC_MSG_EN[r_c11_no_decoder]='No Brotli decoder in this file (it neither contains one nor loads libbrotlidec).'
BCC_MSG_JA[r_c11_no_decoder]='このファイルには Brotli のデコーダーがありません（含んでおらず、libbrotlidec も読み込みません）。'
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
BCC_MSG_EN[n_confirm_vendor]='Probably fixed; confirm with the vendor.'
BCC_MSG_JA[n_confirm_vendor]='修正済みの可能性が高い。提供元に確認する。'
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
BCC_MSG_EN[e_cmdline]='cmdline: %s'
BCC_MSG_JA[e_cmdline]='コマンドライン: %s'
BCC_MSG_EN[conf_heur]='medium (string heuristic verified on Brotli 1.2.0/1.2.1 builds and official Node.js and PyPI binaries)'
BCC_MSG_JA[conf_heur]='中（文字列による推定。Brotli 1.2.0/1.2.1 のビルドと Node.js・PyPI の公式バイナリで検証済み）'

# --- information --------------------------------------------------------------
BCC_MSG_EN[i_c01_none]='None of libbrotli1, brotli, libbrotli-dev, python3-brotli is installed.'
BCC_MSG_JA[i_c01_none]='libbrotli1・brotli・libbrotli-dev・python3-brotli はどれも入っていません。'
BCC_MSG_EN[i_c02_dependents]='%s installed packages depend on libbrotli1; the libbrotli1 update plus a restart fixes them: %s'
BCC_MSG_JA[i_c02_dependents]='libbrotli1 に依存するパッケージが %s 個あります。libbrotli1 の更新と再起動で直ります: %s'
BCC_MSG_EN[i_c06_dpkg]='%s belongs to the distribution package %s; C01 judges it.'
BCC_MSG_JA[i_c06_dpkg]='%s は配布元パッケージ %s のものなので、C01 で判定します。'
BCC_MSG_EN[i_pkg_cached]='%s files in package-manager caches (pip, uv, poetry, npm, yarn) were not reported: they are downloads, not installed software. Installed copies are reported on their own.'
BCC_MSG_JA[i_pkg_cached]='パッケージ管理のキャッシュ（pip・uv・poetry・npm・yarn）にある %s 件は報告していません。ダウンロードしたもので、インストール済みのソフトではないためです。インストール済みのものは別に報告します。'
BCC_MSG_EN[i_unsafe_exec]='%s found programs were not run, because a user other than root (or you) could have replaced them; their versions come from files.'
BCC_MSG_JA[i_unsafe_exec]='見つけたプログラムのうち %s 個は実行していません。root（または実行者）以外のユーザーが置き換えられる場所にあるためで、版はファイルから判定しました。'
BCC_MSG_EN[i_uses_os_lib]='%s (%s) loads the OS libbrotlidec (%s, found by %s); C01 covers it.'
BCC_MSG_JA[i_uses_os_lib]='%s（%s）は OS の libbrotlidec（%s、%s で確認）を読み込むので、C01 の判定に従います。'
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
BCC_MSG_EN[skip_proc_unreadable]='%s processes could not be read (other users; run as root)'
BCC_MSG_JA[skip_proc_unreadable]='%s 個のプロセスを読めなかった（他ユーザーのもの。root で実行すると対象になる）'
BCC_MSG_EN[skip_no_dpkg]='dpkg is not available (not Debian/Ubuntu)'
BCC_MSG_JA[skip_no_dpkg]='dpkg が無い（Debian/Ubuntu ではない）'
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
BCC_MSG_EN[err_missing_tool]='required tool not found: %s'
BCC_MSG_JA[err_missing_tool]='必要なコマンドが見つかりません: %s'
