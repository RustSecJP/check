<div align="center">

<img src="site/assets/rustsecjp.png" width="88" height="88" alt="RustSecJP のロゴ">

# RustSecJP check

**悪性の crate・脆弱性・名前を似せた crate を、マージの前にプルリクエストで知らせます。**

[![CI](https://github.com/RustSecJP/check/actions/workflows/ci.yml/badge.svg)](https://github.com/RustSecJP/check/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RustSecJP/check?sort=semver)](https://github.com/RustSecJP/check/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#ライセンス)

**[製品ページ](https://rustsecjp.github.io/check/)** · [GitHub Action](#github-action-として使う) · [ダウンロード](#ダウンロード) · [English](README.md) · 日本語

</div>

RustSecJP check は、Rust のプロジェクトの `Cargo.lock` を読んで、依存している crate に次の問題が無いかを確かめ、結果をプルリクエストにコメントします。

- **悪性**: 悪性のコードを含むとして crates.io から削除された crate や、[RustSecJP/incidents](https://rustsecjp.github.io/incidents/) に記録された、乗っ取られた版
- **脆弱性**: 既知の助言（RUSTSEC / GHSA / CVE）。直った版も出します
- **情報**: 保守終了（unmaintained）や unsound の知らせ
- **名前の注意**: よく使われる crate と 1 文字違い、`-rs` を付けた形、`-` と `_` の違いだけ、など（目安で、悪性とは限りません）

`Cargo.lock` はデータとして読むだけです。**確かめるプロジェクトのビルドや、コードの実行はしません。** `build.rs` も proc-macro も動かず、`cargo` も使いません。

## GitHub Action として使う

自分のリポジトリに `.github/workflows/rustsecjp-check.yml` を足します。

```yaml
name: RustSecJP check
on:
  pull_request:
    paths: ["**/Cargo.lock", "**/Cargo.toml"]
permissions:
  contents: read        # Cargo.lock を API で読むため
  pull-requests: write  # 結果をコメントするため
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: RustSecJP/check@v1
        with:
          fail-on: malicious   # malicious / vulnerability / never
```

これだけです。`actions/checkout` も Rust も要りません。`Cargo.lock` が変わるプルリクエストのたびに、action は次のことをします。

1. runner に合うバイナリを Release から取ってきて、`SHA256SUMS` と照らし合わせる
2. プルリクエストの先頭のコミットにある `Cargo.lock` を、GitHub の API で読む
3. コメントを **1 つだけ** 書き、次に push されたら同じコメントを書き換える。ジョブの要約にも同じ報告を書く
4. `fail-on` に当たればジョブを失敗にする（必須のチェックにすれば、マージを止められます）

`@v1` は 1.x の一番新しい版を使います。版を固定したいときは `@v1.0.0`（またはコミットの SHA）と書きます。
[`examples/workflow.yml`](examples/workflow.yml) は、メンテナーが `@rustsecjp-bot check` とコメントしたときに確かめ直す設定も入った例です。

| 入力 | 既定 | 内容 |
|---|---|---|
| `fail-on` | `malicious` | どの結果でジョブを失敗にするか。`malicious`（悪性）/ `vulnerability`（悪性か脆弱性）/ `never` |
| `lockfiles` | （空） | 確かめる `Cargo.lock`。パスかグロブを空白や改行で区切って書きます。空なら全部を探します（`target/` は除きます） |
| `comment` | `true` | プルリクエストのときに結果をコメントするか |
| `token` | `${{ github.token }}` | コメントと API に使うトークン |
| `source` | `auto` | `Cargo.lock` の読み方。`auto` はプルリクエストなら API、それ以外は作業ディレクトリ（`api` / `workspace` も選べます） |
| `working-directory` | `.` | `source` が作業ディレクトリのときに探し始める場所 |

出力は `result`（`ok` / `fail` / `error` / `skipped`）と `report`（Markdown の報告のファイルのパス）です。

## こんなときに使います

- **Dependabot や Renovate の版上げのプルリクエストが、名前を似せた crate を連れてきたとき。** 版を上げたら、間接の依存に `reqwets` や `tokio-rs` が増えていた。マージを押す前に、コメントがその crate と、似ている本物の crate を指します。
- **人から Rust のプロジェクトを引き継いだとき。** リポジトリで `rustsecjp-check` を 1 回動かすと、すべての `Cargo.lock` にある脆弱性・保守終了・悪性の crate が、直った版と一緒に数秒で一覧になります。
- **CI でマージを止めたいとき。** `fail-on: malicious`（厳しくするなら `vulnerability`）にして、必須のチェックにします。悪いと分かっている crate を足すプルリクエストは、マージできなくなります。
- **プルリクエストを作ったあとに、新しい助言が出たとき。** メンテナーが `@rustsecjp-bot check` とコメントすれば、新しいコミットを push しなくても、最新のデータでコメントを書き換えます。

## ダウンロード

手元で動かすときは、お使いのコンピューターに合うファイルを選んでください。このリンクは、いつも一番新しい版を指します。

| OS | ファイル |
|---|---|
| Linux（x86_64） | [`rustsecjp-check-linux-x86_64.tar.gz`](https://github.com/RustSecJP/check/releases/latest/download/rustsecjp-check-linux-x86_64.tar.gz) |
| Linux（arm64） | [`rustsecjp-check-linux-aarch64.tar.gz`](https://github.com/RustSecJP/check/releases/latest/download/rustsecjp-check-linux-aarch64.tar.gz) |
| macOS（Apple シリコン） | [`rustsecjp-check-macos-aarch64.tar.gz`](https://github.com/RustSecJP/check/releases/latest/download/rustsecjp-check-macos-aarch64.tar.gz) |
| macOS（Intel） | [`rustsecjp-check-macos-x86_64.tar.gz`](https://github.com/RustSecJP/check/releases/latest/download/rustsecjp-check-macos-x86_64.tar.gz) |
| Windows（x86_64） | [`rustsecjp-check-windows-x86_64.zip`](https://github.com/RustSecJP/check/releases/latest/download/rustsecjp-check-windows-x86_64.zip) |
| チェックサム | [`SHA256SUMS`](https://github.com/RustSecJP/check/releases/latest/download/SHA256SUMS) |

取ってきたファイルは、`SHA256SUMS` と照らし合わせてから使ってください。

```sh
sha256sum --check --ignore-missing SHA256SUMS
# macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
```

Linux のバイナリは Ubuntu 22.04 でビルドしているので、glibc 2.35 以上で動きます。
Rust 1.88 以上があれば、自分でビルドして入れることもできます。

```sh
cargo install --locked --git https://github.com/RustSecJP/check
```

## 使い方（手元で）

確かめたいプロジェクトのディレクトリで動かします。

```sh
cd your-rust-project
rustsecjp-check                                    # この下の Cargo.lock をすべて確かめる
rustsecjp-check --fail-on vulnerability            # 悪性か脆弱性があれば 1 で終わる
rustsecjp-check --format json --output report.json
```

| オプション | 内容 |
|---|---|
| `--lockfile PATH` | 確かめる `Cargo.lock`（何度でも指定可。グロブも可。ディレクトリなら、その下を探します）。省略すると、今のディレクトリの下をすべて探します |
| `--format markdown\|json` | 出力の形 |
| `--fail-on malicious\|vulnerability\|never` | 終了コードを 1 にする条件 |
| `--output FILE` | 報告をファイルに書きます（省略すると標準出力） |
| `--no-osv` / `--no-incidents` / `--no-typo` | それぞれの確認をしない |
| `--incidents-dir DIR` | RustSecJP/incidents の手元のコピーを使います（ネットワークを使わずに試すとき） |

終了コード: `0` 問題なし（または `fail-on` に当たらない）、`1` `fail-on` に当たった、`2` 確認を最後まで終えられなかった（ネットワークの失敗など）か、オプションの誤り。

## 何を確かめるか

| 種類 | 内容 | データ |
|---|---|---|
| 悪性 | 悪性のコードを含むとして削除された crate（`MAL-*` や、RustSec の malicious） | [OSV](https://osv.dev) |
| 脆弱性 | 既知の脆弱性。RUSTSEC / GHSA / CVE の番号と、直った版を出します | OSV |
| 情報 | 保守終了（unmaintained）や unsound の知らせ | OSV |
| 名前の注意 | よく使われる crate に名前が似ている crate | 同梱の一覧（`data/popular-crates.txt`） |
| RustSecJP の記録 | [RustSecJP/incidents](https://rustsecjp.github.io/incidents/) のキャンペーン記録に載っている crate | RustSecJP/incidents |

- RUSTSEC の助言に日本語版のページがあれば、そのリンクも付けます。
- RustSecJP の記録で「乗っ取られた正規の crate」（`role = "hijacked"`）は、記録にある悪性の版だけを「悪性」とします。
  記録の版の書き方から判断できないときは「要確認」とします。
- 名前の注意は、名前が似ているだけで、悪性とは限りません。次のどれかに当たる名前を出します。
  - よく使われる名前（5 文字以上）と、1 文字だけ違う（追加・削除・置き換え・隣り合う 2 文字の入れ替え）。番号だけの違い（`sha1` / `sha2` など）は除きます
  - `-` と `_` の違いだけ
  - よく使われる名前に `-rs` / `-rust` / `_rs` / `_rust` / `-rst` を付けた形
- crates.io から来る crate だけを確かめます。git や path の依存、crates.io 以外のレジストリの crate は「確かめなかった依存」として一覧にします。

## 安全とプライバシー

- **ビルドも実行もしません。** `Cargo.lock` は文字として読むだけです。プルリクエストでは、先頭のコミットにある `Cargo.lock` を GitHub の API（`GET /repos/{owner}/{repo}/contents/...?ref=<コミット>`）で読みます。そのため、書き込みの権限があるトークンで動く `issue_comment` のワークフローでも、フォークの `build.rs` やスクリプトが動くことはありません。`pull_request_target` と、フォークのコードを取り出す `actions/checkout` を組み合わせないでください。
- **バイナリを確かめます。** action は、`uses:` に書いた ref に当たる Release のバイナリを使い、`SHA256SUMS` と合わなければそこで止めます。コミットの SHA で固定したときは、その SHA を指すタグの Release だけを使い、無ければその SHA のソースからビルドします。ソースからビルドするときも、ビルドするのは action（RustSecJP/check）のコードだけです。確かめるリポジトリの `.cargo/config.toml` や `rust-toolchain.toml` を読まないよう、action のディレクトリでビルドします。
- **外へ送るのは、名前と版番号だけです。** crates.io から来る crate の名前と版番号だけを OSV へ送ります。ソースコード、ファイルのパス、git や path の依存、crates.io 以外のレジストリの crate の名前は送りません。RustSecJP/incidents と crates.io からは、データを取ってくるだけです。
- **`@rustsecjp-bot check` は、** コメントした人がリポジトリの OWNER / MEMBER / COLLABORATOR のときだけ動きます。だれでも動かせると、悪用されるおそれがあるためです。

## `@rustsecjp-bot check` で確かめ直す

プルリクエストに `@rustsecjp-bot check` とコメントすると、もう一度確かめます（[`examples/workflow.yml`](examples/workflow.yml) の設定が要ります）。

- 受け付けると、コメントに 👀 を付けます。終わると、問題が無ければ 👍、あれば 👎 を付けます（GitHub の反応には ✅ / ❌ が無いため）。トークンに権限が無いときは、反応は付きません。
- 結果は、いつものコメントを書き換えて知らせます（目印は `<!-- rustsecjp-check -->`）。
- RustSecJP のリポジトリでは、`token` に rustsecjp-bot のトークンを渡しているので、コメントは rustsecjp-bot の名前で出ます。ほかのリポジトリでは `token` を省略してかまいません。その場合は `github-actions[bot]` の名前で出ます。
- `pull_request` で動いたとき、フォークからのプルリクエストではトークンが読み取り専用になり、コメントを書けないことがあります。その場合も結果はジョブの要約に残ります。コメントが欲しいときは、メンテナーが `@rustsecjp-bot check` とコメントしてください。

## できないこと

- OSV に載っていない問題は見つけられません。削除されたばかりの悪性の crate は、助言が出るまで数時間から数日かかることがあります。
- 版番号だけで判断します。同じ版番号で中身が違う場合（出し直された版など）は区別できません。RustSecJP の記録では、そうした場合を「要確認」にしています。
- 名前の注意は、ただの目安です。正規の crate が出ることも、名前を似せた crate を見落とすこともあります。
- `Cargo.lock` が無いプロジェクトは確かめられません。
- crate のコードは読みません。build.rs や proc-macro の中身は確かめません。

## 開発する人へ

```sh
cargo test                                  # ネットワークを使いません
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo deny check
```

- `tests/golden/` には、もとの Python 版（v0.1.0）が同じ試験用のデータで出した報告が入っています。Rust 版の報告が 1 文字ずつ同じであることを確かめています（確認した時刻と、この道具の版番号は除きます）。
- よく使われる crate の一覧は、crates.io のダウンロード数の上位 1000 件です。バイナリに埋め込んでいます。`cargo run --example update-popular` で作り直せます。誤検知を減らすため、その次の 4000 件のうち名前が似ているものは `data/typo-allowlist.txt` に入れて、注意を出しません。
- 使うデータ: **OSV**（`https://api.osv.dev/v1/querybatch` と `/v1/vulns/{id}`。RustSec、GitHub Advisory Database、OpenSSF Malicious Packages の助言をまとめたもの）と、**RustSecJP/incidents**（`https://codeload.github.com/RustSecJP/incidents/tar.gz/refs/heads/main` を毎回取ってきて、メモリの上で読みます。`campaigns/*/campaign.toml` と `advisories/RUSTSEC-*.md` の名前だけを使います）。通信は https だけを使い、64 MiB より大きい応答は読みません。
- `rustsecjp-check action` は GitHub Action から呼ぶためのものです。設定は `INPUT_*` と `GITHUB_*` の環境変数で受け取ります。
- リリース: `Cargo.toml` の版と同じ `vX.Y.Z` のタグを push すると、5 つのバイナリと `SHA256SUMS` を Release に載せ、大きい版のタグ（`v1`）を動かします。
- 製品ページは `site/` にあり、`.github/workflows/pages.yml` で GitHub Pages に出します。

## RustSecJP について

[RustSecJP](https://github.com/RustSecJP) は、Rust のセキュリティについての、非公式の日本語のコミュニティです。Rust Project や Rust Foundation とは関係ありません。

## ライセンス

MIT または Apache-2.0 のどちらかを選べます（[LICENSE-MIT](LICENSE-MIT)、[LICENSE-APACHE](LICENSE-APACHE)）。
Copyright (c) 2026 RustSecJP contributors

誤りや改善の提案は、[issues](https://github.com/RustSecJP/check/issues) へお願いします。
