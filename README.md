# RustSecJP check

Rust のプロジェクトの `Cargo.lock` を読んで、依存している crate に問題が無いかを確かめる小さな道具です。
GitHub Action として使うと、結果をプルリクエストにコメントします。
RustSecJP（Rust のセキュリティについての、非公式の日本語のコミュニティ）が作っています。
道具そのものも Rust で書いています。

`Cargo.lock` はデータとして読むだけです。確かめるプロジェクトのビルドや、コードの実行はしません。

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

## 入れ方

どれか 1 つを選んでください。

### crates.io から

Rust 1.88 以上が要ります。

```sh
cargo install --locked rustsecjp-check
```

### Releases から

[Releases](https://github.com/RustSecJP/check/releases) に、次の 5 つのバイナリがあります。

| OS | ファイル |
|---|---|
| Linux（x86_64） | `rustsecjp-check-x86_64-unknown-linux-gnu.tar.gz` |
| Linux（arm64） | `rustsecjp-check-aarch64-unknown-linux-gnu.tar.gz` |
| macOS（Intel） | `rustsecjp-check-x86_64-apple-darwin.tar.gz` |
| macOS（Apple シリコン） | `rustsecjp-check-aarch64-apple-darwin.tar.gz` |
| Windows（x86_64） | `rustsecjp-check-x86_64-pc-windows-msvc.zip` |

取ってきたファイルは、同じ Release の `SHA256SUMS` と照らし合わせてから使ってください。

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

Linux のバイナリは Ubuntu 22.04 でビルドしているので、glibc 2.35 以上で動きます。

### GitHub Action として

[`examples/workflow.yml`](examples/workflow.yml) を、自分のリポジトリの `.github/workflows/rustsecjp-check.yml` にコピーしてください。

```yaml
- uses: RustSecJP/check@v0
  with:
    fail-on: malicious   # malicious / vulnerability / never
```

action は、runner に合うバイナリを RustSecJP/check の Release から取ってきて、`SHA256SUMS` と照らし合わせてから動かします。

- どの Release を使うかは、`uses:` に書いた ref で決まります。`@v0.1.0` ならその Release、`@v0` や `@v0.1` ならそれに当たる一番新しい Release です。当たる Release が無ければ、一番新しい Release を使います。
- コミットの SHA で固定した（`@<40 桁の SHA>`）ときは、その SHA を指すタグの Release だけを使います。無ければ、その SHA のソースからビルドします。固定したものと違う版のバイナリが動くことはありません。
- `SHA256SUMS` と合わないときは、そこで止めます。
- Release が無いとき（ブランチや `uses: ./` から動かしたときなど）や、バイナリが動かないときは、action のソースから `cargo install --locked` でビルドします。GitHub の runner には Rust が入っているので、そのまま動きます。

入力の一覧です。

| 入力 | 既定 | 内容 |
|---|---|---|
| `lockfiles` | （空） | 確かめる `Cargo.lock`。パスかグロブを空白や改行で区切って書きます。空なら全部を探します（`target/` は除きます） |
| `fail-on` | `malicious` | どの結果でジョブを失敗にするか。`malicious`（悪性）/ `vulnerability`（悪性か脆弱性）/ `never` |
| `comment` | `true` | プルリクエストのときに結果をコメントするか |
| `token` | `${{ github.token }}` | コメントと API に使うトークン |
| `source` | `auto` | `Cargo.lock` の読み方。`auto` はプルリクエストなら API、それ以外は作業ディレクトリ |
| `working-directory` | `.` | `source` が作業ディレクトリのときに探し始める場所 |

出力は `result`（`ok` / `fail` / `error` / `skipped`）と `report`（Markdown の報告のファイルのパス）です。

結果は、ジョブの要約（`$GITHUB_STEP_SUMMARY`）にも書きます。
コメントは 1 つのプルリクエストに 1 つだけで、もう一度確かめると同じコメントを書き換えます（目印は `<!-- rustsecjp-check -->`）。

#### rustsecjp-bot の名前でコメントする

RustSecJP のリポジトリでは、`token` に rustsecjp-bot のトークンを渡しています。そうすると、コメントは rustsecjp-bot の名前で出ます。
ほかのリポジトリでは `token` を省略してかまいません。その場合は `github-actions[bot]` の名前で出ます。

## 使い方（手元で）

確かめたいプロジェクトのディレクトリで動かします。

```sh
cd your-rust-project
rustsecjp-check
```

| オプション | 内容 |
|---|---|
| `--lockfile PATH` | 確かめる `Cargo.lock`（何度でも指定可。グロブも可。ディレクトリなら、その下を探します）。省略すると、今のディレクトリの下をすべて探します |
| `--incidents-dir DIR` | RustSecJP/incidents の手元のコピーを使います（ネットワークを使わずに試すとき） |
| `--format markdown\|json` | 出力の形 |
| `--fail-on malicious\|vulnerability\|never` | 終了コードを 1 にする条件 |
| `--output FILE` | 報告をファイルに書きます（省略すると標準出力） |
| `--no-osv` / `--no-incidents` / `--no-typo` | それぞれの確認をしない |

例:

```sh
rustsecjp-check --lockfile '**/Cargo.lock' --fail-on vulnerability
rustsecjp-check --format json --output report.json
```

終了コード: `0` 問題なし（または `fail-on` に当たらない）、`1` `fail-on` に当たった、`2` 確認を最後まで終えられなかった（ネットワークの失敗など）か、オプションの誤り。

`rustsecjp-check action` は GitHub Action から呼ぶためのものです。設定は `INPUT_*` と `GITHUB_*` の環境変数で受け取ります。

## `@rustsecjp-bot check` で確かめ直す

プルリクエストに `@rustsecjp-bot check` とコメントすると、もう一度確かめます。
新しい助言が出たあとに、マージ前のプルリクエストを確かめ直したいときに使います。

- 動くのは、コメントした人がリポジトリの OWNER / MEMBER / COLLABORATOR のときだけです。だれでも動かせると、悪用されるおそれがあるためです。
- 受け付けると、コメントに 👀 を付けます。終わると、問題が無ければ 👍、あれば 👎 を付けます（GitHub の反応には ✅ / ❌ が無いため）。トークンに権限が無いときは、反応は付きません。
- 結果は、いつものコメントを書き換えて知らせます。

### フォークからのプルリクエストでも安全な理由

この action は、プルリクエストのコードを取り出しません（`actions/checkout` を使いません）。
プルリクエストの先頭のコミットにある `Cargo.lock` だけを、GitHub の API（`GET /repos/{owner}/{repo}/contents/...?ref=<コミット>`）でデータとして読みます。
そのため、フォークの `build.rs` やスクリプトが動くことはありません。
`issue_comment` のワークフローはトークンに書き込みの権限があるので、この点が大事です。`pull_request_target` と `actions/checkout` を組み合わせて、フォークのコードを取り出すことはしないでください。

action がソースからビルドするときも、ビルドするのは action（RustSecJP/check）のコードだけです。確かめるリポジトリの `.cargo/config.toml` や `rust-toolchain.toml` を読まないよう、action のディレクトリでビルドします。

`pull_request` で動いたとき、フォークからのプルリクエストではトークンが読み取り専用になり、コメントを書けないことがあります。
その場合も結果はジョブの要約に残ります。コメントが欲しいときは、メンテナーが `@rustsecjp-bot check` とコメントしてください。

## 使うデータ

- **OSV**（`https://api.osv.dev/v1/querybatch` と `/v1/vulns/{id}`）: RustSec、GitHub Advisory Database、OpenSSF Malicious Packages の助言をまとめたものです。
- **RustSecJP/incidents**: `https://codeload.github.com/RustSecJP/incidents/tar.gz/refs/heads/main` を毎回取ってきて、メモリの上で読みます（ディスクへは展開しません）。`campaigns/*/campaign.toml` と `advisories/RUSTSEC-*.md` の名前だけを使います。
- **よく使われる crate の一覧**: crates.io のダウンロード数の上位 1000 件です。バイナリに埋め込んでいます。`cargo run --example update-popular` で作り直せます。誤検知を減らすため、その次の 4000 件のうち名前が似ているものは `data/typo-allowlist.txt` に入れて、注意を出しません。

通信は https だけを使います。大きすぎる応答（64 MiB より大きいもの）は読みません。

## できないこと

- OSV に載っていない問題は見つけられません。削除されたばかりの悪性の crate は、助言が出るまで数時間から数日かかることがあります。
- 版番号だけで判断します。同じ版番号で中身が違う場合（出し直された版など）は区別できません。RustSecJP の記録では、そうした場合を「要確認」にしています。
- 名前の注意は、ただの目安です。正規の crate が出ることも、名前を似せた crate を見落とすこともあります。
- `Cargo.lock` が無いプロジェクト（ライブラリなど）は確かめられません。
- crate のコードは読みません。build.rs や proc-macro の中身は確かめません。

## プライバシー

外へ送るのは、crates.io から来る crate の名前と版番号だけです（OSV へ）。
ソースコード、ファイルのパス、git や path の依存、crates.io 以外のレジストリの crate の名前は送りません。
RustSecJP/incidents と crates.io からは、データを取ってくるだけです。
GitHub Action として動くときは、そのほかにプルリクエストの `Cargo.lock` を読み、コメントを書くために GitHub の API を使います。

## 開発

```sh
cargo test                                  # ネットワークを使いません
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo deny check
```

`tests/golden/` には、もとの Python 版（v0.1.0）が同じ試験用のデータで出した報告が入っています。Rust 版の報告が 1 文字ずつ同じであることを確かめています。

## ライセンス

MIT または Apache-2.0 のどちらかを選べます（[LICENSE-MIT](LICENSE-MIT)、[LICENSE-APACHE](LICENSE-APACHE)）。
Copyright (c) 2026 RustSecJP contributors

誤りや改善の提案は、[issues](https://github.com/RustSecJP/check/issues) へお願いします。

---

## English summary

RustSecJP check is a small tool written in Rust. It reads `Cargo.lock` files (as data only; nothing from the scanned project is built or run) and reports, in Japanese, known malicious crates, vulnerabilities and informational advisories from OSV, crates listed in RustSecJP campaign records, and names that look like typosquats of popular crates (a hint only).

- Install with `cargo install --locked rustsecjp-check` (Rust 1.88+), or download a binary from Releases and verify it against `SHA256SUMS`.
- Use it as a GitHub Action (copy `examples/workflow.yml`). The action downloads the release binary matching its own ref, verifies the checksum, and falls back to building from source when no release exists. It posts one PR comment that it keeps updated.
- Maintainers (OWNER / MEMBER / COLLABORATOR) can re-run it by commenting `@rustsecjp-bot check`; PR `Cargo.lock` files are read via the GitHub API, so fork code is never checked out or executed.
- Only crate names and versions from crates.io are sent to OSV. Exit codes: 0 ok, 1 `--fail-on` matched, 2 incomplete check.
- Dual-licensed under MIT or Apache-2.0.
