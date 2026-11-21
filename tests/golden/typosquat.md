<!-- rustsecjp-check -->
## :information_source: RustSecJP check: 大きな問題はありません（注意があります）

Cargo.lock 1 個、crates.io の crate 3 個を確かめました。（git や path の依存 1 個は対象外）

### 名前の注意（2 件）

名前が似ているだけで、悪性とは限りません。意図した crate かどうかを確かめてください。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `reqwets` | 0.12.0 | — | よく使われる `reqwest` に似ています（隣り合う 2 文字の入れ替え） | — | [reqwest](https://crates.io/crates/reqwest) |
| `tokio-rs` | 1.0.0 | — | よく使われる `tokio` に似ています（よく使われる名前に「-rs」を付けた形） | — | [tokio](https://crates.io/crates/tokio) |

<details><summary>確かめなかった依存（1 個）</summary>

crates.io 以外から来る依存は、crates.io の助言と比べられないので対象外です。

- `typo-app` 0.1.0（ローカルの path）

</details>

---
<sub>RustSecJP check による自動の確認です。誤りがあれば https://github.com/RustSecJP/check/issues へ<br>データ: RustSecJP/incidents、OSV (api.osv.dev)、crates.io のダウンロード数の上位（名前の注意） ／ 確認した時刻: 2026-11-21 01:01 UTC ／ rustsecjp-check 0.1.0</sub>
