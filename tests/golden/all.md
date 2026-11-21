<!-- rustsecjp-check -->
## :rotating_light: RustSecJP check: 悪性の crate が見つかりました

Cargo.lock 6 個、crates.io の crate 12 個を確かめました。（git や path の依存 8 個は対象外）

### 悪性（3 件）

すぐに依存から外してください。この版をビルドした環境では、認証情報（トークンや鍵）を取り替えることをおすすめします。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `arrayref`<br><sub>hijacked-bad/Cargo.lock</sub> | 0.3.10 | RUSTSEC-2026-0260<br>MAL-2026-14336 | `arrayref` 0.3.10 was removed from crates.io due to a malicious dependency | — | [RUSTSEC-2026-0260](https://rustsec.org/advisories/RUSTSEC-2026-0260.html)<br>[RSJP-C-2026-004](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2026-004/) |
| `finch-rust`<br><sub>malicious/Cargo.lock</sub> | 0.1.0 | RUSTSEC-2025-0148<br>GHSA-f8h5-x737-x4xr | 深刻度 CRITICAL: `finch-rust` was removed from crates.io for malicious code | — | [RUSTSEC-2025-0148](https://rustsec.org/advisories/RUSTSEC-2025-0148.html)<br>[RUSTSEC-2025-0148 日本語版](https://rustsecjp.github.io/incidents/advisories/RUSTSEC-2025-0148.html)<br>[RSJP-C-2025-001](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2025-001/) |
| `sha-rust`<br><sub>malicious/Cargo.lock</sub> | 0.1.8 | RUSTSEC-2025-0146<br>GHSA-3mmg-7c2q-8938 | `sha-rust` was removed from crates.io for malicious code | — | [RUSTSEC-2025-0146](https://rustsec.org/advisories/RUSTSEC-2025-0146.html)<br>[RSJP-C-2025-001](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2025-001/) |

### 脆弱性（1 件）

「直った版」へ上げられるか確かめてください。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `time`<br><sub>malicious/Cargo.lock</sub> | 0.1.45 | RUSTSEC-2020-0071<br>GHSA-wcg3-cvx6-7396<br>CVE-2020-26235 | 深刻度 MODERATE: Potential segfault in the time crate | 0.2.0, 0.2.1, 0.2.23 | [RUSTSEC-2020-0071](https://rustsec.org/advisories/RUSTSEC-2020-0071.html) |

### 情報（保守終了・unsound）（2 件）

すぐに危ないわけではありませんが、代わりの crate を考える手がかりになります。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `atty`<br><sub>malicious/Cargo.lock</sub> | 0.2.14 | RUSTSEC-2021-0145<br>GHSA-g98v-hv3f-hcfr | unsound: Potential unaligned read | — | [RUSTSEC-2021-0145](https://rustsec.org/advisories/RUSTSEC-2021-0145.html) |
| `atty`<br><sub>malicious/Cargo.lock</sub> | 0.2.14 | RUSTSEC-2024-0375 | 保守終了: `atty` is unmaintained | — | [RUSTSEC-2024-0375](https://rustsec.org/advisories/RUSTSEC-2024-0375.html) |

### 名前の注意（2 件）

名前が似ているだけで、悪性とは限りません。意図した crate かどうかを確かめてください。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `reqwets`<br><sub>typosquat/Cargo.lock</sub> | 0.12.0 | — | よく使われる `reqwest` に似ています（隣り合う 2 文字の入れ替え） | — | [reqwest](https://crates.io/crates/reqwest) |
| `tokio-rs`<br><sub>typosquat/Cargo.lock</sub> | 1.0.0 | — | よく使われる `tokio` に似ています（よく使われる名前に「-rs」を付けた形） | — | [tokio](https://crates.io/crates/tokio) |

### RustSecJP の記録（4 件）

RustSecJP がまとめた事件の記録に載っている crate です。「要確認」は、版だけでは判断できないものです。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `append-only-vec`<br><sub>hijacked-bad/Cargo.lock</sub> | 0.1.9 | RSJP-C-2026-004<br>RUSTSEC-2026-0262<br>GHSA-m9v3-f7h2-72cp<br>MAL-2026-14333 | 【要確認】乗っ取られた正規の crateで、記録には「0.1.9（2026-08-20 公開のもの）」とあります。同じ版番号でも問題ない場合があるので、確かめてください。arrayref など 3 つの正規 crate の乗っ取りと、proc-macro2 を装う proc-macro1（2026年8月） | — | [RSJP-C-2026-004](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2026-004/) |
| `arrayref`<br><sub>hijacked-bad/Cargo.lock</sub> | 0.3.10 | RSJP-C-2026-004<br>RUSTSEC-2026-0260<br>GHSA-jwh4-228v-r358<br>MAL-2026-14336 | 【悪性】乗っ取られた正規の crateで、記録にある悪性の版です。arrayref など 3 つの正規 crate の乗っ取りと、proc-macro2 を装う proc-macro1（2026年8月） | — | [RSJP-C-2026-004](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2026-004/) |
| `finch-rust`<br><sub>malicious/Cargo.lock</sub> | 0.1.0 | RSJP-C-2025-001<br>RUSTSEC-2025-0148<br>GHSA-f8h5-x737-x4xr | 【悪性】名前を似せた偽物。finch を装う crate と、認証情報を盗む sha-* 依存（2025年11月〜12月） | — | [RSJP-C-2025-001](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2025-001/)<br>[RUSTSEC-2025-0148 日本語版](https://rustsecjp.github.io/incidents/advisories/RUSTSEC-2025-0148.html) |
| `sha-rust`<br><sub>malicious/Cargo.lock</sub> | 0.1.8 | RSJP-C-2025-001<br>RUSTSEC-2025-0146<br>GHSA-3mmg-7c2q-8938 | 【悪性】悪性のコードを運ぶ crate。finch を装う crate と、認証情報を盗む sha-* 依存（2025年11月〜12月） | — | [RSJP-C-2025-001](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2025-001/) |

<details><summary>確かめなかった依存（8 個）</summary>

crates.io 以外から来る依存は、crates.io の助言と比べられないので対象外です。

- `bio-tool` 0.1.0（ローカルの path）
- `clean-app` 0.1.0（ローカルの path）
- `local-helper` 0.0.1（ローカルの path）
- `private-thing` 1.2.3（crates.io 以外のレジストリ）
- `tracing-tree` 0.3.0（git）
- `typo-app` 0.1.0（ローカルの path）
- `uses-arrayref` 0.1.0（ローカルの path）
- `workspace-member` 0.2.0（ローカルの path）

</details>

---
<sub>RustSecJP check による自動の確認です。誤りがあれば https://github.com/RustSecJP/check/issues へ<br>データ: RustSecJP/incidents、OSV (api.osv.dev)、crates.io のダウンロード数の上位（名前の注意） ／ 確認した時刻: 2026-11-21 01:01 UTC ／ rustsecjp-check 0.1.0</sub>
