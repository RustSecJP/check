<!-- rustsecjp-check -->
## :rotating_light: RustSecJP check: 悪性の crate が見つかりました

Cargo.lock 1 個、crates.io の crate 4 個を確かめました。（git や path の依存 1 個は対象外）

### 悪性（2 件）

すぐに依存から外してください。この版をビルドした環境では、認証情報（トークンや鍵）を取り替えることをおすすめします。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `finch-rust` | 0.1.0 | RUSTSEC-2025-0148<br>GHSA-f8h5-x737-x4xr | 深刻度 CRITICAL: `finch-rust` was removed from crates.io for malicious code | — | [RUSTSEC-2025-0148](https://rustsec.org/advisories/RUSTSEC-2025-0148.html)<br>[RUSTSEC-2025-0148 日本語版](https://rustsecjp.github.io/incidents/advisories/RUSTSEC-2025-0148.html)<br>[RSJP-C-2025-001](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2025-001/) |
| `sha-rust` | 0.1.8 | RUSTSEC-2025-0146<br>GHSA-3mmg-7c2q-8938 | `sha-rust` was removed from crates.io for malicious code | — | [RUSTSEC-2025-0146](https://rustsec.org/advisories/RUSTSEC-2025-0146.html)<br>[RSJP-C-2025-001](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2025-001/) |

### 脆弱性（1 件）

「直った版」へ上げられるか確かめてください。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `time` | 0.1.45 | RUSTSEC-2020-0071<br>GHSA-wcg3-cvx6-7396<br>CVE-2020-26235 | 深刻度 MODERATE: Potential segfault in the time crate | 0.2.0, 0.2.1, 0.2.23 | [RUSTSEC-2020-0071](https://rustsec.org/advisories/RUSTSEC-2020-0071.html) |

### 情報（保守終了・unsound）（2 件）

すぐに危ないわけではありませんが、代わりの crate を考える手がかりになります。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `atty` | 0.2.14 | RUSTSEC-2021-0145<br>GHSA-g98v-hv3f-hcfr | unsound: Potential unaligned read | — | [RUSTSEC-2021-0145](https://rustsec.org/advisories/RUSTSEC-2021-0145.html) |
| `atty` | 0.2.14 | RUSTSEC-2024-0375 | 保守終了: `atty` is unmaintained | — | [RUSTSEC-2024-0375](https://rustsec.org/advisories/RUSTSEC-2024-0375.html) |

### RustSecJP の記録（2 件）

RustSecJP がまとめた事件の記録に載っている crate です。「要確認」は、版だけでは判断できないものです。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `finch-rust` | 0.1.0 | RSJP-C-2025-001<br>RUSTSEC-2025-0148<br>GHSA-f8h5-x737-x4xr | 【悪性】名前を似せた偽物。finch を装う crate と、認証情報を盗む sha-* 依存（2025年11月〜12月） | — | [RSJP-C-2025-001](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2025-001/)<br>[RUSTSEC-2025-0148 日本語版](https://rustsecjp.github.io/incidents/advisories/RUSTSEC-2025-0148.html) |
| `sha-rust` | 0.1.8 | RSJP-C-2025-001<br>RUSTSEC-2025-0146<br>GHSA-3mmg-7c2q-8938 | 【悪性】悪性のコードを運ぶ crate。finch を装う crate と、認証情報を盗む sha-* 依存（2025年11月〜12月） | — | [RSJP-C-2025-001](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2025-001/) |

<details><summary>確かめなかった依存（1 個）</summary>

crates.io 以外から来る依存は、crates.io の助言と比べられないので対象外です。

- `bio-tool` 0.1.0（ローカルの path）

</details>

---
<sub>RustSecJP check による自動の確認です。誤りがあれば https://github.com/RustSecJP/check/issues へ<br>データ: RustSecJP/incidents、OSV (api.osv.dev)、crates.io のダウンロード数の上位（名前の注意） ／ 確認した時刻: 2026-11-21 01:01 UTC ／ rustsecjp-check 0.1.0</sub>
