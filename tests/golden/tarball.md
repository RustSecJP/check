<!-- rustsecjp-check -->
## :rotating_light: RustSecJP check: 悪性の crate が見つかりました

Cargo.lock 1 個、crates.io の crate 2 個を確かめました。（git や path の依存 1 個は対象外）

### 悪性（1 件）

すぐに依存から外してください。この版をビルドした環境では、認証情報（トークンや鍵）を取り替えることをおすすめします。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `arrayref` | 0.3.10 | RUSTSEC-2026-0260<br>MAL-2026-14336 | `arrayref` 0.3.10 was removed from crates.io due to a malicious dependency | — | [RUSTSEC-2026-0260](https://rustsec.org/advisories/RUSTSEC-2026-0260.html)<br>[RSJP-C-2026-004](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2026-004/) |

### RustSecJP の記録（2 件）

RustSecJP がまとめた事件の記録に載っている crate です。「要確認」は、版だけでは判断できないものです。

| crate | 版 | 番号 | 内容 | 直った版 | リンク |
|---|---|---|---|---|---|
| `append-only-vec` | 0.1.9 | RSJP-C-2026-004<br>RUSTSEC-2026-0262<br>GHSA-m9v3-f7h2-72cp<br>MAL-2026-14333 | 【要確認】乗っ取られた正規の crateで、記録には「0.1.9（2026-08-20 公開のもの）」とあります。同じ版番号でも問題ない場合があるので、確かめてください。arrayref など 3 つの正規 crate の乗っ取りと、proc-macro2 を装う proc-macro1（2026年8月） | — | [RSJP-C-2026-004](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2026-004/) |
| `arrayref` | 0.3.10 | RSJP-C-2026-004<br>RUSTSEC-2026-0260<br>GHSA-jwh4-228v-r358<br>MAL-2026-14336 | 【悪性】乗っ取られた正規の crateで、記録にある悪性の版です。arrayref など 3 つの正規 crate の乗っ取りと、proc-macro2 を装う proc-macro1（2026年8月） | — | [RSJP-C-2026-004](https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2026-004/) |

<details><summary>確かめなかった依存（1 個）</summary>

crates.io 以外から来る依存は、crates.io の助言と比べられないので対象外です。

- `uses-arrayref` 0.1.0（ローカルの path）

</details>

---
<sub>RustSecJP check による自動の確認です。誤りがあれば https://github.com/RustSecJP/check/issues へ<br>データ: RustSecJP/incidents、OSV (api.osv.dev)、crates.io のダウンロード数の上位（名前の注意） ／ 確認した時刻: 2026-11-21 01:01 UTC ／ rustsecjp-check 0.1.0</sub>
