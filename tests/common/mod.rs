//! 試験用の偽の HTTP。ネットワークは使いません。
//!
//! OSV の応答は、実際の応答（2026-11）を短くしたものです。

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rustsecjp_check::check::{CheckResult, Sources, run_check};
use rustsecjp_check::http::{Fetch, Headers, HttpError};
use rustsecjp_check::incidents::load_dir;
use rustsecjp_check::lockfile::{merge_packages, parse_lockfile};
use rustsecjp_check::osv::OsvClient;
use rustsecjp_check::typo::{TypoChecker, default_checker};
use serde_json::{Value, json};

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures")
}

pub fn locks() -> PathBuf {
    fixtures().join("lockfiles")
}

pub fn incidents_dir() -> PathBuf {
    fixtures().join("incidents")
}

fn rustsec(
    id: &str,
    name: &str,
    summary: &str,
    events: Value,
    aliases: &[&str],
    categories: &[&str],
    informational: Option<&str>,
) -> Value {
    json!({
        "id": id,
        "summary": summary,
        "aliases": aliases,
        "related": [],
        "database_specific": {"license": "CC0-1.0"},
        "affected": [{
            "package": {"ecosystem": "crates.io", "name": name},
            "ranges": [{"type": "SEMVER", "events": events}],
            "database_specific": {
                "source": "https://github.com/rustsec/advisory-db/blob/osv/crates/X.json",
                "categories": categories,
                "informational": informational,
                "cvss": null,
            },
        }],
    })
}

pub fn vulns() -> HashMap<String, Value> {
    let mut m = HashMap::new();
    let mut add = |v: Value| {
        m.insert(v["id"].as_str().unwrap().to_string(), v);
    };
    add(rustsec(
        "RUSTSEC-2025-0148",
        "finch-rust",
        "`finch-rust` was removed from crates.io for malicious code",
        json!([{"introduced": "0.0.0-0"}]),
        &["GHSA-f8h5-x737-x4xr"],
        &["malicious"],
        None,
    ));
    add(json!({
        "id": "GHSA-f8h5-x737-x4xr",
        "summary": "`finch-rust` was removed from crates.io for malicious code",
        "aliases": ["RUSTSEC-2025-0148"],
        "database_specific": {"severity": "CRITICAL", "github_reviewed": true},
        "affected": [{"package": {"ecosystem": "crates.io", "name": "finch-rust"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}],
    }));
    add(rustsec(
        "RUSTSEC-2025-0146",
        "sha-rust",
        "`sha-rust` was removed from crates.io for malicious code",
        json!([{"introduced": "0.0.0-0"}]),
        &["GHSA-3mmg-7c2q-8938"],
        &[],
        None,
    ));
    add(rustsec(
        "RUSTSEC-2026-0260",
        "arrayref",
        "`arrayref` 0.3.10 was removed from crates.io due to a malicious dependency",
        json!([{"introduced": "0.3.10-0"}]),
        &[],
        &["malicious"],
        None,
    ));
    add(json!({
        "id": "MAL-2026-14336",
        "summary": "Malicious code in arrayref (crates.io)",
        "affected": [{"package": {"ecosystem": "crates.io", "name": "arrayref"}, "versions": ["0.3.10"]}],
    }));
    add(rustsec(
        "RUSTSEC-2020-0071",
        "time",
        "Potential segfault in the time crate",
        json!([{"introduced": "0.0.0-0"}, {"fixed": "0.2.0"}, {"introduced": "0.2.1-0"}, {"fixed": "0.2.1"},
               {"introduced": "0.2.7-0"}, {"fixed": "0.2.23"}]),
        &["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"],
        &["code-execution", "memory-corruption"],
        None,
    ));
    add(json!({
        "id": "GHSA-wcg3-cvx6-7396",
        "summary": "Segmentation fault in time",
        "aliases": ["CVE-2020-26235", "RUSTSEC-2020-0071"],
        "database_specific": {"severity": "MODERATE"},
        "affected": [{"package": {"ecosystem": "crates.io", "name": "time"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.1.0"}, {"fixed": "0.2.23"}]}]}],
    }));
    add(rustsec(
        "RUSTSEC-2024-0375",
        "atty",
        "`atty` is unmaintained",
        json!([{"introduced": "0.0.0-0"}]),
        &[],
        &[],
        Some("unmaintained"),
    ));
    add(rustsec(
        "RUSTSEC-2021-0145",
        "atty",
        "Potential unaligned read",
        json!([{"introduced": "0.0.0-0"}]),
        &["GHSA-g98v-hv3f-hcfr"],
        &[],
        Some("unsound"),
    ));
    let mut withdrawn =
        rustsec("RUSTSEC-2099-0001", "serde", "withdrawn example", json!([{"introduced": "0.0.0-0"}]), &[], &[], None);
    withdrawn["withdrawn"] = json!("2099-01-01T00:00:00Z");
    add(withdrawn);
    m
}

pub type Hits = HashMap<(String, String), Vec<String>>;

pub fn hit(name: &str, version: &str, ids: &[&str]) -> ((String, String), Vec<String>) {
    ((name.to_string(), version.to_string()), ids.iter().map(|s| s.to_string()).collect())
}

/// (name, version) -> OSV の querybatch が返す番号
pub fn hits() -> Hits {
    [
        hit("finch-rust", "0.1.0", &["GHSA-f8h5-x737-x4xr", "RUSTSEC-2025-0148"]),
        hit("sha-rust", "0.1.8", &["RUSTSEC-2025-0146"]),
        hit("arrayref", "0.3.10", &["MAL-2026-14336", "RUSTSEC-2026-0260"]),
        hit("time", "0.1.45", &["GHSA-wcg3-cvx6-7396", "RUSTSEC-2020-0071"]),
        hit("atty", "0.2.14", &["RUSTSEC-2021-0145", "RUSTSEC-2024-0375"]),
        hit("serde", "1.0.228", &["RUSTSEC-2099-0001"]),
    ]
    .into_iter()
    .collect()
}

#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub url: String,
    pub body: Option<Vec<u8>>,
    pub headers: Headers,
}

impl Call {
    pub fn json(&self) -> Value {
        serde_json::from_slice(self.body.as_deref().unwrap_or(b"null")).unwrap()
    }
}

/// GitHub の偽の応答: (method, path) -> (status, 本文)
pub type GitHubMap = HashMap<(String, String), (u16, Vec<u8>)>;

pub fn gh_json(map: &mut GitHubMap, method: &str, path: &str, status: u16, payload: Value) {
    map.insert((method.into(), path.into()), (status, serde_json::to_vec(&payload).unwrap()));
}

pub fn gh_bytes(map: &mut GitHubMap, method: &str, path: &str, status: u16, payload: Vec<u8>) {
    map.insert((method.into(), path.into()), (status, payload));
}

/// URL ごとに偽の応答を返し、呼ばれた記録を残します。
pub struct FakeFetch {
    pub hits: Hits,
    pub vulns: HashMap<String, Value>,
    /// next_page_token を試すとき
    pub page_size: Option<usize>,
    pub fail_osv: bool,
    pub tarball: Option<Vec<u8>>,
    pub github: GitHubMap,
    pub calls: RefCell<Vec<Call>>,
}

impl Default for FakeFetch {
    fn default() -> Self {
        FakeFetch {
            hits: hits(),
            vulns: vulns(),
            page_size: None,
            fail_osv: false,
            tarball: None,
            github: HashMap::new(),
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl FakeFetch {
    pub fn count(&self, prefix: &str) -> usize {
        self.calls.borrow().iter().filter(|c| c.url.starts_with(prefix)).count()
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.borrow().clone()
    }
}

impl Fetch for FakeFetch {
    fn fetch(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        headers: &Headers,
    ) -> Result<(u16, Vec<u8>), HttpError> {
        self.calls.borrow_mut().push(Call {
            method: method.into(),
            url: url.into(),
            body: body.map(<[u8]>::to_vec),
            headers: headers.clone(),
        });
        if url == "https://api.osv.dev/v1/querybatch" {
            if self.fail_osv {
                return Ok((503, b"unavailable".to_vec()));
            }
            let req: Value = serde_json::from_slice(body.unwrap()).unwrap();
            let mut results = Vec::new();
            for q in req["queries"].as_array().unwrap() {
                let key =
                    (q["package"]["name"].as_str().unwrap().to_string(), q["version"].as_str().unwrap().to_string());
                let ids = self.hits.get(&key).cloned().unwrap_or_default();
                let start: usize = q.get("page_token").and_then(Value::as_str).map_or(0, |t| t.parse().unwrap());
                let r = match self.page_size {
                    Some(size) => {
                        let chunk: Vec<&String> = ids.iter().skip(start).take(size).collect();
                        let mut r = if chunk.is_empty() {
                            json!({})
                        } else {
                            json!({"vulns": chunk.iter().map(|i| json!({"id": i})).collect::<Vec<_>>()})
                        };
                        if start + size < ids.len() {
                            r["next_page_token"] = json!((start + size).to_string());
                        }
                        r
                    }
                    None => {
                        if ids.is_empty() {
                            json!({})
                        } else {
                            json!({"vulns": ids.iter().map(|i| json!({"id": i})).collect::<Vec<_>>()})
                        }
                    }
                };
                results.push(r);
            }
            return Ok((200, serde_json::to_vec(&json!({"results": results})).unwrap()));
        }
        if let Some(vid) = url.strip_prefix("https://api.osv.dev/v1/vulns/") {
            return Ok(match self.vulns.get(vid) {
                Some(v) => (200, serde_json::to_vec(v).unwrap()),
                None => (404, b"{}".to_vec()),
            });
        }
        if url.starts_with("https://codeload.github.com/")
            && let Some(t) = &self.tarball
        {
            return Ok((200, t.clone()));
        }
        if let Some(path) = url.strip_prefix("https://api.github.com") {
            return Ok(match self.github.get(&(method.to_string(), path.to_string())) {
                Some((status, data)) => (*status, data.clone()),
                None => (404, br#"{"message":"Not Found"}"#.to_vec()),
            });
        }
        Ok((404, Vec::new()))
    }
}

fn append_dir(b: &mut tar::Builder<Vec<u8>>, dir: &Path, arc: &str) {
    let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name()).collect();
    names.sort();
    for n in names {
        let p = dir.join(&n);
        let a = format!("{arc}/{}", n.to_str().unwrap());
        if p.is_dir() {
            b.append_dir(&a, &p).unwrap();
            append_dir(b, &p, &a);
        } else {
            b.append_path_with_name(&p, &a).unwrap();
        }
    }
}

/// GitHub の codeload と同じ形（一番上に incidents-main/）の tar.gz を作ります。
pub fn make_tarball(root: &Path, prefix: &str) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    b.append_dir(prefix, root).unwrap();
    append_dir(&mut b, root, prefix);
    // ディスクへの展開を試すような、おかしな名前の項目も入れておきます
    let data = b"should be ignored";
    let mut h = tar::Header::new_gnu();
    let name = format!("{prefix}/../../evil.txt");
    h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_entry_type(tar::EntryType::Regular);
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
    gz.finish().unwrap()
}

pub fn default_tarball() -> Vec<u8> {
    make_tarball(&incidents_dir(), "incidents-main")
}

pub fn check_dir_with(name: &str, fetch: &FakeFetch, typo: Option<&TypoChecker>) -> CheckResult {
    let path = locks().join(name).join("Cargo.lock");
    let label = format!("{name}/Cargo.lock");
    let pkgs = merge_packages(vec![parse_lockfile(&path, Some(&label)).unwrap()]);
    let osv = OsvClient::new(fetch);
    let inc = load_dir(&incidents_dir()).unwrap();
    let default_typo = default_checker();
    let sources = Sources { osv: Some(&osv), incidents: Some(&inc), typo: Some(typo.unwrap_or(&default_typo)) };
    run_check(&pkgs, &[label], &sources, None, Vec::new())
}

pub fn check_dir(name: &str) -> CheckResult {
    check_dir_with(name, &FakeFetch::default(), None)
}

/// 試験ごとの一時ディレクトリ（終わると消えます）。
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> Self {
        TempDir(rustsecjp_check::util::make_temp_dir(&std::env::temp_dir(), "rustsecjp-check-test-").unwrap())
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn run_cli(args: &[&str], fetch: &FakeFetch, cwd: Option<&Path>) -> (i32, String) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let cwd = cwd.map_or_else(|| std::env::current_dir().unwrap(), Path::to_path_buf);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = rustsecjp_check::cli::run(&args, &cwd, fetch, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap())
}
