//! OSV（<https://osv.dev>）から、既知の助言を取ってきます。
//!
//! OSV へ送るのは crate の名前と版番号だけです。

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;

use serde_json::{Value, json};

use crate::http::{Fetch, json_request};
use crate::util::{get, get_array, get_str, json_str, quote, truthy};
use crate::versions as v;

pub const QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
pub const VULN_URL_PREFIX: &str = "https://api.osv.dev/v1/vulns/";
pub const BATCH_SIZE: usize = 1000;
pub const MAX_PAGES: usize = 20;

/// `^[A-Za-z0-9][A-Za-z0-9._:-]{1,80}$`
pub fn is_valid_id(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=81).contains(&b.len())
        && b[0].is_ascii_alphanumeric()
        && b[1..].iter().all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(c))
}

/// `removed from crates\.io (for|due to) (a )?malicious`（大文字小文字は区別しません）
pub fn summary_says_malicious(summary: &str) -> bool {
    let s = summary.to_ascii_lowercase();
    ["for malicious", "for a malicious", "due to malicious", "due to a malicious"]
        .iter()
        .any(|tail| s.contains(&format!("removed from crates.io {tail}")))
}

/// 1 つの crate の版に当たる助言（別名でつながったものは 1 つにまとめます）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    /// "malicious" / "vulnerability" / "info"
    pub category: &'static str,
    /// まとめた番号すべて（RUSTSEC を先に）
    pub ids: Vec<String>,
    pub summary: String,
    /// unmaintained / unsound など
    pub informational: Option<String>,
    pub severity: Option<String>,
    pub fixed: Vec<String>,
}

impl Advisory {
    pub fn primary_id(&self) -> &str {
        &self.ids[0]
    }

    pub fn rustsec_ids(&self) -> Vec<&str> {
        self.ids.iter().filter(|i| i.starts_with("RUSTSEC-")).map(String::as_str).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsvError(pub String);

impl fmt::Display for OsvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OsvError {}

pub type Key = (String, String);

pub struct OsvClient<'a> {
    fetch: &'a dyn Fetch,
    vuln_cache: RefCell<HashMap<String, Value>>,
}

impl<'a> OsvClient<'a> {
    pub fn new(fetch: &'a dyn Fetch) -> Self {
        OsvClient { fetch, vuln_cache: RefCell::new(HashMap::new()) }
    }

    // ---- 取ってくる ----

    /// (name, version) ごとに、当たる助言の番号の一覧を返します。
    pub fn query(&self, pkgs: &[Key]) -> Result<HashMap<Key, Vec<String>>, OsvError> {
        let mut out: HashMap<Key, Vec<String>> = HashMap::new();
        for chunk in pkgs.chunks(BATCH_SIZE) {
            let mut pending: Vec<(&Key, Option<Value>)> = chunk.iter().map(|k| (k, None)).collect();
            let mut pages = 0;
            while !pending.is_empty() {
                pages += 1;
                if pages > MAX_PAGES {
                    return Err(OsvError("OSV の応答のページが多すぎます".into()));
                }
                let queries: Vec<Value> = pending
                    .iter()
                    .map(|((name, ver), token)| {
                        let mut q = json!({"package": {"ecosystem": "crates.io", "name": name}, "version": ver});
                        if let Some(t) = token.as_ref().filter(|t| truthy(t)) {
                            q["page_token"] = t.clone();
                        }
                        q
                    })
                    .collect();
                let resp = json_request(self.fetch, "POST", QUERYBATCH_URL, Some(&json!({"queries": queries})), None)
                    .map_err(|e| OsvError(format!("OSV への問い合わせに失敗しました: {e}")))?;
                let shape_err = || OsvError("OSV の応答の形が想定と違います".into());
                let results = match resp.as_ref() {
                    None => return Err(shape_err()),
                    Some(r) if !r.is_object() => return Err(shape_err()),
                    Some(r) => r.get("results").and_then(Value::as_array).ok_or_else(shape_err)?,
                };
                if results.len() != pending.len() {
                    return Err(shape_err());
                }
                let mut next = Vec::new();
                for ((key, _), res) in pending.iter().zip(results) {
                    if !res.is_null() && !res.is_object() {
                        return Err(shape_err());
                    }
                    let ids = out.entry((*key).clone()).or_default();
                    for vv in get_array(Some(res), "vulns") {
                        if let Some(vid) = get_str(Some(vv), "id")
                            && is_valid_id(vid)
                            && !ids.iter().any(|i| i == vid)
                        {
                            ids.push(vid.to_string());
                        }
                    }
                    if let Some(token) = get(Some(res), "next_page_token").filter(|t| truthy(t)) {
                        next.push((*key, Some(token.clone())));
                    }
                }
                pending = next;
            }
        }
        Ok(out)
    }

    pub fn vuln(&self, vid: &str) -> Result<Value, OsvError> {
        if let Some(v) = self.vuln_cache.borrow().get(vid) {
            return Ok(v.clone());
        }
        if !is_valid_id(vid) {
            return Err(OsvError(format!("おかしな番号: {}", crate::util::py_repr(vid))));
        }
        let url = format!("{VULN_URL_PREFIX}{}", quote(vid, ""));
        let d = json_request(self.fetch, "GET", &url, None, None)
            .map_err(|e| OsvError(format!("OSV から {vid} を取れませんでした: {e}")))?;
        let d = match d {
            Some(v) if v.is_object() => v,
            _ => json!({}),
        };
        self.vuln_cache.borrow_mut().insert(vid.to_string(), d.clone());
        Ok(d)
    }

    // ---- まとめる ----

    pub fn advisories_for(&self, name: &str, version: &str, ids: &[String]) -> Result<Vec<Advisory>, OsvError> {
        let mut details = Vec::new();
        for vid in ids {
            let d = self.vuln(vid)?;
            if d.get("withdrawn").is_some_and(truthy) {
                continue;
            }
            details.push((vid.clone(), d));
        }
        Ok(group_advisories(name, version, &details))
    }
}

fn affected_for<'v>(d: &'v Value, name: &str) -> Vec<&'v Value> {
    get_array(Some(d), "affected")
        .iter()
        .filter(|a| {
            let pkg = get(Some(a), "package");
            get_str(pkg, "name") == Some(name) && get_str(pkg, "ecosystem") == Some("crates.io")
        })
        .collect()
}

fn category_of(vid: &str, d: &Value, name: &str) -> (&'static str, Option<String>) {
    let mut informational = None;
    let mut categories: Vec<&str> = Vec::new();
    for a in affected_for(d, name) {
        let ds = get(Some(a), "database_specific");
        if let Some(inf) = get(ds, "informational").filter(|x| truthy(x)) {
            informational = Some(json_str(inf));
        }
        categories.extend(get_array(ds, "categories").iter().filter_map(Value::as_str));
    }
    let summary = get_str(Some(d), "summary").unwrap_or("");
    if vid.starts_with("MAL-") || categories.contains(&"malicious") || summary_says_malicious(summary) {
        return ("malicious", informational);
    }
    if informational.is_some() {
        return ("info", informational); // unmaintained / unsound / notice など
    }
    ("vulnerability", None)
}

fn fixed_versions(d: &Value, name: &str) -> Vec<String> {
    let mut fixed: Vec<String> = Vec::new();
    for a in affected_for(d, name) {
        for r in get_array(Some(a), "ranges") {
            if !matches!(get_str(Some(r), "type"), Some("SEMVER" | "ECOSYSTEM")) {
                continue;
            }
            for ev in get_array(Some(r), "events") {
                if let Some(f) = get_str(Some(ev), "fixed") {
                    // RustSec の OSV では「0.1.10-0」のように書かれる
                    let f = f.strip_suffix("-0").unwrap_or(f);
                    if !fixed.iter().any(|x| x == f) {
                        fixed.push(f.to_string());
                    }
                }
            }
        }
    }
    fixed
}

fn severity(d: &Value) -> Option<String> {
    get_str(get(Some(d), "database_specific"), "severity").filter(|s| !s.is_empty()).map(str::to_uppercase)
}

fn id_order(i: &str) -> (u8, &str) {
    for (n, prefix) in ["RUSTSEC-", "GHSA-", "CVE-", "MAL-"].iter().enumerate() {
        if i.starts_with(prefix) {
            return (n as u8, i);
        }
    }
    (9, i)
}

fn cmp_ids(a: &str, b: &str) -> Ordering {
    id_order(a).cmp(&id_order(b))
}

/// 別名（aliases）でつながる助言を 1 つにまとめます。
///
/// MAL-* には RUSTSEC への別名が付かないことが多いので、
/// 悪性の助言は crate ごとに 1 つにまとめます。
pub fn group_advisories(name: &str, version: &str, details: &[(String, Value)]) -> Vec<Advisory> {
    let index: HashMap<&str, usize> = details.iter().enumerate().map(|(i, (vid, _))| (vid.as_str(), i)).collect();
    let mut parent: Vec<usize> = (0..details.len()).collect();

    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }
    fn union(parent: &mut [usize], a: usize, b: usize) {
        let (ra, rb) = (find(parent, a), find(parent, b));
        if ra != rb {
            parent[rb] = ra;
        }
    }

    for (i, (_, d)) in details.iter().enumerate() {
        for al in get_array(Some(d), "aliases").iter().chain(get_array(Some(d), "related_aliases")) {
            if let Some(&j) = al.as_str().and_then(|s| index.get(s)) {
                union(&mut parent, i, j);
            }
        }
    }

    let cats: Vec<(&'static str, Option<String>)> = details.iter().map(|(vid, d)| category_of(vid, d, name)).collect();
    let mal: Vec<usize> = (0..details.len()).filter(|&i| cats[i].0 == "malicious").collect();
    for &other in mal.iter().skip(1) {
        union(&mut parent, mal[0], other);
    }

    // 根ごとにまとめます（最初に出た順）
    let mut groups: Vec<(usize, Vec<usize>)> = Vec::new();
    for i in 0..details.len() {
        let root = find(&mut parent, i);
        match groups.iter_mut().find(|(r, _)| *r == root) {
            Some((_, members)) => members.push(i),
            None => groups.push((root, vec![i])),
        }
    }

    let mut out = Vec::new();
    for (_, members) in groups {
        let mut all_ids: Vec<String> = Vec::new();
        for &m in &members {
            let (vid, d) = &details[m];
            let aliases = get_array(Some(d), "aliases").iter().filter_map(Value::as_str);
            for i in std::iter::once(vid.as_str()).chain(aliases) {
                if !all_ids.iter().any(|x| x == i) {
                    all_ids.push(i.to_string());
                }
            }
        }
        all_ids.sort_by(|a, b| cmp_ids(a, b));

        let member_cats: Vec<&str> = members.iter().map(|&m| cats[m].0).collect();
        let category = if member_cats.contains(&"malicious") {
            "malicious"
        } else if member_cats.contains(&"vulnerability")
            && !members.iter().any(|&m| details[m].0.starts_with("RUSTSEC-") && cats[m].1.is_some())
        {
            "vulnerability"
        } else if member_cats.contains(&"info") {
            "info"
        } else {
            "vulnerability"
        };
        let informational = members.iter().find_map(|&m| cats[m].1.clone());
        let mut ordered = members.clone();
        ordered.sort_by(|&a, &b| cmp_ids(&details[a].0, &details[b].0));
        let summary = ordered
            .iter()
            .find_map(|&m| get_str(Some(&details[m].1), "summary").filter(|s| !s.is_empty()))
            .unwrap_or("");
        let sev = ordered.iter().find_map(|&m| severity(&details[m].1));
        let mut fixed: Vec<String> = Vec::new();
        for &m in &ordered {
            for f in fixed_versions(&details[m].1, name) {
                if !fixed.contains(&f) {
                    fixed.push(f);
                }
            }
        }
        let mut fixed: Vec<String> =
            fixed.into_iter().filter(|f| v::compare(f, version) == Ordering::Greater).collect();
        fixed.sort_by_cached_key(|f| v::parse(f));
        out.push(Advisory {
            category,
            ids: all_ids,
            summary: crate::util::py_strip(summary).to_string(),
            informational,
            severity: sev,
            fixed,
        });
    }
    out.sort_by(|a, b| cmp_ids(a.primary_id(), b.primary_id()));
    out
}
