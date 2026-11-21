//! 名前を似せた crate（typosquat）かもしれない名前を探します。
//!
//! 名前が似ているだけで、悪性とは限りません。結果は「注意」としてだけ出します。

use std::collections::{HashMap, HashSet};

use crate::util::py_strip;

/// 同梱の「よく使われる crate」の一覧（crates.io のダウンロード数の上位）。
pub const POPULAR_TXT: &str = include_str!("../data/popular-crates.txt");
/// 名前が近くても正規と分かっている組。
pub const ALLOWLIST_TXT: &str = include_str!("../data/typo-allowlist.txt");

pub const MIN_LEN: usize = 5;
pub const SUFFIXES: &[&str] = &["-rs", "-rust", "_rs", "_rust", "-rst"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypoHint {
    pub crate_name: String,
    pub looks_like: String,
    pub reason: String,
}

/// `#` から後ろを除き、空でない行を返します。
pub fn read_list(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| py_strip(line.split('#').next().unwrap_or("")))
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn load_popular(text: &str) -> Vec<String> {
    read_list(text)
}

/// `name  popular` の組。
pub fn load_allowlist(text: &str) -> HashSet<(String, String)> {
    read_list(text)
        .iter()
        .filter_map(|line| {
            let parts: Vec<&str> = crate::util::py_split(line).collect();
            (parts.len() == 2).then(|| (norm(parts[0]), norm(parts[1])))
        })
        .collect()
}

/// crates.io は大文字小文字と - / _ の違いを同じ名前として扱います。
pub fn norm(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

/// a と b が Damerau-Levenshtein 距離（隣り合う入れ替えを 1 とする）でちょうど 1 なら、その種類を返します。
pub fn one_edit(a: &str, b: &str) -> Option<&'static str> {
    if a == b {
        return None;
    }
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (la, lb) = (a.len(), b.len());
    if la.abs_diff(lb) > 1 {
        return None;
    }
    if la == lb {
        let diff: Vec<usize> = (0..la).filter(|&i| a[i] != b[i]).collect();
        if diff.len() == 1 {
            let i = diff[0];
            if a[i].is_ascii_digit() && b[i].is_ascii_digit() {
                return None; // sha1 / sha2 のような、番号だけの違い
            }
            return Some("1 文字違い");
        }
        if diff.len() == 2 && diff[1] == diff[0] + 1 {
            let i = diff[0];
            if a[i] == b[i + 1] && a[i + 1] == b[i] {
                return Some("隣り合う 2 文字の入れ替え");
            }
        }
        return None;
    }
    // 1 文字の追加または削除
    let (short, long) = if la < lb { (&a, &b) } else { (&b, &a) };
    let mut i = 0;
    while i < short.len() && short[i] == long[i] {
        i += 1;
    }
    if short[i..] != long[i + 1..] {
        return None;
    }
    let extra = long[i];
    if extra.is_ascii_digit() {
        return None; // 番号だけの違い（objc / objc2 など）
    }
    if extra == '-' {
        return Some("区切りの - の有無");
    }
    Some("1 文字の追加または削除")
}

#[derive(Debug, Clone)]
pub struct TypoChecker {
    pub popular: Vec<String>,
    /// 正規化した名前 → もとの名前（後に出たものが勝ちます）
    popular_norm: HashMap<String, String>,
    allow: HashSet<(String, String)>,
    by_len: HashMap<usize, Vec<String>>,
}

impl TypoChecker {
    pub fn new<I, S>(popular: I, allow: HashSet<(String, String)>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut seen = HashSet::new();
        let mut list = Vec::new();
        for p in popular {
            let p: String = p.into();
            if seen.insert(p.clone()) {
                list.push(p);
            }
        }
        let mut popular_norm = HashMap::new();
        let mut norm_order = Vec::new();
        for p in &list {
            let n = norm(p);
            if popular_norm.insert(n.clone(), p.clone()).is_none() {
                norm_order.push(n);
            }
        }
        let mut by_len: HashMap<usize, Vec<String>> = HashMap::new();
        for n in norm_order {
            by_len.entry(n.chars().count()).or_default().push(n);
        }
        TypoChecker { popular: list, popular_norm, allow, by_len }
    }

    /// 同梱の一覧を使います。
    pub fn bundled() -> Self {
        TypoChecker::new(load_popular(POPULAR_TXT), load_allowlist(ALLOWLIST_TXT))
    }

    fn allowed(&self, n: &str, p: &str) -> bool {
        self.allow.contains(&(n.to_string(), p.to_string()))
    }

    pub fn check(&self, name: &str) -> Option<TypoHint> {
        let n = norm(name);
        let hint = |looks_like: &str, reason: String| {
            Some(TypoHint { crate_name: name.to_string(), looks_like: looks_like.to_string(), reason })
        };
        if let Some(pop) = self.popular_norm.get(&n) {
            if name.to_lowercase() != pop.to_lowercase() {
                // 区切りだけ違う（crates.io では同じ名前として扱われるので、
                // ほかのレジストリや記録の誤りを疑う手がかりになります）
                return hint(pop, "区切りの - と _ だけが違う".to_string());
            }
            return None;
        }
        for suf in SUFFIXES {
            let ns = norm(suf);
            if let Some(base) = n.strip_suffix(ns.as_str())
                && base.chars().count() >= 3
                && !self.allowed(&n, base)
                && let Some(pop) = self.popular_norm.get(base)
            {
                return hint(pop, format!("よく使われる名前に「{suf}」を付けた形"));
            }
        }
        let len = n.chars().count();
        if len < MIN_LEN {
            return None;
        }
        for ln in [len - 1, len, len + 1] {
            for p in self.by_len.get(&ln).map(Vec::as_slice).unwrap_or(&[]) {
                if p.chars().count() < MIN_LEN || self.allowed(&n, p) {
                    continue;
                }
                if let Some(why) = one_edit(&n, p) {
                    return hint(&self.popular_norm[p], why.to_string());
                }
            }
        }
        None
    }
}

/// 同梱の一覧を使う TypoChecker（Python の `default_checker()`）。
pub fn default_checker() -> TypoChecker {
    TypoChecker::bundled()
}
