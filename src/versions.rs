//! 版番号（semver）の比べ方と、自由な文から版番号を取り出す処理。
//!
//! OSV や RustSecJP の記録の版番号は、厳密な semver とは限りません。
//! 読めない部分は 0 として比べます（もとの Python 版と同じ扱い）。

use std::cmp::Ordering;

use crate::util::py_strip;

/// 範囲や「すべて」を表す言葉。これがあると、版の一覧として扱えません。
pub const RANGE_WORDS: &[&str] = &[
    "〜",
    "～",
    "~",
    "以前",
    "以降",
    "以上",
    "以下",
    "未満",
    "より前",
    "より後",
    "すべて",
    "全て",
    "全版",
    "<",
    ">",
    "*",
    "^",
];

/// 大きさに制限の無い、0 以上の整数（前の 0 を除いた桁の数と、桁の並びで比べます）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Num(usize, String);

impl Num {
    fn zero() -> Self {
        Num(0, String::new())
    }

    fn parse(s: &str) -> Option<Self> {
        let s = py_strip(s);
        let s = s.strip_prefix('+').unwrap_or(s);
        if s.is_empty() || s.starts_with('_') || s.ends_with('_') || s.contains("__") {
            return None;
        }
        let digits: String = s.chars().filter(|c| *c != '_').collect();
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let trimmed = digits.trim_start_matches('0').to_string();
        Some(Num(trimmed.len(), trimmed))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Ident {
    Numeric(Num),
    Alpha(String),
}

/// 先行版（pre-release）は、正式な版より前になります。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Pre {
    Pre(Vec<Ident>),
    Release,
}

/// 比べるためのキー。semver の順序に従います（build メタデータは無視）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VersionKey {
    nums: [Num; 3],
    pre: Pre,
}

pub fn parse(v: &str) -> VersionKey {
    let v = v.split_once('+').map_or(v, |(a, _)| a);
    let (core, pre) = v.split_once('-').unwrap_or((v, ""));
    let mut nums: Vec<Num> = core.split('.').map(|p| Num::parse(p).unwrap_or_else(Num::zero)).collect();
    while nums.len() < 3 {
        nums.push(Num::zero());
    }
    nums.truncate(3);
    let pre = if pre.is_empty() {
        Pre::Release
    } else {
        Pre::Pre(
            pre.split('.')
                .map(|ident| {
                    if !ident.is_empty() && ident.bytes().all(|b| b.is_ascii_digit()) {
                        Ident::Numeric(Num::parse(ident).unwrap_or_else(Num::zero))
                    } else {
                        Ident::Alpha(ident.to_string())
                    }
                })
                .collect(),
        )
    };
    let [a, b, c]: [Num; 3] = nums.try_into().unwrap_or_else(|_| [Num::zero(), Num::zero(), Num::zero()]);
    VersionKey { nums: [a, b, c], pre }
}

pub fn compare(a: &str, b: &str) -> Ordering {
    parse(a).cmp(&parse(b))
}

fn is_alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

fn digits(c: &[char], i: usize) -> Option<usize> {
    let mut j = i;
    while j < c.len() && c[j].is_ascii_digit() {
        j += 1;
    }
    (j > i).then_some(j)
}

/// `[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*` を i から読み、終わりの位置を返します。
fn ident_seq(c: &[char], i: usize) -> Option<usize> {
    let run = |k: usize| {
        let mut j = k;
        while j < c.len() && is_alnum(c[j]) {
            j += 1;
        }
        (j > k).then_some(j)
    };
    let mut j = run(i)?;
    while j < c.len() && c[j] == '.' {
        match run(j + 1) {
            Some(k) => j = k,
            None => break,
        }
    }
    Some(j)
}

/// `\d+\.\d+\.\d+(-pre)?(+build)?` を i から（できるだけ長く）読みます。
fn match_core(c: &[char], i: usize) -> Option<usize> {
    let mut j = digits(c, i)?;
    for _ in 0..2 {
        if c.get(j) != Some(&'.') {
            return None;
        }
        j = digits(c, j + 1)?;
    }
    if c.get(j) == Some(&'-')
        && let Some(k) = ident_seq(c, j + 1)
    {
        j = k;
    }
    if c.get(j) == Some(&'+')
        && let Some(k) = ident_seq(c, j + 1)
    {
        j = k;
    }
    Some(j)
}

/// 文の中の版番号をすべて取り出します。
/// 前が英数字か `.`、後ろが英数字のものは版番号として読みません（日付などを避けるため）。
pub fn extract_versions(text: &str) -> Vec<String> {
    let c: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let boundary = i == 0 || !(is_alnum(c[i - 1]) || c[i - 1] == '.');
        if c[i].is_ascii_digit()
            && boundary
            && let Some(end) = match_core(&c, i)
            && (end >= c.len() || !is_alnum(c[end]))
        {
            out.push(c[i..end].iter().collect());
            i = end;
            continue;
        }
        i += 1;
    }
    out
}

/// 文全体が版番号だけ（先頭の `v` は可）なら、その版番号を返します。
fn exact(entry: &str) -> Option<String> {
    let c: Vec<char> = entry.chars().collect();
    let start = usize::from(c.first() == Some(&'v'));
    match match_core(&c, start) {
        Some(end) if end == c.len() => Some(c[start..end].iter().collect()),
        _ => None,
    }
}

/// `versions` の 1 項目の種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// 版番号だけが書いてある（例 "0.3.10"）
    Exact,
    /// 版番号に説明が付いている（例 "0.1.9（2026-08-20 公開のもの）"）
    Qualified,
    /// 版番号が読み取れない、または範囲やすべてを表している
    Unknown,
}

/// `versions` の 1 項目を調べます。
pub fn classify_entry(entry: &str) -> (EntryKind, Vec<String>) {
    let entry = py_strip(entry);
    if let Some(v) = exact(entry) {
        return (EntryKind::Exact, vec![v]);
    }
    if RANGE_WORDS.iter().any(|w| entry.contains(w)) {
        return (EntryKind::Unknown, extract_versions(entry));
    }
    let found = extract_versions(entry);
    if found.is_empty() { (EntryKind::Unknown, found) } else { (EntryKind::Qualified, found) }
}

pub fn same_version(a: &str, b: &str) -> bool {
    a.split('+').next() == b.split('+').next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_edge_cases() {
        assert_eq!(extract_versions("1.2.3.4"), vec!["1.2.3"]);
        assert_eq!(extract_versions("v1.2.3"), Vec::<String>::new());
        assert_eq!(extract_versions("x 1.2.3-rc.1+b5, 2.0.0。"), vec!["1.2.3-rc.1+b5", "2.0.0"]);
        assert_eq!(extract_versions("1.2.3a"), Vec::<String>::new());
        assert_eq!(extract_versions("1.2.3-"), vec!["1.2.3"]);
        assert_eq!(classify_entry(" v1.0.0 ").1, vec!["1.0.0"]);
    }

    #[test]
    fn big_numbers() {
        assert_eq!(compare("1.0.99999999999999999999999", "1.0.100000000000000000000000"), Ordering::Less);
        assert_eq!(compare("01.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare("1.0.0-1", "1.0.0-a"), Ordering::Less);
        assert_eq!(compare("1.0.0-a", "1.0.0-a.1"), Ordering::Less);
    }
}
