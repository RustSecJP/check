//! 小さなグロブ。Python の `glob.glob(pattern, root_dir=..., recursive=True)` と同じ考え方です。
//!
//! - `*` `?` `[abc]` `[!abc]` `[a-z]` が使えます。`**` は 0 個以上のディレクトリに当たります。
//! - `.` で始まる名前には、パターンの側も `.` で始まるときだけ当たります。
//! - 結果は `root` からの相対のパス（パターンが絶対パスなら絶対パス）です。
//! - `**` はシンボリックリンクのディレクトリの中には入りません（ループを避けるため）。

use std::path::{Path, PathBuf};

pub fn has_magic(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

fn is_hidden(name: &str) -> bool {
    name.starts_with('.')
}

fn is_recursive(pattern: &str) -> bool {
    pattern == "**"
}

/// `os.path.split`
fn split(p: &str) -> (&str, &str) {
    match p.rfind('/') {
        None => ("", p),
        Some(i) => {
            let head = &p[..=i];
            let tail = &p[i + 1..];
            let trimmed = head.trim_end_matches('/');
            (if trimmed.is_empty() { head } else { trimmed }, tail)
        }
    }
}

/// `posixpath.join(a, b)`
fn join(a: &str, b: &str) -> String {
    if b.starts_with('/') || a.is_empty() {
        b.to_string()
    } else if a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

fn under(root: &Path, p: &str) -> PathBuf {
    if p.is_empty() { root.to_path_buf() } else { root.join(p) }
}

fn lexists(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

fn is_dir(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_dir())
}

/// ディレクトリの中の名前（dironly ならディレクトリだけ）。読めなければ空。
fn listdir(dir: &Path, dironly: bool) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_string) else { continue };
        if !dironly || is_dir(&e.path()) {
            out.push(name);
        }
    }
    out
}

/// パターンに当たるパスを返します（順は決まっていません。使う側で並べてください）。
pub fn glob(pattern: &str, root: &Path) -> Vec<String> {
    let mut out = iglob(pattern, root, false);
    if (pattern.is_empty() || pattern.starts_with("**")) && out.first().is_some_and(String::is_empty) {
        out.remove(0);
    }
    out
}

fn iglob(pathname: &str, root: &Path, dironly: bool) -> Vec<String> {
    let (dirname, basename) = split(pathname);
    if !has_magic(pathname) {
        let ok = if basename.is_empty() { is_dir(&under(root, dirname)) } else { lexists(&under(root, pathname)) };
        return if ok { vec![pathname.to_string()] } else { Vec::new() };
    }
    if dirname.is_empty() {
        return if is_recursive(basename) { glob2(root, basename, dironly) } else { glob1(root, basename, dironly) };
    }
    let dirs =
        if dirname != pathname && has_magic(dirname) { iglob(dirname, root, true) } else { vec![dirname.to_string()] };
    let mut out = Vec::new();
    for d in dirs {
        let dir_path = under(root, &d);
        let names = if has_magic(basename) {
            if is_recursive(basename) {
                glob2(&dir_path, basename, dironly)
            } else {
                glob1(&dir_path, basename, dironly)
            }
        } else {
            glob0(&dir_path, basename)
        };
        for n in names {
            out.push(join(&d, &n));
        }
    }
    out
}

fn glob0(dir: &Path, basename: &str) -> Vec<String> {
    let ok = if basename.is_empty() { is_dir(dir) } else { lexists(&dir.join(basename)) };
    if ok { vec![basename.to_string()] } else { Vec::new() }
}

fn glob1(dir: &Path, pattern: &str, dironly: bool) -> Vec<String> {
    let hidden_ok = is_hidden(pattern);
    listdir(dir, dironly).into_iter().filter(|n| (hidden_ok || !is_hidden(n)) && fnmatch(n, pattern)).collect()
}

fn glob2(dir: &Path, _pattern: &str, dironly: bool) -> Vec<String> {
    let mut out = Vec::new();
    if is_dir(dir) {
        out.push(String::new());
    }
    rlistdir(dir, "", dironly, &mut out, 0);
    out
}

fn rlistdir(dir: &Path, prefix: &str, dironly: bool, out: &mut Vec<String>, depth: usize) {
    if depth > 64 {
        return;
    }
    for x in listdir(dir, dironly) {
        if is_hidden(&x) {
            continue;
        }
        let rel = join(prefix, &x);
        out.push(rel.clone());
        let path = dir.join(&x);
        let is_link = std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink());
        if !is_link && is_dir(&path) {
            rlistdir(&path, &rel, dironly, out, depth + 1);
        }
    }
}

#[derive(Debug)]
enum Tok {
    Lit(char),
    Any,
    One,
    Class { neg: bool, items: Vec<(char, char)> },
    Never,
}

fn tokenize(pat: &str) -> Vec<Tok> {
    let p: Vec<char> = pat.chars().collect();
    let n = p.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let c = p[i];
        i += 1;
        match c {
            '*' => {
                if !matches!(out.last(), Some(Tok::Any)) {
                    out.push(Tok::Any);
                }
            }
            '?' => out.push(Tok::One),
            '[' => {
                let mut j = i;
                if j < n && p[j] == '!' {
                    j += 1;
                }
                if j < n && p[j] == ']' {
                    j += 1;
                }
                while j < n && p[j] != ']' {
                    j += 1;
                }
                if j >= n {
                    out.push(Tok::Lit('['));
                    continue;
                }
                let stuff: Vec<char> = p[i..j].to_vec();
                i = j + 1;
                if stuff.is_empty() {
                    out.push(Tok::Never);
                    continue;
                }
                if stuff == ['!'] {
                    out.push(Tok::One);
                    continue;
                }
                let (neg, body) = if stuff[0] == '!' { (true, &stuff[1..]) } else { (false, &stuff[..]) };
                let mut items = Vec::new();
                let mut k = 0;
                while k < body.len() {
                    if k + 2 < body.len() && body[k + 1] == '-' {
                        if body[k] <= body[k + 2] {
                            items.push((body[k], body[k + 2]));
                        }
                        k += 3;
                    } else {
                        items.push((body[k], body[k]));
                        k += 1;
                    }
                }
                if items.is_empty() && !neg {
                    out.push(Tok::Never);
                } else {
                    out.push(Tok::Class { neg, items });
                }
            }
            c => out.push(Tok::Lit(c)),
        }
    }
    out
}

/// `fnmatch.fnmatchcase(name, pattern)`
pub fn fnmatch(name: &str, pattern: &str) -> bool {
    let toks = tokenize(pattern);
    let s: Vec<char> = name.chars().collect();
    matches_at(&toks, &s)
}

fn matches_at(toks: &[Tok], s: &[char]) -> bool {
    // 反復の方法（* の位置を覚えて戻る）
    let (mut ti, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        let ok = match toks.get(ti) {
            Some(Tok::Lit(c)) => *c == s[si],
            Some(Tok::One) => true,
            Some(Tok::Class { neg, items }) => items.iter().any(|(lo, hi)| (*lo..=*hi).contains(&s[si])) != *neg,
            Some(Tok::Any) => {
                star = Some((ti, si));
                ti += 1;
                continue;
            }
            Some(Tok::Never) | None => false,
        };
        if ok {
            ti += 1;
            si += 1;
        } else if let Some((st, ss)) = star {
            ti = st + 1;
            si = ss + 1;
            star = Some((st, ss + 1));
        } else {
            return false;
        }
    }
    toks[ti..].iter().all(|t| matches!(t, Tok::Any))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnmatch_rules() {
        assert!(fnmatch("hijacked-bad", "hijacked-*"));
        assert!(!fnmatch("clean", "hijacked-*"));
        assert!(fnmatch("a1", "a[0-9]"));
        assert!(!fnmatch("ax", "a[0-9]"));
        assert!(fnmatch("ax", "a[!0-9]"));
        assert!(fnmatch("a]", "a[]]"));
        assert!(fnmatch("[x", "[x"));
        assert!(fnmatch("abc", "a*c"));
        assert!(fnmatch("ac", "a*c"));
        assert!(fnmatch("a-c", "a?c"));
        assert!(!fnmatch("abd", "a*c"));
        assert!(fnmatch("Cargo.lock", "*"));
    }

    #[test]
    fn split_and_join() {
        assert_eq!(split("a/b"), ("a", "b"));
        assert_eq!(split("/b"), ("/", "b"));
        assert_eq!(split("a//b"), ("a", "b"));
        assert_eq!(split("b"), ("", "b"));
        assert_eq!(join("", "x"), "x");
        assert_eq!(join("a", "x"), "a/x");
        assert_eq!(join("a", ""), "a/");
    }
}
