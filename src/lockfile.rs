//! `Cargo.lock` をデータとして読みます。ビルドや実行はしません。

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::util::toml_error_message;

pub const CRATES_IO_SOURCES: &[&str] =
    &["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"];

/// 探すときに入らないディレクトリ。
pub const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum: Option<String>,
    /// どの Cargo.lock にあったか
    pub lockfiles: Vec<String>,
}

impl Package {
    /// `crates.io` / `registry`（ほかのレジストリ）/ `git` / `path` / `other` のどれか。
    pub fn kind(&self) -> &'static str {
        match self.source.as_deref() {
            None => "path",
            Some(s) if CRATES_IO_SOURCES.contains(&s) => "crates.io",
            Some(s) if s.starts_with("git+") => "git",
            Some(s) if s.starts_with("registry+") || s.starts_with("sparse+") => "registry",
            Some(_) => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockfileError(pub String);

impl fmt::Display for LockfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LockfileError {}

pub fn parse_lockfile_text(text: &str, label: &str) -> Result<Vec<Package>, LockfileError> {
    let data: toml::Table = toml::from_str(text).map_err(|e| {
        LockfileError(format!("{label}: Cargo.lock を読めませんでした（{}）", toml_error_message(text, &e)))
    })?;
    let mut pkgs = Vec::new();
    let Some(list) = data.get("package").and_then(toml::Value::as_array) else {
        return Ok(pkgs);
    };
    for p in list {
        let Some(p) = p.as_table() else { continue };
        let (Some(name), Some(version)) =
            (p.get("name").and_then(toml::Value::as_str), p.get("version").and_then(toml::Value::as_str))
        else {
            continue;
        };
        pkgs.push(Package {
            name: name.to_string(),
            version: version.to_string(),
            source: p.get("source").and_then(toml::Value::as_str).map(str::to_string),
            checksum: p.get("checksum").and_then(toml::Value::as_str).map(str::to_string),
            lockfiles: vec![label.to_string()],
        });
    }
    Ok(pkgs)
}

pub fn parse_lockfile(path: &Path, label: Option<&str>) -> Result<Vec<Package>, LockfileError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| LockfileError(format!("{}: 読めませんでした（{e}）", path.display())))?;
    let label = label.map_or_else(|| path.display().to_string(), str::to_string);
    parse_lockfile_text(&text, &label)
}

/// root の下の Cargo.lock をすべて探します（`target/` などは除きます）。
///
/// 上のディレクトリから順に、名前の順で深く入っていきます。
/// シンボリックリンクのディレクトリには入りません。
pub fn find_lockfiles(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk(root, &mut found);
    found
}

fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut subdirs = Vec::new();
    let mut has_lock = false;
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Ok(ft) = entry.file_type() else { continue };
        let is_dir =
            if ft.is_symlink() { std::fs::metadata(entry.path()).is_ok_and(|m| m.is_dir()) } else { ft.is_dir() };
        if is_dir {
            if ft.is_symlink() {
                continue; // os.walk(followlinks=False) と同じく、たどりません
            }
            if name.to_str().is_some_and(|n| SKIP_DIRS.contains(&n)) {
                continue;
            }
            subdirs.push(name);
        } else if name == "Cargo.lock" {
            has_lock = true;
        }
    }
    if has_lock {
        found.push(dir.join("Cargo.lock"));
    }
    subdirs.sort();
    for d in subdirs {
        walk(&dir.join(d), found);
    }
}

/// 同じ (name, version, source) をまとめ、どの Cargo.lock にあったかを残します。
pub fn merge_packages(groups: Vec<Vec<Package>>) -> Vec<Package> {
    let mut merged: Vec<Package> = Vec::new();
    let mut index: HashMap<(String, String, Option<String>), usize> = HashMap::new();
    for pkgs in groups {
        for p in pkgs {
            let key = (p.name.clone(), p.version.clone(), p.source.clone());
            if let Some(&i) = index.get(&key) {
                for lf in p.lockfiles {
                    if !merged[i].lockfiles.contains(&lf) {
                        merged[i].lockfiles.push(lf);
                    }
                }
            } else {
                index.insert(key, merged.len());
                merged.push(p);
            }
        }
    }
    merged.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    merged
}
