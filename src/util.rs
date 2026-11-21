//! 小さな手伝い: JSON / TOML の値の扱い、時刻、一時ディレクトリ、パス。
//!
//! 外から来るデータ（OSV、GitHub、RustSecJP/incidents）は形が想定と違うことがあるので、
//! 「無い・空・違う型」をまとめて扱う関数をここに置きます。

use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

// ---- 文字 ----

/// Python の `str.isspace()` と同じ範囲の空白（`\x1c`〜`\x1f` も含みます）。
pub fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python の `str.strip()`。
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

/// Python の `str.split()`（引数なし）。
pub fn py_split(s: &str) -> impl Iterator<Item = &str> {
    s.split(is_py_space).filter(|x| !x.is_empty())
}

/// Python の `repr(str)` に近い形（エラーの文で使います）。
pub fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// URL の一部を百分率符号化します（Python の `urllib.parse.quote(s, safe=...)`）。
pub fn quote(s: &str, safe: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        let c = b as char;
        if b.is_ascii_alphanumeric() || "_.-~".contains(c) || (b.is_ascii() && safe.contains(c)) {
            out.push(c);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

// ---- JSON の値 ----

/// Python の真偽の判定（`if x:`）。
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `(v or {}).get(key)`。v が object でなければ None。
pub fn get<'a>(v: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    v.and_then(|v| v.as_object()).and_then(|o| o.get(key))
}

/// 文字列なら返します。
pub fn get_str<'a>(v: Option<&'a Value>, key: &str) -> Option<&'a str> {
    get(v, key).and_then(Value::as_str)
}

/// 配列なら中身を、そうでなければ空を返します（`x.get(k) or []`）。
pub fn get_array<'a>(v: Option<&'a Value>, key: &str) -> &'a [Value] {
    get(v, key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

/// Python の `str(v)`（JSON から読んだ値）。
pub fn json_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => json_repr(other),
    }
}

fn json_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => py_repr(s),
        Value::Array(a) => format!("[{}]", a.iter().map(json_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter().map(|(k, v)| format!("{}: {}", py_repr(k), json_repr(v))).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// Python の `int(v)` に近い変換。変換できなければ None。
pub fn json_int(v: &Value) -> Option<i64> {
    match v {
        Value::Bool(b) => Some(i64::from(*b)),
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f.trunc() as i64)),
        Value::String(s) => parse_py_int(s),
        _ => None,
    }
}

/// Python の `int(str)` に近い変換（前後の空白、`+`/`-`、数字の間の `_` を受け付けます）。
pub fn parse_py_int(s: &str) -> Option<i64> {
    let s = py_strip(s);
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    if !cleaned.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: i64 = cleaned.parse().ok()?;
    Some(if neg { -n } else { n })
}

// ---- TOML の値 ----

/// Python の真偽の判定（TOML から読んだ値）。
pub fn toml_truthy(v: &toml::Value) -> bool {
    match v {
        toml::Value::String(s) => !s.is_empty(),
        toml::Value::Integer(i) => *i != 0,
        toml::Value::Float(f) => *f != 0.0,
        toml::Value::Boolean(b) => *b,
        toml::Value::Datetime(_) => true,
        toml::Value::Array(a) => !a.is_empty(),
        toml::Value::Table(t) => !t.is_empty(),
    }
}

/// Python の `str(v)`（TOML から読んだ値）。
pub fn toml_str(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        other => toml_repr(other),
    }
}

fn toml_repr(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => py_repr(s),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => {
            if f.is_nan() {
                "nan".into()
            } else if f.is_infinite() {
                if *f > 0.0 { "inf".into() } else { "-inf".into() }
            } else {
                format!("{f:?}")
            }
        }
        toml::Value::Boolean(b) => if *b { "True" } else { "False" }.into(),
        toml::Value::Datetime(d) => d.to_string(),
        toml::Value::Array(a) => format!("[{}]", a.iter().map(toml_repr).collect::<Vec<_>>().join(", ")),
        toml::Value::Table(t) => format!(
            "{{{}}}",
            t.iter().map(|(k, v)| format!("{}: {}", py_repr(k), toml_repr(v))).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// TOML の字句の誤りを、Python の tomllib に近い一行の文にします。
pub fn toml_error_message(text: &str, e: &toml::de::Error) -> String {
    let msg = py_strip(e.message()).to_string();
    match e.span() {
        Some(span) => {
            let start = span.start.min(text.len());
            let before = &text.as_bytes()[..start];
            let line = before.iter().filter(|b| **b == b'\n').count() + 1;
            let line_start = before.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
            let col = String::from_utf8_lossy(&before[line_start..]).chars().count() + 1;
            format!("{msg} (at line {line}, column {col})")
        }
        None => msg,
    }
}

// ---- 時刻 ----

/// 今の時刻（UNIX 時間、秒）。
pub fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// UNIX 時間を `YYYY-MM-DD HH:MM UTC` の形にします。
pub fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant の civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

// ---- ファイルとパス ----

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `base` の下に、ほかと重ならない新しいディレクトリを作ります（Python の `tempfile.mkdtemp`）。
pub fn make_temp_dir(base: &Path, prefix: &str) -> std::io::Result<PathBuf> {
    let pid = std::process::id();
    for _ in 0..100 {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("{prefix}{pid:x}{nanos:08x}{n:x}"));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        match b.create(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "一時ディレクトリを作れませんでした"))
}

/// pathlib のように、`.` や重なった `/` を取り除きます（`..` はそのまま）。
pub fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir if !out.as_os_str().is_empty() => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Python の `Path.resolve()`（strict でない）に近いもの。
/// 存在する部分はシンボリックリンクをたどり、存在しない残りはそのまま付けます。
pub fn resolve(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    let mut existing = p.to_path_buf();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    while let Some(name) = existing.file_name().map(|n| n.to_os_string()) {
        existing.pop();
        rest.push(name);
        if let Ok(c) = std::fs::canonicalize(&existing) {
            let mut out = c;
            for n in rest.iter().rev() {
                out.push(n);
            }
            return lexical_dotdot(&out);
        }
    }
    lexical_dotdot(&normalize(p))
}

fn lexical_dotdot(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_format() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_utc(1_795_259_100), "2026-11-21 11:05 UTC");
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("sub dir/Cargo.lock", "/"), "sub%20dir/Cargo.lock");
        assert_eq!(quote("A:b/c", ""), "A%3Ab%2Fc");
        assert_eq!(py_repr("a'b"), "\"a'b\"");
        assert_eq!(py_repr("x/y"), "'x/y'");
    }

    #[test]
    fn ints() {
        assert_eq!(json_int(&serde_json::json!("12")), Some(12));
        assert_eq!(json_int(&serde_json::json!(" 1_000 ")), Some(1000));
        assert_eq!(json_int(&serde_json::json!(3.7)), Some(3));
        assert_eq!(json_int(&serde_json::json!(true)), Some(1));
        assert_eq!(json_int(&serde_json::json!("x")), None);
        assert_eq!(json_int(&serde_json::json!(null)), None);
    }

    #[test]
    fn temp_dirs_are_unique() {
        let base = std::env::temp_dir();
        let a = make_temp_dir(&base, "rustsecjp-check-test-").unwrap();
        let b = make_temp_dir(&base, "rustsecjp-check-test-").unwrap();
        assert_ne!(a, b);
        std::fs::remove_dir(a).unwrap();
        std::fs::remove_dir(b).unwrap();
    }
}
