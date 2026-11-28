//! もとの Python 版（v0.1.0）が同じ偽の応答で出した報告（tests/golden/）と、1 文字ずつ同じかを確かめます。
//!
//! 確認した時刻だけは、比べる前に消します。
//! この道具の版番号は、Python 版の 0.1.0 から今の版に置き換えてから比べます。

mod common;

use common::*;
use serde_json::Value;

fn golden_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden")
}

/// 確認した時刻を消します。
fn strip_time(s: &str) -> String {
    let mut out = s.to_string();
    for (key, end) in [("確認した時刻: ", " ／"), ("\"checked_at\": \"", "\"")] {
        if let Some(i) = out.find(key) {
            let start = i + key.len();
            if let Some(j) = out[start..].find(end) {
                out.replace_range(start..start + j, "<time>");
            }
        }
    }
    out
}

/// 報告の中のこの道具の版番号（Python 版の 0.1.0）を、今の版に置き換えます。
/// crate の版番号（依存の一覧の "version"）は置き換えません。
fn with_current_version(s: &str) -> String {
    let v = env!("CARGO_PKG_VERSION");
    let mut out = s.replace("rustsecjp-check 0.1.0", &format!("rustsecjp-check {v}"));
    // JSON の先頭（"tool" のすぐ後ろ）にある版番号だけを置き換えます
    let old = "\"version\": \"0.1.0\"";
    if let Some(i) = out.find(old)
        && out[..i].matches('{').count() == 1
    {
        out.replace_range(i..i + old.len(), &format!("\"version\": \"{v}\""));
    }
    out
}

#[test]
fn same_output_as_python() {
    let cases: Value =
        serde_json::from_str(&std::fs::read_to_string(golden_dir().join("cases.json")).unwrap()).unwrap();
    let mut n = 0;
    for (fname, case) in cases.as_object().unwrap() {
        let args: Vec<&str> = case["args"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
        let fake: Vec<&str> = case["fake"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
        let f = FakeFetch {
            fail_osv: fake.contains(&"fail_osv"),
            tarball: fake.contains(&"tarball").then(default_tarball),
            ..Default::default()
        };
        let (code, out) = run_cli(&args, &f, Some(&locks()));
        let want = with_current_version(&std::fs::read_to_string(golden_dir().join(fname)).unwrap());
        assert_eq!(strip_time(&out), strip_time(&want), "{fname}");
        assert_eq!(i64::from(code), case["code"].as_i64().unwrap(), "{fname}");
        n += 1;
    }
    assert!(n >= 10);
}
