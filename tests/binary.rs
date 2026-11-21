//! できあがったプログラムそのものを動かす試験。ネットワークを使わない場合だけを試します。

mod common;

use std::process::Command;

use common::*;

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rustsecjp-check"));
    // 試験の環境の GitHub Actions の値を引き継がないようにします
    for (k, _) in std::env::vars() {
        if k.starts_with("GITHUB_") || k.starts_with("INPUT_") || k == "RUNNER_TEMP" {
            c.env_remove(k);
        }
    }
    c
}

#[test]
fn version_and_help() {
    let out = bin().arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), format!("rustsecjp-check {}\n", env!("CARGO_PKG_VERSION")));
    let out = bin().arg("--help").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout).unwrap().contains("--fail-on"));
}

#[test]
fn bad_arguments_exit_2() {
    for args in [&["--format", "xml"][..], &["--nope"], &["--lockfile"], &["positional"], &["action", "extra"]] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(!out.stderr.is_empty(), "{args:?}");
    }
}

#[test]
fn prefix_options_like_argparse() {
    let inc = incidents_dir();
    let out = bin()
        .current_dir(locks())
        .args(["--lock", "hijacked-good/Cargo.lock", "--no-o", "--incidents-d"])
        .arg(&inc)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8(out.stdout).unwrap().contains("問題なし"));
}

#[test]
fn offline_run_on_fixtures() {
    let d = TempDir::new();
    let report = d.path().join("r.json");
    let out = bin()
        .current_dir(locks())
        .args(["--no-osv", "--format", "json", "--incidents-dir"])
        .arg(incidents_dir())
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1)); // RustSecJP の記録で悪性
    assert!(out.stdout.is_empty());
    let data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(data["verdict"], "malicious");
    assert_eq!(data["sources"], serde_json::json!(["RustSecJP/incidents"]));
}

#[test]
fn action_skips_unrelated_comment() {
    let d = TempDir::new();
    let ev = d.path().join("event.json");
    std::fs::write(&ev, r#"{"action":"created","issue":{"number":3},"comment":{"id":1,"body":"hi"}}"#).unwrap();
    let output = d.path().join("output.txt");
    let out = bin()
        .arg("action")
        .current_dir(d.path())
        .env("GITHUB_EVENT_NAME", "issue_comment")
        .env("GITHUB_EVENT_PATH", &ev)
        .env("GITHUB_OUTPUT", &output)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("::notice::RustSecJP check を飛ばしました: プルリクエストへのコメントではありません"));
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "result=skipped\n");
}
