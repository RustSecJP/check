//! GitHub Action（action.yml）から呼ばれる入り口: `rustsecjp-check action`
//!
//! 環境変数（action.yml が渡します）:
//!   `INPUT_LOCKFILES`, `INPUT_FAIL_ON`, `INPUT_COMMENT`, `INPUT_TOKEN`, `INPUT_INCIDENTS_DIR`,
//!   `INPUT_SOURCE`（auto / workspace / api）, `INPUT_WORKING_DIRECTORY`
//!   と、GitHub Actions がふつうに用意する `GITHUB_*` の値。

use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::cli::{self, EXIT_ERROR, EXIT_FOUND, EXIT_OK};
use crate::github::{GitHub, read_event};
use crate::http::Fetch;
use crate::util::{make_temp_dir, py_strip, resolve};

/// 環境変数を読む関数（試験では偽物を渡します）。
pub type Env<'a> = dyn Fn(&str) -> Option<String> + 'a;

fn env_or(env: &Env<'_>, name: &str, default: &str) -> String {
    py_strip(&env(name).unwrap_or_else(|| default.to_string())).to_string()
}

/// GitHub Actions のログに注釈として出ます。
fn notice(out: &mut dyn Write, kind: &str, msg: &str) {
    let msg = msg.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A");
    let _ = writeln!(out, "::{kind}::{msg}");
    let _ = out.flush();
}

fn append(env: &Env<'_>, out: &mut dyn Write, path_env: &str, text: &str) {
    let Some(p) = env(path_env).filter(|p| !p.is_empty()) else { return };
    let res =
        std::fs::OpenOptions::new().create(true).append(true).open(&p).and_then(|mut f| f.write_all(text.as_bytes()));
    if let Err(e) = res {
        notice(out, "warning", &format!("{path_env} に書けませんでした: {e}"));
    }
}

/// Action として動かします。`cwd` はプロセスの今のディレクトリ（ふつうは `$GITHUB_WORKSPACE`）。
pub fn run(env: &Env<'_>, cwd: &Path, fetch: &dyn Fetch, out: &mut dyn Write) -> i32 {
    let event_name = env_or(env, "GITHUB_EVENT_NAME", "");
    let mut event = Value::Object(Default::default());
    if let Some(p) = env("GITHUB_EVENT_PATH").filter(|p| !p.is_empty()).map(PathBuf::from)
        && p.is_file()
    {
        let parsed = std::fs::read_to_string(&p)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()));
        match parsed {
            Ok(v) if v.is_object() => event = v,
            Ok(_) => {
                notice(out, "error", "イベントの JSON の形が想定と違います");
                return EXIT_ERROR;
            }
            Err(e) => {
                notice(out, "error", &format!("イベントの JSON を読めませんでした: {e}"));
                return EXIT_ERROR;
            }
        }
    }
    let ctx = read_event(&event_name, &event);
    if !ctx.run {
        notice(out, "notice", &format!("RustSecJP check を飛ばしました: {}", ctx.reason));
        append(env, out, "GITHUB_OUTPUT", "result=skipped\n");
        return EXIT_OK;
    }

    let repo = env_or(env, "GITHUB_REPOSITORY", "");
    let token = env_or(env, "INPUT_TOKEN", "");
    let gh = GitHub::new(fetch, &token);
    let fail_on =
        Some(env_or(env, "INPUT_FAIL_ON", "malicious")).filter(|s| !s.is_empty()).unwrap_or("malicious".into());
    let want_comment = matches!(env_or(env, "INPUT_COMMENT", "true").to_lowercase().as_str(), "true" | "1" | "yes");
    let source = Some(env_or(env, "INPUT_SOURCE", "auto")).filter(|s| !s.is_empty()).unwrap_or("auto".into());
    let workdir = Some(env_or(env, "INPUT_WORKING_DIRECTORY", ".")).filter(|s| !s.is_empty()).unwrap_or(".".into());
    let comment_id = ctx.comment_id.filter(|id| *id != 0);
    let pr_number = ctx.pr_number.filter(|n| *n != 0);

    if let Some(id) = comment_id {
        gh.react(&repo, id, "eyes");
    }

    let mut argv: Vec<String> = vec!["--fail-on".into(), fail_on, "--format".into(), "markdown".into()];
    let incidents_dir = env_or(env, "INPUT_INCIDENTS_DIR", "");
    if !incidents_dir.is_empty() {
        argv.push("--incidents-dir".into());
        argv.push(resolve(&cwd.join(&incidents_dir)).display().to_string());
    }

    let use_api = source == "api" || (source == "auto" && ctx.from_api && pr_number.is_some());
    let temp_base = env("RUNNER_TEMP").filter(|s| !s.is_empty()).map_or_else(std::env::temp_dir, PathBuf::from);
    let tmp = match make_temp_dir(&cwd.join(temp_base), "rustsecjp-check-") {
        Ok(t) => t,
        Err(e) => {
            notice(out, "error", &format!("一時ディレクトリを作れませんでした: {e}"));
            return EXIT_ERROR;
        }
    };
    let mut note = String::new();
    let run_dir;
    if use_api {
        let Some(number) = pr_number else {
            notice(out, "error", "source=api ですが、プルリクエストの番号が分かりません");
            return EXIT_ERROR;
        };
        let lockdir = tmp.join("lockfiles");
        match gh.fetch_pr_lockfiles(&repo, number, &lockdir) {
            Ok((files, sha)) => {
                note = format!(
                    "プルリクエスト #{number} の先頭のコミット `{}` の Cargo.lock を API で読みました。\n\n",
                    &sha[..12]
                );
                if !files.is_empty() {
                    argv.push("--lockfile".into());
                    argv.push(lockdir.display().to_string());
                }
            }
            Err(e) => {
                notice(out, "error", &e.to_string());
                if let Some(id) = comment_id {
                    gh.react(&repo, id, "-1");
                }
                return EXIT_ERROR;
            }
        }
        run_dir = lockdir;
    } else {
        run_dir = cwd.join(&workdir);
        let lockfiles = env_or(env, "INPUT_LOCKFILES", "");
        if !lockfiles.is_empty() {
            argv.push("--lockfile".into());
            argv.push(lockfiles);
        }
    }

    let report_path = tmp.join("report.md");
    argv.push("--output".into());
    argv.push(report_path.display().to_string());
    if let Err(e) = std::fs::create_dir_all(&run_dir) {
        notice(out, "error", &format!("{} を作れませんでした: {e}", run_dir.display()));
        return EXIT_ERROR;
    }
    let run_dir = resolve(&run_dir);
    let mut err_buf: Vec<u8> = Vec::new();
    let code = cli::run(&argv, &run_dir, fetch, &mut std::io::sink(), &mut err_buf);
    if !err_buf.is_empty() {
        let _ = out.write_all(&err_buf);
    }

    let mut report = match std::fs::read_to_string(&report_path) {
        Ok(r) => r,
        Err(e) => {
            notice(out, "error", &format!("報告を読めませんでした: {e}"));
            return EXIT_ERROR;
        }
    };
    if !note.is_empty() {
        let (first, rest) = report.split_once('\n').unwrap_or((report.as_str(), ""));
        report = format!("{first}\n{note}{rest}");
    }
    append(env, out, "GITHUB_STEP_SUMMARY", &report);
    let result = match code {
        EXIT_FOUND => "fail",
        EXIT_ERROR => "error",
        _ => "ok",
    };
    append(env, out, "GITHUB_OUTPUT", &format!("result={result}\nreport={}\n", report_path.display()));
    let _ = writeln!(out, "{report}");

    if want_comment
        && let Some(number) = pr_number
        && let Err(e) = gh.upsert_comment(&repo, number, &report)
    {
        notice(
            out,
            "warning",
            &format!(
                "コメントを書けませんでした（フォークからのプルリクエストでは、トークンに書き込みの権限が無いことがあります）: {e}"
            ),
        );
    }

    if let Some(id) = comment_id {
        gh.react(&repo, id, if code == EXIT_OK { "+1" } else { "-1" });
    }
    code
}
