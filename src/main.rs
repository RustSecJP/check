//! コマンドラインの入り口: `rustsecjp-check [OPTIONS]` と `rustsecjp-check action`。

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use rustsecjp_check::{action, cli, http::UreqFetch};

fn main() -> ExitCode {
    let mut args = Vec::new();
    for a in std::env::args_os().skip(1) {
        match a.into_string() {
            Ok(s) => args.push(s),
            Err(a) => {
                eprintln!("rustsecjp-check: error: UTF-8 ではない引数があります: {a:?}");
                return ExitCode::from(cli::EXIT_ERROR as u8);
            }
        }
    }
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("rustsecjp-check: error: 今のディレクトリが分かりません（{e}）");
            return ExitCode::from(cli::EXIT_ERROR as u8);
        }
    };
    let fetch = UreqFetch::new();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();

    let code = if args.first().map(String::as_str) == Some("action") {
        if args.len() > 1 {
            let _ = writeln!(err, "rustsecjp-check: error: action は引数を取りません（設定は環境変数で渡します）");
            cli::EXIT_ERROR
        } else {
            let env = |name: &str| std::env::var(name).ok();
            action::run(&env, &cwd, &fetch, &mut out)
        }
    } else {
        cli::run(&args, &cwd, &fetch, &mut out, &mut err)
    };
    let _ = out.flush();
    ExitCode::from(code.clamp(0, 255) as u8)
}
