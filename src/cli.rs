//! コマンドラインの入り口: `rustsecjp-check [OPTIONS]`

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::VERSION;
use crate::check::{Sources, run_check};
use crate::http::Fetch;
use crate::incidents::{TARBALL_URL, fetch_tarball, load_dir};
use crate::lockfile::{find_lockfiles, merge_packages, parse_lockfile};
use crate::osv::OsvClient;
use crate::report::{render_json, render_markdown};
use crate::typo::default_checker;
use crate::util::{normalize, py_split, resolve};

pub const EXIT_OK: i32 = 0;
pub const EXIT_FOUND: i32 = 1;
pub const EXIT_ERROR: i32 = 2;

const PROG: &str = "rustsecjp-check";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Markdown,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    Malicious,
    Vulnerability,
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub lockfile: Vec<String>,
    pub incidents_dir: Option<PathBuf>,
    pub no_incidents: bool,
    pub no_osv: bool,
    pub no_typo: bool,
    pub format: Format,
    pub fail_on: FailOn,
    pub output: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            lockfile: Vec::new(),
            incidents_dir: None,
            no_incidents: false,
            no_osv: false,
            no_typo: false,
            format: Format::Markdown,
            fail_on: FailOn::Malicious,
            output: None,
        }
    }
}

/// 引数を読んだ結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Run(Options),
    Help,
    Version,
}

pub fn usage() -> String {
    format!(
        "usage: {PROG} [-h] [--version] [--lockfile PATH] [--incidents-dir DIR] [--no-incidents] [--no-osv]
                       [--no-typo] [--format {{markdown,json}}] [--fail-on {{malicious,vulnerability,never}}]
                       [--output FILE]
       {PROG} action
"
    )
}

pub fn help() -> String {
    format!(
        "{}
Cargo.lock の依存を、OSV と RustSecJP の記録で確かめます。

options:
  -h, --help            この説明を出して終わります
  --version             版番号を出して終わります
  --lockfile PATH       確かめる Cargo.lock（何度でも指定可。グロブも可）。省略すると、今のディレクトリの下をすべて探します
  --incidents-dir DIR   RustSecJP/incidents の手元のコピー（指定しないと GitHub から取ってきます）
  --no-incidents        RustSecJP の記録を使わない
  --no-osv              OSV に問い合わせない（試しに動かすとき用）
  --no-typo             名前の注意を出さない
  --format {{markdown,json}}
  --fail-on {{malicious,vulnerability,never}}
                        どの結果で終了コード 1 にするか（既定: malicious）
  --output FILE         報告をファイルに書く（省略すると標準出力）

subcommands:
  action                GitHub Action として動きます（設定は INPUT_* と GITHUB_* の環境変数で渡します）
",
        usage()
    )
}

const LONG_OPTS: &[(&str, bool)] = &[
    ("--help", false),
    ("--version", false),
    ("--lockfile", true),
    ("--incidents-dir", true),
    ("--no-incidents", false),
    ("--no-osv", false),
    ("--no-typo", false),
    ("--format", true),
    ("--fail-on", true),
    ("--output", true),
];

/// argparse と同じく、まぎれの無い前方一致（`--lock` など）も受け付けます。
fn resolve_opt(name: &str) -> Result<(&'static str, bool), String> {
    if let Some(&(n, v)) = LONG_OPTS.iter().find(|(n, _)| *n == name) {
        return Ok((n, v));
    }
    let hits: Vec<&(&str, bool)> = LONG_OPTS.iter().filter(|(n, _)| n.starts_with(name)).collect();
    match hits.as_slice() {
        [one] => Ok((one.0, one.1)),
        [] => Err(format!("unrecognized arguments: {name}")),
        many => Err(format!(
            "ambiguous option: {name} could match {}",
            many.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
        )),
    }
}

fn choice<T: Copy>(opt: &str, value: &str, choices: &[(&str, T)]) -> Result<T, String> {
    choices.iter().find(|(n, _)| *n == value).map(|(_, v)| *v).ok_or_else(|| {
        format!(
            "argument {opt}: invalid choice: '{value}' (choose from {})",
            choices.iter().map(|(n, _)| format!("'{n}'")).collect::<Vec<_>>().join(", ")
        )
    })
}

pub fn parse_args(args: &[String]) -> Result<Parsed, String> {
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        i += 1;
        if arg == "-h" {
            return Ok(Parsed::Help);
        }
        if !arg.starts_with("--") || arg == "--" {
            return Err(format!("unrecognized arguments: {arg}"));
        }
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (arg.as_str(), None),
        };
        let (name, takes_value) = resolve_opt(name)?;
        let value = if takes_value {
            match inline {
                Some(v) => v,
                None => match args.get(i) {
                    Some(v) if !(v.starts_with('-') && v.len() > 1) => {
                        i += 1;
                        v.clone()
                    }
                    _ => return Err(format!("argument {name}: expected one argument")),
                },
            }
        } else {
            if inline.is_some() {
                return Err(format!("argument {name}: ignored explicit argument '{}'", inline.unwrap_or_default()));
            }
            String::new()
        };
        match name {
            "--help" => return Ok(Parsed::Help),
            "--version" => return Ok(Parsed::Version),
            "--lockfile" => o.lockfile.push(value),
            "--incidents-dir" => o.incidents_dir = Some(PathBuf::from(value)),
            "--no-incidents" => o.no_incidents = true,
            "--no-osv" => o.no_osv = true,
            "--no-typo" => o.no_typo = true,
            "--format" => o.format = choice(name, &value, &[("markdown", Format::Markdown), ("json", Format::Json)])?,
            "--fail-on" => {
                o.fail_on = choice(
                    name,
                    &value,
                    &[
                        ("malicious", FailOn::Malicious),
                        ("vulnerability", FailOn::Vulnerability),
                        ("never", FailOn::Never),
                    ],
                )?
            }
            "--output" => o.output = Some(PathBuf::from(value)),
            _ => unreachable!("LONG_OPTS にある名前だけが来ます"),
        }
    }
    Ok(Parsed::Run(o))
}

fn rel_or_abs(cwd: &Path, item: &str) -> PathBuf {
    normalize(&cwd.join(item))
}

/// パス、グロブ（`**/Cargo.lock` など）、改行や空白で区切った一覧を受け付けます。
pub fn expand_lockfiles(specs: &[String], cwd: &Path) -> Vec<PathBuf> {
    if specs.is_empty() {
        return find_lockfiles(cwd);
    }
    let mut out = Vec::new();
    for spec in specs {
        for item in py_split(spec) {
            if crate::glob::has_magic(item) {
                // グロブは / で区切ります（Windows では \ も / として扱います）
                let pattern = if cfg!(windows) { item.replace('\\', "/") } else { item.to_string() };
                let mut matches = crate::glob::glob(&pattern, cwd);
                matches.sort();
                for m in matches {
                    let p = rel_or_abs(cwd, &m);
                    if Path::new(&m).components().any(|c| c.as_os_str() == "target") || !p.is_file() {
                        continue;
                    }
                    out.push(p);
                }
            } else {
                let p = rel_or_abs(cwd, item);
                if p.is_dir() {
                    out.extend(find_lockfiles(&p));
                } else {
                    out.push(p);
                }
            }
        }
    }
    let mut seen = HashSet::new();
    out.into_iter().filter(|p| seen.insert(resolve(p))).collect()
}

/// 報告に出す名前。今のディレクトリからの相対パス（Windows でも `/` で区切ります）。
fn label(p: &Path, cwd: &Path) -> String {
    match resolve(p).strip_prefix(resolve(cwd)) {
        Ok(rel) => {
            let s = rel.display().to_string();
            let s = if cfg!(windows) { s.replace('\\', "/") } else { s };
            if s.is_empty() { ".".into() } else { s }
        }
        Err(_) => p.display().to_string(),
    }
}

/// CLI を動かします。`cwd` は今のディレクトリとして使う場所です（プロセスの今のディレクトリは変えません）。
pub fn run(args: &[String], cwd: &Path, fetch: &dyn Fetch, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse_args(args) {
        Ok(Parsed::Run(o)) => o,
        Ok(Parsed::Help) => {
            let _ = stdout.write_all(help().as_bytes());
            return EXIT_OK;
        }
        Ok(Parsed::Version) => {
            let _ = writeln!(stdout, "{PROG} {VERSION}");
            return EXIT_OK;
        }
        Err(e) => {
            let _ = writeln!(stderr, "{}{PROG}: error: {e}", usage());
            return EXIT_ERROR;
        }
    };
    run_with(&opts, cwd, fetch, stdout, stderr)
}

pub fn run_with(opts: &Options, cwd: &Path, fetch: &dyn Fetch, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let mut errors = Vec::new();
    let paths = expand_lockfiles(&opts.lockfile, cwd);
    let mut groups = Vec::new();
    let mut labels = Vec::new();
    for p in &paths {
        let l = label(p, cwd);
        match parse_lockfile(p, Some(&l)) {
            Ok(pkgs) => {
                groups.push(pkgs);
                labels.push(l);
            }
            Err(e) => errors.push(e.to_string()),
        }
    }
    let packages = merge_packages(groups);

    let incidents = if opts.no_incidents {
        None
    } else {
        let loaded = match &opts.incidents_dir {
            Some(dir) => load_dir(&cwd.join(dir)),
            None => fetch_tarball(fetch, TARBALL_URL),
        };
        match loaded {
            Ok(inc) => Some(inc),
            Err(e) => {
                // 記録が取れなくても、ほかの確認は続けます
                errors.push(format!("RustSecJP の記録を読めませんでした: {e}"));
                None
            }
        }
    };
    let osv = (!opts.no_osv).then(|| OsvClient::new(fetch));
    let typo = (!opts.no_typo).then(default_checker);

    let sources = Sources { osv: osv.as_ref(), incidents: incidents.as_ref(), typo: typo.as_ref() };
    let res = run_check(&packages, &labels, &sources, None, errors);
    let text = match opts.format {
        Format::Json => render_json(&res),
        Format::Markdown => render_markdown(&res),
    };
    match &opts.output {
        Some(out) => {
            let out = cwd.join(out);
            if let Err(e) = std::fs::write(&out, text.as_bytes()) {
                let _ = writeln!(stderr, "{PROG}: error: {} に書けませんでした（{e}）", out.display());
                return EXIT_ERROR;
            }
        }
        None => {
            let _ = stdout.write_all(text.as_bytes());
        }
    }

    match opts.fail_on {
        FailOn::Never => EXIT_OK,
        _ if res.has_malicious() => EXIT_FOUND,
        FailOn::Vulnerability if res.has_vulnerability() => EXIT_FOUND,
        _ if !res.errors.is_empty() => EXIT_ERROR,
        _ => EXIT_OK,
    }
}
