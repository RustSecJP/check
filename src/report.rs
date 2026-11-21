//! 報告を Markdown（日本語）か JSON で書きます。

use serde::Serialize;

use crate::VERSION;
use crate::check::{CheckResult, Row};
use crate::lockfile::Package;
use crate::util::is_py_space;

pub const MARKER: &str = "<!-- rustsecjp-check -->";
pub const ISSUES_URL: &str = "https://github.com/RustSecJP/check/issues";

pub fn section_title(sec: &str) -> &'static str {
    match sec {
        "malicious" => "悪性",
        "vulnerability" => "脆弱性",
        "info" => "情報（保守終了・unsound）",
        "typo" => "名前の注意",
        "campaign" => "RustSecJP の記録",
        _ => "",
    }
}

pub fn section_note(sec: &str) -> &'static str {
    match sec {
        "malicious" => {
            "すぐに依存から外してください。この版をビルドした環境では、認証情報（トークンや鍵）を取り替えることをおすすめします。"
        }
        "vulnerability" => "「直った版」へ上げられるか確かめてください。",
        "info" => "すぐに危ないわけではありませんが、代わりの crate を考える手がかりになります。",
        "typo" => "名前が似ているだけで、悪性とは限りません。意図した crate かどうかを確かめてください。",
        "campaign" => {
            "RustSecJP がまとめた事件の記録に載っている crate です。「要確認」は、版だけでは判断できないものです。"
        }
        _ => "",
    }
}

fn info_label(informational: &str) -> &str {
    match informational {
        "unmaintained" => "保守終了",
        "unsound" => "unsound",
        "notice" => "お知らせ",
        other => other,
    }
}

fn verdict_icon(key: &str) -> &'static str {
    match key {
        "malicious" => ":rotating_light:",
        "vulnerability" => ":warning:",
        "review" => ":mag:",
        "notice" => ":information_source:",
        "ok" => ":white_check_mark:",
        _ => ":grey_question:", // error / none
    }
}

fn kind_label(kind: &str) -> &str {
    match kind {
        "git" => "git",
        "path" => "ローカルの path",
        "registry" => "crates.io 以外のレジストリ",
        "other" => "その他",
        other => other,
    }
}

/// 表のセルに入れる文字列を無害にします（Cargo.lock や外部のデータは信用しない）。
pub fn esc(text: &str) -> String {
    let t = text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('|', "\\|");
    // 続いた空白を 1 つの空白にし、前後の空白を除きます
    let mut collapsed = String::with_capacity(t.len());
    let mut in_space = false;
    for c in t.chars() {
        if is_py_space(c) {
            if !in_space {
                collapsed.push(' ');
            }
            in_space = true;
        } else {
            collapsed.push(c);
            in_space = false;
        }
    }
    let trimmed = collapsed.trim_matches(' ');
    // 誰かへの通知（メンション）にならないように
    trimmed.replace('@', "@\u{200b}")
}

pub fn code(text: &str) -> String {
    format!("`{}`", esc(text).replace('`', "'"))
}

fn fixed_cell(fixed: &[String]) -> String {
    match fixed.len() {
        0 => "—".into(),
        n if n > 3 => format!("{}, …, {}", esc(&fixed[0]), esc(&fixed[n - 1])),
        _ => fixed.iter().map(|f| esc(f)).collect::<Vec<_>>().join(", "),
    }
}

fn links_cell(r: &Row) -> String {
    let out: Vec<String> = r
        .links
        .iter()
        .filter(|l| l.url.starts_with("https://"))
        .map(|l| format!("[{}]({})", esc(&l.label), l.url))
        .collect();
    if out.is_empty() { "—".into() } else { out.join("<br>") }
}

fn row_line(r: &Row, multi_lockfile: bool) -> String {
    let mut crate_cell = code(&r.crate_name);
    if multi_lockfile && !r.lockfiles.is_empty() {
        let shown: Vec<String> = r.lockfiles.iter().take(3).map(|l| esc(l)).collect();
        crate_cell += &format!("<br><sub>{}{}</sub>", shown.join(", "), if r.lockfiles.len() > 3 { " …" } else { "" });
    }
    let ids =
        if r.ids.is_empty() { "—".into() } else { r.ids.iter().map(|i| esc(i)).collect::<Vec<_>>().join("<br>") };
    let mut summary = if r.summary.is_empty() { "—".to_string() } else { esc(&r.summary) };
    if r.section == "info"
        && let Some(inf) = r.informational.as_deref().filter(|s| !s.is_empty())
    {
        summary = format!("{}: {summary}", esc(info_label(inf)));
    }
    if let Some(sev) = r.severity.as_deref().filter(|s| !s.is_empty()) {
        summary = format!("深刻度 {}: {summary}", esc(sev));
    }
    format!("| {crate_cell} | {} | {ids} | {summary} | {} | {} |", esc(&r.version), fixed_cell(&r.fixed), links_cell(r))
}

pub fn render_markdown(res: &CheckResult) -> String {
    let (key, verdict) = res.verdict();
    let multi = res.lockfiles.len() > 1;
    let mut lines: Vec<String> =
        vec![MARKER.into(), format!("## {} RustSecJP check: {verdict}", verdict_icon(key)), String::new()];
    let mut summary =
        format!("Cargo.lock {} 個、crates.io の crate {} 個を確かめました。", res.lockfiles.len(), res.checked.len());
    if !res.skipped.is_empty() {
        summary += &format!("（git や path の依存 {} 個は対象外）", res.skipped.len());
    }
    lines.push(summary);
    lines.push(String::new());

    if !res.errors.is_empty() {
        lines.push("> [!WARNING]".into());
        lines.push("> 一部を確かめられませんでした。結果は不完全です。".into());
        for e in res.errors.iter().take(10) {
            lines.push(format!("> - {}", esc(e)));
        }
        lines.push(String::new());
    }

    for sec in crate::check::SECTIONS {
        let rows = res.section(sec);
        if rows.is_empty() {
            continue;
        }
        lines.push(format!("### {}（{} 件）", section_title(sec), rows.len()));
        lines.push(String::new());
        lines.push(section_note(sec).into());
        lines.push(String::new());
        lines.push("| crate | 版 | 番号 | 内容 | 直った版 | リンク |".into());
        lines.push("|---|---|---|---|---|---|".into());
        for r in rows {
            lines.push(row_line(r, multi));
        }
        lines.push(String::new());
    }

    if !res.skipped.is_empty() {
        lines.push(format!("<details><summary>確かめなかった依存（{} 個）</summary>", res.skipped.len()));
        lines.push(String::new());
        lines.push("crates.io 以外から来る依存は、crates.io の助言と比べられないので対象外です。".into());
        lines.push(String::new());
        for p in res.skipped.iter().take(200) {
            lines.push(format!("- {} {}（{}）", code(&p.name), esc(&p.version), kind_label(p.kind())));
        }
        if res.skipped.len() > 200 {
            lines.push(format!("- ほか {} 個", res.skipped.len() - 200));
        }
        lines.push(String::new());
        lines.push("</details>".into());
        lines.push(String::new());
    }

    let mut sources = res.sources.clone();
    sources.push("crates.io のダウンロード数の上位（名前の注意）".into());
    lines.push("---".into());
    lines.push(format!(
        "<sub>RustSecJP check による自動の確認です。誤りがあれば {ISSUES_URL} へ<br>データ: {} ／ 確認した時刻: {} ／ rustsecjp-check {VERSION}</sub>",
        esc(&sources.join("、")),
        esc(&res.checked_at)
    ));
    lines.join("\n") + "\n"
}

#[derive(Serialize)]
struct JsonSkipped<'a> {
    name: &'a str,
    version: &'a str,
    kind: &'a str,
    source: Option<&'a str>,
}

impl<'a> From<&'a Package> for JsonSkipped<'a> {
    fn from(p: &'a Package) -> Self {
        JsonSkipped { name: &p.name, version: &p.version, kind: p.kind(), source: p.source.as_deref() }
    }
}

#[derive(Serialize)]
struct JsonFindings<'a> {
    malicious: Vec<&'a Row>,
    vulnerability: Vec<&'a Row>,
    info: Vec<&'a Row>,
    typo: Vec<&'a Row>,
    campaign: Vec<&'a Row>,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    tool: &'static str,
    version: &'static str,
    verdict: &'static str,
    verdict_ja: &'static str,
    checked_at: &'a str,
    lockfiles: &'a [String],
    checked_count: usize,
    skipped: Vec<JsonSkipped<'a>>,
    errors: &'a [String],
    sources: &'a [String],
    findings: JsonFindings<'a>,
}

pub fn render_json(res: &CheckResult) -> String {
    let (key, verdict) = res.verdict();
    let out = JsonReport {
        tool: "rustsecjp-check",
        version: VERSION,
        verdict: key,
        verdict_ja: verdict,
        checked_at: &res.checked_at,
        lockfiles: &res.lockfiles,
        checked_count: res.checked.len(),
        skipped: res.skipped.iter().map(JsonSkipped::from).collect(),
        errors: &res.errors,
        sources: &res.sources,
        findings: JsonFindings {
            malicious: res.section("malicious"),
            vulnerability: res.section("vulnerability"),
            info: res.section("info"),
            typo: res.section("typo"),
            campaign: res.section("campaign"),
        },
    };
    serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into()) + "\n"
}
