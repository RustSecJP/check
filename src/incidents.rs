//! RustSecJP/incidents の記録（キャンペーン記録と日本語の助言ページ）を読みます。
//!
//! GitHub の tarball をメモリの上で読みます。ディスクへは展開しません。

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use crate::http::{Fetch, Headers, HttpError};
use crate::util::{py_strip, toml_error_message, toml_str, toml_truthy};
use crate::versions::{self as v, EntryKind};

pub const TARBALL_URL: &str = "https://codeload.github.com/RustSecJP/incidents/tar.gz/refs/heads/main";
pub const SITE: &str = "https://rustsecjp.github.io/incidents";
pub const SKIP_STATUS: &[&str] = &["draft", "withdrawn"];
pub const MAX_MEMBER_SIZE: u64 = 1024 * 1024;

pub const LEVEL_MALICIOUS: &str = "悪性";
pub const LEVEL_REVIEW: &str = "要確認";

/// role ごとの判定。hijacked は版によって変わるので、ここには入れません。
pub fn role_level(role: &str) -> Option<&'static str> {
    match role {
        "typosquat" | "carrier" | "lure" => Some(LEVEL_MALICIOUS),
        "same-owner" | "related" => Some(LEVEL_REVIEW),
        _ => None,
    }
}

pub fn role_label(role: &str) -> Option<&'static str> {
    Some(match role {
        "hijacked" => "乗っ取られた正規の crate",
        "typosquat" => "名前を似せた偽物",
        "carrier" => "悪性のコードを運ぶ crate",
        "lure" => "悪性の crate を呼び出すおとり",
        "same-owner" => "同じ持ち主の crate（悪性のコードは見つかっていない）",
        "related" => "同じ事件で削除された crate（役割は不明）",
        _ => return None,
    })
}

/// `RSJP-C-YYYY-NNN`
pub fn is_campaign_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 15
        && s.starts_with("RSJP-C-")
        && b[7..11].iter().all(u8::is_ascii_digit)
        && b[11] == b'-'
        && b[12..].iter().all(u8::is_ascii_digit)
}

/// `RUSTSEC-YYYY-NNNN`
pub fn is_rustsec_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 17
        && s.starts_with("RUSTSEC-")
        && b[8..12].iter().all(u8::is_ascii_digit)
        && b[12] == b'-'
        && b[13..].iter().all(u8::is_ascii_digit)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub crate_name: String,
    /// 文字列の場合は 1 項目のリストにします
    pub versions: Vec<String>,
    pub role: String,
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Campaign {
    pub id: String,
    pub title: String,
    pub status: String,
    pub members: Vec<Member>,
}

impl Campaign {
    pub fn url(&self) -> String {
        format!("{SITE}/campaigns/{}/", self.id)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Incidents {
    pub campaigns: Vec<Campaign>,
    pub ja_advisories: BTreeSet<String>,
    pub source: String,
    pub errors: Vec<String>,
}

impl Incidents {
    pub fn ja_advisory_url(&self, rustsec_id: &str) -> Option<String> {
        self.ja_advisories.contains(rustsec_id).then(|| format!("{SITE}/advisories/{rustsec_id}.html"))
    }

    pub fn members_for(&self, crate_name: &str) -> Vec<(&Campaign, &Member)> {
        self.campaigns
            .iter()
            .flat_map(|c| c.members.iter().filter(|m| m.crate_name == crate_name).map(move |m| (c, m)))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct CampaignMatch<'a> {
    pub campaign: &'a Campaign,
    pub member: &'a Member,
    /// "悪性" / "要確認"
    pub level: &'static str,
    /// 判定の理由
    pub note: String,
}

/// 値を、Python で `for x in value` としたときの項目として並べます（文字列は 1 文字ずつ、表は鍵）。
fn py_iter(v: &toml::Value) -> Result<Vec<toml::Value>, String> {
    match v {
        toml::Value::Array(a) => Ok(a.clone()),
        toml::Value::String(s) => Ok(s.chars().map(|c| toml::Value::String(c.to_string())).collect()),
        toml::Value::Table(t) => Ok(t.keys().map(|k| toml::Value::String(k.clone())).collect()),
        _ => Err("繰り返せない値があります".to_string()),
    }
}

/// `data.get(key) or []` を繰り返す項目。
fn items_or_empty(t: &toml::Table, key: &str) -> Result<Vec<toml::Value>, String> {
    match t.get(key) {
        Some(v) if toml_truthy(v) => py_iter(v),
        _ => Ok(Vec::new()),
    }
}

/// `str(data.get(key) or "")`
fn str_or_empty(t: &toml::Table, key: &str) -> String {
    match t.get(key) {
        Some(v) if toml_truthy(v) => toml_str(v),
        _ => String::new(),
    }
}

/// campaign.toml を読みます。記録として使わないもの（id がおかしい、下書きなど）は `Ok(None)`。
pub fn parse_campaign(text: &str) -> Result<Option<Campaign>, String> {
    let data: toml::Table = toml::from_str(text).map_err(|e| toml_error_message(text, &e))?;
    let Some(cid) = data.get("id").and_then(toml::Value::as_str).filter(|s| is_campaign_id(s)) else {
        return Ok(None);
    };
    let status = str_or_empty(&data, "status");
    if SKIP_STATUS.contains(&status.as_str()) {
        return Ok(None);
    }
    let mut members = Vec::new();
    for m in items_or_empty(&data, "members")? {
        let Some(m) = m.as_table() else { continue };
        let Some(crate_name) = m.get("crate").and_then(toml::Value::as_str) else { continue };
        let versions = match m.get("versions") {
            Some(toml::Value::String(s)) => vec![s.clone()],
            Some(toml::Value::Array(a)) => a.iter().map(toml_str).collect(),
            _ => Vec::new(),
        };
        let ids = items_or_empty(m, "ids")?
            .iter()
            .filter(|x| matches!(x, toml::Value::String(_) | toml::Value::Integer(_) | toml::Value::Boolean(_)))
            .map(toml_str)
            .collect();
        members.push(Member { crate_name: crate_name.to_string(), versions, role: str_or_empty(m, "role"), ids });
    }
    Ok(Some(Campaign { id: cid.to_string(), title: str_or_empty(&data, "title"), status, members }))
}

fn add_campaign(inc: &mut Incidents, text: &str, label: &str) {
    match parse_campaign(text) {
        Ok(Some(c)) => inc.campaigns.push(c),
        Ok(None) => {}
        Err(e) => inc.errors.push(format!("{label}: 読めませんでした（{e}）")),
    }
}

/// 手元のコピー（`campaigns/*/campaign.toml` と `advisories/RUSTSEC-*.md`）を読みます。
pub fn load_dir(root: &Path) -> Result<Incidents, String> {
    let mut inc = Incidents { source: root.display().to_string(), ..Default::default() };
    let mut files = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root.join("campaigns")) {
        for e in rd.flatten() {
            let p = e.path().join("campaign.toml");
            if std::fs::symlink_metadata(&p).is_ok() {
                files.push((e.file_name(), p));
            }
        }
    }
    files.sort_by(|a, b| a.1.cmp(&b.1));
    for (dir_name, p) in files {
        if dir_name.to_string_lossy().starts_with('_') {
            continue;
        }
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        add_campaign(&mut inc, &text, &p.display().to_string());
    }
    if let Ok(rd) = std::fs::read_dir(root.join("advisories")) {
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".md")) else { continue };
            if stem.starts_with("RUSTSEC-") && is_rustsec_id(stem) {
                inc.ja_advisories.insert(stem.to_string());
            }
        }
    }
    inc.campaigns.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(inc)
}

/// GitHub の codeload と同じ形の tar.gz を、メモリの上で読みます。
pub fn load_tarball_bytes(data: &[u8], source: &str) -> Result<Incidents, String> {
    let mut inc = Incidents { source: source.to_string(), ..Default::default() };
    let gz = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(gz);
    let entries = archive.entries().map_err(|e| e.to_string())?;
    for entry in entries {
        let mut entry = entry.map_err(|e| e.to_string())?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let parts: Vec<&str> = name.split('/').collect();
        // <root>/campaigns/<ID>/campaign.toml
        if parts.len() == 4 && parts[1] == "campaigns" && parts[3] == "campaign.toml" {
            if parts[2].starts_with('_') || entry.size() > MAX_MEMBER_SIZE {
                continue;
            }
            let mut buf = Vec::new();
            (&mut entry).take(MAX_MEMBER_SIZE + 1).read_to_end(&mut buf).map_err(|e| e.to_string())?;
            match String::from_utf8(buf) {
                Ok(text) => add_campaign(&mut inc, &text, &name),
                Err(_) => inc.errors.push(format!("{name}: UTF-8 ではありません")),
            }
        }
        // <root>/advisories/RUSTSEC-YYYY-NNNN.md
        else if parts.len() == 3
            && parts[1] == "advisories"
            && let Some(stem) = parts[2].strip_suffix(".md")
            && is_rustsec_id(stem)
        {
            inc.ja_advisories.insert(stem.to_string());
        }
    }
    inc.campaigns.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(inc)
}

pub fn fetch_tarball(fetch: &dyn Fetch, url: &str) -> Result<Incidents, String> {
    let headers: Headers = vec![("Accept".into(), "application/x-gzip".into())];
    let (status, data) = fetch.fetch("GET", url, None, &headers).map_err(|e| e.to_string())?;
    if status != 200 {
        return Err(HttpError::Status { status, url: url.to_string(), body: data }.to_string());
    }
    load_tarball_bytes(&data, url)
}

/// この版が記録に当たるかを調べます。当たれば (level, note) を返します。
pub fn match_member(member: &Member, version: &str) -> Option<(&'static str, String)> {
    let role = member.role.as_str();
    if role != "hijacked" {
        let level = role_level(role).unwrap_or(LEVEL_REVIEW);
        let label = role_label(role).map_or_else(|| format!("役割: {role}"), str::to_string);
        return Some((level, label));
    }
    let label = role_label("hijacked").unwrap_or_default();
    let mut unknown_entries = Vec::new();
    for entry in &member.versions {
        let (kind, found) = v::classify_entry(entry);
        match kind {
            EntryKind::Exact => {
                if found.iter().any(|f| v::same_version(f, version)) {
                    return Some((LEVEL_MALICIOUS, format!("{label}で、記録にある悪性の版です")));
                }
            }
            EntryKind::Qualified => {
                if found.iter().any(|f| v::same_version(f, version)) {
                    return Some((
                        LEVEL_REVIEW,
                        format!(
                            "{label}で、記録には「{}」とあります。同じ版番号でも問題ない場合があるので、確かめてください",
                            py_strip(entry)
                        ),
                    ));
                }
            }
            EntryKind::Unknown => unknown_entries.push(py_strip(entry).to_string()),
        }
    }
    if !unknown_entries.is_empty() || member.versions.is_empty() {
        let shown =
            if unknown_entries.is_empty() { "（記載なし）".to_string() } else { unknown_entries.join("、") };
        return Some((LEVEL_REVIEW, format!("{label}ですが、悪性の版を記録から読み取れませんでした（{shown}）")));
    }
    None
}

pub fn match_package<'a>(inc: &'a Incidents, crate_name: &str, version: &str) -> Vec<CampaignMatch<'a>> {
    inc.members_for(crate_name)
        .into_iter()
        .filter_map(|(c, m)| {
            match_member(m, version).map(|(level, note)| CampaignMatch { campaign: c, member: m, level, note })
        })
        .collect()
}
