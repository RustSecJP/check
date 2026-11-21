//! 確認の本体。Cargo.lock の一覧から、報告に載せる行を作ります。

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::incidents::{Incidents, LEVEL_MALICIOUS, LEVEL_REVIEW, match_package};
use crate::lockfile::Package;
use crate::osv::OsvClient;
use crate::typo::TypoChecker;
use crate::util::{format_utc, now_unix, quote};

pub const SECTIONS: &[&str] = &["malicious", "vulnerability", "info", "typo", "campaign"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    pub label: String,
    pub url: String,
}

impl Link {
    pub fn new(label: impl Into<String>, url: impl Into<String>) -> Self {
        Link { label: label.into(), url: url.into() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    pub section: String,
    #[serde(rename = "crate")]
    pub crate_name: String,
    pub version: String,
    pub ids: Vec<String>,
    pub summary: String,
    pub fixed: Vec<String>,
    pub links: Vec<Link>,
    pub lockfiles: Vec<String>,
    /// RustSecJP の記録では "悪性" / "要確認"
    pub level: Option<String>,
    pub severity: Option<String>,
    pub informational: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CheckResult {
    pub lockfiles: Vec<String>,
    pub checked: Vec<Package>,
    pub skipped: Vec<Package>,
    pub rows: Vec<Row>,
    pub errors: Vec<String>,
    pub sources: Vec<String>,
    pub checked_at: String,
}

impl CheckResult {
    pub fn section(&self, name: &str) -> Vec<&Row> {
        self.rows.iter().filter(|r| r.section == name).collect()
    }

    pub fn has_malicious(&self) -> bool {
        self.rows.iter().any(|r| {
            r.section == "malicious" || (r.section == "campaign" && r.level.as_deref() == Some(LEVEL_MALICIOUS))
        })
    }

    pub fn has_vulnerability(&self) -> bool {
        self.rows.iter().any(|r| r.section == "vulnerability")
    }

    pub fn needs_review(&self) -> bool {
        self.rows.iter().any(|r| r.section == "campaign" && r.level.as_deref() == Some(LEVEL_REVIEW))
    }

    /// (key, 日本語の一文)
    pub fn verdict(&self) -> (&'static str, &'static str) {
        if self.has_malicious() {
            return ("malicious", "悪性の crate が見つかりました");
        }
        if self.has_vulnerability() {
            return ("vulnerability", "脆弱性があります");
        }
        if self.needs_review() {
            return ("review", "確認が必要な crate があります");
        }
        if !self.errors.is_empty() {
            return ("error", "確認を最後まで終えられませんでした");
        }
        if self.lockfiles.is_empty() {
            return ("none", "Cargo.lock が見つかりませんでした");
        }
        if self.rows.iter().any(|r| r.section == "info" || r.section == "typo") {
            return ("notice", "大きな問題はありません（注意があります）");
        }
        ("ok", "問題なし")
    }
}

pub fn advisory_link(vid: &str) -> Link {
    // 番号は OSV のデータから来るので、URL に入れる前に符号化します（ふつうの番号は変わりません）
    let q = quote(vid, ":");
    if vid.starts_with("RUSTSEC-") {
        return Link::new(vid, format!("https://rustsec.org/advisories/{q}.html"));
    }
    if vid.starts_with("GHSA-") {
        return Link::new(vid, format!("https://github.com/advisories/{q}"));
    }
    Link::new(vid, format!("https://osv.dev/vulnerability/{q}"))
}

/// 確かめるときの材料。どれも `None` なら、その確認をしません。
#[derive(Default)]
pub struct Sources<'a> {
    pub osv: Option<&'a OsvClient<'a>>,
    pub incidents: Option<&'a Incidents>,
    pub typo: Option<&'a TypoChecker>,
}

pub fn run_check(
    packages: &[Package],
    lockfiles: &[String],
    src: &Sources<'_>,
    now: Option<i64>,
    extra_errors: Vec<String>,
) -> CheckResult {
    let now = now.unwrap_or_else(now_unix);
    let checked: Vec<Package> = packages.iter().filter(|p| p.kind() == "crates.io").cloned().collect();
    let skipped: Vec<Package> = packages.iter().filter(|p| p.kind() != "crates.io").cloned().collect();
    let mut res = CheckResult {
        lockfiles: lockfiles.to_vec(),
        checked,
        skipped,
        checked_at: format_utc(now),
        errors: extra_errors,
        ..Default::default()
    };
    let mut rows = Vec::new();

    // ---- RustSecJP の記録 ----
    let mut campaign_links: HashMap<(String, String), Vec<Link>> = HashMap::new();
    if let Some(incidents) = src.incidents {
        res.sources.push("RustSecJP/incidents".into());
        res.errors.extend(incidents.errors.iter().cloned());
        for p in &res.checked {
            for m in match_package(incidents, &p.name, &p.version) {
                let link = Link::new(m.campaign.id.clone(), m.campaign.url());
                campaign_links.entry((p.name.clone(), p.version.clone())).or_default().push(link.clone());
                let mut links = vec![link];
                for rid in &m.member.ids {
                    if let Some(ja) = incidents.ja_advisory_url(rid) {
                        links.push(Link::new(format!("{rid} 日本語版"), ja));
                    }
                }
                let mut ids = vec![m.campaign.id.clone()];
                ids.extend(m.member.ids.iter().cloned());
                rows.push(Row {
                    section: "campaign".into(),
                    crate_name: p.name.clone(),
                    version: p.version.clone(),
                    ids,
                    summary: format!("【{}】{}。{}", m.level, m.note, m.campaign.title),
                    fixed: Vec::new(),
                    links,
                    lockfiles: p.lockfiles.clone(),
                    level: Some(m.level.to_string()),
                    severity: None,
                    informational: None,
                });
            }
        }
    }

    // ---- OSV ----
    let mut flagged_malicious: HashSet<String> = HashSet::new();
    if let Some(osv) = src.osv {
        res.sources.push("OSV (api.osv.dev)".into());
        let keys: Vec<(String, String)> = res.checked.iter().map(|p| (p.name.clone(), p.version.clone())).collect();
        let outcome = (|| {
            let hits = osv.query(&keys)?;
            for p in &res.checked {
                let ids = hits.get(&(p.name.clone(), p.version.clone())).cloned().unwrap_or_default();
                if ids.is_empty() {
                    continue;
                }
                for adv in osv.advisories_for(&p.name, &p.version, &ids)? {
                    let mut links = vec![advisory_link(adv.primary_id())];
                    if let Some(incidents) = src.incidents {
                        for rid in adv.rustsec_ids() {
                            if let Some(ja) = incidents.ja_advisory_url(rid) {
                                links.push(Link::new(format!("{rid} 日本語版"), ja));
                            }
                        }
                    }
                    if adv.category == "malicious" {
                        if let Some(cl) = campaign_links.get(&(p.name.clone(), p.version.clone())) {
                            links.extend(cl.iter().cloned());
                        }
                        flagged_malicious.insert(p.name.clone());
                    }
                    rows.push(Row {
                        section: adv.category.into(),
                        crate_name: p.name.clone(),
                        version: p.version.clone(),
                        ids: adv.ids,
                        summary: adv.summary,
                        fixed: adv.fixed,
                        links,
                        lockfiles: p.lockfiles.clone(),
                        level: None,
                        severity: adv.severity,
                        informational: adv.informational,
                    });
                }
            }
            Ok::<(), crate::osv::OsvError>(())
        })();
        if let Err(e) = outcome {
            res.errors.push(e.to_string());
        }
    }

    // ---- 名前の注意 ----
    if let Some(typo) = src.typo {
        let recorded: HashSet<String> =
            rows.iter().filter(|r| r.section == "campaign").map(|r| r.crate_name.clone()).collect();
        let mut seen: HashSet<String> = HashSet::new();
        for p in &res.checked {
            if flagged_malicious.contains(&p.name) || recorded.contains(&p.name) || seen.contains(&p.name) {
                continue;
            }
            seen.insert(p.name.clone());
            if let Some(hint) = typo.check(&p.name) {
                rows.push(Row {
                    section: "typo".into(),
                    crate_name: p.name.clone(),
                    version: p.version.clone(),
                    ids: Vec::new(),
                    summary: format!("よく使われる `{}` に似ています（{}）", hint.looks_like, hint.reason),
                    fixed: Vec::new(),
                    links: vec![Link::new(
                        hint.looks_like.clone(),
                        format!("https://crates.io/crates/{}", hint.looks_like),
                    )],
                    lockfiles: p.lockfiles.clone(),
                    level: None,
                    severity: None,
                    informational: None,
                });
            }
        }
    }
    res.rows = rows;
    res
}
