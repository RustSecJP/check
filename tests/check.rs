//! RustSecJP check の試験。ネットワークは使いません。
//!
//! もとの Python 版の tests/test_check.py を、同じ試験用のファイルで移したものです。

mod common;

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use common::*;
use rustsecjp_check::github::{GitHub, read_event, safe_join};
use rustsecjp_check::incidents::{Member, load_dir, load_tarball_bytes, match_member, parse_campaign};
use rustsecjp_check::lockfile::{find_lockfiles, merge_packages, parse_lockfile};
use rustsecjp_check::osv::OsvClient;
use rustsecjp_check::report::{MARKER, esc, render_json, render_markdown};
use rustsecjp_check::typo::{TypoChecker, default_checker, one_edit};
use rustsecjp_check::versions::{self as v, EntryKind};
use serde_json::{Value, json};

fn strings(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

mod version_tests {
    use super::*;

    #[test]
    fn order() {
        assert_eq!(v::compare("0.2.0", "0.2.23"), Ordering::Less);
        assert_eq!(v::compare("1.0.0-alpha", "1.0.0"), Ordering::Less);
        assert_eq!(v::compare("1.0.0-alpha.2", "1.0.0-alpha.10"), Ordering::Less);
        assert_eq!(v::compare("1.0.0+build", "1.0.0"), Ordering::Equal);
    }

    #[test]
    fn classify() {
        assert_eq!(v::classify_entry("0.3.10"), (EntryKind::Exact, strings(&["0.3.10"])));
        assert_eq!(v::classify_entry("0.1.9（2026-08-20 公開のもの）"), (EntryKind::Qualified, strings(&["0.1.9"])));
        assert_eq!(
            v::classify_entry("1.3.1-dev.34027618345 のみ（2026-09-06 に公開）。ほかの版は対象外"),
            (EntryKind::Qualified, strings(&["1.3.1-dev.34027618345"]))
        );
        assert_eq!(v::classify_entry("すべて（1.0.106、1.0.107）").0, EntryKind::Unknown);
        assert_eq!(v::classify_entry("0.3.5〜0.3.9").0, EntryKind::Unknown);
        assert_eq!(v::classify_entry("不明（RustSec: 版の情報は残っていない）"), (EntryKind::Unknown, vec![]));
        // 日付は版番号として読まない
        assert_eq!(v::extract_versions("2026-08-20 に公開"), Vec::<String>::new());
        assert_eq!(
            v::extract_versions("6 版（10.1.1、11.1.1、12.1.1、20.1.0、20.10.0、20.10.10。"),
            strings(&["10.1.1", "11.1.1", "12.1.1", "20.1.0", "20.10.0", "20.10.10"])
        );
    }
}

mod lockfile_tests {
    use super::*;

    #[test]
    fn find_skips_target() {
        let found = find_lockfiles(&locks());
        assert!(!found.is_empty());
        assert!(!found.iter().any(|p| p.components().any(|c| c.as_os_str() == "target")));
        assert_eq!(found.len(), 6);
    }

    #[test]
    fn kinds() {
        let pkgs = parse_lockfile(&locks().join("path-git").join("Cargo.lock"), None).unwrap();
        let kinds: HashMap<&str, &str> = pkgs.iter().map(|p| (p.name.as_str(), p.kind())).collect();
        assert_eq!(kinds["workspace-member"], "path");
        assert_eq!(kinds["tracing-tree"], "git");
        assert_eq!(kinds["private-thing"], "registry");
    }

    #[test]
    fn merge() {
        let a = parse_lockfile(&locks().join("clean").join("Cargo.lock"), Some("a")).unwrap();
        let b = parse_lockfile(&locks().join("typosquat").join("Cargo.lock"), Some("b")).unwrap();
        let merged = merge_packages(vec![a, b]);
        let serde: Vec<_> = merged.iter().filter(|p| p.name == "serde").collect();
        assert_eq!(serde.len(), 1);
        assert_eq!(serde[0].lockfiles, strings(&["a", "b"]));
    }
}

mod incidents_tests {
    use super::*;

    #[test]
    fn load_dir_reads_campaigns_and_advisories() {
        let inc = load_dir(&incidents_dir()).unwrap();
        let ids: Vec<&str> = inc.campaigns.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["RSJP-C-2025-001", "RSJP-C-2026-004"]);
        assert_eq!(inc.ja_advisories.iter().collect::<Vec<_>>(), ["RUSTSEC-2025-0148"]);
        assert!(inc.ja_advisory_url("RUSTSEC-2025-0148").unwrap().contains("advisories/RUSTSEC-2025-0148.html"));
    }

    #[test]
    fn tarball_in_memory() {
        // 読む処理はバイト列だけを受け取り、ファイルを作りません。
        // 念のため、展開されていれば出来るはずのものが無いことも確かめます。
        let cwd = std::env::current_dir().unwrap();
        let before: HashSet<_> = std::fs::read_dir(&cwd).unwrap().map(|e| e.unwrap().file_name()).collect();
        let inc = load_tarball_bytes(&default_tarball(), "test").unwrap();
        let after: HashSet<_> = std::fs::read_dir(&cwd).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(before, after); // 何も展開しない
        for up in [cwd.join("evil.txt"), cwd.join("..").join("evil.txt"), cwd.join("../..").join("evil.txt")] {
            assert!(!up.exists(), "{}", up.display());
        }
        assert_eq!(inc.campaigns.len(), 2);
        assert_eq!(inc.ja_advisories.iter().collect::<Vec<_>>(), ["RUSTSEC-2025-0148"]);
    }

    fn member(name: &str, versions: &[&str], role: &str) -> Member {
        Member { crate_name: name.into(), versions: strings(versions), role: role.into(), ids: vec![] }
    }

    #[test]
    fn hijacked_versions() {
        let m = member("arrayref", &["0.3.10"], "hijacked");
        assert_eq!(match_member(&m, "0.3.10").unwrap().0, "悪性");
        assert!(match_member(&m, "0.3.9").is_none());
        let q = member("append-only-vec", &["0.1.9（2026-08-20 公開のもの）"], "hijacked");
        assert_eq!(match_member(&q, "0.1.9").unwrap().0, "要確認");
        assert!(match_member(&q, "0.1.10").is_none());
        let u = member("x", &["不明"], "hijacked");
        assert_eq!(match_member(&u, "1.0.0").unwrap().0, "要確認");
        assert_eq!(match_member(&member("x", &[], "hijacked"), "1.0.0").unwrap().0, "要確認");
    }

    #[test]
    fn other_roles_match_any_version() {
        for (role, level) in [
            ("typosquat", "悪性"),
            ("carrier", "悪性"),
            ("lure", "悪性"),
            ("same-owner", "要確認"),
            ("related", "要確認"),
            ("unknown-role", "要確認"),
        ] {
            let m = member("x", &["1 版"], role);
            assert_eq!(match_member(&m, "9.9.9").unwrap().0, level, "{role}");
        }
    }

    /// 手元の下書き（環境変数 RUSTSECJP_DRAFTS）の campaign.toml がすべて読めることを確かめます。
    #[test]
    fn all_drafts_parse() {
        let Some(drafts) = std::env::var_os("RUSTSECJP_DRAFTS").map(std::path::PathBuf::from).filter(|p| p.is_dir())
        else {
            eprintln!("RUSTSECJP_DRAFTS が指定されていないので飛ばします");
            return;
        };
        let mut files: Vec<_> = std::fs::read_dir(&drafts)
            .unwrap()
            .map(|e| e.unwrap().path().join("campaign.toml"))
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        let mut n = 0;
        for p in files {
            let c = parse_campaign(&std::fs::read_to_string(&p).unwrap()).unwrap();
            let c = c.unwrap_or_else(|| panic!("{}", p.display()));
            for m in &c.members {
                assert!(!m.versions.is_empty(), "{} {}", p.display(), m.crate_name);
                let mut vs = vec!["0.0.0".to_string()];
                vs.extend(m.versions.iter().flat_map(|e| v::extract_versions(e)));
                for ver in vs {
                    let _ = match_member(m, &ver); // 落ちないこと
                }
                n += 1;
            }
        }
        assert!(n > 0);
    }
}

mod osv_tests {
    use super::*;

    #[test]
    fn grouping_and_classes() {
        let res = check_dir("malicious");
        let mal = res.section("malicious");
        let crates: HashSet<&str> = mal.iter().map(|r| r.crate_name.as_str()).collect();
        assert_eq!(crates, HashSet::from(["finch-rust", "sha-rust"]));
        let finch = mal.iter().find(|r| r.crate_name == "finch-rust").unwrap();
        assert_eq!(finch.ids, strings(&["RUSTSEC-2025-0148", "GHSA-f8h5-x737-x4xr"])); // 別名は 1 行にまとまる
        assert_eq!(finch.severity.as_deref(), Some("CRITICAL"));
        let labels: Vec<&str> = finch.links.iter().map(|l| l.label.as_str()).collect();
        assert!(labels.contains(&"RUSTSEC-2025-0148 日本語版"));
        assert!(labels.contains(&"RSJP-C-2025-001"));

        let vul = res.section("vulnerability");
        assert_eq!(vul.len(), 1);
        assert_eq!(vul[0].ids[0], "RUSTSEC-2020-0071");
        assert!(vul[0].ids.contains(&"CVE-2020-26235".to_string()));
        assert_eq!(vul[0].fixed, strings(&["0.2.0", "0.2.1", "0.2.23"]));

        let info: HashSet<&str> = res.section("info").iter().filter_map(|r| r.informational.as_deref()).collect();
        assert_eq!(info, HashSet::from(["unmaintained", "unsound"]));
        assert_eq!(res.verdict().0, "malicious");
    }

    #[test]
    fn mal_and_rustsec_merge() {
        let res = check_dir("hijacked-bad");
        let mal = res.section("malicious");
        assert_eq!(mal.len(), 1);
        assert_eq!(mal[0].ids, strings(&["RUSTSEC-2026-0260", "MAL-2026-14336"]));
    }

    #[test]
    fn withdrawn_is_ignored() {
        let res = check_dir("clean");
        assert!(res.rows.is_empty());
        assert_eq!(res.verdict(), ("ok", "問題なし"));
    }

    #[test]
    fn details_cached() {
        let f = FakeFetch::default();
        let osv = OsvClient::new(&f);
        osv.vuln("RUSTSEC-2020-0071").unwrap();
        osv.vuln("RUSTSEC-2020-0071").unwrap();
        assert_eq!(f.count("https://api.osv.dev/v1/vulns/"), 1);
    }

    #[test]
    fn batches_and_pages() {
        let mut hits: Hits = (0..2500).map(|i| ((format!("c{i}"), "1.0.0".to_string()), vec![])).collect();
        hits.insert(
            ("c7".into(), "1.0.0".into()),
            strings(&["RUSTSEC-2020-0071", "GHSA-wcg3-cvx6-7396", "RUSTSEC-2024-0375"]),
        );
        let keys: Vec<(String, String)> = (0..2500).map(|i| (format!("c{i}"), "1.0.0".to_string())).collect();
        let f = FakeFetch { hits, page_size: Some(1), ..Default::default() };
        let got = OsvClient::new(&f).query(&keys).unwrap();
        assert_eq!(
            got[&("c7".to_string(), "1.0.0".to_string())],
            strings(&["RUSTSEC-2020-0071", "GHSA-wcg3-cvx6-7396", "RUSTSEC-2024-0375"])
        );
        let posts: Vec<Value> = f.calls().iter().filter(|c| c.method == "POST").map(|c| c.json()).collect();
        assert!(posts.iter().all(|p| p["queries"].as_array().unwrap().len() <= 1000));
        assert_eq!(posts.len(), 3 + 2); // 3 回に分けて送り、ページの続きを 2 回
    }

    #[test]
    fn osv_failure_is_reported() {
        let res = check_dir_with("clean", &FakeFetch { fail_osv: true, ..Default::default() }, None);
        assert!(!res.errors.is_empty());
        assert_eq!(res.verdict().0, "error");
    }

    #[test]
    fn only_crates_io_is_sent() {
        let f = FakeFetch::default();
        check_dir_with("path-git", &f, None);
        let sent: Vec<String> = f
            .calls()
            .iter()
            .filter(|c| c.method == "POST")
            .flat_map(|c| {
                c.json()["queries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|q| q["package"]["name"].as_str().unwrap().to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(sent.is_empty()); // path / git / ほかのレジストリは送らない
    }
}

mod campaign_tests {
    use super::*;

    #[test]
    fn hijacked_bad_version() {
        let res = check_dir("hijacked-bad");
        let camp: HashMap<&str, _> = res.section("campaign").into_iter().map(|r| (r.crate_name.as_str(), r)).collect();
        assert_eq!(camp["arrayref"].level.as_deref(), Some("悪性"));
        assert_eq!(camp["append-only-vec"].level.as_deref(), Some("要確認"));
        assert!(res.has_malicious());
    }

    #[test]
    fn hijacked_good_version() {
        let res = check_dir("hijacked-good");
        assert!(res.section("campaign").is_empty());
        assert_eq!(res.verdict().0, "ok");
    }

    #[test]
    fn typosquat_record_any_version() {
        let res = check_dir("malicious");
        let camp: HashMap<&str, _> = res.section("campaign").into_iter().map(|r| (r.crate_name.as_str(), r)).collect();
        assert_eq!(camp["finch-rust"].level.as_deref(), Some("悪性"));
        assert_eq!(camp["sha-rust"].level.as_deref(), Some("悪性"));
        assert!(camp["finch-rust"].links.iter().any(|l| l.label.contains("日本語版")));
    }
}

mod typo_tests {
    use super::*;

    #[test]
    fn one_edit_kinds() {
        assert_eq!(one_edit("reqwets", "reqwest"), Some("隣り合う 2 文字の入れ替え"));
        assert_eq!(one_edit("serde", "serd"), Some("1 文字の追加または削除"));
        assert_eq!(one_edit("sha1", "sha2"), None);
        assert_eq!(one_edit("objc2", "objc"), None);
        assert_eq!(one_edit("tokio", "tokyo2"), None);
    }

    #[test]
    fn rules() {
        let t = TypoChecker::new(["reqwest", "tokio", "serde", "lazy_static", "serde_json", "finch"], HashSet::new());
        let looks = |n: &str| t.check(n).map(|h| h.looks_like);
        assert_eq!(t.check("reqwest"), None);
        assert_eq!(t.check("serde"), None);
        assert_eq!(looks("reqwets").as_deref(), Some("reqwest"));
        assert_eq!(looks("tokio-rs").as_deref(), Some("tokio"));
        assert_eq!(looks("finch-rust").as_deref(), Some("finch"));
        assert_eq!(looks("lazy-static").as_deref(), Some("lazy_static"));
        assert_eq!(looks("lazystatic").as_deref(), Some("lazy_static"));
        assert_eq!(looks("tokyo").as_deref(), Some("tokio")); // 5 文字なら 1 文字違いを見る
        assert_eq!(t.check("serd"), None); // 4 文字以下の名前は 1 文字違いを見ない
        assert_eq!(t.check("rand"), None);
    }

    #[test]
    fn allowlist() {
        let t = TypoChecker::new(["dotenvy"], HashSet::from([("dotenv".to_string(), "dotenvy".to_string())]));
        assert_eq!(t.check("dotenv"), None);
    }

    #[test]
    fn fixture() {
        let res = check_dir("typosquat");
        let typo: HashSet<&str> = res.section("typo").iter().map(|r| r.crate_name.as_str()).collect();
        assert_eq!(typo, HashSet::from(["reqwets", "tokio-rs"]));
        assert_eq!(res.verdict().0, "notice");
        let md = render_markdown(&res);
        assert!(md.contains("名前が似ているだけで、悪性とは限りません"));
    }

    #[test]
    fn bundled_list() {
        let t = default_checker();
        assert!(t.popular.len() >= 900);
        for name in ["serde", "tokio", "syn", "serde_json", "rand_core", "windows-sys"] {
            assert_eq!(t.check(name), None, "{name}");
        }
    }
}

mod report_tests {
    use super::*;

    #[test]
    fn markdown_shape() {
        let md = render_markdown(&check_dir("malicious"));
        assert!(md.starts_with(&format!("{MARKER}\n")));
        assert!(md.lines().nth(1).unwrap().contains("悪性の crate が見つかりました"));
        for title in ["### 悪性", "### 脆弱性", "### 情報（保守終了・unsound）", "### RustSecJP の記録"]
        {
            assert!(md.contains(title), "{title}");
        }
        assert!(md.contains("| crate | 版 | 番号 | 内容 | 直った版 | リンク |"));
        assert!(md.contains("https://rustsecjp.github.io/incidents/campaigns/RSJP-C-2025-001/"));
        assert!(md.contains("https://rustsecjp.github.io/incidents/advisories/RUSTSEC-2025-0148.html"));
        assert!(md.contains(
            "RustSecJP check による自動の確認です。誤りがあれば https://github.com/RustSecJP/check/issues へ"
        ));
        assert!(md.contains("OSV (api.osv.dev)"));
    }

    #[test]
    fn skipped_listed() {
        let md = render_markdown(&check_dir("path-git"));
        assert!(md.contains("確かめなかった依存（4 個）"));
        assert!(md.contains("`tracing-tree` 0.3.0（git）"));
        assert!(md.contains("crates.io 以外のレジストリ"));
    }

    #[test]
    fn escape() {
        assert_eq!(esc("a|b<script>@user"), "a\\|b&lt;script&gt;@\u{200b}user");
    }

    #[test]
    fn json_output() {
        let data: Value = serde_json::from_str(&render_json(&check_dir("hijacked-bad"))).unwrap();
        assert_eq!(data["verdict"], "malicious");
        assert_eq!(data["findings"]["campaign"].as_array().unwrap().len(), 2);
    }
}

mod cli_tests {
    use super::*;

    #[test]
    fn default_search_and_exit_codes() {
        let inc = incidents_dir().display().to_string();
        let (code, out) = run_cli(&["--incidents-dir", &inc], &FakeFetch::default(), Some(&locks()));
        assert_eq!(code, 1);
        assert!(out.contains("Cargo.lock 6 個"));
        assert!(!out.contains("target/debug"));
        let (code, _) =
            run_cli(&["--incidents-dir", &inc, "--fail-on", "never"], &FakeFetch::default(), Some(&locks()));
        assert_eq!(code, 0);
    }

    #[test]
    fn fail_on_vulnerability() {
        let lock = locks().join("malicious").join("Cargo.lock").display().to_string();
        let hits: Hits = [hit("time", "0.1.45", &["RUSTSEC-2020-0071"])].into_iter().collect();
        let base = ["--lockfile", lock.as_str(), "--no-incidents"];
        let f = FakeFetch { hits: hits.clone(), ..Default::default() };
        assert_eq!(run_cli(&base, &f, None).0, 0);
        let f = FakeFetch { hits, ..Default::default() };
        let mut args = base.to_vec();
        args.extend(["--fail-on", "vulnerability"]);
        assert_eq!(run_cli(&args, &f, None).0, 1);
    }

    #[test]
    fn glob_and_json() {
        let inc = incidents_dir().display().to_string();
        let (_, out) = run_cli(
            &["--lockfile", "hijacked-*/Cargo.lock", "--incidents-dir", &inc, "--format", "json", "--fail-on", "never"],
            &FakeFetch::default(),
            Some(&locks()),
        );
        let data: Value = serde_json::from_str(&out).unwrap();
        let mut lockfiles: Vec<&str> =
            data["lockfiles"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        lockfiles.sort();
        assert_eq!(lockfiles, ["hijacked-bad/Cargo.lock", "hijacked-good/Cargo.lock"]);
    }

    #[test]
    fn tarball_download() {
        let f = FakeFetch { tarball: Some(default_tarball()), ..Default::default() };
        let lock = locks().join("hijacked-bad").join("Cargo.lock").display().to_string();
        let (code, out) = run_cli(&["--lockfile", &lock], &f, None);
        assert_eq!(code, 1);
        assert!(out.contains("RSJP-C-2026-004"));
        assert_eq!(f.count("https://codeload.github.com/"), 1);
    }

    #[test]
    fn error_exit() {
        let lock = locks().join("clean").join("Cargo.lock").display().to_string();
        let f = FakeFetch { fail_osv: true, ..Default::default() };
        let (code, out) = run_cli(&["--lockfile", &lock, "--no-incidents"], &f, None);
        assert_eq!(code, 2);
        assert!(out.contains("確認を最後まで終えられませんでした"));
    }

    #[test]
    fn no_lockfile() {
        let d = TempDir::new();
        let (code, out) = run_cli(&["--no-incidents"], &FakeFetch::default(), Some(d.path()));
        assert_eq!(code, 0);
        assert!(out.contains("Cargo.lock が見つかりませんでした"));
    }
}

mod github_tests {
    use super::*;

    const REPO: &str = "RustSecJP/example";

    #[test]
    fn event_rules() {
        let base = json!({"issue": {"number": 5, "pull_request": {}}, "action": "created",
            "comment": {"id": 9, "body": "@rustsecjp-bot check", "author_association": "MEMBER", "user": {"type": "User"}}});
        assert!(read_event("issue_comment", &base).run);
        let with_comment = |k: &str, val: &str| {
            let mut e = base.clone();
            e["comment"][k] = json!(val);
            e
        };
        let mut not_pr = base.clone();
        not_pr["issue"] = json!({"number": 5}); // プルリクエストではない issue
        let mut edited = base.clone();
        edited["action"] = json!("edited");
        for change in [
            with_comment("author_association", "CONTRIBUTOR"),
            with_comment("author_association", "NONE"),
            with_comment("body", "looks good"),
            not_pr,
            edited,
        ] {
            assert!(!read_event("issue_comment", &change).run, "{change}");
        }
        let pr = read_event("pull_request", &json!({"pull_request": {"number": 7}}));
        assert_eq!((pr.run, pr.pr_number, pr.from_api), (true, Some(7), true));
    }

    #[test]
    fn upsert_creates_then_updates() {
        let mut gh = GitHubMap::new();
        gh_json(&mut gh, "GET", "/user", 200, json!({"login": "rustsecjp-bot"}));
        gh_json(
            &mut gh,
            "GET",
            &format!("/repos/{REPO}/issues/3/comments?per_page=100&page=1"),
            200,
            json!([{"id": 1, "body": format!("{MARKER}\nfake"), "user": {"login": "someone", "type": "User"}}]),
        );
        gh_json(&mut gh, "POST", &format!("/repos/{REPO}/issues/3/comments"), 201, json!({"id": 2}));
        let f = FakeFetch { github: gh.clone(), ..Default::default() };
        GitHub::new(&f, "t").upsert_comment(REPO, 3, &format!("{MARKER}\nhello")).unwrap();
        assert!(
            f.calls().iter().any(
                |c| c.method == "POST" && c.url == format!("https://api.github.com/repos/{REPO}/issues/3/comments")
            )
        );

        gh_json(
            &mut gh,
            "GET",
            &format!("/repos/{REPO}/issues/3/comments?per_page=100&page=1"),
            200,
            json!([
                {"id": 1, "body": format!("{MARKER}\nfake"), "user": {"login": "someone", "type": "User"}},
                {"id": 2, "body": format!("{MARKER}\nold"), "user": {"login": "rustsecjp-bot", "type": "User"}},
            ]),
        );
        gh_json(&mut gh, "PATCH", &format!("/repos/{REPO}/issues/comments/2"), 200, json!({"id": 2}));
        let f = FakeFetch { github: gh, ..Default::default() };
        GitHub::new(&f, "t").upsert_comment(REPO, 3, &format!("{MARKER}\nnew")).unwrap();
        let patches: Vec<Call> = f.calls().into_iter().filter(|c| c.method == "PATCH").collect();
        assert_eq!(patches.len(), 1);
        assert!(patches[0].url.ends_with("/issues/comments/2"));
        assert_eq!(rustsecjp_check::http::header(&patches[0].headers, "Authorization"), Some("Bearer t"));
    }

    #[test]
    fn github_token_updates_bot_comment() {
        let mut gh = GitHubMap::new();
        gh_json(&mut gh, "GET", "/user", 403, json!({"message": "Resource not accessible by integration"}));
        gh_json(
            &mut gh,
            "GET",
            &format!("/repos/{REPO}/issues/3/comments?per_page=100&page=1"),
            200,
            json!([{"id": 4, "body": format!("{MARKER}\nold"), "user": {"login": "github-actions[bot]", "type": "Bot"}}]),
        );
        gh_json(&mut gh, "PATCH", &format!("/repos/{REPO}/issues/comments/4"), 200, json!({"id": 4}));
        let f = FakeFetch { github: gh, ..Default::default() };
        GitHub::new(&f, "t").upsert_comment(REPO, 3, "body").unwrap();
        let patch = f.calls().into_iter().find(|c| c.method == "PATCH").unwrap();
        assert_eq!(patch.json()["body"], format!("{MARKER}\nbody"));
    }

    #[test]
    fn react_ignores_failure() {
        let f = FakeFetch::default();
        assert!(!GitHub::new(&f, "t").react(REPO, 1, "eyes"));
    }

    #[test]
    fn fetch_pr_lockfiles_from_fork() {
        let sha = "a".repeat(40);
        let lock = std::fs::read(locks().join("hijacked-bad").join("Cargo.lock")).unwrap();
        let mut gh = GitHubMap::new();
        gh_json(
            &mut gh,
            "GET",
            &format!("/repos/{REPO}/pulls/8"),
            200,
            json!({"head": {"sha": sha, "repo": {"full_name": "fork/example"}}}),
        );
        gh_json(
            &mut gh,
            "GET",
            &format!("/repos/fork/example/git/trees/{sha}?recursive=1"),
            200,
            json!({"tree": [
                {"path": "Cargo.lock", "type": "blob", "size": 100},
                {"path": "sub/crate/Cargo.lock", "type": "blob", "size": 100},
                {"path": "target/Cargo.lock", "type": "blob", "size": 100},
                {"path": "build.rs", "type": "blob", "size": 100},
            ]}),
        );
        gh_bytes(&mut gh, "GET", &format!("/repos/fork/example/contents/Cargo.lock?ref={sha}"), 200, lock.clone());
        gh_bytes(&mut gh, "GET", &format!("/repos/fork/example/contents/sub/crate/Cargo.lock?ref={sha}"), 200, lock);
        let f = FakeFetch { github: gh, ..Default::default() };
        let d = TempDir::new();
        let (files, got_sha) = GitHub::new(&f, "t").fetch_pr_lockfiles(REPO, 8, d.path()).unwrap();
        let mut rel: Vec<String> =
            files.iter().map(|p| p.strip_prefix(d.path()).unwrap().to_str().unwrap().replace('\\', "/")).collect();
        rel.sort();
        assert_eq!(rel, ["Cargo.lock", "sub/crate/Cargo.lock"]);
        assert_eq!(got_sha, sha);
        assert!(!f.calls().iter().any(|c| c.url.contains("build.rs")));
    }

    #[test]
    fn safe_join_rules() {
        let root = std::path::Path::new("/tmp/x");
        assert_eq!(safe_join(root, "a/Cargo.lock").unwrap(), root.join("a").join("Cargo.lock"));
        for bad in ["../Cargo.lock", "/etc/Cargo.lock", "a/../../Cargo.lock", ""] {
            assert!(safe_join(root, bad).is_err(), "{bad}");
        }
    }
}

mod action_tests {
    use super::*;

    #[test]
    fn issue_comment_flow() {
        let repo = "RustSecJP/example";
        let sha = "b".repeat(40);
        let lock = std::fs::read(locks().join("hijacked-bad").join("Cargo.lock")).unwrap();
        let mut gh = GitHubMap::new();
        gh_json(&mut gh, "POST", &format!("/repos/{repo}/issues/comments/99/reactions"), 201, json!({}));
        gh_json(
            &mut gh,
            "GET",
            &format!("/repos/{repo}/pulls/12"),
            200,
            json!({"head": {"sha": sha, "repo": {"full_name": repo}}}),
        );
        gh_json(
            &mut gh,
            "GET",
            &format!("/repos/{repo}/git/trees/{sha}?recursive=1"),
            200,
            json!({"tree": [{"path": "Cargo.lock", "type": "blob", "size": 9}]}),
        );
        gh_bytes(&mut gh, "GET", &format!("/repos/{repo}/contents/Cargo.lock?ref={sha}"), 200, lock);
        gh_json(&mut gh, "GET", "/user", 200, json!({"login": "rustsecjp-bot"}));
        gh_json(&mut gh, "GET", &format!("/repos/{repo}/issues/12/comments?per_page=100&page=1"), 200, json!([]));
        gh_json(&mut gh, "POST", &format!("/repos/{repo}/issues/12/comments"), 201, json!({"id": 1}));
        let f = FakeFetch { github: gh, ..Default::default() };

        let d = TempDir::new();
        let ev = d.path().join("event.json");
        std::fs::write(
            &ev,
            json!({
                "action": "created",
                "issue": {"number": 12, "pull_request": {"url": "x"}},
                "comment": {"id": 99, "body": "@rustsecjp-bot check", "author_association": "OWNER", "user": {"type": "User"}},
            })
            .to_string(),
        )
        .unwrap();
        let summary = d.path().join("summary.md");
        let env: HashMap<&str, String> = HashMap::from([
            ("GITHUB_EVENT_NAME", "issue_comment".to_string()),
            ("GITHUB_EVENT_PATH", ev.display().to_string()),
            ("GITHUB_REPOSITORY", repo.to_string()),
            ("GITHUB_STEP_SUMMARY", summary.display().to_string()),
            ("RUNNER_TEMP", d.path().display().to_string()),
            ("INPUT_TOKEN", "t".to_string()),
            ("INPUT_INCIDENTS_DIR", incidents_dir().display().to_string()),
            ("INPUT_FAIL_ON", "malicious".to_string()),
        ]);
        let getenv = |k: &str| env.get(k).cloned();
        let mut out = Vec::new();
        let code = rustsecjp_check::action::run(&getenv, d.path(), &f, &mut out);
        assert_eq!(code, 1);
        assert!(std::fs::read_to_string(&summary).unwrap().contains("悪性の crate が見つかりました"));

        let calls = f.calls();
        let reactions: Vec<String> = calls
            .iter()
            .filter(|c| c.url.ends_with("/reactions"))
            .map(|c| c.json()["content"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(reactions, ["eyes", "-1"]);
        let posted: Vec<String> = calls
            .iter()
            .filter(|c| c.method == "POST" && c.url.ends_with("/issues/12/comments"))
            .map(|c| c.json()["body"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(posted.len(), 1);
        assert!(posted[0].starts_with(MARKER));
        assert!(posted[0].contains(&sha[..12]));
    }
}
