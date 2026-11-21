//! data/popular-crates.txt と data/typo-allowlist.txt を作り直します（保守用。インストールはされません）。
//!
//! crates.io の API から、ダウンロード数の多い順に crate の名前を取ってきます。
//! - 上位 --count 件（既定 1000）を「よく使われる名前」として popular-crates.txt に書きます。
//! - その次の --allow-count 件（既定 4000）は、長く使われている正規の crate とみなし、
//!   よく使われる名前に似ているものを typo-allowlist.txt に書きます（誤検知を減らすため）。
//!
//! API の利用の決まりに合わせて、User-Agent を付け、1 秒に 1 回までにしています。
//!
//! 使い方: cargo run --example update-popular -- [--count 1000] [--allow-count 4000] [--data-dir DIR]

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use rustsecjp_check::http::{UreqFetch, json_request};
use rustsecjp_check::typo::TypoChecker;
use rustsecjp_check::util::{format_utc, now_unix};

const API: &str = "https://crates.io/api/v1/crates?sort=downloads&per_page=100&page=";

fn fetch_page(fetch: &UreqFetch, page: usize) -> Result<Vec<String>, String> {
    let data = json_request(fetch, "GET", &format!("{API}{page}"), None, None).map_err(|e| e.to_string())?;
    let crates = data.as_ref().and_then(|d| d.get("crates")).and_then(|c| c.as_array()).cloned().unwrap_or_default();
    Ok(crates.iter().filter_map(|c| c.get("id").and_then(|i| i.as_str()).map(str::to_string)).collect())
}

fn fetch_top(n: usize) -> Result<Vec<String>, String> {
    let fetch = UreqFetch::new();
    let mut names: Vec<String> = Vec::new();
    let mut page = 1;
    while names.len() < n {
        if page > 1 {
            std::thread::sleep(Duration::from_secs(1)); // 1 秒に 1 回まで
        }
        let got = fetch_page(&fetch, page)?;
        if got.is_empty() {
            break;
        }
        names.extend(got);
        page += 1;
    }
    let mut seen = HashSet::new();
    names.retain(|x| seen.insert(x.clone()));
    names.truncate(n);
    Ok(names)
}

fn main() -> Result<(), String> {
    let mut count = 1000usize;
    let mut allow_count = 4000usize;
    let mut data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = || args.next().ok_or(format!("{a} には値が要ります"));
        match a.as_str() {
            "--count" => count = value()?.parse().map_err(|e| format!("--count: {e}"))?,
            "--allow-count" => allow_count = value()?.parse().map_err(|e| format!("--allow-count: {e}"))?,
            "--data-dir" => data_dir = PathBuf::from(value()?),
            _ => return Err(format!("知らない引数です: {a}")),
        }
    }

    let names = fetch_top(count + allow_count)?;
    let split = count.min(names.len());
    let (popular, established) = names.split_at(split);
    let today = &format_utc(now_unix())[..10];

    let mut text = format!(
        "# crates.io でダウンロード数の多い crate（上位 {} 件、{today} 取得）\n\
         # cargo run --example update-popular で作り直せます。\n",
        popular.len()
    );
    for p in popular {
        text.push_str(p);
        text.push('\n');
    }
    std::fs::write(data_dir.join("popular-crates.txt"), text).map_err(|e| e.to_string())?;

    let checker = TypoChecker::new(popular.iter().cloned(), HashSet::new());
    let pairs: Vec<String> =
        established.iter().filter_map(|name| checker.check(name).map(|h| format!("{name} {}", h.looks_like))).collect();
    let mut text = format!(
        "# よく使われる名前に似ているが、正規と見なす crate（左）と、似ている名前（右）。\n\
         # crates.io のダウンロード数で {}〜{} 位の crate から自動で作りました（{today} 取得）。\n\
         # 手で足してもかまいません。cargo run --example update-popular で作り直すと、手で足した行は消えます。\n",
        count + 1,
        count + established.len()
    );
    for p in &pairs {
        text.push_str(p);
        text.push('\n');
    }
    std::fs::write(data_dir.join("typo-allowlist.txt"), text).map_err(|e| e.to_string())?;
    println!("popular: {} 件、allowlist: {} 件", popular.len(), pairs.len());
    Ok(())
}
