//! RustSecJP check: `Cargo.lock` の依存を、OSV と RustSecJP の記録で確かめる小さな道具です。
//!
//! `Cargo.lock` はデータとして読むだけです。確かめるプロジェクトのビルドや、コードの実行はしません。
//!
//! モジュールの分け方は、もとの Python 版（v0.1.0）に合わせています。

#![forbid(unsafe_code)]

pub mod action;
pub mod check;
pub mod cli;
pub mod github;
pub mod glob;
pub mod http;
pub mod incidents;
pub mod lockfile;
pub mod osv;
pub mod report;
pub mod typo;
pub mod util;
pub mod versions;

/// この道具の版番号（Cargo.toml の `version`）。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// HTTP の要求に付ける User-Agent。
pub const USER_AGENT: &str =
    concat!("rustsecjp-check/", env!("CARGO_PKG_VERSION"), " (https://github.com/RustSecJP/check)");
