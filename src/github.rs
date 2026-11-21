//! GitHub の REST API を使う部分。
//!
//! - プルリクエストに、目印（[`MARKER`]）の付いたコメントを 1 つだけ作り、あとは書き換えます。
//! - 呼び出したコメントに 👀 / 👍 / 👎 の反応を付けます（失敗しても無視します）。
//! - プルリクエストの Cargo.lock を、API で「データとして」読み出します。
//!   フォークのコードを取り出したり、実行したりはしません。

use std::fmt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::http::{Fetch, Headers, HttpError, json_request};
use crate::report::MARKER;
use crate::util::{get, get_array, get_str, json_int, py_repr, quote, resolve, truthy};

pub const API: &str = "https://api.github.com";
pub const MAX_LOCKFILES: usize = 50;
pub const MAX_LOCKFILE_SIZE: i64 = 10 * 1024 * 1024;
pub const TRUSTED_ASSOCIATIONS: &[&str] = &["OWNER", "MEMBER", "COLLABORATOR"];
pub const COMMAND: &str = "@rustsecjp-bot check";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitHubError {
    Http(HttpError),
    /// おかしな値（リポジトリ名、パスなど）
    Invalid(String),
    /// そのほかの失敗
    Other(String),
}

impl fmt::Display for GitHubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitHubError::Http(e) => e.fmt(f),
            GitHubError::Invalid(s) | GitHubError::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for GitHubError {}

impl From<HttpError> for GitHubError {
    fn from(e: HttpError) -> Self {
        GitHubError::Http(e)
    }
}

/// `^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`
pub fn check_repo(repo: &str) -> Result<&str, GitHubError> {
    let ok_part = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
    match repo.split_once('/') {
        Some((a, b)) if ok_part(a) && ok_part(b) => Ok(repo),
        _ => Err(GitHubError::Invalid(format!("おかしなリポジトリ名: {}", py_repr(repo)))),
    }
}

/// `^[0-9a-f]{40}$`
pub fn is_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// rel（`/` で区切ったパス）を root の下のパスにします。外へ出るパスは断ります。
pub fn safe_join(root: &Path, rel: &str) -> Result<PathBuf, GitHubError> {
    let bad = || GitHubError::Invalid(format!("おかしなパス: {}", py_repr(rel)));
    let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() || parts.iter().any(|p| *p == "." || *p == "..") || rel.starts_with('/') {
        return Err(bad());
    }
    // Windows では \ や : もパスの区切りになるので断ります
    if cfg!(windows) && parts.iter().any(|p| p.contains(['\\', ':'])) {
        return Err(bad());
    }
    let mut out = root.to_path_buf();
    for p in &parts {
        out.push(p);
    }
    if !resolve(&out).starts_with(resolve(root)) {
        return Err(bad());
    }
    Ok(out)
}

pub struct GitHub<'a> {
    pub fetch: &'a dyn Fetch,
    pub token: String,
    pub api: String,
}

impl<'a> GitHub<'a> {
    pub fn new(fetch: &'a dyn Fetch, token: &str) -> Self {
        GitHub { fetch, token: token.to_string(), api: API.to_string() }
    }

    fn headers(&self, accept: &str) -> Headers {
        let mut h: Headers =
            vec![("Accept".into(), accept.into()), ("X-GitHub-Api-Version".into(), "2022-11-28".into())];
        if !self.token.is_empty() {
            h.push(("Authorization".into(), format!("Bearer {}", self.token)));
        }
        h
    }

    pub fn request(&self, method: &str, path: &str, payload: Option<&Value>) -> Result<Option<Value>, GitHubError> {
        if !path.starts_with('/') {
            return Err(GitHubError::Invalid(path.to_string()));
        }
        let h = self.headers("application/vnd.github+json");
        Ok(json_request(self.fetch, method, &format!("{}{path}", self.api), payload, Some(&h))?)
    }

    pub fn raw(&self, path: &str) -> Result<Vec<u8>, GitHubError> {
        let url = format!("{}{path}", self.api);
        let (status, data) = self.fetch.fetch("GET", &url, None, &self.headers("application/vnd.github.raw+json"))?;
        if status != 200 {
            return Err(HttpError::Status { status, url, body: data }.into());
        }
        Ok(data)
    }

    // ---- コメント ----

    /// トークンの持ち主。GITHUB_TOKEN では取れないので None を返します。
    pub fn viewer_login(&self) -> Option<String> {
        let me = self.request("GET", "/user", None).ok()?;
        get_str(me.as_ref(), "login").map(str::to_string)
    }

    pub fn list_comments(&self, repo: &str, number: i64) -> Result<Vec<Value>, GitHubError> {
        let mut out = Vec::new();
        for page in 1..=30 {
            let got =
                self.request("GET", &format!("/repos/{repo}/issues/{number}/comments?per_page=100&page={page}"), None)?;
            let got = match got {
                Some(Value::Array(a)) => a,
                Some(v) if truthy(&v) => {
                    return Err(GitHubError::Other("コメントの一覧の形が想定と違います".into()));
                }
                _ => Vec::new(),
            };
            let n = got.len();
            out.extend(got);
            if n < 100 {
                break;
            }
        }
        Ok(out)
    }

    pub fn find_own_comment(&self, repo: &str, number: i64) -> Result<Option<Value>, GitHubError> {
        let me = self.viewer_login().filter(|s| !s.is_empty());
        for c in self.list_comments(repo, number)? {
            let body = get_str(Some(&c), "body").unwrap_or("");
            if !body.starts_with(MARKER) {
                continue;
            }
            let user = get(Some(&c), "user");
            // 目印をまねた他人のコメントを書き換えないよう、作者も確かめます
            let mine = match &me {
                Some(me) => get_str(user, "login") == Some(me.as_str()),
                None => get_str(user, "type") == Some("Bot"),
            };
            if mine {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    pub fn upsert_comment(&self, repo: &str, number: i64, body: &str) -> Result<Option<Value>, GitHubError> {
        check_repo(repo)?;
        let body = if body.starts_with(MARKER) { body.to_string() } else { format!("{MARKER}\n{body}") };
        let payload = json!({ "body": body });
        if let Some(existing) = self.find_own_comment(repo, number)? {
            let id = get(Some(&existing), "id")
                .and_then(json_int)
                .ok_or_else(|| GitHubError::Other("コメントの番号が分かりません".into()))?;
            return self.request("PATCH", &format!("/repos/{repo}/issues/comments/{id}"), Some(&payload));
        }
        self.request("POST", &format!("/repos/{repo}/issues/{number}/comments"), Some(&payload))
    }

    /// 反応を付けます。権限が無いなどで失敗しても false を返すだけです。
    pub fn react(&self, repo: &str, comment_id: i64, content: &str) -> bool {
        check_repo(repo).is_ok()
            && self
                .request(
                    "POST",
                    &format!("/repos/{repo}/issues/comments/{comment_id}/reactions"),
                    Some(&json!({ "content": content })),
                )
                .is_ok()
    }

    // ---- Cargo.lock をデータとして読む ----

    pub fn pull_request(&self, repo: &str, number: i64) -> Result<Value, GitHubError> {
        check_repo(repo)?;
        Ok(self.request("GET", &format!("/repos/{repo}/pulls/{number}"), None)?.unwrap_or_else(|| json!({})))
    }

    pub fn lockfile_paths(&self, repo: &str, sha: &str) -> Result<Vec<String>, GitHubError> {
        let tree = self.request("GET", &format!("/repos/{repo}/git/trees/{sha}?recursive=1"), None)?;
        let mut paths = Vec::new();
        for e in get_array(tree.as_ref(), "tree") {
            let p = get_str(Some(e), "path").unwrap_or("");
            if get_str(Some(e), "type") != Some("blob") || !(p == "Cargo.lock" || p.ends_with("/Cargo.lock")) {
                continue;
            }
            if p.split('/').any(|x| x == "target") {
                continue;
            }
            let size = match get(Some(e), "size") {
                Some(v) if truthy(v) => {
                    json_int(v).ok_or_else(|| GitHubError::Invalid(format!("おかしな大きさ: {p}")))?
                }
                _ => 0,
            };
            if size > MAX_LOCKFILE_SIZE {
                continue;
            }
            paths.push(p.to_string());
        }
        paths.sort();
        paths.truncate(MAX_LOCKFILES);
        Ok(paths)
    }

    /// プルリクエストの先頭のコミットにある Cargo.lock を dest の下に書き出します。
    ///
    /// 返り値: (書き出したファイル, 読んだコミット)
    pub fn fetch_pr_lockfiles(
        &self,
        repo: &str,
        number: i64,
        dest: &Path,
    ) -> Result<(Vec<PathBuf>, String), GitHubError> {
        let pr = self.pull_request(repo, number)?;
        let head = get(Some(&pr), "head");
        let sha = get_str(head, "sha").unwrap_or("");
        if !is_sha(sha) {
            return Err(GitHubError::Other("プルリクエストの先頭のコミットが分かりませんでした".into()));
        }
        let head_repo = get_str(get(head, "repo"), "full_name").filter(|s| !s.is_empty()).unwrap_or(repo);
        let candidates: Vec<&str> = if head_repo == repo { vec![head_repo] } else { vec![head_repo, repo] };
        let mut last_err: Option<GitHubError> = None;
        for src in candidates {
            match self.fetch_from(src, sha, dest) {
                Ok(written) => return Ok((written, sha.to_string())),
                Err(e) => last_err = Some(e),
            }
        }
        let msg = last_err.map(|e| e.to_string()).unwrap_or_default();
        Err(GitHubError::Other(format!("Cargo.lock を読み出せませんでした: {msg}")))
    }

    fn fetch_from(&self, src: &str, sha: &str, dest: &Path) -> Result<Vec<PathBuf>, GitHubError> {
        check_repo(src)?;
        let io = |e: std::io::Error| GitHubError::Other(e.to_string());
        let mut written = Vec::new();
        for p in self.lockfile_paths(src, sha)? {
            let data = self.raw(&format!("/repos/{src}/contents/{}?ref={sha}", quote(&p, "/")))?;
            if data.len() as i64 > MAX_LOCKFILE_SIZE {
                continue;
            }
            let out = safe_join(dest, &p)?;
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).map_err(io)?;
            }
            std::fs::write(&out, &data).map_err(io)?;
            written.push(out);
        }
        Ok(written)
    }
}

// ---- イベントの読み取り ----

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventContext {
    pub event: String,
    pub pr_number: Option<i64>,
    pub comment_id: Option<i64>,
    pub run: bool,
    pub reason: String,
    pub from_api: bool,
}

fn int_of(v: Option<&Value>) -> Option<i64> {
    v.filter(|v| !v.is_null()).and_then(json_int)
}

/// `a or b`
fn or_value<'v>(a: Option<&'v Value>, b: Option<&'v Value>) -> Option<&'v Value> {
    match a {
        Some(v) if truthy(v) => Some(v),
        _ => b,
    }
}

/// GitHub Actions のイベントから、何をするかを決めます。
pub fn read_event(event_name: &str, event: &Value) -> EventContext {
    let ev = Some(event);
    match event_name {
        "pull_request" | "pull_request_target" => {
            let pr = get(ev, "pull_request");
            EventContext {
                event: event_name.into(),
                pr_number: int_of(or_value(get(pr, "number"), get(ev, "number"))),
                run: true,
                from_api: true,
                ..Default::default()
            }
        }
        "issue_comment" => {
            let issue = get(ev, "issue");
            let comment = get(ev, "comment");
            let ctx = EventContext {
                event: event_name.into(),
                pr_number: int_of(get(issue, "number")),
                comment_id: int_of(get(comment, "id")),
                run: true,
                from_api: true,
                ..Default::default()
            };
            let skip = |reason: String| EventContext { run: false, reason, ..ctx.clone() };
            if get(issue, "pull_request").is_none_or(Value::is_null) {
                return skip("プルリクエストへのコメントではありません".into());
            }
            match get(ev, "action") {
                None | Some(Value::Null) => {}
                Some(Value::String(s)) if s == "created" => {}
                _ => return skip("新しいコメントではありません".into()),
            }
            if !get_str(comment, "body").unwrap_or("").contains(COMMAND) {
                return skip(format!("「{COMMAND}」を含みません"));
            }
            if !get_str(comment, "author_association").is_some_and(|a| TRUSTED_ASSOCIATIONS.contains(&a)) {
                return skip("コメントした人に権限がありません（OWNER / MEMBER / COLLABORATOR のみ）".into());
            }
            if get_str(get(comment, "user"), "type") == Some("Bot") {
                return skip("bot のコメントには反応しません".into());
            }
            ctx
        }
        _ => EventContext { event: event_name.into(), run: true, ..Default::default() },
    }
}
