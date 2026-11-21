//! 小さな HTTP の手伝い。
//!
//! ネットワークへの出入りは [`Fetch`] の一か所だけを通ります。
//! 試験では [`Fetch`] の偽物を渡して、ネットワークを使わないようにします。

use std::fmt;
use std::io::Read;
use std::time::Duration;

use serde_json::Value;

use crate::USER_AGENT;

/// 要求の見出し（名前, 値）。同じ名前は後のものが勝ちます。
pub type Headers = Vec<(String, String)>;

/// 64 MiB より大きな応答は読みません。
pub const MAX_BODY: u64 = 64 * 1024 * 1024;
/// 失敗の応答は 1 MiB まで読みます。
pub const MAX_ERROR_BODY: u64 = 1024 * 1024;

/// 見出しを置きます（同じ名前があれば書き換えます）。
pub fn set_header(h: &mut Headers, name: &str, value: &str) {
    if let Some(slot) = h.iter_mut().find(|(k, _)| k == name) {
        slot.1 = value.to_string();
    } else {
        h.push((name.to_string(), value.to_string()));
    }
}

pub fn header<'a>(h: &'a Headers, name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// 2xx 以外の応答。status が 0 のときは、応答が大きすぎたことを表します。
    Status { status: u16, url: String, body: Vec<u8> },
    /// 使ってはいけない URL など
    Invalid(String),
    /// 接続の失敗など
    Transport(String),
    /// 応答を JSON として読めなかった
    Decode(String),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::Status { status, url, .. } => write!(f, "HTTP {status}: {url}"),
            HttpError::Invalid(s) | HttpError::Transport(s) | HttpError::Decode(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for HttpError {}

/// (method, url, body, headers) -> (status, body)
///
/// 2xx 以外の応答も `Ok((status, body))` で返します。
pub trait Fetch {
    fn fetch(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        headers: &Headers,
    ) -> Result<(u16, Vec<u8>), HttpError>;
}

/// ureq（rustls）を使う、本物の HTTP。https だけを使います（転送先も https に限ります）。
pub struct UreqFetch {
    agent: ureq::Agent,
}

impl Default for UreqFetch {
    fn default() -> Self {
        Self::new()
    }
}

impl UreqFetch {
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .http_status_as_error(false)
            .user_agent(USER_AGENT)
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .timeout_global(Some(Duration::from_secs(300)))
            .max_redirects(5)
            .build();
        UreqFetch { agent: config.into() }
    }
}

impl Fetch for UreqFetch {
    fn fetch(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        headers: &Headers,
    ) -> Result<(u16, Vec<u8>), HttpError> {
        if !url.starts_with("https://") {
            return Err(HttpError::Invalid(format!("https 以外の URL は使いません: {url}")));
        }
        let transport = |e: ureq::Error| HttpError::Transport(format!("{url}: {e}"));
        let result = match method {
            "GET" => {
                let mut r = self.agent.get(url);
                for (k, v) in headers {
                    r = r.header(k.as_str(), v.as_str());
                }
                r.call()
            }
            "POST" | "PATCH" | "PUT" => {
                let mut r = match method {
                    "POST" => self.agent.post(url),
                    "PATCH" => self.agent.patch(url),
                    _ => self.agent.put(url),
                };
                for (k, v) in headers {
                    r = r.header(k.as_str(), v.as_str());
                }
                match body {
                    Some(b) => r.send(b),
                    None => r.send_empty(),
                }
            }
            other => return Err(HttpError::Invalid(format!("使えない method です: {other}"))),
        };
        let mut resp = result.map_err(transport)?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            match resp.body_mut().with_config().limit(MAX_BODY).read_to_vec() {
                Ok(data) => Ok((status, data)),
                Err(ureq::Error::BodyExceedsLimit(_)) => {
                    Err(HttpError::Status { status: 0, url: url.to_string(), body: b"response too large".to_vec() })
                }
                Err(e) => Err(transport(e)),
            }
        } else {
            let mut data = Vec::new();
            let reader = resp.body_mut().with_config().limit(MAX_ERROR_BODY + 1).reader();
            if reader.take(MAX_ERROR_BODY).read_to_end(&mut data).is_err() {
                data.clear();
            }
            Ok((status, data))
        }
    }
}

/// JSON の要求を送り、JSON の応答を返します。応答が空なら `None`。
pub fn json_request(
    fetch: &dyn Fetch,
    method: &str,
    url: &str,
    payload: Option<&Value>,
    headers: Option<&Headers>,
) -> Result<Option<Value>, HttpError> {
    let mut h: Headers = vec![("Accept".into(), "application/json".into())];
    for (k, v) in headers.into_iter().flatten() {
        set_header(&mut h, k, v);
    }
    let body = match payload {
        Some(p) => {
            set_header(&mut h, "Content-Type", "application/json");
            Some(serde_json::to_vec(p).map_err(|e| HttpError::Invalid(e.to_string()))?)
        }
        None => None,
    };
    let (status, data) = fetch.fetch(method, url, body.as_deref(), &h)?;
    if !(200..300).contains(&status) {
        return Err(HttpError::Status { status, url: url.to_string(), body: data });
    }
    if data.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&data).map_err(|e| HttpError::Decode(e.to_string()))?;
    serde_json::from_str(text).map(Some).map_err(|e| HttpError::Decode(e.to_string()))
}
