//! Message envelopes and the HTTP helpers shared by all nodes.

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::{AggregateShare, CountShare, MaskMessage, Report, VerifierMessage};
use fhe_prio3::messages::ReportId;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const CONTENT_TYPE: &str = "application/x-fhe-prio3";
pub const TOKEN_HEADER: &str = "x-fhe-prio3-token";

#[derive(Serialize, Deserialize)]
pub struct GroupTicket {
    pub group: u32,
    pub groups: u32,
}

#[derive(Serialize, Deserialize)]
pub struct MasksRequest {
    pub report_id: ReportId,
    pub masks: Vec<MaskMessage>,
}

#[derive(Serialize, Deserialize)]
pub struct VerifiersRequest {
    pub report_id: ReportId,
    pub verifiers: Vec<VerifierMessage>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum SubmitOutcome {
    Accepted,
    Rejected(String),
}

#[derive(Serialize, Deserialize)]
pub struct CountFinishRequest {
    pub shares: Vec<CountShare>,
}

#[derive(Serialize, Deserialize)]
pub struct StatusReply {
    pub index: usize,
    pub accepted: usize,
    pub closed: bool,
    pub mode: String,
}

#[derive(Serialize, Deserialize)]
pub struct ShareEnvelope {
    pub share: AggregateShare,
}

/// A protocol error carried back to the caller as HTTP 4xx/5xx with a body.
#[derive(Debug)]
pub struct HttpError(pub StatusCode, pub String);

impl axum::response::IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        (self.0, self.1).into_response()
    }
}

impl From<fhe_prio3::Error> for HttpError {
    fn from(e: fhe_prio3::Error) -> Self {
        match e {
            fhe_prio3::Error::Reject(r) => HttpError(StatusCode::UNPROCESSABLE_ENTITY, format!("rejected: {r}")),
            fhe_prio3::Error::Protocol(m) => HttpError(StatusCode::CONFLICT, m),
            other => HttpError(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        }
    }
}

impl From<anyhow::Error> for HttpError {
    fn from(e: anyhow::Error) -> Self {
        HttpError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

pub fn parse_body<T: DeserializeOwned>(body: &Bytes) -> Result<T, HttpError> {
    decode(body).map_err(|e| HttpError(StatusCode::BAD_REQUEST, format!("malformed body: {e}")))
}

pub fn reply<T: Serialize>(t: &T) -> Result<axum::response::Response, HttpError> {
    let bytes = encode(t).map_err(|e| HttpError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(axum::response::IntoResponse::into_response(([(header::CONTENT_TYPE, CONTENT_TYPE)], bytes)))
}

/// Constant-time comparison of the bearer token.
pub fn check_token(headers: &HeaderMap, expected: &str) -> Result<(), HttpError> {
    let got = headers.get(TOKEN_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
    let a = got.as_bytes();
    let b = expected.as_bytes();
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    if diff != 0 || expected.is_empty() {
        return Err(HttpError(StatusCode::UNAUTHORIZED, "bad token".into()));
    }
    Ok(())
}

/// Installs the process-wide rustls crypto provider once. rustls refuses to
/// pick one when several are compiled in (reqwest and axum-server can pull
/// different ones), and a missing provider surfaces as a panic inside the
/// server task, so every entry point calls this first.
pub fn init_crypto() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// HTTPS client trusting one CA (the deployment's), used by every node and
/// by the client library.
pub fn https_client(ca_pem: &[u8]) -> anyhow::Result<reqwest::Client> {
    init_crypto();
    let cert = reqwest::Certificate::from_pem(ca_pem)?;
    Ok(reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(cert)
        .tls_built_in_root_certs(false)
        .timeout(std::time::Duration::from_secs(3600))
        .build()?)
}

pub async fn http_post<T: Serialize, R: DeserializeOwned>(client: &reqwest::Client, url: &str, token: Option<&str>, body: &T) -> anyhow::Result<R> {
    let bytes = encode(body)?;
    let mut req = client.post(url).header(header::CONTENT_TYPE, CONTENT_TYPE).body(bytes);
    if let Some(t) = token {
        req = req.header(TOKEN_HEADER, t);
    }
    let resp = req.send().await?;
    let status = resp.status();
    let data = resp.bytes().await?;
    if !status.is_success() {
        anyhow::bail!("{url}: HTTP {status}: {}", String::from_utf8_lossy(&data));
    }
    Ok(decode(&data)?)
}

pub async fn http_get<R: DeserializeOwned>(client: &reqwest::Client, url: &str, token: Option<&str>) -> anyhow::Result<R> {
    let mut req = client.get(url);
    if let Some(t) = token {
        req = req.header(TOKEN_HEADER, t);
    }
    let resp = req.send().await?;
    let status = resp.status();
    let data = resp.bytes().await?;
    if !status.is_success() {
        anyhow::bail!("{url}: HTTP {status}: {}", String::from_utf8_lossy(&data));
    }
    Ok(decode(&data)?)
}

pub fn report_id_hex(r: &Report) -> String {
    hex::encode(r.report_id)
}
