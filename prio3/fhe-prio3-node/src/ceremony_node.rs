//! The distributed key ceremony between aggregator machines over HTTPS
//! (`fhe_prio3::ceremony`). Each aggregator runs `fhe-prio3-node ceremony`
//! on its own machine: a small HTTPS server that serves this party's signed
//! messages and, once released, its blobs; and a client that polls the
//! other parties for theirs. Nothing is pushed, so a party can only read
//! what another has chosen to publish, and a blob is readable only after
//! its owner published the reveal round, which it does only after holding
//! every other party's commitment.
//!
//! Messages are authenticated by the ceremony's own Ed25519 signatures
//! (pinned identity keys); TLS with the deployment's CA and the shared
//! token keep outsiders out of the exchange. Staged blobs (the key
//! contributions, gigabytes in silent mode) are kept in files under the
//! work directory, not in memory. The secret share never leaves the
//! process: it is returned to the caller, which seals it.

use crate::wire::{ServerHandle, TOKEN_HEADER, check_token, https_client, init_crypto};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use fhe_prio3::TaskConfig;
use fhe_prio3::attest::AggregatorIdentity;
use fhe_prio3::ceremony::{self, CeremonyOutput, Message, Round, Transport};
use fhe_prio3::messages::{decode, encode};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Header naming the requesting party, so a party knows when every peer has
/// read its final message and it may stop serving.
pub const PARTY_HEADER: &str = "x-fhe-prio3-party";

/// Largest message body accepted (a signed round message is a few KiB).
const MAX_MESSAGE_BYTES: usize = 4 << 20;
/// Largest blob accepted: a round-2 eval-mult contribution at ring
/// dimension 131072 with the widest key-switching basis is below this.
const MAX_BLOB_BYTES: usize = 1 << 30;

pub struct CeremonyNodeConfig {
    pub task: TaskConfig,
    pub index: usize,
    pub identity: AggregatorIdentity,
    /// Identity keys of every aggregator, by index.
    pub pinned: Vec<[u8; 32]>,
    pub session: [u8; 32],
    pub listen: SocketAddr,
    /// Base URLs of every aggregator's ceremony server, by index.
    pub peers: Vec<String>,
    pub token: String,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub ca_pem: Vec<u8>,
    /// Holds the staged blobs while the ceremony runs.
    pub work_dir: PathBuf,
    /// Longest wait for any single peer message or blob.
    pub timeout: Duration,
}

#[derive(Default)]
struct Served {
    messages: HashMap<u8, Vec<u8>>,
    staged: HashMap<(u8, String), PathBuf>,
    released: HashSet<u8>,
    aborted: Option<String>,
    confirm_read_by: HashSet<u32>,
}

struct ServerState {
    session_hex: String,
    token: String,
    served: Mutex<Served>,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 32 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn requester(headers: &HeaderMap) -> Option<u32> {
    headers.get(PARTY_HEADER)?.to_str().ok()?.parse().ok()
}

async fn get_message(State(st): State<Arc<ServerState>>, Path((session, round)): Path<(String, u8)>, headers: HeaderMap) -> Response {
    if let Err(e) = check_token(&headers, &st.token) {
        return e.into_response();
    }
    if session != st.session_hex {
        return (StatusCode::NOT_FOUND, "no such session").into_response();
    }
    let mut s = st.served.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(why) = &s.aborted {
        return (StatusCode::GONE, why.clone()).into_response();
    }
    match s.messages.get(&round).cloned() {
        Some(bytes) => {
            if round == Round::Confirm.number()
                && let Some(p) = requester(&headers)
            {
                s.confirm_read_by.insert(p);
            }
            bytes.into_response()
        }
        None => (StatusCode::NOT_FOUND, "not yet published").into_response(),
    }
}

async fn get_blob(State(st): State<Arc<ServerState>>, Path((session, round, name)): Path<(String, u8, String)>, headers: HeaderMap) -> Response {
    if let Err(e) = check_token(&headers, &st.token) {
        return e.into_response();
    }
    if session != st.session_hex || !valid_name(&name) {
        return (StatusCode::NOT_FOUND, "no such blob").into_response();
    }
    let path = {
        let s = st.served.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(why) = &s.aborted {
            return (StatusCode::GONE, why.clone()).into_response();
        }
        if !s.released.contains(&round) {
            return (StatusCode::NOT_FOUND, "not yet released").into_response();
        }
        match s.staged.get(&(round, name)) {
            Some(p) => p.clone(),
            None => return (StatusCode::NOT_FOUND, "no such blob").into_response(),
        }
    };
    match tokio::fs::read(&path).await {
        Ok(b) => b.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// [`Transport`] over the server above and the peers' servers.
struct HttpTransport {
    st: Arc<ServerState>,
    index: usize,
    peers: Vec<String>,
    http: reqwest::Client,
    rt: tokio::runtime::Handle,
    work_dir: PathBuf,
    timeout: Duration,
}

impl HttpTransport {
    /// Polls `url` until it answers 200 (returning at most `limit` bytes),
    /// fails on 410 (the peer aborted) or at the deadline. Connection errors
    /// and 404 (not yet published) are retried: peers start at different times.
    fn poll(&self, url: &str, what: &str, limit: usize) -> fhe_prio3::Result<Vec<u8>> {
        enum Outcome {
            Body(Vec<u8>),
            NotYet,
            Stop(String),
        }
        let deadline = Instant::now() + self.timeout;
        let mut wait = Duration::from_millis(100);
        loop {
            let r: Result<Outcome, reqwest::Error> = self.rt.block_on(async {
                let mut resp = self
                    .http
                    .get(url)
                    .header(TOKEN_HEADER, &self.st.token)
                    .header(PARTY_HEADER, self.index.to_string())
                    .send()
                    .await?;
                Ok(match resp.status() {
                    StatusCode::OK => {
                        if resp.content_length().is_some_and(|n| n > limit as u64) {
                            return Ok(Outcome::Stop(format!("exceeds {limit} bytes")));
                        }
                        let mut body = Vec::new();
                        while let Some(chunk) = resp.chunk().await? {
                            body.extend_from_slice(&chunk);
                            if body.len() > limit {
                                return Ok(Outcome::Stop(format!("exceeds {limit} bytes")));
                            }
                        }
                        Outcome::Body(body)
                    }
                    StatusCode::NOT_FOUND => Outcome::NotYet,
                    StatusCode::GONE => Outcome::Stop(format!("the party aborted: {}", resp.text().await.unwrap_or_default())),
                    s => Outcome::Stop(format!("HTTP {s}: {}", resp.text().await.unwrap_or_default())),
                })
            });
            match r {
                Ok(Outcome::Body(b)) => return Ok(b),
                Ok(Outcome::Stop(why)) => return Err(fhe_prio3::Error::Protocol(format!("ceremony: {what}: {why}"))),
                // not yet published, or the peer's server is not up yet
                Ok(Outcome::NotYet) | Err(_) => {}
            }
            if Instant::now() >= deadline {
                return Err(fhe_prio3::Error::Protocol(format!("ceremony: timed out waiting for {what}")));
            }
            std::thread::sleep(wait);
            wait = (wait * 2).min(Duration::from_secs(2));
        }
    }
}

impl Transport for HttpTransport {
    fn stage_blob(&mut self, round: Round, name: &str, bytes: Vec<u8>) -> fhe_prio3::Result<()> {
        if !valid_name(name) {
            return Err(fhe_prio3::Error::Protocol(format!("ceremony: invalid blob name {name}")));
        }
        let path = self.work_dir.join(format!("r{}-{name}.blob", round.number()));
        std::fs::write(&path, bytes).map_err(|e| fhe_prio3::Error::Protocol(format!("ceremony: staging {name}: {e}")))?;
        self.st
            .served
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .staged
            .insert((round.number(), name.to_string()), path);
        Ok(())
    }
    fn publish(&mut self, msg: &Message) -> fhe_prio3::Result<()> {
        let bytes = encode(msg)?;
        let mut s = self.st.served.lock().unwrap_or_else(|e| e.into_inner());
        s.messages.insert(msg.round.number(), bytes);
        s.released.insert(msg.round.number());
        Ok(())
    }
    fn fetch(&mut self, round: Round, from: usize) -> fhe_prio3::Result<Message> {
        let url = format!("{}/v1/ceremony/{}/{}/message", self.peers[from], self.st.session_hex, round.number());
        let bytes = self.poll(&url, &format!("party {from}'s round {round:?} message"), MAX_MESSAGE_BYTES)?;
        decode(&bytes)
    }
    fn fetch_blob(&mut self, round: Round, from: usize, name: &str) -> fhe_prio3::Result<Vec<u8>> {
        let url = format!("{}/v1/ceremony/{}/{}/blob/{name}", self.peers[from], self.st.session_hex, round.number());
        self.poll(&url, &format!("party {from}'s {name}"), MAX_BLOB_BYTES)
    }
    fn abort(&mut self, reason: &str) {
        self.st
            .served
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .aborted
            .get_or_insert(reason.to_string());
    }
}

/// Runs this party's side of the ceremony: serves, exchanges, and after
/// success keeps serving until every peer has read the final message (or
/// the timeout); after failure serves the abort for a short while so the
/// peers stop too.
pub async fn run(cfg: CeremonyNodeConfig) -> anyhow::Result<CeremonyOutput> {
    init_crypto();
    let n = cfg.task.num_aggregators;
    anyhow::ensure!(
        cfg.peers.len() == n && cfg.pinned.len() == n && cfg.index < n,
        "need one peer URL and one pinned key per aggregator, and index < {n}"
    );
    std::fs::create_dir_all(&cfg.work_dir)?;
    let st = Arc::new(ServerState {
        session_hex: hex::encode(cfg.session),
        token: cfg.token.clone(),
        served: Mutex::new(Served::default()),
    });
    let app = Router::new()
        .route("/v1/ceremony/:session/:round/message", get(get_message))
        .route("/v1/ceremony/:session/:round/blob/:name", get(get_blob))
        .with_state(st.clone());
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cfg.tls_cert, &cfg.tls_key).await?;
    let handle = ServerHandle::new();
    let server = tokio::spawn(axum_server::bind_rustls(cfg.listen, tls).handle(handle.clone()).serve(app.into_make_service()));

    let mut transport = HttpTransport {
        st: st.clone(),
        index: cfg.index,
        peers: cfg.peers.clone(),
        http: https_client(&cfg.ca_pem)?,
        rt: tokio::runtime::Handle::current(),
        work_dir: cfg.work_dir.clone(),
        timeout: cfg.timeout,
    };
    let (task, index, pinned, session) = (cfg.task.clone(), cfg.index, cfg.pinned.clone(), cfg.session);
    let identity = cfg.identity;
    let result = tokio::task::spawn_blocking(move || ceremony::run(&task, index, &identity, &pinned, session, &mut transport)).await?;

    let linger_until = Instant::now() + if result.is_ok() { cfg.timeout } else { Duration::from_secs(30) };
    loop {
        let done = {
            let s = st.served.lock().unwrap_or_else(|e| e.into_inner());
            result.is_ok() && (0..n as u32).filter(|&j| j as usize != cfg.index).all(|j| s.confirm_read_by.contains(&j))
        };
        if done || Instant::now() >= linger_until {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    handle.graceful_shutdown(Some(Duration::from_secs(5)));
    let _ = server.await;
    // the staged contributions are public key material, but not needed any more
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
    Ok(result?)
}
