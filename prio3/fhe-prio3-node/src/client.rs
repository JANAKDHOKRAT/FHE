//! Client library: obtains a group from the leader when the task batches,
//! encrypts, signs when required, submits, and returns the outcome.

use crate::wire::*;
use fhe_prio3::*;

pub struct NetworkClient {
    client: Client,
    http: reqwest::Client,
    leader: String,
    batched: bool,
}

/// Parses an aggregator key file: one 32-byte hex Ed25519 public key per
/// line, line `i` for aggregator `i`; blank lines and `#` comments ignored.
pub fn parse_aggregator_keys(text: &str) -> anyhow::Result<Vec<[u8; 32]>> {
    let mut keys = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let b = hex::decode(l)?;
        keys.push(b.as_slice().try_into().map_err(|_| anyhow::anyhow!("aggregator key must be 32 bytes"))?);
    }
    Ok(keys)
}

impl NetworkClient {
    /// `pinned`: the aggregators' identity keys, obtained out of band. When
    /// given, the material must carry a valid attestation from every
    /// aggregator or the client refuses to encrypt under it. `None` means
    /// the caller obtained the material itself over a trusted channel (a
    /// file handed over out of band); the router path never passes `None`.
    pub fn new(task: TaskConfig, material: &PublicMaterial, identity: Option<ClientIdentity>, leader: String, ca_pem: &[u8], pinned: Option<&[[u8; 32]]>) -> anyhow::Result<Self> {
        if let Some(p) = pinned {
            fhe_prio3::attest::verify_material(&task, material, p)?;
        }
        let mut client = Client::new(task.clone(), &material.context, &material.public_key)?;
        if let Some(id) = identity {
            client = client.with_identity(id);
        }
        let batched = task.mode == VerificationMode::Silent && task.silent_batch_groups > 1;
        Ok(Self { client, http: https_client(ca_pem)?, leader, batched })
    }

    pub async fn submit(&self, m: &Measurement) -> anyhow::Result<SubmitOutcome> {
        let group = if self.batched {
            let t: GroupTicket = http_get(&self.http, &format!("{}/v1/group", self.leader), None).await?;
            t.group
        } else {
            0
        };
        let report = self.client.shard_in_group(m, group)?;
        http_post(&self.http, &format!("{}/v1/submit", self.leader), None, &report).await
    }

    /// Submits an already-built report (tests of malformed submissions).
    pub async fn submit_report(&self, report: &Report) -> anyhow::Result<SubmitOutcome> {
        http_post(&self.http, &format!("{}/v1/submit", self.leader), None, report).await
    }

    pub fn inner(&self) -> &Client {
        &self.client
    }
}

/// Client of a sharded deployment: asks the router for a shard, fetches that
/// shard's task and public material (cached per shard), encrypts under its
/// key and submits to its leader.
pub struct ShardedClient {
    http: reqwest::Client,
    router: String,
    ca_pem: Vec<u8>,
    identity_secret: Option<[u8; 32]>,
    /// Aggregator identity keys, pinned out of band. Material served by the
    /// router is accepted only with every aggregator's attestation, so the
    /// router cannot substitute a key, a task or parameters.
    pinned: Vec<[u8; 32]>,
    cache: tokio::sync::Mutex<std::collections::HashMap<u32, std::sync::Arc<NetworkClient>>>,
}

impl ShardedClient {
    pub fn new(router: String, ca_pem: &[u8], identity: Option<&ClientIdentity>, pinned: Vec<[u8; 32]>) -> anyhow::Result<Self> {
        if pinned.is_empty() {
            anyhow::bail!("a sharded client needs the aggregators' pinned identity keys");
        }
        Ok(Self {
            http: https_client(ca_pem)?,
            router,
            ca_pem: ca_pem.to_vec(),
            identity_secret: identity.map(|i| i.secret_bytes()),
            pinned,
            cache: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    async fn client_for(&self, shard: u32, leader: &str) -> anyhow::Result<std::sync::Arc<NetworkClient>> {
        let mut cache = self.cache.lock().await;
        if let Some(c) = cache.get(&shard) {
            return Ok(c.clone());
        }
        let task: TaskConfig = http_get(&self.http, &format!("{}/v1/shard/{shard}/task", self.router), None).await?;
        let material: PublicMaterial = http_get(&self.http, &format!("{}/v1/shard/{shard}/material", self.router), None).await?;
        let identity = self.identity_secret.map(|s| ClientIdentity::from_secret_bytes(&s));
        let c = std::sync::Arc::new(NetworkClient::new(task, &material, identity, leader.to_string(), &self.ca_pem, Some(&self.pinned))?);
        cache.insert(shard, c.clone());
        Ok(c)
    }

    /// Returns the outcome and the shard that handled the report.
    pub async fn submit(&self, m: &Measurement) -> anyhow::Result<(SubmitOutcome, u32)> {
        let a: crate::router::Assignment = http_get(&self.http, &format!("{}/v1/assign", self.router), None).await?;
        let c = self.client_for(a.shard, &a.leader).await?;
        Ok((c.submit(m).await?, a.shard))
    }
}
