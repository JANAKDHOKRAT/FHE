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

impl NetworkClient {
    pub fn new(task: TaskConfig, material: &PublicMaterial, identity: Option<ClientIdentity>, leader: String, ca_pem: &[u8]) -> anyhow::Result<Self> {
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
