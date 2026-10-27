//! Real paper-core wiring for the authentication layer. Client ciphertext
//! validity and circuit privacy remain separate cryptographic requirements.
use super::*;
use fhe_paper_core::{ClientMaterial, CollectorKey, EvaluatorMaterial, PaperAggregate, PaperClient, PaperCollector, PaperEvaluator, PaperTask};
use fhe_prio3::{
    AggregateResult, Measurement, MeasurementType, Report,
    config::SilentCheck,
    packed::{Codec, Expect, WireFormat},
};
use openfhe_tbgv_rs::CiphertextMeta;
use std::sync::Arc;
fn check_task(task: &PaperTask) -> Result<()> {
    let native = task.native_parameters().ok_or(Error::Policy("native Count profile required"))?;
    if task.measurement_type() != &MeasurementType::Count
        || task.check_kind() != SilentCheck::Exact
        || !native.count_projection
        || native.plain_mod != 786433
        || native.key_switch_digits != 4
        || task.groups() != 4
        || task.row_slots() != 32768
        || task.mult_depth() != 22
        || task.max_batch() > 32
    {
        return Err(Error::Policy(
            "authenticated Count currently requires qualified p786433/ring65536/depth22/digits4/groups4, cap<=32",
        ));
    }
    Ok(())
}

const EXPECTED_QP_FINGERPRINT: [u8; 32] = [
    246, 138, 54, 169, 78, 251, 153, 45, 166, 88, 192, 72, 140, 120, 124, 207, 69, 215, 159, 152, 130, 79, 172, 16, 139, 59, 178, 87, 71, 215, 130, 37,
];
fn checked_context(task: &PaperTask) -> Result<openfhe_tbgv_rs::Context> {
    check_task(task)?;
    let ctx = task.make_context()?;
    let qp = ctx.key_basis_moduli(openfhe_tbgv_rs::KeyBasis::KeySwitch)?;
    let mut h = Sha256::new();
    h.update(b"count-auth/v1/qp-profile");
    h.update((ctx.ring_dim() as u64).to_le_bytes());
    h.update(ctx.plain_mod().to_le_bytes());
    h.update((ctx.key_num_parts()? as u32).to_le_bytes());
    h.update((qp.len() as u32).to_le_bytes());
    for q in qp {
        h.update(q.to_le_bytes());
    }
    let actual: [u8; 32] = h.finalize().into();
    if actual != EXPECTED_QP_FINGERPRINT {
        return Err(Error::Policy("unassessed QP parameters; independent security screening must be repeated"));
    }
    Ok(ctx)
}
pub fn profile(task: &PaperTask, material: &ClientMaterial) -> Result<([u8; 32], usize)> {
    check_task(task)?;
    let _guard = crypto_lock()?;
    let ctx = checked_context(task)?;
    let pk = ctx.deserialize_public_key(&material.public_key)?;
    let codec = Codec::new(&ctx, &pk, &material.public_key)?;
    let mut h = Sha256::new();
    h.update(b"count-auth/v1/count-profile");
    h.update(task.config().binding());
    h.update(task.mult_depth().to_le_bytes());
    h.update(hash(&material.context));
    h.update(hash(&material.public_key));
    Ok((h.finalize().into(), codec.fresh_len() + 8))
}
fn payload_report(task: &PaperTask, payload: &[u8]) -> Result<Report> {
    if payload.len() < 8 {
        return Err(Error::Frame);
    }
    let group = u32::from_le_bytes(payload[..4].try_into().map_err(|_| Error::Frame)?);
    let len = u32::from_le_bytes(payload[4..8].try_into().map_err(|_| Error::Frame)?) as usize;
    if group as usize >= task.groups() || payload.len() != 8 + len {
        return Err(Error::Frame);
    }
    let chunks = vec![payload[8..].to_vec()];
    let task_id = task.config().task_id;
    let report_id = Report::compute_id(&task_id, group, &chunks);
    Ok(Report {
        task_id,
        report_id,
        group,
        chunks,
        auth: None,
    })
}
pub fn client_frame(task: &PaperTask, material: &ClientMaterial, policy: &Policy, identity: &SigningKey, value: bool, group: u32) -> Result<Vec<u8>> {
    let (expected, cap) = profile(task, material)?;
    if expected != policy.profile || task.config().task_id != policy.task || cap != policy.payload_cap {
        return Err(Error::Policy("client policy does not match Count material"));
    }
    let _guard = crypto_lock()?;
    let client = PaperClient::new(task, material)?;
    let r = client.report(&Measurement::Count(value), group)?;
    let mut payload = group.to_le_bytes().to_vec();
    payload.extend((r.chunks[0].len() as u32).to_le_bytes());
    payload.extend(&r.chunks[0]);
    Ok(Submission::sign(policy, identity, payload)?.encode())
}
pub struct Ingress {
    store: Admission,
    task: PaperTask,
    material: Arc<EvaluatorMaterial>,
    format: WireFormat,
    fresh: CiphertextMeta,
    policy: Policy,
}
impl Ingress {
    pub fn open(path: &Path, task: PaperTask, material: Arc<EvaluatorMaterial>, client_material: &ClientMaterial, policy: Policy) -> Result<Self> {
        let (expected, cap) = profile(&task, client_material)?;
        if expected != policy.profile
            || task.config().task_id != policy.task
            || policy.payload_cap != cap
            || policy.maximum as u64 > task.max_batch()
            || material.context != client_material.context
            || material.public_key != client_material.public_key
        {
            return Err(Error::Policy("ingress policy/material mismatch"));
        }
        let (format, fresh) = {
            let _guard = crypto_lock()?;
            let _qualification = PaperEvaluator::new(task.clone(), &material)?;
            let ctx = task.make_context()?;
            let pk = ctx.deserialize_public_key(&material.public_key)?;
            let codec = Codec::new(&ctx, &pk, &material.public_key)?;
            let format = codec.format().clone();
            let fresh = codec.fresh_meta();
            (format, fresh)
        };
        let store = Admission::open(path, policy.clone())?;
        Ok(Self {
            store,
            task,
            material,
            format,
            fresh,
            policy,
        })
    }
    pub fn submit(&mut self, frame: &[u8]) -> Result<()> {
        let submission = Submission::decode(&self.policy, frame)?;
        self.store.submit(&submission, |payload| {
            let report = payload_report(&self.task, payload)?;
            self.format.parse(&report.chunks[0], Expect::Exactly(self.fresh)).map_err(|_| Error::Frame)?;
            Ok(())
        })
    }
    pub fn count(&self) -> Result<u32> {
        self.store.count()
    }
    pub fn seal(&mut self, key: &SigningKey) -> Result<Vec<u8>> {
        let release = self.store.seal(key, |payloads| {
            let _guard = crypto_lock()?;
            let mut evaluator = PaperEvaluator::new(self.task.clone(), &self.material)?;
            for payload in payloads {
                evaluator.admit(&payload_report(&self.task, payload)?)?;
            }
            let aggregate = evaluator.finish()?;
            if aggregate.reports != payloads.len() as u64 {
                return Err(Error::Frame);
            }
            Ok(aggregate.output)
        })?;
        Ok(release.encode())
    }
}
pub struct Collector {
    inner: PaperCollector,
    policy: Policy,
    receipts: Receipts,
}
impl Collector {
    pub fn open(path: &Path, task: PaperTask, material: &ClientMaterial, key: &CollectorKey, policy: Policy) -> Result<Self> {
        let (expected, cap) = profile(&task, material)?;
        if expected != policy.profile || task.config().task_id != policy.task || cap != policy.payload_cap || policy.maximum as u64 > task.max_batch() {
            return Err(Error::Policy("collector policy/material mismatch"));
        }
        let inner = {
            let _guard = crypto_lock()?;
            PaperCollector::new(task, material, key)?
        };
        Ok(Self {
            inner,
            policy,
            receipts: Receipts::open(path)?,
        })
    }
    pub fn decrypt(&mut self, frame: &[u8]) -> Result<u64> {
        self.receipts.consume(&self.policy, frame, |release| {
            let _guard = crypto_lock()?;
            let aggregate = PaperAggregate {
                task_id: self.policy.task,
                reports: release.reports as u64,
                output: release.output.clone(),
            };
            match self.inner.decrypt_aggregate(&aggregate)?.aggregate {
                AggregateResult::Count(n) => Ok(n),
                _ => Err(Error::Frame),
            }
        })
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use fhe_paper_core::NativeParameters;
    #[test]
    fn only_the_screened_profile_is_accepted() {
        let task = PaperTask::new_native(
            [1; 32],
            MeasurementType::Count,
            SilentCheck::Exact,
            NativeParameters {
                plain_mod: 786433,
                key_switch_digits: 4,
                count_projection: true,
                groups: Some(4),
                ..Default::default()
            },
        )
        .unwrap()
        .with_batch_limit(32)
        .unwrap();
        checked_context(&task).unwrap();
        let previous = PaperTask::new_native(
            [1; 32],
            MeasurementType::Count,
            SilentCheck::Exact,
            NativeParameters {
                plain_mod: 65537,
                key_switch_digits: 7,
                count_projection: true,
                groups: Some(4),
                ..Default::default()
            },
        )
        .unwrap()
        .with_batch_limit(32)
        .unwrap();
        assert!(checked_context(&previous).is_err());
    }
}
