//! Experimental encrypted-verdict transport. Client reports and FLP are unchanged.
//!
//! This implements T - U, not a proof of evaluator correctness. W1 noise bounds,
//! constant-time processing, and key custody are NOT established.
//! Do not deploy or treat passing correctness tests as a privacy certification.
use super::*;
mod phase;
use phase::PhaseBound;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

const HEADER: usize = 72;
const CHECK: &[u8; 4] = b"OVC1";
const VERDICTS: &[u8; 4] = b"OVV1";
const FINAL: &[u8; 4] = b"OVF1";

/// Durable fail-closed reservation ledger in an operator-controlled directory.
/// Requires a local filesystem honoring create_new and fsync. Entries never
/// expire automatically. Losing/deleting this ledger voids replay protection.
struct Ledger {
    dir: PathBuf,
    root: PathBuf,
    key_guard: PathBuf,
}
fn io_error(e: std::io::Error) -> Error {
    Error::Protocol(format!("durable ledger: {e}"))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl Ledger {
    fn new(root: &Path, binding: &[u8; 32], key_binding: &[u8; 32]) -> Result<Self> {
        let metadata = fs::symlink_metadata(root).map_err(io_error)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::Protocol("ledger root must be a trusted existing directory".into()));
        }
        let dir = root.join(hex(binding));
        match fs::create_dir(&dir) {
            Ok(()) => fs::File::open(root).and_then(|f| f.sync_all()).map_err(io_error)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_error(e)),
        }
        let metadata = fs::symlink_metadata(&dir).map_err(io_error)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::Protocol("unsafe ledger namespace".into()));
        }
        Ok(Self {
            dir,
            root: root.to_path_buf(),
            key_guard: root.join(format!("key-guard-{}", hex(key_binding))),
        })
    }
    // Durable lease acquired before secret-dependent checks. On any later
    // failure it is retained, permanently disabling this key in this ledger.
    // A concurrent request is refused; a crash during a lease also burns the key.
    fn acquire_key(&self) -> Result<()> {
        let f = OpenOptions::new().write(true).create_new(true).open(&self.key_guard).map_err(io_error)?;
        f.sync_all().map_err(io_error)?;
        fs::File::open(&self.root).and_then(|f| f.sync_all()).map_err(io_error)
    }
    fn release_key(&self) -> Result<()> {
        fs::remove_file(&self.key_guard).map_err(io_error)?;
        fs::File::open(&self.root).and_then(|f| f.sync_all()).map_err(io_error)
    }
    fn reserve(&self, domain: &str, id: &[u8; 32]) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.dir.join(format!("{domain}-{}", hex(id))))
            .map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        fs::File::open(&self.dir).and_then(|f| f.sync_all()).map_err(io_error)?;
        Ok(())
    }
}

/// Block-aligned packing: blocks cannot straddle ciphertext boundaries.
fn capacity(ring: usize, outputs: usize, reports: usize) -> Result<(usize, usize)> {
    if outputs == 0 || outputs > ring || reports == 0 || reports > u32::MAX as usize {
        return Err(Error::Protocol("invalid oblivious packing dimensions".into()));
    }
    let per = ring / outputs;
    Ok((per, reports.div_ceil(per)))
}

fn key_binding<F: FheField, T: VerifierMap<F>>(task: &SingleTask<F, T>, pk: &PublicKey) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"fhe-flp/key-guard-v1");
    h.update(F::PLAIN_MOD.to_le_bytes());
    h.update((task.layout().ring as u64).to_le_bytes());
    for q in task.ctx.moduli()? {
        h.update(q.to_le_bytes());
    }
    for i in 0..2 {
        for r in pk.evaluation_residues(i)? {
            h.update(r.to_le_bytes());
        }
    }
    Ok(h.finalize().into())
}

fn binding<F: FheField, T: VerifierMap<F>>(task: &SingleTask<F, T>, pk: &PublicKey) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"fhe-flp/oblivious-v1/task-key");
    h.update(task.task_id);
    h.update(std::any::type_name::<T>().as_bytes());
    // Pinned prio 0.18.1 Debug includes bounds/chunk parameters that dimensions
    // alone miss (e.g. multihot weights 6 versus 7). This is a version-specific
    // wire format, not a cross-version canonical task descriptor.
    h.update(format!("prio=0.18.1;task={:?}", task.typ()).as_bytes());
    for v in [
        F::PLAIN_MOD,
        task.layout().ring as u64,
        task.layout().input_len as u64,
        task.layout().z_len as u64,
        task.layout().num_rows() as u64,
        task.plan.num_proofs() as u64,
        task.max_batch(),
        task.agg.coeffs().len() as u64,
    ] {
        h.update(v.to_le_bytes());
    }
    for m in task.ctx.moduli()? {
        h.update(m.to_le_bytes());
    }
    for c in task.agg.coeffs() {
        h.update(c.to_le_bytes());
    }
    if let AggMap::Convolution { poly, .. } = &task.agg {
        for c in poly {
            h.update(c.to_le_bytes());
        }
    }
    // Hash canonical key evaluation residues, not Cereal serialization metadata.
    for element in 0..2 {
        for residue in pk.evaluation_residues(element)? {
            h.update(residue.to_le_bytes());
        }
    }
    Ok(h.finalize().into())
}

fn header(kind: &[u8; 4], binding: &[u8; 32], batch: &[u8; 32], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER);
    out.extend(kind);
    out.extend(binding);
    out.extend(batch);
    out.extend((n as u32).to_le_bytes());
    out
}
fn parse(bytes: &[u8], kind: &[u8; 4], binding: &[u8; 32], max: u64) -> Result<([u8; 32], usize)> {
    if bytes.len() < HEADER || &bytes[..4] != kind || &bytes[4..36] != binding {
        return Err(Error::Codec("oblivious message type/task/key mismatch".into()));
    }
    let n = u32::from_le_bytes(bytes[68..72].try_into().expect("header checked")) as usize;
    if n == 0 || n as u64 > max {
        return Err(Error::Protocol("invalid batch size".into()));
    }
    Ok((bytes[36..68].try_into().expect("header checked"), n))
}

/// Evaluator owns the masks and receives only fresh encrypted verdicts.
/// A consumed session cannot ingest more reports or generate another check.
pub struct ObliviousEvaluator<'a, F: FheField, T: VerifierMap<F>> {
    inner: Evaluator<'a, F, T>,
    binding: [u8; 32],
    batch: [u8; 32],
    masks: Option<Vec<Vec<F>>>,
    started: bool,
}
impl<'a, F: FheField, T: VerifierMap<F>> ObliviousEvaluator<'a, F, T> {
    pub fn new(task: &'a SingleTask<F, T>, pk: &PublicKey, verify_key: [u8; 32]) -> Result<Self> {
        let mut batch = [0; 32];
        OsRng.fill_bytes(&mut batch);
        Ok(Self {
            inner: Evaluator::new(task, pk, verify_key)?,
            binding: binding(task, pk)?,
            batch,
            masks: None,
            started: false,
        })
    }
    pub fn ingest(&mut self, report: &[u8]) -> Result<()> {
        if self.started {
            return Err(Error::Protocol("batch already sealed".into()));
        }
        self.inner.ingest(report)
    }
    pub fn check_request(&mut self) -> Result<Vec<u8>> {
        if self.started {
            return Err(Error::Protocol("batch already sealed".into()));
        }
        let task = self.inner.task;
        capacity(task.layout().ring, task.agg.coeffs().len(), self.inner.len())?;
        self.started = true; // Any subsequent failure consumes the session.
        let (base, mut pads) = self.inner.check_request_with_output_pads()?;
        let mut out = header(CHECK, &self.binding, &self.batch, self.inner.len());
        for report in &self.inner.reports {
            out.extend(report.digest);
        }
        out.extend(&base[4..]);
        if let AggMap::Convolution { poly, coeffs } = &task.agg {
            pads.clear();
            for report in &self.inner.reports {
                let mask = task.pad(0..task.layout().ring);
                pads.push(coeffs.iter().map(|&j| F::from_u64(mask[j as usize])).collect());
                let prod = task.ctx.mult_plain(&report.ct, &task.ctx.coef_plaintext(poly)?)?;
                out.extend(task.pack_reduced(&finish::<F>(&task.ctx, &task.ctx.add_plain(&prod, &task.ctx.coef_plaintext(&mask)?)?)?)?);
            }
        }
        self.masks = Some(pads);
        Ok(out)
    }
    pub fn final_request(&mut self, response: &[u8]) -> Result<Vec<u8>> {
        let task = self.inner.task;
        let (batch, n) = parse(response, VERDICTS, &self.binding, task.max_batch())?;
        if batch != self.batch || n != self.inner.len() {
            return Err(Error::Protocol("wrong verdict batch".into()));
        }
        let (per, blocks) = capacity(task.layout().ring, task.agg.coeffs().len(), n)?;
        if response.len() != HEADER + blocks * task.fresh_len() {
            return Err(Error::Codec("wrong encrypted verdict length".into()));
        }
        let masks = self.masks.take().ok_or_else(|| Error::Protocol("no pending verdicts".into()))?;
        let ring = task.layout().ring;
        let len = task.agg.coeffs().len();
        let mut sum: Option<Ciphertext> = None;
        for (block, bytes) in response[HEADER..].chunks_exact(task.fresh_len()).enumerate() {
            let residues = task.fresh_codec.unpack(bytes, 2, ring)?;
            let ct = task.ctx.build_ciphertext(&self.inner.reference, &self.inner.reference.meta()?, &residues)?;
            let mut poly = vec![0u64; ring];
            // V has nonzeros at i*L. P[c-i*L] = r_i[c]. Negative powers
            // use X^N = -1. For c<L these index intervals do not overlap,
            // since every complete block fits within the ring.
            for (i, mask) in masks.iter().skip(block * per).take(per).enumerate() {
                for (c, r) in mask.iter().enumerate() {
                    let shift = i * len;
                    if c >= shift {
                        poly[c - shift] = r.to_u64();
                    } else {
                        poly[ring + c - shift] = (F::PLAIN_MOD - r.to_u64()) % F::PLAIN_MOD;
                    }
                }
            }
            let prod = task.ctx.mult_plain(&ct, &task.ctx.coef_plaintext(&poly)?)?;
            sum = Some(match sum {
                None => prod,
                Some(s) => task.ctx.add(&s, &prod)?,
            });
        }
        let keep: Vec<u32> = (0..len as u32).collect();
        let mask = task.ctx.coef_plaintext(&task.mask(&keep, &vec![F::zero(); len]))?;
        let mut out = header(FINAL, &self.binding, &self.batch, n);
        out.extend(task.pack_reduced(&finish::<F>(&task.ctx, &task.ctx.add_plain(&sum.expect("nonempty blocks"), &mask)?)?)?);
        Ok(out)
    }
}

struct Pending<F> {
    batch: [u8; 32],
    reports: usize,
    accepted: usize,
    total: Vec<F>,
}
/// Collector output is local to this object; its response contains no verdict
/// bitmap, accepted count, or aggregate. Replay reservations persist; unfinished batches after a crash are burned.
pub struct ObliviousCollector<'a, F: FheField, T: VerifierMap<F>> {
    inner: SingleCollector<'a, F, T>,
    pk: PublicKey,
    binding: [u8; 32],
    ledger: Ledger,
    pending: Option<Pending<F>>,
    phase_bound: PhaseBound,
}
impl<'a, F: FheField, T: VerifierMap<F>> ObliviousCollector<'a, F, T> {
    /// The ledger directory must already exist and be writable only by the
    /// collector operator. A fresh key creates a separate ledger namespace.
    pub fn new(task: &'a SingleTask<F, T>, ledger_root: &Path) -> Result<(Self, PublicKey)> {
        let (pk, sk) = keygen_first(&task.ctx)?;
        let own_pk = task.ctx.deserialize_public_key(&pk.serialize()?)?;
        Ok((Self::with_keys(task, own_pk, sk, ledger_root)?, pk))
    }
    /// Reopen with the SAME externally managed key pair and ledger after a
    /// restart. Pending batches cannot be resumed: their reservations persist.
    /// Key files and their access control are the deployment's responsibility.
    pub fn with_keys(task: &'a SingleTask<F, T>, pk: PublicKey, sk: SecretShare, ledger_root: &Path) -> Result<Self> {
        verify_single_rebuild_once(&task.ctx)?;
        let binding = binding(task, &pk)?;
        let reference = task.ctx.encrypt(&pk, &task.ctx.coef_plaintext(&[0])?)?;
        if sk.decrypt_coeffs(&reference, &[0])? != [0] {
            return Err(Error::Protocol("collector key pair does not match".into()));
        }
        let ledger = Ledger::new(ledger_root, &binding, &key_binding(task, &pk)?)?;
        let phase_bound = PhaseBound::new(task)?;
        let inner = SingleCollector {
            task,
            sk,
            reference,
            accepted: None,
            aggregate_consumed: Cell::new(false),
            seen_check_requests: HashSet::new(),
        };
        Ok(Self {
            inner,
            pk,
            binding,
            ledger,
            pending: None,
            phase_bound,
        })
    }
    fn phase_preflight(&self, bytes: &[u8]) -> Result<()> {
        let task = self.inner.task;
        let mut failed = false;
        for chunk in bytes.chunks_exact(task.reduced_len()) {
            let res = task.reduced_codec.unpack(chunk, 2, task.layout().ring)?;
            let ct = task.ctx.build_ciphertext(&self.inner.reference, &task.reduced_meta, &res)?;
            let (norm, q) = self.inner.sk.phase_inf_norm(&ct)?;
            failed |= q != self.phase_bound.modulus || norm > self.phase_bound.maximum;
        }
        if failed {
            return Err(Error::Protocol("phase guard rejected request; key disabled in ledger".into()));
        }
        Ok(())
    }
    pub fn check(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        let task = self.inner.task;
        let (batch, n) = parse(request, CHECK, &self.binding, task.max_batch())?;
        if self.pending.is_some() {
            return Err(Error::Protocol("batch pending or already consumed".into()));
        }
        let extra = usize::from(matches!(task.agg, AggMap::Convolution { .. }));
        let base_start = HEADER + n * 32;
        let base_len = task.check_request_len(n) - 4;
        if request.len() != base_start + base_len + extra * n * task.reduced_len() {
            return Err(Error::Codec("wrong oblivious check length".into()));
        }
        let len = task.reduced_len();
        // Preflight the entire batch, including every extra output ciphertext.
        for bytes in request[base_start..].chunks_exact(len) {
            task.reduced_codec.unpack(bytes, 2, task.layout().ring)?;
        }
        // Durable reservation BEFORE any decryption. Failure may burn a batch
        // or part of its report set; that is deliberate fail-closed behavior.
        self.ledger.reserve("batch", &batch)?;
        for digest in request[HEADER..base_start].chunks_exact(32) {
            self.ledger.reserve("report", digest.try_into().expect("digest length"))?;
        }
        self.ledger.acquire_key()?;
        self.phase_preflight(&request[base_start..])?;
        let mut base = (n as u32).to_le_bytes().to_vec();
        base.extend(&request[base_start..base_start + base_len]);
        let verdicts = self.inner.check(&base)?;
        let outputs = task.agg.coeffs().len();
        let mut total = vec![F::zero(); outputs];
        let mut accepted = 0;
        for i in 0..n {
            let offset = if extra == 1 {
                base_start + base_len + i * len
            } else {
                base_start + (i * (task.layout().groups().len() + task.parts) + task.layout().groups().len()) * len
            };
            let y = self.inner.open(&request[offset..offset + len], task.agg.coeffs())?;
            let valid = verdicts[i / 8] >> (i % 8) & 1;
            accepted += valid as usize;
            for (t, y) in total.iter_mut().zip(y) {
                *t += F::from(valid as u32) * y;
            }
        }
        let (per, blocks) = capacity(task.layout().ring, outputs, n)?;
        let mut response = header(VERDICTS, &self.binding, &batch, n);
        for block in 0..blocks {
            let mut values = vec![0; task.layout().ring];
            for i in 0..per.min(n - block * per) {
                let j = block * per + i;
                values[i * outputs] = u64::from(verdicts[j / 8] >> (j % 8) & 1);
            }
            let ct = task.ctx.encrypt(&self.pk, &task.ctx.coef_plaintext(&values)?)?;
            response.extend(task.fresh_codec.pack(&ct.export_residues()?, 2, task.layout().ring)?);
        }
        self.pending = Some(Pending {
            batch,
            reports: n,
            accepted,
            total,
        });
        self.ledger.release_key()?;
        Ok(response)
    }
    /// Local collector result. No network reply to the evaluator is produced.
    pub fn unshard(&mut self, request: &[u8]) -> Result<T::AggregateResult> {
        let task = self.inner.task;
        let (batch, n) = parse(request, FINAL, &self.binding, task.max_batch())?;
        if request.len() != HEADER + task.reduced_len() {
            return Err(Error::Codec("wrong final length".into()));
        }
        let pending = self.pending.as_ref().ok_or_else(|| Error::Protocol("no pending batch".into()))?;
        if pending.batch != batch || pending.reports != n {
            return Err(Error::Protocol("wrong final batch".into()));
        }
        self.ledger.reserve("release", &batch)?;
        self.ledger.acquire_key()?;
        self.phase_preflight(&request[HEADER..])?;
        let pending = self.pending.take().expect("checked");
        let idx: Vec<u32> = (0..pending.total.len() as u32).collect();
        let u = self.inner.open(&request[HEADER..], &idx)?;
        let output: Vec<F> = pending.total.iter().zip(u).map(|(&t, u)| t - u).collect();
        let result = task.typ().decode_result(&output, pending.accepted)?;
        self.ledger.release_key()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f65537::Field65537 as F;
    use prio::field::FieldElement;
    use prio::flp::types::{Count, Sum};
    fn test_dir() -> PathBuf {
        let mut id = [0; 16];
        OsRng.fill_bytes(&mut id);
        let path = std::env::temp_dir().join(format!("fhe-oblivious-{}", hex(&id)));
        fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn packing_rounds_at_whole_report_boundaries() {
        assert_eq!(capacity(8192, 100, 163).unwrap(), (81, 3));
        assert!(capacity(8192, 8193, 1).is_err());
    }
    #[test]
    fn count_invalid_and_all_rejected_have_same_reply_size_and_one_release() {
        let task = SingleTask::new(Count::<F>::new(), [7; 32], 9).unwrap();
        let (mut collector, pk) = ObliviousCollector::new(&task, &test_dir()).unwrap();
        let client = SingleClient::new(&task, &pk);
        let mut lengths = Vec::new();
        for values in [[1, 0, 2], [2, 2, 2]] {
            let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
            for v in values {
                ev.ingest(&client.shard_with_witness(&[F::from(v)]).unwrap().0).unwrap();
            }
            let request = ev.check_request().unwrap();
            assert!(ev.check_request().is_err());
            let response = collector.check(&request).unwrap();
            lengths.push(response.len());
            assert!(collector.check(&request).is_err());
            let final_request = ev.final_request(&response).unwrap();
            assert!(ev.final_request(&response).is_err());
            assert_eq!(collector.unshard(&final_request).unwrap(), u32::from(values[0] == 1));
            assert!(collector.unshard(&final_request).is_err());
        }
        assert_eq!(lengths[0], lengths[1]);
    }
    #[test]
    fn weighted_sum_uses_output_domain_masks() {
        let typ = Sum::<F>::new(100).unwrap();
        let k = crate::soundness::proofs_for_with_joint_rand(&typ, 65537.0, 128.0, 0);
        let task = SingleTask::new(typ, [8; 32], k).unwrap();
        let (mut collector, pk) = ObliviousCollector::new(&task, &test_dir()).unwrap();
        let client = SingleClient::new(&task, &pk);
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        for v in [70, 100, 0] {
            ev.ingest(&client.shard(&v).unwrap()).unwrap();
        }
        let mut invalid = vec![F::zero(); 7];
        invalid[0] = F::from(2);
        ev.ingest(&client.shard_with_witness(&invalid).unwrap().0).unwrap();
        let req = ev.check_request().unwrap();
        let response = collector.check(&req).unwrap();
        let end = ev.final_request(&response).unwrap();
        assert_eq!(collector.unshard(&end).unwrap(), 170);
    }
    #[test]
    fn replay_survives_collector_restart_and_rerandomized_checks() {
        let task = SingleTask::new(Count::<F>::new(), [19; 32], 9).unwrap();
        let dir = test_dir();
        let (mut collector, pk) = ObliviousCollector::new(&task, &dir).unwrap();
        let key = collector.inner.sk.serialize().unwrap();
        let report = SingleClient::new(&task, &pk).shard(&true).unwrap();
        let mut first = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        first.ingest(&report).unwrap();
        let req = first.check_request().unwrap();
        collector.check(&req).unwrap();
        drop(collector); // Simulates losing all volatile state with same key retained.
        let mut restored = ObliviousCollector::with_keys(
            &task,
            task.ctx.deserialize_public_key(&pk.serialize().unwrap()).unwrap(),
            task.ctx.deserialize_secret_share(&key).unwrap(),
            &dir,
        )
        .unwrap();
        assert!(restored.check(&req).is_err());
        let mut retry = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        retry.ingest(&report).unwrap();
        let fresh_request = retry.check_request().unwrap();
        assert_ne!(fresh_request, req);
        assert!(restored.check(&fresh_request).is_err());
        // Unrelated fresh reports still work after the refused replay.
        let mut fresh = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        fresh.ingest(&SingleClient::new(&task, &pk).shard(&true).unwrap()).unwrap();
        let req = fresh.check_request().unwrap();
        let response = restored.check(&req).unwrap();
        let end = fresh.final_request(&response).unwrap();
        assert_eq!(restored.unshard(&end).unwrap(), 1);
    }

    #[test]
    fn wrong_task_truncated_suffix_and_wrong_final_batch_are_refused() {
        let task = SingleTask::new(Count::<F>::new(), [20; 32], 9).unwrap();
        let other = SingleTask::new(Count::<F>::new(), [21; 32], 9).unwrap();
        let (mut collector, pk) = ObliviousCollector::new(&task, &test_dir()).unwrap();
        let mut wrong = ObliviousEvaluator::new(&other, &pk, [42; 32]).unwrap();
        wrong.ingest(&SingleClient::new(&other, &pk).shard(&true).unwrap()).unwrap();
        assert!(collector.check(&wrong.check_request().unwrap()).is_err());
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        ev.ingest(&SingleClient::new(&task, &pk).shard(&true).unwrap()).unwrap();
        let req = ev.check_request().unwrap();
        assert!(collector.check(&req[..req.len() - 1]).is_err());
        let mut oversized = req.clone();
        oversized[68..72].copy_from_slice(&65537u32.to_le_bytes());
        assert!(collector.check(&oversized).is_err());
        let response = collector.check(&req).unwrap();
        let end = ev.final_request(&response).unwrap();
        let mut wrong = end.clone();
        wrong[36] ^= 1;
        assert!(collector.unshard(&wrong).is_err());
        assert_eq!(collector.unshard(&end).unwrap(), 1);
    }

    #[test]
    fn poisoned_report_cannot_contaminate_neighbours() {
        let task = SingleTask::new(Count::<F>::new(), [22; 32], 9).unwrap();
        let (mut collector, pk) = ObliviousCollector::new(&task, &test_dir()).unwrap();
        let c = SingleClient::new(&task, &pk);
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        ev.ingest(&c.shard(&true).unwrap()).unwrap();
        ev.ingest(&c.report_from_coefficients(&vec![F::from(65536); task.layout().ring]).unwrap())
            .unwrap();
        ev.ingest(&c.shard(&true).unwrap()).unwrap();
        let req = ev.check_request().unwrap();
        let response = collector.check(&req).unwrap();
        let end = ev.final_request(&response).unwrap();
        assert_eq!(collector.unshard(&end).unwrap(), 2);
    }

    fn variants<G: FheField>() {
        use crate::bitvec::BitVec;
        use prio::flp::gadgets::{Mul, ParallelSum};
        use prio::flp::types::{Histogram, MultihotCountVec, SumVec};
        use prio::vdaf::prio3::optimal_chunk_length;
        fn run<G: FheField, T: VerifierMap<G>>(typ: T, m: T::Measurement, expected: T::AggregateResult)
        where
            T::AggregateResult: PartialEq + std::fmt::Debug,
        {
            let k = crate::soundness::proofs_for_with_joint_rand(&typ, G::PLAIN_MOD as f64, 128.0, typ.joint_rand_degree());
            let task = SingleTask::new(typ, [23; 32], k).unwrap();
            let (mut collector, pk) = ObliviousCollector::new(&task, &test_dir()).unwrap();
            let c = SingleClient::new(&task, &pk);
            let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
            for _ in 0..3 {
                ev.ingest(&c.shard(&m).unwrap()).unwrap();
            }
            let mut bad = vec![G::zero(); task.layout().input_len];
            bad[0] = G::from(2);
            ev.ingest(&c.shard_with_witness(&bad).unwrap().0).unwrap();
            let req = ev.check_request().unwrap();
            let response = collector.check(&req).unwrap();
            let end = ev.final_request(&response).unwrap();
            assert_eq!(collector.unshard(&end).unwrap(), expected);
        }
        run(Count::<G>::new(), true, 3);
        run(Sum::<G>::new(100).unwrap(), 70, 210);
        for len in [10, 100] {
            run(BitVec::<G>::new(len).unwrap(), vec![true; len], vec![3; len]);
        }
        for (len, max) in [(10, 3), (100, 1)] {
            let bits = if max == 3 { 2 } else { 1 };
            run(
                SumVec::<G, ParallelSum<G, Mul>>::new(max, len, optimal_chunk_length(len * bits)).unwrap(),
                vec![max; len],
                vec![max * 3; len],
            );
        }
        let mut expected = vec![0; 100];
        expected[99] = 3;
        run(Histogram::<G, ParallelSum<G, Mul>>::new(100, optimal_chunk_length(100)).unwrap(), 99, expected);
        // Multihot measurements are Boolean vectors with bounded Hamming weight.
        let mut expected = vec![0; 100];
        for v in expected.iter_mut().take(10) {
            *v = 3;
        }
        run(
            MultihotCountVec::<G, ParallelSum<G, Mul>>::new(100, 10, optimal_chunk_length(100)).unwrap(),
            (0..100).map(|i| i < 10).collect(),
            expected,
        );
    }
    #[test]
    fn all_variants_small_field() {
        variants::<F>();
    }
    #[test]
    fn all_variants_prio_field() {
        variants::<prio::field::FieldPrio2>();
    }

    #[test]
    fn histogram_crosses_two_block_boundaries_without_spill() {
        use prio::flp::gadgets::{Mul, ParallelSum};
        use prio::flp::types::Histogram;
        let typ = Histogram::<F, ParallelSum<F, Mul>>::new(100, 10).unwrap();
        let k = crate::soundness::proofs_for_with_joint_rand(&typ, 65537.0, 128.0, typ.joint_rand_degree());
        let task = SingleTask::new(typ, [24; 32], k).unwrap();
        let (mut collector, pk) = ObliviousCollector::new(&task, &test_dir()).unwrap();
        let c = SingleClient::new(&task, &pk);
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        let n = 2 * (task.layout().ring / 100) + 1;
        let mut expected = vec![0; 100];
        for i in 0..n {
            let bucket = i % 100;
            expected[bucket] += 1;
            ev.ingest(&c.shard(&bucket).unwrap()).unwrap();
        }
        let req = ev.check_request().unwrap();
        let response = collector.check(&req).unwrap();
        assert_eq!(response.len(), HEADER + 3 * task.fresh_len());
        let end = ev.final_request(&response).unwrap();
        assert_eq!(collector.unshard(&end).unwrap(), expected);
    }
    /// Reproduce the old unit-query attack with real encrypted Count reports.
    /// The response has only encrypted verdicts. A constant-zero guess is a
    /// diagnostic, not a cryptographic indistinguishability test or proof.
    #[test]
    fn crafted_query_returns_encrypted_verdicts_for_100_reports() {
        let task = SingleTask::new(Count::<F>::new(), [25; 32], 9).unwrap();
        let (mut collector, pk) = ObliviousCollector::new(&task, &test_dir()).unwrap();
        let c = SingleClient::new(&task, &pk);
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        let mut zero_guesses = 0;
        for _ in 0..100 {
            let bit = OsRng.next_u32() & 1 == 1;
            zero_guesses += usize::from(!bit);
            ev.ingest(&c.shard(&bit).unwrap()).unwrap();
        }
        let mut req = ev.check_request().unwrap();
        let layout = task.layout();
        assert_eq!(layout.groups().len(), 1);
        let mut rows = vec![vec![F::zero(); layout.z_len]; layout.num_rows()];
        for proof in 0..9 {
            rows[proof * 4][0] = F::one();
        }
        let query = task.ctx.coef_plaintext(&task.plan.query_poly(&rows)).unwrap();
        let idx = layout.group_coeffs(layout.num_rows());
        for i in 0..100 {
            let product = task.ctx.mult_plain(&ev.inner.reports[i].ct, &query).unwrap();
            let mask = task.ctx.coef_plaintext(&task.mask(&idx, &vec![F::zero(); idx.len()])).unwrap();
            let forged = task
                .pack_reduced(&finish::<F>(&task.ctx, &task.ctx.add_plain(&product, &mask).unwrap()).unwrap())
                .unwrap();
            let off = HEADER + 100 * 32 + i * (layout.groups().len() + task.parts) * task.reduced_len();
            req[off..off + forged.len()].copy_from_slice(&forged);
        }
        let response = collector.check(&req).unwrap();
        assert_eq!(response.len(), HEADER + task.fresh_len());
        assert_eq!(&response[..4], VERDICTS);
        assert_eq!(&response[68..72], &100u32.to_le_bytes()); // submitted count, never accepted count
        let residues = task.fresh_codec.unpack(&response[HEADER..], 2, layout.ring).unwrap();
        let encrypted = task
            .ctx
            .build_ciphertext(&collector.inner.reference, &collector.inner.reference.meta().unwrap(), &residues)
            .unwrap();
        // Collector-only inspection: the crafted predicate was evaluated, but
        // these verdicts never leave the collector as plaintext.
        let v = collector.inner.sk.decrypt_coeffs(&encrypted, &(0..100).collect::<Vec<u32>>()).unwrap();
        assert_eq!(v.iter().sum::<u64>(), zero_guesses as u64);
        eprintln!("encrypted-verdict attack diagnostic: constant guess matches {zero_guesses}/100; not a security proof");
        let end = ev.final_request(&response).unwrap();
        assert_eq!(collector.unshard(&end).unwrap(), 0); // crafted predicate accepted only zero inputs
    }

    /// Reflection of a fresh E(V) as a client report has no attached valid FLP.
    /// This example is rejected privately, not a general ciphertext-origin proof.
    #[test]
    fn reflected_verdict_ciphertext_has_no_plaintext_verdict_reply() {
        let task = SingleTask::new(Count::<F>::new(), [26; 32], 9).unwrap();
        let (mut collector, pk) = ObliviousCollector::new(&task, &test_dir()).unwrap();
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        ev.ingest(&SingleClient::new(&task, &pk).shard(&true).unwrap()).unwrap();
        let req = ev.check_request().unwrap();
        let response = collector.check(&req).unwrap();
        let end = ev.final_request(&response).unwrap();
        assert_eq!(collector.unshard(&end).unwrap(), 1);
        let mut reflected = vec![0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut reflected);
        reflected.extend(&response[HEADER..]);
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        ev.ingest(&reflected).unwrap();
        let req = ev.check_request().unwrap();
        let reflected_reply = collector.check(&req).unwrap();
        assert_eq!(reflected_reply.len(), response.len());
        let end = ev.final_request(&reflected_reply).unwrap();
        assert_eq!(collector.unshard(&end).unwrap(), 0);
    }
    /// Real amplified ciphertext is refused before FLP verdict processing.
    /// The durable lease is deliberately retained after failure, and a newly
    /// constructed collector with the same key/ledger cannot resume this key.
    #[test]
    fn amplified_phase_revokes_key_across_collector_reconstruction() {
        let task = SingleTask::new(Count::<F>::new(), [27; 32], 9).unwrap();
        let dir = test_dir();
        let (mut collector, pk) = ObliviousCollector::new(&task, &dir).unwrap();
        let saved = collector.inner.sk.serialize().unwrap();
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        ev.ingest(&SingleClient::new(&task, &pk).shard(&true).unwrap()).unwrap();
        let mut req = ev.check_request().unwrap();
        let off = HEADER + 32;
        let raw = task.reduced_codec.unpack(&req[off..off + task.reduced_len()], 2, task.layout().ring).unwrap();
        let mut ct = task.ctx.build_ciphertext(&collector.inner.reference, &task.reduced_meta, &raw).unwrap();
        let mut doublings = 0;
        while collector.inner.sk.phase_inf_norm(&ct).unwrap().0 <= collector.phase_bound.maximum {
            ct = task.ctx.add(&ct, &ct).unwrap();
            doublings += 1;
            assert!(doublings < 64, "unexpected zero/small phase orbit");
        }
        req[off..off + task.reduced_len()].copy_from_slice(&task.pack_reduced(&ct).unwrap());
        assert!(collector.check(&req).unwrap_err().to_string().contains("phase guard"));
        assert!(collector.inner.accepted.is_none());
        assert!(collector.pending.is_none());
        drop(collector);
        let mut restored = ObliviousCollector::with_keys(
            &task,
            task.ctx.deserialize_public_key(&pk.serialize().unwrap()).unwrap(),
            task.ctx.deserialize_secret_share(&saved).unwrap(),
            &dir,
        )
        .unwrap();
        let mut fresh = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        fresh.ingest(&SingleClient::new(&task, &pk).shard(&true).unwrap()).unwrap();
        assert!(restored.check(&fresh.check_request().unwrap()).is_err());
    }

    /// Final-message gate runs before any output is decoded, not only at checks.
    #[test]
    fn oversized_final_phase_disables_key_without_releasing_output() {
        let task = SingleTask::new(Count::<F>::new(), [28; 32], 9).unwrap();
        let (mut collector, pk) = ObliviousCollector::new(&task, &test_dir()).unwrap();
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        ev.ingest(&SingleClient::new(&task, &pk).shard(&true).unwrap()).unwrap();
        let reply = collector.check(&ev.check_request().unwrap()).unwrap();
        let mut end = ev.final_request(&reply).unwrap();
        let ring = task.layout().ring;
        let mut r = vec![0; 2 * ring];
        r[..ring].fill(collector.phase_bound.modulus / 2);
        let ct = task.ctx.build_ciphertext(&collector.inner.reference, &task.reduced_meta, &r).unwrap();
        end[HEADER..].copy_from_slice(&task.pack_reduced(&ct).unwrap());
        assert!(collector.unshard(&end).unwrap_err().to_string().contains("phase guard"));
        assert!(collector.ledger.key_guard.exists());
    }
}
