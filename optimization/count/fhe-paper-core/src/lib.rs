//! The architecture of Dhokrat et al., "Cost and Trust Trade-offs of
//! FHE-Based Private Aggregation" (ITASEC 2026), and nothing else.
//!
//! Three roles (paper §3): clients encrypt their encoded measurement under
//! the collector's public key; one evaluator, holding only evaluation keys,
//! validates every report homomorphically, multiplies it by its validity
//! flag, decodes it (`A_T`) and sums; the collector, holding the secret
//! key, decrypts the task output. Four tasks (paper §4.1): Count, Sum,
//! SumVec and Histogram, with the paper's encodings (Eq. 5). Two validity
//! circuits: exact (Eq. 10 of the current draft: every residual tested on
//! its own) and randomised (Eq. 11: `t = 7` random combinations of the
//! residuals with coefficients drawn by the evaluator after the reports are
//! fixed, soundness `p^-7 = 2^-137.1`).
//!
//! The retained constructor runs the existing circuits of this crate (`fhe_prio3::verify::Circuit`,
//! `fhe_prio3::verify::exact_circuit`), the production client encryption and the
//! packed wire format, at the retained research parameters (`p = 786433`, ring
//! dimension 65536, 128-bit security). What it leaves out is everything the
//! paper does not specify or names as a separate requirement (§4.6, §6):
//!
//! * one secret key, generated and held by the collector (no threshold
//!   key, no key ceremony, no attestations);
//! * plain decryption of the aggregate by the collector (no verified
//!   decryption rounds);
//! * no release policy (no minimum batch gate, no small-cell suppression,
//!   no count round);
//! * no client authentication, quotas or replay protection;
//! * no verdict mode, share upload, client proofs or second moments.
//!
//! What it keeps because the paper requires it: every report is restricted
//! to its own slots before it meets another (§4.2: slots outside the
//! encoding must be excluded); challenges unpredictable to clients and
//! drawn after the batch is fixed (§4.4: fresh 256-bit keys from the
//! operating system per verification batch); a prime plaintext modulus with
//! `N < p` for Count and Histogram and `N·M < p` for Sum and SumVec (§4.5);
//! linear constraints that cannot wrap modulo `p`. `A_T` is evaluated under
//! encryption (§4.5) and only the decoded outputs survive to decryption:
//! the collector never sees the per-coordinate sums of Sum or SumVec.
//!
//! `PaperTask::new_native` is an explicit, separately qualified single-key path
//! with parameter profiles and a lifetime-attempt soundness contract. The legacy
//! defaults described above do not describe every native profile. Neither path
//! is a production-security certification.
//!
//! The trust model is therefore the paper's: the evaluator and the
//! collector must not collude (the collector's key decrypts any report),
//! the evaluator is honest-but-curious, and the collector must only ever be
//! given aggregates. A malformed ciphertext cannot be rejected individually
//! (silent evaluation decrypts nothing per report).

use fhe_prio3::config::{EXACT_ROW, SILENT_REPETITIONS, SilentCheck, TaskConfig};
use fhe_prio3::error::{Error, Result};
use fhe_prio3::field::Field;
use fhe_prio3::keys::{self, KeyLease, VerifyKey};
use fhe_prio3::layout::Layout;
use fhe_prio3::messages::{PublicMaterial, Report, ReportId};
use fhe_prio3::packed::{Codec, Expect};
use fhe_prio3::types::{AggregateResult, Measurement, MeasurementType, range_weights};
use fhe_prio3::verify::{Challenge, Circuit};
use openfhe_tbgv_rs::{Ciphertext, Context, SecretShare};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zeroize::Zeroize;

/// Smallest t with p^t >= Q * 2^bits, using exact integer arithmetic.
/// p<2^32, Q<2^64 and bits<=256 make the target <2^320. Before
/// termination the product is <2^352, so six 64-bit limbs cannot overflow.
/// This is the ideal predicate bound, not an encryption-security estimate.
pub fn repetitions_for_bound(p: u64, attempts: u64, bits: u32) -> Result<usize> {
    if Field::new(p).is_none() || attempts == 0 || !(128..=256).contains(&bits) {
        return Err(Error::Config("invalid prime, attempt budget or soundness target".into()));
    }
    let mut target = [0u64; 6];
    let word = (bits / 64) as usize;
    let shift = bits % 64;
    target[word] = attempts << shift;
    if shift != 0 {
        target[word + 1] = attempts >> (64 - shift);
    }
    let mut value = [0u64; 6];
    value[0] = 1;
    let mut repetitions = 0;
    while value.iter().rev().cmp(target.iter().rev()).is_lt() {
        let mut carry = 0u128;
        for limb in &mut value {
            let product = *limb as u128 * p as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        if carry != 0 {
            return Err(Error::Config("soundness-bound arithmetic overflow".into()));
        }
        repetitions += 1;
    }
    Ok(repetitions)
}

/// Explicit native-key candidate. Q is an assumed lifetime invalid-attempt
/// bound; enforcing it across deployments requires external admission accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeParameters {
    /// Count-only aggregate projection; never a separate validity flag.
    pub count_projection: bool,
    pub plain_mod: u64,
    pub invalid_attempts: u64,
    pub target_bits: u32,
    pub key_switch_digits: u32,
    pub groups: Option<usize>,
}
impl Default for NativeParameters {
    fn default() -> Self {
        Self {
            count_projection: false,
            plain_mod: 786433,
            invalid_attempts: 1_000_000,
            target_bits: 128,
            key_switch_digits: 5,
            groups: None,
        }
    }
}

/// A task of the paper's architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaperTask {
    cfg: TaskConfig,
    native: Option<NativeParameters>,
    row: usize,
}

impl PaperTask {
    /// The task with the most reports per verification ciphertext the
    /// check allows: the exact check's packing ([`TaskConfig::exact_shape`]),
    /// or for the randomised check `32768 / (8 · block)` with `block` the
    /// encoding length rounded up to a power of two.
    pub fn new(task_id: [u8; 32], measurement_type: MeasurementType, check: SilentCheck) -> Result<Self> {
        measurement_type.validate()?;
        match measurement_type {
            MeasurementType::Count | MeasurementType::Sum { .. } | MeasurementType::SumVec { .. } | MeasurementType::Histogram { .. } => {}
            _ => {
                return Err(Error::Config("the paper defines Count, Sum, SumVec and Histogram (§4.1)".into()));
            }
        }
        let mut cfg = match check {
            SilentCheck::Exact => TaskConfig::new_exact(task_id, measurement_type, 2),
            SilentCheck::Randomised => {
                let mut c = TaskConfig::new_silent(task_id, measurement_type, 2);
                c.repetitions = SILENT_REPETITIONS;
                let block = c.measurement_type.input_len().next_power_of_two();
                c.silent_batch_groups = EXACT_ROW / (c.repetitions.next_power_of_two() * block);
                c
            }
        };
        cfg.max_batch_size = Self::batch_bound(&cfg);
        let t = Self {
            cfg,
            native: None,
            row: EXACT_ROW,
        };
        t.check()?;
        Ok(t)
    }

    /// The same task with fewer reports per verification ciphertext (a
    /// power of two, at least 2): the packing ablation. Randomised check
    /// only; the exact check's packing is fixed by its shape.
    pub fn with_groups(mut self, groups: usize) -> Result<Self> {
        if self.cfg.exact_check() {
            return Err(Error::Config("the exact check's packing is fixed by its slot shape".into()));
        }
        self.cfg.silent_batch_groups = groups;
        self.check()?;
        Ok(self)
    }

    /// The largest batch the paper's correctness conditions allow (§4.5):
    /// `N < p` for Count and Histogram, `N·M < p` for Sum and each SumVec
    /// component, so no accepted admissible batch wraps modulo `p`.
    fn batch_bound(cfg: &TaskConfig) -> u64 {
        let p = cfg.plain_mod;
        let m = match &cfg.measurement_type {
            MeasurementType::Sum { max_measurement } | MeasurementType::SumVec { max_measurement, .. } => *max_measurement,
            _ => 1,
        };
        (p - 1) / m
    }

    fn check(&self) -> Result<()> {
        if self.native.is_some() {
            self.cfg.validate_native(self.row)?;
        } else {
            self.cfg.validate()?;
        }
        if self.cfg.silent_batch_groups < 2 {
            return Err(Error::Config(format!(
                "the encoding ({} slots) leaves no room for two reports per verification ciphertext",
                self.cfg.measurement_type.input_len()
            )));
        }
        let l = self.layout(self.row)?;
        if l.num_chunks != 1 {
            return Err(Error::Config("the encoding must fit one ciphertext per report".into()));
        }
        Ok(())
    }

    /// Native profile with task-specific field, soundness budget and key switch.
    pub fn new_native(task_id: [u8; 32], ty: MeasurementType, check: SilentCheck, profile: NativeParameters) -> Result<Self> {
        if !matches!(
            ty,
            MeasurementType::Count | MeasurementType::Sum { .. } | MeasurementType::SumVec { .. } | MeasurementType::Histogram { .. }
        ) {
            return Err(Error::Config("unsupported native task".into()));
        }
        if matches!(&ty, MeasurementType::SumVec {length,..} | MeasurementType::Histogram {length} if *length > EXACT_ROW/2) {
            return Err(Error::Config("native input exceeds the one-ciphertext study limit".into()));
        }
        if profile.count_projection && (ty != MeasurementType::Count || check != SilentCheck::Exact) {
            return Err(Error::Config("projection requires native exact Count".into()));
        }
        ty.validate()?;
        if ty.input_len() > EXACT_ROW / 2 || profile.key_switch_digits > 8 {
            return Err(Error::Config("native input or key-switching setting exceeds the bounded study domain".into()));
        }
        if Field::new(profile.plain_mod).is_none() || profile.invalid_attempts == 0 || profile.target_bits < 128 || profile.target_bits > 256 {
            return Err(Error::Config("need prime p<2^32, Q>=1 and a 128..256-bit global soundness target".into()));
        }
        let mut cfg = match check {
            SilentCheck::Exact => TaskConfig::new_exact(task_id, ty, 2),
            SilentCheck::Randomised => TaskConfig::new_silent(task_id, ty, 2),
        };
        cfg.plain_mod = profile.plain_mod;
        if check == SilentCheck::Randomised {
            cfg.repetitions = repetitions_for_bound(profile.plain_mod, profile.invalid_attempts, profile.target_bits)?;
        }
        cfg.max_batch_size = Self::batch_bound(&cfg);
        cfg.validate_native(EXACT_ROW)?;
        let ctx = Context::new_single(
            openfhe_tbgv_rs::Params {
                plain_mod: cfg.plain_mod,
                mult_depth: cfg.mult_depth() - if profile.count_projection { 2 } else { 0 },
                security_bits: cfg.security_bits,
            },
            profile.key_switch_digits,
        )?;
        if ctx.ring_dim() > 65536 {
            return Err(Error::Config("native study ring exceeds retained resource cap 65536".into()));
        }
        // Reject incompatible split-field batching, never force a ring dimension.
        if !(cfg.plain_mod - 1).is_multiple_of(2 * ctx.ring_dim() as u64) {
            return Err(Error::Config(
                "prime does not support field slots at the security-selected ring dimension".into(),
            ));
        }
        ctx.plaintext(&[1])?;
        let row = ctx.row_slots();
        let (_, classes, block) = if check == SilentCheck::Exact {
            cfg.exact_shape()
        } else {
            (1, cfg.repetitions.next_power_of_two(), cfg.measurement_type.input_len().next_power_of_two())
        };
        cfg.silent_batch_groups = row / (classes * block);
        if let Some(groups) = profile.groups {
            if check == SilentCheck::Exact && groups != cfg.silent_batch_groups && !matches!(cfg.measurement_type, MeasurementType::Count) {
                return Err(Error::Config("exact profile packing fixed by full slot shape".into()));
            }
            cfg.silent_batch_groups = groups;
        }
        let task = Self {
            cfg,
            native: Some(profile),
            row,
        };
        task.check()?;
        Ok(task)
    }
    pub fn native_parameters(&self) -> Option<&NativeParameters> {
        self.native.as_ref()
    }
    pub fn row_slots(&self) -> usize {
        self.row
    }
    pub fn layout(&self, row: usize) -> Result<Layout> {
        if row != self.row {
            return Err(Error::Config("context row does not match task profile".into()));
        }
        if self.native.is_some() {
            self.cfg.layout_native(row)
        } else {
            self.cfg.layout(row)
        }
    }
    pub fn make_context(&self) -> Result<Context> {
        if let Some(p) = &self.native {
            Ok(Context::new_single(
                openfhe_tbgv_rs::Params {
                    plain_mod: self.cfg.plain_mod,
                    mult_depth: self.mult_depth(),
                    security_bits: self.cfg.security_bits,
                },
                p.key_switch_digits,
            )?)
        } else {
            keys::make_context(&self.cfg)
        }
    }
    fn validate_context_identity(&self, ctx: &Context) -> Result<()> {
        if ctx.plain_mod() != self.cfg.plain_mod || ctx.is_single_mode()? != self.native.is_some() || ctx.mult_depth() < self.mult_depth() {
            return Err(Error::Config("context mode, field or capacity does not match task".into()));
        }
        self.layout(ctx.row_slots())?;
        if self.native.is_some() {
            let expected = self.make_context()?;
            if ctx.moduli()? != expected.moduli()?
                || ctx.key_num_parts()? != expected.key_num_parts()?
                || ctx.key_basis_moduli(openfhe_tbgv_rs::KeyBasis::PublicKey)? != expected.key_basis_moduli(openfhe_tbgv_rs::KeyBasis::PublicKey)?
                || ctx.key_basis_moduli(openfhe_tbgv_rs::KeyBasis::KeySwitch)? != expected.key_basis_moduli(openfhe_tbgv_rs::KeyBasis::KeySwitch)?
            {
                return Err(Error::Config("native context parameters do not match the explicit profile".into()));
            }
        }
        Ok(())
    }
    fn qualify_context(&self, ctx: &Context) -> Result<()> {
        self.validate_context_identity(ctx)?;
        if self.native.is_some() {
            openfhe_tbgv_rs::verify_single_rebuild_once(ctx, self.mult_depth())?;
        } else {
            openfhe_tbgv_rs::verify_rebuild_once(ctx, self.mult_depth())?;
        }
        Ok(())
    }
    pub fn check_kind(&self) -> SilentCheck {
        self.cfg.silent_check
    }
    pub fn measurement_type(&self) -> &MeasurementType {
        &self.cfg.measurement_type
    }
    /// Reports per verification ciphertext.
    pub fn groups(&self) -> usize {
        self.cfg.silent_batch_groups
    }
    /// Explicit operational admission limit, bounded by the no-wrap domain.
    /// A limit is not a certificate of ciphertext-noise capacity.
    pub fn with_batch_limit(mut self, limit: u64) -> Result<Self> {
        if limit == 0 || limit > Self::batch_bound(&self.cfg) {
            return Err(Error::Config("batch limit must be positive and within the arithmetic bound".into()));
        }
        self.cfg.max_batch_size = limit;
        self.check()?;
        Ok(self)
    }
    pub fn max_batch(&self) -> u64 {
        self.cfg.max_batch_size
    }
    pub fn mult_depth(&self) -> u32 {
        self.cfg.mult_depth() - if self.native.as_ref().is_some_and(|p| p.count_projection) { 2 } else { 0 }
    }
    /// The circuit configuration (layout, depth, parameters) this task runs.
    pub fn config(&self) -> &TaskConfig {
        &self.cfg
    }

    /// Element positions (of group 0) holding the task output after `A_T`:
    /// Count position 0; Histogram every bucket; Sum and SumVec the first
    /// position of each value, where the decoded value lands.
    fn output_positions(&self) -> Vec<usize> {
        match &self.cfg.measurement_type {
            MeasurementType::Histogram { length } => (0..*length).collect(),
            MeasurementType::SumVec { .. } => self.cfg.measurement_type.value_slots().expect("vector").iter().map(|&(s, _)| s).collect(),
            _ => vec![0],
        }
    }

    /// `(bits per value, weights)` of Sum and SumVec, whose `A_T` is a
    /// weighted sum (Eq. 5); `None` for Count and Histogram (identity).
    fn decoding(&self) -> Option<(usize, Vec<u64>)> {
        match &self.cfg.measurement_type {
            MeasurementType::Sum { max_measurement } | MeasurementType::SumVec { max_measurement, .. } => {
                let w = range_weights(*max_measurement);
                Some((w.len(), w))
            }
            _ => None,
        }
    }

    /// Upper bound of one output over `n` reports (§4.5).
    fn output_bound(&self, n: u64) -> u128 {
        match &self.cfg.measurement_type {
            MeasurementType::Sum { max_measurement } | MeasurementType::SumVec { max_measurement, .. } => n as u128 * *max_measurement as u128,
            _ => n as u128,
        }
    }
}

/// What the evaluator receives at setup: the context, the public key and
/// the evaluation keys (relinearisation and rotations). No secret.
pub type EvaluatorMaterial = PublicMaterial;

/// What a client receives at setup.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientMaterial {
    pub context: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// The collector's secret key (serialized). Zeroized on drop.
pub struct CollectorKey(Vec<u8>);

impl Drop for CollectorKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl CollectorKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self(b)
    }
}

/// Setup (paper §3): the collector generates `pk`, `sk` and the evaluation
/// keys; clients get `pk`, the evaluator `pk` and the evaluation keys, the
/// collector keeps `sk`. The same key-generation code as the ceremony, with
/// one party.
pub fn setup(task: &PaperTask) -> Result<(EvaluatorMaterial, ClientMaterial, CollectorKey)> {
    let ctx = task.make_context()?;
    let layout = task.layout(ctx.row_slots())?;
    let indices = layout.rotation_indices();
    let (pk, sk) = keys::keygen_step(&ctx, None)?;
    let pk_bytes = pk.serialize()?;
    let tag = pk.tag()?;
    let eval_mult_key = if task.native.is_some() {
        openfhe_tbgv_rs::EvalMultKey::single(&ctx, &sk)?.serialize()?
    } else {
        let r1 = keys::multkey_round1(&ctx, &sk, None)?;
        let r1_sum = keys::multkey_round1_sum(&ctx, &[r1], &tag)?;
        let r2 = keys::multkey_round2(&ctx, &sk, &r1_sum, &tag)?;
        keys::multkey_round2_sum(&ctx, &[r2], &tag)?
    };
    let mut rotation_keys = Vec::with_capacity(indices.len());
    for &i in &indices {
        rotation_keys.push(keys::rotkeys_step(&ctx, &sk, None, &[i], &tag)?);
    }
    let context = ctx.serialize()?;
    let evaluator = PublicMaterial {
        context: context.clone(),
        public_key: pk_bytes.clone(),
        joint_tag: tag,
        eval_mult_key,
        rotation_keys,
        rotation_indices: indices,
        attestations: Vec::new(),
    };
    let client = ClientMaterial { context, public_key: pk_bytes };
    Ok((evaluator, client, CollectorKey(sk.serialize()?)))
}

/// A client: the production encoding and encryption ([`fhe_prio3::Client`]),
/// placing its report in the group the evaluator assigned.
pub struct PaperClient {
    inner: fhe_prio3::Client,
}

impl PaperClient {
    pub fn new(task: &PaperTask, material: &ClientMaterial) -> Result<Self> {
        Ok(Self {
            inner: if task.native.is_some() {
                fhe_prio3::Client::new_native(task.cfg.clone(), &material.context, &material.public_key)?
            } else {
                fhe_prio3::Client::new(task.cfg.clone(), &material.context, &material.public_key)?
            },
        })
    }

    /// Encodes (Eq. 5 for Sum and SumVec, one-hot for Histogram) and
    /// encrypts `m` into `group`'s slots.
    pub fn report(&self, m: &Measurement, group: u32) -> Result<Report> {
        self.inner.shard_in_group(m, group)
    }
}

/// What the evaluator hands the collector: the decoded, validity-gated sum
/// of the batch (one ciphertext in the packed wire format) and the batch
/// size `N`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaperAggregate {
    pub task_id: [u8; 32],
    /// Reports admitted (valid or not): `N`.
    pub reports: u64,
    pub output: Vec<u8>,
}

/// The evaluator: admits reports, runs the validity circuit once per
/// verification ciphertext, and produces the aggregate.
pub struct PaperEvaluator {
    task: PaperTask,
    ctx: Context,
    field: Field,
    layout: Layout,
    circuit: Circuit,
    codec: Codec,
    /// Batch accumulator: reports restricted to their groups' element slots.
    acc: Option<Ciphertext>,
    pending: Vec<(usize, ReportId)>,
    used: BTreeSet<usize>,
    output: Option<Ciphertext>,
    admitted: u64,
    closed: bool,
    _lease: KeyLease,
}

impl PaperEvaluator {
    pub fn new(task: PaperTask, material: &EvaluatorMaterial) -> Result<Self> {
        let ctx = Context::deserialize(&material.context)?;
        if ctx.mult_depth() < task.mult_depth() {
            return Err(Error::Config("the material's context is shallower than the task's circuit".into()));
        }
        let layout = task.layout(ctx.row_slots())?;
        if material.rotation_indices != layout.rotation_indices() {
            return Err(Error::Config("the material's rotation keys are not this task's".into()));
        }
        // Bind the complete public parameter bases before loading any keys.
        task.validate_context_identity(&ctx)?;
        let lease = keys::install(&ctx, material)?;
        let pk = ctx.deserialize_public_key(&material.public_key)?;
        task.qualify_context(&ctx)?;
        let codec = Codec::new(&ctx, &pk, &material.public_key)?;
        let circuit = Circuit::new(&ctx, &layout)?;
        Ok(Self {
            field: task.cfg.field(),
            task,
            ctx,
            layout,
            circuit,
            codec,
            acc: None,
            pending: Vec::new(),
            used: BTreeSet::new(),
            output: None,
            admitted: 0,
            closed: false,
            _lease: lease,
        })
    }

    pub fn admitted(&self) -> u64 {
        self.admitted
    }
    /// Reports admitted into the open verification ciphertext.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Admits one report: structural checks (task, group, identifier, one
    /// fresh ciphertext in the packed format, batch bound), then the
    /// report is restricted to its group's slots and added to the open
    /// verification ciphertext. When every group is taken, or the report's
    /// group is, the circuit runs on the open one first.
    pub fn admit(&mut self, report: &Report) -> Result<()> {
        if self.closed {
            return Err(Error::Protocol("the batch is closed".into()));
        }
        if report.task_id != self.task.cfg.task_id {
            return Err(Error::Protocol("report for another task".into()));
        }
        if report.group as usize >= self.layout.groups {
            return Err(Error::Protocol(format!("group {} outside the layout", report.group)));
        }
        if report.chunks.len() != 1 {
            return Err(Error::Protocol("a report is exactly one ciphertext".into()));
        }
        if Report::compute_id(&report.task_id, report.group, &report.chunks) != report.report_id {
            return Err(Error::Protocol("report identifier does not match its content".into()));
        }
        if self.admitted >= self.task.max_batch() {
            return Err(Error::Protocol(format!(
                "batch full: {} reports is the largest batch for which the output cannot wrap modulo p",
                self.task.max_batch()
            )));
        }
        let ct = self
            .codec
            .decode(&report.chunks[0], Expect::Exactly(self.codec.fresh_meta()))
            .map_err(|e| Error::Protocol(format!("malformed ciphertext: {e}")))?;
        let group = report.group as usize;
        if self.used.contains(&group) {
            self.flush()?;
        }
        let masked = self.circuit.mask_to_group(&ct, 0, group)?;
        self.acc = Some(match self.acc.take() {
            None => masked,
            Some(a) => self.ctx.add(&a, &masked)?,
        });
        self.pending.push((group, report.report_id));
        self.used.insert(group);
        self.admitted += 1;
        if self.used.len() == self.layout.groups {
            self.flush()?;
        }
        Ok(())
    }

    /// Runs the validity circuit on the open verification ciphertext and
    /// adds its gated, decoded reports to the sum.
    /// A no-op when no report is pending.
    pub fn flush(&mut self) -> Result<()> {
        let Some(acc) = self.acc.take() else {
            return Ok(());
        };
        let reports = std::mem::take(&mut self.pending);
        self.used.clear();
        let groups: Vec<usize> = reports.iter().map(|&(g, _)| g).collect();
        // A_T (Sum, SumVec), once for the whole verification ciphertext: it
        // is linear and every report sits in its own group, so weighting
        // each value's bits (Eq. 5) and summing them over the value's
        // positions decodes every report at once; the value lands at its
        // first position. The window wraps within a group, never across.
        let decoded = match self.task.decoding() {
            None => None,
            // Native binary SumVec has A_T = identity. Skip its redundant
            // all-one weighting multiplication; the input group mask and
            // final output mask are still mandatory and remain unchanged.
            Some((1, ref weights)) if self.task.native.is_some() && weights == &[1] => None,
            Some((bits, weights)) => {
                let mut w = vec![0u64; self.layout.row];
                for &g in &groups {
                    for start in self.task.output_positions() {
                        for (j, &wj) in weights.iter().enumerate() {
                            w[self.layout.group_slot(g, start + j)] = wj % self.field.modulus();
                        }
                    }
                }
                let z = self.ctx.mult_plain(&acc, &self.ctx.plaintext(&w)?)?;
                Some(self.circuit.window_sum(z, bits, self.layout.element_stride())?)
            }
        };
        let y = if self.task.native.as_ref().is_some_and(|p| p.count_projection) {
            self.circuit.count_projection(&acc)?
        } else {
            let g = if self.task.cfg.exact_check() {
                self.circuit.exact_validity(&self.task.cfg, &self.field, std::slice::from_ref(&acc), &groups)?
            } else {
                // fresh coefficients for this batch, drawn after its reports
                // are fixed (paper §4.4)
                let key = VerifyKey::random();
                let ch = Challenge::derive_batch(&self.task.cfg, &self.field, &self.layout, &key, &reports);
                let t = self.circuit.report_terms(std::slice::from_ref(&acc), &ch)?;
                self.circuit.silent_validity(&self.circuit.class_sums(&t)?)?
            };
            self.ctx.mult(decoded.as_ref().unwrap_or(&acc), &g)?
        };
        self.output = Some(match self.output.take() {
            None => y,
            Some(o) => self.ctx.add(&o, &y)?,
        });
        Ok(())
    }

    /// Closes the batch: runs the circuit on the open verification
    /// ciphertext, folds every group into group 0 and keeps only the
    /// output positions (one plaintext multiplication), so the decrypted
    /// slots are the task output and zeros.
    pub fn finish(&mut self) -> Result<PaperAggregate> {
        if self.closed {
            return Err(Error::Protocol("the batch is closed".into()));
        }
        self.flush()?;
        let Some(out) = self.output.take() else {
            return Err(Error::Protocol("no report was admitted".into()));
        };
        self.closed = true;
        let mut keep = vec![0u64; self.layout.row];
        for pos in self.task.output_positions() {
            keep[self.layout.group_slot(0, pos)] = 1;
        }
        let out = self.ctx.mult_plain(&self.circuit.fold_all_groups(&out)?, &self.ctx.plaintext(&keep)?)?;
        Ok(PaperAggregate {
            task_id: self.task.cfg.task_id,
            reports: self.admitted,
            output: self.codec.encode(&out)?,
        })
    }
}

/// The decrypted task output over a batch of `reports` reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaperResult {
    pub aggregate: AggregateResult,
    pub reports: u64,
}

/// The collector: holds the secret key and decrypts aggregates.
pub struct PaperCollector {
    task: PaperTask,
    ctx: Context,
    layout: Layout,
    codec: Codec,
    sk: SecretShare,
}

impl PaperCollector {
    pub fn new(task: PaperTask, material: &ClientMaterial, key: &CollectorKey) -> Result<Self> {
        let ctx = Context::deserialize(&material.context)?;
        task.validate_context_identity(&ctx)?;
        let layout = task.layout(ctx.row_slots())?;
        let pk = ctx.deserialize_public_key(&material.public_key)?;
        let sk = ctx.deserialize_secret_share(key.as_bytes())?;
        if task.native.is_some() && sk.tag()? != pk.tag()? {
            return Err(Error::Config("collector secret key does not match the public key epoch".into()));
        }
        task.qualify_context(&ctx)?;
        let codec = Codec::new(&ctx, &pk, &material.public_key)?;
        Ok(Self { task, ctx, layout, codec, sk })
    }

    fn decrypt(&self, bytes: &[u8], what: &str) -> Result<Vec<u64>> {
        let ct = self
            .codec
            .decode(bytes, Expect::Any)
            .map_err(|e| Error::Protocol(format!("{what}: malformed ciphertext: {e}")))?;
        let level = ct.meta()?.level;
        if level != self.task.mult_depth() {
            return Err(Error::Protocol(format!(
                "{what}: at level {level}, the circuit ends at level {}",
                self.task.mult_depth()
            )));
        }
        if self.task.native.is_some() {
            Ok(self.sk.decrypt_single(&ct, self.layout.row)?)
        } else {
            let partial = self.sk.partial_decrypt(&ct, true)?;
            Ok(self.ctx.fuse(&[&partial], self.layout.row)?)
        }
    }

    /// Decrypts an aggregate. The decrypted row must be the task output and
    /// zeros (the evaluator's last mask leaves nothing else), and no output
    /// can exceed `N` (Count, Histogram) or `N·M` (Sum, SumVec), the bounds
    /// of §4.5; anything else is not an aggregate of this task.
    pub fn decrypt_aggregate(&self, agg: &PaperAggregate) -> Result<PaperResult> {
        if agg.task_id != self.task.cfg.task_id {
            return Err(Error::Protocol("aggregate for another task".into()));
        }
        if agg.reports > self.task.max_batch() {
            return Err(Error::Protocol("batch larger than the task allows".into()));
        }
        let slots = self.decrypt(&agg.output, "output")?;
        let positions = self.task.output_positions();
        let read: BTreeSet<usize> = positions.iter().map(|&p| self.layout.group_slot(0, p)).collect();
        if slots.iter().enumerate().any(|(s, &v)| !read.contains(&s) && v != 0) {
            return Err(Error::Protocol("output: data outside the output slots".into()));
        }
        let bound = self.task.output_bound(agg.reports);
        let values: Vec<u128> = positions.iter().map(|&p| slots[self.layout.group_slot(0, p)] as u128).collect();
        if let Some(v) = values.iter().find(|&&v| v > bound) {
            return Err(Error::Protocol(format!("output {v} exceeds its bound {bound} over {} reports", agg.reports)));
        }
        let aggregate = match self.task.measurement_type() {
            MeasurementType::Count => AggregateResult::Count(values[0] as u64),
            MeasurementType::Sum { .. } => AggregateResult::Sum(values[0]),
            MeasurementType::SumVec { .. } => AggregateResult::SumVec(values),
            MeasurementType::Histogram { .. } => AggregateResult::Histogram(values.iter().map(|&v| v as u64).collect()),
            _ => unreachable!("checked by PaperTask::new"),
        };
        Ok(PaperResult {
            aggregate,
            reports: agg.reports,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four tasks, both checks: shapes, depths, packing and the batch
    /// bounds of §4.5; other types and impossible packings refused.
    #[test]
    fn tasks_shapes_and_bounds() {
        let id = [3u8; 32];
        let t = |ty: MeasurementType, c: SilentCheck| PaperTask::new(id, ty, c);
        let e = t(MeasurementType::Count, SilentCheck::Exact).unwrap();
        assert_eq!((e.groups(), e.mult_depth(), e.max_batch()), (32768, 24, 786_432));
        let r = t(MeasurementType::Count, SilentCheck::Randomised).unwrap();
        assert_eq!((r.groups(), r.mult_depth()), (4096, 28));
        let s = t(MeasurementType::Sum { max_measurement: 100 }, SilentCheck::Randomised).unwrap();
        assert_eq!((s.groups(), s.max_batch()), (512, 7864)); // 7 bits -> block 8; 100 * 7864 < 786433
        assert!(100 * (s.max_batch() + 1) >= 786_433);
        let h = t(MeasurementType::Histogram { length: 3 }, SilentCheck::Exact).unwrap();
        assert_eq!((h.groups(), h.mult_depth(), h.max_batch()), (4096, 27, 786_432));
        let v = t(
            MeasurementType::SumVec {
                length: 100,
                max_measurement: 1,
            },
            SilentCheck::Randomised,
        )
        .unwrap();
        assert_eq!((v.groups(), v.mult_depth()), (32, 28));
        // the exact check cannot hold 100 binary coordinates below depth 29
        assert!(
            t(
                MeasurementType::SumVec {
                    length: 100,
                    max_measurement: 1
                },
                SilentCheck::Exact
            )
            .is_err()
        );
        assert!(
            t(
                MeasurementType::SumVec {
                    length: 10,
                    max_measurement: 1
                },
                SilentCheck::Exact
            )
            .is_ok()
        );
        assert!(t(MeasurementType::MultihotCountVec { length: 4, max_weight: 2 }, SilentCheck::Exact).is_err());
        assert!(t(MeasurementType::BoundedSumVec { bounds: vec![3, 5] }, SilentCheck::Randomised).is_err());
        // packing ablation
        assert_eq!(r.clone().with_groups(64).unwrap().groups(), 64);
        assert!(r.clone().with_groups(1).is_err());
        assert!(r.clone().with_groups(8192).is_err());
        assert!(e.clone().with_groups(64).is_err());
        // outputs and decoding
        assert_eq!(s.output_positions(), vec![0]);
        assert_eq!(s.decoding().unwrap(), (7, vec![1, 2, 4, 8, 16, 32, 37]));
        assert_eq!(v.output_positions(), (0..100).collect::<Vec<_>>());
        assert_eq!(h.output_positions(), vec![0, 1, 2]);
        assert!(h.decoding().is_none());
        let sv = t(
            MeasurementType::SumVec {
                length: 3,
                max_measurement: 15,
            },
            SilentCheck::Randomised,
        )
        .unwrap();
        assert_eq!(sv.output_positions(), vec![0, 4, 8]);
        assert_eq!(sv.output_bound(10), 150);
    }
}

#[cfg(test)]
mod native_profile_tests {
    use super::*;
    #[test]
    fn reject_invalid_security_contract_before_context_creation() {
        for profile in [
            NativeParameters {
                plain_mod: 65536,
                ..Default::default()
            },
            NativeParameters {
                invalid_attempts: 0,
                ..Default::default()
            },
            NativeParameters {
                target_bits: 127,
                ..Default::default()
            },
        ] {
            assert!(PaperTask::new_native([0; 32], MeasurementType::Count, SilentCheck::Randomised, profile).is_err());
        }
    }
}

#[cfg(test)]
mod native_binding_tests {
    use super::*;
    #[test]
    fn public_context_roundtrips_and_binds_the_full_parameter_profile() {
        let _serial = native_test_serial();
        let cases = [
            (MeasurementType::Count, 3),
            (MeasurementType::Count, 5),
            (MeasurementType::Sum { max_measurement: 100 }, 3),
            (MeasurementType::Histogram { length: 8 }, 3),
        ];
        for (ty, digits) in cases {
            let task = PaperTask::new_native(
                [0xA1; 32],
                ty,
                SilentCheck::Exact,
                NativeParameters {
                    key_switch_digits: digits,
                    ..Default::default()
                },
            )
            .unwrap();
            let context = task.make_context().unwrap();
            let context = Context::deserialize(&context.serialize().unwrap()).unwrap();
            task.validate_context_identity(&context).unwrap();
        }
        let task = PaperTask::new_native(
            [0xA1; 32],
            MeasurementType::Count,
            SilentCheck::Exact,
            NativeParameters {
                key_switch_digits: 3,
                ..Default::default()
            },
        )
        .unwrap();
        let other = PaperTask::new_native(
            [0xA1; 32],
            MeasurementType::Count,
            SilentCheck::Exact,
            NativeParameters {
                key_switch_digits: 5,
                ..Default::default()
            },
        )
        .unwrap();
        let context = other.make_context().unwrap();
        assert!(
            task.validate_context_identity(&context)
                .unwrap_err()
                .to_string()
                .contains("parameters do not match")
        );
    }
}

#[cfg(test)]
mod exact_soundness_bound_tests {
    use super::*;
    #[test]
    fn exact_repetitions_match_arbitrary_precision_boundary_oracle() {
        // Expected values generated with Python arbitrary-precision p**t.
        for (p, q, b, t) in [
            (3u64, 1u64, 128u32, 81usize),
            (3u64, 1000000u64, 129u32, 94usize),
            (3u64, 100000000u64, 128u32, 98usize),
            (3u64, 18446744073709551615u64, 255u32, 202usize),
            (3u64, 18446744073709551615u64, 256u32, 202usize),
            (5u64, 1u64, 128u32, 56usize),
            (5u64, 1000000u64, 129u32, 65usize),
            (5u64, 100000000u64, 128u32, 67usize),
            (5u64, 18446744073709551615u64, 255u32, 138usize),
            (5u64, 18446744073709551615u64, 256u32, 138usize),
            (17u64, 1u64, 128u32, 32usize),
            (17u64, 1000000u64, 129u32, 37usize),
            (17u64, 100000000u64, 128u32, 38usize),
            (17u64, 18446744073709551615u64, 255u32, 79usize),
            (17u64, 18446744073709551615u64, 256u32, 79usize),
            (65537u64, 1u64, 128u32, 8usize),
            (65537u64, 1000000u64, 129u32, 10usize),
            (65537u64, 100000000u64, 128u32, 10usize),
            (65537u64, 18446744073709551615u64, 255u32, 20usize),
            (65537u64, 18446744073709551615u64, 256u32, 20usize),
            (786433u64, 1u64, 128u32, 7usize),
            (786433u64, 1000000u64, 129u32, 8usize),
            (786433u64, 100000000u64, 128u32, 8usize),
            (786433u64, 18446744073709551615u64, 255u32, 17usize),
            (786433u64, 18446744073709551615u64, 256u32, 17usize),
            (4294967291u64, 1u64, 128u32, 5usize),
            (4294967291u64, 1000000u64, 129u32, 5usize),
            (4294967291u64, 100000000u64, 128u32, 5usize),
            (4294967291u64, 18446744073709551615u64, 255u32, 10usize),
            (4294967291u64, 18446744073709551615u64, 256u32, 11usize),
        ] {
            assert_eq!(repetitions_for_bound(p, q, b).unwrap(), t, "p={p} Q={q} B={b}");
        }
        assert!(repetitions_for_bound(65536, 1, 128).is_err());
        assert!(repetitions_for_bound(65537, 0, 128).is_err());
        assert!(repetitions_for_bound(65537, 1, 127).is_err());
    }
}

#[cfg(test)]
mod native_key_binding_tests {
    use super::*;
    #[test]
    fn wrong_native_secret_epoch_is_rejected_before_startup_decryption() {
        let _serial = native_test_serial();
        let task = PaperTask::new_native(
            [0xAC; 32],
            MeasurementType::Count,
            SilentCheck::Exact,
            NativeParameters {
                key_switch_digits: 3,
                ..Default::default()
            },
        )
        .unwrap();
        let ctx = task.make_context().unwrap();
        let (pk, _) = keys::keygen_step(&ctx, None).unwrap();
        let (_, wrong_sk) = keys::keygen_step(&ctx, None).unwrap();
        let material = ClientMaterial {
            context: ctx.serialize().unwrap(),
            public_key: pk.serialize().unwrap(),
        };
        let key = CollectorKey::from_bytes(wrong_sk.serialize().unwrap());
        let error = match PaperCollector::new(task, &material, &key) {
            Ok(_) => panic!("wrong epoch accepted"),
            Err(e) => e,
        };
        assert!(error.to_string().contains("public key epoch"));
    }
    #[test]
    fn invalid_sum_bound_is_rejected_without_division_by_zero() {
        assert!(PaperTask::new([0; 32], MeasurementType::Sum { max_measurement: 0 }, SilentCheck::Exact).is_err());
    }
}

#[cfg(test)]
fn native_test_serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
