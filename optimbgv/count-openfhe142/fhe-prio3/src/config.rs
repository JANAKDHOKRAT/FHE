//! Task configuration shared by clients, aggregators and the collector.

use crate::error::{Error, Result};
use crate::field::Field;
use crate::layout::{Layout, LayoutKind};
use crate::types::MeasurementType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default plaintext modulus for verdict mode: the largest 32-bit prime
/// congruent to 1 modulo 2^17, so SIMD packing works for ring dimensions up
/// to 65536.
pub const DEFAULT_PLAIN_MOD: u64 = 4_293_918_721;

/// Default plaintext modulus for silent mode: `3 * 2^18 + 1`, the smallest
/// prime congruent to 1 modulo 2^17. Its Fermat exponent `p - 1 = 3 * 2^18`
/// costs 20 multiplicative levels.
pub const SILENT_PLAIN_MOD: u64 = 786_433;

/// Default repetitions of the silent-mode check: `7 * log2(786433) = 137.1`
/// bits of soundness per submitted report, above the 128-bit target. Seven
/// repetitions use eight residue classes (depth 28 batched, 26 single-group,
/// both at ring dimension 65536 with five key-switching digits).
pub const SILENT_REPETITIONS: usize = 7;

/// Multiplicative depth of the verdict-mode verification circuit:
/// `x(x-1)` (1), multiplication by the check coefficients (2), multiplication
/// by the masked aggregator randomness (3).
pub const VERDICT_CIRCUIT_DEPTH: u32 = 3;

/// Slots per row at the ring dimension (65536) of every silent-mode task
/// at 128-bit security: the row the exact check's packing is sized for.
pub const EXACT_ROW: usize = 32768;

/// How the aggregators use the result of the validity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMode {
    /// Two message rounds per report; the aggregators learn accept/reject.
    /// Depth 3, ring dimension 32768 at 128-bit security.
    Verdict,
    /// No per-report messages and no per-report decryption. Each report is
    /// multiplied by a homomorphically computed validity bit and only the
    /// batch sums are ever decrypted. Depth `2 + fermat + log2(classes) + 1`,
    /// ring dimension 65536 at 128-bit security with the default modulus.
    Silent,
}

/// Which validity check silent mode evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SilentCheck {
    /// `repetitions` random linear combinations of the residuals, each
    /// tested for zero (Fermat): soundness `p^-repetitions` per submitted
    /// report, depth independent of the measurement's length.
    #[default]
    Randomised,
    /// Every residual tested for zero on its own and the flags multiplied
    /// (`prod_l (1 - e_l^(p-1))`): no soundness error, depth growing with
    /// `log2` of the slots one report occupies ([`TaskConfig::exact_shape`]).
    /// Batched layout only, one report per `row / silent_batch_groups`
    /// slots; no moments.
    Exact,
}

/// Whether reports must be signed by a registered client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthPolicy {
    /// Anyone may submit. Only appropriate when the transport authenticates
    /// clients by other means.
    Open,
    /// Every report carries an Ed25519 signature by a key the aggregator's
    /// registry accepts, and each key may submit at most this many reports
    /// per batch (attempts count, whether or not they are accepted).
    Required { max_reports_per_client_per_batch: u32 },
}

/// What one collector may receive from a batch. Declared in the task, so
/// it is part of the task digest, the challenge binding and the material
/// attestation: it cannot change after the batch opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorPolicy {
    /// Elements of the aggregate this collector receives, ascending and
    /// distinct. Every element must be listed by at least one collector.
    pub elements: Vec<usize>,
    /// Whether it also receives the second moments of *its* elements
    /// (requires `TaskConfig::moments` and at least two elements).
    pub moments: bool,
    /// X25519 public key: every aggregator seals its share for this
    /// collector to it, so the leader relaying shares reads none of them.
    pub seal_key: [u8; 32],
}

/// Who holds shares of the joint decryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KeyTopology {
    /// `num_aggregators >= 2` aggregators, n-of-n; collectors hold no key.
    #[default]
    Aggregators,
    /// One aggregator and the collector, 2-of-2. The aggregator does every
    /// homomorphic computation; the collector holds the second key share,
    /// takes part in the key ceremony and in the gated release
    /// (`gate.rs`), and is the only party that ever fuses a decryption of
    /// data. Neither learns anything alone: the aggregator sees only
    /// ciphertexts and values masked by the collector, the collector only
    /// what the gates release. Silent mode only; one collector, no release
    /// policies.
    AggregatorAndCollector,
}

/// How a client sends its measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Upload {
    /// The client encrypts its encoded measurement under the joint key and
    /// every aggregator receives the same ciphertexts (one fresh encryption
    /// per chunk, 22 MiB at the silent-mode parameters).
    #[default]
    Ciphertext,
    /// Prio3's upload: the client splits its encoded measurement into
    /// additive shares modulo `p`, one per key party (party 0's explicit,
    /// the others' expanded from 32-byte seeds), and seals each share to
    /// that party's X25519 key in [`TaskConfig::upload_keys`]. A report is
    /// a few hundred bytes and the client runs no homomorphic encryption.
    /// The key parties encrypt their shares of a whole verification batch
    /// themselves, each as one contribution proven well formed
    /// (`shares.rs`), and the validity circuit runs on their sum. Silent
    /// mode with a batched layout only.
    Shares,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskConfig {
    /// 32-byte task identifier chosen by the deployment.
    pub task_id: [u8; 32],
    pub measurement_type: MeasurementType,
    pub mode: VerificationMode,
    pub auth: AuthPolicy,
    /// Number of aggregators holding key shares (n-of-n). At least 2.
    pub num_aggregators: usize,
    /// Independent repetitions of the random-linear-combination check.
    pub repetitions: usize,
    /// Aggregators refuse to release an aggregate over fewer reports.
    pub min_batch_size: usize,
    /// Upper bound on reports admitted per batch; must be below `p`.
    pub max_batch_size: u64,
    /// Upper bound on the serialized size of a report; 0 means "derive from
    /// the size of a fresh ciphertext".
    pub max_report_bytes: usize,
    pub plain_mod: u64,
    pub security_bits: u32,
    /// Silent mode: reports verified together in one ciphertext (a power of
    /// two; 1 disables batching). The Fermat chain is shared by all of them.
    pub silent_batch_groups: usize,
    /// Post-validation computation: also accumulate the second moments
    /// `sum v_a v_b` of the SumVec values over valid reports, so the
    /// collector can solve a linear regression (last value = target) without
    /// ever seeing a record. Requires `SumVec` or `BoundedSumVec`.
    pub moments: bool,
    /// Release policies. Empty: one collector (id 0) receives everything,
    /// unsealed. Otherwise collector `c` receives exactly what
    /// `collectors[c]` says, sealed to its key, and nothing is ever
    /// partially decrypted that no policy names.
    pub collectors: Vec<CollectorPolicy>,
    /// Who holds key shares (absent in task files from before it existed:
    /// the aggregators).
    #[serde(default)]
    pub key_topology: KeyTopology,
    /// Small-cell suppression: every released cell (histogram bucket,
    /// multihot position, count) whose value is below this is zeroed under
    /// encryption before anyone decrypts it, and the collector learns only
    /// that it was suppressed. 0 disables. Silent mode, `Count`, `Histogram`
    /// and `MultihotCountVec`, no moments, no release policies. With
    /// suppression the valid and admitted report counts are withheld from
    /// the collector (with them it would recover the suppressed total).
    #[serde(default)]
    pub min_cell_count: u64,
    /// How clients send their measurements (absent in task files from
    /// before it existed: ciphertexts).
    #[serde(default)]
    pub upload: Upload,
    /// [`Upload::Shares`]: every key party's X25519 public key, in party
    /// order (aggregators, then the key-holding collector). Clients seal
    /// party `i`'s input share to `upload_keys[i]`. Empty otherwise.
    #[serde(default)]
    pub upload_keys: Vec<[u8; 32]>,
    /// Verdict mode: every report carries, per chunk, a zero-knowledge
    /// proof that the chunk is a public-key encryption with short randomness
    /// ([`crate::wfe`], [`crate::messages::ProvenReport`]), and the
    /// aggregators evaluate the proven effective ciphertext `2C`. Without
    /// it a client chooses the noise of what the aggregators decrypt for
    /// it and learns, from the verdict, whether that decryption failed: a
    /// decryption-failure oracle of the kind the IND-CPA^D key-recovery
    /// attacks on exact and threshold FHE use (Checri et al., ePrint
    /// 2024/116; Cheon et al., ePrint 2024/127). Absent in task files from
    /// before it existed (off). Verdict mode with ciphertext upload only.
    #[serde(default)]
    pub client_proofs: bool,
    /// Silent mode: the randomised check (default) or the exact one
    /// ([`SilentCheck`]). Absent in task files from before it existed
    /// (randomised).
    #[serde(default)]
    pub silent_check: SilentCheck,
}

/// The configuration fields that existed before `key_topology` and
/// `min_cell_count`, in declaration order: their postcard encoding is the
/// binding of every task that leaves the new fields at their defaults, so
/// existing tasks keep their digest, their attestations and their reports.
#[derive(Serialize)]
struct LegacyBinding<'a> {
    task_id: &'a [u8; 32],
    measurement_type: &'a MeasurementType,
    mode: &'a VerificationMode,
    auth: &'a AuthPolicy,
    num_aggregators: &'a usize,
    repetitions: &'a usize,
    min_batch_size: &'a usize,
    max_batch_size: &'a u64,
    max_report_bytes: &'a usize,
    plain_mod: &'a u64,
    security_bits: &'a u32,
    silent_batch_groups: &'a usize,
    moments: &'a bool,
    collectors: &'a Vec<CollectorPolicy>,
}

/// A task file written before `key_topology` and `min_cell_count`
/// existed (postcard, field by field).
#[derive(Deserialize)]
struct LegacyTaskConfig {
    task_id: [u8; 32],
    measurement_type: MeasurementType,
    mode: VerificationMode,
    auth: AuthPolicy,
    num_aggregators: usize,
    repetitions: usize,
    min_batch_size: usize,
    max_batch_size: u64,
    max_report_bytes: usize,
    plain_mod: u64,
    security_bits: u32,
    silent_batch_groups: usize,
    moments: bool,
    collectors: Vec<CollectorPolicy>,
}

/// A task file written before `upload` and `upload_keys` existed
/// (postcard, field by field).
#[derive(Deserialize)]
struct TaskConfigV2 {
    task_id: [u8; 32],
    measurement_type: MeasurementType,
    mode: VerificationMode,
    auth: AuthPolicy,
    num_aggregators: usize,
    repetitions: usize,
    min_batch_size: usize,
    max_batch_size: u64,
    max_report_bytes: usize,
    plain_mod: u64,
    security_bits: u32,
    silent_batch_groups: usize,
    moments: bool,
    collectors: Vec<CollectorPolicy>,
    key_topology: KeyTopology,
    min_cell_count: u64,
}

/// A task file written before `client_proofs` existed (postcard, field by
/// field).
#[derive(Deserialize)]
struct TaskConfigV3 {
    task_id: [u8; 32],
    measurement_type: MeasurementType,
    mode: VerificationMode,
    auth: AuthPolicy,
    num_aggregators: usize,
    repetitions: usize,
    min_batch_size: usize,
    max_batch_size: u64,
    max_report_bytes: usize,
    plain_mod: u64,
    security_bits: u32,
    silent_batch_groups: usize,
    moments: bool,
    collectors: Vec<CollectorPolicy>,
    key_topology: KeyTopology,
    min_cell_count: u64,
    upload: Upload,
    upload_keys: Vec<[u8; 32]>,
}

/// A task file written before `silent_check` existed (postcard, field by
/// field).
#[derive(Deserialize)]
struct TaskConfigV4 {
    task_id: [u8; 32],
    measurement_type: MeasurementType,
    mode: VerificationMode,
    auth: AuthPolicy,
    num_aggregators: usize,
    repetitions: usize,
    min_batch_size: usize,
    max_batch_size: u64,
    max_report_bytes: usize,
    plain_mod: u64,
    security_bits: u32,
    silent_batch_groups: usize,
    moments: bool,
    collectors: Vec<CollectorPolicy>,
    key_topology: KeyTopology,
    min_cell_count: u64,
    upload: Upload,
    upload_keys: Vec<[u8; 32]>,
    client_proofs: bool,
}

/// Separates the legacy binding from the extension in tasks that use it.
const BINDING_EXTENSION: &[u8] = b"fhe-prio3/2 task extension";

/// Separates the upload extension (`upload`, `upload_keys`) in tasks whose
/// upload is not the default.
const BINDING_UPLOAD_EXTENSION: &[u8] = b"fhe-prio3/3 upload extension";

/// Separates the client-proofs extension in tasks that require proofs.
const BINDING_PROOFS_EXTENSION: &[u8] = b"fhe-prio3/4 client proofs extension";

/// Separates the silent-check extension in tasks that use the exact check.
const BINDING_CHECK_EXTENSION: &[u8] = b"fhe-prio3/5 silent check extension";

/// Whether an X25519 public key is a point a Diffie-Hellman with it can
/// be contributory for (not one of the small-order points, for which every
/// shared secret is the identity whatever the client's secret).
fn upload_key_usable(key: &[u8; 32]) -> bool {
    let probe = x25519_dalek::StaticSecret::from([0x5Au8; 32]);
    probe.diffie_hellman(&x25519_dalek::PublicKey::from(*key)).was_contributory()
}

impl TaskConfig {
    /// Verdict mode with 128-bit soundness (`4 * 32 = 128` bits).
    pub fn new(task_id: [u8; 32], measurement_type: MeasurementType, num_aggregators: usize) -> Self {
        Self {
            task_id,
            measurement_type,
            mode: VerificationMode::Verdict,
            auth: AuthPolicy::Open,
            num_aggregators,
            repetitions: 4,
            min_batch_size: 1,
            max_batch_size: 1 << 20,
            max_report_bytes: 0,
            plain_mod: DEFAULT_PLAIN_MOD,
            security_bits: 128,
            silent_batch_groups: 1,
            moments: false,
            collectors: Vec::new(),
            key_topology: KeyTopology::Aggregators,
            min_cell_count: 0,
            upload: Upload::Ciphertext,
            upload_keys: Vec::new(),
            client_proofs: false,
            silent_check: SilentCheck::Randomised,
        }
    }

    /// Decodes a task file (postcard): the current format, or one written
    /// before `silent_check`, `client_proofs`, `upload`, or `key_topology`
    /// and `min_cell_count` existed (read with the missing fields at their
    /// defaults, which keeps its digest).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if let Ok(c) = crate::messages::decode::<TaskConfig>(bytes) {
            return Ok(c);
        }
        if let Ok(v) = crate::messages::decode::<TaskConfigV4>(bytes) {
            return Ok(Self {
                task_id: v.task_id,
                measurement_type: v.measurement_type,
                mode: v.mode,
                auth: v.auth,
                num_aggregators: v.num_aggregators,
                repetitions: v.repetitions,
                min_batch_size: v.min_batch_size,
                max_batch_size: v.max_batch_size,
                max_report_bytes: v.max_report_bytes,
                plain_mod: v.plain_mod,
                security_bits: v.security_bits,
                silent_batch_groups: v.silent_batch_groups,
                moments: v.moments,
                collectors: v.collectors,
                key_topology: v.key_topology,
                min_cell_count: v.min_cell_count,
                upload: v.upload,
                upload_keys: v.upload_keys,
                client_proofs: v.client_proofs,
                silent_check: SilentCheck::Randomised,
            });
        }
        if let Ok(v) = crate::messages::decode::<TaskConfigV3>(bytes) {
            return Ok(Self {
                task_id: v.task_id,
                measurement_type: v.measurement_type,
                mode: v.mode,
                auth: v.auth,
                num_aggregators: v.num_aggregators,
                repetitions: v.repetitions,
                min_batch_size: v.min_batch_size,
                max_batch_size: v.max_batch_size,
                max_report_bytes: v.max_report_bytes,
                plain_mod: v.plain_mod,
                security_bits: v.security_bits,
                silent_batch_groups: v.silent_batch_groups,
                moments: v.moments,
                collectors: v.collectors,
                key_topology: v.key_topology,
                min_cell_count: v.min_cell_count,
                upload: v.upload,
                upload_keys: v.upload_keys,
                client_proofs: false,
                silent_check: SilentCheck::Randomised,
            });
        }
        if let Ok(v) = crate::messages::decode::<TaskConfigV2>(bytes) {
            return Ok(Self {
                task_id: v.task_id,
                measurement_type: v.measurement_type,
                mode: v.mode,
                auth: v.auth,
                num_aggregators: v.num_aggregators,
                repetitions: v.repetitions,
                min_batch_size: v.min_batch_size,
                max_batch_size: v.max_batch_size,
                max_report_bytes: v.max_report_bytes,
                plain_mod: v.plain_mod,
                security_bits: v.security_bits,
                silent_batch_groups: v.silent_batch_groups,
                moments: v.moments,
                collectors: v.collectors,
                key_topology: v.key_topology,
                min_cell_count: v.min_cell_count,
                upload: Upload::Ciphertext,
                upload_keys: Vec::new(),
                client_proofs: false,
                silent_check: SilentCheck::Randomised,
            });
        }
        let l: LegacyTaskConfig = crate::messages::decode(bytes)?;
        Ok(Self {
            task_id: l.task_id,
            measurement_type: l.measurement_type,
            mode: l.mode,
            auth: l.auth,
            num_aggregators: l.num_aggregators,
            repetitions: l.repetitions,
            min_batch_size: l.min_batch_size,
            max_batch_size: l.max_batch_size,
            max_report_bytes: l.max_report_bytes,
            plain_mod: l.plain_mod,
            security_bits: l.security_bits,
            silent_batch_groups: l.silent_batch_groups,
            moments: l.moments,
            collectors: l.collectors,
            key_topology: KeyTopology::Aggregators,
            min_cell_count: 0,
            upload: Upload::Ciphertext,
            upload_keys: Vec::new(),
            client_proofs: false,
            silent_check: SilentCheck::Randomised,
        })
    }

    /// Silent mode with one aggregator and the collector holding the two
    /// key shares ([`KeyTopology::AggregatorAndCollector`]).
    pub fn new_split_key(task_id: [u8; 32], measurement_type: MeasurementType) -> Self {
        let mut c = Self::new_silent(task_id, measurement_type, 1);
        c.key_topology = KeyTopology::AggregatorAndCollector;
        c
    }

    /// Parties holding key shares: the aggregators, plus the collector in
    /// [`KeyTopology::AggregatorAndCollector`] (party index 1).
    pub fn num_key_parties(&self) -> usize {
        match self.key_topology {
            KeyTopology::Aggregators => self.num_aggregators,
            KeyTopology::AggregatorAndCollector => self.num_aggregators + 1,
        }
    }

    /// The same task with [`Self::client_proofs`] on.
    pub fn with_client_proofs(mut self) -> Self {
        self.client_proofs = true;
        self
    }

    /// Whether clients upload secret shares ([`Upload::Shares`]).
    pub fn shares_upload(&self) -> bool {
        self.upload == Upload::Shares
    }

    /// Whether the collector holds a key share.
    pub fn collector_holds_key(&self) -> bool {
        self.key_topology == KeyTopology::AggregatorAndCollector
    }

    /// Party index of the key-holding collector.
    pub fn collector_party(&self) -> Option<usize> {
        self.collector_holds_key().then_some(self.num_aggregators)
    }

    /// Whether releases go through the gated pipeline (`gate.rs`): with a
    /// key-holding collector (the batch-size gate runs under encryption),
    /// or with small-cell suppression.
    pub fn gated(&self) -> bool {
        self.collector_holds_key() || self.min_cell_count > 0
    }

    /// Multiplicative depth of the gated release after the refresh (which
    /// restarts every refreshed value at the top of the chain): the
    /// product trees of the batch-size gate (`min_batch_size` linear
    /// factors and one random factor per aggregator) and of the cell gate
    /// (`min_cell_count` factors and the random factors), then the
    /// release `X * Z_v * Z_c`.
    pub fn gate_depth(&self) -> u32 {
        let tree = |len: u64| if len <= 1 { 0 } else { 64 - (len - 1).leading_zeros() };
        let factors = self.num_aggregators as u64;
        let zv = if self.collector_holds_key() {
            tree(self.min_batch_size as u64 + factors)
        } else {
            0
        };
        let zc = if self.min_cell_count > 0 { tree(self.min_cell_count + factors) } else { 0 };
        let gates = [zv, zc].iter().filter(|&&d| d > 0).count() as u32;
        zv.max(zc) + gates
    }

    /// Number of collectors a batch is released to.
    pub fn num_collectors(&self) -> usize {
        self.collectors.len().max(1)
    }

    /// Elements collector `c` receives (all of them without policies).
    pub fn collector_elements(&self, c: usize) -> Result<Vec<usize>> {
        if self.collectors.is_empty() {
            if c != 0 {
                return Err(Error::Config("task has a single collector, id 0".into()));
            }
            return Ok((0..self.measurement_type.num_elements()).collect());
        }
        self.collectors
            .get(c)
            .map(|p| p.elements.clone())
            .ok_or_else(|| Error::Config(format!("no collector {c} in the task")))
    }

    /// Whether collector `c` receives second moments.
    pub fn collector_moments(&self, c: usize) -> bool {
        if self.collectors.is_empty() {
            self.moments
        } else {
            self.moments && self.collectors.get(c).is_some_and(|p| p.moments)
        }
    }

    /// Visibility class of each encoded slot: the set of collectors (as a
    /// bitmask) allowed to see it. Slots outside every element (constraint
    /// slots) go to the collectors that see every element.
    fn slot_classes(&self) -> Vec<u128> {
        let t = &self.measurement_type;
        let m = t.input_len();
        let n = self.num_collectors();
        let mut classes = vec![0u128; m];
        let full: u128 = if self.collectors.is_empty() {
            1
        } else {
            let mut mask = 0u128;
            for (c, p) in self.collectors.iter().enumerate() {
                if p.elements.len() == t.num_elements() {
                    mask |= 1 << c;
                }
            }
            mask
        };
        let mut owned = vec![false; m];
        for e in 0..t.num_elements() {
            let mask: u128 = if self.collectors.is_empty() {
                1
            } else {
                (0..n)
                    .filter(|&c| self.collectors[c].elements.contains(&e))
                    .fold(0u128, |acc, c| acc | (1 << c))
            };
            for i in t.element_slots(e) {
                classes[i] = mask;
                owned[i] = true;
            }
        }
        for i in 0..m {
            if !owned[i] {
                classes[i] = full;
            }
        }
        classes
    }

    /// Slot indices at which the visibility class changes: chunk cuts. A
    /// chunk then lies entirely inside one class, so releasing to a
    /// collector is releasing whole chunks, at no homomorphic cost.
    pub fn chunk_cuts(&self) -> Vec<usize> {
        let classes = self.slot_classes();
        (1..classes.len()).filter(|&i| classes[i] != classes[i - 1]).collect()
    }

    /// Collector bitmask (bit `c` = collector `c` sees it) of chunk `k`.
    pub fn chunk_visibility(&self, layout: &Layout, k: usize) -> u128 {
        let classes = self.slot_classes();
        classes[layout.chunk_range(k).start]
    }

    /// Chunks released to collector `c`.
    pub fn collector_chunks(&self, layout: &Layout, c: usize) -> Vec<usize> {
        let classes = self.slot_classes();
        (0..layout.num_chunks).filter(|&k| classes[layout.chunk_range(k).start] >> c & 1 == 1).collect()
    }

    /// Value pairs `(a <= b)`, as indices into the type's value list, whose
    /// second moments collector `c` receives, in accumulator order.
    pub fn collector_moment_pairs(&self, c: usize) -> Result<Vec<(usize, usize)>> {
        if !self.collector_moments(c) {
            return Ok(Vec::new());
        }
        let elems = self.collector_elements(c)?;
        let n = self.measurement_type.num_elements();
        let mut out = Vec::new();
        for a in 0..n {
            for b in a..n {
                if elems.contains(&a) && elems.contains(&b) {
                    out.push((a, b));
                }
            }
        }
        Ok(out)
    }

    /// Width of the widest moment piece (all pieces are plain binary), whose
    /// square bounds every product of two pieces and of two digits. `None`
    /// when the type has no values.
    fn widest_value(&self) -> Option<u32> {
        self.measurement_type.moment_pieces()?.iter().map(|p| p.bits).max()
    }

    /// Digit width `D` of the second-moment decomposition: the largest
    /// `D <= widest` with `(2^min(D, widest) - 1)^2 * max_batch_size <= p - 1`.
    /// Every accumulator slot sums at most `max_batch_size` products of two
    /// digits of at most `D` bits, so it never reaches `p` and the
    /// collector recombines the exact integer moments. When the widest
    /// value's square already fits, `D = widest` and each value is a single
    /// digit. `None` when moments are off or the type has no values.
    pub fn moment_digit_bits(&self) -> Option<u32> {
        if !self.moments {
            return None;
        }
        let w = self.widest_value()?;
        (1..=w).rev().find(|&d| {
            let m = (1u128 << d) - 1;
            m * m * self.max_batch_size as u128 <= (self.plain_mod - 1) as u128
        })
    }

    /// Silent mode with 137-bit soundness (`7 * log2(786433)`, above the
    /// 128-bit target), batched with 64 groups: depth 28, ring dimension
    /// 65536 with five key-switching digits (depth 26 for a single group,
    /// also 65536 with five digits). Seven repetitions occupy eight residue
    /// classes, the same as eight would. `repetitions = 4` gives 78 bits at
    /// depth 27 (25 single-group); measured with `simulate` (spec §5), it
    /// saves 2 to 14% of aggregator time and 17% of rotation-key size.
    pub fn new_silent(task_id: [u8; 32], measurement_type: MeasurementType, num_aggregators: usize) -> Self {
        let mut c = Self::new(task_id, measurement_type, num_aggregators);
        c.mode = VerificationMode::Silent;
        c.repetitions = SILENT_REPETITIONS;
        c.plain_mod = SILENT_PLAIN_MOD;
        c.max_batch_size = 1 << 16;
        c.silent_batch_groups = 64;
        c
    }

    /// Silent mode with the exact check ([`SilentCheck::Exact`], Eq. 9 of
    /// the paper): every residual tested on its own, no soundness error.
    /// One report per [`Self::exact_shape`] slots of a row of 32768 (ring
    /// dimension 65536, which every exact task's depth of 24 to 28 needs at
    /// 128-bit security; [`Self::layout`] refuses any other row). Fails
    /// validation when the measurement's slots take the chain past depth 28.
    pub fn new_exact(task_id: [u8; 32], measurement_type: MeasurementType, num_aggregators: usize) -> Self {
        let mut c = Self::new_silent(task_id, measurement_type, num_aggregators);
        c.silent_check = SilentCheck::Exact;
        c.repetitions = 1;
        let (_, classes, block) = c.exact_shape();
        c.silent_batch_groups = (EXACT_ROW / (classes * block)).max(1);
        c
    }

    /// Whether silent mode runs the exact check.
    pub fn exact_check(&self) -> bool {
        self.mode == VerificationMode::Silent && self.silent_check == SilentCheck::Exact
    }

    /// Slot shape of one report under the exact check: `(chunks, classes,
    /// block)`. Chunks are cut only where the visibility class changes;
    /// `block` is the longest chunk rounded up to a power of two (element
    /// positions per report); `classes` is the number of residue classes
    /// the residuals need (one per chunk for the bit residuals, one per
    /// linear constraint) rounded up to a power of two. One report
    /// occupies `classes * block` slots, and the product of its zero tests
    /// costs `log2(classes * block)` levels.
    pub fn exact_shape(&self) -> (usize, usize, usize) {
        let n = self.measurement_type.input_len();
        let mut bounds = self.chunk_cuts();
        bounds.push(n);
        let mut start = 0usize;
        let mut longest = 0usize;
        for &end in &bounds {
            longest = longest.max(end - start);
            start = end;
        }
        let chunks = bounds.len();
        let classes = (chunks + self.measurement_type.linear_constraints().len()).next_power_of_two();
        (chunks, classes, longest.next_power_of_two())
    }

    pub fn validate(&self) -> Result<Field> {
        self.validate_with_depth_cap(28)
    }
    fn validate_with_depth_cap(&self, depth_cap: u32) -> Result<Field> {
        self.measurement_type.validate()?;
        if self.silent_check == SilentCheck::Exact {
            if self.mode != VerificationMode::Silent {
                return Err(Error::Config("the exact check is a silent-mode check".into()));
            }
            if self.repetitions != 1 {
                return Err(Error::Config("the exact check has no repetitions: set repetitions to 1".into()));
            }
            if self.moments {
                return Err(Error::Config("the exact check does not compute second moments".into()));
            }
            let (_, classes, block) = self.exact_shape();
            if self.silent_batch_groups < 2 || self.silent_batch_groups * classes * block != EXACT_ROW {
                return Err(Error::Config(format!(
                    "the exact check packs one report per {} slots: silent_batch_groups must be {}",
                    classes * block,
                    EXACT_ROW / (classes * block)
                )));
            }
        }
        match self.key_topology {
            KeyTopology::Aggregators if self.num_aggregators < 2 => {
                return Err(Error::Config(
                    "at least two aggregators are required (or one aggregator with KeyTopology::AggregatorAndCollector)".into(),
                ));
            }
            KeyTopology::AggregatorAndCollector => {
                if self.num_aggregators != 1 {
                    return Err(Error::Config("KeyTopology::AggregatorAndCollector has exactly one aggregator".into()));
                }
                if self.mode != VerificationMode::Silent {
                    return Err(Error::Config(
                        "KeyTopology::AggregatorAndCollector requires silent mode (verdict mode decrypts per report)".into(),
                    ));
                }
                if !self.collectors.is_empty() {
                    return Err(Error::Config(
                        "KeyTopology::AggregatorAndCollector has one collector: no release policies".into(),
                    ));
                }
            }
            _ => {}
        }
        if self.min_cell_count > 0 {
            if self.mode != VerificationMode::Silent {
                return Err(Error::Config("small-cell suppression requires silent mode".into()));
            }
            if self.measurement_type.cell_slots().is_none() {
                return Err(Error::Config(
                    "small-cell suppression is defined for Count, Histogram and MultihotCountVec (one slot per cell)".into(),
                ));
            }
            if self.moments || !self.collectors.is_empty() {
                return Err(Error::Config("small-cell suppression excludes moments and release policies".into()));
            }
            if self.min_cell_count < 2 || self.min_cell_count > self.max_batch_size {
                return Err(Error::Config("min_cell_count must be 0 (off) or in 2..=max_batch_size".into()));
            }
        }
        match self.upload {
            Upload::Ciphertext if !self.upload_keys.is_empty() => {
                return Err(Error::Config("upload_keys are only used with Upload::Shares".into()));
            }
            Upload::Ciphertext => {}
            Upload::Shares => {
                if self.mode != VerificationMode::Silent || self.silent_batch_groups < 2 {
                    return Err(Error::Config(
                        "Upload::Shares requires silent mode with a batched layout (silent_batch_groups >= 2)".into(),
                    ));
                }
                if self.upload_keys.len() != self.num_key_parties() {
                    return Err(Error::Config(format!(
                        "Upload::Shares needs one upload key per key party: {} given, {} key parties",
                        self.upload_keys.len(),
                        self.num_key_parties()
                    )));
                }
                for (i, k) in self.upload_keys.iter().enumerate() {
                    if !upload_key_usable(k) {
                        return Err(Error::Config(format!("upload key {i} is a small-order X25519 point")));
                    }
                    if self.upload_keys[..i].contains(k) {
                        return Err(Error::Config(format!("upload key {i} repeats an earlier party's key")));
                    }
                }
            }
        }
        if self.client_proofs && (self.mode != VerificationMode::Verdict || self.upload != Upload::Ciphertext) {
            return Err(Error::Config(
                "client_proofs applies to verdict mode with ciphertext upload (share upload already proves every ciphertext; silent mode is not supported yet)"
                    .into(),
            ));
        }
        if self.repetitions == 0 || self.repetitions > 64 {
            return Err(Error::Config("repetitions must be in 1..=64".into()));
        }
        let field = Field::new(self.plain_mod).ok_or_else(|| Error::Config("plain_mod must be a prime below 2^32".into()))?;
        // The check tests each linear constraint modulo p; refuse types
        // whose constraints could be a nonzero multiple of p.
        crate::types::check_constraints_fit(&self.measurement_type, self.plain_mod)?;
        if self.min_batch_size == 0 {
            return Err(Error::Config("min_batch_size must be >= 1".into()));
        }
        if self.max_batch_size < self.min_batch_size as u64 || self.max_batch_size >= self.plain_mod {
            return Err(Error::Config("need min_batch_size <= max_batch_size < plain_mod".into()));
        }
        if !matches!(self.security_bits, 128 | 192 | 256) {
            return Err(Error::Config("security_bits must be 128, 192 or 256".into()));
        }
        if let AuthPolicy::Required {
            max_reports_per_client_per_batch: 0,
        } = self.auth
        {
            return Err(Error::Config("max_reports_per_client_per_batch must be >= 1".into()));
        }
        if !self.silent_batch_groups.is_power_of_two() {
            return Err(Error::Config("silent_batch_groups must be a power of two".into()));
        }
        if self.moments {
            match self.measurement_type.value_slots() {
                Some(map) => {
                    if map.len() < 2 {
                        return Err(Error::Config("moments need at least two elements (features + target)".into()));
                    }
                    // recombined moments are u128: max_batch_size * B_a * B_b < 2^128
                    let w = self
                        .measurement_type
                        .value_bounds()
                        .expect("vector type")
                        .iter()
                        .map(|&b| 64 - b.leading_zeros())
                        .max()
                        .unwrap_or(1);
                    if 2 * w + (64 - self.max_batch_size.leading_zeros()) > 128 {
                        return Err(Error::Config(format!(
                            "moments: {w}-bit values over batches of {} overflow 128-bit moments",
                            self.max_batch_size
                        )));
                    }
                    if self.moment_digit_bits().is_none() {
                        return Err(Error::Config("moments: max_batch_size must be below plain_mod".into()));
                    }
                }
                None => return Err(Error::Config("moments are only defined for SumVec and BoundedSumVec".into())),
            }
        }
        if !self.collectors.is_empty() {
            let n = self.measurement_type.num_elements();
            if self.collectors.len() > 128 {
                return Err(Error::Config("at most 128 collectors".into()));
            }
            let mut covered = vec![false; n];
            for (c, p) in self.collectors.iter().enumerate() {
                if p.elements.is_empty() {
                    return Err(Error::Config(format!("collector {c}: no elements")));
                }
                if p.elements.windows(2).any(|w| w[0] >= w[1]) || *p.elements.last().unwrap() >= n {
                    return Err(Error::Config(format!("collector {c}: elements must be ascending, distinct and below {n}")));
                }
                if p.moments && (!self.moments || p.elements.len() < 2) {
                    return Err(Error::Config(format!(
                        "collector {c}: moments need the task's moments on and at least two elements"
                    )));
                }
                for &e in &p.elements {
                    covered[e] = true;
                }
            }
            if let Some(e) = covered.iter().position(|c| !c) {
                return Err(Error::Config(format!(
                    "element {e} is released to no collector; drop it from the task or assign it"
                )));
            }
            // Chunks are cut wherever the visibility class changes, so any
            // policy set is expressible; interleaved policies simply cost one
            // chunk (one ciphertext per report) per run of equal visibility.
        }
        if self.gated() && self.gate_depth() > self.mult_depth() {
            return Err(Error::Config(format!(
                "the release gates need depth {} after the refresh, the chain has {}: lower min_batch_size or min_cell_count",
                self.gate_depth(),
                self.mult_depth()
            )));
        }
        if self.exact_check() && self.mult_depth() > depth_cap {
            let (_, classes, block) = self.exact_shape();
            return Err(Error::Config(format!(
                "exact check depth {} exceeds {depth_cap}: a report occupies {} slots ({} classes of {} positions) and its zero tests cost log2 of that; use the randomised check",
                self.mult_depth(),
                classes * block,
                classes,
                block
            )));
        }
        if self.mode == VerificationMode::Silent && self.mult_depth() > depth_cap {
            return Err(Error::Config(format!(
                "silent mode circuit depth {} exceeds {depth_cap}; use a plaintext modulus with a shorter Fermat chain or fewer repetitions",
                self.mult_depth()
            )));
        }
        Ok(field)
    }

    pub fn field(&self) -> Field {
        Field::new(self.plain_mod).expect("validated")
    }

    pub fn layout_kind(&self) -> LayoutKind {
        match self.mode {
            VerificationMode::Verdict => LayoutKind::Blocked,
            VerificationMode::Silent if self.silent_batch_groups > 1 => LayoutKind::Batched,
            VerificationMode::Silent => LayoutKind::Interleaved,
        }
    }

    /// Native paper-core profile validation. The threshold validator and fixed
    /// exact row remain unchanged. Only the four plain silent tasks are allowed.
    pub fn validate_native(&self, row: usize) -> Result<Field> {
        if !matches!(
            self.measurement_type,
            crate::types::MeasurementType::Count
                | crate::types::MeasurementType::Sum { .. }
                | crate::types::MeasurementType::SumVec { .. }
                | crate::types::MeasurementType::Histogram { .. }
        ) || self.mode != VerificationMode::Silent
            || self.moments
            || self.gated()
            || self.client_proofs
            || !self.collectors.is_empty()
            || self.upload != Upload::Ciphertext
        {
            return Err(Error::Config("native profiles support only the four ungated paper tasks".into()));
        }
        if !row.is_power_of_two() || row < 2 || self.silent_batch_groups < 2 || self.silent_batch_groups > row || !self.silent_batch_groups.is_power_of_two() {
            return Err(Error::Config("native row and packing require powers of two and at least two groups".into()));
        }
        let mut canonical = self.clone();
        if self.exact_check() {
            let (_, classes, block) = self.exact_shape();
            canonical.silent_batch_groups = EXACT_ROW / (classes * block);
        }
        let f = canonical.validate_with_depth_cap(32)?;
        self.layout_native(row)?;
        Ok(f)
    }
    /// Variable-row layout for explicitly selected native paper-core profiles.
    pub fn layout_native(&self, row: usize) -> Result<Layout> {
        self.layout_impl(row, true)
    }
    pub fn layout(&self, row: usize) -> Result<Layout> {
        self.layout_impl(row, false)
    }
    fn layout_impl(&self, row: usize, native: bool) -> Result<Layout> {
        let groups = if self.layout_kind() == LayoutKind::Batched {
            self.silent_batch_groups
        } else {
            1
        };
        // The exact check uses one residue class per chunk and per linear
        // constraint, where the randomised check uses one per repetition.
        let classes_used = if self.exact_check() {
            let (chunks, classes, block) = self.exact_shape();
            let cells = groups.checked_mul(classes).and_then(|x| x.checked_mul(block));
            let scalar_count = native && matches!(self.measurement_type, crate::types::MeasurementType::Count);
            let fits = if scalar_count {
                groups >= 2 && groups.is_power_of_two() && cells.is_some_and(|n| n <= row)
            } else {
                cells == Some(row)
            };
            if (!native && row != EXACT_ROW) || !fits {
                return Err(Error::Config(format!(
                    "the exact check needs a row of {EXACT_ROW} slots holding {groups} reports of {} slots; the context has {row}",
                    classes * block
                )));
            }
            chunks + self.measurement_type.linear_constraints().len()
        } else {
            self.repetitions
        };
        let mut l = Layout::with_cuts(
            self.layout_kind(),
            self.measurement_type.input_len(),
            classes_used,
            row,
            groups,
            &self.chunk_cuts(),
        )?;
        if native && self.exact_check() && matches!(self.measurement_type, crate::types::MeasurementType::Count) {
            // Count's predicate and contribution are pointwise in its sole
            // coordinate. No cyclic broadcast over padded coordinates is
            // needed. The admission and final output masks are unchanged.
            l.block = 1;
        }
        if self.moments
            && let Some(pieces) = self.measurement_type.moment_pieces()
        {
            for p in &pieces {
                let k = l.chunk_of(p.start);
                if l.chunk_range(k).end < p.start + p.bits as usize {
                    return Err(Error::Config("moments need each value's bits inside one chunk".into()));
                }
            }
            l.moments = Some(pieces.iter().map(|p| (p.start, p.bits)).collect());
            l.moment_pieces = pieces.iter().map(|p| (p.element, p.multiplier)).collect();
            l.moment_digit = self
                .moment_digit_bits()
                .ok_or_else(|| Error::Config("moments: max_batch_size must be below plain_mod".into()))?;
            if !l.moment_slots_fit() {
                return Err(Error::Config(
                    "moments: the digits of the widest pair do not fit in a row of this layout".into(),
                ));
            }
        }
        Ok(l)
    }

    /// Multiplicative levels consumed by `E^(p-1)` with left-to-right
    /// square-and-multiply.
    pub fn fermat_depth(&self) -> u32 {
        let e = self.plain_mod - 1;
        (64 - e.leading_zeros() - 1) + (e.count_ones() - 1)
    }

    /// Multiplicative depth the crypto context must support.
    pub fn mult_depth(&self) -> u32 {
        match self.mode {
            VerificationMode::Verdict => VERDICT_CIRCUIT_DEPTH,
            VerificationMode::Silent => {
                let classes = self.repetitions.next_power_of_two();
                // x(x-1) and its coefficients, the Fermat chain, the product
                // over the classes and the gating multiplication. The
                // batched layout adds two plaintext masks: each report is
                // restricted to its group's slots before it enters the
                // batch (so the circuit's input is one level down), and the
                // other groups' slots are zeroed after the fold at the
                // close. `key_switch_digits` keeps that chain at ring
                // dimension 65536.
                let batched = if self.silent_batch_groups > 1 { 2 } else { 0 };
                if self.silent_check == SilentCheck::Exact {
                    // x(x-1) and the linear sums (one level: no
                    // coefficients), the Fermat chain, the product of the
                    // zero tests over the report's slots, gating, and the
                    // two batched masks.
                    let (_, classes, block) = self.exact_shape();
                    return 1 + self.fermat_depth() + (classes * block).trailing_zeros() + 1 + batched;
                }
                2 + self.fermat_depth() + classes.trailing_zeros() + 1 + batched
            }
        }
    }

    /// OpenFHE's hybrid key-switching digit count for the task's context, 0
    /// for OpenFHE's default (3). From depth 26 on, the default digit count
    /// takes the auxiliary modulus past what the 128-bit bound allows for
    /// ring dimension 65536 and OpenFHE doubles the ring (measured at depths
    /// 26, 27 and 28: 131072). Five digits keep it at 65536 (depth 26: 30
    /// towers, 1293 bits; depth 27: 31 towers, 1336 bits; depth 28: 32
    /// towers, 1379 bits; four digits no longer fit at depth 27), at the
    /// cost of a larger key-switching modulus per switch. Measured by
    /// `openfhe-tbgv-rs/examples/params_probe.rs --tuned`. Only silent mode
    /// reaches depth 26.
    pub fn key_switch_digits(&self) -> u32 {
        if self.mode == VerificationMode::Silent && self.mult_depth() >= 26 {
            5
        } else {
            0
        }
    }

    /// Bits of soundness of the validity check against a malicious client.
    /// Infinite for the exact check, which accepts exactly the valid
    /// encodings.
    pub fn soundness_bits(&self) -> f64 {
        if self.exact_check() {
            return f64::INFINITY;
        }
        self.repetitions as f64 * self.field().log2()
    }

    /// Canonical bytes that every derived randomness commits to. Tasks
    /// that leave `key_topology` and `min_cell_count` at their defaults bind
    /// exactly the bytes they bound before those fields existed; the others
    /// append a separator and the new fields.
    pub fn binding(&self) -> Vec<u8> {
        let legacy = LegacyBinding {
            task_id: &self.task_id,
            measurement_type: &self.measurement_type,
            mode: &self.mode,
            auth: &self.auth,
            num_aggregators: &self.num_aggregators,
            repetitions: &self.repetitions,
            min_batch_size: &self.min_batch_size,
            max_batch_size: &self.max_batch_size,
            max_report_bytes: &self.max_report_bytes,
            plain_mod: &self.plain_mod,
            security_bits: &self.security_bits,
            silent_batch_groups: &self.silent_batch_groups,
            moments: &self.moments,
            collectors: &self.collectors,
        };
        let mut out = postcard::to_allocvec(&legacy).expect("TaskConfig is serializable");
        if self.key_topology != KeyTopology::default() || self.min_cell_count != 0 {
            out.extend_from_slice(BINDING_EXTENSION);
            out.extend_from_slice(&postcard::to_allocvec(&(self.key_topology, self.min_cell_count)).expect("serializable"));
        }
        if self.upload != Upload::default() || !self.upload_keys.is_empty() {
            out.extend_from_slice(BINDING_UPLOAD_EXTENSION);
            out.extend_from_slice(&postcard::to_allocvec(&(self.upload, &self.upload_keys)).expect("serializable"));
        }
        if self.client_proofs {
            out.extend_from_slice(BINDING_PROOFS_EXTENSION);
            out.extend_from_slice(&postcard::to_allocvec(&self.client_proofs).expect("serializable"));
        }
        if self.silent_check != SilentCheck::default() {
            out.extend_from_slice(BINDING_CHECK_EXTENSION);
            out.extend_from_slice(&postcard::to_allocvec(&self.silent_check).expect("serializable"));
        }
        out
    }

    /// Hash of the configuration, for logging and for peers to compare.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.binding()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digit width is the widest for which every digit product summed
    /// over `max_batch_size` reports stays below `p`, over both primes,
    /// value mixes and batch sizes from 1 to `p - 1`.
    #[test]
    fn moment_digit_width_is_the_widest_that_cannot_wrap() {
        for silent in [false, true] {
            for bounds in [vec![255u64, 255, 255], vec![100, 5, 15], vec![65535, 1], vec![1, 1]] {
                let t = MeasurementType::BoundedSumVec { bounds };
                let mut c = if silent {
                    TaskConfig::new_silent([0; 32], t.clone(), 2)
                } else {
                    TaskConfig::new([0; 32], t.clone(), 2)
                };
                c.moments = true;
                // digits are of the power-of-two pieces, whose widest sets the width
                let w = t.moment_pieces().unwrap().iter().map(|p| p.bits).max().unwrap();
                let fits = |d: u32, n: u64| ((1u128 << d) - 1).pow(2) * n as u128 <= (c.plain_mod - 1) as u128;
                for n in [1u64, 2, 12, 13, 1000, 1 << 16, 1 << 20, c.plain_mod - 1] {
                    if n >= c.plain_mod {
                        continue;
                    }
                    c.max_batch_size = n;
                    let d = c.moment_digit_bits().unwrap();
                    assert!((1..=w).contains(&d));
                    assert!(fits(d, n), "silent={silent} w={w} n={n} d={d}");
                    assert!(d == w || !fits(d + 1, n), "silent={silent} w={w} n={n} d={d} not the widest");
                    c.validate().unwrap();
                }
            }
        }
    }

    /// The batch cap before the digit decomposition was `(p-1) >> (a+b)`
    /// for the two widest values `a >= b`. It ignored the square of the
    /// widest value (`2a` bits): for 7- and 4-bit values it admitted
    /// batches whose 7-bit square sum wraps modulo `p`.
    #[test]
    fn the_former_cap_let_the_widest_square_wrap() {
        let p = DEFAULT_PLAIN_MOD;
        let former_cap = (p - 1) >> (7 + 4);
        assert!(former_cap as u128 * 127 * 127 >= p as u128);
        let mut c = TaskConfig::new([0; 32], MeasurementType::BoundedSumVec { bounds: vec![100, 5, 15] }, 2);
        c.moments = true;
        c.max_batch_size = former_cap;
        let d = c.moment_digit_bits().unwrap();
        assert!(d < 7 && ((1u128 << d) - 1).pow(2) * former_cap as u128 <= (p - 1) as u128);
    }
    /// A default task binds exactly the postcard encoding of the fields it
    /// had before `key_topology` and `min_cell_count` (so its digest, and
    /// every attestation and challenge derived from it, is unchanged); any
    /// use of the new fields changes the binding; and task files without
    /// the new fields still parse.
    #[test]
    fn binding_is_stable_for_legacy_tasks() {
        #[derive(Serialize)]
        struct Before {
            task_id: [u8; 32],
            measurement_type: MeasurementType,
            mode: VerificationMode,
            auth: AuthPolicy,
            num_aggregators: usize,
            repetitions: usize,
            min_batch_size: usize,
            max_batch_size: u64,
            max_report_bytes: usize,
            plain_mod: u64,
            security_bits: u32,
            silent_batch_groups: usize,
            moments: bool,
            collectors: Vec<CollectorPolicy>,
        }
        let c = TaskConfig::new_silent([7; 32], MeasurementType::Histogram { length: 5 }, 2);
        let before = Before {
            task_id: c.task_id,
            measurement_type: c.measurement_type.clone(),
            mode: c.mode,
            auth: c.auth,
            num_aggregators: c.num_aggregators,
            repetitions: c.repetitions,
            min_batch_size: c.min_batch_size,
            max_batch_size: c.max_batch_size,
            max_report_bytes: c.max_report_bytes,
            plain_mod: c.plain_mod,
            security_bits: c.security_bits,
            silent_batch_groups: c.silent_batch_groups,
            moments: c.moments,
            collectors: c.collectors.clone(),
        };
        assert_eq!(c.binding(), postcard::to_allocvec(&before).unwrap());
        let mut k = c.clone();
        k.min_cell_count = 5;
        let mut s = TaskConfig::new_split_key([7; 32], MeasurementType::Histogram { length: 5 });
        assert_ne!(k.digest(), c.digest());
        assert_ne!(s.digest(), c.digest());
        s.min_cell_count = 5;
        assert_ne!(s.digest(), k.digest());
        // a task file written before the fields existed is its legacy binding
        let old = postcard::to_allocvec(&before).unwrap();
        assert_eq!(TaskConfig::decode(&old).unwrap(), c);
        // current files round-trip, with and without the new fields
        for t in [&c, &k, &s] {
            assert_eq!(&TaskConfig::decode(&postcard::to_allocvec(t).unwrap()).unwrap(), t);
        }
        // no format accepts a file cut inside a field or extended; a file
        // cut by exactly its last fields is the older encoding without them
        // (`attest::check_attested_task`)
        let cur = postcard::to_allocvec(&s).unwrap();
        // (here the same task: the fields are at their defaults), which is
        // why a node checks its task against the attested digest
        assert_eq!(TaskConfig::decode(&cur[..cur.len() - 1]).unwrap(), s); // no silent_check
        assert_eq!(TaskConfig::decode(&cur[..cur.len() - 2]).unwrap(), s); // nor client_proofs
        assert!(TaskConfig::decode(&cur[..cur.len() - 3]).is_err()); // cut inside the upload fields
        let mut longer = cur.clone();
        longer.push(0);
        assert!(TaskConfig::decode(&longer).is_err());
    }

    #[test]
    fn topology_and_suppression_rules() {
        let h = MeasurementType::Histogram { length: 8 };
        let s = TaskConfig::new_split_key([0; 32], h.clone());
        assert_eq!((s.num_key_parties(), s.collector_party(), s.gated()), (2, Some(1), true));
        s.validate().unwrap();
        let mut bad = s.clone();
        bad.num_aggregators = 2;
        assert!(bad.validate().is_err());
        let mut bad = s.clone();
        bad.mode = VerificationMode::Verdict;
        assert!(bad.validate().is_err());
        let mut one = TaskConfig::new_silent([0; 32], h.clone(), 1);
        assert!(one.validate().is_err()); // one aggregator needs the collector's share
        one.key_topology = KeyTopology::AggregatorAndCollector;
        one.validate().unwrap();
        let a = TaskConfig::new_silent([0; 32], h.clone(), 2);
        assert!(!a.gated());
        let mut k = a.clone();
        k.min_cell_count = 5;
        assert!(k.gated());
        k.validate().unwrap();
        assert_eq!(k.gate_depth(), 3 + 1); // product tree of 5 + 2 factors, then the release
        for (t, ok) in [
            (MeasurementType::Count, true),
            (MeasurementType::MultihotCountVec { length: 6, max_weight: 3 }, true),
            (MeasurementType::Sum { max_measurement: 9 }, false),
            (MeasurementType::SumVec { length: 2, max_measurement: 3 }, false),
        ] {
            let mut c = TaskConfig::new_silent([0; 32], t, 2);
            c.min_cell_count = 3;
            assert_eq!(c.validate().is_ok(), ok);
        }
        for bad_k in [1u64, a.max_batch_size + 1] {
            let mut c = a.clone();
            c.min_cell_count = bad_k;
            assert!(c.validate().is_err());
        }
        let mut v = TaskConfig::new([0; 32], h.clone(), 2);
        v.min_cell_count = 3;
        assert!(v.validate().is_err());
        // the gates must fit the chain after the refresh
        let mut deep = s.clone();
        deep.min_batch_size = 1 << 14;
        deep.validate().unwrap();
        assert_eq!(deep.gate_depth(), 15 + 1);
        deep.min_cell_count = 1 << 14;
        assert_eq!(deep.gate_depth(), 15 + 2);
        deep.validate().unwrap();
        assert!(deep.gate_depth() <= deep.mult_depth());
    }

    #[test]
    fn client_proofs_binding_files_and_rules() {
        let h = MeasurementType::Histogram { length: 5 };
        let v = TaskConfig::new([3; 32], h.clone(), 2);
        let p = v.clone().with_client_proofs();
        // off: the binding is the one before the field existed
        let mut without = v.binding();
        assert!(!without.windows(BINDING_PROOFS_EXTENSION.len()).any(|w| w == BINDING_PROOFS_EXTENSION));
        // on: the same binding, extended
        let with = p.binding();
        assert_ne!(p.digest(), v.digest());
        without.extend_from_slice(BINDING_PROOFS_EXTENSION);
        without.extend_from_slice(&postcard::to_allocvec(&true).unwrap());
        assert_eq!(with, without);
        // a file written before the field existed is the task without proofs
        let cur = postcard::to_allocvec(&v).unwrap();
        assert_eq!(&cur[cur.len() - 2..], &[0, 0]); // `false`, then the default silent check
        let v3 = &cur[..cur.len() - 2];
        assert!(crate::messages::decode::<TaskConfig>(v3).is_err());
        assert_eq!(TaskConfig::decode(v3).unwrap(), v);
        assert_eq!(TaskConfig::decode(v3).unwrap().digest(), v.digest());
        for t in [&v, &p] {
            assert_eq!(&TaskConfig::decode(&postcard::to_allocvec(t).unwrap()).unwrap(), t);
        }
        // a flag byte other than 0 or 1 is not a task
        let mut two = postcard::to_allocvec(&p).unwrap();
        *two.last_mut().unwrap() = 2;
        assert!(TaskConfig::decode(&two).is_err());
        // verdict mode with ciphertext upload only
        p.validate().unwrap();
        assert!(TaskConfig::new_silent([3; 32], h.clone(), 2).with_client_proofs().validate().is_err());
        assert!(TaskConfig::new_split_key([3; 32], h.clone()).with_client_proofs().validate().is_err());
        let mut shares = p.clone();
        shares.upload = Upload::Shares;
        shares.upload_keys = vec![[9; 32]; 2];
        assert!(shares.validate().is_err());
        let mut shares_plain = shares.clone();
        shares_plain.client_proofs = false;
        assert!(
            shares_plain
                .validate()
                .map_err(|e| e.to_string())
                .err()
                .is_none_or(|e| !e.contains("client_proofs"))
        );
    }

    /// The exact check's slot shapes, depths, key-switching digits and
    /// packing for the types the paper names, the refusals, and its place
    /// in task files and bindings.
    #[test]
    fn exact_check_shapes_depths_files_and_rules() {
        let shape = |t: MeasurementType| {
            let c = TaskConfig::new_exact([5; 32], t, 2);
            let (chunks, classes, block) = c.exact_shape();
            (
                chunks,
                classes,
                block,
                c.silent_batch_groups,
                c.mult_depth(),
                c.key_switch_digits(),
                c.validate().is_ok(),
            )
        };
        // 1 + 20 + log2(classes * block) + 1 + 2
        assert_eq!(shape(MeasurementType::Count), (1, 1, 1, 32768, 24, 0, true));
        assert_eq!(shape(MeasurementType::Sum { max_measurement: 100 }), (1, 1, 8, 4096, 27, 5, true));
        assert_eq!(shape(MeasurementType::Sum { max_measurement: 65535 }), (1, 1, 16, 2048, 28, 5, true));
        assert_eq!(shape(MeasurementType::Sum { max_measurement: 65536 }), (1, 1, 32, 1024, 29, 5, false));
        assert_eq!(shape(MeasurementType::Histogram { length: 3 }), (1, 2, 4, 4096, 27, 5, true)); // + the one-hot class
        assert_eq!(shape(MeasurementType::Histogram { length: 8 }), (1, 2, 8, 2048, 28, 5, true));
        assert_eq!(shape(MeasurementType::Histogram { length: 9 }), (1, 2, 16, 1024, 29, 5, false));
        assert_eq!(shape(MeasurementType::Histogram { length: 21 }), (1, 2, 32, 512, 30, 5, false));
        assert_eq!(
            shape(MeasurementType::MultihotCountVec { length: 4, max_weight: 2 }),
            (1, 2, 8, 2048, 28, 5, true)
        );
        assert_eq!(
            shape(MeasurementType::SumVec {
                length: 8,
                max_measurement: 255
            }),
            (1, 1, 64, 512, 30, 5, false)
        );
        let e = TaskConfig::new_exact([5; 32], MeasurementType::Histogram { length: 21 }, 2)
            .validate()
            .unwrap_err()
            .to_string();
        assert!(e.contains("exact check depth 30") && e.contains("64 slots"), "{e}");
        let x = TaskConfig::new_exact([5; 32], MeasurementType::Histogram { length: 3 }, 2);
        assert!(x.exact_check() && x.soundness_bits().is_infinite());
        // the layout: one class per chunk and per constraint, the row it was sized for
        let l = x.layout(EXACT_ROW).unwrap();
        assert_eq!(
            (l.kind, l.repetitions, l.classes, l.block, l.groups, l.num_chunks),
            (LayoutKind::Batched, 2, 2, 4, 4096, 1)
        );
        assert!(x.layout(EXACT_ROW * 2).is_err());
        // refusals
        let mut bad = x.clone();
        bad.mode = VerificationMode::Verdict;
        assert!(bad.validate().is_err());
        let mut bad = x.clone();
        bad.repetitions = 7;
        assert!(bad.validate().is_err());
        let mut bad = x.clone();
        bad.silent_batch_groups = 64;
        assert!(bad.validate().unwrap_err().to_string().contains("must be 4096"));
        let mut bad = TaskConfig::new_exact([5; 32], MeasurementType::BoundedSumVec { bounds: vec![1, 3] }, 2);
        bad.validate().unwrap();
        bad.moments = true;
        assert!(bad.validate().unwrap_err().to_string().contains("second moments"));
        // the split-key topology and suppression combine with it
        let mut split = x.clone();
        split.num_aggregators = 1;
        split.key_topology = KeyTopology::AggregatorAndCollector;
        split.min_cell_count = 11;
        split.min_batch_size = 30;
        split.validate().unwrap();
        // files and bindings: the randomised default binds what it bound
        // before the field existed; the exact check extends it
        let r = TaskConfig::new_silent([5; 32], MeasurementType::Histogram { length: 3 }, 2);
        assert!(!r.binding().windows(BINDING_CHECK_EXTENSION.len()).any(|w| w == BINDING_CHECK_EXTENSION));
        let mut rx = r.clone();
        rx.silent_check = SilentCheck::Exact;
        let mut want = r.binding();
        want.extend_from_slice(BINDING_CHECK_EXTENSION);
        want.extend_from_slice(&postcard::to_allocvec(&SilentCheck::Exact).unwrap());
        assert_eq!(rx.binding(), want);
        assert_ne!(rx.digest(), r.digest());
        for t in [&r, &x, &split] {
            assert_eq!(&TaskConfig::decode(&postcard::to_allocvec(t).unwrap()).unwrap(), t);
        }
        let cur = postcard::to_allocvec(&r).unwrap();
        assert_eq!(TaskConfig::decode(&cur[..cur.len() - 1]).unwrap(), r); // a file from before the field
        let ex = postcard::to_allocvec(&x).unwrap();
        assert_eq!(ex.last(), Some(&1));
        let mut two = ex.clone();
        *two.last_mut().unwrap() = 2;
        assert!(TaskConfig::decode(&two).is_err());
    }

    #[test]
    fn depths() {
        let v = TaskConfig::new([0; 32], MeasurementType::Count, 2);
        assert_eq!(v.mult_depth(), 3);
        let s = TaskConfig::new_silent([0; 32], MeasurementType::Count, 2);
        assert_eq!(s.repetitions, 7);
        assert_eq!(s.fermat_depth(), 20); // 3 * 2^18: E^3 then 18 squarings
        assert_eq!(s.mult_depth(), 28); // 2 + 20 + 3 (8 classes) + 1 + 2 (batched: group mask, fold mask)
        assert_eq!(s.key_switch_digits(), 5);
        assert!(s.validate().is_ok());
        assert!(s.soundness_bits() > 128.0); // 137.1
        let mut single = s.clone();
        single.silent_batch_groups = 1;
        assert_eq!((single.mult_depth(), single.key_switch_digits()), (26, 5)); // no group mask, no fold
        let mut four = s.clone();
        four.repetitions = 4;
        assert_eq!((four.mult_depth(), four.key_switch_digits()), (27, 5));
        assert!(four.soundness_bits() > 78.0 && four.soundness_bits() < 79.0);
        four.silent_batch_groups = 1;
        assert_eq!((four.mult_depth(), four.key_switch_digits()), (25, 0)); // default digits fit at 25
        let mut eight = s.clone();
        eight.repetitions = 8; // same 8 classes, same depth
        assert_eq!(eight.mult_depth(), 28);
        assert!(eight.validate().is_ok());
        let mut too_deep = s.clone();
        too_deep.repetitions = 9; // 16 classes -> depth 29
        assert!(too_deep.validate().is_err());
    }
}

#[cfg(test)]
mod native_layout_tests {
    use super::*;
    #[test]
    fn variable_row_does_not_relax_threshold_layout() {
        let mut cfg = TaskConfig::new_exact([0xDD; 32], crate::types::MeasurementType::Count, 2);
        cfg.silent_batch_groups = 16384;
        assert!(cfg.validate().is_err());
        assert!(cfg.validate_native(16384).is_ok());
        assert!(cfg.layout(16384).is_err());
        assert_eq!(cfg.layout_native(16384).unwrap().groups, 16384);
        cfg.silent_batch_groups = 1usize << (usize::BITS - 1);
        assert!(cfg.validate_native(16384).is_err());
    }
}

#[cfg(test)]
mod native_count_packing_tests {
    use super::*;
    #[test]
    fn prefix_packing_is_count_only_and_threshold_validation_stays_strict() {
        for groups in [2, 4, 32, 32768] {
            let mut cfg = TaskConfig::new_exact([0xA2; 32], crate::types::MeasurementType::Count, 2);
            cfg.silent_batch_groups = groups;
            cfg.validate_native(EXACT_ROW).unwrap();
            let layout = cfg.layout_native(EXACT_ROW).unwrap();
            assert_eq!(layout.block, 1);
            assert_eq!(layout.rotation_indices().len(), groups.trailing_zeros() as usize);
            if groups != 32768 {
                assert!(cfg.validate().is_err());
                assert!(cfg.layout(EXACT_ROW).is_err());
            }
        }
        for ty in [
            crate::types::MeasurementType::Sum { max_measurement: 100 },
            crate::types::MeasurementType::Histogram { length: 8 },
            crate::types::MeasurementType::SumVec {
                length: 10,
                max_measurement: 1,
            },
        ] {
            let mut cfg = TaskConfig::new_exact([0xA2; 32], ty, 2);
            cfg.silent_batch_groups = 4;
            assert!(cfg.validate_native(EXACT_ROW).is_err());
        }
    }
}
