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
        }
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

    pub fn validate(&self) -> Result<Field> {
        self.measurement_type.validate()?;
        if self.num_aggregators < 2 {
            return Err(Error::Config("at least two aggregators are required".into()));
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
        if self.mode == VerificationMode::Silent && self.mult_depth() > 28 {
            return Err(Error::Config(format!(
                "silent mode circuit depth {} exceeds 28; use a plaintext modulus with a shorter Fermat chain or fewer repetitions",
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

    pub fn layout(&self, row: usize) -> Result<Layout> {
        let groups = if self.layout_kind() == LayoutKind::Batched {
            self.silent_batch_groups
        } else {
            1
        };
        let mut l = Layout::with_cuts(
            self.layout_kind(),
            self.measurement_type.input_len(),
            self.repetitions,
            row,
            groups,
            &self.chunk_cuts(),
        )?;
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
    pub fn soundness_bits(&self) -> f64 {
        self.repetitions as f64 * self.field().log2()
    }

    /// Canonical bytes that every derived randomness commits to.
    pub fn binding(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("TaskConfig is serializable")
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
