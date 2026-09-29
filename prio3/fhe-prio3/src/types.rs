//! Prio3 measurement types, encoded exactly as in draft-irtf-cfrg-vdaf-13
//! (Section 7.4): Count, Sum, SumVec, Histogram and MultihotCountVec.
//!
//! Every type maps a measurement to a vector of field elements that are all
//! bits, plus zero or more linear constraints. A report is valid iff every
//! slot `x_i` satisfies `x_i(x_i - 1) = 0` and every linear constraint
//! `sum_i c_i x_i + c_0 = 0` holds. That is the same validity circuit Prio3's
//! FLP proves; here it is evaluated homomorphically instead.

use crate::error::{Error, Result};
use crate::field::Field;
use serde::{Deserialize, Serialize};

/// Largest bit width for any bit-decomposed integer. Keeps every decoded
/// integer, and sums of two of them, below the 32-bit plaintext modulus so
/// that equality modulo `p` implies equality over the integers.
pub const MAX_BITS: u32 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeasurementType {
    /// Measurement in {0, 1}; aggregate is the number of ones.
    Count,
    /// Integer in `[0, max_measurement]`; aggregate is the sum.
    Sum { max_measurement: u64 },
    /// `length` integers each in `[0, 2^bits)`; aggregate is the element-wise sum.
    SumVec { length: usize, bits: u32 },
    /// One integer per bound, element `e` in `[0, bounds[e]]` exactly;
    /// aggregate is the element-wise sum (`AggregateResult::SumVec`).
    /// Each element uses the Prio3 `Sum` encoding: `bits_e` bits of the
    /// value and `bits_e` bits of `value + offset_e`, with
    /// `offset_e = 2^bits_e - 1 - bounds[e]`, plus one linear constraint per
    /// element. Not a draft-13 type; an extension for per-element ranges.
    BoundedSumVec { bounds: Vec<u64> },
    /// Bucket index in `[0, length)`; aggregate is the per-bucket count.
    Histogram { length: usize },
    /// Subset of `[0, length)` with at most `max_weight` elements; aggregate
    /// is the per-position count.
    MultihotCountVec { length: usize, max_weight: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Measurement {
    Count(bool),
    Sum(u64),
    SumVec(Vec<u64>),
    Histogram(usize),
    MultihotCountVec(Vec<bool>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregateResult {
    Count(u64),
    Sum(u128),
    SumVec(Vec<u128>),
    Histogram(Vec<u64>),
    MultihotCountVec(Vec<u64>),
}

/// What the collector returns for a batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchResult {
    /// Collector this result was released to (0 without release policies).
    pub collector: u32,
    /// Elements of `aggregate` this collector received; the others are zero.
    pub elements: Vec<usize>,
    pub aggregate: AggregateResult,
    /// Reports that entered the sums (verdict mode: accepted reports;
    /// silent mode: admitted reports, valid or not).
    pub report_count: u64,
    /// Reports that contributed a valid measurement. Equal to
    /// `report_count` in verdict mode; decrypted from the encrypted counter
    /// in silent mode.
    pub valid_count: u64,
    /// Present when the task accumulates second moments.
    pub regression: Option<RegressionResult>,
}

/// Ordinary least squares from encrypted first and second moments. Values
/// `0..length-1` are the features, value `length-1` is the target, and an
/// intercept is included through the valid-report count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegressionResult {
    pub n: u64,
    /// `sum v_a` for every value.
    pub first: Vec<u128>,
    /// `sum v_a v_b`, symmetric, length x length.
    pub second: Vec<Vec<u128>>,
    /// `[intercept, beta_1, ..., beta_{length-1}]`, or empty if the normal
    /// equations are singular.
    pub beta: Vec<f64>,
}

impl RegressionResult {
    /// Assembles the normal equations with intercept and solves them.
    pub fn from_moments(n: u64, first: Vec<u128>, second: Vec<Vec<u128>>) -> Self {
        let length = first.len();
        let d = length - 1; // features
        // A is (d+1)x(d+1): [[n, sum x_j], [sum x_i, sum x_i x_j]]; b = [sum y, sum x_i y]
        let mut a = vec![vec![0f64; d + 1]; d + 1];
        let mut b = vec![0f64; d + 1];
        a[0][0] = n as f64;
        b[0] = first[d] as f64;
        for i in 0..d {
            a[0][i + 1] = first[i] as f64;
            a[i + 1][0] = first[i] as f64;
            b[i + 1] = second[i][d] as f64;
            for j in 0..d {
                a[i + 1][j + 1] = second[i][j] as f64;
            }
        }
        let beta = solve_linear(a, b).unwrap_or_default();
        Self { n, first, second, beta }
    }
}

/// Gaussian elimination with partial pivoting; `None` if singular.
pub fn solve_linear(mut a: Vec<Vec<f64>>, mut b: Vec<f64>) -> Option<Vec<f64>> {
    let n = b.len();
    for col in 0..n {
        let piv = (col..n).max_by(|&i, &j| a[i][col].abs().partial_cmp(&a[j][col].abs()).unwrap())?;
        if a[piv][col].abs() < 1e-12 {
            return None;
        }
        a.swap(col, piv);
        b.swap(col, piv);
        for r in col + 1..n {
            let f = a[r][col] / a[col][col];
            for c in col..n {
                a[r][c] -= f * a[col][c];
            }
            b[r] -= f * b[col];
        }
    }
    let mut x = vec![0f64; n];
    for i in (0..n).rev() {
        let s: f64 = (i + 1..n).map(|j| a[i][j] * x[j]).sum();
        x[i] = (b[i] - s) / a[i][i];
    }
    Some(x)
}

/// Plaintext reference for the regression pilot.
pub fn regression_plain(values: &[Vec<u64>]) -> RegressionResult {
    let length = values[0].len();
    let n = values.len() as u64;
    let mut first = vec![0u128; length];
    let mut second = vec![vec![0u128; length]; length];
    for v in values {
        for a in 0..length {
            first[a] += v[a] as u128;
            for b in 0..length {
                second[a][b] += v[a] as u128 * v[b] as u128;
            }
        }
    }
    RegressionResult::from_moments(n, first, second)
}

/// `sum_i coeffs[i].1 * x[coeffs[i].0] + constant == 0` over the integers,
/// for slots `x_i` in `{0, 1}`.
///
/// The homomorphic check can only test the constraint modulo `p`. That is
/// the same test exactly when the left side, over every 0/1 assignment,
/// stays strictly between `-p` and `p`: then a multiple of `p` in that
/// range is zero. [`check_constraints_fit`] enforces this for every task,
/// and [`LinearConstraint::range`] gives the exact range it checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearConstraint {
    pub coeffs: Vec<(usize, i64)>,
    pub constant: i64,
}

impl LinearConstraint {
    /// Smallest and largest value of the left side over all 0/1 slots.
    pub fn range(&self) -> (i128, i128) {
        let mut lo = self.constant as i128;
        let mut hi = self.constant as i128;
        for &(_, c) in &self.coeffs {
            if c < 0 { lo += c as i128 } else { hi += c as i128 }
        }
        (lo, hi)
    }

    /// Value of the left side over the integers.
    pub fn eval(&self, x: &[u64]) -> i128 {
        self.constant as i128 + self.coeffs.iter().map(|&(i, c)| c as i128 * x[i] as i128).sum::<i128>()
    }

    /// Coefficients reduced into `F_p`.
    pub fn field_coeffs<'a>(&'a self, f: &'a Field) -> impl Iterator<Item = (usize, u64)> + 'a {
        self.coeffs.iter().map(move |&(i, c)| (i, f.reduce_i128(c as i128)))
    }

    /// Constant reduced into `F_p`.
    pub fn field_constant(&self, f: &Field) -> u64 {
        f.reduce_i128(self.constant as i128)
    }
}

/// Refuses a measurement type whose linear constraints the check cannot
/// enforce modulo `p`: some constraint's range over 0/1 slots reaches `p`
/// or `-p`, so a report could make it a nonzero multiple of `p` (zero
/// modulo `p`) with values outside the declared range. With `p` about
/// `2^32` (verdict mode) every type within `MAX_BITS` fits; with the
/// 19.6-bit prime of silent mode, `Sum` and `BoundedSumVec` fit up to
/// `2^19 - 1`.
pub fn check_constraints_fit(t: &MeasurementType, p: u64) -> Result<()> {
    let p = p as i128;
    for (l, (lo, hi)) in t.constraint_ranges().into_iter().enumerate() {
        if hi >= p || lo <= -p {
            return Err(Error::Config(format!(
                "{t:?}: linear constraint {l} takes values in [{lo}, {hi}] on 0/1 slots, which reaches p = {p}; \
                 checked modulo p it would not enforce the declared range. Use a narrower range or a larger plaintext modulus"
            )));
        }
    }
    Ok(())
}

fn bit_length(v: u64) -> u32 {
    64 - v.leading_zeros()
}

fn encode_bits(v: u64, bits: u32) -> Vec<u64> {
    (0..bits).map(|i| (v >> i) & 1).collect()
}

fn decode_bits_u128(slot_sums: &[u64]) -> u128 {
    slot_sums.iter().enumerate().map(|(i, &s)| (s as u128) << i).sum()
}

impl MeasurementType {
    /// Rejects parameter sets that the field cannot represent soundly.
    pub fn validate(&self) -> Result<()> {
        match self {
            MeasurementType::Count => Ok(()),
            MeasurementType::Sum { max_measurement } => {
                if *max_measurement == 0 {
                    return Err(Error::Config("Sum: max_measurement must be >= 1".into()));
                }
                if bit_length(*max_measurement) > MAX_BITS {
                    return Err(Error::Config(format!("Sum: max_measurement must be < 2^{MAX_BITS}")));
                }
                Ok(())
            }
            MeasurementType::SumVec { length, bits } => {
                if *length == 0 || *bits == 0 || *bits > MAX_BITS {
                    return Err(Error::Config(format!("SumVec: need length >= 1 and 1 <= bits <= {MAX_BITS}")));
                }
                Ok(())
            }
            MeasurementType::BoundedSumVec { bounds } => {
                if bounds.is_empty() {
                    return Err(Error::Config("BoundedSumVec: need at least one bound".into()));
                }
                for (e, &b) in bounds.iter().enumerate() {
                    if b == 0 || bit_length(b) > MAX_BITS {
                        return Err(Error::Config(format!("BoundedSumVec: bound {e} must be in [1, 2^{MAX_BITS})")));
                    }
                }
                Ok(())
            }
            MeasurementType::Histogram { length } => {
                if *length < 2 || (*length as u64) >= (1u64 << MAX_BITS) {
                    return Err(Error::Config("Histogram: need 2 <= length < 2^30".into()));
                }
                Ok(())
            }
            MeasurementType::MultihotCountVec { length, max_weight } => {
                if *length == 0 || (*length as u64) >= (1u64 << MAX_BITS) {
                    return Err(Error::Config("MultihotCountVec: need 1 <= length < 2^30".into()));
                }
                if *max_weight == 0 || max_weight > length {
                    return Err(Error::Config("MultihotCountVec: need 1 <= max_weight <= length".into()));
                }
                Ok(())
            }
        }
    }

    fn sum_bits(max_measurement: u64) -> u32 {
        bit_length(max_measurement)
    }
    fn sum_offset(max_measurement: u64) -> u64 {
        (1u64 << Self::sum_bits(max_measurement)) - 1 - max_measurement
    }
    fn weight_bits(max_weight: usize) -> u32 {
        bit_length(max_weight as u64)
    }
    fn weight_offset(max_weight: usize) -> u64 {
        (1u64 << Self::weight_bits(max_weight)) - 1 - max_weight as u64
    }

    /// Slot map of the integer values a type carries, as `(start, bits)`
    /// per value in encoding order: the value's bits are the `bits` slots
    /// from `start`. `None` for types that carry no integer vector. Used by
    /// the aggregate decoder, the second moments and the release policies.
    pub fn value_slots(&self) -> Option<Vec<(usize, u32)>> {
        match self {
            MeasurementType::SumVec { length, bits } => Some((0..*length).map(|a| (a * *bits as usize, *bits)).collect()),
            MeasurementType::BoundedSumVec { bounds } => {
                let mut v = Vec::with_capacity(bounds.len());
                let mut start = 0usize;
                for &b in bounds {
                    let bits = Self::sum_bits(b);
                    v.push((start, bits));
                    start += 2 * bits as usize;
                }
                Some(v)
            }
            _ => None,
        }
    }

    /// Number of elements of the aggregate (what a release policy names).
    pub fn num_elements(&self) -> usize {
        match self {
            MeasurementType::Count | MeasurementType::Sum { .. } => 1,
            MeasurementType::SumVec { length, .. } | MeasurementType::Histogram { length } | MeasurementType::MultihotCountVec { length, .. } => *length,
            MeasurementType::BoundedSumVec { bounds } => bounds.len(),
        }
    }

    /// Encoded slots that belong to element `e`: everything the collector
    /// needs to read that element and check its own constraints (for `Sum`
    /// and `BoundedSumVec` the offset bits too). Slots outside every
    /// element's range (the weight bits of `MultihotCountVec`) serve a
    /// constraint spanning all elements and are released only to collectors
    /// that see every element.
    pub fn element_slots(&self, e: usize) -> std::ops::Range<usize> {
        debug_assert!(e < self.num_elements());
        match self {
            MeasurementType::Count => 0..1,
            MeasurementType::Sum { .. } => 0..self.input_len(),
            MeasurementType::SumVec { bits, .. } => e * *bits as usize..(e + 1) * *bits as usize,
            MeasurementType::BoundedSumVec { .. } => {
                let (start, bits) = self.value_slots().expect("vector type")[e];
                start..start + 2 * bits as usize
            }
            MeasurementType::Histogram { .. } | MeasurementType::MultihotCountVec { .. } => e..e + 1,
        }
    }

    /// Number of field elements (all bits) in an encoded measurement.
    pub fn input_len(&self) -> usize {
        match self {
            MeasurementType::Count => 1,
            MeasurementType::Sum { max_measurement } => 2 * Self::sum_bits(*max_measurement) as usize,
            MeasurementType::SumVec { length, bits } => length * *bits as usize,
            MeasurementType::BoundedSumVec { bounds } => bounds.iter().map(|&b| 2 * Self::sum_bits(b) as usize).sum(),
            MeasurementType::Histogram { length } => *length,
            MeasurementType::MultihotCountVec { length, max_weight } => length + Self::weight_bits(*max_weight) as usize,
        }
    }

    /// Encodes a measurement into bits, checking it is in range.
    pub fn encode(&self, m: &Measurement) -> Result<Vec<u64>> {
        match (self, m) {
            (MeasurementType::Count, Measurement::Count(b)) => Ok(vec![*b as u64]),
            (MeasurementType::Sum { max_measurement }, Measurement::Sum(v)) => {
                if v > max_measurement {
                    return Err(Error::Measurement(format!("Sum: {v} > max_measurement {max_measurement}")));
                }
                let bits = Self::sum_bits(*max_measurement);
                let mut out = encode_bits(*v, bits);
                out.extend(encode_bits(v + Self::sum_offset(*max_measurement), bits));
                Ok(out)
            }
            (MeasurementType::SumVec { length, bits }, Measurement::SumVec(vs)) => {
                if vs.len() != *length {
                    return Err(Error::Measurement(format!("SumVec: expected {length} elements, got {}", vs.len())));
                }
                let mut out = Vec::with_capacity(self.input_len());
                for &v in vs {
                    if v >= (1u64 << bits) {
                        return Err(Error::Measurement(format!("SumVec: element {v} >= 2^{bits}")));
                    }
                    out.extend(encode_bits(v, *bits));
                }
                Ok(out)
            }
            (MeasurementType::BoundedSumVec { bounds }, Measurement::SumVec(vs)) => {
                if vs.len() != bounds.len() {
                    return Err(Error::Measurement(format!("BoundedSumVec: expected {} elements, got {}", bounds.len(), vs.len())));
                }
                let mut out = Vec::with_capacity(self.input_len());
                for (e, (&v, &b)) in vs.iter().zip(bounds).enumerate() {
                    if v > b {
                        return Err(Error::Measurement(format!("BoundedSumVec: element {e} is {v} > bound {b}")));
                    }
                    let bits = Self::sum_bits(b);
                    out.extend(encode_bits(v, bits));
                    out.extend(encode_bits(v + Self::sum_offset(b), bits));
                }
                Ok(out)
            }
            (MeasurementType::Histogram { length }, Measurement::Histogram(idx)) => {
                if idx >= length {
                    return Err(Error::Measurement(format!("Histogram: bucket {idx} >= length {length}")));
                }
                let mut out = vec![0u64; *length];
                out[*idx] = 1;
                Ok(out)
            }
            (MeasurementType::MultihotCountVec { length, max_weight }, Measurement::MultihotCountVec(set)) => {
                if set.len() != *length {
                    return Err(Error::Measurement(format!("MultihotCountVec: expected {length} entries, got {}", set.len())));
                }
                let weight = set.iter().filter(|b| **b).count();
                if weight > *max_weight {
                    return Err(Error::Measurement(format!("MultihotCountVec: weight {weight} > max_weight {max_weight}")));
                }
                let mut out: Vec<u64> = set.iter().map(|&b| b as u64).collect();
                out.extend(encode_bits(weight as u64 + Self::weight_offset(*max_weight), Self::weight_bits(*max_weight)));
                Ok(out)
            }
            _ => Err(Error::Measurement("measurement does not match the task's type".into())),
        }
    }

    /// The range of each linear constraint over 0/1 slots, in the order of
    /// [`Self::linear_constraints`], in closed form: validation must not
    /// allocate in proportion to a declared length. The unit tests check it
    /// against [`LinearConstraint::range`].
    pub fn constraint_ranges(&self) -> Vec<(i128, i128)> {
        let sum_range = |max: u64| -> (i128, i128) {
            let span = (1i128 << Self::sum_bits(max)) - 1;
            let o = Self::sum_offset(max) as i128;
            (o - span, o + span)
        };
        match self {
            MeasurementType::Count | MeasurementType::SumVec { .. } => vec![],
            MeasurementType::Sum { max_measurement } => vec![sum_range(*max_measurement)],
            MeasurementType::BoundedSumVec { bounds } => bounds.iter().map(|&b| sum_range(b)).collect(),
            MeasurementType::Histogram { length } => vec![(-1, *length as i128 - 1)],
            MeasurementType::MultihotCountVec { length, max_weight } => {
                let o = Self::weight_offset(*max_weight) as i128;
                vec![(o - ((1i128 << Self::weight_bits(*max_weight)) - 1), o + *length as i128)]
            }
        }
    }

    /// Linear constraints in addition to the per-slot bit checks, over the
    /// integers.
    pub fn linear_constraints(&self) -> Vec<LinearConstraint> {
        // value(x) + offset - value(y) == 0 over `bits` bits starting at `start`
        let sum_constraint = |start: usize, max: u64| -> LinearConstraint {
            let bits = Self::sum_bits(max) as usize;
            let mut coeffs = Vec::with_capacity(2 * bits);
            for i in 0..bits {
                coeffs.push((start + i, 1i64 << i));
            }
            for i in 0..bits {
                coeffs.push((start + bits + i, -(1i64 << i)));
            }
            LinearConstraint { coeffs, constant: Self::sum_offset(max) as i64 }
        };
        match self {
            MeasurementType::Count | MeasurementType::SumVec { .. } => vec![],
            MeasurementType::Sum { max_measurement } => vec![sum_constraint(0, *max_measurement)],
            MeasurementType::BoundedSumVec { bounds } => {
                // one constraint per element, each with its own challenge
                // coefficient (see verify.rs)
                let mut out = Vec::with_capacity(bounds.len());
                let mut start = 0usize;
                for &b in bounds {
                    out.push(sum_constraint(start, b));
                    start += 2 * Self::sum_bits(b) as usize;
                }
                out
            }
            MeasurementType::Histogram { length } => {
                // sum(x) - 1 == 0
                vec![LinearConstraint { coeffs: (0..*length).map(|i| (i, 1i64)).collect(), constant: -1 }]
            }
            MeasurementType::MultihotCountVec { length, max_weight } => {
                // sum(x) + offset - value(w) == 0
                let wb = Self::weight_bits(*max_weight) as usize;
                let mut coeffs: Vec<(usize, i64)> = (0..*length).map(|i| (i, 1i64)).collect();
                for j in 0..wb {
                    coeffs.push((length + j, -(1i64 << j)));
                }
                vec![LinearConstraint { coeffs, constant: Self::weight_offset(*max_weight) as i64 }]
            }
        }
    }

    /// Decodes per-slot sums over all accepted reports. Sums are exact
    /// integers because every slot is a bit and the batch is smaller than `p`.
    pub fn decode_aggregate(&self, slot_sums: &[u64]) -> Result<AggregateResult> {
        if slot_sums.len() < self.input_len() {
            return Err(Error::Protocol("aggregate has too few slots".into()));
        }
        Ok(match self {
            MeasurementType::Count => AggregateResult::Count(slot_sums[0]),
            MeasurementType::Sum { max_measurement } => {
                let bits = Self::sum_bits(*max_measurement) as usize;
                AggregateResult::Sum(decode_bits_u128(&slot_sums[..bits]))
            }
            MeasurementType::SumVec { length, bits } => {
                let b = *bits as usize;
                AggregateResult::SumVec((0..*length).map(|i| decode_bits_u128(&slot_sums[i * b..(i + 1) * b])).collect())
            }
            MeasurementType::BoundedSumVec { .. } => {
                let map = self.value_slots().expect("vector type");
                AggregateResult::SumVec(map.iter().map(|&(start, bits)| decode_bits_u128(&slot_sums[start..start + bits as usize])).collect())
            }
            MeasurementType::Histogram { length } => AggregateResult::Histogram(slot_sums[..*length].to_vec()),
            MeasurementType::MultihotCountVec { length, .. } => AggregateResult::MultihotCountVec(slot_sums[..*length].to_vec()),
        })
    }

    /// Checks that decrypted per-slot sums over `count` reports are
    /// consistent with `count` valid reports: every slot sum is at most
    /// `count`, and the type's linear constraints, summed over the batch,
    /// hold over the integers. A batch that contains a contribution that is
    /// not a proper encryption fails this with overwhelming probability,
    /// which is how silent mode detects (but cannot attribute) corruption.
    pub fn check_aggregate_consistency(&self, slot_sums: &[u64], count: u64) -> Result<()> {
        self.check_aggregate_consistency_visible(slot_sums, count, None)
    }

    /// As [`Self::check_aggregate_consistency`], for a collector that sees
    /// only `visible` slots (`None`: all). Hidden slots are zero in
    /// `slot_sums` and are not checked; a linear constraint is checked only
    /// when every slot it involves is visible. Constraints are evaluated
    /// over the integers with the type's own arithmetic, so this is the
    /// same check as the full one restricted to what the collector holds.
    pub fn check_aggregate_consistency_visible(&self, slot_sums: &[u64], count: u64, visible: Option<&[bool]>) -> Result<()> {
        let m = self.input_len();
        if slot_sums.len() < m {
            return Err(Error::Protocol("aggregate has too few slots".into()));
        }
        let vis = |i: usize| visible.map_or(true, |v| v[i]);
        if let Some((i, &s)) = slot_sums[..m].iter().enumerate().find(|&(i, &s)| vis(i) && s > count) {
            return Err(Error::Protocol(format!("aggregate inconsistent: slot {i} sums to {s} over {count} reports")));
        }
        let value = |bits: &[u64]| -> u128 { decode_bits_u128(bits) };
        let all_visible = |r: std::ops::Range<usize>| r.into_iter().all(vis);
        let ok = match self {
            MeasurementType::Count | MeasurementType::SumVec { .. } => true,
            MeasurementType::Sum { max_measurement } => {
                let bits = Self::sum_bits(*max_measurement) as usize;
                !all_visible(0..2 * bits) || value(&slot_sums[..bits]) + count as u128 * Self::sum_offset(*max_measurement) as u128 == value(&slot_sums[bits..2 * bits])
            }
            MeasurementType::BoundedSumVec { bounds } => {
                let map = self.value_slots().expect("vector type");
                map.iter().zip(bounds).all(|(&(start, bits), &b)| {
                    let bits = bits as usize;
                    !all_visible(start..start + 2 * bits)
                        || value(&slot_sums[start..start + bits]) + count as u128 * Self::sum_offset(b) as u128 == value(&slot_sums[start + bits..start + 2 * bits])
                })
            }
            MeasurementType::Histogram { length } => !all_visible(0..*length) || slot_sums[..*length].iter().map(|&s| s as u128).sum::<u128>() == count as u128,
            MeasurementType::MultihotCountVec { length, max_weight } => {
                let wb = Self::weight_bits(*max_weight) as usize;
                let weight: u128 = slot_sums[..*length].iter().map(|&s| s as u128).sum();
                !all_visible(0..*length + wb) || weight + count as u128 * Self::weight_offset(*max_weight) as u128 == value(&slot_sums[*length..*length + wb])
            }
        };
        if !ok {
            return Err(Error::Protocol("aggregate inconsistent: the batch linear constraint does not hold".into()));
        }
        Ok(())
    }

    /// Plaintext reference aggregation, for tests and for the collector's
    /// documentation of what the aggregate means.
    pub fn aggregate_plain(&self, ms: &[Measurement]) -> Result<AggregateResult> {
        let mut sums = vec![0u64; self.input_len()];
        for m in ms {
            for (s, b) in sums.iter_mut().zip(self.encode(m)?) {
                *s += b;
            }
        }
        self.decode_aggregate(&sums)
    }
}

/// Evaluates the validity predicate on a plaintext vector. Used by tests and
/// by the soundness discussion in the spec; never by the protocol itself.
pub fn is_valid_plain(t: &MeasurementType, _f: &Field, x: &[u64]) -> bool {
    if x.len() != t.input_len() {
        return false;
    }
    if x.iter().any(|&v| v != 0 && v != 1) {
        return false;
    }
    t.linear_constraints().iter().all(|c| c.eval(x) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fit rule is exact. For small primes and every type small enough
    /// to enumerate, a type passes `check_constraints_fit` exactly when no
    /// 0/1 assignment makes a constraint a nonzero multiple of p, that is,
    /// exactly when "zero modulo p" and "zero over the integers" agree.
    #[test]
    fn constraint_fit_is_exact_on_every_assignment() {
        let mut types = Vec::new();
        for max in 1..=255u64 {
            types.push(MeasurementType::Sum { max_measurement: max });
        }
        for length in 2..=14 {
            types.push(MeasurementType::Histogram { length });
        }
        for (length, w) in [(3, 1), (4, 2), (6, 3), (8, 5), (10, 7), (12, 12), (9, 8)] {
            types.push(MeasurementType::MultihotCountVec { length, max_weight: w });
        }
        for bounds in [vec![3u64, 5], vec![100, 2], vec![127, 1], vec![15, 15], vec![60, 6]] {
            types.push(MeasurementType::BoundedSumVec { bounds });
        }
        let (mut fit, mut unfit) = (0, 0);
        for p in [11u64, 97, 101, 257, 263] {
            for t in &types {
                t.validate().unwrap();
                let n = t.input_len();
                assert!(n <= 18, "{t:?} too large to enumerate");
                let cs = t.linear_constraints();
                assert_eq!(t.constraint_ranges(), cs.iter().map(|c| c.range()).collect::<Vec<_>>(), "{t:?}");
                let mut wraps = false;
                for mask in 0u32..(1 << n) {
                    let x: Vec<u64> = (0..n).map(|i| ((mask >> i) & 1) as u64).collect();
                    for c in &cs {
                        let v = c.eval(&x);
                        // the field evaluation used by the check agrees with v mod p
                        let f = Field::new(p).unwrap();
                        let mut acc = c.field_constant(&f);
                        for (i, coef) in c.field_coeffs(&f) {
                            acc = f.add(acc, f.mul(coef, x[i]));
                        }
                        assert_eq!(acc as i128, v.rem_euclid(p as i128), "{t:?} p={p}");
                        wraps |= v != 0 && v.rem_euclid(p as i128) == 0;
                    }
                }
                let ok = check_constraints_fit(t, p).is_ok();
                assert_eq!(ok, !wraps, "{t:?} p={p}: rule says fits={ok}, enumeration found a wrap={wraps}");
                if ok { fit += 1 } else { unfit += 1 }
            }
        }
        assert!(fit > 100 && unfit > 100, "both outcomes exercised: {fit} fit, {unfit} do not");
    }

    /// The widest ranges each real prime supports.
    #[test]
    fn widest_sound_ranges_under_the_real_primes() {
        let silent = 786_433u64;
        let verdict = 4_293_918_721u64;
        let sum = |m| MeasurementType::Sum { max_measurement: m };
        assert!(check_constraints_fit(&sum(524_287), silent).is_ok());
        assert!(check_constraints_fit(&sum(400_000), silent).is_ok());
        assert!(check_constraints_fit(&sum(524_288), silent).is_err());
        assert!(check_constraints_fit(&sum(600_000), silent).is_err());
        assert!(check_constraints_fit(&MeasurementType::BoundedSumVec { bounds: vec![100, 524_287] }, silent).is_ok());
        assert!(check_constraints_fit(&MeasurementType::BoundedSumVec { bounds: vec![100, 524_288] }, silent).is_err());
        assert!(check_constraints_fit(&MeasurementType::Histogram { length: 786_433 }, silent).is_ok());
        assert!(check_constraints_fit(&MeasurementType::Histogram { length: 786_434 }, silent).is_err());
        assert!(check_constraints_fit(&sum((1 << MAX_BITS) - 1), verdict).is_ok());
        assert!(check_constraints_fit(&MeasurementType::BoundedSumVec { bounds: vec![(1 << MAX_BITS) - 1; 3] }, verdict).is_ok());
        assert!(check_constraints_fit(&MeasurementType::MultihotCountVec { length: (1 << MAX_BITS) - 1, max_weight: 7 }, verdict).is_ok());
        // The report demonstrated against the unchecked configuration: for
        // max 600,000 under the silent prime it makes the constraint exactly p.
        let c = &sum(600_000).linear_constraints()[0];
        let b = 20;
        let mut x: Vec<u64> = (0..b).map(|i| (637_858u64 >> i) & 1).collect();
        x.extend((0..b).map(|i| (300_000u64 >> i) & 1));
        assert_eq!(c.eval(&x), silent as i128);
        let e = check_constraints_fit(&sum(600_000), silent).unwrap_err().to_string();
        assert!(e.contains("reaches p = 786433"), "{e}");
    }
    fn f() -> Field {
        Field::new(4_293_918_721).unwrap()
    }

    #[test]
    fn sum_encoding_matches_draft() {
        // max_measurement = 100 -> bits = 7, offset = 27
        let t = MeasurementType::Sum { max_measurement: 100 };
        assert_eq!(t.input_len(), 14);
        let e = t.encode(&Measurement::Sum(100)).unwrap();
        assert_eq!(&e[..7], &[0, 0, 1, 0, 0, 1, 1]); // 100
        assert_eq!(&e[7..], &[1, 1, 1, 1, 1, 1, 1]); // 127
        assert!(t.encode(&Measurement::Sum(101)).is_err());
        assert!(is_valid_plain(&t, &f(), &e));
        // 101 encoded "by hand" with a consistent second half fails the range check
        let mut bad = encode_bits(101, 7);
        bad.extend(encode_bits(101 + 27 - 128, 7)); // wraps: not representable
        assert!(!is_valid_plain(&t, &f(), &bad));
        // and 101 with y = 127 (max) violates value(y) == value(x) + offset
        let mut bad2 = encode_bits(101, 7);
        bad2.extend(encode_bits(127, 7));
        assert!(!is_valid_plain(&t, &f(), &bad2));
    }

    #[test]
    fn bounded_sumvec_encoding_and_per_element_ranges() {
        // bounds 100 (7 bits, offset 27), 255 (8 bits, offset 0), 5 (3 bits, offset 2), 1 (1 bit, offset 0)
        let t = MeasurementType::BoundedSumVec { bounds: vec![100, 255, 5, 1] };
        t.validate().unwrap();
        assert_eq!(t.input_len(), 2 * (7 + 8 + 3 + 1));
        assert_eq!(t.value_slots().unwrap(), vec![(0, 7), (14, 8), (30, 3), (36, 1)]);
        assert_eq!(t.linear_constraints().len(), 4);
        let e = t.encode(&Measurement::SumVec(vec![100, 255, 5, 1])).unwrap();
        assert_eq!(&e[..7], &[0, 0, 1, 0, 0, 1, 1]); // 100
        assert_eq!(&e[7..14], &[1, 1, 1, 1, 1, 1, 1]); // 127
        assert_eq!(&e[30..33], &[1, 0, 1]); // 5
        assert_eq!(&e[33..36], &[1, 1, 1]); // 7
        assert!(is_valid_plain(&t, &f(), &e));
        assert!(t.encode(&Measurement::SumVec(vec![101, 255, 5, 1])).is_err());
        assert!(t.encode(&Measurement::SumVec(vec![100, 256, 5, 1])).is_err());
        assert!(t.encode(&Measurement::SumVec(vec![100, 255, 6, 1])).is_err());
        assert!(t.encode(&Measurement::SumVec(vec![100, 255, 5, 2])).is_err());
        assert!(t.encode(&Measurement::SumVec(vec![100, 255, 5])).is_err());
        assert!(t.encode(&Measurement::Sum(1)).is_err());
        // element 2 = 6 (> 5) with any offset half: 6 + 2 = 8 does not fit in 3 bits
        for y in 0..8u64 {
            let mut bad = e.clone();
            bad[30..33].copy_from_slice(&encode_bits(6, 3));
            bad[33..36].copy_from_slice(&encode_bits(y, 3));
            assert!(!is_valid_plain(&t, &f(), &bad), "y = {y}");
        }
        // value bits fine, offset bits inconsistent
        let mut inc = e.clone();
        inc[33] ^= 1;
        assert!(!is_valid_plain(&t, &f(), &inc));
        // aggregate over three records and consistency
        let ms = vec![Measurement::SumVec(vec![100, 255, 5, 1]), Measurement::SumVec(vec![0, 0, 0, 0]), Measurement::SumVec(vec![50, 128, 3, 1])];
        let agg = t.aggregate_plain(&ms).unwrap();
        assert_eq!(agg, AggregateResult::SumVec(vec![150, 383, 8, 2]));
        let mut sums = vec![0u64; t.input_len()];
        for m in &ms {
            for (s, b) in sums.iter_mut().zip(t.encode(m).unwrap()) {
                *s += b;
            }
        }
        t.check_aggregate_consistency(&sums, 3).unwrap();
        let mut corrupt = sums.clone();
        corrupt[33] += 1; // offset half of element 2 no longer matches value half + 3*offset
        assert!(t.check_aggregate_consistency(&corrupt, 3).is_err());
        // parameter validation
        assert!(MeasurementType::BoundedSumVec { bounds: vec![] }.validate().is_err());
        assert!(MeasurementType::BoundedSumVec { bounds: vec![0] }.validate().is_err());
        assert!(MeasurementType::BoundedSumVec { bounds: vec![1u64 << MAX_BITS] }.validate().is_err());
    }

    #[test]
    fn histogram_and_multihot() {
        let h = MeasurementType::Histogram { length: 4 };
        assert!(is_valid_plain(&h, &f(), &[0, 0, 1, 0]));
        assert!(!is_valid_plain(&h, &f(), &[0, 1, 1, 0]));
        assert!(!is_valid_plain(&h, &f(), &[0, 0, 0, 0]));
        let m = MeasurementType::MultihotCountVec { length: 5, max_weight: 2 };
        // weight bits = 2, offset = 1
        assert_eq!(m.input_len(), 7);
        let e = m.encode(&Measurement::MultihotCountVec(vec![true, false, false, true, false])).unwrap();
        assert_eq!(e, vec![1, 0, 0, 1, 0, 1, 1]); // weight 2 + 1 = 3
        assert!(is_valid_plain(&m, &f(), &e));
        assert!(!is_valid_plain(&m, &f(), &[1, 1, 1, 0, 0, 1, 1]));
        assert!(m.encode(&Measurement::MultihotCountVec(vec![true, true, true, false, false])).is_err());
    }

    #[test]
    fn aggregate_roundtrip() {
        let t = MeasurementType::SumVec { length: 3, bits: 4 };
        let ms = vec![Measurement::SumVec(vec![15, 0, 7]), Measurement::SumVec(vec![1, 2, 3])];
        assert_eq!(t.aggregate_plain(&ms).unwrap(), AggregateResult::SumVec(vec![16, 2, 10]));
        let c = MeasurementType::Count;
        assert_eq!(c.aggregate_plain(&[Measurement::Count(true), Measurement::Count(false), Measurement::Count(true)]).unwrap(), AggregateResult::Count(2));
    }

    #[test]
    fn consistency_check() {
        let t = MeasurementType::Sum { max_measurement: 100 };
        let ms = vec![Measurement::Sum(51), Measurement::Sum(49)];
        let mut sums = vec![0u64; t.input_len()];
        for m in &ms {
            for (s, b) in sums.iter_mut().zip(t.encode(m).unwrap()) {
                *s += b;
            }
        }
        assert!(t.check_aggregate_consistency(&sums, 2).is_ok());
        let mut bad = sums.clone();
        bad[0] += 1; // breaks value(x) + 2*offset == value(y)
        assert!(t.check_aggregate_consistency(&bad, 2).is_err());
        let mut big = sums.clone();
        big[3] = 3; // more than count
        assert!(t.check_aggregate_consistency(&big, 2).is_err());
        let h = MeasurementType::Histogram { length: 3 };
        assert!(h.check_aggregate_consistency(&[1, 0, 2], 3).is_ok());
        assert!(h.check_aggregate_consistency(&[1, 0, 1], 3).is_err());
    }

    #[test]
    fn regression_from_moments_matches_closed_form() {
        // y = 2 + 3*x exactly
        let rows: Vec<Vec<u64>> = (0..6).map(|x| vec![x, 2 + 3 * x]).collect();
        let r = regression_plain(&rows);
        assert_eq!(r.n, 6);
        assert!((r.beta[0] - 2.0).abs() < 1e-9 && (r.beta[1] - 3.0).abs() < 1e-9, "{:?}", r.beta);
        // two features
        let rows: Vec<Vec<u64>> = vec![vec![1, 2, 8], vec![2, 1, 7], vec![3, 5, 19], vec![4, 1, 11], vec![0, 3, 8]];
        // y = 1 + 2 x1 + 2 x2 + noise-free? check: 1+2+4=7 vs 8 -> not exact; just check consistency
        let r = regression_plain(&rows);
        assert_eq!(r.first, vec![10, 12, 53]);
        assert_eq!(r.second[0][2], 1 * 8 + 2 * 7 + 3 * 19 + 4 * 11 + 0);
        assert_eq!(r.beta.len(), 3);
        assert!(solve_linear(vec![vec![1.0, 2.0], vec![2.0, 4.0]], vec![1.0, 2.0]).is_none());
    }

    #[test]
    fn parameter_validation() {
        assert!(MeasurementType::Sum { max_measurement: 1 << 30 }.validate().is_err());
        assert!(MeasurementType::Sum { max_measurement: (1 << 30) - 1 }.validate().is_ok());
        assert!(MeasurementType::SumVec { length: 1, bits: 31 }.validate().is_err());
        assert!(MeasurementType::Histogram { length: 1 }.validate().is_err());
        assert!(MeasurementType::MultihotCountVec { length: 3, max_weight: 4 }.validate().is_err());
    }
}
