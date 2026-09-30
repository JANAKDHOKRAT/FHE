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
    /// `length` integers each in `[0, max_measurement]`; aggregate is the
    /// element-wise sum.
    SumVec { length: usize, max_measurement: u64 },
    /// One integer per bound, element `e` in `[0, bounds[e]]` exactly;
    /// aggregate is the element-wise sum (`AggregateResult::SumVec`).
    /// Each element uses the draft's range-checked encoding against its
    /// own bound. Not a draft type; an extension for per-element ranges.
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
            // `r > col`: the pivot row is in the upper half of the split
            let (upper, lower) = a.split_at_mut(r);
            for (x, &y) in lower[0][col..].iter_mut().zip(&upper[col][col..]) {
                *x -= f * y;
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
    // The draft's condition on a range-checked integer: 2^bits < p.
    for max in t.range_bounds() {
        if (1u128 << range_bits(max)) >= p as u128 {
            return Err(Error::Config(format!(
                "{t:?}: a range-checked integer up to {max} needs {} bits and the draft requires 2^bits < p = {p}. \
                 Use a smaller bound or a larger plaintext modulus",
                range_bits(max)
            )));
        }
    }
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

/* ---- draft-22 range-checked integers (Section 7.4.5 of the draft) --------
 * An integer in `[0, max]` is `bits = bitlen(max)` slots, each 0 or 1, read
 * as a weighted sum: weights `1, 2, .., 2^(bits-2)` and a last weight
 * `max - (2^(bits-1) - 1)`. The weights sum to `max`, so every 0/1 vector
 * decodes to a value in range and no linear constraint is needed; the
 * validity check is the bit check alone. `encode_range_checked` and
 * `decode_range_checked` are the draft's `encode_range_checked_int` and
 * `decode_range_checked_int`; the unit tests compare them with vectors
 * produced by running the draft's reference code. */

/// Slots of the range-checked encoding of `[0, max]`, `max >= 1`.
pub fn range_bits(max: u64) -> u32 {
    bit_length(max)
}

/// Weight of the last slot: `max - (2^(bits-1) - 1)`, in `[1, 2^(bits-1)]`.
pub fn range_last_weight(max: u64) -> u64 {
    max - ((1u64 << (range_bits(max) - 1)) - 1)
}

/// Slot weights `1, 2, .., 2^(bits-2), last_weight`; they sum to `max`.
pub fn range_weights(max: u64) -> Vec<u64> {
    let bits = range_bits(max);
    let mut w: Vec<u64> = (0..bits - 1).map(|i| 1u64 << i).collect();
    w.push(range_last_weight(max));
    w
}

/// The draft's `encode_range_checked_int`: `v <= max` as `bits` 0/1 slots.
pub fn encode_range_checked(v: u64, max: u64) -> Vec<u64> {
    debug_assert!(v <= max);
    let bits = range_bits(max);
    let rest_all_ones = (1u64 << (bits - 1)) - 1;
    let last_weight = max - rest_all_ones;
    let (rest, last) = if v <= rest_all_ones { (v, 0u64) } else { (v - last_weight, 1u64) };
    let mut out: Vec<u64> = (0..bits - 1).map(|l| (rest >> l) & 1).collect();
    out.push(last);
    out
}

/// The draft's `decode_range_checked_int` over slot *sums*: the weighted
/// sum is linear, so it decodes a batch's per-slot sums into the exact sum
/// of the batch's values (in `u128`: `count * max < 2^128`).
pub fn decode_range_checked(slot_sums: &[u64], max: u64) -> u128 {
    range_weights(max).iter().zip(slot_sums).map(|(&w, &s)| w as u128 * s as u128).sum()
}

/// One power-of-two-weighted piece of an element, for the second moments:
/// its `bits` slots from `start` (weights `1, 2, .., 2^(bits-1)`), the
/// element it belongs to and the multiplier its value carries in that
/// element.
///
/// An element with bound `2^bits - 1` is one piece with multiplier 1. Any
/// other bound `B` is two pieces: `P`, the first `bits - 1` slots with
/// multiplier 1, and `b`, the last slot with multiplier
/// `L = B - 2^(bits-1) + 1`, so that `v = P + L * b`. The collector
/// recombines the products of pieces into the products of values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MomentPiece {
    pub start: usize,
    pub bits: u32,
    pub element: usize,
    pub multiplier: u64,
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
            MeasurementType::SumVec { length, max_measurement } => {
                if *length == 0 || *max_measurement == 0 || bit_length(*max_measurement) > MAX_BITS {
                    return Err(Error::Config(format!("SumVec: need length >= 1 and 1 <= max_measurement < 2^{MAX_BITS}")));
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

    /// Every bound a range-checked integer of this type is encoded against
    /// (the draft requires `2^bitlen(bound) < p` for each).
    pub fn range_bounds(&self) -> Vec<u64> {
        match self {
            MeasurementType::Count | MeasurementType::Histogram { .. } => vec![],
            MeasurementType::Sum { max_measurement } => vec![*max_measurement],
            MeasurementType::SumVec { max_measurement, .. } => vec![*max_measurement],
            MeasurementType::BoundedSumVec { bounds } => bounds.clone(),
            MeasurementType::MultihotCountVec { max_weight, .. } => vec![*max_weight as u64],
        }
    }

    /// Slot map of the integer values a type carries, as `(start, bits)`
    /// per element in encoding order: the element's range-checked slots
    /// are the `bits` slots from `start`. `None` for types that carry no
    /// integer vector. Used by the aggregate decoder and the release
    /// policies; the second moments use [`Self::moment_pieces`].
    pub fn value_slots(&self) -> Option<Vec<(usize, u32)>> {
        match self {
            MeasurementType::SumVec { length, max_measurement } => {
                let bits = range_bits(*max_measurement);
                Some((0..*length).map(|a| (a * bits as usize, bits)).collect())
            }
            MeasurementType::BoundedSumVec { bounds } => {
                let mut v = Vec::with_capacity(bounds.len());
                let mut start = 0usize;
                for &b in bounds {
                    let bits = range_bits(b);
                    v.push((start, bits));
                    start += bits as usize;
                }
                Some(v)
            }
            _ => None,
        }
    }

    /// The bound of each element of a vector type, in element order.
    pub fn value_bounds(&self) -> Option<Vec<u64>> {
        match self {
            MeasurementType::SumVec { length, max_measurement } => Some(vec![*max_measurement; *length]),
            MeasurementType::BoundedSumVec { bounds } => Some(bounds.clone()),
            _ => None,
        }
    }

    /// Power-of-two-weighted pieces of the elements (see [`MomentPiece`]),
    /// in element order, `None` for types without an integer vector.
    pub fn moment_pieces(&self) -> Option<Vec<MomentPiece>> {
        let slots = self.value_slots()?;
        let bounds = self.value_bounds()?;
        let mut out = Vec::with_capacity(slots.len());
        for (e, (&(start, bits), &max)) in slots.iter().zip(&bounds).enumerate() {
            let last = range_last_weight(max);
            if last == 1u64 << (bits - 1) {
                // bound 2^bits - 1: plain binary, one piece
                out.push(MomentPiece {
                    start,
                    bits,
                    element: e,
                    multiplier: 1,
                });
            } else {
                if bits > 1 {
                    out.push(MomentPiece {
                        start,
                        bits: bits - 1,
                        element: e,
                        multiplier: 1,
                    });
                }
                out.push(MomentPiece {
                    start: start + bits as usize - 1,
                    bits: 1,
                    element: e,
                    multiplier: last,
                });
            }
        }
        Some(out)
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
    /// needs to read that element. Slots outside every element's range (the
    /// weight slots of `MultihotCountVec`) serve a constraint spanning all
    /// elements and are released only to collectors that see every element.
    pub fn element_slots(&self, e: usize) -> std::ops::Range<usize> {
        debug_assert!(e < self.num_elements());
        match self {
            MeasurementType::Count => 0..1,
            MeasurementType::Sum { .. } => 0..self.input_len(),
            MeasurementType::SumVec { .. } | MeasurementType::BoundedSumVec { .. } => {
                let (start, bits) = self.value_slots().expect("vector type")[e];
                start..start + bits as usize
            }
            MeasurementType::Histogram { .. } | MeasurementType::MultihotCountVec { .. } => e..e + 1,
        }
    }

    /// Number of field elements (all bits) in an encoded measurement.
    pub fn input_len(&self) -> usize {
        match self {
            MeasurementType::Count => 1,
            MeasurementType::Sum { max_measurement } => range_bits(*max_measurement) as usize,
            MeasurementType::SumVec { length, max_measurement } => length * range_bits(*max_measurement) as usize,
            MeasurementType::BoundedSumVec { bounds } => bounds.iter().map(|&b| range_bits(b) as usize).sum(),
            MeasurementType::Histogram { length } => *length,
            MeasurementType::MultihotCountVec { length, max_weight } => length + range_bits(*max_weight as u64) as usize,
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
                Ok(encode_range_checked(*v, *max_measurement))
            }
            (MeasurementType::SumVec { length, max_measurement }, Measurement::SumVec(vs)) => {
                if vs.len() != *length {
                    return Err(Error::Measurement(format!("SumVec: expected {length} elements, got {}", vs.len())));
                }
                let mut out = Vec::with_capacity(self.input_len());
                for &v in vs {
                    if v > *max_measurement {
                        return Err(Error::Measurement(format!("SumVec: element {v} > max_measurement {max_measurement}")));
                    }
                    out.extend(encode_range_checked(v, *max_measurement));
                }
                Ok(out)
            }
            (MeasurementType::BoundedSumVec { bounds }, Measurement::SumVec(vs)) => {
                if vs.len() != bounds.len() {
                    return Err(Error::Measurement(format!(
                        "BoundedSumVec: expected {} elements, got {}",
                        bounds.len(),
                        vs.len()
                    )));
                }
                let mut out = Vec::with_capacity(self.input_len());
                for (e, (&v, &b)) in vs.iter().zip(bounds).enumerate() {
                    if v > b {
                        return Err(Error::Measurement(format!("BoundedSumVec: element {e} is {v} > bound {b}")));
                    }
                    out.extend(encode_range_checked(v, b));
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
                out.extend(encode_range_checked(weight as u64, *max_weight as u64));
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
        match self {
            MeasurementType::Count | MeasurementType::Sum { .. } | MeasurementType::SumVec { .. } | MeasurementType::BoundedSumVec { .. } => vec![],
            MeasurementType::Histogram { length } => vec![(-1, *length as i128 - 1)],
            // sum(x) - value(w): the weights of w sum to max_weight
            MeasurementType::MultihotCountVec { length, max_weight } => vec![(-(*max_weight as i128), *length as i128)],
        }
    }

    /// Linear constraints in addition to the per-slot bit checks, over the
    /// integers. Range-checked integers need none: their weights already
    /// confine every 0/1 vector to the range.
    pub fn linear_constraints(&self) -> Vec<LinearConstraint> {
        match self {
            MeasurementType::Count | MeasurementType::Sum { .. } | MeasurementType::SumVec { .. } | MeasurementType::BoundedSumVec { .. } => vec![],
            MeasurementType::Histogram { length } => {
                // sum(x) - 1 == 0
                vec![LinearConstraint {
                    coeffs: (0..*length).map(|i| (i, 1i64)).collect(),
                    constant: -1,
                }]
            }
            MeasurementType::MultihotCountVec { length, max_weight } => {
                // sum(x) - value(w) == 0, value(w) the range-checked weight
                let mut coeffs: Vec<(usize, i64)> = (0..*length).map(|i| (i, 1i64)).collect();
                for (j, w) in range_weights(*max_weight as u64).into_iter().enumerate() {
                    coeffs.push((length + j, -(w as i64)));
                }
                vec![LinearConstraint { coeffs, constant: 0 }]
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
                let bits = range_bits(*max_measurement) as usize;
                AggregateResult::Sum(decode_range_checked(&slot_sums[..bits], *max_measurement))
            }
            MeasurementType::SumVec { .. } | MeasurementType::BoundedSumVec { .. } => {
                let map = self.value_slots().expect("vector type");
                let bounds = self.value_bounds().expect("vector type");
                AggregateResult::SumVec(
                    map.iter()
                        .zip(&bounds)
                        .map(|(&(start, bits), &max)| decode_range_checked(&slot_sums[start..start + bits as usize], max))
                        .collect(),
                )
            }
            MeasurementType::Histogram { length } => AggregateResult::Histogram(slot_sums[..*length].to_vec()),
            MeasurementType::MultihotCountVec { length, .. } => AggregateResult::MultihotCountVec(slot_sums[..*length].to_vec()),
        })
    }

    /// Checks that decrypted per-slot sums over `count` reports are
    /// consistent with `count` valid reports: every slot sum is at most
    /// `count`, and the type's linear constraints, summed over the batch,
    /// hold over the integers. A contribution that is not a proper
    /// encryption lands each of its slots on a value that is uniform modulo
    /// `p`, so it passes the slot bound with probability `(count + 1) / p`
    /// per slot; that is how silent mode detects (but cannot attribute)
    /// corruption.
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
        let vis = |i: usize| visible.is_none_or(|v| v[i]);
        if let Some((i, &s)) = slot_sums[..m].iter().enumerate().find(|&(i, &s)| vis(i) && s > count) {
            return Err(Error::Protocol(format!("aggregate inconsistent: slot {i} sums to {s} over {count} reports")));
        }
        let all_visible = |r: std::ops::Range<usize>| r.into_iter().all(vis);
        let ok = match self {
            MeasurementType::Count | MeasurementType::Sum { .. } | MeasurementType::SumVec { .. } | MeasurementType::BoundedSumVec { .. } => true,
            MeasurementType::Histogram { length } => !all_visible(0..*length) || slot_sums[..*length].iter().map(|&s| s as u128).sum::<u128>() == count as u128,
            MeasurementType::MultihotCountVec { length, max_weight } => {
                let wb = range_bits(*max_weight as u64) as usize;
                let weight: u128 = slot_sums[..*length].iter().map(|&s| s as u128).sum();
                !all_visible(0..*length + wb) || weight == decode_range_checked(&slot_sums[*length..*length + wb], *max_weight as u64)
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
    /// to enumerate, a type passes the constraint part of
    /// `check_constraints_fit` exactly when no 0/1 assignment makes a
    /// constraint a nonzero multiple of p, that is, exactly when "zero
    /// modulo p" and "zero over the integers" agree. (The field-size rule
    /// on range-checked bounds is separate and tested below.)
    #[test]
    fn constraint_fit_is_exact_on_every_assignment() {
        let mut types = Vec::new();
        for length in 2..=14 {
            types.push(MeasurementType::Histogram { length });
        }
        for (length, w) in [(3, 1), (4, 2), (6, 3), (8, 5), (10, 7), (12, 12), (9, 8), (14, 3), (13, 13)] {
            types.push(MeasurementType::MultihotCountVec { length, max_weight: w });
        }
        let (mut fit, mut unfit) = (0, 0);
        for p in [11u64, 17, 97, 101, 257, 263] {
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
                // range-checked bounds that the field-size rule refuses are
                // not part of this enumeration
                let field_ok = t.range_bounds().iter().all(|&m| (1u128 << range_bits(m)) < p as u128);
                if !field_ok {
                    continue;
                }
                let ok = check_constraints_fit(t, p).is_ok();
                assert_eq!(ok, !wraps, "{t:?} p={p}: rule says fits={ok}, enumeration found a wrap={wraps}");
                if ok { fit += 1 } else { unfit += 1 }
            }
        }
        // 125 fit and 4 do not with these types and primes (the unfit ones
        // are Histogram lengths and MultihotCountVec ranges reaching p = 11)
        assert!(fit > 100 && unfit >= 4, "both outcomes exercised: {fit} fit, {unfit} do not");
    }

    /// The widest ranges each real prime supports: the draft's `2^bits < p`
    /// on every range-checked bound, and the constraint ranges inside (-p, p).
    #[test]
    fn widest_sound_ranges_under_the_real_primes() {
        let silent = 786_433u64;
        let verdict = 4_293_918_721u64;
        let sum = |m| MeasurementType::Sum { max_measurement: m };
        // 19 bits: 2^19 = 524,288 < 786,433; 20 bits: 2^20 >= p
        assert!(check_constraints_fit(&sum(524_287), silent).is_ok());
        assert!(check_constraints_fit(&sum(400_000), silent).is_ok());
        assert!(check_constraints_fit(&sum(524_288), silent).is_err());
        assert!(check_constraints_fit(&sum(600_000), silent).is_err());
        assert!(check_constraints_fit(&MeasurementType::BoundedSumVec { bounds: vec![100, 524_287] }, silent).is_ok());
        assert!(check_constraints_fit(&MeasurementType::BoundedSumVec { bounds: vec![100, 524_288] }, silent).is_err());
        assert!(
            check_constraints_fit(
                &MeasurementType::SumVec {
                    length: 3,
                    max_measurement: 524_287
                },
                silent
            )
            .is_ok()
        );
        assert!(
            check_constraints_fit(
                &MeasurementType::SumVec {
                    length: 3,
                    max_measurement: 524_288
                },
                silent
            )
            .is_err()
        );
        assert!(check_constraints_fit(&MeasurementType::Histogram { length: 786_433 }, silent).is_ok());
        assert!(check_constraints_fit(&MeasurementType::Histogram { length: 786_434 }, silent).is_err());
        assert!(check_constraints_fit(&sum((1 << MAX_BITS) - 1), verdict).is_ok());
        assert!(
            check_constraints_fit(
                &MeasurementType::BoundedSumVec {
                    bounds: vec![(1 << MAX_BITS) - 1; 3]
                },
                verdict
            )
            .is_ok()
        );
        assert!(
            check_constraints_fit(
                &MeasurementType::MultihotCountVec {
                    length: (1 << MAX_BITS) - 1,
                    max_weight: 7
                },
                verdict
            )
            .is_ok()
        );
        // the weight of a MultihotCountVec is range-checked too
        assert!(
            check_constraints_fit(
                &MeasurementType::MultihotCountVec {
                    length: 700_000,
                    max_weight: 524_288
                },
                silent
            )
            .is_err()
        );
        let e = check_constraints_fit(&sum(600_000), silent).unwrap_err().to_string();
        assert!(e.contains("2^bits < p = 786433"), "{e}");
    }

    fn f() -> Field {
        Field::new(4_293_918_721).unwrap()
    }

    /// Vectors produced by running draft-22's reference `encode_range_checked_int`
    /// (poc/vdaf_poc/flp_bbcggi19.py, tag draft-irtf-cfrg-vdaf-22) verbatim
    /// with a prime field of modulus 4293918721: `(max, value, slots)`,
    /// slots least significant first, last slot last.
    const DRAFT_VECTORS: &[(u64, u64, &str)] = &[
        (1, 0, "0"),
        (1, 1, "1"),
        (2, 0, "00"),
        (2, 1, "10"),
        (2, 2, "11"),
        (3, 0, "00"),
        (3, 1, "10"),
        (3, 2, "01"),
        (3, 3, "11"),
        (7, 0, "000"),
        (7, 1, "100"),
        (7, 3, "110"),
        (7, 6, "011"),
        (7, 7, "111"),
        (8, 0, "0000"),
        (8, 1, "1000"),
        (8, 4, "0010"),
        (8, 7, "1110"),
        (8, 8, "1111"),
        (100, 0, "0000000"),
        (100, 1, "1000000"),
        (100, 50, "0100110"),
        (100, 99, "0111111"),
        (100, 100, "1111111"),
        (255, 0, "00000000"),
        (255, 1, "10000000"),
        (255, 127, "11111110"),
        (255, 254, "01111111"),
        (255, 255, "11111111"),
        (256, 0, "000000000"),
        (256, 1, "100000000"),
        (256, 128, "000000010"),
        (256, 255, "111111110"),
        (256, 256, "111111111"),
        (1000, 0, "0000000000"),
        (1000, 1, "1000000000"),
        (1000, 500, "0010111110"),
        (1000, 999, "0111111111"),
        (1000, 1000, "1111111111"),
        (4293918720, 0, "00000000000000000000000000000000"),
        (4293918720, 1, "10000000000000000000000000000000"),
        (4293918720, 2146959360, "00000000000000000001111111111110"),
        (4293918720, 4293918719, "01111111111111111111111111111111"),
        (4293918720, 4293918720, "11111111111111111111111111111111"),
    ];

    #[test]
    fn range_checked_encoding_matches_the_draft_reference() {
        for &(max, v, slots) in DRAFT_VECTORS {
            let want: Vec<u64> = slots.bytes().map(|b| (b - b'0') as u64).collect();
            assert_eq!(encode_range_checked(v, max), want, "max {max} value {v}");
            assert_eq!(decode_range_checked(&want, max), v as u128, "decode max {max} value {v}");
            assert_eq!(range_bits(max) as usize, slots.len());
        }
        // the weights sum to max, so every 0/1 vector is in range and no
        // value above max has an encoding
        for max in [1u64, 2, 3, 7, 8, 100, 255, 256, 1000] {
            assert_eq!(range_weights(max).iter().sum::<u64>(), max);
            let bits = range_bits(max);
            for mask in 0u64..(1 << bits) {
                let x: Vec<u64> = (0..bits).map(|i| (mask >> i) & 1).collect();
                assert!(decode_range_checked(&x, max) <= max as u128);
            }
            for v in 0..=max {
                assert_eq!(decode_range_checked(&encode_range_checked(v, max), max), v as u128);
            }
        }
    }

    #[test]
    fn sum_encoding_matches_draft() {
        // max_measurement = 100 -> 7 slots, weights 1, 2, 4, 8, 16, 32, 37
        let t = MeasurementType::Sum { max_measurement: 100 };
        assert_eq!(t.input_len(), 7);
        assert_eq!(range_weights(100), vec![1, 2, 4, 8, 16, 32, 37]);
        assert!(t.linear_constraints().is_empty());
        let e = t.encode(&Measurement::Sum(98)).unwrap();
        assert_eq!(e, vec![1, 0, 1, 1, 1, 1, 1]); // 1 + 4 + 8 + 16 + 32 + 37
        assert!(t.encode(&Measurement::Sum(101)).is_err());
        assert!(is_valid_plain(&t, &f(), &e));
        // a non-bit slot is the only way to claim 101: 2 * 32 + 37
        assert!(!is_valid_plain(&t, &f(), &[0, 0, 0, 0, 0, 2, 1]));
        assert_eq!(
            t.aggregate_plain(&[Measurement::Sum(51), Measurement::Sum(49)]).unwrap(),
            AggregateResult::Sum(100)
        );
    }

    #[test]
    fn bounded_sumvec_encoding_and_per_element_ranges() {
        // bounds 100 (7 slots, last weight 37), 255 (8, last 128), 5 (3, last 2), 1 (1, last 1)
        let t = MeasurementType::BoundedSumVec { bounds: vec![100, 255, 5, 1] };
        t.validate().unwrap();
        assert_eq!(t.input_len(), 7 + 8 + 3 + 1);
        assert_eq!(t.value_slots().unwrap(), vec![(0, 7), (7, 8), (15, 3), (18, 1)]);
        assert!(t.linear_constraints().is_empty());
        let e = t.encode(&Measurement::SumVec(vec![100, 255, 5, 1])).unwrap();
        assert_eq!(&e[..7], &[1, 1, 1, 1, 1, 1, 1]);
        assert_eq!(&e[7..15], &[1, 1, 1, 1, 1, 1, 1, 1]);
        assert_eq!(&e[15..18], &[1, 1, 1]); // 1 + 2 + 2
        assert_eq!(&e[18..], &[1]);
        assert!(is_valid_plain(&t, &f(), &e));
        assert!(t.encode(&Measurement::SumVec(vec![101, 255, 5, 1])).is_err());
        assert!(t.encode(&Measurement::SumVec(vec![100, 256, 5, 1])).is_err());
        assert!(t.encode(&Measurement::SumVec(vec![100, 255, 6, 1])).is_err());
        assert!(t.encode(&Measurement::SumVec(vec![100, 255, 5, 2])).is_err());
        assert!(t.encode(&Measurement::SumVec(vec![100, 255, 5])).is_err());
        assert!(t.encode(&Measurement::Sum(1)).is_err());
        // every 0/1 assignment of element 2's slots is at most 5
        for mask in 0u64..8 {
            let x: Vec<u64> = (0..3).map(|i| (mask >> i) & 1).collect();
            assert!(decode_range_checked(&x, 5) <= 5);
        }
        // moment pieces: 100 and 5 split (last weights 37 and 2), 255 and 1 do not
        assert_eq!(
            t.moment_pieces().unwrap(),
            vec![
                MomentPiece {
                    start: 0,
                    bits: 6,
                    element: 0,
                    multiplier: 1
                },
                MomentPiece {
                    start: 6,
                    bits: 1,
                    element: 0,
                    multiplier: 37
                },
                MomentPiece {
                    start: 7,
                    bits: 8,
                    element: 1,
                    multiplier: 1
                },
                MomentPiece {
                    start: 15,
                    bits: 2,
                    element: 2,
                    multiplier: 1
                },
                MomentPiece {
                    start: 17,
                    bits: 1,
                    element: 2,
                    multiplier: 2
                },
                MomentPiece {
                    start: 18,
                    bits: 1,
                    element: 3,
                    multiplier: 1
                },
            ]
        );
        // aggregate over three records and consistency
        let ms = vec![
            Measurement::SumVec(vec![100, 255, 5, 1]),
            Measurement::SumVec(vec![0, 0, 0, 0]),
            Measurement::SumVec(vec![50, 128, 3, 1]),
        ];
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
        corrupt[6] = 4; // more than the three reports
        assert!(t.check_aggregate_consistency(&corrupt, 3).is_err());
        // parameter validation
        assert!(MeasurementType::BoundedSumVec { bounds: vec![] }.validate().is_err());
        assert!(MeasurementType::BoundedSumVec { bounds: vec![0] }.validate().is_err());
        assert!(
            MeasurementType::BoundedSumVec {
                bounds: vec![1u64 << MAX_BITS]
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn histogram_and_multihot() {
        let h = MeasurementType::Histogram { length: 4 };
        assert!(is_valid_plain(&h, &f(), &[0, 0, 1, 0]));
        assert!(!is_valid_plain(&h, &f(), &[0, 1, 1, 0]));
        assert!(!is_valid_plain(&h, &f(), &[0, 0, 0, 0]));
        let m = MeasurementType::MultihotCountVec { length: 5, max_weight: 2 };
        // weight slots: 2, weights 1 and 1 (2 - (2^1 - 1))
        assert_eq!(m.input_len(), 7);
        assert_eq!(range_weights(2), vec![1, 1]);
        let e = m.encode(&Measurement::MultihotCountVec(vec![true, false, false, true, false])).unwrap();
        assert_eq!(e, vec![1, 0, 0, 1, 0, 1, 1]); // weight 2 = 1 + 1
        assert!(is_valid_plain(&m, &f(), &e));
        // weight 3 claimed as 2
        assert!(!is_valid_plain(&m, &f(), &[1, 1, 1, 0, 0, 1, 1]));
        // weight 1 claimed as 2
        assert!(!is_valid_plain(&m, &f(), &[1, 0, 0, 0, 0, 1, 1]));
        assert!(m.encode(&Measurement::MultihotCountVec(vec![true, true, true, false, false])).is_err());
        assert_eq!(m.constraint_ranges(), vec![(-2, 5)]);
        // max_weight 5 over 6 positions: weights 1, 2, 2
        let m5 = MeasurementType::MultihotCountVec { length: 6, max_weight: 5 };
        assert_eq!(range_weights(5), vec![1, 2, 2]);
        let e5 = m5.encode(&Measurement::MultihotCountVec(vec![true, true, true, true, true, false])).unwrap();
        assert_eq!(&e5[6..], &[1, 1, 1]); // 5 > 3: rest = 5 - 2 = 3 -> [1, 1], last slot 1
        assert!(is_valid_plain(&m5, &f(), &e5));
    }

    #[test]
    fn aggregate_roundtrip() {
        let t = MeasurementType::SumVec {
            length: 3,
            max_measurement: 15,
        };
        let ms = vec![Measurement::SumVec(vec![15, 0, 7]), Measurement::SumVec(vec![1, 2, 3])];
        assert_eq!(t.aggregate_plain(&ms).unwrap(), AggregateResult::SumVec(vec![16, 2, 10]));
        let t = MeasurementType::SumVec { length: 2, max_measurement: 5 };
        let ms = vec![Measurement::SumVec(vec![3, 5]), Measurement::SumVec(vec![4, 4])];
        assert_eq!(t.aggregate_plain(&ms).unwrap(), AggregateResult::SumVec(vec![7, 9]));
        let c = MeasurementType::Count;
        assert_eq!(
            c.aggregate_plain(&[Measurement::Count(true), Measurement::Count(false), Measurement::Count(true)])
                .unwrap(),
            AggregateResult::Count(2)
        );
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
        let mut big = sums.clone();
        big[3] = 3; // more than count
        assert!(t.check_aggregate_consistency(&big, 2).is_err());
        let h = MeasurementType::Histogram { length: 3 };
        assert!(h.check_aggregate_consistency(&[1, 0, 2], 3).is_ok());
        assert!(h.check_aggregate_consistency(&[1, 0, 1], 3).is_err());
        let m = MeasurementType::MultihotCountVec { length: 3, max_weight: 2 };
        // two reports of weight 1 and 2: counts [2, 1, 0], weight slots (1, 1) summed: [2, 1]
        assert!(m.check_aggregate_consistency(&[2, 1, 0, 2, 1], 2).is_ok());
        assert!(m.check_aggregate_consistency(&[2, 1, 0, 1, 1], 2).is_err());
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
        // rows' x1 * y: 1*8 + 2*7 + 3*19 + 4*11 + 0*8
        assert_eq!(r.second[0][2], 8 + 2 * 7 + 3 * 19 + 4 * 11);
        assert_eq!(r.beta.len(), 3);
        assert!(solve_linear(vec![vec![1.0, 2.0], vec![2.0, 4.0]], vec![1.0, 2.0]).is_none());
    }

    #[test]
    fn parameter_validation() {
        assert!(MeasurementType::Sum { max_measurement: 1 << 30 }.validate().is_err());
        assert!(
            MeasurementType::Sum {
                max_measurement: (1 << 30) - 1
            }
            .validate()
            .is_ok()
        );
        assert!(
            MeasurementType::SumVec {
                length: 1,
                max_measurement: 1 << 30
            }
            .validate()
            .is_err()
        );
        assert!(MeasurementType::SumVec { length: 0, max_measurement: 1 }.validate().is_err());
        assert!(MeasurementType::SumVec { length: 1, max_measurement: 0 }.validate().is_err());
        assert!(MeasurementType::Histogram { length: 1 }.validate().is_err());
        assert!(MeasurementType::MultihotCountVec { length: 3, max_weight: 4 }.validate().is_err());
    }
}
