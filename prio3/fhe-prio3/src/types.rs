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

/// `sum_i coeffs[i].1 * x[coeffs[i].0] + constant == 0` in F_p.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearConstraint {
    pub coeffs: Vec<(usize, u64)>,
    pub constant: u64,
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

    /// Linear constraints in addition to the per-slot bit checks.
    pub fn linear_constraints(&self, f: &Field) -> Vec<LinearConstraint> {
        match self {
            MeasurementType::Count | MeasurementType::SumVec { .. } => vec![],
            MeasurementType::Sum { max_measurement } => {
                // value(x) + offset - value(y) == 0
                let bits = Self::sum_bits(*max_measurement) as usize;
                let mut coeffs = Vec::with_capacity(2 * bits);
                for i in 0..bits {
                    coeffs.push((i, 1u64 << i));
                }
                for i in 0..bits {
                    coeffs.push((bits + i, f.neg(1u64 << i)));
                }
                vec![LinearConstraint { coeffs, constant: Self::sum_offset(*max_measurement) }]
            }
            MeasurementType::BoundedSumVec { bounds } => {
                // per element e: value(x_e) + offset_e - value(y_e) == 0, each
                // with its own challenge coefficient (see verify.rs)
                let mut out = Vec::with_capacity(bounds.len());
                let mut start = 0usize;
                for &b in bounds {
                    let bits = Self::sum_bits(b) as usize;
                    let mut coeffs = Vec::with_capacity(2 * bits);
                    for i in 0..bits {
                        coeffs.push((start + i, 1u64 << i));
                    }
                    for i in 0..bits {
                        coeffs.push((start + bits + i, f.neg(1u64 << i)));
                    }
                    out.push(LinearConstraint { coeffs, constant: Self::sum_offset(b) });
                    start += 2 * bits;
                }
                out
            }
            MeasurementType::Histogram { length } => {
                // sum(x) - 1 == 0
                vec![LinearConstraint { coeffs: (0..*length).map(|i| (i, 1u64)).collect(), constant: f.neg(1) }]
            }
            MeasurementType::MultihotCountVec { length, max_weight } => {
                // sum(x) + offset - value(w) == 0
                let wb = Self::weight_bits(*max_weight) as usize;
                let mut coeffs: Vec<(usize, u64)> = (0..*length).map(|i| (i, 1u64)).collect();
                for j in 0..wb {
                    coeffs.push((length + j, f.neg(1u64 << j)));
                }
                vec![LinearConstraint { coeffs, constant: Self::weight_offset(*max_weight) }]
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
        if slot_sums.len() < self.input_len() {
            return Err(Error::Protocol("aggregate has too few slots".into()));
        }
        if let Some((i, &s)) = slot_sums[..self.input_len()].iter().enumerate().find(|&(_, &s)| s > count) {
            return Err(Error::Protocol(format!("aggregate inconsistent: slot {i} sums to {s} over {count} reports")));
        }
        let value = |bits: &[u64]| -> u128 { decode_bits_u128(bits) };
        let ok = match self {
            MeasurementType::Count | MeasurementType::SumVec { .. } => true,
            MeasurementType::Sum { max_measurement } => {
                let bits = Self::sum_bits(*max_measurement) as usize;
                value(&slot_sums[..bits]) + count as u128 * Self::sum_offset(*max_measurement) as u128 == value(&slot_sums[bits..2 * bits])
            }
            MeasurementType::BoundedSumVec { bounds } => {
                let map = self.value_slots().expect("vector type");
                map.iter().zip(bounds).all(|(&(start, bits), &b)| {
                    let bits = bits as usize;
                    value(&slot_sums[start..start + bits]) + count as u128 * Self::sum_offset(b) as u128 == value(&slot_sums[start + bits..start + 2 * bits])
                })
            }
            MeasurementType::Histogram { length } => slot_sums[..*length].iter().map(|&s| s as u128).sum::<u128>() == count as u128,
            MeasurementType::MultihotCountVec { length, max_weight } => {
                let wb = Self::weight_bits(*max_weight) as usize;
                let weight: u128 = slot_sums[..*length].iter().map(|&s| s as u128).sum();
                weight + count as u128 * Self::weight_offset(*max_weight) as u128 == value(&slot_sums[*length..*length + wb])
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
pub fn is_valid_plain(t: &MeasurementType, f: &Field, x: &[u64]) -> bool {
    if x.len() != t.input_len() {
        return false;
    }
    if x.iter().any(|&v| v != 0 && v != 1) {
        return false;
    }
    t.linear_constraints(f).iter().all(|c| {
        let mut acc = c.constant;
        for &(i, coef) in &c.coeffs {
            acc = f.add(acc, f.mul(coef, x[i]));
        }
        acc == 0
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(t.linear_constraints(&f()).len(), 4);
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
