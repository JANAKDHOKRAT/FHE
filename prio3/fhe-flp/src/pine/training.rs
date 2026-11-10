//! Local softmax training and exact, bounded PINE update encoding.
//!
//! No secret key or evaluator state is needed by local training. The model
//! update is the equal-weight mean of ACCEPTED client deltas. PINE bounds the
//! quantized delta, not the original unrounded gradient or its usefulness.
use super::collector_session::ReleasedSum;
use super::descriptor::TaskDescriptor;
use super::{PineParams, circuit::Shape};
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

fn invalid(message: &str) -> Error {
    Error::Protocol(format!("training: {message}"))
}

#[derive(Clone, Debug, PartialEq)]
pub struct Model {
    pub features: usize,
    pub classes: usize,
    /// Class-major weights, each class has `features` coefficients and a bias.
    pub weights: Vec<f64>,
}

#[derive(Clone, Debug)]
pub struct Example {
    pub features: Vec<f64>,
    pub label: usize,
}

#[derive(Clone, Debug)]
pub struct TrainingConfig {
    pub local_epochs: usize,
    pub local_learning_rate: f64,
    pub server_learning_rate: f64,
}
impl TrainingConfig {
    pub fn validate(&self) -> Result<()> {
        if self.local_epochs == 0
            || !self.local_learning_rate.is_finite()
            || self.local_learning_rate <= 0.0
            || !self.server_learning_rate.is_finite()
            || self.server_learning_rate <= 0.0
        {
            return Err(invalid("positive finite learning rates and at least one local epoch required"));
        }
        Ok(())
    }
    /// Bind optimizer/averaging semantics to the signed task's application ID.
    pub fn application(&self, application: &[u8; 32]) -> Result<[u8; 32]> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(b"PINE-BGV-softmax-equal-client-delta-v1");
        h.update(application);
        h.update((self.local_epochs as u64).to_le_bytes());
        h.update(self.local_learning_rate.to_bits().to_le_bytes());
        h.update(self.server_learning_rate.to_bits().to_le_bytes());
        Ok(h.finalize().into())
    }
}

impl Model {
    pub fn zeros(features: usize, classes: usize) -> Result<Self> {
        let n = features
            .checked_add(1)
            .and_then(|n| n.checked_mul(classes))
            .ok_or_else(|| invalid("model size overflow"))?;
        if features == 0 || classes < 2 {
            return Err(invalid("nonempty features and at least two classes required"));
        }
        Ok(Self {
            features,
            classes,
            weights: vec![0.0; n],
        })
    }
    pub fn validate(&self) -> Result<()> {
        if self.features == 0
            || self.classes < 2
            || self.features.checked_add(1).and_then(|n| n.checked_mul(self.classes)) != Some(self.weights.len())
            || self.weights.iter().any(|w| !w.is_finite())
        {
            return Err(invalid("invalid model"));
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(b"PINE-BGV-softmax-model-v1");
        h.update((self.features as u64).to_le_bytes());
        h.update((self.classes as u64).to_le_bytes());
        for w in &self.weights {
            h.update(w.to_bits().to_le_bytes());
        }
        Ok(h.finalize().into())
    }
    fn validate_data(&self, data: &[Example]) -> Result<()> {
        self.validate()?;
        if data.is_empty()
            || data
                .iter()
                .any(|r| r.features.len() != self.features || r.label >= self.classes || r.features.iter().any(|v| !v.is_finite()))
        {
            return Err(invalid("empty or malformed local data"));
        }
        Ok(())
    }
    fn probabilities(&self, row: &Example) -> Result<Vec<f64>> {
        let mut scores: Vec<f64> = self
            .weights
            .chunks_exact(self.features + 1)
            .map(|w| w[self.features] + w[..self.features].iter().zip(&row.features).map(|(a, b)| a * b).sum::<f64>())
            .collect();
        if scores.iter().any(|v| !v.is_finite()) {
            return Err(invalid("nonfinite model score"));
        }
        let max = scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        for v in &mut scores {
            *v = (*v - max).exp();
        }
        let sum: f64 = scores.iter().sum();
        for v in &mut scores {
            *v /= sum;
        }
        Ok(scores)
    }
    pub fn accuracy(&self, data: &[Example]) -> Result<f64> {
        self.validate_data(data)?;
        let mut correct = 0usize;
        for row in data {
            let p = self.probabilities(row)?;
            let predicted = p.iter().enumerate().max_by(|a, b| a.1.total_cmp(b.1)).expect("nonempty classes").0;
            correct += usize::from(predicted == row.label);
        }
        Ok(correct as f64 / data.len() as f64)
    }
    /// Full-batch local gradient descent on multiclass cross entropy.
    pub fn local_delta(&self, data: &[Example], config: &TrainingConfig) -> Result<Vec<f64>> {
        config.validate()?;
        self.validate_data(data)?;
        let mut local = self.clone();
        for _ in 0..config.local_epochs {
            let mut grad = vec![0.0; self.weights.len()];
            for row in data {
                let probabilities = local.probabilities(row)?;
                for (class, (&prob, block)) in probabilities.iter().zip(grad.chunks_exact_mut(self.features + 1)).enumerate() {
                    let error = (prob - f64::from(class == row.label)) / data.len() as f64;
                    for (g, x) in block[..self.features].iter_mut().zip(&row.features) {
                        *g += error * x;
                    }
                    block[self.features] += error;
                }
            }
            for (w, g) in local.weights.iter_mut().zip(grad) {
                *w -= config.local_learning_rate * g;
            }
            local.validate()?;
        }
        let delta: Vec<_> = local.weights.iter().zip(&self.weights).map(|(a, b)| a - b).collect();
        if delta.iter().any(|x| !x.is_finite()) {
            return Err(invalid("nonfinite update"));
        }
        Ok(delta)
    }
}

#[derive(Debug)]
pub struct PreparedUpdate {
    pub integers: Vec<i64>,
    /// Exactly representable dyadic values that PineClient::shard encodes.
    pub measurement: Vec<f64>,
    pub squared_norm: u128,
}
fn squared_norm(q: &[i64]) -> Result<u128> {
    q.iter().try_fold(0u128, |s, &v| {
        s.checked_add((v as i128 * v as i128) as u128).ok_or_else(|| invalid("norm overflow"))
    })
}

/// Clip before rounding; then enforce the integer norm AFTER rounding.
/// If q is out of bound, set q'_j = trunc(q_j B / ceil(sqrt(sum q²))).
/// Since the denominator is >= ||q|| and truncation decreases magnitude,
/// sum(q'_j²) <= B². All projection arithmetic is exact integer arithmetic.
pub fn prepare_update(shape: &Shape, delta: &[f64]) -> Result<PreparedUpdate> {
    if delta.len() != shape.dimension() || delta.iter().any(|v| !v.is_finite()) {
        return Err(invalid("invalid update dimension or value"));
    }
    let norm = delta.iter().fold(0.0f64, |n, x| n.hypot(*x));
    if !norm.is_finite() {
        return Err(invalid("update norm overflow"));
    }
    let scale = 2f64.powi(shape.num_frac_bits() as i32);
    let radius = shape.l2_norm_bound() as f64 / scale;
    let factor = if norm > radius { radius / norm } else { 1.0 };
    let clipped: Vec<_> = delta.iter().map(|x| x * factor).collect();
    let mut q = shape.encode_gradient(&clipped)?;
    let bound = u128::from(shape.l2_norm_bound());
    let sq = squared_norm(&q)?;
    if sq > bound * bound {
        let root = sq.isqrt();
        let denominator = root + u128::from(root * root != sq);
        for x in &mut q {
            *x = (*x as i128 * bound as i128 / denominator as i128) as i64;
        }
    }
    let sq = squared_norm(&q)?;
    if sq > bound * bound {
        return Err(invalid("integer norm exceeded after projection"));
    }
    let measurement: Vec<_> = q.iter().map(|v| *v as f64 / scale).collect();
    // The production encoder is the final authority; check exact round trip too.
    shape.encode_gradient_and_norm(&measurement)?;
    if shape.encode_gradient(&measurement)? != q {
        return Err(invalid("encoding changed quantized update"));
    }
    Ok(PreparedUpdate {
        integers: q,
        measurement,
        squared_norm: sq,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub struct TrainingState {
    pub model: Model,
    pub next_round: u64,
}
impl TrainingState {
    pub fn descriptor(
        &self,
        config: &TrainingConfig,
        application: &[u8; 32],
        params: PineParams,
        min_accepted: u32,
        identities: Vec<[u8; 32]>,
    ) -> Result<TaskDescriptor> {
        if params.dimension != self.model.weights.len() {
            return Err(invalid("task/model dimension mismatch"));
        }
        let d = TaskDescriptor {
            application: config.application(application)?,
            model_hash: self.model.hash()?,
            round: self.next_round,
            params,
            min_accepted,
            identities,
        };
        d.validate()?;
        Ok(d)
    }
    /// Return a new state; the caller must durably commit it before serving
    /// the next round. Reject stale model/round/config, malformed sums, and
    /// counts outside the signed cohort. This is NOT aggregate authentication.
    pub fn apply(&self, config: &TrainingConfig, application: &[u8; 32], expected: &TaskDescriptor, release: &ReleasedSum) -> Result<Self> {
        config.validate()?;
        expected.validate()?;
        Shape::new(expected.params.dimension, expected.params.l2_norm_bound, expected.params.num_frac_bits)?;
        if expected.application != config.application(application)?
            || expected != &release.task
            || expected.model_hash != self.model.hash()?
            || expected.round != self.next_round
            || expected.params.dimension != self.model.weights.len()
            || release.accepted < u64::from(expected.min_accepted)
            || release.accepted > expected.identities.len() as u64
            || release.sum.len() != self.model.weights.len()
            || release.sum.iter().any(|v| !v.is_finite())
        {
            return Err(invalid("release does not match current training round"));
        }
        let scale = 2f64.powi(expected.params.num_frac_bits as i32);
        let max_integer = release
            .accepted
            .checked_mul(expected.params.l2_norm_bound)
            .ok_or_else(|| invalid("aggregate bound overflow"))?;
        if max_integer >= crate::PLAIN_MOD / 2 {
            return Err(invalid("aggregate signed decoding may wrap"));
        }
        // Reject malformed, fractional-grid or coordinate-out-of-bound releases.
        if release.sum.iter().any(|x| {
            let q = x * scale;
            !q.is_finite() || q.fract() != 0.0 || q.abs() > max_integer as f64
        }) {
            return Err(invalid("release outside the quantized aggregate domain"));
        }
        // Triangle inequality: ||sum_i q_i|| <= accepted * B. This rejects
        // impossible outputs but does not prove which clients were summed.
        let integers: Vec<i64> = release.sum.iter().map(|x| (x * scale) as i64).collect();
        if squared_norm(&integers)? > u128::from(max_integer) * u128::from(max_integer) {
            return Err(invalid("aggregate exceeds the sum norm bound"));
        }
        let mut model = self.model.clone();
        for (w, s) in model.weights.iter_mut().zip(&release.sum) {
            *w += config.server_learning_rate * (*s / release.accepted as f64);
        }
        model.validate()?;
        Ok(Self {
            model,
            next_round: self.next_round.checked_add(1).ok_or_else(|| invalid("round overflow"))?,
        })
    }
    /// Immutable checkpoint, create-new + file and directory fsync. A crash
    /// can leave an incomplete file; load rejects it, and never rolls back.
    /// Operators must protect against filesystem rollback and concurrent writers.
    pub fn save_new(&self, path: &Path) -> Result<()> {
        self.model.validate()?;
        let mut bytes = b"PINEFL01".to_vec();
        for n in [self.next_round, self.model.features as u64, self.model.classes as u64] {
            bytes.extend(n.to_le_bytes());
        }
        for w in &self.model.weights {
            bytes.extend(w.to_bits().to_le_bytes());
        }
        bytes.extend(Sha256::digest(&bytes));
        let io = |e| invalid(&format!("checkpoint: {e}"));
        let mut f = std::fs::OpenOptions::new().create_new(true).write(true).open(path).map_err(io)?;
        f.write_all(&bytes).and_then(|()| f.sync_all()).map_err(io)?;
        std::fs::File::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))
            .and_then(|f| f.sync_all())
            .map_err(io)?;
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Self> {
        let b = std::fs::read(path).map_err(|e| invalid(&format!("checkpoint: {e}")))?;
        if b.len() < 64 || &b[..8] != b"PINEFL01" || Sha256::digest(&b[..b.len() - 32])[..] != b[b.len() - 32..] {
            return Err(invalid("invalid checkpoint checksum or header"));
        }
        let read = |i| u64::from_le_bytes(b[i..i + 8].try_into().expect("length checked"));
        let features = usize::try_from(read(16)).map_err(|_| invalid("features overflow"))?;
        let classes = usize::try_from(read(24)).map_err(|_| invalid("classes overflow"))?;
        let n = features
            .checked_add(1)
            .and_then(|x| x.checked_mul(classes))
            .and_then(|x| x.checked_mul(8))
            .and_then(|x| x.checked_add(64));
        if n != Some(b.len()) {
            return Err(invalid("checkpoint size mismatch"));
        }
        let model = Model {
            features,
            classes,
            weights: b[32..b.len() - 32]
                .chunks_exact(8)
                .map(|x| f64::from_bits(u64::from_le_bytes(x.try_into().expect("chunk"))))
                .collect(),
        };
        model.validate()?;
        Ok(Self { model, next_round: read(8) })
    }
}
