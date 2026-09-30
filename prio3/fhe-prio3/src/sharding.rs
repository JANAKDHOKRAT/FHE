//! Horizontal scaling by sharding.
//!
//! A shard is a complete, independent task: its own task id, its own key
//! ceremony, its own aggregator processes and collector. Nothing
//! cryptographic is shared between shards, so the security argument of one
//! task applies to each shard unchanged; the only cross-shard object is the
//! sum of decrypted shard results, which each shard releases only after its
//! own `min_batch_size` valid reports. Clients are assigned to a shard
//! *before* encrypting, because they must encrypt under that shard's key.

use crate::config::TaskConfig;
use crate::error::{Error, Result};
use crate::types::{AggregateResult, BatchResult, RegressionResult};
use sha2::{Digest, Sha256};

/// Derives `shards` independent task configurations from a base one. Shard
/// `i` gets task id `SHA-256("fhe-prio3/1 shard" || base_id || i)`; every
/// other parameter is identical.
pub fn shard_configs(base: &TaskConfig, shards: usize) -> Result<Vec<TaskConfig>> {
    if shards == 0 {
        return Err(Error::Config("at least one shard".into()));
    }
    base.validate()?;
    Ok((0..shards as u32)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(b"fhe-prio3/1 shard");
            h.update(base.task_id);
            h.update(i.to_le_bytes());
            let mut c = base.clone();
            c.task_id = h.finalize().into();
            c
        })
        .collect())
}

/// Adds shard results. All shards must have the same measurement type;
/// counts add, aggregates add element-wise, and regression moments add
/// before the normal equations are solved again.
pub fn combine_results(results: &[BatchResult]) -> Result<BatchResult> {
    let first = results.first().ok_or_else(|| Error::Protocol("no shard results".into()))?;
    let mut aggregate = first.aggregate.clone();
    let mut report_count = first.report_count;
    let mut valid_count = first.valid_count;
    let mut moments: Option<(Vec<u128>, Vec<Vec<u128>>)> = first.regression.as_ref().map(|r| (r.first.clone(), r.second.clone()));
    for r in &results[1..] {
        if r.collector != first.collector || r.elements != first.elements {
            return Err(Error::Protocol("shard results were released to different collectors or elements".into()));
        }
        aggregate = add_aggregates(&aggregate, &r.aggregate)?;
        report_count = report_count
            .checked_add(r.report_count)
            .ok_or_else(|| Error::Protocol("count overflow".into()))?;
        valid_count = valid_count.checked_add(r.valid_count).ok_or_else(|| Error::Protocol("count overflow".into()))?;
        match (&mut moments, &r.regression) {
            (Some((f, s)), Some(reg)) => {
                if f.len() != reg.first.len() {
                    return Err(Error::Protocol("shard regressions have different dimensions".into()));
                }
                for (a, b) in f.iter_mut().zip(&reg.first) {
                    *a += b;
                }
                for (row, brow) in s.iter_mut().zip(&reg.second) {
                    for (a, b) in row.iter_mut().zip(brow) {
                        *a += b;
                    }
                }
            }
            (None, None) => {}
            _ => return Err(Error::Protocol("some shards carry regression moments and some do not".into())),
        }
    }
    let regression = moments.map(|(f, s)| RegressionResult::from_moments(valid_count, f, s));
    Ok(BatchResult {
        collector: first.collector,
        elements: first.elements.clone(),
        aggregate,
        report_count,
        valid_count,
        regression,
    })
}

fn add_aggregates(a: &AggregateResult, b: &AggregateResult) -> Result<AggregateResult> {
    Ok(match (a, b) {
        (AggregateResult::Count(x), AggregateResult::Count(y)) => AggregateResult::Count(x + y),
        (AggregateResult::Sum(x), AggregateResult::Sum(y)) => AggregateResult::Sum(x + y),
        (AggregateResult::SumVec(x), AggregateResult::SumVec(y)) if x.len() == y.len() => {
            AggregateResult::SumVec(x.iter().zip(y).map(|(p, q)| p + q).collect())
        }
        (AggregateResult::Histogram(x), AggregateResult::Histogram(y)) if x.len() == y.len() => {
            AggregateResult::Histogram(x.iter().zip(y).map(|(p, q)| p + q).collect())
        }
        (AggregateResult::MultihotCountVec(x), AggregateResult::MultihotCountVec(y)) if x.len() == y.len() => {
            AggregateResult::MultihotCountVec(x.iter().zip(y).map(|(p, q)| p + q).collect())
        }
        _ => return Err(Error::Protocol("shard aggregates have different types or lengths".into())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Measurement, MeasurementType, regression_plain};

    #[test]
    fn shard_ids_are_distinct_and_deterministic() {
        let base = TaskConfig::new([3u8; 32], MeasurementType::Count, 2);
        let a = shard_configs(&base, 4).unwrap();
        let b = shard_configs(&base, 4).unwrap();
        assert_eq!(a.iter().map(|c| c.task_id).collect::<Vec<_>>(), b.iter().map(|c| c.task_id).collect::<Vec<_>>());
        let mut ids: Vec<_> = a.iter().map(|c| c.task_id).collect();
        ids.dedup();
        assert_eq!(ids.len(), 4);
        assert!(ids.iter().all(|id| *id != base.task_id));
        assert!(shard_configs(&base, 0).is_err());
    }

    #[test]
    fn combine_adds_everything_and_refits() {
        let t = MeasurementType::SumVec {
            length: 3,
            max_measurement: 15,
        };
        let rows_a: Vec<Vec<u64>> = vec![vec![1, 2, 8], vec![2, 1, 7], vec![3, 5, 15]];
        let rows_b: Vec<Vec<u64>> = vec![vec![4, 1, 11], vec![0, 3, 8], vec![5, 5, 15]];
        let ms = |rows: &Vec<Vec<u64>>| rows.iter().map(|r| Measurement::SumVec(r.clone())).collect::<Vec<_>>();
        let ra = BatchResult {
            collector: 0,
            elements: vec![0, 1, 2],
            aggregate: t.aggregate_plain(&ms(&rows_a)).unwrap(),
            report_count: 3,
            valid_count: 3,
            regression: Some(regression_plain(&rows_a)),
        };
        let rb = BatchResult {
            collector: 0,
            elements: vec![0, 1, 2],
            aggregate: t.aggregate_plain(&ms(&rows_b)).unwrap(),
            report_count: 4,
            valid_count: 3,
            regression: Some(regression_plain(&rows_b)),
        };
        let c = combine_results(&[ra, rb]).unwrap();
        let all: Vec<Vec<u64>> = rows_a.iter().chain(&rows_b).cloned().collect();
        assert_eq!(c.aggregate, t.aggregate_plain(&ms(&all)).unwrap());
        assert_eq!((c.report_count, c.valid_count), (7, 6));
        let plain = regression_plain(&all);
        let reg = c.regression.clone().unwrap();
        assert_eq!((reg.first, reg.second), (plain.first, plain.second));
        for (x, y) in reg.beta.iter().zip(&plain.beta) {
            assert!((x - y).abs() < 1e-9);
        }
        // mismatched shapes are refused
        let bad = BatchResult {
            collector: 0,
            elements: vec![0],
            aggregate: AggregateResult::Count(1),
            report_count: 1,
            valid_count: 1,
            regression: None,
        };
        assert!(combine_results(&[c.clone(), bad]).is_err());
    }
}
