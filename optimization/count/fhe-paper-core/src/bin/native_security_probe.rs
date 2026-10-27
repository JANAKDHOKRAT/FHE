//! Inspect actual public Q/PK/QP bases. Not an independent lattice estimate.
use fhe_paper_core::*;
use fhe_prio3::{MeasurementType, config::SilentCheck};
use openfhe_tbgv_rs::KeyBasis;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        ("threshold-count", MeasurementType::Count, None),
        ("native-count-d3", MeasurementType::Count, Some(3)),
        ("native-count-d5", MeasurementType::Count, Some(5)),
        ("native-sum-exact", MeasurementType::Sum { max_measurement: 100 }, Some(3)),
        ("native-depth28-d3", MeasurementType::Histogram { length: 8 }, Some(3)),
    ];
    let mut rows = Vec::new();
    for (name, ty, digits) in cases {
        let task = match digits {
            None => PaperTask::new([0xAE; 32], ty, SilentCheck::Exact)?,
            Some(d) => PaperTask::new_native(
                [0xAE; 32],
                ty,
                SilentCheck::Exact,
                NativeParameters {
                    key_switch_digits: d,
                    ..Default::default()
                },
            )?,
        };
        let ctx = task.make_context()?;
        let q = ctx.moduli()?;
        let pk = ctx.key_basis_moduli(KeyBasis::PublicKey)?;
        let qp = ctx.key_basis_moduli(KeyBasis::KeySwitch)?;
        let log = |v: &[u64]| v.iter().map(|&q| (q as f64).log2()).sum::<f64>();
        // Strings preserve 60-bit primes in JSON consumers using doubles.
        let primes = |v: &[u64]| format!("[{}]", v.iter().map(|q| format!("\"{q}\"")).collect::<Vec<_>>().join(","));
        let qs = primes(&q);
        let pks = primes(&pk);
        let qps = primes(&qp);
        rows.push(format!("{{\"profile\":\"{name}\",\"nominal_security_bits\":128,\"ring_dim\":{},\"circuit_depth\":{},\"actual_digits\":{},\"log2_q\":{:.6},\"log2_qp\":{:.6},\"q_moduli_decimal\":{qs},\"public_key_moduli_decimal\":{pks},\"key_switch_moduli_decimal\":{qps}}}",
            ctx.ring_dim(),task.mult_depth(),ctx.key_num_parts()?,log(&q),log(&qp)));
    }
    println!("[\n{}\n]", rows.join(",\n"));
    Ok(())
}
