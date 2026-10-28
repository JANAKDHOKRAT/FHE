use fhe_paper_core::*;
use fhe_prio3::{MeasurementType, config::SilentCheck};
use openfhe_tbgv_rs::KeyBasis;
fn main() {
    for digits in 2..=8 {
        match PaperTask::new_native(
            [29; 32],
            MeasurementType::Count,
            SilentCheck::Exact,
            NativeParameters {
                plain_mod: 786433,
                key_switch_digits: digits,
                count_projection: true,
                groups: Some(4),
                ..Default::default()
            },
        ) {
            Ok(t) => {
                let c = t.make_context().unwrap();
                let qp = c.key_basis_moduli(KeyBasis::KeySwitch).unwrap();
                println!(
                    "{{\"name\":\"projected-786433-d{digits}\",\"n\":{},\"p\":786433,\"sigma\":3.19,\"qp_moduli\":[{}]}}",
                    c.ring_dim(),
                    qp.iter().map(|q| format!("\"{q}\"")).collect::<Vec<_>>().join(",")
                );
            }
            Err(e) => eprintln!("REJECTED digits={digits}: {e}"),
        }
    }
}
