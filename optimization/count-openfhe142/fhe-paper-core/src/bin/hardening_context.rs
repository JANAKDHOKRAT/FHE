use fhe_paper_core::*;
use fhe_prio3::{MeasurementType, config::SilentCheck};
fn main() {
    let t = PaperTask::new_native(
        [77; 32],
        MeasurementType::Count,
        SilentCheck::Exact,
        NativeParameters {
            plain_mod: 786433,
            key_switch_digits: 4,
            count_projection: true,
            groups: Some(4),
            ..Default::default()
        },
    )
    .unwrap()
    .with_batch_limit(32)
    .unwrap();
    let c = t.make_context().unwrap();
    let q = c.moduli().unwrap();
    let retained = q.len() - t.mult_depth() as usize;
    println!(
        "{{\"ring\":{},\"p\":{},\"depth\":{},\"full_towers\":{},\"final_towers\":{},\"final_moduli\":[{}]}}",
        c.ring_dim(),
        c.plain_mod(),
        t.mult_depth(),
        q.len(),
        retained,
        q[..retained].iter().map(|q| format!("\"{q}\"")).collect::<Vec<_>>().join(",")
    );
}
