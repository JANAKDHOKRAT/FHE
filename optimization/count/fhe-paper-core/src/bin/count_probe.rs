use fhe_paper_core::*;
use fhe_prio3::{MeasurementType, config::SilentCheck};
fn main() {
    println!("prime,digits,projection,status,ring,depth,detail");
    for p in [65537, 786433] {
        for digits in 1..=8 {
            for projection in [false, true] {
                match PaperTask::new_native(
                    [17; 32],
                    MeasurementType::Count,
                    SilentCheck::Exact,
                    NativeParameters {
                        plain_mod: p,
                        key_switch_digits: digits,
                        count_projection: projection,
                        ..Default::default()
                    },
                ) {
                    Ok(t) => println!("{p},{digits},{projection},selected,{},{},", t.row_slots() * 2, t.mult_depth()),
                    Err(e) => println!("{p},{digits},{projection},rejected,,,{}", e.to_string().replace([',', '\n'], ";")),
                }
            }
        }
    }
}
