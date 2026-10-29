//! Parameter selection only. A selected profile is NOT a qualified circuit.
use fhe_paper_core::*;
use fhe_prio3::{MeasurementType, config::SilentCheck};
fn main() {
    println!("prime,task,mode,digits,status,ring,depth,groups,repetitions,detail");
    for p in [65537, 786433] {
        for (name, ty) in [
            ("count", MeasurementType::Count),
            ("sum100", MeasurementType::Sum { max_measurement: 100 }),
            ("hist8", MeasurementType::Histogram { length: 8 }),
            (
                "sv10",
                MeasurementType::SumVec {
                    length: 10,
                    max_measurement: 1,
                },
            ),
            (
                "sv25",
                MeasurementType::SumVec {
                    length: 25,
                    max_measurement: 1,
                },
            ),
            (
                "sv50",
                MeasurementType::SumVec {
                    length: 50,
                    max_measurement: 1,
                },
            ),
            (
                "sv100",
                MeasurementType::SumVec {
                    length: 100,
                    max_measurement: 1,
                },
            ),
        ] {
            for (mode, check) in [("exact", SilentCheck::Exact), ("randomised", SilentCheck::Randomised)] {
                for digits in [1, 2, 3, 4, 5, 6, 7] {
                    match PaperTask::new_native(
                        [0xBE; 32],
                        ty.clone(),
                        check,
                        NativeParameters {
                            plain_mod: p,
                            key_switch_digits: digits,
                            ..Default::default()
                        },
                    ) {
                        Ok(t) => println!(
                            "{p},{name},{mode},{digits},selected,{},{},{},{},",
                            t.row_slots() * 2,
                            t.mult_depth(),
                            t.groups(),
                            t.config().repetitions
                        ),
                        Err(e) => println!("{p},{name},{mode},{digits},rejected,,,,,{}", e.to_string().replace([',', '\n'], ";")),
                    }
                }
            }
        }
    }
}
