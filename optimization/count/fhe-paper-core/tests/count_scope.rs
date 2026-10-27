use fhe_paper_core::*;
use fhe_prio3::{MeasurementType, config::SilentCheck};
use std::process::Command;
#[test]
fn projection_is_opt_in_and_count_exact_only() {
    assert!(!NativeParameters::default().count_projection);
    for (ty, check) in [
        (MeasurementType::Count, SilentCheck::Randomised),
        (MeasurementType::Sum { max_measurement: 1 }, SilentCheck::Exact),
        (
            MeasurementType::SumVec {
                length: 10,
                max_measurement: 1,
            },
            SilentCheck::Exact,
        ),
        (MeasurementType::Histogram { length: 8 }, SilentCheck::Exact),
    ] {
        assert!(
            PaperTask::new_native(
                [1; 32],
                ty,
                check,
                NativeParameters {
                    count_projection: true,
                    ..Default::default()
                }
            )
            .unwrap_err()
            .to_string()
            .contains("projection requires native exact Count")
        );
    }
    let baseline = PaperTask::new([1; 32], MeasurementType::Count, SilentCheck::Exact).unwrap();
    assert_eq!(baseline.mult_depth(), 24);
    assert_eq!(baseline.groups(), 32768);
}
#[test]
fn projection_cli_cannot_silently_enter_threshold_mode() {
    for value in ["true", "false"] {
        let o = Command::new(env!("CARGO_BIN_EXE_paper_core_eval"))
            .args(["exact", "--type", "count", "--count-projection", value])
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2));
    }
    let o = Command::new(env!("CARGO_BIN_EXE_paper_core_eval"))
        .args(["randomised", "--type", "count", "--key-mode", "single", "--count-projection", "true"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("projection requires native exact Count"));
}
