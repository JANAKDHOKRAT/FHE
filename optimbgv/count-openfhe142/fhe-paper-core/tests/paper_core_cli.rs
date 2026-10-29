use std::process::Command;

#[test]
fn exact_command_selects_exact_configuration_before_setup() {
    let output = Command::new(env!("CARGO_BIN_EXE_paper_core_eval"))
        .args(["exact", "--type", "count", "--groups", "64"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("the exact check's packing is fixed"), "{stderr}");
}

#[test]
fn obsolete_core_exact_spelling_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_paper_core_eval"))
        .args(["core-exact", "--type", "count"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr).unwrap().contains("usage:"));
}

#[test]
fn native_parameters_cannot_be_silently_applied_to_threshold_mode() {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_paper_core_eval"))
        .args(["exact", "--type", "count", "--plain-mod", "65537"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
}

#[test]
fn native_only_options_are_rejected_even_when_equal_to_their_defaults() {
    for (flag, value) in [
        ("--plain-mod", "786433"),
        ("--attempts", "1000000"),
        ("--soundness-bits", "128"),
        ("--digits", "5"),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_paper_core_eval"))
            .args(["exact", "--type", "count", "--groups", "64", flag, value])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{flag} must not be silently ignored");
    }
}
