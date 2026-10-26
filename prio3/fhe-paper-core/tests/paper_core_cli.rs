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
