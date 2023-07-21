use std::process::Command;

/// Gets the path of the `hwtrust` binary that works with `atest` and `Cargo`.
fn hwtrust_bin() -> &'static str {
    option_env!("CARGO_BIN_EXE_hwtrust").unwrap_or("./hwtrust")
}

#[test]
fn exit_code_for_good_chain() {
    let output = Command::new(hwtrust_bin())
        .args(["verify-dice-chain", "testdata/dice/valid_ed25519.chain"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn exit_code_for_bad_chain() {
    let output = Command::new(hwtrust_bin())
        .args(["verify-dice-chain", "testdata/dice/bad_p256.chain"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn factory_csr_empty_input_fails() {
    let output = Command::new(hwtrust_bin())
        .args(["verify-dice-chain", "testdata/dice/bad_p256.chain"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn factory_csr_multiple_valid_csrs_succeeds() {
    // Input file intentionally has some blank lines, ensuring we skip over them expectedly
    let output = Command::new(hwtrust_bin())
        .args(["factory-csr", "testdata/factory_csr/all_versions_valid.json"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn factory_csr_one_invalid_csr_of_multiple_fails() {
    let output = Command::new(hwtrust_bin())
        .args(["factory-csr", "testdata/factory_csr/all_versions_invalid.json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}
