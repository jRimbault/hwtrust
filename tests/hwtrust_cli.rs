use std::process::Command;

#[test]
fn exit_code_for_good_chain() {
    let output = Command::new("./hwtrust")
        .args(["verify-dice-chain", "testdata/dice/valid_ed25519.chain"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn exit_code_for_bad_chain() {
    let output = Command::new("./hwtrust")
        .args(["verify-dice-chain", "testdata/dice/bad_p256.chain"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}
