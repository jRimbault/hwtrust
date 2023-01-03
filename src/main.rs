//! A tool for handling data related to the hardware root-of-trust.

use anyhow::Result;
use clap::{Parser, Subcommand};
use hwtrust::dice;
use std::fs;

#[derive(Parser)]
/// A tool for handling data related to the hardware root-of-trust
#[clap(name = "hwtrust")]
struct Args {
    #[clap(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    VerifyDiceChain(VerifyDiceChainArgs),
}

#[derive(Parser)]
/// Verify that a DICE chain is well-formed
///
/// DICE chains are expected to follow the specification of the RKP HAL [1] which is based on the
/// Open Profile for DICE [2].
///
/// [1] -- https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl
/// [2] -- https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md
struct VerifyDiceChainArgs {
    /// Dump the DICE chain on the standard output
    #[clap(long)]
    dump: bool,

    /// Path to a file containing a DICE chain
    chain: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let Action::VerifyDiceChain(sub_args) = args.action;
    let chain = dice::Chain::from_cbor(&fs::read(sub_args.chain)?)?;
    println!("Success!");
    if sub_args.dump {
        print!("{}", chain);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_command() {
        Args::command().debug_assert();
    }
}
