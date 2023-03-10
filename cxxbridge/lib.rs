//! This library provides bindings for C++ code to comfortably and reasonably safely interface with
//! the libhwtrust Rust library.

use coset::CborSerializable;
use hwtrust::dice::ChainForm;
use hwtrust::session::{ConfigFormat, KeyOpsType, Options, Session};

#[cxx::bridge(namespace = "hwtrust::rust")]
mod ffi {
    /// The kind of DICE chain to verify which implies the set of validation rules to apply.
    enum DiceChainKind {
        /// The DICE chain from an AuthenticatedMessage.
        AuthenticatedMessage,
        /// The DICE chain from ProtectedData.
        ProtectedData,
    }

    /// The result type used by [`verify_dice_chain()`]. The standard [`Result`] is currently only
    /// converted to exceptions by `cxxbridge` but we can't use exceptions so need to do something
    /// custom.
    struct VerifyDiceChainResult {
        /// If non-empty, the description of the verification error that occurred.
        error: String,
        /// If [`error`] is empty, a handle to the verified chain.
        chain: Box<DiceChain>,
        /// If [`error`] is empty, the length of the chain.
        len: usize,
    }

    extern "Rust" {
        type DiceChain;

        #[cxx_name = VerifyDiceChain]
        fn verify_dice_chain(chain: &[u8], kind: DiceChainKind) -> VerifyDiceChainResult;

        #[cxx_name = GetDiceChainPublicKey]
        fn get_dice_chain_public_key(chain: &DiceChain, n: usize) -> Vec<u8>;
    }
}

/// A DICE chain as exposed over the cxx bridge.
pub struct DiceChain(Option<ChainForm>);

fn verify_dice_chain(chain: &[u8], kind: ffi::DiceChainKind) -> ffi::VerifyDiceChainResult {
    let session = Session {
        options: Options {
            first_dice_chain_cert_config_format: ConfigFormat::Permissive,
            // DICE chains in ProtectedData objects follow the specification from versions 1 and 2
            // of the HAL which allowed for key_ops to be an integer as opposed to the array that
            // is specified by COSE.
            dice_chain_key_ops_type: match kind {
                ffi::DiceChainKind::AuthenticatedMessage => KeyOpsType::default(),
                ffi::DiceChainKind::ProtectedData => KeyOpsType::IntOrArray,
                _ => {
                    return ffi::VerifyDiceChainResult {
                        error: "invalid chain kind".to_string(),
                        chain: Box::new(DiceChain(None)),
                        len: 0,
                    }
                }
            },
        },
    };
    match ChainForm::from_cbor(&session, chain) {
        Ok(chain) => {
            let len = match chain {
                ChainForm::Proper(ref chain) => chain.payloads().len(),
                ChainForm::Degenerate(_) => 1,
            };
            let chain = Box::new(DiceChain(Some(chain)));
            ffi::VerifyDiceChainResult { error: "".to_string(), chain, len }
        }
        Err(e) => {
            let error = format!("{:#}", e);
            ffi::VerifyDiceChainResult { error, chain: Box::new(DiceChain(None)), len: 0 }
        }
    }
}

fn get_dice_chain_public_key(chain: &DiceChain, n: usize) -> Vec<u8> {
    if let DiceChain(Some(chain)) = chain {
        let key = match chain {
            ChainForm::Proper(chain) => chain.payloads()[n].subject_public_key(),
            ChainForm::Degenerate(chain) => chain.public_key(),
        };
        if let Ok(cose_key) = key.to_cose_key() {
            if let Ok(bytes) = cose_key.to_vec() {
                return bytes;
            }
        }
    }
    Vec::new()
}
