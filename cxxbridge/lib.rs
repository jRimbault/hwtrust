//! This library provides bindings for C++ code to comfortably and reasonably safely interface with
//! the libhwtrust Rust library.

use coset::CborSerializable;
use hwtrust::dice::ChainForm;
use hwtrust::rkp::Csr as InnerCsr;
use hwtrust::session::{Options, RkpInstance, Session};
use std::str::FromStr;

#[allow(clippy::needless_maybe_sized)]
#[allow(unsafe_op_in_unsafe_fn)]
#[cxx::bridge(namespace = "hwtrust::rust")]
mod ffi {
    /// The set of validation rules to apply.
    enum DiceChainKind {
        /// The DICE chain specified by VSR 13.
        Vsr13,
        /// The DICE chain specified by VSR 14.
        Vsr14,
        /// The DICE chain specified by VSR 15.
        Vsr15,
        /// The DICE chain specified by VSR 16.
        Vsr16,
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

    /// The result type used by [`validate_csr()`]. The standard [`Result`] is currently only
    /// converted to exceptions by `cxxbridge` but we can't use exceptions so need to do something
    /// custom.
    struct ValidateCsrResult {
        /// If non-empty, the description of the verification error that occurred.
        error: String,
        /// If [`error`] is empty, a handle to the validated Csr.
        csr: Box<Csr>,
    }

    extern "Rust" {
        type DiceChain;

        #[cxx_name = VerifyDiceChain]
        fn verify_dice_chain(
            chain: &[u8],
            kind: DiceChainKind,
            allow_any_mode: bool,
            instance: &str,
        ) -> VerifyDiceChainResult;

        #[cxx_name = GetDiceChainPublicKey]
        fn get_dice_chain_public_key(chain: &DiceChain, n: usize) -> Vec<u8>;

        #[cxx_name = IsDiceChainProper]
        fn is_dice_chain_proper(chain: &DiceChain) -> bool;

        type Csr;

        #[cxx_name = validateCsr]
        fn validate_csr(
            csr: &[u8],
            kind: DiceChainKind,
            allow_any_mode: bool,
            instance: &str,
        ) -> ValidateCsrResult;

        #[cxx_name = getDiceChainFromCsr]
        fn get_dice_chain_from_csr(csr: &Csr) -> VerifyDiceChainResult;
    }
}

/// A DICE chain as exposed over the cxx bridge.
pub struct DiceChain(Option<ChainForm>);

fn verify_dice_chain(
    chain: &[u8],
    kind: ffi::DiceChainKind,
    allow_any_mode: bool,
    instance: &str,
) -> ffi::VerifyDiceChainResult {
    let mut session = Session {
        options: match kind {
            ffi::DiceChainKind::Vsr13 => Options::vsr13(),
            ffi::DiceChainKind::Vsr14 => Options::vsr14(),
            ffi::DiceChainKind::Vsr15 => Options::vsr15(),
            ffi::DiceChainKind::Vsr16 => Options::vsr16(),
            _ => {
                return ffi::VerifyDiceChainResult {
                    error: "invalid chain kind".to_string(),
                    chain: Box::new(DiceChain(None)),
                    len: 0,
                }
            }
        },
    };
    let Ok(rkp_instance) = RkpInstance::from_str(instance) else {
        return ffi::VerifyDiceChainResult {
            error: format!("invalid RKP instance: {}", instance),
            chain: Box::new(DiceChain(None)),
            len: 0,
        };
    };
    session.set_allow_any_mode(allow_any_mode);
    session.set_rkp_instance(rkp_instance);
    match ChainForm::from_cbor(&session, chain) {
        Ok(chain) => {
            let len = chain.length();
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

fn is_dice_chain_proper(chain: &DiceChain) -> bool {
    if let DiceChain(Some(chain)) = chain {
        match chain {
            ChainForm::Proper(_) => true,
            ChainForm::Degenerate(_) => false,
        }
    } else {
        false
    }
}

/// A Csr as exposed over the cxx bridge.
pub struct Csr(Option<InnerCsr>);

fn validate_csr(
    csr: &[u8],
    kind: ffi::DiceChainKind,
    allow_any_mode: bool,
    instance: &str,
) -> ffi::ValidateCsrResult {
    let mut session = Session {
        options: match kind {
            ffi::DiceChainKind::Vsr13 => Options::vsr13(),
            ffi::DiceChainKind::Vsr14 => Options::vsr14(),
            ffi::DiceChainKind::Vsr15 => Options::vsr15(),
            ffi::DiceChainKind::Vsr16 => Options::vsr16(),
            _ => {
                return ffi::ValidateCsrResult {
                    error: "invalid chain kind".to_string(),
                    csr: Box::new(Csr(None)),
                }
            }
        },
    };
    let Ok(rkp_instance) = RkpInstance::from_str(instance) else {
        return ffi::ValidateCsrResult {
            error: format!("invalid RKP instance: {}", instance),
            csr: Box::new(Csr(None)),
        };
    };
    session.set_allow_any_mode(allow_any_mode);
    session.set_rkp_instance(rkp_instance);
    match InnerCsr::from_cbor(&session, csr) {
        Ok(csr) => {
            let csr = Box::new(Csr(Some(csr)));
            ffi::ValidateCsrResult { error: "".to_string(), csr }
        }
        Err(e) => {
            let error = format!("{:#}", e);
            ffi::ValidateCsrResult { error, csr: Box::new(Csr(None)) }
        }
    }
}

fn get_dice_chain_from_csr(csr: &Csr) -> ffi::VerifyDiceChainResult {
    match csr {
        Csr(Some(csr)) => {
            let chain = csr.dice_chain();
            let len = chain.length();
            let chain = Box::new(DiceChain(Some(chain)));
            ffi::VerifyDiceChainResult { error: "".to_string(), chain, len }
        }
        _ => ffi::VerifyDiceChainResult {
            error: "CSR could not be destructured".to_string(),
            chain: Box::new(DiceChain(None)),
            len: 0,
        },
    }
}
