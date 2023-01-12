//! This module provides functions for validating chains of bcc certificates

mod chain;
pub mod entry;

pub use chain::{Chain, ChainForm, DegenerateChain};
