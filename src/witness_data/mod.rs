/*
 * Witness Data for Zero-Knowledge Proofs
 *
 * This module provides structures to capture intermediate processing data
 * from barcode decoding for use in zero-knowledge proof generation.
 *
 * Submodules:
 * - types:      shared data types (RowIndicatorVars, PolynomialResult, TableState)
 * - raw:        WitnessData — mutable accumulator built up during PDF417 decoding
 * - finalized:  FinalizedWitnessData — immutable, fully-populated data for proof generation
 * - block_ops:  image block operations (run-length encoding, lookup table computation)
 */

pub mod types;
pub mod accumulator;
pub mod finalized;
pub mod block_ops;
#[cfg(feature = "serde")]
pub(crate) mod serde_support;

pub use types::{PolynomialResult, RowIndicatorVars, TableState};
pub use accumulator::WitnessData;
pub use finalized::FinalizedWitnessData;
