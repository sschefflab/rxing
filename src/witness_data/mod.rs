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

pub mod accumulator;
pub mod block_ops;
mod width_tables;
pub mod constants;
pub mod disjoint_set_polynomials;
pub mod finalized;
pub mod mode_config;
pub mod polynomial_bezout;
pub mod types;

#[cfg(feature = "serde")]
pub(crate) mod serde_support;

pub use accumulator::WitnessData;
pub use finalized::FinalizedWitnessData;
pub use mode_config::{G_MAX_DECOMPS, ImageMode, ModeConfig, WB_MAX_DECOMPS};
pub use types::{PolynomialResult, RowIndicatorVars, TableState};
