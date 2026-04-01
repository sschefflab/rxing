/*
 * Shared types for zero-knowledge proof witness data.
 */

#[cfg(feature = "serde")]
use serde::Serialize;

#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(Clone, Debug)]
pub struct RowIndicatorVars {
    pub l0: u32,
    pub l3: u32,
    pub l6: u32,

    pub q0: u32,
    pub q3: u32,
    pub q6: u32,

    pub r0: u32,
    pub r3: u32,
}

#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(Clone, Debug)]
pub struct PolynomialResult {
    pub result: u32,
    pub result_quotient: u32,
    pub should_be_zero: bool,
}

/// Represents a single character interpretation state in the PDF417 Text Compaction Mode.
/// Mirrors the ZoKrates `TableState` struct in char_lookup.zok.
///
/// Encoding: next_next_table*2^16 + next_table*2^14 + this_table*2^12 + char*2^5 + base30_val
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(Clone, Debug)]
pub struct TableState {
    /// 0-29: codeword value within the sub-mode (codeword / 30 or % 30)
    pub base30_val: u32,
    /// 0-127: ASCII character value (0 for mode-switch entries with no output char)
    pub char: u32,
    /// 0-3: current sub-mode (0=Alpha, 1=Lower, 2=Mixed, 3=Punctuation)
    pub this_table: u32,
    /// 0-3: next sub-mode after this entry
    pub next_table: u32,
    /// 0-3: sub-mode to return to after a temporary shift completes
    pub next_next_table: u32,
}

// A dummy table state used before decoding actually begins
pub(super) const ZERO_TABLE_STATE: TableState = TableState {
    base30_val: 0,
    char: 0,
    this_table: 0,
    next_table: 0,
    next_next_table: 0,
};

// A pad table state that may be present between data and error correction codewords
pub(super) const PAD_TABLE_STATE: TableState = TableState {
    base30_val: 0,
    char: 32,
    this_table: 0,
    next_table: 0,
    next_next_table: 0,
};

// A table state used for error correction codewords that shouldn't actually be decoded
pub(super) const EC_TABLE_STATE: TableState = TableState {
    base30_val: 0,
    char: 6,
    this_table: 0,
    next_table: 0,
    next_next_table: 0,
};

// A table state used for the SLD
pub(super) const SLD_TABLE_STATE: TableState = TableState {
    base30_val: 0,
    char: 95,
    this_table: 0,
    next_table: 0,
    next_next_table: 0,
};
