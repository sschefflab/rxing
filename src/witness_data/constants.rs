/// Maximum number of rows in a PDF417 barcode (spec limit).
pub const MAX_ROWS: usize = 90;

/// Number of garbage rows
/// Always MAX_ROWS - 1 since the garbage is found in between well-behaved rows
pub const GARBAGE_ROWS: usize = MAX_ROWS - 1;

/// Maximum number of data columns in a PDF417 barcode (spec limit).
pub const MAX_DATA_COLS: usize = 30;

/// Maximum number of data codewords = MAX_ROWS * MAX_DATA_COLS.
pub const MAX_DATA_CODEWORDS: usize = MAX_ROWS * MAX_DATA_COLS;

/// Maximum number of decoded characters = 2 per codeword (base-30 encoding).
pub const MAX_CHARS: usize = 2 * MAX_DATA_CODEWORDS;

/// Maximum error correction level (spec limit).
pub const MAX_EC_LEVEL: usize = 8;

/// Maximum number of EC codewords = 2^(MAX_EC_LEVEL + 1).
pub const MAX_EC_CODEWORDS: usize = 1 << (MAX_EC_LEVEL + 1);
