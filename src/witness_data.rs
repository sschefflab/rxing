/*
 * Witness Data for Zero-Knowledge Proofs
 *
 * This module provides a structure to capture intermediate processing data
 * from barcode decoding for use in zero-knowledge proof generation.
 */

use crate::common::BitMatrix;
use crate::pdf417::decoder::pdf_417_codeword_decoder::sampleBitCounts;

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
const ZERO_TABLE_STATE: TableState = TableState {
    base30_val: 0,
    char: 0,
    this_table: 0,
    next_table: 0,
    next_next_table: 0,
};

// A pad table state that may be present between data and error correction codewords
const PAD_TABLE_STATE: TableState = TableState {
    base30_val: 0,
    char: 32,
    this_table: 0,
    next_table: 0,
    next_next_table: 0,
};

// A table state used for error correction codewords that shouldn't actually be decoded
const EC_TABLE_STATE: TableState = TableState {
    base30_val: 0,
    char: 6,
    this_table: 0,
    next_table: 0,
    next_next_table: 0,
};

// A table state used for the SLD
const SLD_TABLE_STATE: TableState = TableState {
    base30_val: 0,
    char: 95,
    this_table: 0,
    next_table: 0,
    next_next_table: 0,
};

/// Appends dummy SLD, EC, and pad table states to `char_table_states`, then prepends
/// zero states so the total length reaches 2700.
///
/// Layout (appended in order):
///   1. 1 SLD codeword → 2 `SLD_TABLE_STATE` entries
///   2. 2^(ec_level + 1) EC codewords → 2 `EC_TABLE_STATE` entries each
///   3. Remaining pad codewords → 2 `PAD_TABLE_STATE` entries each
///      where pad_count = row_count * column_count − 1 (SLD) − ec_count − text_codewords
/// Finally, `ZERO_TABLE_STATE` entries are prepended until the total reaches 2700.
fn add_dummy_table_states(
    char_table_states: &mut Vec<TableState>,
    row_count: u32,
    column_count: u32,
    ec_level: u32,
) {
    let text_codeword_count = char_table_states.len() as u32 / 2;

    // 1 SLD codeword (2 states)
    char_table_states.push(SLD_TABLE_STATE);
    char_table_states.push(SLD_TABLE_STATE);

    // 2^(ec_level + 1) EC codewords (2 states each)
    let ec_count = 1u32 << (ec_level + 1);
    for _ in 0..ec_count {
        char_table_states.push(EC_TABLE_STATE);
        char_table_states.push(EC_TABLE_STATE);
    }

    // Pad codewords between data and EC sections (2 states each)
    let total_codewords = row_count * column_count;
    let pad_codewords = total_codewords.saturating_sub(1 + ec_count + text_codeword_count);
    for _ in 0..pad_codewords {
        char_table_states.push(PAD_TABLE_STATE);
        char_table_states.push(PAD_TABLE_STATE);
    }

    // Prepend zero states to reach exactly 5400 total states
    let current_count = char_table_states.len();
    if current_count < 5400 {
        let zero_count = 5400 - current_count;
        let mut result: Vec<TableState> = (0..zero_count).map(|_| ZERO_TABLE_STATE).collect();
        result.append(char_table_states);
        *char_table_states = result;
    }
}

/**
 * Holds witness data for zero-knowledge proof generation during barcode processing.
 *
 * # Fields
 * * `width` - The width of the image in pixels
 * * `height` - The height of the image in pixels
 * * `image` - The original grayscale luminance values (0-255 per pixel), stored as 2D array [row][col]
 * * `binarized_image` - The binarized black/white BitMatrix after threshold application
 */
#[derive(Clone, Debug)]
pub struct WitnessData {
    /// The width of the image in pixels
    pub width: usize,

    /// The height of the image in pixels
    pub height: usize,

    /// The original grayscale luminance values (0-255 per pixel)
    /// Stored as a 2D array: image[row][col] where row is y-coordinate and col is x-coordinate
    /// Outer vector has `height` elements, each inner vector has `width` elements
    pub image: Vec<Vec<u8>>,

    /// The binarized image after applying the threshold
    /// Pixels are represented as bits: true/1 = black, false/0 = white
    pub binarized_image: Option<BitMatrix>,

    pub wb_image: Option<BitMatrix>,
    pub wb_inds: Option<Vec<u32>>,
    pub garbage_image: Option<BitMatrix>,
    pub garbage_inds: Option<Vec<i32>>,

    /// Barcode metadata values: how many rows and columns it has, and its error correction level
    pub row_count: Option<u32>,
    pub column_count: Option<u32>,
    pub ec_level: Option<u32>,

    pub row_indicators: Option<RowIndicatorVars>,

    pub all_left_row_indicators: Option<Vec<u32>>,

    /// Codewords before error correction
    pub codewords: Option<Vec<u32>>,

    /// Codewords after error correction
    pub corrected_codewords: Option<Vec<u32>>,

    /// Results from error correction polynomial evaluations
    pub polynomial_results: Option<Vec<PolynomialResult>>,

    /// Character interpretation states from PDF417 Text Compaction Mode decoding.
    /// Each text codeword (0-899) produces two entries: one for (codeword/30) and one for (codeword%30).
    pub char_table_states: Option<Vec<TableState>>,

    /// The final decoded text of the barcode, represented as ASCII integer values.
    pub chars: Option<Vec<u8>>,
}

const WB_DECOMP: usize = 2;
const G_DECOMP: usize = 4;

/**
 * WitnessData with no optional fields
 */

#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(Clone, Debug)]
pub struct FinalizedWitnessData {
    /// The width of the image in pixels
    pub width: usize,

    /// The height of the image in pixels
    pub height: usize,

    /// The original grayscale luminance values (0-255 per pixel)
    /// Stored as a 2D array: image[row][col] where row is y-coordinate and col is x-coordinate
    /// Outer vector has `height` elements, each inner vector has `width` elements
    pub image: Vec<Vec<u8>>,

    /// The binarized image after applying the threshold
    /// Pixels are represented as bits: 1 = black, 0 = white
    /// Serialized as a 2D array of 0s and 1s: binarized_image[row][col]
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_bitmatrix"))]
    pub binarized_image: BitMatrix,

    // The well-behaved rows of the image (ie, rows that conform to pdf417 spec).
    // Some rows repeated to maintain the original image size.
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_bitmatrix"))]
    pub wb_image: BitMatrix,
    // The row number from the original image that row i in wb_image came from
    pub wb_inds: Vec<u32>,
    // How many times index i appears in wb_inds. Should be the same length as wb_inds.
    pub wb_ind_counts: Vec<u32>,

    // data that should be in the lookup table we use in the proof for the well-behaved image
    pub wb_lookups: Vec<[u128; 6]>,
    // the baseB decomp of each encoded chunk of blocks
    pub wb_baseB_decomps: Vec<[usize; WB_DECOMP]>,

    // The "garbage" rows of the image that will not decode
    // Will always have exactly 89 rows. Padded with zero rows.
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_bitmatrix"))]
    pub garbage_image: BitMatrix,
    // The row number from the original image that row i in garbage_image came from
    // If it's a zero row, index is -1
    pub garbage_inds: Vec<i32>,
    // How many zero rows appear in garbage_image
    pub num_zero_rows: u32,

    // data that should be in the lookup table we use in the proof for the garbage image
    pub garbage_lookups: Vec<[u128; 6]>,
    // the baseB decomp of each encoded chunk of blocks
    pub g_baseB_decomps: Vec<[usize; G_DECOMP]>,

    pub wb_blocks: Vec<Vec<u32>>,
    pub wb_normalized_blocks: Vec<Vec<[u32; 8]>>,

    pub garbage_blocks: Vec<Vec<u32>>,
    pub garbage_normalized_blocks: Vec<Vec<[u32; 8]>>,

    pub row_count: u32,
    pub column_count: u32,
    pub ec_level: u32,

    pub row_indicators: RowIndicatorVars,

    pub all_left_row_indicators: Vec<u32>,

    /// Codewords before error correction
    pub codewords: Vec<u32>,

    /// Codewords after error correction
    pub corrected_codewords: Vec<u32>,

    /// Results from error correction polynomial evaluations
    pub polynomial_results: Vec<PolynomialResult>,

    /// Character interpretation states from PDF417 Text Compaction Mode decoding.
    /// Each text codeword (0-899) produces two entries: one for (codeword/30) and one for (codeword%30).
    pub char_table_states: Vec<TableState>,

    /// The final decoded text of the barcode, represented as ASCII integer values.
    pub chars: Vec<u8>,
}

impl FinalizedWitnessData {
    pub fn new(
        width: usize,
        height: usize,
        image: Vec<Vec<u8>>,
        binarized_image: BitMatrix,
        wb_image: BitMatrix,
        wb_inds: Vec<u32>,
        garbage_image: BitMatrix,
        garbage_inds: Vec<i32>,
        row_count: u32,
        column_count: u32,
        ec_level: u32,
        row_indicators: RowIndicatorVars,
        all_left_row_indicators: Vec<u32>,
        codewords: Vec<u32>,
        corrected_codewords: Vec<u32>,
        polynomial_results: Vec<PolynomialResult>,
        char_table_states: Vec<TableState>,
        chars: Vec<u8>,
    ) -> Self {
        assert_eq!(
            image.len(),
            height,
            "Image height mismatch: expected {} rows, got {}",
            height,
            image.len()
        );
        for (row_idx, row) in image.iter().enumerate() {
            assert_eq!(
                row.len(),
                width,
                "Image width mismatch at row {}: expected {} columns, got {}",
                row_idx,
                width,
                row.len()
            );
        }
        const WB_B: usize = 27;
        const G_B: usize = 1080;
        const WB_NB: usize = 273;
        const G_NB: usize = 1080;

        let wb_ind_counts: Vec<u32> = wb_inds
            .iter()
            .map(|target| wb_inds.iter().filter(|&&x| x == *target).count() as u32)
            .collect();
        let num_zero_rows = garbage_inds.iter().filter(|&&x| x == -1).count() as u32;
        let (wb_lookups, wb_baseB_decomps) =
            Self::compute_lookups_and_decomps::<WB_DECOMP>(&wb_image, WB_B);
        let (garbage_lookups, g_baseB_decomps) =
            Self::compute_lookups_and_decomps::<G_DECOMP>(&garbage_image, G_B);

        let wb_blocks = Self::compute_blocks(&wb_image, WB_NB);
        let wb_normalized_blocks = Self::compute_normalized_blocks(&wb_blocks);
        let garbage_blocks = Self::compute_blocks(&garbage_image, G_NB);
        let garbage_normalized_blocks = Self::compute_normalized_blocks(&garbage_blocks);

        Self {
            width,
            height,
            image,
            binarized_image,
            wb_image,
            wb_inds,
            wb_ind_counts,
            wb_lookups,
            wb_baseB_decomps,
            garbage_image,
            garbage_inds,
            num_zero_rows,
            garbage_lookups,
            g_baseB_decomps,
            wb_blocks,
            wb_normalized_blocks,
            garbage_blocks,
            garbage_normalized_blocks,
            row_count,
            column_count,
            ec_level,
            row_indicators,
            all_left_row_indicators,
            codewords,
            corrected_codewords,
            polynomial_results,
            char_table_states,
            chars,
        }
    }

    fn compute_lookups_and_decomps<const N: usize>(
        image: &BitMatrix,
        B: usize,
    ) -> (Vec<[u128; 6]>, Vec<[usize; N]>) {
        const L: usize = 10;
        let width = image.width() as usize;
        let height = image.height() as usize;
        let mut lookups = Vec::new();
        let mut decomps = Vec::new();

        for row in 0..height {
            let num_chunks = width.div_ceil(L);
            for chunk in 0..num_chunks {
                let start_col = chunk * L;
                let chunk_len = L.min(width - start_col);

                // Take chunk_len pixels and compute int as a binary string
                let mut int_val: u128 = 0;
                let mut pixels = [false; L];
                for i in 0..chunk_len {
                    let px = image.get((start_col + i) as u32, row as u32);
                    pixels[i] = px;
                    if px {
                        int_val |= 1 << i;
                    }
                }

                // Compute blocks: lengths of runs of the same color
                let mut blocks_vec: Vec<u128> = Vec::new();
                let mut current_run: u128 = 1;
                for i in 1..chunk_len {
                    if pixels[i] == pixels[i - 1] {
                        current_run += 1;
                    } else {
                        blocks_vec.push(current_run);
                        current_run = 1;
                    }
                }
                blocks_vec.push(current_run);

                // Encode blocks base B (big-endian: first block is most significant)
                let mut blocks_base_b: u128 = 0;
                for &b in &blocks_vec {
                    blocks_base_b = blocks_base_b * B as u128 + b;
                }

                // Base-B decomposition: blocks_vec padded with leading zeros to length N
                let nb = blocks_vec.len();
                assert!(nb <= N, "blocks_vec length {nb} exceeds decomp size {N}");
                let mut decomp = [0; N];
                let offset = N - nb;
                for (i, &b) in blocks_vec.iter().enumerate() {
                    decomp[offset + i] = b as usize;
                }
                decomps.push(decomp);

                // r = last block length
                let r = *blocks_vec.last().unwrap();

                // nb = number of blocks
                let nb = nb as u128;

                // odd = nb % 2 == 1
                let odd = nb % 2;

                // block = 1 if last block is black, 0 if white
                // The last block has the same color as the first pixel when (nb-1) is even,
                // and the opposite color when (nb-1) is odd.
                let first_is_black = pixels[0];
                let last_is_black = if (nb - 1) % 2 == 0 {
                    first_is_black
                } else {
                    !first_is_black
                };
                let block: u128 = if last_is_black { 1 } else { 0 };

                lookups.push([int_val, blocks_base_b, r, nb, odd, block]);
            }
        }

        (lookups, decomps)
    }

    fn compute_blocks(image: &BitMatrix, len: usize) -> Vec<Vec<u32>> {
        let width = image.width() as usize;
        let height = image.height() as usize;
        let mut result: Vec<Vec<u32>> = Vec::new();

        for r in 0..height {
            let mut row_result = Vec::new();
            if width == 0 {
                continue;
            }
            let mut current_run: u32 = 1;
            for i in 1..width {
                let prev = image.get((i - 1) as u32, r as u32);
                let curr = image.get(i as u32, r as u32);
                if curr == prev {
                    current_run += 1;
                } else {
                    row_result.push(current_run);
                    current_run = 1;
                }
            }
            row_result.push(current_run);
            row_result.resize(len, 0);
            result.push(row_result);
        }

        result
    }

    fn compute_normalized_blocks(blocks: &[Vec<u32>]) -> Vec<Vec<[u32; 8]>> {
        blocks
            .iter()
            .map(|row| {
                row.chunks_exact(8)
                    .filter(|window| window.iter().all(|&x| x != 0))
                    .map(|window| sampleBitCounts(window))
                    .collect()
            })
            .collect()
    }

    pub fn from_witness_data(witness_data: &WitnessData) -> Result<Self, String> {
        let binarized_image = Option::ok_or(
            witness_data.binarized_image.clone(),
            "no binarized image data",
        )?;

        let wb_image = Option::ok_or(witness_data.wb_image.clone(), "no wb_image data")?;
        let wb_inds = Option::ok_or(witness_data.wb_inds.clone(), "no wb_inds data")?;
        let garbage_image =
            Option::ok_or(witness_data.garbage_image.clone(), "no garbage_image data")?;
        let garbage_inds =
            Option::ok_or(witness_data.garbage_inds.clone(), "no garbage_inds data")?;

        let row_count = Option::ok_or(witness_data.row_count.clone(), "no row count data")?;

        let column_count =
            Option::ok_or(witness_data.column_count.clone(), "no column count data")?;

        let ec_level = Option::ok_or(
            witness_data.ec_level.clone(),
            "no error correction level data",
        )?;

        let row_indicators =
            Option::ok_or(witness_data.row_indicators.clone(), "no row indicator data")?;

        let all_left_row_indicators = Option::ok_or(
            witness_data.all_left_row_indicators.clone(),
            "no all left row indicators data",
        )?;

        let codewords = Option::ok_or(witness_data.codewords.clone(), "no codewords data")?;

        let corrected_codewords = Option::ok_or(
            witness_data.corrected_codewords.clone(),
            "no corrected codewords data",
        )?;

        let polynomial_results = Option::ok_or(
            witness_data.polynomial_results.clone(),
            "no polynomial results data",
        )?;

        let mut char_table_states = Option::ok_or(
            witness_data.char_table_states.clone(),
            "no char table states data",
        )?;

        add_dummy_table_states(&mut char_table_states, row_count, column_count, ec_level);

        let chars = Option::ok_or(witness_data.chars.clone(), "no chars data")?;

        Ok(Self::new(
            witness_data.width,
            witness_data.height,
            witness_data.image.clone(),
            binarized_image,
            wb_image,
            wb_inds,
            garbage_image,
            garbage_inds,
            row_count,
            column_count,
            ec_level,
            row_indicators,
            all_left_row_indicators,
            codewords,
            corrected_codewords,
            polynomial_results,
            char_table_states,
            chars,
        ))
    }

    /**
     * Saves this WitnessData to a JSON file.
     *
     * # Arguments
     * * `path` - The file path to write to
     *
     * # Returns
     * Result indicating success or error
     */
    #[cfg(feature = "serde")]
    pub fn save_to_json(&self, path: &str) -> Result<(), String> {
        use std::fs::File;
        use std::io::Write;

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize to JSON: {}", e))?;

        let mut file =
            File::create(path).map_err(|e| format!("Failed to create file '{}': {}", path, e))?;

        file.write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write to file '{}': {}", path, e))?;

        Ok(())
    }
}

impl WitnessData {
    /**
     * Creates a new WitnessData instance.
     *
     * # Arguments
     * * `width` - The width of the image in pixels
     * * `height` - The height of the image in pixels
     * * `image` - The grayscale luminance data as a 2D array [row][col]
     *
     * # Panics
     * Panics if the image dimensions don't match width and height
     */
    pub fn new(width: usize, height: usize, image: Vec<Vec<u8>>) -> Self {
        assert_eq!(
            image.len(),
            height,
            "Image height mismatch: expected {} rows, got {}",
            height,
            image.len()
        );
        for (row_idx, row) in image.iter().enumerate() {
            assert_eq!(
                row.len(),
                width,
                "Image width mismatch at row {}: expected {} columns, got {}",
                row_idx,
                width,
                row.len()
            );
        }

        Self {
            width,
            height,
            image,
            binarized_image: None,
            wb_image: None,
            wb_inds: None,
            garbage_image: None,
            garbage_inds: None,
            row_count: None,
            column_count: None,
            ec_level: None,
            row_indicators: None,
            all_left_row_indicators: None,
            codewords: None,
            corrected_codewords: None,
            polynomial_results: None,
            char_table_states: None,
            chars: None,
        }
    }

    /**
     * Returns the width of the image in pixels.
     */
    pub fn width(&self) -> usize {
        self.width
    }

    /**
     * Returns the height of the image in pixels.
     */
    pub fn height(&self) -> usize {
        self.height
    }

    /**
     * Returns a reference to the grayscale image data as a 2D array.
     */
    pub fn image(&self) -> &[Vec<u8>] {
        &self.image
    }

    /**
     * Returns a reference to the binarized image.
     */
    pub fn binarized_image(&self) -> &Option<BitMatrix> {
        &self.binarized_image
    }

    pub fn set_binarized_image(&mut self, binarized_image: BitMatrix) {
        self.binarized_image = Some(binarized_image)
    }

    pub fn set_barcode_metadata(&mut self, row_count: u32, column_count: u32, ec_level: u32) {
        self.row_count = Some(row_count);
        self.column_count = Some(column_count);
        self.ec_level = Some(ec_level);
    }

    pub fn set_row_indicators(&mut self, row_indicators: RowIndicatorVars) {
        self.row_indicators = Some(row_indicators);
    }

    pub fn set_all_left_row_indicators(&mut self, all_left_row_indicators: Vec<u32>) {
        self.all_left_row_indicators = Some(all_left_row_indicators);
    }

    pub fn set_codewords(&mut self, codewords: Vec<u32>, corrected_codewords: Vec<u32>) {
        self.codewords = Some(codewords);
        self.corrected_codewords = Some(corrected_codewords);
    }

    pub fn set_polynomial_results(&mut self, polynomial_results: Vec<PolynomialResult>) {
        self.polynomial_results = Some(polynomial_results);
    }

    pub fn set_char_table_states(&mut self, char_table_states: Vec<TableState>) {
        self.char_table_states = Some(char_table_states);
    }

    pub fn set_chars(&mut self, chars: Vec<u8>) {
        self.chars = Some(chars);
    }

    /**
     * Makes sure that all optional fields have data in them.
     */
    pub fn finalize(&self) -> Result<FinalizedWitnessData, String> {
        FinalizedWitnessData::from_witness_data(self)
    }

    /**
     * Gets the grayscale pixel value at position (x, y).
     *
     * # Arguments
     * * `x` - The x coordinate (column)
     * * `y` - The y coordinate (row)
     *
     * # Panics
     * Panics if x >= width or y >= height
     */
    pub fn get_pixel(&self, x: usize, y: usize) -> u8 {
        assert!(
            x < self.width && y < self.height,
            "Pixel coordinates out of bounds"
        );
        self.image[y][x]
    }

    /**
     * Gets the binarized bit value at position (x, y).
     *
     * # Arguments
     * * `x` - The x coordinate (column)
     * * `y` - The y coordinate (row)
     *
     * # Returns
     * `true` if the pixel is black, `false` if white
     */
    pub fn get_binarized_pixel(&self, x: usize, y: usize) -> Option<bool> {
        match &self.binarized_image {
            Some(binarized_image) => Some(binarized_image.get(x as u32, y as u32)),
            None => None,
        }
    }
}

// Custom serialization for BitMatrix - convert to 2D array of 0s and 1s
// Stored as rows[y][x] where each value is 0 (white) or 1 (black)
#[cfg(feature = "serde")]
fn serialize_bitmatrix<S>(matrix: &BitMatrix, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;

    let width = matrix.getWidth();
    let height = matrix.getHeight();

    // Create outer sequence for rows
    let mut rows = serializer.serialize_seq(Some(height as usize))?;
    for y in 0..height {
        // Build each row as a Vec<u8> of 0s and 1s
        let row: Vec<u8> = (0..width)
            .map(|x| if matrix.get(x, y) { 1 } else { 0 })
            .collect();
        rows.serialize_element(&row)?;
    }
    rows.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a BitMatrix from a slice of bool slices (rows).
    fn make_bitmatrix(rows: &[&[bool]]) -> BitMatrix {
        let height = rows.len();
        let width = rows.first().map_or(0, |r| r.len());
        let mut bm = BitMatrix::new(width as u32, height as u32).unwrap();
        for (y, row) in rows.iter().enumerate() {
            for (x, &px) in row.iter().enumerate() {
                if px {
                    bm.set(x as u32, y as u32);
                }
            }
        }
        bm
    }

    // -------------------------------------------------------------------------
    // compute_lookups_and_decomps
    // -------------------------------------------------------------------------

    #[test]
    fn test_compute_lookups_all_white() {
        // Single row, 5 white pixels → one block of length 5
        let image = make_bitmatrix(&[&[false, false, false, false, false]]);
        let (lookups, decomps) =
            FinalizedWitnessData::compute_lookups_and_decomps::<2>(&image, 27);

        assert_eq!(lookups.len(), 1);
        assert_eq!(decomps.len(), 1);
        let [int_val, blocks_base_b, r, nb, odd, block] = lookups[0];
        assert_eq!(int_val, 0);
        assert_eq!(blocks_base_b, 5); // B=27, single block of 5
        assert_eq!(r, 5);
        assert_eq!(nb, 1);
        assert_eq!(odd, 1);
        assert_eq!(block, 0); // last block is white
        assert_eq!(decomps[0], [0, 5]); // padded with one leading zero
    }

    #[test]
    fn test_compute_lookups_all_black() {
        // Single row, 5 black pixels → one block of length 5
        let image = make_bitmatrix(&[&[true, true, true, true, true]]);
        let (lookups, decomps) =
            FinalizedWitnessData::compute_lookups_and_decomps::<2>(&image, 27);

        assert_eq!(lookups.len(), 1);
        let [int_val, blocks_base_b, r, nb, odd, block] = lookups[0];
        assert_eq!(int_val, 0b11111); // all 5 bits set
        assert_eq!(blocks_base_b, 5);
        assert_eq!(r, 5);
        assert_eq!(nb, 1);
        assert_eq!(odd, 1);
        assert_eq!(block, 1); // last block is black
        assert_eq!(decomps[0], [0, 5]);
    }

    #[test]
    fn test_compute_lookups_two_blocks() {
        // 3 black then 7 white, fills exactly one chunk of 10
        let row: &[bool] = &[
            true, true, true, false, false, false, false, false, false, false,
        ];
        let image = make_bitmatrix(&[row]);
        let (lookups, decomps) =
            FinalizedWitnessData::compute_lookups_and_decomps::<2>(&image, 27);

        assert_eq!(lookups.len(), 1);
        let [int_val, blocks_base_b, r, nb, odd, block] = lookups[0];
        assert_eq!(int_val, 0b0000000111); // bits 0,1,2 set
        assert_eq!(blocks_base_b, 3 * 27 + 7); // = 88
        assert_eq!(r, 7);
        assert_eq!(nb, 2);
        assert_eq!(odd, 0);
        // first_is_black=true, (nb-1)%2=1 → last is opposite → white → block=0
        assert_eq!(block, 0);
        assert_eq!(decomps[0], [3, 7]);
    }

    #[test]
    fn test_compute_lookups_four_blocks() {
        // [W,B,B,W,W,W,W,B,B,B] → blocks [1,2,4,3], N=4
        let row: &[bool] = &[
            false, true, true, false, false, false, false, true, true, true,
        ];
        let image = make_bitmatrix(&[row]);
        let (lookups, decomps) =
            FinalizedWitnessData::compute_lookups_and_decomps::<4>(&image, 1080);

        let [_int_val, blocks_base_b, r, nb, odd, block] = lookups[0];
        assert_eq!(nb, 4);
        assert_eq!(odd, 0);
        assert_eq!(r, 3);
        // first_is_black=false, (nb-1)%2=3%2=1 → last is opposite → black → block=1
        assert_eq!(block, 1);
        // decomp fills all N=4 slots, no leading zeros
        assert_eq!(decomps[0], [1, 2, 4, 3]);
        // blocks_base_b = 1*1080^3 + 2*1080^2 + 4*1080 + 3
        let expected = 1u128 * 1080u128.pow(3)
            + 2 * 1080u128.pow(2)
            + 4 * 1080
            + 3;
        assert_eq!(blocks_base_b, expected);
    }

    #[test]
    fn test_compute_lookups_multiple_chunks() {
        // Width=20, one row: first 2 cols black, cols 15-19 black
        // Chunk 0 (cols 0-9):  [T,T,F,F,F,F,F,F,F,F] → blocks [2,8]
        // Chunk 1 (cols 10-19):[F,F,F,F,F,T,T,T,T,T] → blocks [5,5]
        let mut row = vec![false; 20];
        row[0] = true;
        row[1] = true;
        for i in 15..20 {
            row[i] = true;
        }
        let image = make_bitmatrix(&[row.as_slice()]);
        let (lookups, decomps) =
            FinalizedWitnessData::compute_lookups_and_decomps::<2>(&image, 27);

        assert_eq!(lookups.len(), 2);
        assert_eq!(decomps.len(), 2);

        // Chunk 0
        let [int_val0, blocks_base_b0, r0, nb0, odd0, block0] = lookups[0];
        assert_eq!(int_val0, 3); // bits 0,1
        assert_eq!(blocks_base_b0, 2 * 27 + 8); // = 62
        assert_eq!(r0, 8);
        assert_eq!(nb0, 2);
        assert_eq!(odd0, 0);
        assert_eq!(block0, 0); // first=black, (nb-1)%2=1 → last=white
        assert_eq!(decomps[0], [2, 8]);

        // Chunk 1
        let [int_val1, blocks_base_b1, r1, nb1, odd1, block1] = lookups[1];
        // pixels 5-9 of the chunk (cols 15-19) are black → bits 5-9 set
        assert_eq!(int_val1, (1u128 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9));
        assert_eq!(blocks_base_b1, 5 * 27 + 5); // = 140
        assert_eq!(r1, 5);
        assert_eq!(nb1, 2);
        assert_eq!(odd1, 0);
        assert_eq!(block1, 1); // first=white, (nb-1)%2=1 → last=black
        assert_eq!(decomps[1], [5, 5]);
    }

    #[test]
    fn test_compute_lookups_multiple_rows() {
        // 2 rows: all-black, all-white
        let image = make_bitmatrix(&[
            &[true, true, true, true, true],
            &[false, false, false, false, false],
        ]);
        let (lookups, decomps) =
            FinalizedWitnessData::compute_lookups_and_decomps::<2>(&image, 27);

        assert_eq!(lookups.len(), 2);
        assert_eq!(decomps.len(), 2);
        assert_eq!(lookups[0][5], 1); // row 0: last block black
        assert_eq!(lookups[1][5], 0); // row 1: last block white
        assert_eq!(decomps[0], [0, 5]);
        assert_eq!(decomps[1], [0, 5]);
    }

    #[test]
    fn test_decomp_reconstructs_blocks_base_b() {
        // For any chunk, folding the decomp big-endian must equal blocks_base_b in the lookup.
        let rows: &[&[bool]] = &[
            &[true, false, true, false, true, false, true, false, true, false], // alternating, 10 blocks
            &[true, true, false, false, true, true, false, false, true, true], // pairs
            &[false, false, false, true, true, true, true, true, true, true], // 3 white then 7 black
        ];
        let image = make_bitmatrix(rows);
        const B: usize = 27;
        // Use N=10 so even fully alternating rows (10 blocks) fit
        let (lookups, decomps) =
            FinalizedWitnessData::compute_lookups_and_decomps::<10>(&image, B);

        for (lookup, decomp) in lookups.iter().zip(decomps.iter()) {
            let blocks_base_b = lookup[1];
            let reconstructed: u128 = decomp
                .iter()
                .fold(0u128, |acc, &d| acc * B as u128 + d as u128);
            assert_eq!(
                reconstructed, blocks_base_b,
                "decomp {:?} does not reconstruct blocks_base_b {}",
                decomp, blocks_base_b
            );
        }
    }

    #[test]
    fn test_decomp_leading_zeros_match_nb() {
        // The number of leading zeros in the decomp should equal N - nb.
        let rows: &[&[bool]] = &[
            &[true, true, true, false, false, false, false, false, false, false], // 2 blocks
            &[true, false, true, false, true, false, false, false, false, false], // 6 blocks (alt)
        ];
        let image = make_bitmatrix(rows);
        let (lookups, decomps) =
            FinalizedWitnessData::compute_lookups_and_decomps::<10>(&image, 27);

        for (lookup, decomp) in lookups.iter().zip(decomps.iter()) {
            let nb = lookup[3] as usize;
            let leading_zeros = decomp.iter().take_while(|&&d| d == 0).count();
            assert_eq!(leading_zeros, 10 - nb);
            // All non-leading-zero elements should be positive
            for &d in &decomp[(10 - nb)..] {
                assert!(d > 0, "non-leading element should be positive");
            }
        }
    }

    // -------------------------------------------------------------------------
    // compute_blocks
    // -------------------------------------------------------------------------

    #[test]
    fn test_compute_blocks_basic() {
        // [T,T,F,F,F] → run-lengths [2, 3], padded to len=5
        let image = make_bitmatrix(&[&[true, true, false, false, false]]);
        let blocks = FinalizedWitnessData::compute_blocks(&image, 5);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0][0], 2);
        assert_eq!(blocks[0][1], 3);
        assert_eq!(blocks[0][2], 0); // zero-padded
    }

    #[test]
    fn test_compute_blocks_single_run() {
        // All white → one run, padded to len=4
        let image = make_bitmatrix(&[&[false, false, false, false]]);
        let blocks = FinalizedWitnessData::compute_blocks(&image, 4);
        assert_eq!(blocks[0][0], 4);
        for &b in &blocks[0][1..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn test_compute_blocks_multiple_rows() {
        let image = make_bitmatrix(&[
            &[true, true, false],   // [2, 1]
            &[false, false, false], // [3]
        ]);
        let blocks = FinalizedWitnessData::compute_blocks(&image, 4);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0][0], 2);
        assert_eq!(blocks[0][1], 1);
        assert_eq!(blocks[1][0], 3);
        assert_eq!(blocks[1][1], 0);
    }

    // -------------------------------------------------------------------------
    // add_dummy_table_states
    // -------------------------------------------------------------------------

    #[test]
    fn test_add_dummy_table_states_total_length() {
        let mut states: Vec<TableState> = Vec::new();
        // row_count=1, column_count=1, ec_level=0
        // total_codewords=1, ec_count=2, pad=max(0, 1-1-2-0)=0
        // pushed: 0 + 2(SLD) + 4(EC) + 0(pad) = 6 → prepend 5394 zeros
        add_dummy_table_states(&mut states, 1, 1, 0);
        assert_eq!(states.len(), 5400);
    }

    #[test]
    fn test_add_dummy_table_states_with_text_codewords() {
        // 2 text codewords → 4 states; row_count=5, col_count=4, ec_level=1
        // total=20, ec_count=4, pad=20-1-4-2=13
        // pushed: 4 + 2 + 8 + 26 = 40 → prepend 5360 zeros
        let mut states: Vec<TableState> = (0..4)
            .map(|_| TableState {
                base30_val: 1,
                char: 65,
                this_table: 0,
                next_table: 0,
                next_next_table: 0,
            })
            .collect();
        add_dummy_table_states(&mut states, 5, 4, 1);
        assert_eq!(states.len(), 5400);
    }

    #[test]
    fn test_add_dummy_table_states_markers() {
        // Empty input, 1x1 barcode, ec_level=0:
        // Layout: [5394 × ZERO] [SLD SLD] [EC EC EC EC]
        let mut states: Vec<TableState> = Vec::new();
        add_dummy_table_states(&mut states, 1, 1, 0);

        // Leading entries are zeros (char=0)
        assert_eq!(states[0].char, 0);
        assert_eq!(states[5393].char, 0);
        // SLD entries (char=95)
        assert_eq!(states[5394].char, 95);
        assert_eq!(states[5395].char, 95);
        // EC entries (char=6)
        assert_eq!(states[5396].char, 6);
        assert_eq!(states[5397].char, 6);
        assert_eq!(states[5398].char, 6);
        assert_eq!(states[5399].char, 6);
    }

    #[test]
    fn test_add_dummy_table_states_pad_marker() {
        // Use a barcode large enough to have pad codewords.
        // 4 text states (2 codewords), row_count=10, col_count=5, ec_level=0
        // total=50, ec_count=2, pad=50-1-2-2=45
        // Layout: [zeros] [text×4] [SLD×2] [EC×4] [PAD×90]
        let mut states: Vec<TableState> = (0..4)
            .map(|_| TableState {
                base30_val: 0,
                char: 65,
                this_table: 0,
                next_table: 0,
                next_next_table: 0,
            })
            .collect();
        add_dummy_table_states(&mut states, 10, 5, 0);
        assert_eq!(states.len(), 5400);

        // The last 90 entries should be PAD (char=32)
        for entry in states.iter().rev().take(90) {
            assert_eq!(entry.char, 32, "expected PAD_TABLE_STATE at tail");
        }
    }

    #[test]
    fn test_witness_data_creation() {
        // Create a simple 4x4 test image as 2D array
        let image = vec![
            vec![0, 64, 127, 128],
            vec![129, 192, 200, 255],
            vec![50, 100, 150, 200],
            vec![127, 128, 129, 130],
        ];

        let mut binarized = BitMatrix::new(4, 4).unwrap();
        // Set some pixels black (< 128)
        binarized.set(0, 0); // 0
        binarized.set(1, 0); // 64
        binarized.set(2, 0); // 127
        // 128+ stay white

        let mut witness = WitnessData::new(4, 4, image.clone());
        witness.set_binarized_image(binarized);

        assert_eq!(witness.width(), 4);
        assert_eq!(witness.height(), 4);
        assert_eq!(witness.image().len(), 4); // 4 rows
        assert_eq!(witness.image()[0].len(), 4); // 4 columns per row
        assert_eq!(witness.get_pixel(0, 0), 0);
        assert_eq!(witness.get_pixel(3, 1), 255);
        assert_eq!(witness.get_binarized_pixel(0, 0), Some(true)); // black
        assert_eq!(witness.get_binarized_pixel(3, 0), Some(false)); // white
    }

    #[test]
    #[should_panic(expected = "Image height mismatch")]
    fn test_witness_data_size_mismatch() {
        let image = vec![vec![1, 2, 3]]; // Wrong number of rows
        let _witness = WitnessData::new(3, 4, image);
    }

    #[test]
    fn test_witness_finalization_flow() {
        let image = vec![vec![255; 2]; 2];
        let mut witness = WitnessData::new(2, 2, image);

        // Test that finalization fails when fields are missing
        assert!(witness.finalize().is_err());

        // Populate required fields
        witness.set_binarized_image(BitMatrix::new(2, 2).unwrap());
        witness.wb_image = Some(BitMatrix::new(2, 2).unwrap());
        witness.wb_inds = Some(vec![0, 1]);
        witness.garbage_image = Some(BitMatrix::new(2, 89).unwrap());
        witness.garbage_inds = Some(vec![-1; 89]);
        witness.set_barcode_metadata(30, 10, 2);
        witness.set_row_indicators(RowIndicatorVars {
            l0: 1,
            l3: 1,
            l6: 1,
            q0: 1,
            q3: 1,
            q6: 1,
            r0: 1,
            r3: 1,
        });
        witness.set_all_left_row_indicators(vec![]);
        witness.set_codewords(vec![1, 2], vec![1, 2]);
        witness.set_polynomial_results(vec![PolynomialResult {
            result: 0,
            result_quotient: 0,
            should_be_zero: true,
        }]);
        witness.set_char_table_states(vec![]);
        witness.set_chars(vec![]);

        // Verify successful finalization
        let finalized = witness
            .finalize()
            .expect("Should finalize with all fields set");
        assert_eq!(finalized.row_count, 30);
    }
}
