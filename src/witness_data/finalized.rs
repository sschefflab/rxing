/*
 * FinalizedWitnessData: immutable, fully-populated witness data ready for ZK proof generation.
 */

use ark_ed25519::Fr;
use ark_ff::{FftField, PrimeField};
#[cfg(feature = "serde")]
use serde::Serialize;

use super::accumulator::WitnessData;
use super::block_ops::{
    compute_blocks, compute_ext_codewords, compute_lookups_and_decomps, compute_normalized_blocks,
    compute_words, compute_words_with_dummies,
};
use super::types::{
    BarcodeStats, BlockLookup, EC_TABLE_STATE, PAD_TABLE_STATE, PolynomialResult, RowIndicatorVars,
    SLD_TABLE_STATE, TableState, ZERO_TABLE_STATE,
};
use crate::common::BitMatrix;
use crate::disjoint_set_polynomials::show_disjoint_from_valid_words;

#[cfg(feature = "serde")]
use super::serde_support::{serialize_bitmatrix, serialize_fr_vec, serialize_u32_array_vec_2d};

const WB_NB: usize = 273;
const G_NB: usize = 1080;

/// Appends dummy SLD, EC, and pad table states to `char_table_states`, then prepends
/// zero states so the total length reaches 5400.
///
/// Layout (appended in order):
///   1. 1 SLD codeword → 2 `SLD_TABLE_STATE` entries
///   2. 2^(ec_level + 1) EC codewords → 2 `EC_TABLE_STATE` entries each
///   3. Remaining pad codewords → 2 `PAD_TABLE_STATE` entries each
///      where pad_count = row_count * column_count − 1 (SLD) − ec_count − text_codewords
/// Finally, `ZERO_TABLE_STATE` entries are prepended until the total reaches 5400.
fn add_dummy_table_states(char_table_states: &mut Vec<TableState>, stats: &BarcodeStats) {
    let text_codeword_count = char_table_states.len() as u32 / 2;

    // 1 SLD codeword (2 states)
    char_table_states.push(SLD_TABLE_STATE);
    char_table_states.push(SLD_TABLE_STATE);

    for _ in 0..stats.num_ec_codewords {
        char_table_states.push(EC_TABLE_STATE);
        char_table_states.push(EC_TABLE_STATE);
    }

    // Pad codewords between data and EC sections (2 states each)
    let total_codewords: u32 = (stats.num_rows as u32) * (stats.num_cols as u32);
    let pad_codewords: u32 =
        total_codewords.saturating_sub(1 + (stats.num_ec_codewords as u32) + text_codeword_count);
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

#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "")))]
#[derive(Clone, Debug)]
pub struct FinalizedWitnessData<F: FftField + PrimeField> {
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
    pub bin_image: BitMatrix,

    // The well-behaved rows of the image (ie, rows that conform to pdf417 spec).
    // Some rows repeated to maintain the original image size.
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_bitmatrix"))]
    pub well_behaved: BitMatrix,
    // The row number from the original image that row i in well_behaved came from
    pub wb_inds: Vec<u32>,
    // How many times index i appears in wb_inds. Should be the same length as wb_inds.
    pub wb_ind_counts: Vec<u32>,

    // data that should be in the lookup table we use in the proof for the well-behaved image
    pub wb_lookups: Vec<Vec<BlockLookup>>,
    // the baseB decomp of each encoded chunk of blocks; indexed [row][chunk][element]
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serialize_u32_array_vec_2d")
    )]
    pub wb_baseB_decomps: Vec<Vec<[u32; WB_NB]>>,

    // The "garbage" rows of the image that will not decode
    // Will always have exactly 89 rows. Padded with zero rows.
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_bitmatrix"))]
    pub garbage: BitMatrix,
    // The row number from the original image that row i in garbage came from
    // If it's a zero row, index is -1
    pub garbage_inds: Vec<i32>,
    // How many zero rows appear in garbage
    pub num_zero_rows: u32,

    // data that should be in the lookup table we use in the proof for the garbage image
    pub g_lookups: Vec<Vec<BlockLookup>>,
    // the baseB decomp of each encoded chunk of blocks; indexed [row][chunk][element]
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serialize_u32_array_vec_2d")
    )]
    pub g_baseB_decomps: Vec<Vec<[u32; G_NB]>>,

    pub wb_blocks: Vec<Vec<u32>>,
    pub wb_normalized_blocks: Vec<Vec<[u32; 8]>>,

    // coefficients of polynomials showing that the stuff we throw out from the well-behaved image is disjoint from valid words
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_fr_vec"))]
    pub wb_disjoint_set_poly_f: Vec<F>,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_fr_vec"))]
    pub wb_disjoint_set_poly_g: Vec<F>,

    pub g_blocks: Vec<Vec<u32>>,
    pub garbage_normalized_blocks: Vec<Vec<[u32; 8]>>,

    // coefficients of polynomials showing that gcd(garbage, valid_words) = 1
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_fr_vec"))]
    pub garbage_disjoint_set_poly_f: Vec<F>,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_fr_vec"))]
    pub garbage_disjoint_set_poly_g: Vec<F>,

    pub stats: BarcodeStats,

    #[cfg_attr(feature = "serde", serde(rename = "row_indc"))]
    pub row_indicators: RowIndicatorVars,

    #[cfg_attr(feature = "serde", serde(rename = "left_row_inds"))]
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

    /// Well-behaved words with dummies zeroed out. Shape: [R][WB_CW].
    ///   - Duplicate rows (per wb_inds) are entirely zeroed out.
    ///   - Words that don't decode exactly and aren't START/STOP are replaced with 0.
    pub words_with_dummies: Vec<Vec<u64>>,

    /// All codewords (GF(929) elements) in the barcode, plus 919 for start, stop, and garbage.
    /// Shape: [R][WB_CW], same as words_with_dummies.
    ///   - words_with_dummies == 0 (dummy/garbage) → 919
    ///   - START or STOP word → 919
    ///   - valid data word → codeword index 0–928 from the PDF417 lookup table
    pub ext_codewords: Vec<Vec<u32>>,
}

impl FinalizedWitnessData<Fr> {
    pub fn new(
        width: usize,
        height: usize,
        image: Vec<Vec<u8>>,
        bin_image: BitMatrix,
        well_behaved: BitMatrix,
        wb_inds: Vec<u32>,
        garbage: BitMatrix,
        garbage_inds: Vec<i32>,
        stats: BarcodeStats,
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

        let wb_ind_counts: Vec<u32> = wb_inds
            .iter()
            .map(|target| wb_inds.iter().filter(|&&x| x == *target).count() as u32)
            .collect();
        let num_zero_rows = garbage_inds.iter().filter(|&&x| x == -1).count() as u32;
        let (wb_lookups, wb_baseB_decomps) =
            compute_lookups_and_decomps::<WB_NB>(&well_behaved, WB_B);
        let (g_lookups, g_baseB_decomps) = compute_lookups_and_decomps::<G_NB>(&garbage, G_B);

        let wb_blocks = compute_blocks(&well_behaved, WB_NB);
        let wb_normalized_blocks = compute_normalized_blocks(&wb_blocks);
        let g_blocks = compute_blocks(&garbage, G_NB);
        let garbage_normalized_blocks = compute_normalized_blocks(&g_blocks);

        let garbage_words = compute_words(&garbage_normalized_blocks);
        let (garbage_disjoint_set_poly_f, garbage_disjoint_set_poly_g) =
            show_disjoint_from_valid_words(garbage_words.into_iter().flatten().collect());

        let (words_with_dummies, wb_garbage) =
            compute_words_with_dummies(&wb_normalized_blocks, &wb_inds);
        let ext_codewords = compute_ext_codewords(&wb_normalized_blocks, &words_with_dummies);
        let (wb_disjoint_set_poly_f, wb_disjoint_set_poly_g) =
            show_disjoint_from_valid_words(wb_garbage);

        Self {
            width,
            height,
            image,
            bin_image,
            well_behaved,
            wb_inds,
            wb_ind_counts,
            wb_lookups,
            wb_baseB_decomps,
            garbage,
            garbage_inds,
            num_zero_rows,
            g_lookups,
            g_baseB_decomps,
            wb_blocks,
            wb_normalized_blocks,
            wb_disjoint_set_poly_f,
            wb_disjoint_set_poly_g,
            g_blocks,
            garbage_normalized_blocks,
            garbage_disjoint_set_poly_f,
            garbage_disjoint_set_poly_g,
            stats,
            row_indicators,
            all_left_row_indicators,
            codewords,
            corrected_codewords,
            polynomial_results,
            char_table_states,
            chars,
            words_with_dummies,
            ext_codewords,
        }
    }

    pub fn from_witness_data(witness_data: &WitnessData) -> Result<Self, String> {
        let bin_image = Option::ok_or(witness_data.bin_image.clone(), "no binarized image data")?;

        let well_behaved = Option::ok_or(witness_data.wb_image.clone(), "no wb_image data")?;
        let wb_inds = Option::ok_or(witness_data.wb_inds.clone(), "no wb_inds data")?;
        let garbage = Option::ok_or(witness_data.garbage_image.clone(), "no garbage_image data")?;
        let garbage_inds =
            Option::ok_or(witness_data.garbage_inds.clone(), "no garbage_inds data")?;

        let stats = Option::ok_or(witness_data.stats.clone(), "no barcode stats data")?;

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

        add_dummy_table_states(&mut char_table_states, &stats);

        let chars = Option::ok_or(witness_data.chars.clone(), "no chars data")?;

        Ok(Self::new(
            witness_data.width,
            witness_data.height,
            witness_data.image.clone(),
            bin_image,
            well_behaved,
            wb_inds,
            garbage,
            garbage_inds,
            stats,
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

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // add_dummy_table_states
    // -------------------------------------------------------------------------

    #[test]
    fn test_add_dummy_table_states_total_length() {
        let mut states: Vec<TableState> = Vec::new();
        // row_count=1, column_count=1, ec_level=0
        // total_codewords=1, ec_count=2, pad=max(0, 1-1-2-0)=0
        // pushed: 0 + 2(SLD) + 4(EC) + 0(pad) = 6 → prepend 5394 zeros
        add_dummy_table_states(&mut states, &BarcodeStats { num_rows: 1, num_cols: 1, ec_level: 0, num_ec_codewords: 2 });
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
        add_dummy_table_states(&mut states, &BarcodeStats { num_rows: 5, num_cols: 4, ec_level: 1, num_ec_codewords: 4 });
        assert_eq!(states.len(), 5400);
    }

    #[test]
    fn test_add_dummy_table_states_markers() {
        // Empty input, 1x1 barcode, ec_level=0:
        // Layout: [5394 × ZERO] [SLD SLD] [EC EC EC EC]
        let mut states: Vec<TableState> = Vec::new();
        add_dummy_table_states(&mut states, &BarcodeStats { num_rows: 1, num_cols: 1, ec_level: 0, num_ec_codewords: 2 });

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
        add_dummy_table_states(&mut states, &BarcodeStats { num_rows: 10, num_cols: 5, ec_level: 0, num_ec_codewords: 2 });
        assert_eq!(states.len(), 5400);

        // The last 90 entries should be PAD (char=32)
        for entry in states.iter().rev().take(90) {
            assert_eq!(entry.char, 32, "expected PAD_TABLE_STATE at tail");
        }
    }
}
