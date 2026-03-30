/*
 * Witness Data for Zero-Knowledge Proofs
 *
 * This module provides a structure to capture intermediate processing data
 * from barcode decoding for use in zero-knowledge proof generation.
 */

use crate::common::BitMatrix;

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

    /// Lengths of blocks of contiguous pixels of the same color
    pub blocks: Option<Vec<Vec<u32>>>,

    pub normalized_blocks: Option<Vec<Vec<[u32; 8]>>>,

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
}

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

    // The "garbage" rows of the image that will not decode
    // Will always have exactly 89 rows. Padded with zero rows.
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_bitmatrix"))]
    pub garbage_image: BitMatrix,
    // The row number from the original image that row i in garbage_image came from
    // If it's a zero row, index is -1
    pub garbage_inds: Vec<i32>,
    // How many zero rows appear in garbage_image
    pub num_zero_rows: u32,

    /// Lengths of blocks of contiguous pixels of the same color
    pub blocks: Vec<Vec<u32>>,

    pub normalized_blocks: Vec<Vec<[u32; 8]>>,

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
        blocks: Vec<Vec<u32>>,
        normalized_blocks: Vec<Vec<[u32; 8]>>,
        row_count: u32,
        column_count: u32,
        ec_level: u32,
        row_indicators: RowIndicatorVars,
        all_left_row_indicators: Vec<u32>,
        codewords: Vec<u32>,
        corrected_codewords: Vec<u32>,
        polynomial_results: Vec<PolynomialResult>,
        char_table_states: Vec<TableState>,
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

        let wb_ind_counts: Vec<u32> = wb_inds
            .iter()
            .map(|target| wb_inds.iter().filter(|&&x| x == *target).count() as u32)
            .collect();
        let num_zero_rows = garbage_inds.iter().filter(|&&x| x == -1).count() as u32;

        Self {
            width,
            height,
            image,
            binarized_image,
            wb_image,
            wb_inds,
            wb_ind_counts,
            garbage_image,
            garbage_inds,
            num_zero_rows,
            blocks,
            normalized_blocks,
            row_count,
            column_count,
            ec_level,
            row_indicators,
            all_left_row_indicators,
            codewords,
            corrected_codewords,
            polynomial_results,
            char_table_states,
        }
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

        let blocks = Option::ok_or(witness_data.blocks.clone(), "no blocks data")?;

        let normalized_blocks = Option::ok_or(
            witness_data.normalized_blocks.clone(),
            "no normalized blocks data",
        )?;

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

        let char_table_states = Option::ok_or(
            witness_data.char_table_states.clone(),
            "no char table states data",
        )?;

        let wb_ind_counts: Vec<u32> = wb_inds
            .iter()
            .map(|target| wb_inds.iter().filter(|&&x| x == *target).count() as u32)
            .collect();
        let num_zero_rows = garbage_inds.iter().filter(|&&x| x == -1).count() as u32;

        Ok(Self {
            width: witness_data.width,
            height: witness_data.height,
            image: witness_data.image.clone(),
            binarized_image,
            wb_image,
            wb_inds,
            wb_ind_counts,
            garbage_image,
            garbage_inds,
            num_zero_rows,
            blocks,
            normalized_blocks,
            row_count,
            column_count,
            ec_level,
            row_indicators,
            all_left_row_indicators,
            codewords,
            corrected_codewords,
            polynomial_results,
            char_table_states,
        })
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
            blocks: None,
            normalized_blocks: None,
            row_count: None,
            column_count: None,
            ec_level: None,
            row_indicators: None,
            all_left_row_indicators: None,
            codewords: None,
            corrected_codewords: None,
            polynomial_results: None,
            char_table_states: None,
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

    /// does the flattening here
    pub fn set_blocks(&mut self, blocks: Vec<Vec<[u32; 8]>>) {
        let flat: Vec<Vec<u32>> = blocks
            .iter()
            .map(|column| column.iter().flat_map(|bits| *bits).collect())
            .collect();

        self.blocks = Some(flat);
    }

    pub fn set_normalized_blocks(&mut self, normalized_blocks: Vec<Vec<[u32; 8]>>) {
        self.normalized_blocks = Some(normalized_blocks);
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
        witness.set_codewords(vec![1, 2], vec![1, 2]);
        witness.set_polynomial_results(vec![PolynomialResult {
            result: 0,
            result_quotient: 0,
            should_be_zero: true,
        }]);

        // Verify successful finalization
        let finalized = witness
            .finalize()
            .expect("Should finalize with all fields set");
        assert_eq!(finalized.row_count, 30);
    }
}
