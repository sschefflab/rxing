/*
 * WitnessData: mutable accumulator built up during PDF417 decoding.
 */

use crate::common::BitMatrix;
use super::types::{PolynomialResult, RowIndicatorVars, TableState};
use ark_bls12_381::Fr;
use super::finalized::FinalizedWitnessData;

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
    pub fn finalize(&self) -> Result<FinalizedWitnessData<Fr>, String> {
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
        use super::super::types::{PolynomialResult, RowIndicatorVars};

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
