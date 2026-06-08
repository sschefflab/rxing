/*
 * WitnessData: mutable accumulator built up during PDF417 decoding.
 */

use super::finalized::FinalizedWitnessData;
use super::mode_config::ImageParams;
use super::types::{BarcodeStats, PolynomialResult, RowIndicatorVars, TableState};
use crate::common::BitMatrix;
use ark_ed25519::Fr;

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
    /// Image configuration parameters driving all derived constants.
    pub image_params: ImageParams,

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
    pub bin_image: Option<BitMatrix>,

    pub wb_image: Option<BitMatrix>,
    pub wb_inds: Option<Vec<u32>>,
    /// Logical row number for each wb_image row from the left row indicator.
    /// -1 if the row is a fill (not well-behaved) or the left indicator fails to decode.
    pub ext_row_num: Option<Vec<i32>>,
    pub garbage_image: Option<BitMatrix>,
    pub garbage_inds: Option<Vec<i32>>,

    /// Barcode metadata values: how many rows and columns it has, and its error correction level
    pub stats: Option<BarcodeStats>,

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

    /// Bounding box of the detected barcode in the full image: (min_x, max_x, min_y, max_y).
    pub barcode_bbox: Option<(u32, u32, u32, u32)>,
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
    pub fn new(
        width: usize,
        height: usize,
        image: Vec<Vec<u8>>,
        image_params: ImageParams,
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

        Self {
            image_params,
            width,
            height,
            image,
            bin_image: None,
            wb_image: None,
            wb_inds: None,
            ext_row_num: None,
            garbage_image: None,
            garbage_inds: None,
            stats: None,
            row_indicators: None,
            all_left_row_indicators: None,
            codewords: None,
            corrected_codewords: None,
            polynomial_results: None,
            char_table_states: None,
            chars: None,
            barcode_bbox: None,
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
    pub fn bin_image(&self) -> &Option<BitMatrix> {
        &self.bin_image
    }

    pub fn set_bin_image(&mut self, bin_image: BitMatrix) {
        self.bin_image = Some(bin_image)
    }

    pub fn set_barcode_bbox(&mut self, min_x: u32, max_x: u32, min_y: u32, max_y: u32) {
        self.barcode_bbox = Some((min_x, max_x, min_y, max_y));
    }

    pub fn set_barcode_stats(&mut self, row_count: u8, column_count: u8, ec_level: u8) {
        let num_ec_codewords = 2u16.pow((ec_level + 1) as u32);
        let stats: BarcodeStats = BarcodeStats {
            num_rows: row_count,
            num_cols: column_count,
            ec_level,
            num_ec_codewords,
        };
        self.stats = Some(stats);
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
        match &self.bin_image {
            Some(bin_image) => Some(bin_image.get(x as u32, y as u32)),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::mode_config::ImageMode;
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

        let mut witness = WitnessData::new(4, 4, image.clone(), ImageMode::Hd.image_params());
        witness.set_bin_image(binarized);

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
        let _witness = WitnessData::new(3, 4, image, ImageMode::Hd.image_params());
    }

    #[test]
    fn test_witness_finalization_flow() {
        use super::super::types::{PolynomialResult, RowIndicatorVars};

        let image = vec![vec![255; 2]; 2];
        let hd_params = ImageMode::Hd.image_params();
        let garbage_rows = hd_params.garbage_rows();
        let mut witness = WitnessData::new(2, 2, image, hd_params);

        // Test that finalization fails when fields are missing
        assert!(witness.finalize().is_err());

        // Populate required fields
        witness.set_bin_image(BitMatrix::new(2, 2).unwrap());
        witness.wb_image = Some(BitMatrix::new(2, 2).unwrap());
        witness.wb_inds = Some(vec![0, 1]);
        witness.ext_row_num = Some(vec![-1, -1]);
        witness.garbage_image = Some(BitMatrix::new(2, garbage_rows as u32).unwrap());
        witness.garbage_inds = Some(vec![-1; garbage_rows]);
        witness.set_barcode_stats(30, 10, 2);
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
        assert_eq!(finalized.stats.num_rows, 30);
    }
}
