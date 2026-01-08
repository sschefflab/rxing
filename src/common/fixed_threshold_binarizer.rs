/*
 * Fixed Threshold Binarizer
 *
 * A simple, deterministic binarizer that uses a fixed threshold value.
 * Pixels with luminance < threshold are considered black (true).
 * Pixels with luminance >= threshold are considered white (false).
 *
 */

use std::borrow::Cow;

use once_cell::sync::OnceCell;

use crate::common::Result;
use crate::{Binarizer, LuminanceSource};

use super::{BitArray, BitMatrix, LineOrientation};

const DEFAULT_THRESHOLD: u8 = 128;

/**
 * A simple binarizer that uses a fixed threshold value.
 * Any pixel with luminance below the threshold is considered black,
 * and any pixel at or above the threshold is considered white.
 *
 * Default threshold is 128 (midpoint of 0-255 range).
 */
pub struct FixedThresholdBinarizer<LS: LuminanceSource> {
    source: LS,
    threshold: u8,
    width: usize,
    height: usize,
    black_matrix: OnceCell<BitMatrix>,
    black_row_cache: Vec<OnceCell<BitArray>>,
    black_column_cache: Vec<OnceCell<BitArray>>,
}

impl<LS: LuminanceSource> FixedThresholdBinarizer<LS> {
    /**
     * Creates a new FixedThresholdBinarizer with default threshold of 128.
     */
    pub fn new(source: LS) -> Self {
        Self::with_threshold(source, DEFAULT_THRESHOLD)
    }

    /**
     * Creates a new FixedThresholdBinarizer with a custom threshold value.
     *
     * @param source The luminance source
     * @param threshold The threshold value (0-255). Pixels < threshold become black.
     */
    pub fn with_threshold(source: LS, threshold: u8) -> Self {
        let width = source.get_width();
        let height = source.get_height();

        Self {
            width,
            height,
            black_row_cache: vec![OnceCell::default(); height],
            black_column_cache: vec![OnceCell::default(); width],
            source,
            threshold,
            black_matrix: OnceCell::new(),
        }
    }

    /**
     * Get the threshold value used by this binarizer.
     */
    pub fn get_threshold(&self) -> u8 {
        self.threshold
    }
}

impl<LS: LuminanceSource> Binarizer for FixedThresholdBinarizer<LS> {
    type Source = LS;

    fn get_luminance_source(&self) -> &Self::Source {
        &self.source
    }

    fn get_black_row(&self, y: usize) -> Result<Cow<'_, BitArray>> {
        let row = self.black_row_cache[y].get_or_try_init(|| {
            let source = self.get_luminance_source();
            let width = source.get_width();
            let mut row = BitArray::with_size(width);

            let luminances = source
                .get_row(y)
                .ok_or_else(|| crate::Exceptions::index_out_of_bounds_with("row out of bounds"))?;

            for (x, &luminance) in luminances.iter().enumerate().take(width) {
                if luminance < self.threshold {
                    row.set(x);
                }
            }

            Ok(row)
        })?;

        Ok(Cow::Borrowed(row))
    }

    fn get_black_line(&self, l: usize, lt: LineOrientation) -> Result<Cow<'_, BitArray>> {
        if lt == LineOrientation::Row {
            self.get_black_row(l)
        } else {
            let col = self.black_column_cache[l].get_or_try_init(|| {
                let source = self.get_luminance_source();
                let height = source.get_height();
                let mut col = BitArray::with_size(height);

                let luminances = source.get_column(l);

                for (y, &luminance) in luminances.iter().enumerate().take(height) {
                    if luminance < self.threshold {
                        col.set(y);
                    }
                }

                Ok(col)
            })?;

            Ok(Cow::Borrowed(col))
        }
    }

    fn get_black_matrix(&self) -> Result<&BitMatrix> {
        let matrix = self.black_matrix.get_or_try_init(|| {
            let source = self.get_luminance_source();
            let width = source.get_width();
            let height = source.get_height();
            let mut matrix = BitMatrix::new(width as u32, height as u32)?;

            let luminances = source.get_matrix();

            for y in 0..height {
                for x in 0..width {
                    let index = y * width + x;
                    if luminances[index] < self.threshold {
                        matrix.set(x as u32, y as u32);
                    }
                }
            }

            Ok(matrix)
        })?;

        Ok(matrix)
    }

    fn get_black_row_from_matrix(&self, y: usize) -> Result<Cow<'_, BitArray>> {
        if let Some(matrix) = self.black_matrix.get() {
            Ok(Cow::Owned(matrix.getRow(y as u32)))
        } else {
            self.get_black_row(y)
        }
    }

    fn create_binarizer(&self, source: Self::Source) -> Self
    where
        Self: Sized,
    {
        Self::with_threshold(source, self.threshold)
    }

    fn get_width(&self) -> usize {
        self.width
    }

    fn get_height(&self) -> usize {
        self.height
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Luma8LuminanceSource;

    #[test]
    fn test_fixed_threshold_128() {
        // Create a simple 4x4 test image
        let luma = vec![
            0, 64, 127, 128, // Row 0: black, black, black, white
            129, 192, 200, 255, // Row 1: all white
            50, 100, 150, 200, // Row 2: black, black, white, white
            127, 128, 129, 130, // Row 3: black, white, white, white
        ];
        let source = Luma8LuminanceSource::new(luma, 4, 4);
        let binarizer = FixedThresholdBinarizer::new(source);

        let matrix = binarizer.get_black_matrix().unwrap();

        // Check row 0: 0, 64, 127 should be black (true), 128 should be white (false)
        assert_eq!(matrix.get(0, 0), true); // 0 < 128
        assert_eq!(matrix.get(1, 0), true); // 64 < 128
        assert_eq!(matrix.get(2, 0), true); // 127 < 128
        assert_eq!(matrix.get(3, 0), false); // 128 >= 128

        // Check row 1: all white
        assert_eq!(matrix.get(0, 1), false); // 129 >= 128
        assert_eq!(matrix.get(1, 1), false); // 192 >= 128
        assert_eq!(matrix.get(2, 1), false); // 200 >= 128
        assert_eq!(matrix.get(3, 1), false); // 255 >= 128

        // Check row 2: mixed
        assert_eq!(matrix.get(0, 2), true); // 50 < 128
        assert_eq!(matrix.get(1, 2), true); // 100 < 128
        assert_eq!(matrix.get(2, 2), false); // 150 >= 128
        assert_eq!(matrix.get(3, 2), false); // 200 >= 128

        // Check row 3: boundary cases
        assert_eq!(matrix.get(0, 3), true); // 127 < 128
        assert_eq!(matrix.get(1, 3), false); // 128 >= 128
        assert_eq!(matrix.get(2, 3), false); // 129 >= 128
        assert_eq!(matrix.get(3, 3), false); // 130 >= 128
    }

    #[test]
    fn test_custom_threshold() {
        let luma = vec![0, 50, 100, 150];
        let source = Luma8LuminanceSource::new(luma, 4, 1);
        let binarizer = FixedThresholdBinarizer::with_threshold(source, 100);

        assert_eq!(binarizer.get_threshold(), 100);

        let matrix = binarizer.get_black_matrix().unwrap();

        assert_eq!(matrix.get(0, 0), true); // 0 < 100
        assert_eq!(matrix.get(1, 0), true); // 50 < 100
        assert_eq!(matrix.get(2, 0), false); // 100 >= 100
        assert_eq!(matrix.get(3, 0), false); // 150 >= 100
    }

    #[test]
    fn test_get_black_row() {
        let luma = vec![0, 127, 128, 255, 50, 100, 150, 200];
        let source = Luma8LuminanceSource::new(luma, 4, 2);
        let binarizer = FixedThresholdBinarizer::new(source);

        let row0 = binarizer.get_black_row(0).unwrap();
        assert_eq!(row0.get(0), true); // 0 < 128
        assert_eq!(row0.get(1), true); // 127 < 128
        assert_eq!(row0.get(2), false); // 128 >= 128
        assert_eq!(row0.get(3), false); // 255 >= 128

        let row1 = binarizer.get_black_row(1).unwrap();
        assert_eq!(row1.get(0), true); // 50 < 128
        assert_eq!(row1.get(1), true); // 100 < 128
        assert_eq!(row1.get(2), false); // 150 >= 128
        assert_eq!(row1.get(3), false); // 200 >= 128
    }
}
