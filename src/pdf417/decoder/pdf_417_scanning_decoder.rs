/*
 * Copyright 2013 ZXing authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::sync::Arc;

use crate::{
    Exceptions, Point, WitnessData,
    common::{BitMatrix, DecoderRXingResult, Result},
    pdf417::pdf_417_common,
};

use super::{
    BarcodeMetadata, BarcodeValue, BoundingBox, Codeword, DetectionRXingResult,
    DetectionRXingResultColumn, DetectionRXingResultColumnTrait,
    DetectionRXingResultRowIndicatorColumn, decoded_bit_stream_parser, ec,
    pdf_417_codeword_decoder,
};

/*
 * @author Guenther Grau
 */

const CODEWORD_SKEW_SIZE: u32 = 2;

const MAX_ERRORS: u32 = 3;
// const  errorCorrection:ErrorCorrection =  ErrorCorrection::new();

// TODO don't pass in minCodewordWidth and maxCodewordWidth, pass in barcode columns for start and stop pattern
// columns. That way width can be deducted from the pattern column.
// This approach also allows to detect more details about the barcode, e.g. if a bar type (white or black) is wider
// than it should be. This can happen if the scanner used a bad blackpoint.
pub fn decode(
    image: &BitMatrix,
    image_top_left: Option<Point>,
    imageBottomLeft: Option<Point>,
    image_top_right: Option<Point>,
    imageBottomRight: Option<Point>,
    barcode_top_left: Option<Point>,
    barcode_top_right: Option<Point>,
    minCodewordWidth: u32,
    maxCodewordWidth: u32,
    mut witness_data: Option<&mut WitnessData>,
) -> Result<DecoderRXingResult> {
    let mut minCodewordWidth = minCodewordWidth;
    let mut maxCodewordWidth = maxCodewordWidth;
    let mut boundingBox = BoundingBox::new(
        Arc::new(image.clone()),
        image_top_left,
        imageBottomLeft,
        image_top_right,
        imageBottomRight,
    )?;
    let mut leftRowIndicatorColumn = None;
    let mut rightRowIndicatorColumn = None;
    let mut detectionRXingResult = None;
    for firstPass in [true, false] {
        if let Some(image_top_left) = image_top_left {
            leftRowIndicatorColumn = Some(getRowIndicatorColumn(
                image,
                &boundingBox,
                image_top_left,
                true,
                minCodewordWidth,
                maxCodewordWidth,
            ));
        }
        if let Some(image_top_right) = image_top_right {
            rightRowIndicatorColumn = Some(getRowIndicatorColumn(
                image,
                &boundingBox,
                image_top_right,
                false,
                minCodewordWidth,
                maxCodewordWidth,
            ));
        }
        detectionRXingResult = merge(
            &mut leftRowIndicatorColumn,
            &mut rightRowIndicatorColumn,
            witness_data.as_deref_mut(),
        )?;
        if detectionRXingResult.is_none() {
            return Err(Exceptions::NOT_FOUND);
        }
        // detectionRXingResult = detectionRXingResult;

        let resultBox = detectionRXingResult.as_ref().unwrap().getBoundingBox();
        if firstPass
            && (resultBox.getMinY() < boundingBox.getMinY()
                || resultBox.getMaxY() > boundingBox.getMaxY())
        // if firstPass && resultBox.is_some() &&
        {
            boundingBox = resultBox.clone();
        } else {
            break;
        }
    }
    let mut detectionRXingResult = detectionRXingResult.unwrap();

    let leftToRight = leftRowIndicatorColumn.is_some();

    detectionRXingResult.setBoundingBox(boundingBox.clone());
    let maxBarcodeColumn = detectionRXingResult.getBarcodeColumnCount() + 1;
    detectionRXingResult.setDetectionRXingResultColumn(0, leftRowIndicatorColumn);
    detectionRXingResult.setDetectionRXingResultColumn(maxBarcodeColumn, rightRowIndicatorColumn);

    // let leftToRight = leftRowIndicatorColumn.is_some();
    for barcodeColumnCount in 1..=maxBarcodeColumn {
        // for (int barcodeColumnCount = 1; barcodeColumnCount <= maxBarcodeColumn; barcodeColumnCount++) {
        let barcodeColumn = if leftToRight {
            barcodeColumnCount
        } else {
            maxBarcodeColumn - barcodeColumnCount
        };
        if detectionRXingResult
            .getDetectionRXingResultColumn(barcodeColumn)
            .is_some()
        {
            // This will be the case for the opposite row indicator column, which doesn't need to be decoded again.
            continue;
        }
        let detectionRXingResultColumn = if barcodeColumn == 0 || barcodeColumn == maxBarcodeColumn
        {
            DetectionRXingResultColumn::new_with_is_left(&boundingBox, barcodeColumn == 0)
        } else {
            DetectionRXingResultColumn::new_column(&boundingBox)
        };

        detectionRXingResult
            .setDetectionRXingResultColumn(barcodeColumn, Some(detectionRXingResultColumn));

        let mut startColumn: i32 = -1;
        let mut previousStartColumn = startColumn;
        // TODO start at a row for which we know the start position, then detect upwards and downwards from there.
        for imageRow in boundingBox.getMinY()..=boundingBox.getMaxY() {
            // for (int imageRow = boundingBox.getMinY(); imageRow <= boundingBox.getMaxY(); imageRow++) {
            startColumn =
                getStartColumn(&detectionRXingResult, barcodeColumn, imageRow, leftToRight)
                    .ok_or(Exceptions::ILLEGAL_STATE)? as i32;
            if startColumn < 0 || startColumn > boundingBox.getMaxX() as i32 {
                if previousStartColumn == -1 {
                    continue;
                }
                startColumn = previousStartColumn;
            }
            if let Some(codeword) = detectCodeword(
                image,
                boundingBox.getMinX(),
                boundingBox.getMaxX(),
                leftToRight,
                startColumn as u32,
                imageRow,
                minCodewordWidth,
                maxCodewordWidth,
            ) {
                detectionRXingResult
                    .getDetectionRXingResultColumnMut(barcodeColumn)
                    .as_mut()
                    .unwrap()
                    .setCodeword(imageRow, codeword);
                previousStartColumn = startColumn;
                minCodewordWidth = minCodewordWidth.min(codeword.getWidth());
                maxCodewordWidth = maxCodewordWidth.max(codeword.getWidth());
            }
        }
    }

    // Write barcode metadata to witness data if provided
    if let Some(wd) = witness_data.as_deref_mut() {
        wd.set_barcode_stats(
            detectionRXingResult.getBarcodeRowCount() as u8,
            detectionRXingResult.getBarcodeColumnCount() as u8,
            detectionRXingResult.getBarcodeECLevel() as u8,
        );
    }

    // Classify pixel rows into well-behaved (all data columns decoded) and garbage.
    // wb_image is the same size as the original image; garbage rows within the bounding
    // box are replaced by the nearest well-behaved row above them (or the first
    // well-behaved row below if no good row precedes them). wb_inds[i] is the source row
    // used for bounding-box row (min_y + i). garbage_image is a compact image of only
    // the garbage pixel rows, unchanged.
    if witness_data.is_some() {
        let min_y = boundingBox.getMinY();
        let max_y = boundingBox.getMaxY();
        let barcode_col_count = detectionRXingResult.getBarcodeColumnCount();
        // Use outer barcode corners (including start/stop patterns) for x-crop,
        // falling back to the codeword-area bounding box if not available.
        let min_x = barcode_top_left
            .map(|p| p.x as u32)
            .unwrap_or_else(|| boundingBox.getMinX());
        let max_x = barcode_top_right
            .map(|p| p.x as u32)
            .unwrap_or_else(|| boundingBox.getMaxX());
        let image_width = max_x - min_x; // max_x is exclusive (one past last pixel of stop pattern)
        let num_rows = (max_y - min_y + 1) as usize;
        if let Some(wd) = witness_data.as_deref_mut() {
            wd.set_barcode_bbox(min_x, max_x, min_y, max_y);
        }

        // Determine which bounding-box rows are well-behaved
        let mut is_good = vec![false; num_rows];
        {
            let columns = detectionRXingResult.getDetectionRXingResultColumns();
            for image_row in min_y..=max_y {
                let codeword_idx = (image_row - min_y) as usize;
                is_good[codeword_idx] = (1..=barcode_col_count).all(|col| {
                    columns[col]
                        .as_ref()
                        .map_or(false, |c| c.getCodewords()[codeword_idx].is_some())
                    // this codewords array contains one row for every pixel row, not logical barcode row
                });
            }
        }

        // Forward pass: map each row to itself if good, or to the last good row above
        let mut wb_inds_opt: Vec<Option<u32>> = Vec::with_capacity(num_rows);
        let mut last_good: Option<u32> = None;
        for i in 0..num_rows {
            let image_row = min_y + i as u32;
            if is_good[i] {
                last_good = Some(image_row);
            }
            wb_inds_opt.push(last_good);
        }

        // For leading garbage rows (no good row above), use the first good row below
        let first_good = wb_inds_opt.iter().find_map(|&x| x);
        let wb_inds: Vec<u32> = wb_inds_opt
            .iter()
            .enumerate()
            .map(|(i, &opt)| opt.or(first_good).unwrap_or(min_y + i as u32))
            .collect();

        let mut garbage_inds: Vec<i32> = (0..num_rows)
            .filter(|&i| !is_good[i])
            .map(|i| (min_y + i as u32) as i32)
            .collect();

        // wb_image: only bounding-box rows and columns, sourced from wb_inds
        let mut wb_bm = BitMatrix::new(image_width, num_rows as u32).unwrap();
        for (dest_row, &src_row) in wb_inds.iter().enumerate() {
            let full_row = image.getRow(src_row);
            for x in min_x..max_x {
                if full_row.get(x as usize) {
                    wb_bm.set(x - min_x, dest_row as u32);
                }
            }
        }

        // garbage_image: exactly garbage_rows rows. Non-good bounding-box rows only,
        // remainder padded with zero rows. garbage_inds uses -1 for padded rows.
        let garbage_rows = witness_data
            .as_deref()
            .map_or(89usize, |wd| wd.image_params.garbage_rows());

        assert!(
            garbage_inds.len() <= garbage_rows,
            "Too many garbage rows: {} (max {})",
            garbage_inds.len(),
            garbage_rows
        );
        let mut garbage_bm = BitMatrix::new(image_width, garbage_rows as u32).unwrap();
        for (dest_row, &src_row) in garbage_inds.iter().enumerate() {
            let full_row = image.getRow(src_row as u32);
            for x in min_x..max_x {
                if full_row.get(x as usize) {
                    garbage_bm.set(x - min_x, dest_row as u32);
                }
            }
        }
        // Pad garbage_inds with -1s to reach exactly garbage_rows
        garbage_inds.resize(garbage_rows, -1);

        if let Some(wd) = witness_data.as_deref_mut() {
            // Crop bin_image to the bounding box so it matches wb_image/garbage_image dimensions.
            if let Some(bin) = wd.bin_image.take() {
                let bb_height = (max_y - min_y + 1) as u32;
                let mut cropped = BitMatrix::new(image_width, bb_height).unwrap();
                for y in min_y..=max_y {
                    let full_row = bin.getRow(y);
                    for x in min_x..max_x {
                        if full_row.get(x as usize) {
                            cropped.set(x - min_x, y - min_y);
                        }
                    }
                }
                wd.bin_image = Some(cropped);
            }
            wd.wb_image = Some(wb_bm);
            wd.wb_inds = Some(wb_inds);
            wd.garbage_image = Some(garbage_bm);
            wd.garbage_inds = Some(garbage_inds);
        }
    }

    createDecoderRXingResult(&mut detectionRXingResult, witness_data)
}

fn merge<'a, T: DetectionRXingResultRowIndicatorColumn>(
    leftRowIndicatorColumn: &'a mut Option<T>,
    rightRowIndicatorColumn: &'a mut Option<T>,
    witness_data: Option<&mut WitnessData>,
) -> Result<Option<DetectionRXingResult>> {
    if leftRowIndicatorColumn.is_none() && rightRowIndicatorColumn.is_none() {
        return Ok(None);
    }
    let barcodeMetadata = getBarcodeMetadata(
        leftRowIndicatorColumn,
        rightRowIndicatorColumn,
        witness_data,
    );
    if barcodeMetadata.is_none() {
        return Ok(None);
    }
    let boundingBox = BoundingBox::merge(
        adjustBoundingBox(leftRowIndicatorColumn)?,
        adjustBoundingBox(rightRowIndicatorColumn)?,
    )?;

    Ok(Some(DetectionRXingResult::new(
        barcodeMetadata.unwrap(),
        boundingBox,
    )))
}

fn adjustBoundingBox<T: DetectionRXingResultRowIndicatorColumn>(
    rowIndicatorColumn: &mut Option<T>,
) -> Result<Option<BoundingBox>> {
    if rowIndicatorColumn.is_none() {
        return Ok(None);
    }
    let rowIndicatorColumn = rowIndicatorColumn.as_mut().unwrap();

    let rowHeights = rowIndicatorColumn.getRowHeights();
    if rowHeights.is_none() {
        return Ok(None);
    }
    let rowHeights = rowHeights.unwrap();
    let maxRowHeight = getMax(&rowHeights);
    let mut missingStartRows = 0;
    for rowHeight in &rowHeights {
        // for (int rowHeight : rowHeights) {
        missingStartRows += maxRowHeight - rowHeight;
        if *rowHeight > 0 {
            break;
        }
    }
    let codewords = rowIndicatorColumn.getCodewords();

    let mut row = 0;
    while missingStartRows > 0 && codewords[row].is_none() {
        // for (int row = 0; missingStartRows > 0 && codewords[row] == null; row++) {
        missingStartRows -= 1;
        row += 1;
    }
    let mut missingEndRows = 0;
    for row in (0..rowHeights.len()).rev() {
        // for (int row = rowHeights.length - 1; row >= 0; row--) {
        missingEndRows += maxRowHeight - rowHeights[row];
        if rowHeights[row] > 0 {
            break;
        }
    }
    let mut row = codewords.len() - 1;
    while missingEndRows > 0 && codewords[row].is_none() {
        // for (int row = codewords.length - 1; missingEndRows > 0 && codewords[row] == null; row--) {
        missingEndRows -= 1;

        row -= 1;
    }
    Ok(Some(rowIndicatorColumn.getBoundingBox().addMissingRows(
        missingStartRows,
        missingEndRows,
        rowIndicatorColumn.isLeft(),
    )?))
}

fn getMax(values: &[u32]) -> u32 {
    // let maxValue = -1;
    // for (int value : values) {
    //   maxValue = Math.max(maxValue, value);
    // }
    // return maxValue;
    *values.iter().max().unwrap()
}

fn getBarcodeMetadata<T: DetectionRXingResultRowIndicatorColumn>(
    leftRowIndicatorColumn: &mut Option<T>,
    rightRowIndicatorColumn: &mut Option<T>,
    witness_data: Option<&mut WitnessData>,
) -> Option<BarcodeMetadata> {
    let left_ri_md = leftRowIndicatorColumn
        .as_mut()
        .map_or_else(|| None, |col| col.getBarcodeMetadata(witness_data));
    let right_ri_md = rightRowIndicatorColumn
        .as_mut()
        .map_or_else(|| None, |col| col.getBarcodeMetadata(None));

    if leftRowIndicatorColumn.is_none() && rightRowIndicatorColumn.is_none() {
        return None;
    } else if leftRowIndicatorColumn.is_none() {
        return right_ri_md;
    } else if rightRowIndicatorColumn.is_none() && right_ri_md.is_none() {
        return left_ri_md;
    } else if let Some((leftBarcodeMetadata, rightBarcodeMetadata)) =
        left_ri_md.as_ref().zip(right_ri_md.as_ref())
    {
        if leftBarcodeMetadata.getColumnCount() != rightBarcodeMetadata.getColumnCount()
            && leftBarcodeMetadata.getErrorCorrectionLevel()
                != rightBarcodeMetadata.getErrorCorrectionLevel()
            && leftBarcodeMetadata.getRowCount() != rightBarcodeMetadata.getRowCount()
        {
            return None;
        }
    }

    left_ri_md
}

fn getRowIndicatorColumn<'a>(
    image: &BitMatrix,
    boundingBox: &BoundingBox,
    startPoint: Point,
    leftToRight: bool,
    minCodewordWidth: u32,
    maxCodewordWidth: u32,
) -> impl DetectionRXingResultRowIndicatorColumn + 'a {
    let mut rowIndicatorColumn =
        DetectionRXingResultColumn::new_with_is_left(boundingBox, leftToRight);
    for i in 0..2 {
        // for (int i = 0; i < 2; i++) {
        let increment: i32 = if i == 0 { 1 } else { -1 };
        let mut startColumn: u32 = startPoint.x as u32;
        let mut imageRow: i32 = startPoint.y as i32;
        while imageRow <= boundingBox.getMaxY() as i32 && imageRow >= boundingBox.getMinY() as i32 {
            // for (int imageRow = (int) startPoint.getY(); imageRow <= boundingBox.getMaxY() &&
            //     imageRow >= boundingBox.getMinY(); imageRow += increment) {
            if let Some(codeword) = detectCodeword(
                image,
                0,
                image.getWidth(),
                leftToRight,
                startColumn,
                imageRow as u32,
                minCodewordWidth,
                maxCodewordWidth,
            ) {
                // if codeword.is_some() {
                rowIndicatorColumn.setCodeword(imageRow as u32, codeword);
                if leftToRight {
                    startColumn = codeword.getStartX();
                } else {
                    startColumn = codeword.getEndX();
                }
            }

            imageRow += increment;
        }
    }

    rowIndicatorColumn
}

fn adjustCodewordCount(
    detectionRXingResult: &DetectionRXingResult,
    barcodeMatrix: &mut [Vec<BarcodeValue>],
) -> Result<()> {
    let barcodeMatrix01 = &mut barcodeMatrix[0][1];
    let numberOfCodewords = barcodeMatrix01.getValue();
    let calculatedNumberOfCodewords = (detectionRXingResult.getBarcodeColumnCount() as isize
        * detectionRXingResult.getBarcodeRowCount() as isize
        - getNumberOfECCodeWords(detectionRXingResult.getBarcodeECLevel()) as isize)
        as u32;
    if numberOfCodewords.is_empty() {
        if !(1..=pdf_417_common::MAX_CODEWORDS_IN_BARCODE).contains(&calculatedNumberOfCodewords) {
            return Err(Exceptions::NOT_FOUND);
        }
        barcodeMatrix01.setValue(calculatedNumberOfCodewords);
    } else if numberOfCodewords[0] != calculatedNumberOfCodewords
        && (1..=pdf_417_common::MAX_CODEWORDS_IN_BARCODE).contains(&calculatedNumberOfCodewords)
    {
        // The calculated one is more reliable as it is derived from the row indicator columns
        barcodeMatrix01.setValue(calculatedNumberOfCodewords);
    }
    Ok(())
}

fn createDecoderRXingResult(
    detectionRXingResult: &mut DetectionRXingResult,
    witness_data: Option<&mut WitnessData>,
) -> Result<DecoderRXingResult> {
    let mut barcodeMatrix = createBarcodeMatrix(detectionRXingResult);
    adjustCodewordCount(detectionRXingResult, &mut barcodeMatrix)?;
    let mut erasures = Vec::new();
    let mut codewords = vec![
        0;
        detectionRXingResult.getBarcodeRowCount() as usize
            * detectionRXingResult.getBarcodeColumnCount()
    ];
    let mut ambiguousIndexValuesList: Vec<Vec<u32>> = Vec::new();
    let mut ambiguousIndexesList = Vec::new();
    for row in 0..detectionRXingResult.getBarcodeRowCount() {
        for column in 0..detectionRXingResult.getBarcodeColumnCount() {
            let values = barcodeMatrix[row as usize][column + 1].getValue();
            let codewordIndex =
                row as usize * detectionRXingResult.getBarcodeColumnCount() + column;
            if values.is_empty() {
                erasures.push(codewordIndex as u32);
            } else if values.len() == 1 {
                codewords[codewordIndex] = values[0];
            } else {
                ambiguousIndexesList.push(codewordIndex as u32);
                ambiguousIndexValuesList.push(values);
            }
        }
    }
    let ambiguousIndexValues = Vec::from_iter(ambiguousIndexValuesList);
    // for value in ambiguousIndexValuesList {
    //     ambiguousIndexValues.push(value);
    // }
    // for i in 0..ambiguousIndexValuesList.len() {
    // // for (int i = 0; i < ambiguousIndexValues.length; i++) {
    //   ambiguousIndexValues[i] = ambiguousIndexValuesList.get(i) as u32;
    // }
    createDecoderRXingResultFromAmbiguousValues(
        detectionRXingResult.getBarcodeECLevel(),
        &mut codewords,
        &mut erasures,
        &mut ambiguousIndexesList,
        &ambiguousIndexValues,
        witness_data,
    )
}

/**
 * This method deals with the fact, that the decoding process doesn't always yield a single most likely value. The
 * current error correction implementation doesn't deal with erasures very well, so it's better to provide a value
 * for these ambiguous codewords instead of treating it as an erasure. The problem is that we don't know which of
 * the ambiguous values to choose. We try decode using the first value, and if that fails, we use another of the
 * ambiguous values and try to decode again. This usually only happens on very hard to read and decode barcodes,
 * so decoding the normal barcodes is not affected by this.
 *
 * @param erasureArray contains the indexes of erasures
 * @param ambiguousIndexes array with the indexes that have more than one most likely value
 * @param ambiguousIndexValues two dimensional array that contains the ambiguous values. The first dimension must
 * be the same length as the ambiguousIndexes array
 */
fn createDecoderRXingResultFromAmbiguousValues(
    ecLevel: u32,
    codewords: &mut [u32],
    erasureArray: &mut [u32],
    ambiguousIndexes: &mut [u32],
    ambiguousIndexValues: &[Vec<u32>],
    mut witness_data: Option<&mut WitnessData>,
) -> Result<DecoderRXingResult> {
    let mut ambiguousIndexCount = vec![0; ambiguousIndexes.len()];

    let mut tries = 100;
    while tries > 0 {
        for i in 0..ambiguousIndexCount.len() {
            codewords[ambiguousIndexes[i] as usize] =
                ambiguousIndexValues[i][ambiguousIndexCount[i]];
        }
        let pre_correction_codewords: Vec<u32> = codewords.to_vec();
        let attempted_decode = decodeCodewords(
            codewords,
            ecLevel,
            erasureArray,
            witness_data.as_deref_mut(),
        );
        if attempted_decode.is_ok() {
            if let Some(wd) = witness_data.as_deref_mut() {
                wd.set_codewords(pre_correction_codewords, codewords.to_vec());
                let table_states = decoded_bit_stream_parser::collect_table_states(codewords);
                wd.set_char_table_states(table_states);
            }
            return attempted_decode;
        }
        if ambiguousIndexCount.is_empty() {
            return Err(Exceptions::CHECKSUM);
        }
        for i in 0..ambiguousIndexCount.len() {
            if ambiguousIndexCount[i] < ambiguousIndexValues[i].len() - 1 {
                ambiguousIndexCount[i] += 1;
                break;
            } else {
                ambiguousIndexCount[i] = 0;
                if i == ambiguousIndexCount.len() - 1 {
                    return Err(Exceptions::CHECKSUM);
                }
            }
        }

        tries -= 1;
    }
    Err(Exceptions::CHECKSUM)
}

fn createBarcodeMatrix(detectionRXingResult: &mut DetectionRXingResult) -> Vec<Vec<BarcodeValue>> {
    let mut barcodeMatrix =
        vec![
            vec![BarcodeValue::new(); detectionRXingResult.getBarcodeColumnCount() + 2];
            detectionRXingResult.getBarcodeRowCount() as usize
        ];
    // BarcodeValue[][] barcodeMatrix =
    //     new BarcodeValue[detectionRXingResult.getBarcodeRowCount()][detectionRXingResult.getBarcodeColumnCount() + 2];
    // for row in 0..barcodeMatrix.len() {
    // // for (int row = 0; row < barcodeMatrix.length; row++) {
    //   for column in 0..barcodeMatrix[row].len() {
    //   // for (int column = 0; column < barcodeMatrix[row].length; column++) {
    //     barcodeMatrix[row][column] =  BarcodeValue::new();
    //   }
    // }

    let mut column = 0;
    for detectionRXingResultColumn in detectionRXingResult.getDetectionRXingResultColumns() {
        // for (DetectionRXingResultColumn detectionRXingResultColumn : detectionRXingResult.getDetectionRXingResultColumns()) {
        if detectionRXingResultColumn.is_some() {
            for codeword in detectionRXingResultColumn
                .as_ref()
                .unwrap()
                .getCodewords()
                .iter()
                .flatten()
            {
                // for (Codeword codeword : detectionRXingResultColumn.getCodewords()) {
                // if let Some(codeword) = codeword {
                // if codeword.is_some() {
                let rowNumber = codeword.getRowNumber();
                if rowNumber >= 0 {
                    if rowNumber as usize >= barcodeMatrix.len() {
                        // We have more rows than the barcode metadata allows for, ignore them.
                        continue;
                    }
                    barcodeMatrix[rowNumber as usize][column].setValue(codeword.getValue());
                }
                // }
            }
        }
        column += 1;
    }
    barcodeMatrix
}

fn isValidBarcodeColumn(detectionRXingResult: &DetectionRXingResult, barcodeColumn: usize) -> bool {
    /*barcodeColumn >= 0 &&*/
    barcodeColumn <= detectionRXingResult.getBarcodeColumnCount() + 1
}

fn getStartColumn(
    detectionRXingResult: &DetectionRXingResult,
    barcodeColumn: usize,
    imageRow: u32,
    leftToRight: bool,
) -> Option<u32> {
    let offset: isize = if leftToRight { 1 } else { -1 };
    let mut barcodeColumn = barcodeColumn as isize;
    let mut codeword = &None;
    if isValidBarcodeColumn(detectionRXingResult, (barcodeColumn - offset) as usize) {
        codeword = detectionRXingResult
            .getDetectionRXingResultColumn((barcodeColumn - offset) as usize)
            .as_ref()?
            .getCodeword(imageRow);
    }
    if let Some(codeword) = codeword {
        return if leftToRight {
            Some(codeword.getEndX())
        } else {
            Some(codeword.getStartX())
        };
    }

    if detectionRXingResult
        .getDetectionRXingResultColumn(barcodeColumn as usize)
        .is_some()
    {
        codeword = detectionRXingResult
            .getDetectionRXingResultColumn(barcodeColumn as usize)
            .as_ref()?
            .getCodewordNearby(imageRow);
    }

    if let Some(codeword) = codeword {
        return if leftToRight {
            Some(codeword.getStartX())
        } else {
            Some(codeword.getEndX())
        };
    }
    if isValidBarcodeColumn(detectionRXingResult, (barcodeColumn - offset) as usize) {
        codeword = detectionRXingResult
            .getDetectionRXingResultColumn((barcodeColumn - offset) as usize)
            .as_ref()?
            .getCodewordNearby(imageRow);
    }
    if let Some(codeword) = codeword {
        return if leftToRight {
            Some(codeword.getEndX())
        } else {
            Some(codeword.getStartX())
        };
    }
    let mut skippedColumns = 0;

    while isValidBarcodeColumn(detectionRXingResult, (barcodeColumn - offset) as usize) {
        barcodeColumn -= offset;
        if let Some(previousRowCodeword) = detectionRXingResult
            .getDetectionRXingResultColumn(barcodeColumn as usize)
            .as_ref()?
            .getCodewords()
            .iter()
            .flatten()
            .next()
        {
            // for (Codeword previousRowCodeword : detectionRXingResult.getDetectionRXingResultColumn(barcodeColumn).getCodewords()) {
            // if let Some(previousRowCodeword) = previousRowCodeword {
            // if previousRowCodeword.is_some() {
            return Some(
                ((if leftToRight {
                    previousRowCodeword.getEndX()
                } else {
                    previousRowCodeword.getStartX()
                }) as isize
                    + offset
                        * skippedColumns as isize
                        * (previousRowCodeword.getEndX() - previousRowCodeword.getStartX())
                            as isize) as u32,
            );
            // }
        }
        skippedColumns += 1;
    }
    if leftToRight {
        Some(detectionRXingResult.getBoundingBox().getMinX())
    } else {
        Some(detectionRXingResult.getBoundingBox().getMaxX())
    }
}

fn detectCodeword(
    image: &BitMatrix,
    minColumn: u32,
    maxColumn: u32,
    leftToRight: bool,
    startColumn: u32,
    imageRow: u32,
    minCodewordWidth: u32,
    maxCodewordWidth: u32,
) -> Option<Codeword> {
    let mut startColumn = adjustCodewordStartColumn(
        image,
        minColumn,
        maxColumn,
        leftToRight,
        startColumn,
        imageRow,
    );
    // we usually know fairly exact now how long a codeword is. We should provide minimum and maximum expected length
    // and try to adjust the read pixels, e.g. remove single pixel errors or try to cut off exceeding pixels.
    // min and maxCodewordWidth should not be used as they are calculated for the whole barcode an can be inaccurate
    // for the current position
    let mut moduleBitCount = getModuleBitCount(
        image,
        minColumn,
        maxColumn,
        leftToRight,
        startColumn,
        imageRow,
    )?;

    let endColumn;
    let codewordBitCount = moduleBitCount.iter().sum::<u32>();
    if leftToRight {
        endColumn = startColumn + codewordBitCount;
    } else {
        for i in 0..(moduleBitCount.len() / 2) {
            // for (int i = 0; i < moduleBitCount.length / 2; i++) {

            let len = moduleBitCount.len();
            moduleBitCount.swap(i, len - 1 - i);

            // let tmpCount = moduleBitCount[i];
            // moduleBitCount[i] = moduleBitCount[moduleBitCount.len() - 1 - i];
            // moduleBitCount[moduleBitCount.len() - 1 - i] = tmpCount;
        }
        endColumn = startColumn;
        startColumn = endColumn - codewordBitCount;
    }
    // TODO implement check for width and correction of black and white bars
    // use start (and maybe stop pattern) to determine if black bars are wider than white bars. If so, adjust.
    // should probably done only for codewords with a lot more than 17 bits.
    // The following fixes 10-1.png, which has wide black bars and small white bars
    //    for (int i = 0; i < moduleBitCount.length; i++) {
    //      if (i % 2 == 0) {
    //        moduleBitCount[i]--;
    //      } else {
    //        moduleBitCount[i]++;
    //      }
    //    }

    // We could also use the width of surrounding codewords for more accurate results, but this seems
    // sufficient for now
    if !checkCodewordSkew(codewordBitCount, minCodewordWidth, maxCodewordWidth) {
        // We could try to use the startX and endX position of the codeword in the same column in the previous row,
        // create the bit count from it and normalize it to 8. This would help with single pixel errors.
        return None;
    }

    let decodedValue = pdf_417_codeword_decoder::getDecodedValue(&moduleBitCount);
    let codeword = pdf_417_common::getCodeword(decodedValue);
    if codeword == -1 {
        return None;
    }

    Some(Codeword::new(
        startColumn,
        endColumn,
        getCodewordBucketNumber(decodedValue),
        codeword as u32,
    ))
}

fn getModuleBitCount(
    image: &BitMatrix,
    minColumn: u32,
    maxColumn: u32,
    leftToRight: bool,
    startColumn: u32,
    imageRow: u32,
) -> Option<[u32; 8]> {
    let mut imageColumn = startColumn as i32;
    let mut moduleBitCount = [0_u32; 8];
    let mut moduleNumber = 0;
    let increment: i32 = if leftToRight { 1 } else { -1 };
    let mut previousPixelValue = leftToRight;
    while (if leftToRight {
        imageColumn < maxColumn as i32
    } else {
        imageColumn >= minColumn as i32
    }) && moduleNumber < moduleBitCount.len()
    {
        if image.get(imageColumn as u32, imageRow) == previousPixelValue {
            moduleBitCount[moduleNumber] += 1;
            imageColumn += increment;
        } else {
            moduleNumber += 1;
            previousPixelValue = !previousPixelValue;
        }
    }
    if moduleNumber == moduleBitCount.len()
        || ((imageColumn
            == (if leftToRight {
                maxColumn as i32
            } else {
                minColumn as i32
            }))
            && moduleNumber == moduleBitCount.len() - 1)
    {
        return Some(moduleBitCount);
    }

    None
}

fn getNumberOfECCodeWords(barcodeECLevel: u32) -> u32 {
    2 << barcodeECLevel
}

fn adjustCodewordStartColumn(
    image: &BitMatrix,
    minColumn: u32,
    maxColumn: u32,
    leftToRight: bool,
    codewordStartColumn: u32,
    imageRow: u32,
) -> u32 {
    let mut correctedStartColumn = codewordStartColumn;
    let mut increment: i32 = if leftToRight { -1 } else { 1 };
    let mut leftToRight = leftToRight;
    // there should be no black pixels before the start column. If there are, then we need to start earlier.
    for _i in 0..2 {
        while (if leftToRight {
            correctedStartColumn >= minColumn
        } else {
            correctedStartColumn < maxColumn
        }) && leftToRight == image.get(correctedStartColumn, imageRow)
        {
            if (codewordStartColumn as i64 - correctedStartColumn as i64).unsigned_abs() as u32
                > CODEWORD_SKEW_SIZE
            {
                return codewordStartColumn;
            }
            correctedStartColumn = (correctedStartColumn as i32 + increment) as u32;
            if image.check_in_bounds(correctedStartColumn, imageRow) {
                return 0;
            }
        }
        increment = -increment;
        leftToRight = !leftToRight;
    }
    correctedStartColumn
}

fn checkCodewordSkew(codewordSize: u32, minCodewordWidth: u32, maxCodewordWidth: u32) -> bool {
    minCodewordWidth as i64 - CODEWORD_SKEW_SIZE as i64 <= codewordSize as i64
        && codewordSize <= maxCodewordWidth + CODEWORD_SKEW_SIZE
}

fn decodeCodewords(
    codewords: &mut [u32],
    ecLevel: u32,
    erasures: &mut [u32],
    mut witness_data: Option<&mut WitnessData>,
) -> Result<DecoderRXingResult> {
    if codewords.is_empty() {
        return Err(Exceptions::FORMAT);
    }

    let numECCodewords = 1 << (ecLevel + 1);
    let correctedErrorsCount = correctErrors(
        codewords,
        erasures,
        numECCodewords,
        witness_data.as_deref_mut(),
    )?;
    verifyCodewordCount(codewords, numECCodewords)?;

    // Decode the codewords
    let mut decoderRXingResult =
        decoded_bit_stream_parser::decode(codewords, &ecLevel.to_string())?;
    decoderRXingResult.setErrorsCorrected(correctedErrorsCount);
    decoderRXingResult.setErasures(erasures.len());

    if let Some(wd) = witness_data {
        let chars: Vec<u8> = decoderRXingResult
            .getText()
            .chars()
            .map(|c| c as u8)
            .collect();
        wd.set_chars(chars);
    }

    Ok(decoderRXingResult)
}

/**
 * <p>Given data and error-correction codewords received, possibly corrupted by errors, attempts to
 * correct the errors in-place.</p>
 *
 * @param codewords   data and error correction codewords
 * @param erasures positions of any known erasures
 * @param numECCodewords number of error correction codewords that are available in codewords
 * @throws ChecksumException if error correction fails
 */
fn correctErrors(
    codewords: &mut [u32],
    erasures: &mut [u32],
    numECCodewords: u32,
    witness_data: Option<&mut WitnessData>,
) -> Result<usize> {
    let max_ec = witness_data
        .as_deref()
        .map_or(512usize, |wd| wd.image_params.max_ec_codewords()) as u32;
    if !erasures.is_empty() && erasures.len() as u32 > numECCodewords / 2 + MAX_ERRORS
        /*|| numECCodewords < 0*/
        || numECCodewords > max_ec
    {
        // Too many errors or EC Codewords is corrupted
        return Err(Exceptions::CHECKSUM);
    }
    ec::error_correction::decode(codewords, numECCodewords, erasures, witness_data)
}

/**
 * Verify that all is OK with the codeword array.
 */
fn verifyCodewordCount(codewords: &mut [u32], numECCodewords: u32) -> Result<()> {
    if codewords.len() < 4 {
        // Codeword array size should be at least 4 allowing for
        // Count CW, At least one Data CW, Error Correction CW, Error Correction CW
        return Err(Exceptions::FORMAT);
    }
    // The first codeword, the Symbol Length Descriptor, shall always encode the total number of data
    // codewords in the symbol, including the Symbol Length Descriptor itself, data codewords and pad
    // codewords, but excluding the number of error correction codewords.
    let numberOfCodewords = codewords[0];
    if numberOfCodewords > codewords.len() as u32 {
        return Err(Exceptions::FORMAT);
    }
    if numberOfCodewords == 0 {
        // Reset to the length of the array - 8 (Allow for at least level 3 Error Correction (8 Error Codewords)
        if numECCodewords < codewords.len() as u32 {
            codewords[0] = codewords.len() as u32 - numECCodewords;
        } else {
            return Err(Exceptions::FORMAT);
        }
    }
    Ok(())
}

fn getBitCountForCodeword(codeword: u32) -> [u32; 8] {
    let mut codeword = codeword;
    let mut result = [0; 8];
    let mut previousValue = 0;
    let mut i = result.len() as isize - 1;
    loop {
        if (codeword & 0x1) != previousValue {
            previousValue = codeword & 0x1;
            i -= 1;
            if i < 0 {
                break;
            }
        }
        result[i as usize] += 1;
        codeword >>= 1;
    }

    result
}

fn getCodewordBucketNumber(codeword: u32) -> u32 {
    getCodewordBucketNumberArray(&getBitCountForCodeword(codeword))
}

fn getCodewordBucketNumberArray(moduleBitCount: &[u32]) -> u32 {
    (moduleBitCount[0] as i32 - moduleBitCount[2] as i32 + moduleBitCount[4] as i32
        - moduleBitCount[6] as i32
        + 9) as u32
        % 9
}

// fn toString( barcodeMatrix:Vec<Vec<BarcodeValue>>) -> String{
//   try (Formatter formatter = new Formatter()) {
//     for (int row = 0; row < barcodeMatrix.length; row++) {
//       formatter.format("Row %2d: ", row);
//       for (int column = 0; column < barcodeMatrix[row].length; column++) {
//         BarcodeValue barcodeValue = barcodeMatrix[row][column];
//         if (barcodeValue.getValue().length == 0) {
//           formatter.format("        ", (Object[]) null);
//         } else {
//           formatter.format("%4d(%2d)", barcodeValue.getValue()[0],
//               barcodeValue.getConfidence(barcodeValue.getValue()[0]));
//         }
//       }
//       formatter.format("%n");
//     }
//     return formatter.toString();
//   }
// }
