# rxing PDF417 Barcode Decoding Workflow

This document provides a comprehensive walkthrough of the rxing library's PDF417 barcode decoding process, including file paths and line numbers.

## 1. Entry Point: PDF417Reader
**File:** `external/rxing/src/pdf417/pdf_417_reader.rs`

The decoding process starts when you call:
- `decode_with_hints()` (line 48-54) - Main entry point
- This calls `internal_decode_with_hints()` (line 198-208)
- Which calls the static `decode()` method (line 89-156)

## 2. Detection Phase: Finding the Barcode
**File:** `external/rxing/src/pdf417/detector/pdf_417_detector.rs`

The `decode()` method calls `pdf_417_detector::detect_with_hints()` at line 95:

### Key detection steps:
- **detect_with_hints()** (line 67-95): Tries 4 rotations (0°, 90°, 180°, 270°)
  - Gets black matrix from image (line 77)
  - Applies rotation with `applyRotation()` (line 80)
  - Calls `detect()` for each rotation (line 81)

- **detect()** (line 120-164): Scans the image for PDF417 patterns
  - Iterates through rows using `ROW_STEP` (5 pixels, line 53)
  - Calls `findVertices()` for each position (line 126)

- **findVertices()** (line 181-205): Locates barcode corners using start/stop patterns
  - **START_PATTERN**: `[8, 1, 1, 1, 1, 1, 1, 3]` (line 42)
  - **STOP_PATTERN**: `[7, 1, 1, 3, 1, 1, 1, 2, 1]` (line 44)
  - Calls `findRowsWithPattern()` twice (lines 190, 200)
  - Returns 8 vertices:
    - vertices[0-3]: outer barcode corners (top-left, bottom-left, top-right, bottom-right)
    - vertices[4-7]: inner codeword area corners

- **findRowsWithPattern()** (line 217-301): Finds start/end rows with specific pattern
  - Uses `findGuardPattern()` to locate pattern (line 232)
  - Scans upward to find earliest row (line 235-246)
  - Scans downward to find last row (line 261-291)
  - Validates minimum height `BARCODE_MIN_HEIGHT` (10 pixels, line 296)

- **findGuardPattern()** (line 313-367): Pattern matching algorithm
  - Scans pixels and builds module counts
  - Uses `patternMatchVariance()` to validate (line 341, 361)
  - **MAX_AVG_VARIANCE**: 0.42 (line 37)
  - **MAX_INDIVIDUAL_VARIANCE**: 0.8 (line 38)

- **patternMatchVariance()** (line 379-413): Computes variance between observed and expected patterns
  - Returns ratio of total variance to pattern size
  - Uses unit bar width normalization (line 395)
  - Rejects if individual variance exceeds threshold (line 407)

## 3. Decoding Phase: Extracting Codewords
**File:** `external/rxing/src/pdf417/decoder/pdf_417_scanning_decoder.rs`

Back in `pdf_417_reader.rs`, the detector result is processed (line 101-109):

### Main decode function (line 45-178):
- Creates `BoundingBox` from detected vertices (line 56-62)
- Two-pass process (line 66):
  - **First pass**: Get row indicators and adjust bounding box
  - **Second pass**: Final decode with adjusted bounds

### Row Indicator Processing:
- **getRowIndicatorColumn()** (line 358-401): Scans left/right indicators
  - Detects codewords in each row (line 376-394)
  - Row indicators contain metadata (row count, column count, EC level)

### Merge metadata:
- **merge()** (line 180-200): Combines left/right indicator data
- **getBarcodeMetadata()** (line 263-356): Extracts barcode structure info
- **adjustBoundingBox()** (line 202-252): Refines boundaries
  - Calculates row heights (line 210)
  - Adjusts for missing start/end rows (line 216-246)

### Codeword Detection (lines 114-175):
- Iterates through each column (left-to-right or right-to-left)
- **getStartColumn()** (line 582-670): Determines where to start scanning
  - Looks at adjacent columns for hints (line 591-603)
  - Uses nearby codewords if available (line 609-621)
  - Estimates position from previous columns (line 637-664)
- **detectCodeword()** (line 673-752): Core codeword extraction
  - `adjustCodewordStartColumn()`: Fine-tunes start position
  - **getModuleBitCount()** (line 695): Extracts bit pattern (8 modules)
  - Validates codeword width with `checkCodewordSkew()` (line 736)
  - Returns `Codeword` object (line 748) with start/end positions and value

### Building the Codeword Matrix:
- **createBarcodeMatrix()** (line 531-575): Creates 2D array of BarcodeValue objects
  - Dimensions: [row count] x [column count + 2]
  - Column 0 and last column are row indicators
  - Populates from DetectionResultColumns (line 548-573)

## 4. Codeword Value Decoding
**File:** `external/rxing/src/pdf417/decoder/pdf_417_codeword_decoder.rs`

At scanning_decoder line 742: `pdf_417_codeword_decoder::getDecodedValue()`

### getDecodedValue() (line 54-60):
1. **sampleBitCounts()** (line 62-79): Normalizes module counts to 8 bars
   - Computes total bit count (line 63)
   - Samples at specific positions to get 8-bar pattern (line 67-77)

2. **getDecodedCodewordValue()** (line 81-88): Converts to integer value
   - Uses `getBitValue()` to convert pattern to integer
   - Validates against PDF417 symbol table

3. **getBitValue()** (line 90-100): Converts bar pattern to binary
   - Black bars = 1, white bars = 0
   - Shifts and combines bits (line 96)

4. **getClosestDecodedValue()** (line 102-130): Fuzzy matching using pre-computed ratio table
   - Uses **RATIOS_TABLE** (line 24) with 2787 possible patterns
   - Computes bit count ratios (line 106-110)
   - Finds best match using least-squares error (line 113-128)
   - Returns symbol from SYMBOL_TABLE (line 126)

## 5. Building the Codeword Matrix
**File:** `external/rxing/src/pdf417/decoder/pdf_417_scanning_decoder.rs`

### createDecoderRXingResult() (line 427-470):
1. **createBarcodeMatrix()** (line 531-575): 2D array of BarcodeValue objects
   - Each BarcodeValue can hold multiple candidate values

2. **adjustCodewordCount()** (line 403-425): Validates codeword count
   - Calculates expected count from dimensions (line 409-411)
   - Updates if missing or incorrect (line 413-423)

3. Build codeword array (line 433-454):
   - Identifies **erasures** (missing codewords, line 445-446)
   - Handles **ambiguous codewords** (multiple possible values, line 449-452)
   - Single-value codewords added directly (line 447-448)

4. **createDecoderRXingResultFromAmbiguousValues()** (line 485-529):
   - Tries different combinations of ambiguous values (line 495-527)
   - Attempts decode up to 100 times (line 494)
   - Returns first successful decode (line 502-503)

## 6. Error Correction
**File:** `external/rxing/src/pdf417/decoder/pdf_417_scanning_decoder.rs:842`

### decodeCodewords() (line 842-862):
- Calculates EC codewords: `numECCodewords = 1 << (ecLevel + 1)` (line 851)
- **correctErrors()** (line 873-886): Reed-Solomon error correction
  - Maximum erasures: `numECCodewords / 2 + MAX_ERRORS` (line 878, MAX_ERRORS=3)
  - Maximum EC codewords: 512 (line 38)
  - Calls Reed-Solomon decoder (line 885)

- **verifyCodewordCount()** (line 891-913): Validates codeword array
  - Minimum 4 codewords required (line 892)
  - First codeword is Symbol Length Descriptor (line 900)
  - Adjusts if needed (line 905-910)

**File:** `external/rxing/src/pdf417/decoder/ec/error_correction.rs`

### Reed-Solomon Implementation:
- **decode()** (line 47-112): Main EC algorithm
  - Uses Galois Field GF(929) with modulus 3 (line 28)
  - Creates polynomial from received codewords (line 49)

1. **Syndrome calculation** (line 52-59):
   - Evaluates polynomial at error correction positions
   - If all syndromes are 0, no errors detected (line 61-62)

2. **Known erasures** (line 69-78):
   - Builds erasure locator polynomial
   - Each erasure adds a (1 - bx) term (line 74)

3. **runEuclideanAlgorithm()** (line 83-88):
   - Finds error locator polynomial (sigma)
   - Finds error evaluator polynomial (omega)

4. **findErrorLocations()** (line 94):
   - Identifies positions of errors using sigma roots

5. **findErrorMagnitudes()** (line 95):
   - Calculates correction values using Forney algorithm

6. **Apply corrections** (line 97-111):
   - Subtracts error magnitudes from codewords (line 106)
   - Returns number of errors corrected (line 109)

## 7. Final Decoding: Text Extraction
**File:** `external/rxing/src/pdf417/decoder/decoded_bit_stream_parser.rs`

At scanning_decoder line 857: `decoded_bit_stream_parser::decode()`

### decode() (line 109-163): Main parsing function
- Codeword[0] = total codeword count
- Processes modes starting at codeword[1]:

### Mode Values:
- **TEXT_COMPACTION_MODE_LATCH** (900): `textCompaction()` - alphanumeric text
- **BYTE_COMPACTION_MODE_LATCH** (901): `byteCompaction()` - binary data
- **BYTE_COMPACTION_MODE_LATCH_6** (924): Alternative byte mode
- **NUMERIC_COMPACTION_MODE_LATCH** (902): `numericCompaction()` - numbers (base-900)
- **MODE_SHIFT_TO_BYTE_COMPACTION_MODE** (913): Single byte (line 124)
- **ECI_CHARSET** (927): Character set encoding (line 130-132)
- **ECI_GENERAL_PURPOSE** (926): Skip 2 characters (line 137)
- **ECI_USER_DEFINED** (925): Skip 1 character (line 141)
- **BEGIN_MACRO_PDF417_CONTROL_BLOCK** (928): `decodeMacroBlock()` - metadata
- **BEGIN_MACRO_PDF417_OPTIONAL_FIELD** (923): Macro optional fields
- **MACRO_PDF417_TERMINATOR** (922): End of macro block

### Text Compaction Mode:
Text modes use state machine (line 34-42):
- **Alpha**: Uppercase letters (A-Z)
- **Lower**: Lowercase letters (a-z)
- **Mixed**: Numbers and symbols (line 80-83)
  - Contains: 0-9, &, \r, \t, comma, colon, #, -, ., $, /, +, %, *, =, ^
- **Punct**: Punctuation (line 75-78)
  - Contains: ;, <, >, @, [, \\, ], _, `, ~, !, etc.
- **AlphaShift**: Temporary shift to Alpha
- **PunctShift**: Temporary shift to Punct

### Numeric Compaction Mode:
- Numbers encoded in base-900
- Uses **EXP900** lookup table (line 91-105)
- Decodes up to 15 codewords at a time (line 55)
- Converts to decimal using BigUint arithmetic

### Byte Compaction Mode:
- Mode 901: Groups of 5 codewords → 6 bytes (base-900)
- Mode 924: Direct byte encoding (6-bit encoding)
- Mode 913: Single byte shift

## 8. Return Result
**File:** `external/rxing/src/pdf417/pdf_417_reader.rs:111`

Creates `RXingResult` with:
- **Decoded text** (line 112): UTF-8 string from decoded bytes
- **Raw bytes** (line 113): Original byte data
- **Corner points** (line 114): 8 vertices from detection
- **Format**: `BarcodeFormat::PDF_417` (line 115)

### Metadata:
- **Error correction level** (line 118-123): EC level string
- **PDF417 extra metadata** (line 125-135):
  - Segment info (if macro barcode)
  - File ID, optional data fields
- **Orientation** (line 142-145): Rotation applied (0°, 90°, 180°, 270°)
- **Symbology identifier** (line 146-152): Format: `]L{modifier}`
  - Modifier indicates encoding mode and options

## Summary Flow Diagram

```
BinaryBitmap (input image)
    ↓
┌─────────────────────────────────────────────────────────────┐
│ [1] PDF417Reader::decode_with_hints()                      │
│     external/rxing/src/pdf417/pdf_417_reader.rs:48         │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ [2] PDF417Detector::detect_with_hints()                    │
│     external/rxing/src/pdf417/detector/pdf_417_detector.rs │
│     - Try rotations (0°, 90°, 180°, 270°)                  │
│     - findVertices() → locate START/STOP patterns          │
│     - findGuardPattern() → pattern matching                │
│     → Returns: BitMatrix + 8 corner points                 │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ [3] PDF417ScanningDecoder::decode()                        │
│     external/rxing/src/pdf417/decoder/                     │
│             pdf_417_scanning_decoder.rs:45                  │
│     - getRowIndicatorColumn() → extract metadata           │
│     - detectCodeword() → scan each codeword                │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ [4] PDF417CodewordDecoder::getDecodedValue()               │
│     external/rxing/src/pdf417/decoder/                     │
│             pdf_417_codeword_decoder.rs:54                  │
│     - Pattern matching → codeword values                   │
│     - sampleBitCounts() → normalize to 8 bars              │
│     - getClosestDecodedValue() → fuzzy matching            │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│     - createBarcodeMatrix() → 2D array of BarcodeValues    │
│     - adjustCodewordCount() → validate dimensions          │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ [5] Error Correction                                        │
│     external/rxing/src/pdf417/decoder/ec/                  │
│             error_correction.rs:47                          │
│     - Reed-Solomon decoding (GF(929))                      │
│     - Syndrome calculation                                 │
│     - Euclidean algorithm → error locator polynomial       │
│     - Forney algorithm → error magnitudes                  │
│     - Correct errors/erasures                              │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ [6] DecodedBitStreamParser::decode()                       │
│     external/rxing/src/pdf417/decoder/                     │
│             decoded_bit_stream_parser.rs:109                │
│     - Text compaction (mode 900): Alpha/Lower/Mixed/Punct  │
│     - Byte compaction (mode 901, 924): Binary data         │
│     - Numeric compaction (mode 902): Base-900 numbers      │
│     - Mode state machine                                   │
│     - Handle ECI encodings (mode 927)                      │
│     - Macro block parsing (mode 928)                       │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ [7] RXingResult                                            │
│     - Decoded text string                                  │
│     - Raw bytes                                            │
│     - Corner points (8 vertices)                           │
│     - Metadata (EC level, orientation, symbology ID)       │
└─────────────────────────────────────────────────────────────┘
```

## Key Constants and Thresholds

### Detection Constants:
- `ROW_STEP = 5`: Pixels to skip between row scans
- `BARCODE_MIN_HEIGHT = 10`: Minimum barcode height in pixels
- `MAX_AVG_VARIANCE = 0.42`: Maximum average pattern variance
- `MAX_INDIVIDUAL_VARIANCE = 0.8`: Maximum individual bar variance
- `MAX_PIXEL_DRIFT = 3`: Maximum pixel drift for pattern start
- `MAX_PATTERN_DRIFT = 5`: Maximum pattern drift between rows
- `SKIPPED_ROW_COUNT_MAX = 25`: Maximum rows to skip while tracking

### Decoding Constants:
- `CODEWORD_SKEW_SIZE = 2`: Allowable codeword width variation
- `MAX_ERRORS = 3`: Maximum correctable errors beyond erasures
- `MAX_EC_CODEWORDS = 512`: Maximum error correction codewords
- `MAX_NUMERIC_CODEWORDS = 15`: Maximum numeric codewords per group

### Pattern Constants:
- `START_PATTERN = [8, 1, 1, 1, 1, 1, 1, 3]`: 8 bars defining start
- `STOP_PATTERN = [7, 1, 1, 3, 1, 1, 1, 2, 1]`: 9 bars defining stop
- `MODULES_IN_CODEWORD = 17`: Modules per codeword
- `BARS_IN_MODULE = 8`: Bars per module pattern

### Galois Field:
- `NUMBER_OF_CODEWORDS = 929`: GF(929) for error correction
- Primitive element: 3

## Error Handling

The decoder handles various error conditions:
- **NOT_FOUND**: No barcode detected, pattern not found
- **FORMAT**: Invalid barcode structure, bad codeword count
- **CHECKSUM**: Error correction failed, too many errors
- **PARSE**: Invalid character encoding
- **ILLEGAL_STATE**: Internal state inconsistency

This workflow handles rotation detection, robust pattern matching, error correction with Reed-Solomon codes, and multiple encoding modes to reliably decode PDF417 barcodes from images.
