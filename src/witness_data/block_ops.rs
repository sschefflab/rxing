/*
 * Block-level image operations for zero-knowledge proof generation.
 *
 * Functions for computing run-length block structure from BitMatrix images,
 * used to build lookup tables for the ZK proof system.
 */

use crate::common::BitMatrix;
use crate::pdf417::decoder::pdf_417_codeword_decoder::sampleBitCounts;
use crate::witness_data::types::BlockLookup;

/// For each row in `image`, splits it into chunks of 10 pixels and computes:
/// - `int_val`: the chunk as a binary integer (bit i = pixel i)
/// - `blocks_base_b`: the run-length block vector encoded in base B (big-endian)
/// - `r`: length of the last block
/// - `nb`: number of blocks
/// - `odd`: nb % 2
/// - `block`: 1 if the last block is black, 0 if white
///
/// Also returns the base-B decomposition of each chunk: `blocks_vec` padded with
/// leading zeros to length N.
pub fn compute_lookups_and_decomps<const N: usize>(
    image: &BitMatrix,
    B: usize,
) -> (Vec<Vec<BlockLookup>>, Vec<Vec<[u32; N]>>) {
    const L: usize = 10;
    let width = image.width() as usize;
    let height = image.height() as usize;
    let mut lookups: Vec<Vec<BlockLookup>> = Vec::new();
    let mut decomps: Vec<Vec<[u32; N]>> = Vec::new();

    for row in 0..height {
        let num_chunks = width.div_ceil(L);
        let mut row_lookups = Vec::new();
        let mut row_decomps: Vec<[u32; N]> = Vec::new();
        let mut black_r: u8 = 0; // previous chunk's remainder_is_black; starts at 0 per row
        for chunk in 0..num_chunks {
            let start_col = chunk * L;
            let chunk_len = L.min(width - start_col);

            // Take chunk_len pixels and compute int as a binary string
            let mut int_val: u16 = 0;
            let mut pixels = [false; L];
            for i in 0..chunk_len {
                let px = image.get((start_col + i) as u32, row as u32);
                pixels[i] = px;
                if px {
                    int_val |= 1 << i;
                }
            }

            // Compute blocks: lengths of runs of the same color
            let mut blocks_vec: Vec<u8> = Vec::new();
            let mut current_run: u8 = 1;
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
                blocks_base_b = blocks_base_b * B as u128 + b as u128;
            }

            // Base-B decomposition: blocks_vec padded with leading zeros to length N
            let nb_usize = blocks_vec.len();
            assert!(nb_usize <= N, "blocks_vec length {nb_usize} exceeds decomp size {N}");
            let mut decomp = [0u32; N];
            let decomp_offset = N - nb_usize;
            for (i, &b) in blocks_vec.iter().enumerate() {
                decomp[decomp_offset + i] = b as u32;
            }
            row_decomps.push(decomp);

            let nb = nb_usize as u8;

            // r = last block length
            let r = *blocks_vec.last().unwrap();

            // odd = nb % 2 == 1
            let odd: u8 = nb % 2;

            // remainder_is_black = 1 if last block is black, 0 if white
            // The last block has the same color as the first pixel when (nb-1) is even,
            // and the opposite color when (nb-1) is odd.
            let first_is_black = pixels[0];
            let last_is_black = if (nb - 1) % 2 == 0 {
                first_is_black
            } else {
                !first_is_black
            };
            let remainder_is_black: u8 = if last_is_black { 1 } else { 0 };

            // power_of_B = B^exp where exp = num_blocks - offset
            // offset = XNOR(remainder_is_black, black_r, num_blocks_is_odd)
            //        = 1 if even parity among the three bits, 0 if odd parity
            let xor_abc = remainder_is_black ^ black_r ^ odd;
            let offset: u8 = 1 - xor_abc; // 1 when even parity, 0 when odd parity
            let exp = nb - offset;
            let power_of_b = (B as u128).pow(exp as u32);

            row_lookups.push(BlockLookup {
                binary_enc: int_val,
                baseB_enc: blocks_base_b,
                remainder: r,
                num_blocks: nb,
                num_blocks_is_odd: odd,
                remainder_is_black,
                power_of_B: power_of_b,
            });
            black_r = remainder_is_black;
        }
        lookups.push(row_lookups);
        decomps.push(row_decomps);
    }

    (lookups, decomps)
}

/// For each row in `image`, computes the run-length block vector (lengths of
/// consecutive same-color pixel runs), zero-padded to `len`.
pub fn compute_blocks(image: &BitMatrix, len: usize) -> Vec<Vec<u32>> {
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

/// Word value of the PDF417 start pattern
pub const START_WORD: u32 = 81_111_113;
/// Word value of the PDF417 stop pattern
pub const STOP_WORD: u32 = 71_131_112;

pub const DUMMY_CW: u32 = 919;

/// Converts a normalized 8-element block into a single integer by concatenating digits.
/// e.g. [1,2,3,4,4,3,2,1] → 12344321
pub fn get_word(block: &[u32; 8]) -> u32 {
    block.iter().fold(0u32, |acc, &b| acc * 10 + b)
}

/// Converts a normalized 8-element block to its binary symbol value (same logic as
/// `getBitValue` in pdf_417_codeword_decoder).
fn bit_value_of_block(block: &[u32; 8]) -> u32 {
    let mut result: u64 = 0;
    for (i, &mbc) in block.iter().enumerate() {
        for _ in 0..mbc {
            result = (result << 1) | u64::from(i % 2 == 0);
        }
    }
    result as u32
}

/// Returns true if the normalized block decodes exactly to a valid PDF417 codeword
/// (i.e. without falling back to closest-match).
fn decodes_exactly(block: &[u32; 8]) -> bool {
    use crate::pdf417::pdf_417_common;
    pdf_417_common::getCodeword(bit_value_of_block(block)) != -1
}

/// Returns the ext_codeword for a (block, word_with_dummy) pair.
///   - word == 0, START_WORD, or STOP_WORD → 919 (dummy)
///   - otherwise → the PDF417 codeword index (0–928) from the lookup table
fn ext_codeword_of(block: &[u32; 8], word: u32) -> u32 {
    use crate::pdf417::pdf_417_common;
    if word == 0 || word == START_WORD || word == STOP_WORD {
        return DUMMY_CW;
    }
    let cw = pdf_417_common::getCodeword(bit_value_of_block(block));
    debug_assert!(
        cw != -1,
        "ext_codeword_of called on non-decodable word {word}"
    );
    cw as u32
}

/// Computes ext_codewords[R][WB_CW] from normalized_blocks and words_with_dummies.
pub fn compute_ext_codewords(
    normalized_blocks: &[Vec<[u32; 8]>],
    words_with_dummies: &[Vec<u32>],
) -> Vec<Vec<u32>> {
    normalized_blocks
        .iter()
        .zip(words_with_dummies.iter())
        .map(|(row_blocks, row_words)| {
            row_blocks
                .iter()
                .zip(row_words.iter())
                .map(|(block, &word)| ext_codeword_of(block, word))
                .collect()
        })
        .collect()
}

/// Computes raw words from normalized_blocks: each [u32; 8] → single u32 word.
pub fn compute_words(normalized_blocks: &[Vec<[u32; 8]>]) -> Vec<Vec<u32>> {
    normalized_blocks
        .iter()
        .map(|row| row.iter().map(|block| get_word(block)).collect())
        .collect()
}

/// Computes words_with_dummies[R][WB_CW]:
///   - Duplicate rows (per wb_inds) are entirely zeroed out.
///   - In non-duplicate rows: words that don't decode exactly and aren't START/STOP → 0.
///   - START/STOP words and exact-decode words are kept as-is.
/// Returns (words_with_dummies, garbage_words)
pub fn compute_words_with_dummies(
    normalized_blocks: &[Vec<[u32; 8]>],
    wb_inds: &[u32],
) -> (Vec<Vec<u32>>, Vec<u32>) {
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut garbage = Vec::new();
    let words_with_dummies = normalized_blocks
        .iter()
        .zip(wb_inds.iter())
        .map(|(row, &orig_idx)| {
            if !seen.insert(orig_idx) {
                // Duplicate row — zero everything out
                vec![0u32; row.len()]
            } else {
                row.iter()
                    .map(|block| {
                        let word = get_word(block);
                        if word == START_WORD || word == STOP_WORD || decodes_exactly(block) {
                            word
                        } else {
                            garbage.push(word);
                            0
                        }
                    })
                    .collect()
            }
        })
        .collect();
    (words_with_dummies, garbage)
}

/// For each row of blocks, splits into non-overlapping windows of 8 and runs
/// `sampleBitCounts` on each window that contains no zeros.
pub fn compute_normalized_blocks(blocks: &[Vec<u32>]) -> Vec<Vec<[u32; 8]>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::BitMatrix;

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
        let (lookups, decomps) = compute_lookups_and_decomps::<2>(&image, 27);

        assert_eq!(lookups.len(), 1);
        assert_eq!(decomps.len(), 1);
        let l = &lookups[0][0];
        assert_eq!(l.binary_enc, 0);
        assert_eq!(l.baseB_enc, 5); // B=27, single block of 5
        assert_eq!(l.remainder, 5);
        assert_eq!(l.num_blocks, 1);
        assert_eq!(l.num_blocks_is_odd, 1);
        assert_eq!(l.remainder_is_black, 0); // last block is white
        assert_eq!(decomps[0], [0, 5]); // padded with one leading zero
    }

    #[test]
    fn test_compute_lookups_all_black() {
        // Single row, 5 black pixels → one block of length 5
        let image = make_bitmatrix(&[&[true, true, true, true, true]]);
        let (lookups, decomps) = compute_lookups_and_decomps::<2>(&image, 27);

        assert_eq!(lookups.len(), 1);
        let l = &lookups[0][0];
        assert_eq!(l.binary_enc, 0b11111); // all 5 bits set
        assert_eq!(l.baseB_enc, 5);
        assert_eq!(l.remainder, 5);
        assert_eq!(l.num_blocks, 1);
        assert_eq!(l.num_blocks_is_odd, 1);
        assert_eq!(l.remainder_is_black, 1); // last block is black
        assert_eq!(decomps[0], [0, 5]);
    }

    #[test]
    fn test_compute_lookups_two_blocks() {
        // 3 black then 7 white, fills exactly one chunk of 10
        let row: &[bool] = &[
            true, true, true, false, false, false, false, false, false, false,
        ];
        let image = make_bitmatrix(&[row]);
        let (lookups, decomps) = compute_lookups_and_decomps::<2>(&image, 27);

        assert_eq!(lookups.len(), 1);
        let l = &lookups[0][0];
        assert_eq!(l.binary_enc, 0b0000000111); // bits 0,1,2 set
        assert_eq!(l.baseB_enc, 3 * 27 + 7); // = 88
        assert_eq!(l.remainder, 7);
        assert_eq!(l.num_blocks, 2);
        assert_eq!(l.num_blocks_is_odd, 0);
        // first_is_black=true, (nb-1)%2=1 → last is opposite → white → remainder_is_black=0
        assert_eq!(l.remainder_is_black, 0);
        assert_eq!(decomps[0], [3, 7]);
    }

    #[test]
    fn test_compute_lookups_four_blocks() {
        // [W,B,B,W,W,W,W,B,B,B] → blocks [1,2,4,3], N=4
        let row: &[bool] = &[
            false, true, true, false, false, false, false, true, true, true,
        ];
        let image = make_bitmatrix(&[row]);
        let (lookups, decomps) = compute_lookups_and_decomps::<4>(&image, 1080);

        let l = &lookups[0][0];
        assert_eq!(l.num_blocks, 4);
        assert_eq!(l.num_blocks_is_odd, 0);
        assert_eq!(l.remainder, 3);
        // first_is_black=false, (nb-1)%2=3%2=1 → last is opposite → black → remainder_is_black=1
        assert_eq!(l.remainder_is_black, 1);
        // decomp fills all N=4 slots, no leading zeros
        assert_eq!(decomps[0], [1, 2, 4, 3]);
        // baseB_enc = 1*1080^3 + 2*1080^2 + 4*1080 + 3
        let expected = 1u128 * 1080u128.pow(3) + 2 * 1080u128.pow(2) + 4 * 1080 + 3;
        assert_eq!(l.baseB_enc, expected);
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
        let (lookups, decomps) = compute_lookups_and_decomps::<2>(&image, 27);

        assert_eq!(lookups.len(), 1); // 1 row
        assert_eq!(lookups[0].len(), 2); // 2 chunks
        assert_eq!(decomps.len(), 2);

        // Chunk 0
        let l0 = &lookups[0][0];
        assert_eq!(l0.binary_enc, 3); // bits 0,1
        assert_eq!(l0.baseB_enc, 2 * 27 + 8); // = 62
        assert_eq!(l0.remainder, 8);
        assert_eq!(l0.num_blocks, 2);
        assert_eq!(l0.num_blocks_is_odd, 0);
        assert_eq!(l0.remainder_is_black, 0); // first=black, (nb-1)%2=1 → last=white
        assert_eq!(decomps[0], [2, 8]);

        // Chunk 1
        let l1 = &lookups[0][1];
        // pixels 5-9 of the chunk (cols 15-19) are black → bits 5-9 set
        assert_eq!(
            l1.binary_enc,
            (1u128 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9)
        );
        assert_eq!(l1.baseB_enc, 5 * 27 + 5); // = 140
        assert_eq!(l1.remainder, 5);
        assert_eq!(l1.num_blocks, 2);
        assert_eq!(l1.num_blocks_is_odd, 0);
        assert_eq!(l1.remainder_is_black, 1); // first=white, (nb-1)%2=1 → last=black
        assert_eq!(decomps[1], [5, 5]);
    }

    #[test]
    fn test_compute_lookups_multiple_rows() {
        // 2 rows: all-black, all-white
        let image = make_bitmatrix(&[
            &[true, true, true, true, true],
            &[false, false, false, false, false],
        ]);
        let (lookups, decomps) = compute_lookups_and_decomps::<2>(&image, 27);

        assert_eq!(lookups.len(), 2); // 2 rows
        assert_eq!(lookups[0].len(), 1); // 1 chunk per row
        assert_eq!(lookups[1].len(), 1);
        assert_eq!(decomps.len(), 2);
        assert_eq!(lookups[0][0].remainder_is_black, 1); // row 0: last block black
        assert_eq!(lookups[1][0].remainder_is_black, 0); // row 1: last block white
        assert_eq!(decomps[0], [0, 5]);
        assert_eq!(decomps[1], [0, 5]);
    }

    #[test]
    fn test_decomp_reconstructs_blocks_base_b() {
        // For any chunk, folding the decomp big-endian must equal blocks_base_b in the lookup.
        let rows: &[&[bool]] = &[
            &[
                true, false, true, false, true, false, true, false, true, false,
            ], // alternating, 10 blocks
            &[
                true, true, false, false, true, true, false, false, true, true,
            ], // pairs
            &[
                false, false, false, true, true, true, true, true, true, true,
            ], // 3 white then 7 black
        ];
        let image = make_bitmatrix(rows);
        const B: usize = 27;
        // Use N=10 so even fully alternating rows (10 blocks) fit
        let (lookups, decomps) = compute_lookups_and_decomps::<10>(&image, B);

        for (row_lookups, decomp) in lookups.iter().flat_map(|r| r.iter()).zip(decomps.iter()) {
            let blocks_base_b = row_lookups.baseB_enc;
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
            &[
                true, true, true, false, false, false, false, false, false, false,
            ], // 2 blocks
            &[
                true, false, true, false, true, false, false, false, false, false,
            ], // 6 blocks (alt)
        ];
        let image = make_bitmatrix(rows);
        let (lookups, decomps) = compute_lookups_and_decomps::<10>(&image, 27);

        for (lookup, decomp) in lookups.iter().flat_map(|r| r.iter()).zip(decomps.iter()) {
            let nb = lookup.num_blocks as usize;
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
        let blocks = compute_blocks(&image, 5);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0][0], 2);
        assert_eq!(blocks[0][1], 3);
        assert_eq!(blocks[0][2], 0); // zero-padded
    }

    #[test]
    fn test_compute_blocks_single_run() {
        // All white → one run, padded to len=4
        let image = make_bitmatrix(&[&[false, false, false, false]]);
        let blocks = compute_blocks(&image, 4);
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
        let blocks = compute_blocks(&image, 4);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0][0], 2);
        assert_eq!(blocks[0][1], 1);
        assert_eq!(blocks[1][0], 3);
        assert_eq!(blocks[1][1], 0);
    }

    // -------------------------------------------------------------------------
    // compute_normalized_blocks
    // -------------------------------------------------------------------------

    #[test]
    fn test_normalized_blocks_sum_is_17() {
        // sampleBitCounts runs exactly MODULES_IN_CODEWORD=17 iterations, each
        // incrementing one slot, so every normalized block must sum to 17.
        let blocks = vec![vec![3u32, 1, 2, 4, 1, 3, 2, 1]];
        let normalized = compute_normalized_blocks(&blocks);
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].len(), 1);
        let sum: u32 = normalized[0][0].iter().sum();
        assert_eq!(sum, 17);
    }

    const START_BLOCKS: [u32; 8] = [8, 1, 1, 1, 1, 1, 1, 3];

    #[test]
    fn test_normalized_blocks_start() {
        // start blocks normalize to the start symbol
        let blocks = vec![Vec::from(START_BLOCKS)];
        let normalized = compute_normalized_blocks(&blocks);
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].len(), 1);
        assert_eq!(normalized[0][0], START_BLOCKS);
    }

    #[test]
    fn test_normalized_blocks_start_2x() {
        // start blocks but doubled normalize to the start symbol
        let start_blocks_2x: [u32; 8] = [16, 2, 2, 2, 2, 2, 2, 6];
        let blocks = vec![Vec::from(start_blocks_2x)];
        let normalized = compute_normalized_blocks(&blocks);
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].len(), 1);
        assert_eq!(normalized[0][0], START_BLOCKS);
    }

    #[test]
    fn test_normalized_blocks_zero_window_filtered() {
        // A window with any zero element must be dropped entirely.
        let blocks = vec![vec![3u32, 0, 2, 4, 1, 3, 2, 1]];
        let normalized = compute_normalized_blocks(&blocks);
        assert_eq!(normalized[0].len(), 0);
    }

    #[test]
    fn test_normalized_blocks_partial_chunk_ignored() {
        // chunks_exact(8) ignores trailing elements that don't fill a full window.
        let blocks = vec![vec![1u32, 2, 3, 4, 5, 6, 7, 8, 9]]; // 9 values → 1 window + 1 leftover
        let normalized = compute_normalized_blocks(&blocks);
        assert_eq!(normalized[0].len(), 1);
        let sum: u32 = normalized[0][0].iter().sum();
        assert_eq!(sum, 17);
    }

    #[test]
    fn test_normalized_blocks_multiple_windows() {
        // Two complete 8-windows in one row, both all-nonzero.
        let blocks = vec![vec![1u32, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2]];
        let normalized = compute_normalized_blocks(&blocks);
        assert_eq!(normalized[0].len(), 2);
        for window in &normalized[0] {
            assert_eq!(window.iter().sum::<u32>(), 17);
        }
    }

    #[test]
    fn test_normalized_blocks_multiple_rows() {
        // Each row is handled independently; zero windows are per-row.
        let blocks = vec![
            vec![1u32, 2, 3, 4, 5, 6, 7, 8], // 1 nonzero window
            vec![1u32, 0, 1, 1, 1, 1, 1, 1], // zero in window → filtered
            vec![],                          // empty row
        ];
        let normalized = compute_normalized_blocks(&blocks);
        assert_eq!(normalized.len(), 3);
        assert_eq!(normalized[0].len(), 1);
        assert_eq!(normalized[1].len(), 0);
        assert_eq!(normalized[2].len(), 0);
    }

    #[test]
    fn test_normalized_blocks_mixed_windows() {
        // Two windows: first has a zero (filtered), second is all-nonzero.
        let blocks = vec![vec![
            1u32, 2, 0, 4, 5, 6, 7, 8, // window 0: has a zero
            1, 1, 1, 1, 1, 1, 1, 1, // window 1: all nonzero
        ]];
        let normalized = compute_normalized_blocks(&blocks);
        assert_eq!(normalized[0].len(), 1); // only window 1 survives
        assert_eq!(normalized[0][0].iter().sum::<u32>(), 17);
    }
}
