/*
 * Block-level image operations for zero-knowledge proof generation.
 *
 * Functions for computing run-length block structure from BitMatrix images,
 * used to build lookup tables for the ZK proof system.
 */

use crate::common::BitMatrix;
use crate::witness_data::types::BlockLookup;

const L: usize = 10;

/// For each row in `image`, splits it into chunks of 10 pixels and computes:
/// - `int_val`: the chunk as a binary integer (bit i = pixel i)
/// - `blocks_base_b`: the run-length block vector encoded in base B (big-endian)
/// - `r`: length of the last block
/// - `nb`: number of blocks
/// - `odd`: nb % 2
/// - `block`: 1 if the last block is black, 0 if white
fn compute_lookups_and_raw_decomps<const N: usize>(
    image: &BitMatrix,
    B: usize,
) -> (Vec<Vec<BlockLookup>>, Vec<Vec<[u16; N]>>) {
    let width = image.width() as usize;
    let height = image.height() as usize;
    let mut lookups: Vec<Vec<BlockLookup>> = Vec::new();
    let mut decomps: Vec<Vec<[u16; N]>> = Vec::new();

    for row in 0..height {
        let num_chunks = width.div_ceil(L);
        let mut row_lookups = Vec::new();
        let mut row_decomps = Vec::new();
        let mut black_r: u8 = 0; // previous chunk's remainder_is_black; starts at 0 per row
        for chunk in 0..num_chunks {
            let mut decomp: [u16; N] = [0; N];
            let start_col = chunk * L;
            let chunk_len = L.min(width - start_col);

            // Take chunk_len pixels and compute int as a binary string (big endian)
            let mut int_val: u16 = 0;
            let mut pixels = [false; L];
            for i in 0..chunk_len {
                let px = image.get((start_col + i) as u32, row as u32);
                pixels[i] = px;
                if px {
                    int_val |= 1 << (chunk_len - 1 - i);
                }
            }

            // Compute blocks: lengths of runs of the same color
            let mut blocks_vec: Vec<u16> = Vec::new();
            let mut current_run: u16 = 1;
            for i in 1..chunk_len {
                if pixels[i] == pixels[i - 1] {
                    current_run += 1;
                } else {
                    blocks_vec.push(current_run);
                    current_run = 1;
                }
            }
            blocks_vec.push(current_run);

            let nb_usize = blocks_vec.len();

            // Big-endian base-B encoding and decomposition
            let mut blocks_base_b: u128 = 0;
            let num_non_remainder = nb_usize - 1;
            for (i, &b) in blocks_vec[..num_non_remainder].iter().enumerate() {
                let power: u32 = (num_non_remainder - 1 - i) as u32;
                blocks_base_b += b as u128 * (B as u128).pow(power);
                let decomp_idx = N.saturating_sub(num_non_remainder) + i;
                decomp[decomp_idx] = b;
            }

            row_decomps.push(decomp); // this decomp ignores the remainder blocks

            let nb = num_non_remainder as u8;
            let odd: u8 = nb % 2;
            let first_is_black = pixels[0];

            // remainder = rightmost block length (remainder that may merge with the next chunk)
            let remainder = *blocks_vec.last().unwrap();

            // remainder_is_black = 1 if the rightmost block is black, 0 if white.
            // Uses actual block count (nb_usize) to determine the color of the last run.
            let last_is_black = if (nb_usize - 1) % 2 == 0 {
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
            let exp = nb.saturating_sub(offset);
            let power_of_b = (B as u128).pow(exp as u32);

            row_lookups.push(BlockLookup {
                binary_enc: int_val,
                baseB_enc: blocks_base_b,
                remainder,
                num_blocks: num_non_remainder as u8,
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

// Iterate through the chunks and combine remainders with the next block such that there are no breaks in the middle of blocks
// Return the base-B decomposition of these new, combined chunks
// N is max number of blocks per chunk
fn accumulate_decomps<const N: usize>(
    lookups: &[Vec<BlockLookup>],
    decomps: Vec<Vec<[u16; N]>>,
) -> Vec<Vec<[u16; N]>> {
    lookups
        .iter()
        .zip(decomps)
        .map(|(row_lookups, row_raw)| {
            let mut result = Vec::new();
            let mut decomp = row_raw[0];
            let mut last_remainder = row_lookups[0].remainder;
            let mut last_remainder_is_black = row_lookups[0].remainder_is_black != 0;

            for (lookup, next_decomp) in row_lookups[1..].iter().zip(row_raw[1..].iter().copied()) {
                result.push(decomp);
                decomp = next_decomp;

                if lookup.num_blocks == 0 {
                    let remainder_is_black = lookup.remainder_is_black != 0;
                    if last_remainder_is_black == remainder_is_black {
                        // same color: chunk merges into running remainder, block_chunks[i]=0 → zero decomp
                        last_remainder += lookup.remainder;
                        decomp = [0; N];
                    } else {
                        // different colors: commit previous remainder as last block
                        decomp.copy_within(1.., 0);
                        decomp[N - 1] = last_remainder;
                        last_remainder = lookup.remainder;
                        last_remainder_is_black = remainder_is_black;
                    }
                } else {
                    let first_block_is_black =
                        (lookup.num_blocks_is_odd != 0) ^ (lookup.remainder_is_black != 0);
                    let idx = if first_block_is_black == last_remainder_is_black {
                        N - lookup.num_blocks as usize // first block and remainder are same color: merge
                    } else {
                        N - lookup.num_blocks as usize - 1 // remainder is its own block
                    };
                    decomp[idx] += last_remainder;
                    last_remainder = lookup.remainder;
                    last_remainder_is_black = lookup.remainder_is_black != 0;
                }
            }

            // Commit the final remainder as the last block
            decomp.copy_within(1.., 0);
            decomp[N - 1] = last_remainder;
            result.push(decomp);
            result
        })
        .collect()
}

pub fn compute_lookups_and_decomps<const N: usize>(
    image: &BitMatrix,
    B: usize,
) -> (Vec<Vec<BlockLookup>>, Vec<Vec<[u16; N]>>) {
    let (lookups, raw_decomps) = compute_lookups_and_raw_decomps::<N>(image, B);
    let finalized_decomps = accumulate_decomps::<N>(&lookups, raw_decomps);
    (lookups, finalized_decomps)
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
pub fn get_word(block: &[u32; 8]) -> u64 {
    block.iter().fold(0u64, |acc, &b| acc * 10 + b as u64)
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
fn ext_codeword_of(block: &[u32; 8], word: u64) -> u32 {
    use crate::pdf417::pdf_417_common;
    if word == 0 || word == START_WORD as u64 || word == STOP_WORD as u64 {
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
    words_with_dummies: &[Vec<u64>],
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

/// Computes raw words from normalized_blocks: each [u32; 8] → single u64 word.
pub fn compute_words(normalized_blocks: &[Vec<[u32; 8]>]) -> Vec<Vec<u64>> {
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
) -> (Vec<Vec<u64>>, Vec<u64>) {
    let mut garbage = Vec::new();
    // Precompute all words so we can look up the previous row's words by index.
    let all_words: Vec<Vec<u64>> = normalized_blocks
        .iter()
        .map(|row| row.iter().map(|b| get_word(b)).collect())
        .collect();
    let words_with_dummies: Vec<Vec<u64>> = normalized_blocks
        .iter()
        .zip(wb_inds.iter())
        .enumerate()
        .map(|(i, (row, &orig_idx))| {
            let is_consecutive_duplicate = i > 0 && orig_idx == wb_inds[i - 1];
            if is_consecutive_duplicate {
                // Consecutive duplicate — same source as row above, so circuit's
                // curr_word == words[i-1][j] for all j, and garbage stays 1.
                vec![0u64; row.len()]
            } else {
                row.iter()
                    .enumerate()
                    .map(|(j, block)| {
                        let word = get_word(block);
                        if word == START_WORD as u64
                            || word == STOP_WORD as u64
                            || decodes_exactly(block)
                        {
                            word
                        } else {
                            // Match circuit: if this garbage word equals the word at the
                            // same column in the previous row, the circuit uses 1 (KNOWN_GARBAGE).
                            let same_as_prev = i > 0 && word == all_words[i - 1][j];
                            if !same_as_prev {
                                garbage.push(word);
                            }
                            0
                        }
                    })
                    .collect()
            }
        })
        .collect();
    let garbage_len = words_with_dummies.len() * words_with_dummies[0].len();
    garbage.resize(garbage_len, 1); // pad garbage to the max length with 1's (known garbage)
    (words_with_dummies, garbage)
}

/// Proportionally normalizes an 8-element block window so that each element
/// satisfies `|blocks[i] * sum - 17 * result[i]| <= 8`. Returns all zeros
/// for a zero window (sum == 0).
fn proportional_normalize(window: &[u32]) -> [u32; 8] {
    let sum: u64 = window.iter().map(|&x| x as u64).sum();
    if sum == 0 {
        return [0u32; 8];
    }
    let mut result = [0u32; 8];
    for (i, &b) in window.iter().enumerate() {
        result[i] = ((b as u64 * sum + 8) / 17) as u32;
    }
    result
}

/// For each row of blocks, splits into non-overlapping windows of 8 and
/// proportionally normalizes each window.
pub fn compute_normalized_blocks(blocks: &[Vec<u32>]) -> Vec<Vec<[u32; 8]>> {
    blocks
        .iter()
        .map(|row| {
            let num_chunks = (row.len() + 7) / 8;
            let mut result: Vec<[u32; 8]> = row
                .chunks_exact(8)
                .map(|window| proportional_normalize(window))
                .collect();
            result.resize(num_chunks, [0u32; 8]);
            result
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
        let (lookups, decomps) = compute_lookups_and_decomps::<2>(&image, 104);

        assert_eq!(lookups.len(), 1);
        assert_eq!(decomps.len(), 1);
        let l = &lookups[0][0];
        assert_eq!(l.binary_enc, 0);
        assert_eq!(l.baseB_enc, 0); // single block: no non-remainder blocks to encode
        assert_eq!(l.remainder, 5);
        assert_eq!(l.num_blocks, 0); // num_blocks does not include the remainder
        assert_eq!(l.num_blocks_is_odd, 0); // 0 % 2 == 1
        assert_eq!(l.remainder_is_black, 0); // rightmost block is white
        assert_eq!(l.power_of_B, 1); // nb=0, odd=0, rem_black=0, black_r=0 → xor=0, offset=1, exp=0 → 104^0=1
        assert_eq!(decomps[0][0], [0u16, 5u16]); // enc_baseB=5 → only one block of len 5
    }

    #[test]
    fn test_compute_lookups_all_black() {
        // Single row, 5 black pixels → one block of length 5
        let image = make_bitmatrix(&[&[true, true, true, true, true]]);
        let (lookups, decomps) = compute_lookups_and_decomps::<2>(&image, 104);

        assert_eq!(lookups.len(), 1);
        let l = &lookups[0][0];
        assert_eq!(l.binary_enc, 0b11111); // all 5 bits set
        assert_eq!(l.baseB_enc, 0); // single block: no non-remainder blocks to encode
        assert_eq!(l.remainder, 5);
        assert_eq!(l.num_blocks, 0);
        assert_eq!(l.num_blocks_is_odd, 0); // 0 % 2 == 0
        assert_eq!(l.remainder_is_black, 1); // rightmost block is black
        assert_eq!(l.power_of_B, 1); // nb=0, odd=0, rem_black=1, black_r=0 → xor=1, offset=0, exp=0 → 104^0=1
        assert_eq!(decomps[0][0], [0u16, 5u16]); // enc_baseB=5 → only one block of len 5
    }

    #[test]
    fn test_compute_lookups_two_blocks() {
        // 3 black then 7 white, fills exactly one chunk of 10
        let row: &[bool] = &[
            true, true, true, false, false, false, false, false, false, false,
        ];
        let image = make_bitmatrix(&[row]);
        let (lookups, decomps) = compute_lookups_and_decomps::<2>(&image, 104);

        assert_eq!(lookups.len(), 1);
        let l = &lookups[0][0];
        assert_eq!(l.binary_enc, 0b1110000000); // first three bits set (big endian encoding)
        // leftmost block (3) is the only non-remainder block: enc_baseB = 3 * B^0 = 3
        assert_eq!(l.baseB_enc, 3);
        assert_eq!(l.remainder, 7);
        assert_eq!(l.num_blocks, 1);
        assert_eq!(l.num_blocks_is_odd, 1); // 1 % 2 == 1
        // first_is_black=true, (2-1)%2=1 → last is opposite → white → remainder_is_black=0
        assert_eq!(l.remainder_is_black, 0);
        assert_eq!(l.power_of_B, 104); // nb=1, odd=1, rem_black=0, black_r=0 → xor=1, offset=0, exp=1 → 104^1=104
        assert_eq!(decomps[0][0], [3u16, 7u16]);
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
        assert_eq!(l.num_blocks, 3);
        assert_eq!(l.num_blocks_is_odd, 1);
        assert_eq!(l.remainder, 3);
        // first_is_black=false, (nb-1)%2=3%2=1 → last is opposite → black → remainder_is_black=1
        assert_eq!(l.remainder_is_black, 1);
        assert_eq!(l.power_of_B, 1166400); // nb=3, odd=1, rem_black=1, black_r=0 → xor=0, offset=1, exp=2 → 1080^2=1166400
        // decomp is little-endian of non-remainder blocks [1,2,4]:
        //   decomp[0]=4 (coeff of B^0), decomp[1]=2 (B^1), decomp[2]=1 (B^2), decomp[3]=0 (pad)
        assert_eq!(decomps[0][0], [1u16, 2u16, 4u16, 3u16]);
        // baseB_enc = 1*1080^2 + 2*1080 + 4 (excludes remainder=3)
        let expected = 1u128 * 1080u128.pow(2) + 2 * 1080 + 4;
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
        let (lookups, decomps) = compute_lookups_and_decomps::<2>(&image, 104);

        assert_eq!(lookups.len(), 1); // 1 row
        assert_eq!(lookups[0].len(), 2); // 2 chunks
        assert_eq!(decomps[0].len(), 2);

        // Chunk 0
        let l0 = &lookups[0][0];
        assert_eq!(l0.binary_enc, 0b1100000000); // first two bits are true
        assert_eq!(l0.baseB_enc, 2); // excludes remainder
        assert_eq!(l0.remainder, 8);
        assert_eq!(l0.num_blocks, 1);
        assert_eq!(l0.num_blocks_is_odd, 1);
        assert_eq!(l0.remainder_is_black, 0); // first=black, (nb-1)%2=1 → last=white
        assert_eq!(l0.power_of_B, 104); // nb=1, odd=1, rem_black=0, black_r=0 → xor=1, offset=0, exp=1 → 104^1=104
        assert_eq!(decomps[0][0], [0u16, 2u16]);

        // Chunk 1
        let l1 = &lookups[0][1];
        // pixels 5-9 of the chunk (cols 15-19) are black → bits 5-9 set
        assert_eq!(l1.binary_enc, 0b0000011111);
        assert_eq!(l1.baseB_enc, 5); // excluding remainder
        assert_eq!(l1.remainder, 5);
        assert_eq!(l1.num_blocks, 1);
        assert_eq!(l1.num_blocks_is_odd, 1);
        assert_eq!(l1.remainder_is_black, 1); // first=white, (nb-1)%2=1 → last=black
        assert_eq!(l1.power_of_B, 1); // nb=1, odd=1, rem_black=1, black_r=0 → xor=0, offset=1, exp=0 → 27^0=1
        assert_eq!(decomps[0][1], [13u16, 5u16]);
    }

    #[test]
    fn test_compute_lookups_multiple_rows() {
        // 2 rows: all-black, all-white
        let image = make_bitmatrix(&[
            &[true, true, true, true, true],
            &[false, false, false, false, false],
        ]);
        let (lookups, decomps) = compute_lookups_and_decomps::<2>(&image, 104);

        assert_eq!(lookups.len(), 2); // 2 rows
        assert_eq!(lookups[0].len(), 1); // 1 chunk per row
        assert_eq!(lookups[1].len(), 1);
        assert_eq!(decomps.len(), 2);
        assert_eq!(lookups[0][0].remainder_is_black, 1); // row 0: last block black
        assert_eq!(lookups[1][0].remainder_is_black, 0); // row 1: last block white
        assert_eq!(lookups[0][0].power_of_B, 1); // nb=0, odd=0, rem_black=1, black_r=0 → xor=1, offset=0, exp=0 → 104^0=1
        assert_eq!(lookups[1][0].power_of_B, 1); // nb=0, odd=0, rem_black=0, black_r=0 → xor=0, offset=1, exp=0 → 104^0=1
        assert_eq!(decomps[0][0], [0u16, 5u16]);
        assert_eq!(decomps[1][0], [0u16, 5u16]);
    }

    #[test]
    fn test_compute_lookups_zero_blocks() {
        let row: &[bool] = &[
            false, false, false, false, false, true, true, true, true, true, true, true, true,
            true, true, true, true, true, true, true, true, true, true, false, false, false, false,
            false, false, false,
        ];
        let image = make_bitmatrix(&[row]);
        let (lookups, decomps) = compute_lookups_and_decomps::<2>(&image, 104);
        assert_eq!(lookups.len(), 1); // 1 row
        assert_eq!(lookups[0].len(), 3); // 3 chunks in row
        assert_eq!(decomps.len(), 1);
        assert_eq!(decomps[0].len(), 3); // 3 block chunks
        assert_eq!(decomps[0][0], [0u16, 5u16]);
        assert_eq!(decomps[0][1], [0u16, 0u16]); // 0 decomp for 0 block chunk
        assert_eq!(decomps[0][2], [18u16, 7u16]); // combined chunk and last remainder
    }

    #[test]
    fn test_compute_lookups_even_nb_black_remainder() {
        // Tests the case: odd=0, remainder_is_black=1 (previously buggy path in first_block_is_black).
        //
        // Row (20px, 2 chunks):
        //   Chunk 0: [T,T,T,T,T,F,F,F,F,F] → blocks [5,5], nb=1, odd=1, rem=5 (white)
        //   Chunk 1: [T,T,T,F,F,T,T,T,T,T] → blocks [3,2,5], nb=2, odd=0, rem=5 (black)
        //
        // Chunk 1's first block is black (= rem_is_black XOR odd = 1 XOR 0 = black).
        // Prev remainder (chunk 0) is white → different colors → no merge.
        // Decomp[1] should be [prev_rem=5, block0=3, block1=2, final_rem=5] = [5,3,2,5].
        //
        // With the old buggy formula (odd && !rb = false), the code thought first was white
        // and merged at the wrong index, producing [0, 8, 2, 5] instead.
        let row: &[bool] = &[
            true, true, true, true, true, false, false, false, false, false, // chunk 0
            true, true, true, false, false, true, true, true, true, true,    // chunk 1
        ];
        let image = make_bitmatrix(&[row]);
        let (lookups, decomps) = compute_lookups_and_decomps::<4>(&image, 104);

        assert_eq!(lookups[0].len(), 2);

        // Chunk 0: nb=1, odd=1, remainder_is_black=0
        let l0 = &lookups[0][0];
        assert_eq!(l0.num_blocks, 1);
        assert_eq!(l0.num_blocks_is_odd, 1);
        assert_eq!(l0.remainder, 5);
        assert_eq!(l0.remainder_is_black, 0);

        // Chunk 1: nb=2, odd=0, remainder_is_black=1 — the key case
        let l1 = &lookups[0][1];
        assert_eq!(l1.num_blocks, 2);
        assert_eq!(l1.num_blocks_is_odd, 0);
        assert_eq!(l1.remainder, 5);
        assert_eq!(l1.remainder_is_black, 1);

        // Chunk 0 decomp: only its one non-remainder block (5); its remainder feeds into chunk 1
        assert_eq!(decomps[0][0], [0u16, 0, 0, 5]);
        // Chunk 1 decomp: [prev_rem=5, block0=3, block1=2, final_rem=5]
        // baseB_sum = 5*104^3 + 3*104^2 + 2*104 + 5 = 5656981 = block_chunks[1] in circuit
        assert_eq!(decomps[0][1], [5u16, 3, 2, 5]);
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
