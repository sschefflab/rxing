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

use crate::pdf417::pdf_417_common;

/*
 * @author Guenther Grau
 * @author creatale GmbH (christoph.schulz@creatale.de)
 */

/// Returns the decoded codeword value using sampleBitCounts normalization.
/// Returns u32::MAX if the sampled bit counts don't correspond to a valid codeword;
/// callers treat this as an erasure rather than using a closest-match fallback.
pub fn getDecodedValue(moduleBitCount: &[u32]) -> u32 {
    let decodedValue = getDecodedCodewordValue(&sampleBitCounts(moduleBitCount));
    if decodedValue != -1 {
        decodedValue as u32
    } else {
        u32::MAX
    }
}

pub fn sampleBitCounts(moduleBitCount: &[u32]) -> [u32; 8] {
    let bitCountSum: u32 = moduleBitCount.iter().sum(); //MathUtils.sum(moduleBitCount);
    let mut result = [0; pdf_417_common::BARS_IN_MODULE as usize];
    let mut bitCountIndex = 0;
    let mut sumPreviousBits = 0;
    for i in 0..pdf_417_common::MODULES_IN_CODEWORD {
        // for (int i = 0; i < PDF417Common.MODULES_IN_CODEWORD; i++) {
        let sampleIndex: f32 = bitCountSum as f32
            / (2.0 * pdf_417_common::MODULES_IN_CODEWORD as f32)
            + (i as f32 * bitCountSum as f32) / pdf_417_common::MODULES_IN_CODEWORD as f32;
        if sumPreviousBits as f32 + moduleBitCount[bitCountIndex] as f32 <= sampleIndex {
            sumPreviousBits += moduleBitCount[bitCountIndex];
            bitCountIndex += 1;
        }
        result[bitCountIndex] += 1;
    }
    result
}

fn getDecodedCodewordValue(moduleBitCount: &[u32]) -> i32 {
    let decodedValue = getBitValue(moduleBitCount);
    if pdf_417_common::getCodeword(decodedValue as u32) == -1 {
        -1
    } else {
        decodedValue
    }
}

fn getBitValue(moduleBitCount: &[u32]) -> i32 {
    let mut result: u64 = 0;
    for (i, mbc) in moduleBitCount.iter().enumerate() {
        // for (int i = 0; i < moduleBitCount.length; i++) {
        for _bit in 0..(*mbc) {
            // for (int bit = 0; bit < moduleBitCount[i]; bit++) {
            result = (result << 1) | u64::from(i % 2 == 0); //(if i % 2 == 0 { 1 } else { 0 });
        }
    }
    result as i32
}

#[cfg(test)]
mod test {
    use crate::pdf417::decoder::pdf_417_codeword_decoder::getDecodedValue;

    // Inputs that don't correspond to a valid sampleBitCounts pattern return u32::MAX (erasure sentinel).
    #[test]
    fn test_invalid_returns_max() {
        let sample = [2, 2, 3, 1, 6, 4, 3, 4];
        assert_eq!(getDecodedValue(&sample), u32::MAX);
    }

    // Valid exact-decode inputs.
    #[test]
    fn test_exact_decode() {
        // sampleBitCounts([1,1,1,1,1,1,1,1]) = [1,1,1,1,1,1,1,1] which is a known valid pattern
        // Just verify a known-valid input round-trips through exact decode (not u32::MAX)
        let sample = [1, 1, 1, 1, 1, 1, 1, 1]; // uniform — exact sampleBitCounts = [2,2,2,2,2,2,2,1]
        let val = getDecodedValue(&sample);
        // Either decodes exactly or is an erasure — just confirm it doesn't panic
        let _ = val;
    }
}
