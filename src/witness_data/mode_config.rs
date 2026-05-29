/*
 * Image configuration for witness generation.
 *
 * Six high-level parameters drive all derived constants used in witness
 * generation and ZoKrates circuit compilation.
 */

/// Fixed upper bound for the well-behaved decomp array size (across all configs).
/// Any ImageParams must produce wb_num_decomps() ≤ this value.
pub const WB_MAX_DECOMPS: usize = 13;

/// Fixed upper bound for the garbage decomp array size (across all configs).
pub const G_MAX_DECOMPS: usize = 13;

/// Image and barcode parameters from which all circuit constants are derived.
#[derive(Debug, Clone)]
pub struct ImageParams {
    /// Width of the full input image in pixels (IC in the circuit).
    pub image_width: usize,
    /// Height of the full input image in pixels (IR in the circuit).
    pub image_height: usize,
    /// Width of the barcode crop region in pixels (C in the circuit).
    /// Must be divisible by chunk_size. Must be ≤ image_width.
    pub barcode_width: usize,
    /// Height of the barcode crop region in pixels (R in the circuit).
    /// Must be ≤ image_height.
    pub barcode_height: usize,
    /// Row offset of the top-left corner of the barcode crop (R_START in the circuit).
    pub r_start: usize,
    /// Column offset of the top-left corner of the barcode crop (C_START in the circuit).
    pub c_start: usize,
    /// Maximum number of logical barcode rows (spec limit).
    pub max_rows: usize,
    /// Maximum number of data columns (spec limit).
    pub max_cols: usize,
    /// Maximum error correction level (spec limit, 0–8).
    pub max_ec_level: usize,
    /// Block chunk size in pixels (L). Must divide barcode_width evenly.
    pub chunk_size: usize,
}

impl ImageParams {
    // ── Garbage-row derived values ────────────────────────────────────────────

    /// Maximum number of garbage rows = max_rows − 1.
    pub fn garbage_rows(&self) -> usize {
        self.max_rows - 1
    }

    /// Base B for garbage chunk encoding = barcode_width + 1.
    pub fn garbage_b(&self) -> usize {
        self.barcode_width + 1
    }

    /// Number of garbage blocks per row = barcode_width.
    pub fn garbage_nb(&self) -> usize {
        self.barcode_width
    }

    /// Max blocks per garbage chunk = chunk_size (same as L).
    pub fn garbage_m(&self) -> usize {
        self.chunk_size
    }

    /// ceil(log2(garbage_m + 1)).
    /// +1 because all_nb can reach garbage_m after process_chunks adds 1 for the last chunk.
    pub fn garbage_logm(&self) -> usize {
        ceil_log2(self.garbage_m() + 1)
    }

    /// Number of garbage column words = ceil(barcode_width / 8).
    pub fn garbage_col_words(&self) -> usize {
        (self.barcode_width + 7) / 8
    }

    // ── Well-behaved-row derived values ───────────────────────────────────────

    /// Base B for well-behaved chunk encoding.
    /// = ceil(barcode_width / 86) * 8 + 1
    /// (86 = minimum modules per row - 17 for start, lri, data, rri, 18 for stop; *8 = pixels per bar; +1 makes it a base)
    pub fn wb_b(&self) -> usize {
        ((self.barcode_width + 85) / 86) * 8 + 1
    }

    /// Number of well-behaved blocks per row.
    /// = 8 * max_cols + 24 + 9
    /// (8 blocks/data-col + 24 for start/row-indicators + 9 for stop)
    pub fn wb_nb(&self) -> usize {
        8 * self.max_cols + 24 + 9
    }

    /// Max blocks per well-behaved chunk = min(ceil(L / (barcode_width / wb_nb)), L).
    pub fn wb_m(&self) -> usize {
        let pixels_per_module = self.barcode_width as f64 / self.wb_nb() as f64;
        let raw = (self.chunk_size as f64 / pixels_per_module).ceil() as usize;
        raw.min(self.chunk_size)
    }

    /// Number of WB decomp slots used (= wb_m).
    pub fn wb_num_decomps(&self) -> usize {
        self.wb_m()
    }

    /// ceil(log2(wb_m + 1)).
    /// +1 because all_nb can reach wb_m (= M) after process_chunks adds 1 for the last chunk,
    /// so we need enough bits to represent M, not just M-1.
    pub fn wb_logm(&self) -> usize {
        ceil_log2(self.wb_m() + 1)
    }

    /// Number of well-behaved column words = ceil(wb_nb / 8).
    pub fn wb_col_words(&self) -> usize {
        (self.wb_nb() + 7) / 8
    }

    // ── Barcode-spec derived values ───────────────────────────────────────────

    /// Maximum data codewords = max_rows * max_cols.
    pub fn max_data_codewords(&self) -> usize {
        self.max_rows * self.max_cols
    }

    /// Maximum decoded characters = 2 * max_data_codewords.
    pub fn max_chars(&self) -> usize {
        2 * self.max_data_codewords()
    }

    /// Maximum EC codewords = 2^(max_ec_level + 1).
    pub fn max_ec_codewords(&self) -> usize {
        1 << (self.max_ec_level + 1)
    }

    /// Lookup table size = 2^chunk_size.
    pub fn table_len(&self) -> usize {
        1 << self.chunk_size
    }

    /// Bits needed for the quotient in EC polynomial evaluation
    /// = ceil(log2(max_data_codewords * 929)).
    pub fn qbits(&self) -> usize {
        let max_val = self.max_data_codewords() * 929;
        ceil_log2(max_val)
    }

    // ── Validation ────────────────────────────────────────────────────────────

    /// Returns an error if any derived value exceeds implementation limits.
    pub fn validate(&self) -> Result<(), String> {
        if self.chunk_size == 0 {
            return Err("chunk_size must be > 0".to_string());
        }
        if self.max_rows == 0 {
            return Err("max_rows must be > 0".to_string());
        }
        if self.wb_num_decomps() > WB_MAX_DECOMPS {
            return Err(format!(
                "wb_num_decomps ({}) exceeds WB_MAX_DECOMPS ({})",
                self.wb_num_decomps(),
                WB_MAX_DECOMPS
            ));
        }
        Ok(())
    }

    // ── params.zok generation ─────────────────────────────────────────────────

    /// Generate the full content of a params.zok file encoding all derived
    /// constants and lookup tables for this image configuration.
    pub fn to_params_zok(&self) -> String {
        let l = self.chunk_size;
        let table_len = self.table_len();
        let wb_b = self.wb_b();
        let wb_nb = self.wb_nb();
        let wb_m = self.wb_m();
        let wb_logm = self.wb_logm();
        let wb_cw = self.wb_col_words();
        let g_b = self.garbage_b();
        let g_nb = self.garbage_nb();
        let g_m = self.garbage_m();
        let g_logm = self.garbage_logm();
        let g_cw = self.garbage_col_words();

        let wb_powers = generate_powers_of_b(wb_b as u128, wb_m);
        let g_powers = generate_powers_of_b(g_b as u128, g_m);
        let wb_lookup = generate_chunk_lookup(wb_b as u128, l);
        let g_lookup = generate_chunk_lookup(g_b as u128, l);

        let mut out = String::new();

        out.push_str("// Auto-generated by rxing -- do not edit by hand.\n");
        out.push_str(&format!(
            "// Parameters: image_width={}, image_height={}, barcode_width={}, barcode_height={}, r_start={}, c_start={}, max_rows={}, max_cols={}, max_ec_level={}, chunk_size={}\n\n",
            self.image_width, self.image_height, self.barcode_width, self.barcode_height,
            self.r_start, self.c_start, self.max_rows, self.max_cols, self.max_ec_level, l
        ));

        // Scalar constants
        out.push_str(&format!("const u32 L = {};\n", l));
        out.push_str(&format!("const u32 TABLE_LEN = {}; // 2^L\n\n", table_len));

        out.push_str(&format!("const u32 WB_B = {};\n", wb_b));
        out.push_str(&format!("const u32 WB_NB = {};\n", wb_nb));
        out.push_str(&format!("const u32 WB_M = {};\n", wb_m));
        out.push_str(&format!("const u32 WB_LOGM = {};\n", wb_logm));
        out.push_str(&format!("const u32 WB_CW = {};\n\n", wb_cw));

        out.push_str(&format!("const u32 G_B = {};\n", g_b));
        out.push_str(&format!("const u32 G_NB = {};\n", g_nb));
        out.push_str(&format!("const u32 G_M = {};\n", g_m));
        out.push_str(&format!("const u32 G_LOGM = {};\n", g_logm));
        out.push_str(&format!("const u32 G_CW = {};\n\n", g_cw));

        out.push_str(&format!("const u32 IR = {};\n", self.image_height));
        out.push_str(&format!("const u32 IC = {};\n", self.image_width));
        out.push_str(&format!("const u32 R = {};\n", self.barcode_height));
        out.push_str(&format!("const u32 C = {};\n", self.barcode_width));
        out.push_str(&format!("const u32 R_START = {};\n", self.r_start));
        out.push_str(&format!("const u32 C_START = {};\n", self.c_start));
        out.push_str(&format!("const u32 R_W = {};\n", self.max_rows));
        out.push_str(&format!("const u32 C_W = {};\n", self.max_cols));
        out.push_str(&format!("const u32 EC = {};\n", self.max_ec_level));
        out.push_str(&format!("const u32 G_R = {};\n", self.garbage_rows()));
        out.push_str(&format!("const u32 W = {};\n", self.max_data_codewords()));
        out.push_str(&format!("const u32 EC_W = {};\n", self.max_ec_codewords()));
        out.push_str(&format!("const u32 QBITS = {};\n\n", self.qbits()));

        // WB powers of B
        out.push_str(&format!("const field[WB_M][2] WB_POWERS_OF_B = [\n"));
        for row in &wb_powers {
            out.push_str(&format!("    [{}, {}]", row[0], row[1]));
            if row[0] as usize + 1 < wb_m {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("];\n\n");

        // G powers of B
        out.push_str(&format!("const field[G_M][2] G_POWERS_OF_B = [\n"));
        for row in &g_powers {
            out.push_str(&format!("    [{}, {}]", row[0], row[1]));
            if row[0] as usize + 1 < g_m {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("];\n\n");

        // WB chunk lookup table
        out.push_str("const field[TABLE_LEN][6] WB_CHUNK_LOOKUP_TABLE = [\n");
        for (idx, row) in wb_lookup.iter().enumerate() {
            out.push_str(&format!(
                "    [{}, {}, {}, {}, {}, {}]",
                row[0], row[1], row[2], row[3], row[4], row[5]
            ));
            if idx + 1 < table_len {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("];\n\n");

        // G chunk lookup table
        out.push_str("const field[TABLE_LEN][6] G_CHUNK_LOOKUP_TABLE = [\n");
        for (idx, row) in g_lookup.iter().enumerate() {
            out.push_str(&format!(
                "    [{}, {}, {}, {}, {}, {}]",
                row[0], row[1], row[2], row[3], row[4], row[5]
            ));
            if idx + 1 < table_len {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("];\n\n");

        // Range check tables (inline so circuits don't need const_range_check.zok)
        // Word-width constants (used for words range tables in the circuit)
        let wb_ww = (self.image_width + 4) / 5; // ceil(image_width / 5)
        let g_ww = self.image_width;
        out.push_str(&format!("const u32 WB_WW = {};\n", wb_ww));
        out.push_str(&format!("const u32 G_WW = {};\n\n", g_ww));

        // Range check tables (inline so circuits don't need const_range_check.zok)
        out.push_str("const field[WB_B] RANGE_0_WB_B = [");
        let wb_range: Vec<String> = (0..wb_b).map(|i| i.to_string()).collect();
        out.push_str(&wb_range.join(", "));
        out.push_str("];\n\n");

        out.push_str("const field[G_B] RANGE_0_G_B = [");
        let g_range: Vec<String> = (0..g_b).map(|i| i.to_string()).collect();
        out.push_str(&g_range.join(", "));
        out.push_str("];\n\n");

        out.push_str("const field[2*WB_WW] WB_WORDS_RANGE = [");
        let wb_words_range: Vec<String> = (0..2 * wb_ww).map(|i| i.to_string()).collect();
        out.push_str(&wb_words_range.join(", "));
        out.push_str("];\n\n");

        out.push_str("const field[2*G_WW] G_WORDS_RANGE = [");
        let g_words_range: Vec<String> = (0..2 * g_ww).map(|i| i.to_string()).collect();
        out.push_str(&g_words_range.join(", "));
        out.push_str("];\n\n");

        // BarcodeRanges tables (sizes match BarcodeRanges<R_W, EC, EC_CW> field types)
        let ec = self.max_ec_level;
        let ec_cw = self.max_ec_codewords();
        let max_rows = self.max_rows;

        // ec_level_range: field[EC+1], values [0..=EC]
        out.push_str("const field[EC+1] RANGE_EC_LEVEL = [");
        let ec_level_range: Vec<String> = (0..=ec).map(|i| i.to_string()).collect();
        out.push_str(&ec_level_range.join(", "));
        out.push_str("];\n\n");

        // num_rows_range: field[R_W-2], values [3..=R_W]
        out.push_str("const field[R_W-2] RANGE_NUM_ROWS = [");
        let num_rows_range: Vec<String> = (3..=max_rows).map(|i| i.to_string()).collect();
        out.push_str(&num_rows_range.join(", "));
        out.push_str("];\n\n");

        // ec_cw_range: field[EC_W], values [1..=EC_W]
        out.push_str("const field[EC_W] EC_CW_RANGE = [");
        let ec_cw_range: Vec<String> = (1..=ec_cw).map(|i| i.to_string()).collect();
        out.push_str(&ec_cw_range.join(", "));
        out.push_str("];\n\n");

        // powers_of_two: field[EC+2][2], [[0,0],[1,2],[2,4],...,[EC+1, 2^(EC+1)]]
        out.push_str("const field[EC+2][2] POWERS_OF_TWO = [\n");
        for i in 0..=(ec + 1) {
            let val: u64 = if i == 0 { 0 } else { 1u64 << i };
            out.push_str(&format!("    [{}, {}]", i, val));
            if i < ec + 1 {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("];\n\n");

        out.push_str("def main() {\n    assert(true);\n}\n");

        out
    }
}

// ── Preset modes ──────────────────────────────────────────────────────────────

/// Image resolution mode. Controls witness generation constants.
#[derive(Debug, Clone, Default)]
pub enum ImageMode {
    /// 1080×720 (HD). Default.
    #[default]
    Hd,
    /// 640×480 (SD).
    Sd,
    /// 192×144 (Small).
    Small,
    /// Caller-supplied parameters for any image size not covered by the presets.
    /// Call `ImageParams::validate()` before use.
    Custom(ImageParams),
}

impl ImageMode {
    pub fn image_params(self) -> ImageParams {
        match self {
            ImageMode::Hd => ImageParams {
                image_width: 1080,
                image_height: 720,
                barcode_width: 1080,
                barcode_height: 720,
                r_start: 0,
                c_start: 0,
                max_rows: 90,
                max_cols: 30,
                max_ec_level: 8,
                chunk_size: 10,
            },
            ImageMode::Sd => ImageParams {
                image_width: 640,
                image_height: 480,
                barcode_width: 640,
                barcode_height: 480,
                r_start: 0,
                c_start: 0,
                max_rows: 90,
                max_cols: 30,
                max_ec_level: 8,
                chunk_size: 10,
            },
            ImageMode::Small => ImageParams {
                image_width: 192,
                image_height: 144,
                barcode_width: 192,
                barcode_height: 144,
                r_start: 0,
                c_start: 0,
                max_rows: 90,
                max_cols: 30,
                max_ec_level: 8,
                chunk_size: 8,
            },
            ImageMode::Custom(params) => params,
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// ceil(log2(n)), with ceil_log2(0) = 0 and ceil_log2(1) = 0.
fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    usize::BITS as usize - (n - 1).leading_zeros() as usize
}

/// [[i, B^i] for i in 0..m]
/// Uses u128 to avoid overflow for large B values (e.g. G_B = image_width+1).
fn generate_powers_of_b(b: u128, m: usize) -> Vec<[u128; 2]> {
    (0..m).map(|i| [i as u128, b.pow(i as u32)]).collect()
}

/// For each i in 0..2^L, compute the six-field chunk lookup entry.
/// Entry: [i, enc_baseB, remainder, num_blocks, odd, black]
/// Uses u128 for enc_baseB to avoid overflow with large B values.
fn generate_chunk_lookup(b: u128, l: usize) -> Vec<[u128; 6]> {
    let table_len = 1usize << l;
    let mut table = Vec::with_capacity(table_len);
    for i in 0..table_len {
        // L-bit little-endian binary: bit 0 = LSB = leftmost pixel
        let mut blocks: Vec<usize> = Vec::new();
        let mut previous = (i >> 0) & 1;
        let mut run = 1usize;
        for bit_idx in 1..l {
            let bit = (i >> bit_idx) & 1;
            if bit == previous {
                run += 1;
            } else {
                blocks.push(run);
                run = 1;
                previous = bit;
            }
        }
        let remainder = run;
        let nb = blocks.len();
        let odd = (nb % 2) as u128;
        let black = previous as u128; // 1 if rightmost (remainder) block is black
        let enc_baseb: u128 = blocks
            .iter()
            .enumerate()
            .map(|(j, &s)| b.pow(j as u32) * s as u128)
            .sum();
        table.push([
            i as u128,
            enc_baseb,
            remainder as u128,
            nb as u128,
            odd,
            black,
        ]);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hd_derived_constants_match_presets() {
        let p = ImageMode::Hd.image_params();
        assert_eq!(p.wb_b(), 105);
        assert_eq!(p.wb_nb(), 273);
        assert_eq!(p.wb_m(), 3);
        assert_eq!(p.wb_logm(), 2);
        assert_eq!(p.wb_col_words(), 35);
        assert_eq!(p.garbage_b(), 1081);
        assert_eq!(p.garbage_nb(), 1080);
        assert_eq!(p.garbage_m(), 10);
        assert_eq!(p.garbage_logm(), 4);
        assert_eq!(p.garbage_col_words(), 135);
        assert_eq!(p.max_data_codewords(), 2700);
        assert_eq!(p.max_chars(), 5400);
        assert_eq!(p.max_ec_codewords(), 512);
        assert_eq!(p.table_len(), 1024);
        assert_eq!(p.qbits(), 22);
    }

    #[test]
    fn test_sd_derived_constants_match_presets() {
        let p = ImageMode::Sd.image_params();
        assert_eq!(p.wb_b(), 65);
        assert_eq!(p.wb_nb(), 273);
        assert_eq!(p.wb_m(), 5);
        assert_eq!(p.wb_col_words(), 35);
        assert_eq!(p.garbage_b(), 641);
        assert_eq!(p.garbage_nb(), 640);
        assert_eq!(p.garbage_col_words(), 80);
    }

    #[test]
    fn test_small_derived_constants_match_presets() {
        let p = ImageMode::Small.image_params();
        assert_eq!(p.wb_b(), 25);
        assert_eq!(p.wb_nb(), 273);
        assert_eq!(p.wb_m(), 8);
        assert_eq!(p.garbage_b(), 193);
        assert_eq!(p.garbage_nb(), 192);
        assert_eq!(p.table_len(), 256); // 2^8
    }

    #[test]
    fn test_chunk_lookup_first_entry() {
        // i=0: all pixels white (0), one run of L=10 zeros
        // blocks=[], remainder=10, nb=0, odd=0, black=0, enc=0
        let t = generate_chunk_lookup(105u128, 10);
        assert_eq!(t[0], [0, 0, 10, 0, 0, 0]);
    }

    #[test]
    fn test_params_zok_contains_scalars() {
        let p = ImageMode::Hd.image_params();
        let zok = p.to_params_zok();
        assert!(zok.contains("const u32 WB_B = 105;"));
        assert!(zok.contains("const u32 WB_NB = 273;"));
        assert!(zok.contains("const u32 G_B = 1081;"));
        assert!(zok.contains("const u32 IR = 720;"));
        assert!(zok.contains("const u32 IC = 1080;"));
        assert!(zok.contains("const u32 R = 720;"));
        assert!(zok.contains("const u32 C = 1080;"));
        assert!(zok.contains("const u32 R_START = 0;"));
        assert!(zok.contains("const u32 C_START = 0;"));
        assert!(zok.contains("def main()"));
    }
}
