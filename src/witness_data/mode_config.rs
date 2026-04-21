/*
 * Image mode configuration for witness generation.
 *
 * Each mode encodes constants tuned for a specific image resolution,
 * covering base-B encoding parameters and block counts.
 */

/// Fixed upper bound for the well-behaved decomp array size (max across all modes).
/// HD uses 4 slots; SD uses all 5. HD output zero-pads the unused 5th slot.
pub const WB_MAX_DECOMPS: usize = 5;

/// Fixed decomp array size for the garbage image (same across all modes).
pub const G_NUM_DECOMPS: usize = 10;

/// Image resolution mode. Controls witness generation constants.
#[derive(Debug, Clone, Copy, Default)]
pub enum ImageMode {
    /// 1080×720 (HD). Default.
    #[default]
    Hd,
    /// 640×480 (SD).
    Sd,
}

/// Per-mode constants used during witness generation.
pub struct ModeConfig {
    /// Number of well-behaved blocks per row (NB).
    pub wb_nb: usize,
    /// Base B for well-behaved chunk encoding.
    pub wb_b: usize,
    /// Number of decomp slots actually used for well-behaved chunks (≤ WB_MAX_DECOMPS).
    pub wb_num_decomps: usize,
    /// Number of garbage blocks per row (NB).
    pub g_nb: usize,
    /// Base B for garbage chunk encoding.
    pub g_b: usize,
}

impl ImageMode {
    pub fn config(self) -> ModeConfig {
        match self {
            ImageMode::Hd => ModeConfig {
                wb_nb: 281,
                wb_b: 105,
                wb_num_decomps: 4,
                g_nb: 1080,
                g_b: 1081,
            },
            ImageMode::Sd => ModeConfig {
                wb_nb: 281,
                wb_b: 69,
                wb_num_decomps: 5,
                g_nb: 640,
                g_b: 641,
            },
        }
    }
}
