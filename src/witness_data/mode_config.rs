/*
 * Image mode configuration for witness generation.
 *
 * Each mode encodes constants tuned for a specific image resolution,
 * covering base-B encoding parameters and block counts.
 */

/// Fixed upper bound for the well-behaved decomp array size (max across all modes).
/// HD uses 3 slots; SD uses 5; Small uses 8. Unused slots are zero-padded.
pub const WB_MAX_DECOMPS: usize = 8;

/// Fixed upper bound for the garbage decomp array size (max across all modes).
/// HD and SD use 10; Small uses 8.
pub const G_MAX_DECOMPS: usize = 10;

/// Image resolution mode. Controls witness generation constants.
#[derive(Debug, Clone, Copy, Default)]
pub enum ImageMode {
    /// 1080×720 (HD). Default.
    #[default]
    Hd,
    /// 640×480 (SD).
    Sd,
    /// 192×144 (Small).
    Small,
}

/// Per-mode constants used during witness generation.
pub struct ModeConfig {
    /// Size of block measurement chunks in pixels (L).
    pub chunk_size: usize,
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
                chunk_size: 10,
                wb_nb: 273,
                wb_b: 105,
                wb_num_decomps: 3,
                g_nb: 1080,
                g_b: 1081,
            },
            ImageMode::Sd => ModeConfig {
                chunk_size: 10,
                wb_nb: 273,
                wb_b: 65,
                wb_num_decomps: 5,
                g_nb: 640,
                g_b: 641,
            },
            ImageMode::Small => ModeConfig {
                chunk_size: 8,
                wb_nb: 273,
                wb_b: 25,
                wb_num_decomps: 10,
                g_nb: 192,
                g_b: 193,
            },
        }
    }
}
