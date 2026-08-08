pub const LOWMC_LEVEL: u32 = 1;
pub const LOWMC_BLOCK_BYTES: usize = 16;
pub const LOWMC_KEY_BYTES: usize = 16;
pub const LOWMC_NONCE_BYTES: usize = 16;
pub const LOWMC_MESSAGE_BYTES: usize = 16;
pub const LOWMC_ROUNDS: usize = 13;

pub const LOWMC_WITNESS_BYTES: usize =
    LOWMC_KEY_BYTES + LOWMC_NONCE_BYTES + LOWMC_ROUNDS * LOWMC_BLOCK_BYTES;

unsafe extern "C" {
    pub fn nibs_lowmc_init();
    pub fn nibs_lowmc_param_level() -> u32;

    pub fn nibs_lowmc_encrypt(key: *const u8, pt: *const u8, ct: *mut u8);

    pub fn nibs_lowmc_witness_states(
        key: *const u8,
        pt: *const u8,
        states: *mut u8,
        ct: *mut u8,
    );

    pub fn nibs_derive_message(k: *const u8, r: *const u8, m: *mut u8);

    pub fn nibs_lowmc_witness_expand(k: *const u8, r: *const u8, out: *mut u8, m_out: *mut u8);
}

pub fn init_checked() {
    unsafe {
        nibs_lowmc_init();
        assert_eq!(
            nibs_lowmc_param_level(),
            LOWMC_LEVEL,
            "LowMC backend built at a different NIBS_LOWMC_LEVEL than the Rust crate"
        );
    }
}
