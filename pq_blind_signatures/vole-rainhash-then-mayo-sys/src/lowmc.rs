//  Only the two keyed LowMC gadgets (A: pkR, M: m) live here.

pub const LOWMC_PRF: i32 = 1; // 13 rounds, d = 2^64 

pub const LOWMC_BLOCK_BYTES: usize = 32;
pub const LOWMC_KEY_BYTES: usize = 32;

// LowMC region of the witness only: skR(32) | open(16) | nonce(16) |
// GadA(13*32) | GadM(13*32).
pub const LOWMC_WITNESS_BYTES: usize = 32 + 16 + 16 + (13 + 13) * 32; // 896

unsafe extern "C" {
    pub fn nibs_lowmc_init();
    pub fn nibs_lowmc_rounds(inst: i32) -> u32;
    pub fn nibs_lowmc_encrypt(inst: i32, key: *const u8, pt: *const u8, ct: *mut u8);

    // Post-S-box states, rounds(inst) * 32 bytes; ct may be null.
    pub fn nibs_lowmc_witness_states(
        inst: i32,
        key: *const u8,
        pt: *const u8,
        states: *mut u8,
        ct: *mut u8,
    );

    pub fn nibs_lowmc_build_pt(dom: u8, payload16: *const u8, pt: *mut u8);

    // pkR = E^PRF_skR(PT(DOM_PK, open))
    pub fn nibs_derive_pkr(sk_r: *const u8, open: *const u8, pk_r: *mut u8);
    // m = E^PRF_skR(PT(DOM_M, nonce))
    pub fn nibs_derive_message(sk_r: *const u8, nonce: *const u8, m: *mut u8);

    // Fills the LowMC witness region and returns pkR through pkr_out for the
    // Rain Gad2 block B1. Left exposed for tests.
    pub fn nibs_lowmc_witness_expand(
        sk_r: *const u8,
        open: *const u8,
        nonce: *const u8,
        out: *mut u8,
        pkr_out: *mut u8,
    );
}
