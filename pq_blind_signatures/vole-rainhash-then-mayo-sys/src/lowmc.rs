//  lowmc.rs -- FFI to vole/conservative_bs/lowmc_plain/lowmc.cpp.
//
//  Wire-up (two changes in this sys crate, both already applied):
//    1. src/lib.rs           :  pub mod lowmc;
//    2. vole/meson.build     :  lowmc_plain/lowmc.cpp is in faest_sources, so
//                               the symbols ship in libconsv_bs_rainhash.so
//                               (build_consv_bs_rainhash.sh copies the dir).
//
//  All byte buffers use the project-wide packing: bit i of a 256-bit block
//  is (bytes[i/8] >> (i%8)) & 1.
//
//  MIXED-circuit note: only the three LowMC gadgets (A: pkR, 1: com, M: m)
//  live here. The MAYO message hash t = Rain(com | salt | cap) is Rain and
//  is handled by the MAYO signer (mayo-c-rain-sys) and by get_witness_nibs
//  on the C++ side -- there is no derive_target here anymore.

pub const LOWMC_HASH: i32 = 0; // 22 rounds, d = 2^256 -- MMO (Gad1)
pub const LOWMC_PRF: i32 = 1; //  13 rounds, d = 2^64  -- keyed by skR (GadA, GadM)

pub const LOWMC_BLOCK_BYTES: usize = 32;
pub const LOWMC_KEY_BYTES: usize = 32;
/// LowMC region of the witness only: skR(32) | open(16) | nonce(16) |
/// GadA(13*32) | Gad1(22*32) | GadM(13*32). The Rain gadget-2 region and the
/// MAYO preimage are appended by the C++ witness expansion.
pub const LOWMC_WITNESS_BYTES: usize = 32 + 16 + 16 + (13 + 22 + 13) * 32; // 1600

unsafe extern "C" {
    /// Idempotent; must precede everything else. Instantiation order of the
    /// two instances is fixed inside (HASH then PRF) -- part of the spec.
    pub fn nibs_lowmc_init();

    pub fn nibs_lowmc_rounds(inst: i32) -> u32;

    pub fn nibs_lowmc_encrypt(inst: i32, key: *const u8, pt: *const u8, ct: *mut u8);

    /// MMO with the HASH instance: out = E_chain(msg) ^ msg.
    pub fn nibs_lowmc_mmo(chain: *const u8, msg: *const u8, out: *mut u8);

    /// Post-S-box states, rounds(inst) * 32 bytes; ct may be null.
    pub fn nibs_lowmc_witness_states(
        inst: i32,
        key: *const u8,
        pt: *const u8,
        states: *mut u8,
        ct: *mut u8,
    );

    pub fn nibs_lowmc_build_pt(dom: u8, payload16: *const u8, pt: *mut u8);

    /// pkR = Com(skR; open) = E^PRF_skR( PT(DOM_PK, open) ).
    pub fn nibs_derive_pkr(sk_r: *const u8, open: *const u8, pk_r: *mut u8);
    /// com = MMO(pkR, PT(DOM_COM, nonce)).
    pub fn nibs_derive_com(pk_r: *const u8, nonce: *const u8, com: *mut u8);
    /// m = E^PRF_skR( PT(DOM_M, nonce) ).
    pub fn nibs_derive_message(sk_r: *const u8, nonce: *const u8, m: *mut u8);

    /// Fills the LowMC witness region (LOWMC_WITNESS_BYTES) and returns
    /// com through com_out (32 B) for the Rain gadget-2 in-block. Normally
    /// called from C++ (get_witness_nibs); exposed for tests.
    pub fn nibs_lowmc_witness_expand(
        sk_r: *const u8,
        open: *const u8,
        nonce: *const u8,
        out: *mut u8,
        com_out: *mut u8,
    );
}
