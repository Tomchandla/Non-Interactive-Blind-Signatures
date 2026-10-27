//! Cleartext LowMC (all three NIST levels) and the NIBS derivations.

use crate::{
    nibs_derive_message, nibs_derive_pkr, nibs_lowmc_block_bytes, nibs_lowmc_decrypt,
    nibs_lowmc_encrypt, nibs_lowmc_init, nibs_lowmc_rounds, nibs_target,
};

pub fn init() {
    unsafe { nibs_lowmc_init() }
}

pub fn block_bytes(level: u32) -> usize {
    unsafe { nibs_lowmc_block_bytes(level) as usize }
}

pub fn rounds(level: u32) -> usize {
    unsafe { nibs_lowmc_rounds(level) as usize }
}

/// ct = E_K(pt)
pub fn encrypt(level: u32, key: &[u8], pt: &[u8]) -> Vec<u8> {
    let n = block_bytes(level);
    assert!(key.len() == n && pt.len() == n);
    let mut ct = vec![0u8; n];
    unsafe { nibs_lowmc_encrypt(level, key.as_ptr(), pt.as_ptr(), ct.as_mut_ptr()) };
    ct
}

/// pt = E_K^{-1}(ct)
pub fn decrypt(level: u32, key: &[u8], ct: &[u8]) -> Vec<u8> {
    let n = block_bytes(level);
    assert!(key.len() == n && ct.len() == n);
    let mut pt = vec![0u8; n];
    unsafe { nibs_lowmc_decrypt(level, key.as_ptr(), ct.as_ptr(), pt.as_mut_ptr()) };
    pt
}

/// pk_R for the given variant: `op` is the BCGY opening, or the sPRP
/// randomness s (pk_R = P_K(0||s)).
pub fn derive_pkr(variant: u32, level: u32, key: &[u8], op: &[u8], pkr_bytes: usize) -> Vec<u8> {
    let mut pkr = vec![0u8; pkr_bytes];
    unsafe { nibs_derive_pkr(variant, level, key.as_ptr(), op.as_ptr(), pkr.as_mut_ptr()) };
    pkr
}

/// m for the given variant.
pub fn derive_message(variant: u32, level: u32, key: &[u8], r: &[u8]) -> Vec<u8> {
    let mut m = vec![0u8; block_bytes(level)];
    unsafe { nibs_derive_message(variant, level, key.as_ptr(), r.as_ptr(), m.as_mut_ptr()) };
    m
}

/// MAYO target t = T(msg) (t_len bytes).
pub fn target(level: u32, msg: &[u8], t_len: usize) -> Vec<u8> {
    let mut t = vec![0u8; t_len];
    unsafe { nibs_target(level, msg.as_ptr(), msg.len(), t.as_mut_ptr(), t_len) };
    t
}
