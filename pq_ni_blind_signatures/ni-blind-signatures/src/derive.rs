use vole_rainhash_then_mayo_sys::lowmc::{init_checked, nibs_derive_message};
use vole_rainhash_then_mayo_sys::nibs_rain_pkr;

pub const SKR_BYTES: usize = 16; // K: 128-bit LowMC key 
pub const OPEN_BYTES: usize = 16; // op: 128-bit opening randomness
pub const NONCE_BYTES: usize = 16; // r: signer-sampled nonce, one LowMC block
pub const PKR_BYTES: usize = 32;
pub const SALT_BYTES: usize = 24;
pub const MSG_BYTES: usize = 16; // m = LowMC_K(r)
pub const PRESIG_MSG_BYTES: usize = PKR_BYTES + NONCE_BYTES;

pub fn lowmc_setup() {
    init_checked();
}

/// pk_R = c = RainHash_{256,7}(op || K)
pub fn derive_pkr(sk_r: &[u8], open: &[u8]) -> Vec<u8> {
    assert_eq!(sk_r.len(), SKR_BYTES);
    assert_eq!(open.len(), OPEN_BYTES);
    let mut pkr = vec![0u8; PKR_BYTES];
    unsafe { nibs_rain_pkr(open.as_ptr(), sk_r.as_ptr(), pkr.as_mut_ptr()) };
    pkr
}

/// m = LowMC_K(r).
pub fn derive_message(sk_r: &[u8], nonce: &[u8]) -> Vec<u8> {
    assert_eq!(sk_r.len(), SKR_BYTES);
    assert_eq!(nonce.len(), NONCE_BYTES);
    let mut m = vec![0u8; MSG_BYTES];
    unsafe { nibs_derive_message(sk_r.as_ptr(), nonce.as_ptr(), m.as_mut_ptr()) };
    m
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn derivations_are_deterministic() {
        lowmc_setup();
        let skr = vec![0xA5u8; SKR_BYTES];
        let open = vec![0x5Au8; OPEN_BYTES];
        let nonce = vec![0x11u8; NONCE_BYTES];
        assert_eq!(derive_pkr(&skr, &open), derive_pkr(&skr, &open));
        assert_eq!(derive_message(&skr, &nonce), derive_message(&skr, &nonce));
    }

    #[test]
    fn distinct_keys_separate_outputs() {
        lowmc_setup();
        let k1 = vec![0xA5u8; SKR_BYTES];
        let k2 = vec![0xA6u8; SKR_BYTES];
        let open = vec![0x11u8; OPEN_BYTES];
        let nonce = vec![0x11u8; NONCE_BYTES];
        assert_ne!(derive_pkr(&k1, &open), derive_pkr(&k2, &open));
        assert_ne!(derive_message(&k1, &nonce), derive_message(&k2, &nonce));
    }

    #[test]
    fn distinct_openings_give_distinct_pkr() {
        lowmc_setup();
        let skr = vec![0xA5u8; SKR_BYTES];
        let pkr = derive_pkr(&skr, &vec![0x5Au8; OPEN_BYTES]);
        assert_ne!(pkr, derive_pkr(&skr, &vec![0x5Bu8; OPEN_BYTES]));
    }
}
